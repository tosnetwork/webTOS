#!/usr/bin/env python3
"""Build a deterministic, content-addressed webTOS workload image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

import build_chunk_manifest
import package_release


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_guest_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or value == "/"
        or value.endswith("/")
        or any(part in ("", ".", "..") for part in path.parts[1:])
    ):
        raise ValueError(f"noncanonical workload path: {value!r}")
    return path


def load_spec(path: Path, workload_id: str | None = None) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("workload spec schema_version must be 1")
    if "workloads" in document:
        if not workload_id:
            raise ValueError("--workload-id is required with a workload lock")
        matches = [item for item in document["workloads"] if item.get("id") == workload_id]
        if len(matches) != 1:
            raise ValueError(f"workload lock does not name {workload_id} exactly once")
        document = {"schema_version": 1, **matches[0]}
    for field in ("id", "version", "source", "expected_manifest_sha256"):
        if not document.get(field):
            raise ValueError(f"workload spec is missing {field}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", document["id"]):
        raise ValueError("workload id is not canonical")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", document["version"]):
        raise ValueError("workload version is not canonical")
    if not re.fullmatch(r"[0-9a-f]{64}", document["expected_manifest_sha256"]):
        raise ValueError("expected_manifest_sha256 must be lowercase SHA-256")
    return document


def validate_files(source: Path, spec: dict) -> list[dict]:
    declared: dict[str, dict] = {}
    for record in spec.get("files", []):
        path = safe_guest_path(record["path"]).as_posix()
        if path in declared:
            raise ValueError(f"workload spec names {path} twice")
        if not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")):
            raise ValueError(f"workload file {path} has no valid SHA-256")
        if not isinstance(record.get("size"), int) or record["size"] < 0:
            raise ValueError(f"workload file {path} has no valid size")
        if not re.fullmatch(r"[0-7]{3,4}", record.get("mode", "")):
            raise ValueError(f"workload file {path} has no canonical mode")
        if not record.get("license") or not record.get("redistribution"):
            raise ValueError(f"workload file {path} lacks license policy")
        declared[path] = record

    actual: set[str] = set()
    for path in source.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        guest = "/" + path.relative_to(source).as_posix()
        actual.add(guest)
        record = declared.get(guest)
        if record is None:
            if spec.get("allow_unlisted_files") is True:
                continue
            raise ValueError(f"workload source contains undeclared file {guest}")
        data = path.read_bytes()
        mode = f"{stat.S_IMODE(path.stat().st_mode):o}"
        if len(data) != record["size"] or sha256(data) != record["sha256"]:
            raise ValueError(f"workload source bytes do not match {guest}")
        if mode != record["mode"]:
            raise ValueError(
                f"workload source mode for {guest} is {mode}, expected {record['mode']}"
            )
    missing = set(declared) - actual
    if missing:
        raise ValueError(f"workload source is missing {sorted(missing)}")
    return [declared[path] for path in sorted(declared)]


def license_inventory(spec_path: Path, spec: dict, files: list[dict]) -> bytes:
    inventory_path = spec.get("license_inventory")
    if inventory_path:
        path = (spec_path.parent / inventory_path).resolve()
        document = json.loads(path.read_text(encoding="utf-8"))
    else:
        document = {
            "schema_version": 1,
            "workload": spec["id"],
            "version": spec["version"],
            "files": [
                {
                    "license": item["license"],
                    "path": item["path"],
                    "redistribution": item["redistribution"],
                    **({"source": item["source"]} if item.get("source") else {}),
                }
                for item in files
            ],
        }
    if document.get("schema_version") != 1:
        raise ValueError("license inventory schema_version must be 1")
    records = document.get("files") or document.get("packages")
    if not records:
        raise ValueError("license inventory is empty")
    for record in records:
        if not record.get("license") or not record.get("redistribution"):
            raise ValueError("license inventory has an undecided record")
    return canonical_json(document)


def build(args: argparse.Namespace) -> Path:
    source = args.source.resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    if source == output or source in output.parents:
        raise ValueError("output must not be inside the workload source")
    spec = load_spec(args.spec, args.workload_id)
    files = validate_files(source, spec)
    output.mkdir(parents=True)
    manifest = build_chunk_manifest.build(
        source, output, b"/", args.chunk_size, args.source_epoch, False
    )
    manifest_hash = sha256(manifest)
    if manifest_hash != spec["expected_manifest_sha256"]:
        raise ValueError(
            f"workload manifest root is {manifest_hash}, expected "
            f"{spec['expected_manifest_sha256']}"
        )
    licenses = license_inventory(args.spec, spec, files)
    (output / "LICENSES.json").write_bytes(licenses)
    locked_spec = canonical_json(spec)
    (output / "SPEC.json").write_bytes(locked_spec)
    descriptor = {
        **({"build": spec["build"]} if spec.get("build") else {}),
        "chunk_size": args.chunk_size,
        "id": spec["id"],
        "licenses_sha256": sha256(licenses),
        "manifest_sha256": manifest_hash,
        "schema_version": 1,
        "source": spec["source"],
        "source_epoch": args.source_epoch,
        "spec_sha256": sha256(locked_spec),
        "version": spec["version"],
    }
    descriptor_bytes = canonical_json(descriptor)
    (output / "WORKLOAD.json").write_bytes(descriptor_bytes)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "buildType": "https://webtos.network/build/workload-image/v1",
            "builder": {"id": "tools/build_workload_image.py"},
            "externalParameters": {
                **({"build": spec["build"]} if spec.get("build") else {}),
                "chunkSize": args.chunk_size,
                "sourceEpoch": args.source_epoch,
                "workload": f"{spec['id']}@{spec['version']}",
            },
            "materials": spec["source"],
        },
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {"digest": {"sha256": manifest_hash}, "name": "manifest.txt"},
            {
                "digest": {"sha256": sha256(descriptor_bytes)},
                "name": "WORKLOAD.json",
            },
        ],
    }
    (output / "ATTESTATION.intoto.json").write_bytes(canonical_json(statement))
    archive = args.archive.resolve()
    package_release.create(
        output,
        archive,
        f"webtos-workload-{spec['id']}-{spec['version']}",
    )
    package_release.verify(archive, expected_files=None)
    return archive


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--workload-id")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--chunk-size", type=int, default=64 * 1024)
    parser.add_argument(
        "--source-epoch",
        type=int,
        default=os.environ.get("SOURCE_DATE_EPOCH"),
    )
    args = parser.parse_args()
    if args.source_epoch is None:
        parser.error("--source-epoch or SOURCE_DATE_EPOCH is required")
    archive = build(args)
    print(f"workload-archive {archive}")


if __name__ == "__main__":
    main()
