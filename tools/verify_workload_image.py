#!/usr/bin/env python3
"""Verify a canonical webTOS workload archive and its in-toto statement."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

import package_release


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(path: Path) -> dict:
    package_release.verify(path, expected_files=None)
    payload: dict[str, bytes] = {}
    with tarfile.open(path, "r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = PurePosixPath(member.name).parts
            relative = PurePosixPath(*parts[1:]).as_posix()
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read {member.name}")
            payload[relative] = stream.read()
    required = {
        "ATTESTATION.intoto.json",
        "LICENSES.json",
        "SPEC.json",
        "WORKLOAD.json",
        "manifest.txt",
    }
    missing = required - set(payload)
    if missing:
        raise ValueError(f"workload archive lacks {sorted(missing)}")
    descriptor = json.loads(payload["WORKLOAD.json"])
    spec = json.loads(payload["SPEC.json"])
    statement = json.loads(payload["ATTESTATION.intoto.json"])
    manifest_hash = digest(payload["manifest.txt"])
    if descriptor.get("licenses_sha256") != digest(payload["LICENSES.json"]):
        raise ValueError("WORKLOAD.json does not commit to LICENSES.json")
    if descriptor.get("spec_sha256") != digest(payload["SPEC.json"]):
        raise ValueError("WORKLOAD.json does not commit to SPEC.json")
    if descriptor.get("manifest_sha256") != manifest_hash:
        raise ValueError("WORKLOAD.json does not commit to manifest.txt")
    if spec.get("expected_manifest_sha256") != manifest_hash:
        raise ValueError("SPEC.json does not commit to manifest.txt")
    if any(descriptor.get(field) != spec.get(field) for field in ("id", "version", "source")):
        raise ValueError("WORKLOAD.json identity differs from SPEC.json")
    if statement.get("_type") != "https://in-toto.io/Statement/v1" or \
       statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ValueError("attestation type is not the workload provenance contract")
    subjects_list = statement.get("subject", [])
    subjects = {
        item["name"]: item["digest"]["sha256"] for item in subjects_list
    }
    if len(subjects_list) != 2 or set(subjects) != {"manifest.txt", "WORKLOAD.json"}:
        raise ValueError("attestation subject set is not canonical")
    if subjects.get("manifest.txt") != manifest_hash:
        raise ValueError("attestation does not commit to manifest.txt")
    if subjects.get("WORKLOAD.json") != digest(payload["WORKLOAD.json"]):
        raise ValueError("attestation does not commit to WORKLOAD.json")
    predicate = statement.get("predicate", {})
    parameters = predicate.get("externalParameters", {})
    if (
        predicate.get("buildType") != "https://webtos.network/build/workload-image/v1"
        or predicate.get("builder", {}).get("id") != "tools/build_workload_image.py"
        or predicate.get("materials") != spec.get("source")
        or parameters.get("workload") != f"{spec['id']}@{spec['version']}"
        or parameters.get("chunkSize") != descriptor.get("chunk_size")
        or parameters.get("sourceEpoch") != descriptor.get("source_epoch")
    ):
        raise ValueError("attestation predicate differs from the workload contract")
    expected_chunks: set[str] = set()
    for line in payload["manifest.txt"].decode("utf-8").splitlines()[1:]:
        fields = line.split(" ")
        if fields[0] == "f" and fields[7]:
            expected_chunks.update(fields[7].split(","))
    actual_chunks = {
        name.removeprefix("chunks/")
        for name in payload
        if name.startswith("chunks/")
    }
    if expected_chunks != actual_chunks:
        raise ValueError("manifest chunk set differs from archive")
    for name in actual_chunks:
        if not re.fullmatch(r"[0-9a-f]{64}", name):
            raise ValueError(f"invalid chunk name: {name}")
        if digest(payload[f"chunks/{name}"]) != name:
            raise ValueError(f"chunk bytes do not match name: {name}")
    return descriptor


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    descriptor = verify(args.archive.resolve())
    print(
        f"verified-workload {descriptor['id']}@{descriptor['version']} "
        f"manifest={descriptor['manifest_sha256']}"
    )


if __name__ == "__main__":
    main()
