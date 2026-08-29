#!/usr/bin/env python3
"""Build a deterministic SPDX 2.3 SBOM for the shipped wasm dependency graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def spdx_id(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", value).strip("-")
    suffix = hashlib.sha256(value.encode()).hexdigest()[:10]
    return f"SPDXRef-{prefix}-{cleaned}-{suffix}"


def lock_checksums(path: Path) -> dict[tuple[str, str, str], str]:
    result: dict[tuple[str, str, str], str] = {}
    package: dict[str, str] | None = None
    scalar = re.compile(r'^(name|version|source|checksum) = ("(?:[^"\\]|\\.)*")$')

    def save() -> None:
        if package is None or "checksum" not in package:
            return
        result[
            (package["name"], package["version"], package.get("source", ""))
        ] = package["checksum"]

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            save()
            package = {}
            continue
        if package is None:
            continue
        match = scalar.fullmatch(line)
        if match:
            package[match.group(1)] = json.loads(match.group(2))
    save()
    return result


def normal_edges(node: dict) -> list[str]:
    result = []
    for dependency in node.get("deps", []):
        kinds = dependency.get("dep_kinds", [])
        if any(kind.get("kind") is None for kind in kinds):
            result.append(dependency["pkg"])
    return sorted(set(result))


def reachable(metadata: dict, root_id: str) -> tuple[set[str], dict[str, list[str]]]:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    seen: set[str] = set()
    edges: dict[str, list[str]] = {}
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        dependencies = normal_edges(nodes[package_id])
        edges[package_id] = dependencies
        pending.extend(dependencies)
    return seen, edges


def source_download(package: dict) -> str:
    source = package.get("source")
    if source and source.startswith("registry+"):
        return f"https://crates.io/crates/{package['name']}/{package['version']}"
    if source and source.startswith("git+"):
        return source[4:]
    return "NOASSERTION"


def build(args: argparse.Namespace) -> dict:
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    roots = [
        package for package in metadata["packages"] if package["name"] == "webtos-web"
    ]
    if len(roots) != 1:
        raise ValueError(f"expected one webtos-web package, found {len(roots)}")
    reachable_ids, edges = reachable(metadata, roots[0]["id"])
    checksums = lock_checksums(args.lock)
    ids = {
        package_id: spdx_id(
            "CargoPackage",
            f"{packages_by_id[package_id]['name']}-{packages_by_id[package_id]['version']}-"
            f"{packages_by_id[package_id].get('source') or 'path'}",
        )
        for package_id in reachable_ids
    }
    runtime_id = "SPDXRef-Package-webtos-runtime"
    wasm_id = "SPDXRef-File-webtos-web-wasm"
    package_records = []
    for package_id in sorted(
        reachable_ids,
        key=lambda item: (
            packages_by_id[item]["name"],
            packages_by_id[item]["version"],
            item,
        ),
    ):
        package = packages_by_id[package_id]
        source = package.get("source") or ""
        record = {
            "SPDXID": ids[package_id],
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": source_download(package),
            "filesAnalyzed": False,
            "licenseConcluded": package.get("license") or "NOASSERTION",
            "licenseDeclared": package.get("license") or "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        checksum = checksums.get((package["name"], package["version"], source))
        if checksum:
            record["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": checksum}
            ]
        package_records.append(record)
    ghidra_id = "SPDXRef-Package-ghidra-x86-spec"
    package_records.extend(
        [
            {
                "SPDXID": runtime_id,
                "name": "webtos-runtime",
                "versionInfo": args.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
            },
            {
                "SPDXID": ghidra_id,
                "name": "ghidra-x86-sleigh-spec",
                "versionInfo": "6b502aab73ff22397f3f1fb5d6dcf42822464ccb",
                "downloadLocation": "git+https://github.com/NationalSecurityAgency/ghidra@6b502aab73ff22397f3f1fb5d6dcf42822464ccb",
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "copyrightText": "NOASSERTION",
            },
        ]
    )
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": runtime_id,
        },
        {
            "spdxElementId": runtime_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": wasm_id,
        },
        {
            "spdxElementId": runtime_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ids[roots[0]["id"]],
        },
        {
            "spdxElementId": ids[roots[0]["id"]],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ghidra_id,
        },
    ]
    for source_id in sorted(edges):
        for target_id in edges[source_id]:
            if target_id in reachable_ids:
                relationships.append(
                    {
                        "spdxElementId": ids[source_id],
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": ids[target_id],
                    }
                )
    created = datetime.fromtimestamp(args.source_epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"webtos-runtime-{args.version}",
        "documentNamespace": f"https://github.com/tosnetwork/webTOS/spdx/{args.source_commit}/{args.version}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: webTOS-tools-build-sbom-1"],
        },
        "documentDescribes": [runtime_id],
        "packages": sorted(package_records, key=lambda item: item["SPDXID"]),
        "files": [
            {
                "SPDXID": wasm_id,
                "fileName": "./webtos_web.wasm",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": hashlib.sha256(
                            args.wasm.read_bytes()
                        ).hexdigest(),
                    }
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": sorted(
            relationships,
            key=lambda item: (
                item["spdxElementId"],
                item["relationshipType"],
                item["relatedSpdxElement"],
            ),
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--wasm", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("--source-commit must be a full lowercase Git object id")
    document = build(args)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
