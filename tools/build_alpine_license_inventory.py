#!/usr/bin/env python3
"""Build or verify the package-level license inventory for the pinned Alpine rootfs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOTFS = {
    "version": "3.20.3",
    "architecture": "x86_64",
    "uri": "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz",
    "sha256": "d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c",
}

POLICY = {
    "Apache-2.0": ("allowed_with_obligations", ["preserve Apache-2.0 license and notices"]),
    "GPL-2.0-only": (
        "allowed_with_obligations",
        ["provide corresponding source and preserve GPL-2.0-only license notices"],
    ),
    "MIT": ("allowed_with_obligations", ["preserve MIT copyright and license notice"]),
    "MIT AND BSD-2-Clause AND GPL-2.0-or-later": (
        "allowed_with_obligations",
        [
            "preserve MIT and BSD-2-Clause notices",
            "provide corresponding source and preserve GPL-2.0-or-later license notices",
        ],
    ),
    "MPL-2.0 AND MIT": (
        "allowed_with_obligations",
        ["preserve MIT notices and make MPL-2.0-covered source modifications available"],
    ),
    "Zlib": ("allowed_with_obligations", ["preserve the zlib license notice"]),
}


def parse_installed(path: Path) -> list[dict]:
    packages = []
    for paragraph in path.read_text(encoding="utf-8").strip().split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if len(line) >= 3 and line[1] == ":" and line[0] in "PVLUo":
                fields[line[0]] = line[2:]
        missing = [key for key in "PVLUo" if not fields.get(key)]
        if missing:
            raise ValueError(f"Alpine package record lacks {','.join(missing)}")
        license_expression = fields["L"]
        if license_expression not in POLICY:
            raise ValueError(
                f"package {fields['P']} has no redistribution decision for {license_expression}"
            )
        decision, obligations = POLICY[license_expression]
        packages.append(
            {
                "license": license_expression,
                "name": fields["P"],
                "obligations": obligations,
                "origin": fields["o"],
                "redistribution": decision,
                "source": fields["U"],
                "version": fields["V"],
                "binary_package": (
                    "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/"
                    f"{fields['P']}-{fields['V']}.apk"
                ),
            }
        )
    packages.sort(key=lambda package: package["name"])
    names = [package["name"] for package in packages]
    if len(names) != len(set(names)) or not names:
        raise ValueError("Alpine package inventory is empty or has duplicate packages")
    return packages


def build(installed: Path) -> dict:
    payload = installed.read_bytes()
    return {
        "installed_db_sha256": hashlib.sha256(payload).hexdigest(),
        "packages": parse_installed(installed),
        "rootfs": ROOTFS,
        "schema_version": 1,
    }


def canonical(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("installed", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = canonical(build(args.installed))
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("Alpine license inventory is missing or stale")
        print(f"verified-alpine-licenses {len(json.loads(rendered)['packages'])} packages")
    else:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote-alpine-licenses {args.output}")


if __name__ == "__main__":
    main()
