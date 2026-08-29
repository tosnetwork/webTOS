#!/usr/bin/env python3
"""Create and verify the canonical, uncompressed webTOS release tar."""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import tarfile
from pathlib import Path, PurePosixPath

ROOT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
MANIFEST = "SHA256SUMS"
RELEASE_FILES = {
    "BUILDINFO.json",
    "Cargo.lock",
    "LICENSE",
    "LICENSES.tsv",
    "README.md",
    "RELEASE.md",
    "SBOM.spdx.json",
    "SECURITY.md",
    "jit_host.mjs",
    "provenance/ghidra-x86-LICENSE",
    "provenance/ghidra-x86-PROVENANCE.md",
    "provenance/icicle-LICENCE-APACHE",
    "provenance/icicle-LICENCE-MIT",
    "provenance/icicle-PROVENANCE.md",
    "rust-toolchain.toml",
    "webtos_web.wasm",
    "worker.js",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative_files(stage: Path) -> list[tuple[str, bytes, int]]:
    files: list[tuple[str, bytes, int]] = []
    for path in sorted(stage.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError(f"release payload cannot contain a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == MANIFEST:
            raise ValueError(f"{MANIFEST} is generated; do not stage it")
        if "\n" in relative or "\r" in relative:
            raise ValueError(f"release path contains a newline: {relative!r}")
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        files.append((relative, path.read_bytes(), mode))
    if not files:
        raise ValueError("release stage is empty")
    return files


def manifest_bytes(files: list[tuple[str, bytes, int]]) -> bytes:
    return "".join(f"{digest(data)}  {name}\n" for name, data, _ in files).encode()


def directory_names(root: str, names: list[str]) -> list[str]:
    directories = {root}
    for name in names:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(f"{root}/{parent.as_posix()}")
            parent = parent.parent
    return sorted(directories, key=lambda item: (item.count("/"), item))


def canonical_info(
    name: str, mode: int, size: int = 0, *, directory: bool = False
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name + ("/" if directory and not name.endswith("/") else ""))
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = size
    if directory:
        info.type = tarfile.DIRTYPE
    return info


def create(stage: Path, output: Path, root: str) -> None:
    if not ROOT_RE.fullmatch(root):
        raise ValueError(f"invalid archive root name: {root!r}")
    files = relative_files(stage)
    payload = files + [(MANIFEST, manifest_bytes(files), 0o644)]
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with tarfile.open(temporary, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in directory_names(root, [name for name, _, _ in payload]):
            archive.addfile(canonical_info(directory, 0o755, directory=True))
        for name, data, mode in sorted(payload):
            info = canonical_info(f"{root}/{name}", mode, len(data))
            archive.addfile(info, io.BytesIO(data))
    temporary.replace(output)
    output.with_name(output.name + ".sha256").write_text(
        f"{digest(output.read_bytes())}  {output.name}\n", encoding="ascii"
    )


def safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or not path.parts or any(
        part in ("", ".", "..") for part in path.parts
    ):
        raise ValueError(f"unsafe archive member: {name!r}")
    return path


def verify(archive_path: Path, expected_files: set[str] | None = RELEASE_FILES) -> None:
    data: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:") as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError("archive is empty")
        root = safe_member_name(members[0].name).parts[0]
        for member in members:
            path = safe_member_name(member.name)
            if path.parts[0] != root:
                raise ValueError("archive has more than one root")
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                raise ValueError(f"non-canonical owner metadata: {member.name}")
            if member.mtime != 0:
                raise ValueError(f"nonzero timestamp: {member.name}")
            if member.isdir():
                if member.mode != 0o755:
                    raise ValueError(f"non-canonical directory mode: {member.name}")
                continue
            if not member.isfile() or member.mode not in (0o644, 0o755):
                raise ValueError(f"unsupported member type or mode: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read member: {member.name}")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in data:
                raise ValueError(f"duplicate archive member: {relative}")
            data[relative] = stream.read()
    if MANIFEST not in data:
        raise ValueError(f"archive does not contain {MANIFEST}")
    expected: dict[str, str] = {}
    for line in data[MANIFEST].decode("ascii").splitlines():
        value, separator, name = line.partition("  ")
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", value)
            or not name
            or name in expected
        ):
            raise ValueError(f"malformed {MANIFEST} line: {line!r}")
        expected[name] = value
    actual_names = set(data) - {MANIFEST}
    if expected_files is not None and actual_names != expected_files:
        raise ValueError(
            f"release allowlist differs: expected={sorted(expected_files)} "
            f"actual={sorted(actual_names)}"
        )
    if set(expected) != actual_names:
        raise ValueError(
            f"manifest member set differs: expected={sorted(expected)} "
            f"actual={sorted(actual_names)}"
        )
    for name, value in expected.items():
        if digest(data[name]) != value:
            raise ValueError(f"payload digest mismatch: {name}")
    sidecar = archive_path.with_name(archive_path.name + ".sha256")
    if sidecar.exists():
        wanted = f"{digest(archive_path.read_bytes())}  {archive_path.name}\n"
        if sidecar.read_text(encoding="ascii") != wanted:
            raise ValueError("archive sidecar digest mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("stage", type=Path)
    create_parser.add_argument("output", type=Path)
    create_parser.add_argument("--root", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if args.command == "create":
        create(args.stage.resolve(), args.output.resolve(), args.root)
    else:
        verify(args.archive.resolve())


if __name__ == "__main__":
    main()
