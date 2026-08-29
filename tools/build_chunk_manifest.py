#!/usr/bin/env python3
"""Build a canonical webTOS chunk manifest and SHA-256 chunk directory."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path

CHUNK_SIZE = 64 * 1024
HEADER = b"webtos-chunk-manifest 1\n"


def fnv1a_update(value: int, data: bytes) -> int:
    for byte in data:
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def guest_path(prefix: bytes, relative: bytes) -> bytes:
    parts = [part for part in (prefix.strip(b"/"), relative.strip(b"/")) if part]
    return b"/" + b"/".join(parts)


def store_chunk(directory: Path, data: bytes, expected: set[str]) -> str:
    digest = hashlib.sha256(data).hexdigest()
    expected.add(digest)
    target = directory / digest
    try:
        with target.open("xb") as stream:
            stream.write(data)
    except FileExistsError:
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"existing chunk {target} does not match its name")
    return digest


def clean_stale_chunks(directory: Path, expected: set[str]) -> None:
    for path in directory.iterdir():
        if path.is_dir() and not path.is_symlink():
            raise ValueError(f"chunk output contains an unexpected directory: {path}")
        if path.name not in expected or not re.fullmatch(r"[0-9a-f]{64}", path.name):
            path.unlink()


def build(
    source: Path,
    output: Path,
    prefix: bytes,
    chunk_size: int,
    source_epoch: int,
    legacy_fnv: bool = True,
) -> bytes:
    if chunk_size <= 0 or chunk_size % 4096:
        raise ValueError("chunk size must be a nonzero multiple of 4096")
    if source_epoch < -(1 << 63) or source_epoch >= 1 << 63:
        raise ValueError("source epoch does not fit the manifest's signed 64-bit mtime")
    source = source.resolve()
    if output.is_symlink():
        raise ValueError("output must not be a symlink")
    output = output.resolve()
    if output == source or source in output.parents:
        raise ValueError("output must not be inside the source tree")
    source_raw = os.fsencode(source)
    output.mkdir(parents=True, exist_ok=True)
    chunks_dir = output / "chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    records: list[tuple[bytes, bytes]] = []
    expected_chunks: set[str] = set()

    for root, dirs, files in os.walk(source_raw, followlinks=False):
        dirs.sort()
        files.sort()
        rel_root = os.path.relpath(root, source_raw)
        rel_root = b"" if rel_root == b"." else rel_root
        # Record the packaged root as well as descendants. For guest prefix
        # "/" this pins the root directory metadata; for any other prefix it
        # also ensures the mount point exists with the source root's metadata.
        if rel_root or root == source_raw:
            st = os.lstat(root)
            path = guest_path(prefix, rel_root)
            record = f"d {stat.S_IMODE(st.st_mode):o} {source_epoch} ".encode() + path.hex().encode()
            records.append((path, record))

        # os.walk lists directory symlinks in dirs; keep them as links and do
        # not descend through them.
        for name in list(dirs):
            host = os.path.join(root, name)
            if not os.path.islink(host):
                continue
            dirs.remove(name)
            st = os.lstat(host)
            path = guest_path(prefix, os.path.join(rel_root, name))
            target = os.readlink(host)
            if isinstance(target, str):
                target = os.fsencode(target)
            record = (
                f"l {stat.S_IMODE(st.st_mode):o} {source_epoch} ".encode()
                + path.hex().encode()
                + b" "
                + target.hex().encode()
            )
            records.append((path, record))

        for name in files:
            host = os.path.join(root, name)
            st = os.lstat(host)
            path = guest_path(prefix, os.path.join(rel_root, name))
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(host)
                if isinstance(target, str):
                    target = os.fsencode(target)
                record = (
                    f"l {stat.S_IMODE(st.st_mode):o} {source_epoch} ".encode()
                    + path.hex().encode()
                    + b" "
                    + target.hex().encode()
                )
                records.append((path, record))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            hashes: list[str] = []
            legacy = 0xCBF29CE484222325 if legacy_fnv else 0
            size = 0
            with open(host, "rb") as stream:
                while data := stream.read(chunk_size):
                    size += len(data)
                    if legacy_fnv:
                        legacy = fnv1a_update(legacy, data)
                    hashes.append(store_chunk(chunks_dir, data, expected_chunks))
            record = (
                f"f {stat.S_IMODE(st.st_mode):o} {source_epoch} ".encode()
                + path.hex().encode()
                + f" {size} {chunk_size} {legacy:016x} ".encode()
                + ",".join(hashes).encode()
            )
            records.append((path, record))

    records.sort(key=lambda item: item[0])
    manifest = HEADER + b"\n".join(record for _, record in records) + b"\n"
    clean_stale_chunks(chunks_dir, expected_chunks)
    manifest_path = output / "manifest.txt"
    temporary = output / "manifest.txt.tmp"
    temporary.write_bytes(manifest)
    temporary.replace(manifest_path)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="host directory to package")
    parser.add_argument("output", type=Path, help="output directory")
    parser.add_argument("--guest-prefix", default="/", help="absolute guest prefix")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    parser.add_argument(
        "--source-epoch",
        type=int,
        default=os.environ.get("SOURCE_DATE_EPOCH"),
        help="canonical mtime for every image entry (or SOURCE_DATE_EPOCH)",
    )
    parser.add_argument(
        "--legacy-fnv",
        choices=("compute", "zero"),
        default="compute",
        help="legacy trace identifier; workload releases use zero",
    )
    args = parser.parse_args()
    prefix = os.fsencode(args.guest_prefix)
    parts = (
        []
        if prefix == b"/"
        else prefix.split(b"/")[1:] if prefix.startswith(b"/") else []
    )
    if (
        not prefix.startswith(b"/")
        or b"\0" in prefix
        or (prefix != b"/" and prefix.endswith(b"/"))
        or any(part in (b"", b".", b"..") for part in parts)
    ):
        parser.error("--guest-prefix must be an absolute canonical NUL-free path")
    if args.source_epoch is None:
        parser.error("--source-epoch or SOURCE_DATE_EPOCH is required")
    manifest = build(
        args.source,
        args.output,
        prefix,
        args.chunk_size,
        args.source_epoch,
        args.legacy_fnv == "compute",
    )
    print(f"manifest-root {hashlib.sha256(manifest).hexdigest()}")


if __name__ == "__main__":
    main()
