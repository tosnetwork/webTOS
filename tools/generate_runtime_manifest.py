#!/usr/bin/env python3
"""
Generate base_image.runtime.manifest from host-installed runtimes.

The generated manifest is consumed automatically by build.rs when present.
It is intentionally host-specific and should usually stay uncommitted.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from pathlib import Path


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def resolve_executable(spec: str) -> Path:
    candidate = Path(spec)
    if candidate.is_absolute():
        return candidate.resolve()
    resolved = shutil.which(spec)
    if not resolved:
        raise SystemExit(f"executable not found: {spec}")
    return Path(resolved).resolve()


def parse_ldd(binary: Path) -> list[tuple[str, Path]]:
    deps: list[tuple[str, Path]] = []
    output = run(["ldd", str(binary)])
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=>" in line:
            _, rhs = line.split("=>", 1)
            rhs = rhs.strip()
            if rhs == "not found":
                continue
            path = rhs.split("(", 1)[0].strip()
            if path.startswith("/"):
                deps.append((os.path.normpath(path), Path(path).resolve()))
            continue
        token = line.split("(", 1)[0].strip()
        if token.startswith("/"):
            deps.append((os.path.normpath(token), Path(token).resolve()))
    return deps


def python_stdlib(python_bin: Path) -> Path:
    code = (
        "import sysconfig; "
        "print(sysconfig.get_paths().get('stdlib', ''))"
    )
    output = run([str(python_bin), "-c", code]).strip()
    if not output:
        raise SystemExit("failed to discover Python stdlib path")
    return Path(output).resolve()


def java_home(java_bin: Path) -> Path:
    output = run([str(java_bin), "-XshowSettings:properties", "-version"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("java.home = "):
            return Path(line.split("=", 1)[1].strip()).resolve()
    raise SystemExit("failed to discover java.home")


def add_file(entries: OrderedDict[str, str], atos_path: str, host_path: Path) -> None:
    entries[atos_path] = str(host_path.resolve())


def trace_python_files(python_bin: Path, stdlib: Path) -> list[tuple[str, Path]]:
    with tempfile.NamedTemporaryFile(prefix="atos-python-trace-", delete=False) as trace_file:
        trace_path = Path(trace_file.name)

    try:
        subprocess.check_call(
            [
                "strace",
                "-f",
                "-qq",
                "-e",
                "trace=file",
                "-o",
                str(trace_path),
                str(python_bin),
                "-S",
                "-c",
                "print(1)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        pass

    results: OrderedDict[str, Path] = OrderedDict()
    path_re = re.compile(r'"([^"]+)"')
    try:
        for raw_line in trace_path.read_text(encoding="utf-8", errors="replace").splitlines():
            for match in path_re.finditer(raw_line):
                path_str = match.group(1)
                if not path_str.startswith(str(stdlib)):
                    continue
                atos_path = os.path.normpath(path_str)
                path = Path(path_str)
                if path.is_file():
                    results[atos_path] = path.resolve()
    finally:
        try:
            trace_path.unlink()
        except FileNotFoundError:
            pass

    return list(results.items())


def trace_java_files(java_bin: Path, home: Path) -> list[tuple[str, Path]]:
    with tempfile.NamedTemporaryFile(prefix="atos-java-trace-", delete=False) as trace_file:
        trace_path = Path(trace_file.name)

    env = {
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC0",
        "JAVA_HOME": home.as_posix(),
    }

    subprocess.check_call(
        [
            "strace",
            "-f",
            "-qq",
            "-e",
            "trace=file",
            "-o",
            str(trace_path),
            str(java_bin),
            "-Xshare:off",
            "-XX:-UsePerfData",
            "-version",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results: OrderedDict[str, Path] = OrderedDict()
    path_re = re.compile(r'"([^"]+)"')
    allowed_prefixes = (
        home.as_posix(),
        "/etc/",
        "/lib/",
        "/lib64/",
        "/usr/lib/",
    )

    try:
        for raw_line in trace_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "ENOENT" in raw_line:
                continue
            for match in path_re.finditer(raw_line):
                path_str = match.group(1)
                if not path_str.startswith(allowed_prefixes):
                    continue
                atos_path = os.path.normpath(path_str)
                path = Path(path_str)
                if path.is_file():
                    results[atos_path] = path.resolve()
    finally:
        try:
            trace_path.unlink()
        except FileNotFoundError:
            pass

    return list(results.items())


def add_java_core_libs(files: OrderedDict[str, str], home: Path) -> None:
    # `java -version` is too shallow to discover all JNI libraries needed by
    # common workloads. Keep a tiny allowlist for runtime-critical libraries
    # that later smokes rely on.
    for rel in (
        "lib/libjava.so",
        "lib/libverify.so",
        "lib/libjimage.so",
        "lib/libzip.so",
        "lib/libnio.so",
        "lib/libnet.so",
    ):
        candidate = home / rel
        atos_path = f"{home.as_posix()}/{rel}"
        if candidate.is_file():
            add_file(files, atos_path, candidate)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="base_image.runtime.manifest")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--node", default="node")
    parser.add_argument("--java", default="java")
    parser.add_argument(
        "--runtimes",
        default="python,node,java",
        help="comma-separated subset of: python,node,java",
    )
    parser.add_argument(
        "--python-stdlib",
        choices=("full", "encodings", "traced", "none"),
        default="full",
        help="how much Python stdlib to include",
    )
    parser.add_argument(
        "--java-home",
        choices=("full", "traced", "none"),
        default="full",
        help="whether to include the full java.home tree",
    )
    args = parser.parse_args()

    runtimes = {item.strip() for item in args.runtimes.split(",") if item.strip()}
    files: OrderedDict[str, str] = OrderedDict()
    trees: OrderedDict[str, str] = OrderedDict()

    if "python" in runtimes:
        python_bin = resolve_executable(args.python)
        add_file(files, "/usr/bin/python3", python_bin)
        for atos_path, host_path in parse_ldd(python_bin):
            add_file(files, atos_path, host_path)

        stdlib = python_stdlib(python_bin)
        if args.python_stdlib == "full":
            trees[f"@tree {stdlib.as_posix()}"] = stdlib.as_posix()
        elif args.python_stdlib == "encodings":
            enc_dir = stdlib / "encodings"
            if enc_dir.is_dir():
                trees[f"@tree {(Path(stdlib.as_posix()) / 'encodings').as_posix()}"] = enc_dir.as_posix()
            for name in ("site.py", "os.py", "codecs.py"):
                candidate = stdlib / name
                if candidate.is_file():
                    add_file(files, f"{stdlib.as_posix()}/{name}", candidate)
        elif args.python_stdlib == "traced":
            for atos_path, host_path in trace_python_files(python_bin, stdlib):
                add_file(files, atos_path, host_path)

    if "node" in runtimes:
        node_bin = resolve_executable(args.node)
        add_file(files, "/usr/bin/node", node_bin)
        for atos_path, host_path in parse_ldd(node_bin):
            add_file(files, atos_path, host_path)

    if "java" in runtimes:
        java_bin = resolve_executable(args.java)
        add_file(files, java_bin.as_posix(), java_bin)
        for atos_path, host_path in parse_ldd(java_bin):
            add_file(files, atos_path, host_path)

        home = java_home(java_bin)
        add_java_core_libs(files, home)
        if args.java_home == "full":
            trees[f"@tree {home.as_posix()}"] = home.as_posix()
            etc_dir = Path("/etc/java-11-openjdk")
            if etc_dir.is_dir():
                trees[f"@tree {etc_dir.as_posix()}"] = etc_dir.as_posix()
        elif args.java_home == "traced":
            for atos_path, host_path in trace_java_files(java_bin, home):
                add_file(files, atos_path, host_path)

    lines = [
        "# Auto-generated by tools/generate_runtime_manifest.py",
        "# Host-specific runtime payloads. Re-generate on the machine that owns the binaries.",
        "",
    ]
    for atos_path, host_path in files.items():
        lines.append(f"{atos_path} = {host_path}")
    if files and trees:
        lines.append("")
    for tree_decl, host_path in trees.items():
        lines.append(f"{tree_decl} = {host_path}")

    output_path = Path(args.output)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {output_path} ({len(files)} files, {len(trees)} trees)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
