#!/usr/bin/env python3
"""Build, render, and verify the versioned native/three-browser dashboard."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path


ENGINES = {"chromium", "firefox", "webkit"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finite_number(value: object, *, positive: bool = False, nonnegative: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if not math.isfinite(value):
        return False
    if positive and value <= 0:
        return False
    if nonnegative and value < 0:
        return False
    return True


def validate_runs(runs: object, owner: str) -> list[dict]:
    if (
        not isinstance(runs, list)
        or not all(isinstance(run, dict) for run in runs)
        or [run.get("mib") for run in runs] != [1, 4]
    ):
        raise ValueError(f"{owner} does not contain the 1 MiB and 4 MiB runs")
    for run in runs:
        if type(run.get("instructions")) is not int or run["instructions"] <= 0:
            raise ValueError(f"{owner} has invalid instruction count")
        if not finite_number(run.get("seconds"), positive=True):
            raise ValueError(f"{owner} has invalid duration")
    if runs[1]["instructions"] <= runs[0]["instructions"] or runs[1]["seconds"] <= runs[0]["seconds"]:
        raise ValueError(f"{owner} has a non-positive marginal measurement")
    return runs


def validate_native(native: object) -> dict:
    if not isinstance(native, dict) or native.get("schema_version") != 1:
        raise ValueError("native benchmark input is not schema v1")
    platform = native.get("platform", {})
    if platform != {"arch": "x86_64", "kind": "native", "os": "linux"}:
        raise ValueError("native benchmark must be x86_64 Linux")
    runs = validate_runs(native.get("runs"), "native")
    if not finite_number(native.get("machine_build_ms"), nonnegative=True):
        raise ValueError("native benchmark has invalid machine build duration")
    marginal = native.get("marginal")
    expected_seconds = runs[1]["seconds"] - runs[0]["seconds"]
    if (
        not isinstance(marginal, dict)
        or type(marginal.get("instructions")) is not int
        or marginal["instructions"] != runs[1]["instructions"] - runs[0]["instructions"]
        or not finite_number(marginal.get("seconds"), positive=True)
        or not math.isclose(marginal["seconds"], expected_seconds, rel_tol=1e-9, abs_tol=1e-9)
    ):
        raise ValueError("native benchmark marginal differs from its runs")
    return native


def validate_browser(engine: object, name: str) -> dict:
    if not isinstance(engine, dict) or engine.get("name") != name:
        raise ValueError(f"{name} browser evidence is malformed")
    if not engine.get("version") or engine.get("version") == "unknown":
        raise ValueError(f"{name} has no browser version")
    validate_runs(engine.get("runs"), name)
    for field in ("machine_build_ms", "module_instantiate_ms", "before_grow_mib"):
        if not finite_number(engine.get(field), nonnegative=True):
            raise ValueError(f"{name} has invalid {field}")
    ceiling = engine.get("linear_memory_ceiling_mib")
    if not finite_number(ceiling, positive=True) or ceiling < engine["before_grow_mib"]:
        raise ValueError(f"{name} has invalid memory-ceiling evidence")
    control = engine.get("control")
    if (
        not isinstance(control, dict)
        or type(control.get("rounds")) is not int
        or control["rounds"] <= 0
        or type(control.get("checksum")) is not int
        or control["checksum"] < 0
        or not finite_number(control.get("seconds"), positive=True)
    ):
        raise ValueError(f"{name} lacks valid control evidence")
    return engine


def build(
    native_path: Path,
    browsers_path: Path,
    runtime_path: Path,
    source_commit: str,
    measured_at: str,
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("performance dashboard needs a full source commit")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", measured_at):
        raise ValueError("measured-at must be UTC YYYY-MM-DDTHH:MM:SSZ")
    native = json.loads(native_path.read_text(encoding="utf-8"))
    browser = json.loads(browsers_path.read_text(encoding="utf-8"))
    validate_native(native)
    engines = browser.get("engines", [])
    by_name = {engine.get("name"): engine for engine in engines}
    if browser.get("schema_version") != 1 or len(engines) != 3 or set(by_name) != ENGINES:
        raise ValueError("browser benchmark input must cover Chromium, Firefox, and WebKit")
    for name, engine in by_name.items():
        validate_browser(engine, name)
    if len({(engine["control"]["rounds"], engine["control"]["checksum"]) for engine in engines}) != 1:
        raise ValueError("browser control fingerprints diverge")

    fingerprints = {
        "native": [run["instructions"] for run in native["runs"]],
        **{
            name: [run["instructions"] for run in by_name[name]["runs"]]
            for name in sorted(ENGINES)
        },
    }
    if len({tuple(values) for values in fingerprints.values()}) != 1:
        raise ValueError("benchmark instruction counts diverge across hosts")
    return {
        "browsers": [by_name[name] for name in sorted(ENGINES)],
        "instruction_fingerprints": fingerprints,
        "measured_at": measured_at,
        "native": native,
        "runtime": {"sha256": digest(runtime_path), "source_commit": source_commit},
        "schema_version": 1,
    }


def marginal(runs: list[dict]) -> tuple[int, float, float]:
    instructions = runs[1]["instructions"] - runs[0]["instructions"]
    seconds = runs[1]["seconds"] - runs[0]["seconds"]
    return instructions, seconds, instructions / seconds / 1e6


def render(report: dict) -> str:
    lines = [
        "# webTOS performance dashboard",
        "",
        f"- Source commit: `{report['runtime']['source_commit']}`",
        f"- Runtime SHA-256: `{report['runtime']['sha256']}`",
        f"- Measured: `{report['measured_at']}`",
        "",
        "| Host | Version | Build | md5sum 4 MiB | Marginal | Control | Ceiling |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    native = report["native"]
    _, _, rate = marginal(native["runs"])
    lines.append(
        f"| Native {native['platform']['arch']}-{native['platform']['os']} | — | "
        f"{native['machine_build_ms']:.0f} ms | {native['runs'][1]['seconds']:.2f} s | "
        f"{rate:.1f} M inst/s | — | — |"
    )
    for engine in report["browsers"]:
        _, _, rate = marginal(engine["runs"])
        control_rate = engine["control"]["rounds"] / engine["control"]["seconds"] / 1e6
        lines.append(
            f"| {engine['name']} | {engine['version']} | {engine['machine_build_ms']:.0f} ms | "
            f"{engine['runs'][1]['seconds']:.2f} s | {rate:.1f} M inst/s | "
            f"{control_rate:.0f} M iter/s | {engine['linear_memory_ceiling_mib']:.0f} MiB |"
        )
    lines.extend(
        [
            "",
            "The adjacent JSON is the machine-readable authority. The verifier requires",
            "all four hosts, exact cross-host guest instruction counts, the control module,",
            "browser versions, the memory ceiling, and the measured runtime digest. Wall",
            "times are evidence, not pass/fail thresholds.",
            "",
        ]
    )
    return "\n".join(lines)


def verify(report_path: Path, runtime_path: Path, markdown_path: Path | None = None) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != 1:
        raise ValueError("performance dashboard is not schema v1")
    rebuilt = build_from_report_shape(report, runtime_path)
    if rebuilt != report:
        raise ValueError("performance dashboard is not canonical or complete")
    if markdown_path and markdown_path.read_text(encoding="utf-8") != render(report):
        raise ValueError("rendered performance dashboard is stale")
    return report


def build_from_report_shape(report: dict, runtime_path: Path) -> dict:
    # Re-run every semantic check without depending on the transient input files.
    if set(report) != {
        "browsers",
        "instruction_fingerprints",
        "measured_at",
        "native",
        "runtime",
        "schema_version",
    }:
        raise ValueError("performance dashboard has unknown or missing fields")
    if report.get("runtime", {}).get("sha256") != digest(runtime_path):
        raise ValueError("measured runtime digest differs")
    if not re.fullmatch(r"[0-9a-f]{40}", report.get("runtime", {}).get("source_commit", "")):
        raise ValueError("performance dashboard has no source commit")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", report.get("measured_at", "")):
        raise ValueError("performance dashboard has invalid measurement time")
    native = report.get("native", {})
    validate_native(native)
    engines = report.get("browsers", [])
    names = [engine.get("name") for engine in engines]
    if names != sorted(ENGINES):
        raise ValueError("performance dashboard does not have three sorted engines")
    for engine in engines:
        validate_browser(engine, engine.get("name", "unknown"))
    if len({(engine["control"]["rounds"], engine["control"]["checksum"]) for engine in engines}) != 1:
        raise ValueError("performance browser control fingerprints diverge")
    expected = {
        "native": [run["instructions"] for run in native["runs"]],
        **{engine["name"]: [run["instructions"] for run in engine["runs"]] for engine in engines},
    }
    if report.get("instruction_fingerprints") != expected or len({tuple(v) for v in expected.values()}) != 1:
        raise ValueError("performance instruction fingerprints diverge")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    builder = subparsers.add_parser("build")
    builder.add_argument("native", type=Path)
    builder.add_argument("browsers", type=Path)
    builder.add_argument("runtime", type=Path)
    builder.add_argument("output", type=Path)
    builder.add_argument("markdown", type=Path)
    builder.add_argument("--source-commit", required=True)
    builder.add_argument("--measured-at", required=True)
    verifier = subparsers.add_parser("verify")
    verifier.add_argument("report", type=Path)
    verifier.add_argument("runtime", type=Path)
    verifier.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        report = build(args.native, args.browsers, args.runtime, args.source_commit, args.measured_at)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render(report), encoding="utf-8")
        print(f"built-performance-dashboard {args.output}")
    else:
        report = verify(args.report, args.runtime, args.markdown)
        print(f"verified-performance-dashboard {report['runtime']['source_commit']}")


if __name__ == "__main__":
    main()
