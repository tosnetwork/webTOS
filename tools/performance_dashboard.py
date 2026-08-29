#!/usr/bin/env python3
"""Build, render, and verify the versioned native/three-browser dashboard."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ENGINES = {"chromium", "firefox", "webkit"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_runs(runs: object, owner: str) -> list[dict]:
    if not isinstance(runs, list) or [run.get("mib") for run in runs] != [1, 4]:
        raise ValueError(f"{owner} does not contain the 1 MiB and 4 MiB runs")
    for run in runs:
        if not isinstance(run.get("instructions"), int) or run["instructions"] <= 0:
            raise ValueError(f"{owner} has invalid instruction count")
        if not isinstance(run.get("seconds"), (int, float)) or run["seconds"] <= 0:
            raise ValueError(f"{owner} has invalid duration")
    if runs[1]["instructions"] <= runs[0]["instructions"] or runs[1]["seconds"] <= runs[0]["seconds"]:
        raise ValueError(f"{owner} has a non-positive marginal measurement")
    return runs


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
    if native.get("schema_version") != 1 or native.get("platform", {}).get("kind") != "native":
        raise ValueError("native benchmark input is not schema v1")
    validate_runs(native.get("runs"), "native")
    engines = browser.get("engines", [])
    by_name = {engine.get("name"): engine for engine in engines}
    if browser.get("schema_version") != 1 or len(engines) != 3 or set(by_name) != ENGINES:
        raise ValueError("browser benchmark input must cover Chromium, Firefox, and WebKit")
    for name, engine in by_name.items():
        if not engine.get("version") or engine.get("version") == "unknown":
            raise ValueError(f"{name} has no browser version")
        validate_runs(engine.get("runs"), name)
        if not engine.get("control") or engine.get("linear_memory_ceiling_mib", 0) <= 0:
            raise ValueError(f"{name} lacks control or memory-ceiling evidence")

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
    if native.get("schema_version") != 1 or native.get("platform", {}).get("kind") != "native":
        raise ValueError("performance dashboard native evidence is invalid")
    validate_runs(native.get("runs"), "native")
    engines = report.get("browsers", [])
    names = [engine.get("name") for engine in engines]
    if names != sorted(ENGINES):
        raise ValueError("performance dashboard does not have three sorted engines")
    for engine in engines:
        validate_runs(engine.get("runs"), engine["name"])
        if (
            not engine.get("version")
            or not engine.get("control")
            or engine.get("linear_memory_ceiling_mib", 0) <= 0
        ):
            raise ValueError(f"{engine['name']} evidence is incomplete")
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
