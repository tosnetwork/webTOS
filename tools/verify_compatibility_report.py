#!/usr/bin/env python3
"""Reject incomplete or unpinned browser compatibility evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REQUIRED_ENGINES = {"chromium", "firefox", "webkit"}


def verify(report_path: Path, lock_path: Path) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != 1 or report.get("status") != "pass":
        raise ValueError("compatibility report is not a passing schema-v1 report")
    runtime = report.get("runtime", {})
    if not re.fullmatch(r"[0-9a-f]{40}", runtime.get("source_commit", "")):
        raise ValueError("compatibility report has no full source commit")
    if not re.fullmatch(r"[0-9a-f]{64}", runtime.get("sha256", "")):
        raise ValueError("compatibility report has no runtime SHA-256")
    engine_list = report.get("engines", [])
    engines = {item.get("name"): item for item in engine_list}
    if len(engine_list) != len(REQUIRED_ENGINES) or set(engines) != REQUIRED_ENGINES:
        raise ValueError("compatibility report does not cover all three browser engines")
    for name, engine in engines.items():
        checks = engine.get("checks", [])
        labels = [item.get("label") for item in checks]
        if (
            not engine.get("version")
            or engine.get("failed") != 0
            or engine.get("passed") != len(checks)
            or not checks
            or any(item.get("ok") is not True or not item.get("label") for item in checks)
            or len(set(labels)) != len(labels)
        ):
            raise ValueError(f"compatibility report has incomplete checks for {name}")
    locked = {item["id"]: item for item in lock.get("workloads", [])}
    actual = report.get("workloads", {})
    if set(actual) != set(locked):
        raise ValueError("compatibility report workload set differs from LOCK.json")
    for name, expected in locked.items():
        evidence = actual[name]
        if not evidence.get("present") or evidence.get("version") != expected["version"]:
            raise ValueError(f"compatibility report did not run locked workload {name}")
        expected_files = {
            item["path"]: (item["sha256"], item["size"])
            for item in expected["files"]
        }
        actual_files = {
            item["path"]: (item["sha256"], item["size"])
            for item in evidence.get("files", [])
        }
        if (
            len(evidence.get("files", [])) != len(actual_files)
            or actual_files != expected_files
        ):
            raise ValueError(f"compatibility report bytes differ for {name}")
    fingerprints = report.get("instruction_fingerprints", {})
    if set(fingerprints) != REQUIRED_ENGINES:
        raise ValueError("instruction fingerprints do not cover every engine")
    command_sets = [set(fingerprints[name]) for name in sorted(REQUIRED_ENGINES)]
    commands = command_sets[0]
    if not commands or any(item != commands for item in command_sets[1:]):
        raise ValueError("instruction fingerprint command sets differ across engines")
    for command in commands:
        values = [fingerprints[name][command] for name in sorted(REQUIRED_ENGINES)]
        if not all(isinstance(value, int) and value >= 0 for value in values):
            raise ValueError(f"instruction fingerprint is invalid for {command}")
        if len(set(values)) != 1:
            raise ValueError(f"instruction fingerprint diverges for {command}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--lock", type=Path, default=Path("workloads/LOCK.json"))
    args = parser.parse_args()
    report = verify(args.report.resolve(), args.lock.resolve())
    print(
        f"verified-compatibility {report['runtime']['source_commit']} "
        f"runtime={report['runtime']['sha256']}"
    )


if __name__ == "__main__":
    main()
