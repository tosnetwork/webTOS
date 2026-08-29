#!/usr/bin/env python3
"""Render verified compatibility evidence as a publishable Markdown page."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import verify_compatibility_report


def render(report: dict) -> str:
    lines = [
        "# webTOS compatibility report",
        "",
        f"- Source commit: `{report['runtime']['source_commit']}`",
        f"- Runtime SHA-256: `{report['runtime']['sha256']}`",
        f"- Completed: `{report['generated_at']}`",
        f"- Result: **{report['status'].upper()}**",
        "",
        "## Browsers",
        "",
        "| Engine | Version | Checks | Result |",
        "|---|---|---:|---|",
    ]
    for engine in report["engines"]:
        lines.append(
            f"| {engine['name']} | {engine['version']} | {engine['passed']} | "
            f"{'PASS' if engine['failed'] == 0 else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            "## Pinned workloads",
            "",
            "| Workload | Version | Files | Result |",
            "|---|---|---:|---|",
        ]
    )
    for name in sorted(report["workloads"]):
        workload = report["workloads"][name]
        lines.append(
            f"| {name} | `{workload['version']}` | {len(workload.get('files', []))} | "
            f"{'PASS' if workload['present'] else 'NOT RUN'} |"
        )
    lines.extend(
        [
            "",
            "The JSON beside this page is the machine-readable evidence. Workload",
            "hashes identify the exact tested bytes; proprietary agent binaries are",
            "not redistributed by this report.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--lock", type=Path, default=Path("workloads/LOCK.json"))
    args = parser.parse_args()
    report = verify_compatibility_report.verify(
        args.report.resolve(), args.lock.resolve()
    )
    args.output.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (args.output / "compatibility.json").write_text(canonical, encoding="utf-8")
    (args.output / "README.md").write_text(render(report), encoding="utf-8")
    print(f"published-compatibility {args.output}")


if __name__ == "__main__":
    main()
