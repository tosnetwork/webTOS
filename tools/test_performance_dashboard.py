#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import performance_dashboard


class PerformanceDashboardTests(unittest.TestCase):
    def inputs(self, root: Path) -> tuple[Path, Path, Path]:
        runtime = root / "runtime.wasm"
        runtime.write_bytes(b"wasm")
        runs = [
            {"instructions": 10, "mib": 1, "seconds": 1.0},
            {"instructions": 40, "mib": 4, "seconds": 2.0},
        ]
        native = root / "native.json"
        native.write_text(json.dumps({
            "machine_build_ms": 10.0,
            "marginal": {"instructions": 30, "seconds": 1.0},
            "platform": {"arch": "x86_64", "kind": "native", "os": "linux"},
            "runs": runs,
            "schema_version": 1,
        }))
        browsers = root / "browsers.json"
        browsers.write_text(json.dumps({
            "engines": [{
                "before_grow_mib": 10,
                "control": {"checksum": 1, "rounds": 100, "seconds": 1.0},
                "linear_memory_ceiling_mib": 3892,
                "machine_build_ms": 11.0,
                "module_instantiate_ms": 2.0,
                "name": name,
                "runs": runs,
                "version": "1.0",
            } for name in ("chromium", "firefox", "webkit")],
            "schema_version": 1,
        }))
        return native, browsers, runtime

    def test_build_render_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native, browsers, runtime = self.inputs(root)
            report = performance_dashboard.build(
                native, browsers, runtime, "a" * 40, "2026-08-29T00:00:00Z"
            )
            report_path = root / "report.json"
            markdown = root / "README.md"
            report_path.write_text(json.dumps(report))
            markdown.write_text(performance_dashboard.render(report))
            performance_dashboard.verify(report_path, runtime, markdown)

    def test_instruction_divergence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native, browsers, runtime = self.inputs(root)
            document = json.loads(browsers.read_text())
            document["engines"][2]["runs"][1]["instructions"] += 1
            browsers.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "instruction counts diverge"):
                performance_dashboard.build(
                    native, browsers, runtime, "a" * 40, "2026-08-29T00:00:00Z"
                )

    def test_render_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native, browsers, runtime = self.inputs(root)
            report = performance_dashboard.build(
                native, browsers, runtime, "a" * 40, "2026-08-29T00:00:00Z"
            )
            report_path = root / "report.json"
            markdown = root / "README.md"
            report_path.write_text(json.dumps(report))
            markdown.write_text("stale")
            with self.assertRaisesRegex(ValueError, "stale"):
                performance_dashboard.verify(report_path, runtime, markdown)

    def test_unknown_report_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native, browsers, runtime = self.inputs(root)
            report = performance_dashboard.build(
                native, browsers, runtime, "a" * 40, "2026-08-29T00:00:00Z"
            )
            report["unverified"] = True
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "unknown or missing"):
                performance_dashboard.verify(report_path, runtime)


if __name__ == "__main__":
    unittest.main()
