#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_compatibility_report


class CompatibilityReportTests(unittest.TestCase):
    def documents(self, root: Path) -> tuple[Path, Path]:
        lock = {
            "schema_version": 1,
            "workloads": [
                {
                    "files": [{"path": "/bin/agent", "sha256": "a" * 64, "size": 1}],
                    "id": "agent",
                    "version": "1",
                }
            ],
        }
        engine = lambda name: {
            "checks": [{"label": "agent starts", "ok": True}],
            "failed": 0,
            "name": name,
            "passed": 1,
            "version": "1.0",
        }
        report = {
            "engines": [engine(name) for name in ("chromium", "firefox", "webkit")],
            "generated_at": "2026-08-29T00:00:00Z",
            "instruction_fingerprints": {
                name: {"agent --version": 10}
                for name in ("chromium", "firefox", "webkit")
            },
            "runtime": {"sha256": "b" * 64, "source_commit": "c" * 40},
            "schema_version": 1,
            "status": "pass",
            "workloads": {
                "agent": {
                    "files": [{"path": "/bin/agent", "sha256": "a" * 64, "size": 1}],
                    "id": "agent",
                    "present": True,
                    "version": "1",
                }
            },
        }
        lock_path = root / "LOCK.json"
        report_path = root / "report.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return report_path, lock_path

    def test_complete_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, lock = self.documents(Path(temporary))
            verify_compatibility_report.verify(report, lock)

    def test_missing_workload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, lock = self.documents(Path(temporary))
            document = json.loads(report.read_text())
            document["workloads"]["agent"]["present"] = False
            report.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "did not run"):
                verify_compatibility_report.verify(report, lock)

    def test_engine_cannot_omit_a_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, lock = self.documents(Path(temporary))
            document = json.loads(report.read_text())
            document["instruction_fingerprints"]["webkit"] = {}
            report.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "command sets differ"):
                verify_compatibility_report.verify(report, lock)

    def test_duplicate_engine_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, lock = self.documents(Path(temporary))
            document = json.loads(report.read_text())
            document["engines"].append(document["engines"][0])
            report.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "all three"):
                verify_compatibility_report.verify(report, lock)


if __name__ == "__main__":
    unittest.main()
