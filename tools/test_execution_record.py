#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import execution_record


class ExecutionRecordTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        for name, payload in {
            "runtime.wasm": b"runtime",
            "manifest.txt": b"manifest",
            "network.json": b"recording",
            "policy.json": b"policy",
            "before.bin": b"before",
            "after.bin": b"after",
            "input.txt": b"input",
            "output.txt": b"output",
            "trace.txt": b"trace",
        }.items():
            (root / name).write_bytes(payload)
        descriptor = {
            "inputs": ["input.txt"],
            "network": {
                "receipts": [{
                    "bytes_received": 7,
                    "bytes_sent": 3,
                    "outcome": "closed",
                    "peer": "127.0.0.1:80",
                    "protocol": "tcp",
                }],
                "recording": "network.json",
            },
            "policy": "policy.json",
            "result": {
                "exit_code": 0,
                "instruction_count": 42,
                "output": "output.txt",
                "status": "halted",
            },
            "runtime": "runtime.wasm",
            "snapshots": {"after": "after.bin", "before": "before.bin"},
            "source_commit": "a" * 40,
            "trace": {"artifact": "trace.txt", "root_sha256": "b" * 64},
            "workload": {"id": "busybox", "manifest": "manifest.txt", "version": "1"},
        }
        path = root / "descriptor.json"
        path.write_text(json.dumps(descriptor), encoding="utf-8")
        return path

    def test_build_and_verify_bind_every_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = execution_record.build(self.fixture(root))
            record_path = root / "execution.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            self.assertEqual(execution_record.verify(record_path)["result"]["exit_code"], 0)

    def test_artifact_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = execution_record.build(self.fixture(root))
            record_path = root / "execution.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            (root / "network.json").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "artifact (size|digest) differs"):
                execution_record.verify(record_path)

    def test_record_tamper_is_rejected_before_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = execution_record.build(self.fixture(root))
            record["result"]["exit_code"] = 9
            record_path = root / "execution.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "record digest"):
                execution_record.verify(record_path)

    def test_output_and_trace_are_required_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = self.fixture(root)
            descriptor = json.loads(descriptor_path.read_text())
            del descriptor["trace"]["root_sha256"]
            descriptor_path.write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError, "trace root"):
                execution_record.build(descriptor_path)

            descriptor_path = self.fixture(root)
            record = execution_record.build(descriptor_path)
            record_path = root / "execution.json"
            record_path.write_text(json.dumps(record))
            (root / "output.txt").write_bytes(b"changed output")
            with self.assertRaisesRegex(ValueError, "artifact (size|digest) differs"):
                execution_record.verify(record_path)

    def test_paths_cannot_escape_record_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = self.fixture(root)
            descriptor = json.loads(descriptor_path.read_text())
            descriptor["runtime"] = "../runtime.wasm"
            descriptor_path.write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError, "relative and contained"):
                execution_record.build(descriptor_path)

    def test_booleans_are_not_accepted_as_integer_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = self.fixture(root)
            descriptor = json.loads(descriptor_path.read_text())
            descriptor["result"]["instruction_count"] = True
            descriptor_path.write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError, "instruction count"):
                execution_record.build(descriptor_path)

            descriptor_path = self.fixture(root)
            descriptor = json.loads(descriptor_path.read_text())
            descriptor["network"]["receipts"][0]["bytes_sent"] = False
            descriptor_path.write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError, "bytes_sent"):
                execution_record.build(descriptor_path)

    def test_exit_code_is_required_and_artifact_envelopes_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = self.fixture(root)
            descriptor = json.loads(descriptor_path.read_text())
            del descriptor["result"]["exit_code"]
            descriptor_path.write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError, "exit code"):
                execution_record.build(descriptor_path)

            record = execution_record.build(self.fixture(root))
            record["build"]["runtime"]["unverified"] = True
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = execution_record.hashlib.sha256(
                execution_record.canonical(unsigned)
            ).hexdigest()
            record_path = root / "execution.json"
            record_path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "envelope"):
                execution_record.verify(record_path)


if __name__ == "__main__":
    unittest.main()
