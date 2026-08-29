#!/usr/bin/env python3
"""Regression gates for reproducible workload archives."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

import build_chunk_manifest
import build_workload_image
import package_release
import verify_workload_image


class WorkloadImageTests(unittest.TestCase):
    def source(self, root: Path) -> Path:
        source = root / "source"
        (source / "bin").mkdir(parents=True)
        agent = source / "bin" / "agent"
        agent.write_bytes(b"workload payload")
        agent.chmod(0o755)
        return source

    def spec(self, root: Path, source: Path) -> Path:
        scratch = root / "scratch"
        manifest = build_chunk_manifest.build(source, scratch, b"/", 4096, 42, False)
        payload = (source / "bin" / "agent").read_bytes()
        document = {
            "expected_manifest_sha256": build_workload_image.sha256(manifest),
            "files": [
                {
                    "license": "MIT",
                    "mode": "755",
                    "path": "/bin/agent",
                    "redistribution": "permitted",
                    "sha256": build_workload_image.sha256(payload),
                    "size": len(payload),
                }
            ],
            "id": "agent-test",
            "schema_version": 1,
            "source": [
                {
                    "digest": {"sha256": build_workload_image.sha256(payload)},
                    "uri": "test:agent",
                }
            ],
            "version": "1.0.0",
        }
        path = root / "spec.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def build(self, root: Path, source: Path, spec: Path) -> Path:
        archive = root / "agent.tar"
        args = argparse.Namespace(
            archive=archive,
            chunk_size=4096,
            output=root / "image",
            source=source,
            source_epoch=42,
            spec=spec,
            workload_id=None,
        )
        return build_workload_image.build(args)

    def test_two_checkout_paths_and_mtimes_produce_identical_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_root = root / "first"
            second_root = root / "second"
            first_source = self.source(first_root)
            second_source = self.source(second_root)
            os.utime(second_source / "bin" / "agent", (1, 2_000_000_000))
            spec = self.spec(root, first_source)
            first = self.build(first_root, first_source, spec)
            second = self.build(second_root, second_source, spec)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            descriptor = verify_workload_image.verify(first)
            self.assertEqual(descriptor["id"], "agent-test")

    def test_locked_payload_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.source(root)
            spec = self.spec(root, source)
            (source / "bin" / "agent").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "do not match"):
                self.build(root, source, spec)

    def test_license_inventory_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.source(root)
            spec = self.spec(root, source)
            self.build(root, source, spec)
            (root / "image" / "LICENSES.json").write_text(
                '{"schema_version":1,"files":[{"license":"NOASSERTION",'
                '"redistribution":"unknown"}]}\n',
                encoding="utf-8",
            )
            tampered = root / "tampered.tar"
            package_release.create(root / "image", tampered, "tampered")
            with self.assertRaisesRegex(ValueError, "LICENSES.json"):
                verify_workload_image.verify(tampered)


if __name__ == "__main__":
    unittest.main()
