#!/usr/bin/env python3
"""Regression gates for canonical release packaging."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import package_release


class PackageReleaseTests(unittest.TestCase):
    def test_host_metadata_does_not_change_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            program = stage / "engine.wasm"
            program.write_bytes(b"wasm bytes")
            first = root / "first.tar"
            second = root / "second.tar"
            package_release.create(stage, first, "webtos-runtime-test")
            os.chmod(program, 0o600)
            os.utime(program, (1_900_000_000, 1_900_000_000))
            package_release.create(stage, second, "webtos-runtime-test")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            package_release.verify(first, expected_files=None)
            package_release.verify(second, expected_files=None)

    def test_payload_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            (stage / "engine.wasm").write_bytes(b"wasm bytes")
            archive = root / "release.tar"
            package_release.create(stage, archive, "webtos-runtime-test")
            sidecar = archive.with_name(archive.name + ".sha256")
            sidecar.write_text("0" * 64 + f"  {archive.name}\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "sidecar digest mismatch"):
                package_release.verify(archive, expected_files=None)

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            (stage / "payload").write_bytes(b"payload")
            (stage / "link").symlink_to("payload")
            with self.assertRaisesRegex(ValueError, "symlink"):
                package_release.create(
                    stage, root / "release.tar", "webtos-runtime-test"
                )


if __name__ == "__main__":
    unittest.main()
