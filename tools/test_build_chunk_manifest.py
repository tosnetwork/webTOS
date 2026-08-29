#!/usr/bin/env python3
"""Regression gates for deterministic chunk-manifest construction."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import build_chunk_manifest


class ChunkManifestBuildTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        source = root / "source"
        (source / "bin").mkdir(parents=True)
        program = source / "bin" / "agent"
        program.write_bytes(b"agent bytes" * 1000)
        program.chmod(0o755)
        (source / "bin" / "agent-link").symlink_to("agent")
        return source

    def build(self, source: Path, output: Path) -> bytes:
        return build_chunk_manifest.build(source, output, b"/", 4096, 123456789)

    def test_host_mtimes_and_checkout_path_do_not_change_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_source = self.fixture(root / "one")
            second_source = self.fixture(root / "two")
            for index, path in enumerate(second_source.rglob("*"), start=1):
                if not path.is_symlink():
                    os.utime(path, (index, 2_000_000_000 - index))
            first = root / "first"
            second = root / "second"
            self.assertEqual(self.build(first_source, first), self.build(second_source, second))
            self.assertEqual(
                sorted(path.name for path in (first / "chunks").iterdir()),
                sorted(path.name for path in (second / "chunks").iterdir()),
            )

    def test_stale_chunks_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            output = root / "output"
            self.build(source, output)
            stale = output / "chunks" / ("0" * 64)
            stale.write_bytes(b"stale")
            self.build(source, output)
            self.assertFalse(stale.exists())

    def test_content_change_moves_manifest_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            output = root / "output"
            before = self.build(source, output)
            (source / "bin" / "agent").write_bytes(b"changed")
            after = self.build(source, output)
            self.assertNotEqual(before, after)

    def test_output_inside_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            with self.assertRaisesRegex(ValueError, "inside the source"):
                self.build(source, source / "output")

    def test_cli_accepts_default_root_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            result = subprocess.run(
                [
                    "python3",
                    "-B",
                    str(Path(__file__).with_name("build_chunk_manifest.py")),
                    str(source),
                    str(root / "output"),
                    "--source-epoch",
                    "0",
                    "--legacy-fnv",
                    "zero",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertRegex(result.stdout, r"manifest-root [0-9a-f]{64}")


if __name__ == "__main__":
    unittest.main()
