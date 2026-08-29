#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import build_alpine_license_inventory as inventory


class AlpineLicenseInventoryTests(unittest.TestCase):
    def record(self, license_expression: str = "MIT") -> str:
        return (
            "P:demo\nV:1.2.3-r0\nU:https://example.test/demo\n"
            f"L:{license_expression}\no:demo-origin\n"
        )

    def test_package_fields_and_decision_are_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary) / "installed"
            installed.write_text(self.record(), encoding="utf-8")
            package = inventory.build(installed)["packages"][0]
            self.assertEqual(package["name"], "demo")
            self.assertEqual(package["version"], "1.2.3-r0")
            self.assertEqual(package["license"], "MIT")
            self.assertEqual(package["redistribution"], "allowed_with_obligations")
            self.assertTrue(package["obligations"])

    def test_undecided_license_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary) / "installed"
            installed.write_text(self.record("LicenseRef-Unknown"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no redistribution decision"):
                inventory.build(installed)


if __name__ == "__main__":
    unittest.main()
