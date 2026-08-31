"""Regression tests for the absorption decision gate."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-absorption-manifest.py"
MANIFEST = (
    ROOT
    / "docs/interop/reports/DOM-CODE-FIRST-ABSORPTION-MANIFEST-2026-08-27.json"
)
SPEC = importlib.util.spec_from_file_location("absorption_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class AbsorptionManifestTests(unittest.TestCase):
    def payload(self) -> dict:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    def validate_payload(self, payload: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return GATE.validate(path)

    def test_canonical_manifest_passes(self) -> None:
        self.assertEqual(GATE.validate(MANIFEST), [])

    def test_restricted_source_cannot_enable_direct_copy(self) -> None:
        payload = self.payload()
        payload["decisions"][0]["production_copy_policy"] = "direct-copy"
        self.assertTrue(
            any("restricted source allows direct copy" in item for item in self.validate_payload(payload))
        )

    def test_release_priority_requires_acceptance_tests(self) -> None:
        payload = self.payload()
        target = next(item for item in payload["decisions"] if item["id"] == "KEY-01")
        target["acceptance_tests"] = []
        self.assertTrue(
            any("KEY-01: missing acceptance tests" == item for item in self.validate_payload(payload))
        )

    def test_quarantined_item_cannot_be_p0(self) -> None:
        payload = self.payload()
        target = next(item for item in payload["decisions"] if item["id"] == "KEY-08")
        target["priority"] = "P0"
        self.assertTrue(
            any("KEY-08: rejected item is release-prioritized" == item for item in self.validate_payload(payload))
        )


if __name__ == "__main__":
    unittest.main()
