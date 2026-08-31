"""Regression tests for the DOM production-readiness manifest gate."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-production-readiness-manifest.py"
MANIFEST = (
    ROOT
    / "docs/interop/reports/DOM-PRODUCTION-READINESS-MANIFEST-2026-08-27.json"
)
SPEC = importlib.util.spec_from_file_location("production_readiness_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ProductionReadinessManifestTests(unittest.TestCase):
    def payload(self) -> dict:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    def validate_payload(self, payload: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return GATE.validate(path)

    def requirement(self, payload: dict, item_id: str) -> dict:
        return next(item for item in payload["requirements"] if item["id"] == item_id)

    def test_canonical_manifest_passes(self) -> None:
        self.assertEqual(GATE.validate(MANIFEST), [])

    def test_p0_cannot_be_downgraded_to_advisory(self) -> None:
        payload = self.payload()
        self.requirement(payload, "PRD-001")["release_blocker"] = False
        self.assertIn("PRD-001: P0 is not a blocker", self.validate_payload(payload))

    def test_contracts_cannot_be_counted_as_snapshot_delivery(self) -> None:
        payload = self.payload()
        self.requirement(payload, "PRD-016")["snapshot_status"] = "present"
        errors = self.validate_payload(payload)
        self.assertTrue(any("contracts counted in snapshot" in error for error in errors))

    def test_product_target_cannot_be_an_acceptance_harness(self) -> None:
        payload = self.payload()
        self.requirement(payload, "PRD-003")["target"] = "crates/f5-e2e"
        self.assertIn(
            "PRD-003: acceptance harness is named as product target",
            self.validate_payload(payload),
        )

    def test_dependency_cycle_is_rejected(self) -> None:
        payload = self.payload()
        self.requirement(payload, "PRD-001")["depends_on"] = ["PRD-002"]
        self.assertTrue(
            any(error.startswith("dependency cycle:") for error in self.validate_payload(payload))
        )

    def test_blocker_must_be_scheduled_in_a_milestone(self) -> None:
        payload = self.payload()
        for milestone in payload["milestones"]:
            milestone["requirements"] = [
                item for item in milestone["requirements"] if item != "PRD-036"
            ]
        self.assertIn("release blockers are missing from milestones", self.validate_payload(payload))

    def test_manifest_cannot_claim_a_push(self) -> None:
        payload = self.payload()
        payload["audit"]["push_performed"] = True
        self.assertIn("manifest claims a push was performed", self.validate_payload(payload))


if __name__ == "__main__":
    unittest.main()
