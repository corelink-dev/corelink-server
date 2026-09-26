from __future__ import annotations
import runpy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_load_teardown_receipt import TeardownReceiptError, validate

def receipt() -> dict[str, object]:
    resources: dict[str, dict[str, int]] = {}
    retained = {"cas_reference", "dsr_obligation", "audit_evidence", "billing_audit"}
    for name in {"cas_reference", "webhook_inbox", "webhook_effect", "dsr_artifact", "dsr_obligation", "audit_evidence", "billing_audit", "signup_artifact", "byok_artifact"}:
        resources[name] = {"inventory": 0, "attempted": 0, "deleted": 0, "preserved": 0, "quarantined": 0, "remaining": 0}
        if name in retained:
            resources[name]["preserved"] = 0
    return {"schema": "corelink.staging-load-test-teardown-receipt.v2", "run_id": "123", "scenario": "cas", "target_deployment_sha": "a" * 40, "terminal_state": "reconciled", "resources": resources, "cross_run_deletions": 0}

class TeardownContractTests(unittest.TestCase):
    def test_static_guard(self) -> None:
        runpy.run_path(str(ROOT / "scripts/verify_issue_2584_teardown.py"))["verify"]()

    def test_exact_nine_class_receipt_is_accepted(self) -> None:
        self.assertEqual(validate(receipt(), run_id="123", scenario="cas", deployment_sha="a" * 40)["terminal_state"], "reconciled")

    def test_identity_cross_run_partial_and_redaction_fail_closed(self) -> None:
        for mutate in (
            lambda value: value.__setitem__("run_id", "124"),
            lambda value: value.__setitem__("cross_run_deletions", 1),
            lambda value: value["resources"]["webhook_inbox"].__setitem__("remaining", 1),
            lambda value: value.__setitem__("opaque_handle", "must-not-appear"),
        ):
            value = receipt()
            mutate(value)
            with self.assertRaises(TeardownReceiptError):
                validate(value, run_id="123", scenario="cas", deployment_sha="a" * 40)

    def test_webhook_effect_teardown_binds_the_complete_locator(self) -> None:
        source = (ROOT / "crates/corelink-container/src/storage/staging_load_test_ownership.rs").read_text()
        self.assertIn('payload.get("effect_key")', source)
        self.assertIn("WHERE event_id=?1 AND effect_key=?2 RETURNING event_id", source)
        self.assertIn("WHERE event_id=?1 AND effect_key=?2\"", source)

if __name__ == "__main__":
    unittest.main()
