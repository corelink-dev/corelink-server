"""Credentialless contract tests for issue #1649's restricted test-key lane."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stripe_test_mode_evidence.py"
WORKFLOW = ROOT / ".github" / "workflows" / "issue-1649-stripe-test-mode.yml"
SPEC = importlib.util.spec_from_file_location("stripe_test_mode_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StripeRestrictedKeyContractTests(unittest.TestCase):
    def test_identity_only_performs_one_read_and_records_boolean_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            with patch.object(
                MODULE,
                "request_json",
                return_value=(200, {"object": "account", "id": "acct_expected"}),
            ) as request:
                result = MODULE.run_identity_probe(
                    "rk_test_fixture", "123456", "acct_expected", output
                )
            self.assertEqual(result, 0)
            request.assert_called_once_with("rk_test_fixture", "GET", "/v1/account")
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertIs(receipt["livemode"], False)
            self.assertIs(receipt["account_matches_expected"], True)
            self.assertEqual(receipt["provider_mutations"], 0)
            self.assertEqual(receipt["requests"], ["GET /v1/account"])
            self.assertNotIn("acct_expected", receipt_text)
            self.assertNotIn("rk_test_fixture", receipt_text)

    def test_identity_only_records_wrong_account_without_exposing_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            with patch.object(
                MODULE,
                "request_json",
                return_value=(200, {"object": "account", "id": "acct_other"}),
            ) as request:
                with self.assertRaises(MODULE.ProbeError):
                    MODULE.run_identity_probe(
                        "rk_test_fixture", "123456", "acct_expected", output
                    )
            request.assert_called_once_with("rk_test_fixture", "GET", "/v1/account")
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertIs(receipt["account_matches_expected"], False)
            self.assertIs(receipt["livemode"], False)
            self.assertNotIn("acct_other", receipt_text)

    def test_identity_only_rejects_non_test_key_before_request(self) -> None:
        with patch.object(MODULE, "request_json") as request:
            with self.assertRaises(MODULE.ProbeError):
                MODULE.run_identity_probe(
                    "rk_live_fixture", "123456", "acct_expected", Path("unused-receipt.json")
                )
        request.assert_not_called()

    def test_restricted_test_key_runs_only_through_mocked_requests(self) -> None:
        responses = [
            (200, {"object": "account", "id": "acct_fixture"}),
            (200, {"livemode": False, "id": "cus_fixture"}),
            (200, {"livemode": False, "id": "cus_fixture"}),
            (200, {"livemode": False, "id": "cus_fixture"}),
            (200, {"deleted": True, "id": "cus_fixture"}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            with patch.object(MODULE, "request_json", side_effect=responses) as request:
                result = MODULE.run_probe("rk_test_fixture", "123456", output)
            self.assertEqual(result, 0)
            self.assertEqual(request.call_count, 5)
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertIs(receipt["livemode"], False)
            self.assertTrue(receipt["idempotency_replayed"])
            self.assertTrue(receipt["cleanup"]["succeeded"])
            self.assertNotIn("rk_test_fixture", receipt_text)

    def test_account_response_requires_account_identity_without_livemode(self) -> None:
        for account in (
            {"object": "account"},
            {"object": "customer", "id": "cus_fixture"},
            {"object": "account", "id": "cus_fixture"},
        ):
            with self.subTest(account_shape=account):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "receipt.json"
                    with patch.object(
                        MODULE, "request_json", return_value=(200, account)
                    ) as request:
                        with self.assertRaises(MODULE.ProbeError):
                            MODULE.run_probe("rk_test_fixture", "123456", output)
                    self.assertEqual(request.call_count, 1)
                    receipt = json.loads(output.read_text(encoding="utf-8"))
                    self.assertIsNone(receipt["livemode"])
                    self.assertEqual(receipt["ordering"], [])

    def test_non_restricted_or_non_test_prefixes_fail_before_requests(self) -> None:
        for key in ("sk_test_fixture", "sk_live_fixture", "rk_live_fixture", "malformed"):
            with self.subTest(key_class=key.split("_", maxsplit=2)[0:2]):
                with patch.object(MODULE, "request_json") as request:
                    with self.assertRaises(MODULE.ProbeError):
                        MODULE.run_probe(key, "123456", Path("unused-receipt.json"))
                request.assert_not_called()

    def test_workflow_contract_rejects_weak_prefix_or_missing_permissions(self) -> None:
        original = WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            original.replace("rk_test_", "sk_test_"),
            original.replace("Accounts: Read", "Accounts: Write"),
            original.replace("Customers: Write", "Customers: Read"),
            original.replace("identity-only", "customer-mutation-only"),
            original.replace("STRIPE_TEST_ACCOUNT_ID", "STRIPE_OTHER_ACCOUNT_ID"),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "workflow.yml"
                    path.write_text(mutated, encoding="utf-8")
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(MODULE.contract_check(path), 1)


if __name__ == "__main__":
    unittest.main()
