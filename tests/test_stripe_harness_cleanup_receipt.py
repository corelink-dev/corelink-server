from __future__ import annotations

import unittest

from scripts.verify_stripe_harness_cleanup_receipt import validate


class StripeHarnessCleanupReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "987654321-2"
        rows = (
            ("live_create_customer", "customer", "deleted_readback_pass", "1"),
            ("live_create_checkout_session_starter", "checkout", "expired_readback_pass", "2"),
            ("live_create_checkout_session_starter", "customer", "deleted_readback_pass", "3"),
            ("live_create_checkout_session_starter", "price", "archived_readback_pass", "7"),
            ("live_create_checkout_session_starter", "product", "archived_readback_pass", "8"),
            ("live_idempotent_checkout_returns_same_session", "checkout", "expired_readback_pass", "4"),
            ("live_idempotent_checkout_returns_same_session", "customer", "deleted_readback_pass", "5"),
            ("live_idempotent_checkout_returns_same_session", "price", "archived_readback_pass", "9"),
            ("live_idempotent_checkout_returns_same_session", "product", "archived_readback_pass", "10"),
            ("live_billing_portal_session", "customer", "deleted_readback_pass", "6"),
        )
        self.lines = [
            '{"run_id":"%s","test":"%s","kind":"%s","id_sha256":"%064x","status":"%s"}'
            % (self.run_id, test, kind, int(digest), status)
            for test, kind, status, digest in rows
        ]

    def test_accepts_complete_redacted_receipt(self) -> None:
        self.assertTrue(validate(self.lines, self.run_id))

    def test_rejects_missing_cleanup(self) -> None:
        self.assertFalse(validate(self.lines[:-1], self.run_id))

    def test_rejects_missing_or_unarchived_starter_fixture(self) -> None:
        # direct-test (#2565): every Starter fixture must be archived with
        # readback; a missing row or any other status keeps the run red.
        for kind in ("price", "product"):
            missing = [line for line in self.lines if f'"kind":"{kind}"' not in line]
            self.assertEqual(len(missing), len(self.lines) - 2)
            self.assertFalse(validate(missing, self.run_id))
            unarchived = [
                line.replace("archived_readback_pass", "cleanup_failed")
                if f'"kind":"{kind}"' in line
                else line
                for line in self.lines
            ]
            self.assertNotEqual(unarchived, self.lines)
            self.assertFalse(validate(unarchived, self.run_id))
        stray = self.lines + [
            self.lines[0].replace('"kind":"customer"', '"kind":"price"').replace(
                "deleted_readback_pass", "archived_readback_pass"
            )
        ]
        self.assertFalse(validate(stray, self.run_id))

    def test_rejects_wrong_run_or_unredacted_id(self) -> None:
        wrong_run = self.lines.copy()
        wrong_run[0] = wrong_run[0].replace(self.run_id, "other-run")
        self.assertFalse(validate(wrong_run, self.run_id))
        raw_id = self.lines.copy()
        raw_id[0] = raw_id[0].replace("0" * 63 + "1", "cus_test_raw_object_id")
        self.assertFalse(validate(raw_id, self.run_id))


if __name__ == "__main__":
    unittest.main()
