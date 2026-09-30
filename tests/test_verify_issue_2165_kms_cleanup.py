from __future__ import annotations

import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from verify_issue_2165_kms_cleanup import CleanupReceiptError, verify_cleanup_rollback  # noqa: E402
from test_issue_2165_kms_runtime import fixture  # noqa: E402


NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
RUN_ID = "1234567"


def at(minute: int) -> str:
    return f"2026-09-30T11:{minute:02d}:00Z"


class CleanupCloudTrailTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.env = fixture()
        self.env.update({"GITHUB_RUN_ID": RUN_ID, "B083_TARGET_MANIFEST_SECRET_ARN": "secret-ref"})
        self.manifest["expires_at"] = "2026-09-30T23:59:00Z"
        role = self.manifest["aws"]["custodian_role_arn"]
        account = self.manifest["aws"]["account_id"]
        preflight = "arn:aws:iam::123456789012:role/kms-preflight"
        self.env["B083_AWS_PREFLIGHT_ROLE_ARN"] = preflight
        self.caller = {"Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/{preflight.rsplit('/', 1)[-1]}/i2165-cleanup-readback-{RUN_ID}"}
        self.receipt = {
            "schema": "corelink.issue-2165-kms-custodian-receipt-v1", "stage": "cleanup-rollback", "run_id": RUN_ID,
            "observed_at_utc": at(53), "receipt_sha256": "b" * 64,
            "actions": [
                {"operation": "cancel-key-deletion", "key_arn": self.manifest["aws"]["cmk_arn"], "readback": "Disabled"},
                {"operation": "enable-key", "key_arn": self.manifest["aws"]["cmk_arn"], "readback": "Enabled"},
            ],
        }
        key = self.manifest["aws"]["cmk_arn"]
        self.cloudtrail = {"Events": [
            self.event("cleanup-evt-cancel", "CancelKeyDeletion", 50, key, {}),
            self.event("cleanup-evt-enable", "EnableKey", 51, key, {}),
            self.event("cleanup-evt-describe", "DescribeKey", 52, key, {"keyMetadata": {"arn": key, "keyState": "Enabled"}}),
        ]}

    def event(self, event_id, name, minute, key, response):
        account = self.manifest["aws"]["account_id"]
        role = self.manifest["aws"]["custodian_role_arn"]
        arn = f"arn:aws:sts::{account}:assumed-role/{role.rsplit('/', 1)[-1]}/i2165-key-cleanup-{RUN_ID}"
        nested = {
            "eventID": event_id, "eventName": name, "eventTime": at(minute),
            "eventSource": "kms.amazonaws.com", "awsRegion": "us-east-1", "recipientAccountId": account,
            "requestParameters": {"keyId": key}, "responseElements": response,
            "userIdentity": {"type": "AssumedRole", "accountId": account, "arn": arn,
                "sessionContext": {"sessionIssuer": {"arn": role}}},
        }
        return {"EventId": event_id, "EventName": name, "EventSource": "kms.amazonaws.com", "EventTime": at(minute), "CloudTrailEvent": json.dumps(nested)}

    def verify(self):
        return verify_cleanup_rollback(self.manifest, self.env, self.receipt, self.cloudtrail, self.caller, now=NOW)

    def test_accepts_exact_ordered_cancel_enable_enabled_readback(self):
        result = self.verify()
        self.assertTrue(result["cancel_performed"])
        self.assertEqual(result["readback"], "Enabled")
        self.assertIn("cloudtrail:cleanup-evt-cancel/cleanup-evt-enable/cleanup-evt-describe", result["event_ref"])

    def test_cleanup_readback_accepts_expired_manifest_for_recovery(self):
        self.manifest["expires_at"] = "2026-09-30T11:30:00Z"
        result = self.verify()
        self.assertTrue(result["cancel_performed"])
        self.assertEqual(result["readback"], "Enabled")

    def test_expired_recovery_still_rejects_wrong_protected_target(self):
        self.manifest["expires_at"] = "2026-09-30T11:30:00Z"
        self.env["B083_AWS_ACCOUNT_ID"] = "999999999999"
        with self.assertRaisesRegex(CleanupReceiptError, "protected target manifest"):
            self.verify()

    def test_readback_requires_cancel_receipt_when_gated(self):
        self.receipt["actions"] = [{"operation": "revoke-grant", "readback": "absent"}]
        self.cloudtrail = {"Events": []}
        with self.assertRaisesRegex(CleanupReceiptError, "does not record a key cancellation"):
            self.verify()

    def test_rejects_missing_cancel_or_enable_or_enabled_describe(self):
        for name in ("CancelKeyDeletion", "EnableKey", "DescribeKey"):
            with self.subTest(name=name):
                evidence = copy.deepcopy(self.cloudtrail)
                evidence["Events"] = [event for event in evidence["Events"] if event["EventName"] != name]
                with self.assertRaises(CleanupReceiptError):
                    verify_cleanup_rollback(self.manifest, self.env, self.receipt, evidence, self.caller, now=NOW)

    def test_rejects_reordered_enable_before_cancel(self):
        evidence = copy.deepcopy(self.cloudtrail)
        event = next(row for row in evidence["Events"] if row["EventName"] == "EnableKey")
        event["EventTime"] = at(49)
        nested = json.loads(event["CloudTrailEvent"])
        nested["eventTime"] = event["EventTime"]
        event["CloudTrailEvent"] = json.dumps(nested)
        with self.assertRaisesRegex(CleanupReceiptError, "EnableKey"):
            verify_cleanup_rollback(self.manifest, self.env, self.receipt, evidence, self.caller, now=NOW)

    def test_rejects_wrong_key_event(self):
        evidence = copy.deepcopy(self.cloudtrail)
        event = evidence["Events"][0]
        nested = json.loads(event["CloudTrailEvent"])
        nested["requestParameters"]["keyId"] = "arn:aws:kms:us-east-1:123456789012:key/foreign"
        event["CloudTrailEvent"] = json.dumps(nested)
        with self.assertRaisesRegex(CleanupReceiptError, "CancelKeyDeletion"):
            verify_cleanup_rollback(self.manifest, self.env, self.receipt, evidence, self.caller, now=NOW)

    def test_rejects_foreign_cleanup_session(self):
        caller = dict(self.caller)
        caller["Arn"] = caller["Arn"].replace(f"i2165-cleanup-readback-{RUN_ID}", "other-session")
        with self.assertRaisesRegex(CleanupReceiptError, "exact read-only preflight session"):
            verify_cleanup_rollback(self.manifest, self.env, self.receipt, self.cloudtrail, caller, now=NOW)


if __name__ == "__main__":
    unittest.main()
