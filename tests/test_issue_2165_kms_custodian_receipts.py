from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from issue_2165_kms_custodian_receipts import CustodianReceiptError, _canonical_digest, build_receipts  # noqa: E402
from test_issue_2165_kms_runtime import fixture  # noqa: E402


NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
RUN_ID = "1234567"


def utc(minute: int) -> str:
    return f"2026-09-30T11:{minute:02d}:00Z"


class EvidenceFixture:
    def __init__(self):
        self.manifest, self.env = fixture()
        self.env.update({"GITHUB_RUN_ID": RUN_ID, "B083_CUSTODIAN_REF": "restricted://root/i2165/custodian-authority"})
        self.manifest["custodian_authority"] = {
            "ref": self.env["B083_CUSTODIAN_REF"],
            "cmk_arn": self.manifest["aws"]["cmk_arn"],
            "custodian_role_arn": self.manifest["aws"]["custodian_role_arn"],
        }
        self.manifest["lifecycle_window"] = {"started_at_ms": int(datetime(2026, 9, 30, 11, tzinfo=timezone.utc).timestamp() * 1000), "ended_at_ms": int(datetime(2026, 9, 30, 12, tzinfo=timezone.utc).timestamp() * 1000)}
        self.customer_key = {"KeyMetadata": {"Arn": self.manifest["aws"]["cmk_arn"], "AWSAccountId": self.manifest["aws"]["account_id"], "KeyManager": "CUSTOMER", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled"}}
        role = self.manifest["aws"]["custodian_role_arn"]
        self.caller = {"Account": self.manifest["aws"]["account_id"], "Arn": f"arn:aws:sts::{self.manifest['aws']['account_id']}:assumed-role/{role.rsplit('/', 1)[-1]}/i2165-custodian-{RUN_ID}"}
        self.folder = Path(tempfile.mkdtemp())
        self.add_receipt("rotate", 32, {"operation": "rotate-key-on-demand", "readback": "in-progress"})
        self.add_receipt("schedule", 41, {"operation": "schedule-key-deletion", "readback": "PendingDeletion", "deletion_executed": False})
        self.add_receipt("cancel", 53, [
            {"operation": "cancel-key-deletion", "key_arn": self.manifest["aws"]["cmk_arn"], "readback": "Disabled"},
            {"operation": "enable-key", "key_arn": self.manifest["aws"]["cmk_arn"], "readback": "Enabled"},
        ])
        self.add_receipt("grant", 58, {"operation": "create-grant", "grant_id": "grant-1", "operations": ["Encrypt", "Decrypt", "DescribeKey"], "readback": "exact"})
        key = self.manifest["aws"]["cmk_arn"]
        self.cloudtrail = {"Events": [
            self.event("event-00000001", "DescribeKey", 20, {"keyId": key}, {"keyMetadata": {"arn": key, "keyManager": "CUSTOMER", "keyState": "Enabled"}}),
            self.event("event-00000002", "RotateKeyOnDemand", 30, {"keyId": key}, {"keyId": key}),
            self.event("event-00000003", "GetKeyRotationStatus", 31, {"keyId": key}, {"keyRotationEnabled": True}),
            self.event("event-00000004", "ScheduleKeyDeletion", 40, {"keyId": key, "pendingWindowInDays": 7}, {"keyId": key}),
            self.event("event-00000005", "CancelKeyDeletion", 50, {"keyId": key}, {"keyId": key}),
            self.event("event-00000006", "EnableKey", 51, {"keyId": key}, {"keyId": key}),
            self.event("event-00000007", "DescribeKey", 52, {"keyId": key}, {"keyMetadata": {"arn": key, "keyManager": "CUSTOMER", "keyState": "Enabled"}}),
            self.event("event-00000008", "CreateGrant", 57, {"keyId": key, "name": f"issue-2165-{RUN_ID}", "granteePrincipal": self.manifest["aws"]["runtime_role_arn"], "operations": ["Encrypt", "Decrypt", "DescribeKey"]}, {"grantId": "grant-1"}),
        ]}

    def add_receipt(self, stage: str, minute: int, action: dict):
        sub = {"rotate": "key-rotate", "schedule": "key-schedule", "cancel": "key-cancel", "grant": "initial-grant"}[stage]
        folder = self.folder / sub
        folder.mkdir(exist_ok=True)
        actions = action if isinstance(action, list) else [action]
        body = {"schema": "corelink.issue-2165-kms-custodian-receipt-v1", "stage": stage, "run_id": RUN_ID, "observed_at_utc": utc(minute), "actions": actions}
        body["receipt_sha256"] = _canonical_digest({"stage": stage, "run_id": RUN_ID, "actions": body["actions"]})
        path = folder / f"custodian-{stage}-receipt.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        path.chmod(0o600)

    def event(self, event_id, name, minute, params, response):
        at = utc(minute)
        account = self.manifest["aws"]["account_id"]
        role = self.manifest["aws"]["custodian_role_arn"]
        nested = {"eventID": event_id, "eventName": name, "eventTime": at, "eventSource": "kms.amazonaws.com", "awsRegion": "us-east-1", "recipientAccountId": account, "requestParameters": params, "responseElements": response,
                  "userIdentity": {"type": "AssumedRole", "accountId": account, "arn": self.caller["Arn"], "sessionContext": {"sessionIssuer": {"arn": role}}}}
        return {"EventId": event_id, "EventName": name, "EventSource": "kms.amazonaws.com", "EventTime": at, "CloudTrailEvent": json.dumps(nested)}

    def run(self, **kwargs):
        return build_receipts(self.manifest, self.env, self.folder, self.cloudtrail, self.caller, customer_key_readback=self.customer_key, now=NOW, **kwargs)


class CustodianReceiptTests(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceFixture()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.evidence.folder, ignore_errors=True))

    def test_emits_exact_three_rows_with_distinct_direct_provider_event_ids(self):
        rows = self.evidence.run()
        self.assertEqual({row["step"] for row in rows}, {"customer_create_or_import", "rotate", "deletion_schedule"})
        self.assertTrue(all(set(row) == {"step", "occurred_at_utc", "source"} for row in rows))
        self.assertTrue(all(set(row["source"]) == {"kind", "event_ref", "digest"} for row in rows))
        refs = [row["source"]["event_ref"] for row in rows]
        self.assertEqual(len(set(refs)), 3)
        self.assertTrue(all(ref.startswith("cloudtrail:event-") for ref in refs))
        schedule = next(row for row in rows if row["step"] == "deletion_schedule")
        self.assertIn("event-00000004", schedule["source"]["event_ref"])
        self.assertIn("event-00000005", schedule["source"]["event_ref"])
        self.assertIn("event-00000006", schedule["source"]["event_ref"])
        self.assertIn("event-00000007", schedule["source"]["event_ref"])

    def test_requires_restricted_customer_custody_authority_bound_to_key_and_role(self):
        self.evidence.manifest.pop("custodian_authority")
        with self.assertRaisesRegex(CustodianReceiptError, "custodian authority"):
            self.evidence.run()
        self.evidence.manifest["custodian_authority"] = {"ref": "restricted://other", "cmk_arn": "arn:other", "custodian_role_arn": "arn:other"}
        with self.assertRaisesRegex(CustodianReceiptError, "custodian authority"):
            self.evidence.run()

    def test_requires_exact_enabled_customer_key_describe_readback(self):
        self.evidence.customer_key["KeyMetadata"]["KeyManager"] = "AWS"
        with self.assertRaisesRegex(CustodianReceiptError, "exact customer-managed Enabled key"):
            self.evidence.run()
        self.evidence.customer_key["KeyMetadata"]["KeyManager"] = "CUSTOMER"
        self.evidence.customer_key["KeyMetadata"]["KeyState"] = "PendingDeletion"
        with self.assertRaisesRegex(CustodianReceiptError, "exact customer-managed Enabled key"):
            self.evidence.run()

    def test_rejects_wrong_caller_or_cross_run_cloudtrail_session(self):
        wrong = dict(self.evidence.caller, Arn=self.evidence.caller["Arn"].replace("i2165-custodian-1234567", "i2165-custodian-7654321"))
        with self.assertRaisesRegex(CustodianReceiptError, "exact custodian role"):
            build_receipts(self.evidence.manifest, self.evidence.env, self.evidence.folder, self.evidence.cloudtrail, wrong, customer_key_readback=self.evidence.customer_key, now=NOW)
        cloudtrail = copy.deepcopy(self.evidence.cloudtrail)
        nested = json.loads(cloudtrail["Events"][0]["CloudTrailEvent"])
        nested["userIdentity"]["arn"] = wrong["Arn"]
        cloudtrail["Events"][0]["CloudTrailEvent"] = json.dumps(nested)
        with self.assertRaisesRegex(CustodianReceiptError, "exactly one authenticated DescribeKey"):
            build_receipts(self.evidence.manifest, self.evidence.env, self.evidence.folder, cloudtrail, self.evidence.caller, customer_key_readback=self.evidence.customer_key, now=NOW)

    def test_rejects_wrong_key_or_non_customer_managed_initial_describe(self):
        nested = json.loads(self.evidence.cloudtrail["Events"][0]["CloudTrailEvent"])
        nested["responseElements"]["keyMetadata"]["arn"] = "arn:aws:kms:us-east-1:123456789012:key/other"
        self.evidence.cloudtrail["Events"][0]["CloudTrailEvent"] = json.dumps(nested)
        with self.assertRaisesRegex(CustodianReceiptError, "exactly one authenticated DescribeKey"):
            self.evidence.run()

    def test_rejects_absent_rotation_status_and_past_or_future_events(self):
        self.evidence.cloudtrail["Events"] = [e for e in self.evidence.cloudtrail["Events"] if e["EventName"] != "GetKeyRotationStatus"]
        with self.assertRaisesRegex(CustodianReceiptError, "GetKeyRotationStatus"):
            self.evidence.run()
        e = self.evidence.event("event-00000003", "GetKeyRotationStatus", 59, {"keyId": self.evidence.manifest["aws"]["cmk_arn"]}, {"keyRotationEnabled": True})
        e["EventTime"] = "2026-09-30T12:01:00Z"
        nested = json.loads(e["CloudTrailEvent"])
        nested["eventTime"] = e["EventTime"]
        e["CloudTrailEvent"] = json.dumps(nested)
        self.evidence.cloudtrail["Events"].append(e)
        with self.assertRaisesRegex(CustodianReceiptError, "GetKeyRotationStatus"):
            self.evidence.run()

    def test_requires_schedule_cancel_enable_and_enabled_readback(self):
        self.evidence.cloudtrail["Events"] = [e for e in self.evidence.cloudtrail["Events"] if e["EventName"] != "CancelKeyDeletion"]
        with self.assertRaisesRegex(CustodianReceiptError, "CancelKeyDeletion"):
            self.evidence.run()

    def test_requires_enable_key_between_cancel_and_enabled_readback(self):
        self.evidence.cloudtrail["Events"] = [e for e in self.evidence.cloudtrail["Events"] if e["EventName"] != "EnableKey"]
        with self.assertRaisesRegex(CustodianReceiptError, "EnableKey"):
            self.evidence.run()

    def test_enable_key_cloudtrail_event_must_follow_cancel(self):
        event = next(e for e in self.evidence.cloudtrail["Events"] if e["EventName"] == "EnableKey")
        event["EventTime"] = utc(49)
        nested = json.loads(event["CloudTrailEvent"])
        nested["eventTime"] = event["EventTime"]
        event["CloudTrailEvent"] = json.dumps(nested)
        with self.assertRaisesRegex(CustodianReceiptError, "EnableKey"):
            self.evidence.run()

    def test_cancel_receipt_must_include_exact_key_enable_action(self):
        path = self.evidence.folder / "key-cancel" / "custodian-cancel-receipt.json"
        body = json.loads(path.read_text())
        body["actions"][1]["key_arn"] = "arn:wrong-key"
        body["receipt_sha256"] = _canonical_digest({"stage": "cancel", "run_id": RUN_ID, "actions": body["actions"]})
        path.write_text(json.dumps(body), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaisesRegex(CustodianReceiptError, "CancelKeyDeletion Disabled then EnableKey Enabled"):
            self.evidence.run()

    def test_rejects_mode_0644_helper_receipt(self):
        path = self.evidence.folder / "key-rotate" / "custodian-rotate-receipt.json"
        path.chmod(0o644)
        with self.assertRaisesRegex(CustodianReceiptError, "mode-0600"):
            self.evidence.run()

    def test_rejects_modified_or_wrong_run_helper_receipt(self):
        path = self.evidence.folder / "key-grant" / "custodian-grant-receipt.json"
        # Use the exact expected receipt location but tamper with the run field.
        path = self.evidence.folder / "initial-grant" / "custodian-grant-receipt.json"
        body = json.loads(path.read_text())
        body["run_id"] = "7654321"
        path.write_text(json.dumps(body))
        path.chmod(0o600)
        with self.assertRaisesRegex(CustodianReceiptError, "wrong schema, stage, or run"):
            self.evidence.run()


if __name__ == "__main__":
    unittest.main()
