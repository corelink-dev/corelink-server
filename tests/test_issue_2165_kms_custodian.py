"""Mocked negative and bounded-flow tests for Issue #2165 KMS custody."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from issue_2165_kms_custodian import CustodianError, _cancel_deadline, run_stage  # noqa: E402
from test_issue_2165_kms_runtime import fixture  # noqa: E402


class FakeAws:
    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.grants: list[dict] = []
        self.key_state = "Enabled"
        self.calls: list[list[str]] = []
        self.empty_actions: set[str] = set()
        self.rotation_status: dict = {"KeyId": manifest["aws"]["cmk_arn"], "KeyRotationEnabled": True}
        self.rotations: list[dict] = []
        self.seq = 0

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        service, action = command[1:3]
        if service == "sts":
            value = {"Account": self.manifest["aws"]["account_id"], "Arn": "arn:aws:sts::123456789012:assumed-role/kms-custodian/session"}
        elif service == "kms" and action == "describe-key":
            value = {"KeyMetadata": {"Arn": self.manifest["aws"]["cmk_arn"], "AWSAccountId": self.manifest["aws"]["account_id"], "KeyManager": "CUSTOMER", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": self.key_state, "KeyRotationEnabled": True}}
        elif service == "kms" and action == "list-grants":
            value = {"Grants": list(self.grants)}
        elif service == "kms" and action == "get-key-rotation-status":
            value = dict(self.rotation_status)
        elif service == "kms" and action == "list-key-rotations":
            value = {"Rotations": list(self.rotations), "Truncated": False}
        elif service == "kms" and action == "create-grant":
            self.seq += 1
            grant_id = f"grant-{self.seq}"
            self.grants.append({"GrantId": grant_id, "KeyId": self.manifest["aws"]["cmk_arn"], "GranteePrincipal": self.manifest["aws"]["runtime_role_arn"], "Operations": ["Encrypt", "Decrypt", "DescribeKey"], "Name": f"issue-2165-{__import__('os').environ['GITHUB_RUN_ID']}", "GrantToken": "must-not-be-written"})
            value = {"GrantId": grant_id, "GrantToken": "must-not-be-written"}
        elif service == "kms" and action == "revoke-grant":
            grant_id = command[command.index("--grant-id") + 1]
            self.grants = [g for g in self.grants if g["GrantId"] != grant_id]
            value = {"GrantId": grant_id}
        elif service == "kms" and action == "schedule-key-deletion":
            self.key_state = "PendingDeletion"
            value = {"KeyId": self.manifest["aws"]["cmk_arn"]}
        elif service == "kms" and action == "cancel-key-deletion":
            self.key_state = "Disabled"
            value = {"KeyId": self.manifest["aws"]["cmk_arn"]}
        elif service == "kms" and action == "enable-key":
            self.key_state = "Enabled"
            value = {"KeyId": self.manifest["aws"]["cmk_arn"]}
        elif service == "kms" and action == "rotate-key-on-demand":
            self.rotation_status["OnDemandRotationStartDate"] = 1790798400.0
            value = {"KeyId": self.manifest["aws"]["cmk_arn"]}
        else:
            raise AssertionError(f"unexpected AWS command: {command}")
        return SimpleNamespace(stdout="" if action in self.empty_actions else json.dumps(value))


class CustodianTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.env = fixture()
        self.env.update({"GITHUB_RUN_ID": "1234567", "GITHUB_SHA": "a" * 40, "B083_AWS_REGION": "us-east-1"})
        self.aws = FakeAws(self.manifest)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.dict("os.environ", self.env)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def _run_stage_at(self, stage: str, now: datetime):
        with patch("issue_2165_kms_custodian._cancel_deadline", side_effect=lambda manifest: _cancel_deadline(manifest, now=now)):
            return run_stage(stage, self.manifest, Path(self.temp.name), self.aws)

    def test_cancel_deadline_preserves_exact_expiry_boundary(self):
        _, manifest_env = fixture()
        deadline = datetime(2026, 9, 30, 13, 0, tzinfo=timezone.utc)
        manifest_env["key_deletion"] = {
            "disposable_key_ownership_approved": True,
            "ownership_approval_ref": "restricted://root/i2165/key",
            "pending_window_days": 7,
            "cancel_by": deadline.isoformat().replace("+00:00", "Z"),
        }
        self.assertEqual(_cancel_deadline(manifest_env, deadline - timedelta(seconds=1)), deadline)
        with self.assertRaisesRegex(CustodianError, "deadline has passed"):
            _cancel_deadline(manifest_env, deadline)

    def test_grant_creates_exact_operations_and_redacted_receipt(self):
        grant_id = run_stage("grant", self.manifest, Path(self.temp.name), self.aws)
        self.assertEqual(grant_id, "grant-1")
        self.assertEqual(len(self.aws.grants), 1)
        self.assertEqual(set(self.aws.grants[0]["Operations"]), {"Encrypt", "Decrypt", "DescribeKey"})
        receipt = json.loads((Path(self.temp.name) / "custodian-grant-receipt.json").read_text())
        self.assertNotIn("audit://", json.dumps(receipt))
        self.assertNotIn("GrantToken", json.dumps(receipt))
        self.assertNotIn("must-not-be-written", json.dumps(receipt))
        self.assertEqual((Path(self.temp.name) / "custodian-grant-receipt.json").stat().st_mode & 0o777, 0o600)

    def test_refuses_wrong_custodian_identity_before_key_mutation(self):
        calls = []
        def wrong_identity(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout=json.dumps({"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/other/session"}))

        with self.assertRaisesRegex(CustodianError, "exact protected custodian"):
            run_stage("grant", self.manifest, Path(self.temp.name), wrong_identity)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1:3], ["sts", "get-caller-identity"])

    def test_revoke_will_not_touch_foreign_grant(self):
        self.aws.grants = [{"GrantId": "g-other", "GranteePrincipal": "arn:aws:iam::123456789012:role/other", "Operations": ["Decrypt"]}]
        os.environ["B083_ISSUE2165_GRANT_ID"] = "g-other"
        with self.assertRaisesRegex(CustodianError, "not owned"):
            run_stage("revoke", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "revoke-grant"] for cmd in self.aws.calls))

    def test_revoke_is_idempotent_for_exact_absent_grant(self):
        os.environ["B083_ISSUE2165_GRANT_ID"] = "grant-absent"
        run_stage("revoke", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "revoke-grant"] for cmd in self.aws.calls))

    def test_empty_revoke_success_is_verified_by_list_grants(self):
        self.aws.grants = [{"GrantId": "g-1", "KeyId": self.manifest["aws"]["cmk_arn"], "GranteePrincipal": self.manifest["aws"]["runtime_role_arn"], "Operations": ["Encrypt", "Decrypt", "DescribeKey"], "Name": "issue-2165-1234567"}]
        self.aws.empty_actions.add("revoke-grant")
        os.environ["B083_ISSUE2165_GRANT_ID"] = "g-1"
        run_stage("revoke", self.manifest, Path(self.temp.name), self.aws)
        self.assertEqual(self.aws.grants, [])
        self.assertEqual(sum(cmd[1:3] == ["kms", "revoke-grant"] for cmd in self.aws.calls), 1)

    def test_create_timeout_is_not_retried(self):
        calls = []
        def timeout_on_create(command, **kwargs):
            calls.append(command)
            if command[1:3] == ["kms", "create-grant"]:
                raise __import__("subprocess").TimeoutExpired(command, 45)
            return self.aws(command, **kwargs)
        with self.assertRaisesRegex(CustodianError, "bounded AWS kms call failed"):
            run_stage("grant", self.manifest, Path(self.temp.name), timeout_on_create)
        self.assertEqual(sum(command[1:3] == ["kms", "create-grant"] for command in calls), 1)

    def test_schedule_requires_restricted_ownership_approval(self):
        self.manifest["approval"]["schedule_key_deletion"] = True
        self.manifest["key_deletion"] = {"disposable_key_ownership_approved": True, "ownership_approval_ref": "public://not-approved", "pending_window_days": 7, "cancel_by": "2026-09-30T23:00:00Z"}
        with self.assertRaisesRegex(CustodianError, "restricted root ownership"):
            run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "schedule-key-deletion"] for cmd in self.aws.calls))

    def _approved_schedule_manifest(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cancel_by = now + timedelta(days=1)
        expires_at = now + timedelta(days=6)
        self.manifest["approval"]["schedule_key_deletion"] = True
        self.manifest["key_deletion"] = {
            "disposable_key_ownership_approved": True,
            "ownership_approval_ref": "restricted://root/i2165/key",
            "pending_window_days": 7,
            "cancel_by": cancel_by.isoformat().replace("+00:00", "Z"),
            "rollback_proof": {
                "status": "PASS", "reviewed": True,
                "source_ref": "restricted://root/i2165/rollback-proof/reviewed",
                "source_sha256": "b" * 64,
                "cmk_arn": self.manifest["aws"]["cmk_arn"],
                "approved_github_sha": "a" * 40,
                "run_namespace": self.manifest["run_namespace"],
                "pending_window_days": 7,
                "cancel_by": cancel_by.isoformat().replace("+00:00", "Z"),
                "reviewed_at_utc": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                "expires_at_utc": expires_at.isoformat().replace("+00:00", "Z"),
            },
        }

    def test_schedule_accepts_exact_reviewed_rollback_binding_and_reads_back_pending(self):
        self._approved_schedule_manifest()
        run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.assertEqual(self.aws.key_state, "PendingDeletion")
        self.assertEqual(sum(cmd[1:3] == ["kms", "schedule-key-deletion"] for cmd in self.aws.calls), 1)
        receipt = json.loads((Path(self.temp.name) / "custodian-schedule-receipt.json").read_text())
        self.assertEqual(receipt["actions"][0]["readback"], "PendingDeletion")

    def test_schedule_fails_closed_without_rollback_proof(self):
        self._approved_schedule_manifest()
        del self.manifest["key_deletion"]["rollback_proof"]
        with self.assertRaisesRegex(CustodianError, "reviewed source-backed rollback proof"):
            run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "schedule-key-deletion"] for cmd in self.aws.calls))

    def test_schedule_rejects_wrong_key_or_sha_binding(self):
        self._approved_schedule_manifest()
        self.manifest["key_deletion"]["rollback_proof"]["cmk_arn"] = "arn:aws:kms:us-east-1:123456789012:key/other"
        with self.assertRaisesRegex(CustodianError, "different CMK"):
            run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.manifest["key_deletion"]["rollback_proof"]["cmk_arn"] = self.manifest["aws"]["cmk_arn"]
        self.manifest["key_deletion"]["rollback_proof"]["approved_github_sha"] = "c" * 40
        with self.assertRaisesRegex(CustodianError, "exact GitHub SHA"):
            run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "schedule-key-deletion"] for cmd in self.aws.calls))

    def test_schedule_rejects_expired_rollback_proof(self):
        self._approved_schedule_manifest()
        self.manifest["key_deletion"]["rollback_proof"]["expires_at_utc"] = "2020-01-01T00:00:00Z"
        with self.assertRaisesRegex(CustodianError, "expired"):
            run_stage("schedule", self.manifest, Path(self.temp.name), self.aws)
        self.assertFalse(any(cmd[1:3] == ["kms", "schedule-key-deletion"] for cmd in self.aws.calls))

    def test_cancel_enables_key_and_verifies_enabled_state(self):
        frozen_now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
        cancel_by = (frozen_now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        self.manifest["key_deletion"] = {"disposable_key_ownership_approved": True, "ownership_approval_ref": "restricted://root/i2165/key", "pending_window_days": 7, "cancel_by": cancel_by}
        self.aws.key_state = "PendingDeletion"
        self._run_stage_at("cancel", frozen_now)
        self.assertEqual(self.aws.key_state, "Enabled")
        actions = json.loads((Path(self.temp.name) / "custodian-cancel-receipt.json").read_text())["actions"]
        self.assertEqual([item["operation"] for item in actions], ["cancel-key-deletion", "enable-key"])
        self.assertEqual([item["readback"] for item in actions], ["Disabled", "Enabled"])
        self.assertTrue(any(cmd[1:3] == ["kms", "enable-key"] for cmd in self.aws.calls))
        self.assertFalse(any(cmd[1:3] == ["kms", "delete-key"] for cmd in self.aws.calls))

    def test_cleanup_cancels_pending_deletion_then_enables_exact_key(self):
        frozen_now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
        cancel_by = (frozen_now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        self.manifest["key_deletion"] = {"disposable_key_ownership_approved": True, "ownership_approval_ref": "restricted://root/i2165/key", "pending_window_days": 7, "cancel_by": cancel_by}
        self.aws.key_state = "PendingDeletion"
        self._run_stage_at("cleanup", frozen_now)
        self.assertEqual(self.aws.key_state, "Enabled")
        self.assertLess(
            next(i for i, cmd in enumerate(self.aws.calls) if cmd[1:3] == ["kms", "cancel-key-deletion"]),
            next(i for i, cmd in enumerate(self.aws.calls) if cmd[1:3] == ["kms", "enable-key"]),
        )
        rollback = json.loads((Path(self.temp.name) / "custodian-cleanup-rollback-receipt.json").read_text())
        self.assertEqual(rollback["stage"], "cleanup-rollback")
        self.assertEqual([a["operation"] for a in rollback["actions"]], ["cancel-key-deletion", "enable-key"])
        self.assertEqual(rollback["actions"][1]["readback"], "Enabled")
        self.assertEqual((Path(self.temp.name) / "custodian-cleanup-rollback-receipt.json").stat().st_mode & 0o777, 0o600)

    def test_rotate_uses_get_status_and_confirms_in_progress(self):
        self.manifest["approval"]["rotate_key"] = True
        self.aws.empty_actions.add("rotate-key-on-demand")
        run_stage("rotate", self.manifest, Path(self.temp.name), self.aws)
        self.assertEqual(self.aws.calls[1][1:3], ["kms", "describe-key"])
        self.assertEqual(sum(cmd[1:3] == ["kms", "get-key-rotation-status"] for cmd in self.aws.calls), 2)
        self.assertEqual(sum(cmd[1:3] == ["kms", "list-key-rotations"] for cmd in self.aws.calls), 2)
        receipt = json.loads((Path(self.temp.name) / "custodian-rotate-receipt.json").read_text())
        self.assertEqual(receipt["actions"][0]["readback"], "in-progress")

    def test_rotate_refuses_disabled_or_malformed_get_status_before_mutation(self):
        self.manifest["approval"]["rotate_key"] = True
        for status, error in (({"KeyId": self.manifest["aws"]["cmk_arn"], "KeyRotationEnabled": False}, "automatic rotation enabled"), ({"KeyId": self.manifest["aws"]["cmk_arn"]}, "malformed")):
            self.aws.calls.clear()
            self.aws.rotation_status = status
            with self.subTest(status=status), self.assertRaisesRegex(CustodianError, error):
                run_stage("rotate", self.manifest, Path(self.temp.name), self.aws)
            self.assertFalse(any(cmd[1:3] == ["kms", "rotate-key-on-demand"] for cmd in self.aws.calls))


if __name__ == "__main__":
    unittest.main()
