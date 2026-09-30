from __future__ import annotations

import json
import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_issue_2165_cf5128_storage import ContractError, SCHEMA, verify


ACCOUNT_ID = "a" * 32
DATABASE_ID = "d" * 32
ENDPOINT = f"https://{ACCOUNT_ID}.r2.cloudflarestorage.com"
ENV = {"B083_CF_ACCOUNT_ID": ACCOUNT_ID, "B083_D1_DATABASE_ID": DATABASE_ID, "B083_D1_REGION": "inventory-region", "B083_R2_S3_ENDPOINT": ENDPOINT}


def fixtures() -> tuple[dict, dict]:
    manifest = {
        "schema": SCHEMA,
        "environment": "b083-kms-lifecycle",
        "account_alias": "cf5128",
        "account_id": ACCOUNT_ID,
        "d1": {"binding": "B083_D1", "database_id": DATABASE_ID, "region": "inventory-region"},
        "r2": {"binding": "B083_R2", "endpoint": ENDPOINT, "region": "auto", "bucket": "b083-test"},
        "audit_sink": {"durable": True, "kind": "d1", "target_id": "audit-d1"},
        "disposable_tenants": ["tenant-one", "tenant-two"],
    }
    receipt = {
        "schema": SCHEMA,
        "environment": "b083-kms-lifecycle",
        "account_alias": "cf5128",
        "account_id": ACCOUNT_ID,
        "read_only": True,
        "provider_writes": False,
        "phase": "preflight",
        "inventory_method": "cloudflare-native-http-read-only",
        "targets": {"d1_database_id": DATABASE_ID, "d1_binding": "B083_D1", "d1_region": "inventory-region", "r2_endpoint": ENDPOINT, "r2_binding": "B083_R2", "r2_region": "auto", "r2_bucket": "b083-test", "audit_sink_target_id": "audit-d1"},
        "tenant_aliases": ["tenant-one", "tenant-two"],
    }
    return manifest, receipt


class Cloudflare5128StorageContract(unittest.TestCase):
    def test_valid_redacted_inventory_passes_and_summary_omits_identifiers(self) -> None:
        summary = verify(*fixtures(), environ=ENV)
        self.assertEqual(summary["tenant_count"], 2)
        self.assertEqual(summary["phase"], "preflight")
        self.assertFalse(summary["cleanup_complete"])
        serialized = json.dumps(summary)
        self.assertNotIn(ACCOUNT_ID, serialized)
        self.assertNotIn(DATABASE_ID, serialized)
        self.assertNotIn(ENDPOINT, serialized)

    def test_environment_bindings_are_required_and_exact(self) -> None:
        manifest, receipt = fixtures()
        for env in ({}, {**ENV, "B083_CF_ACCOUNT_ID": "wrong"}, {**ENV, "B083_D1_DATABASE_ID": "wrong"}, {**ENV, "B083_D1_REGION": "wrong"}, {**ENV, "B083_R2_S3_ENDPOINT": "https://other.r2.cloudflarestorage.com"}):
            with self.subTest(env=env):
                with self.assertRaises(ContractError):
                    verify(manifest, receipt, environ=env)

    def test_rejects_production_alias_and_inconsistent_endpoint(self) -> None:
        manifest, receipt = fixtures()
        manifest["account_alias"] = "prod6a"
        with self.assertRaisesRegex(ContractError, "production"):
            verify(manifest, receipt, environ=ENV)
        manifest, receipt = fixtures()
        manifest["r2"]["endpoint"] = "https://other.r2.cloudflarestorage.com"
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ={**ENV, "B083_R2_S3_ENDPOINT": manifest["r2"]["endpoint"]})

    def test_rejects_wrong_alias_region_account_or_environment(self) -> None:
        mutations = (
            ("d1", "binding", "OTHER_D1"),
            ("d1", "region", "apac"),
            ("r2", "binding", "OTHER_R2"),
            ("r2", "region", "weur"),
        )
        for section, key, value in mutations:
            manifest, receipt = fixtures()
            manifest[section][key] = value
            if section == "d1" and key == "region":
                ENV_WITH_WRONG_REGION = {**ENV, "B083_D1_REGION": value}
            else:
                ENV_WITH_WRONG_REGION = ENV
            with self.subTest(section=section, key=key):
                with self.assertRaises(ContractError):
                    verify(manifest, receipt, environ=ENV_WITH_WRONG_REGION)
        manifest, receipt = fixtures()
        receipt["account_id"] = "b" * 32
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ=ENV)
        manifest, receipt = fixtures()
        manifest["account_id"] = "6a1fc1c626fc2628823e60b9db01f5cd"
        receipt["account_id"] = manifest["account_id"]
        manifest["r2"]["endpoint"] = f"https://{manifest['account_id']}.r2.cloudflarestorage.com"
        receipt["targets"]["r2_endpoint"] = manifest["r2"]["endpoint"]
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ={**ENV, "B083_CF_ACCOUNT_ID": manifest["account_id"], "B083_R2_S3_ENDPOINT": manifest["r2"]["endpoint"]})
        manifest, receipt = fixtures()
        receipt["target_label"] = "prod6a"
        with self.assertRaisesRegex(ContractError, "production"):
            verify(manifest, receipt, environ=ENV)
        manifest, receipt = fixtures()
        receipt["environment"] = "other"
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ=ENV)

    def test_requires_durable_audit_two_distinct_tenants_and_cleanup(self) -> None:
        changes = (
            ("manifest", "audit_sink", {"durable": False, "kind": "d1", "target_id": "audit-d1"}),
            ("manifest", "disposable_tenants", ["same", "same"]),
            ("manifest", "disposable_tenants", ["one"]),
            ("receipt", "tenant_aliases", ["tenant-one"]),
            ("receipt", "cleanup", {"complete": False, "remaining_resources": 1}),
        )
        for source, key, value in changes:
            manifest, receipt = fixtures()
            (manifest if source == "manifest" else receipt)[key] = value
            with self.subTest(source=source, key=key, value=value):
                with self.assertRaises(ContractError):
                    verify(manifest, receipt, environ=ENV)

    def test_postcleanup_requires_two_lifecycle_events_audit_and_zero_resources(self) -> None:
        manifest, receipt = fixtures()
        receipt.update({
            "phase": "postcleanup",
            "provider_writes": True,
            "lifecycle": {"tenant_create_count": 2, "tenant_cleanup_count": 2, "audit_records_durable": True},
            "cleanup": {"complete": True, "remaining_resources": 0},
        })
        result = verify(manifest, receipt, environ=ENV)
        self.assertTrue(result["cleanup_complete"])
        for field, value in (
            ("provider_writes", False),
            ("lifecycle", {"tenant_create_count": 1, "tenant_cleanup_count": 2, "audit_records_durable": True}),
            ("lifecycle", {"tenant_create_count": 2, "tenant_cleanup_count": 2, "audit_records_durable": False}),
            ("cleanup", {"complete": True, "remaining_resources": False}),
            ("cleanup", {"complete": False, "remaining_resources": 0}),
        ):
            invalid = copy.deepcopy(receipt)
            invalid[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                verify(manifest, invalid, environ=ENV)

    def test_rejects_write_capable_or_secret_bearing_receipt(self) -> None:
        manifest, receipt = fixtures()
        receipt["provider_writes"] = True
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ=ENV)
        manifest, receipt = fixtures()
        receipt["access_key_secret"] = "never print this"
        with self.assertRaises(ContractError):
            verify(manifest, receipt, environ=ENV)

    def test_cli_emits_only_redacted_summary(self) -> None:
        manifest, receipt = fixtures()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path, receipt_path = root / "manifest.json", root / "receipt.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/verify_issue_2165_cf5128_storage.py"), "--manifest", str(manifest_path), "--receipt", str(receipt_path)],
                env={**__import__("os").environ, **ENV}, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(ACCOUNT_ID, result.stdout)
        self.assertNotIn(DATABASE_ID, result.stdout)
        self.assertNotIn(ENDPOINT, result.stdout)


if __name__ == "__main__":
    unittest.main()
