from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.issue_2165_cf5128_readback import ReadbackError, run_readback, validate_manifest


ACCOUNT = "51284495e71acdb5a7677e7383ab026b"
DATABASE = "d" * 32
ENDPOINT = f"https://{ACCOUNT}.r2.cloudflarestorage.com"
TENANTS = ["123e4567-e89b-42d3-a456-426614174000", "123e4567-e89b-42d3-a456-426614174001"]
WINDOW_START = 1_800_000_000_000
WINDOW_END = WINDOW_START + 60 * 60 * 1000
ENV = {
    "B083_CF_ACCOUNT_ID": ACCOUNT,
    "B083_D1_DATABASE_ID": DATABASE,
    "B083_D1_REGION": "iad",
    "B083_R2_S3_ENDPOINT": ENDPOINT,
    "B083_AUDIT_SINK_REF": "audit-sink-ref",
    "B083_CF_API_TOKEN": "protected-test-token",
    "B083_R2_READONLY_ACCESS_KEY_ID": "test-access-key",
    "B083_R2_READONLY_SECRET_ACCESS_KEY": "test-secret-key",
}
def fixture() -> dict:
    return {
        "schema": "corelink-issue-2165-kms-runtime-v1",
        "environment": "b083-kms-lifecycle",
        "cloudflare": {
            "account_alias": "cf5128",
            "account_id": ACCOUNT,
            "d1": {"binding": "B083_D1", "database_id": DATABASE, "region": "iad"},
            "r2": {"binding": "B083_R2", "endpoint": ENDPOINT, "region": "auto", "bucket": "issue-2165-test"},
            "r2_prefixes": [
                {"tenant_id": TENANTS[0], "region": "iad", "prefix": "iad/AbCdEf0123456789/"},
                {"tenant_id": TENANTS[1], "region": "iad", "prefix": "iad/ZyXwVu9876543210/"},
            ],
        },
        "disposable_tenants": TENANTS,
        "lifecycle_window": {"started_at_ms": WINDOW_START, "ended_at_ms": WINDOW_END},
        "audit_sink": {
            "durable": True,
            "kind": "d1-audit-outbox+r2-archive",
            "target_id": "audit-sink-ref",
            "d1_table": "audit_outbox",
            "d1_columns": ["id", "tenant_id", "digest", "request_id", "event_type", "payload_json", "enqueued_at", "emitted_at"],
            "r2_bucket": "issue-2165-test",
            "r2_archive_key": "issue-2165/run-123/audit/receipts.ndjson",
        },
        "audit_outbox_refs": [{"request_id": f"req-{i}", "event_type": f"lifecycle.step_{i}"} for i in range(3)],
    }


def mock_api(*, postcleanup: bool = False, audit_present: bool | None = None, bad_meta: bool = False):
    def call(method: str, path: str, token: str, payload=None):
        if method == "GET" and path == "/user/tokens/verify":
            return {"success": True, "result": {"id": "1" * 32, "status": "active"}}
        if method == "GET" and path.endswith(f"/d1/database/{DATABASE}"):
            return {"success": True, "result": {"uuid": DATABASE, "name": "isolated-test"}}
        if method == "GET" and path.endswith("/r2/buckets/issue-2165-test"):
            return {"success": True, "result": {"name": "issue-2165-test"}}
        if method == "POST" and path.endswith("/query"):
            sql = payload["sql"]
            meta = {"changed_db": False, "rows_written": 0, "changes": 0}
            if bad_meta:
                meta.pop("rows_written")
            if "byok_control_outcome" in sql:
                rows = []
                if postcleanup:
                    for offset, tenant_id in enumerate(TENANTS):
                        rows.extend([
                            {"tenant_id": tenant_id, "action": "degrade", "outcome": "completed", "completed_at_ms": WINDOW_START + 100 + offset},
                            {"tenant_id": tenant_id, "action": "restore", "outcome": "completed", "completed_at_ms": WINDOW_START + 200 + offset},
                        ])
                return {"success": True, "result": [{"success": True, "meta": meta, "results": rows}]}
            count = 1 if (postcleanup if audit_present is None else audit_present) and "audit_outbox" in sql else 0
            return {"success": True, "result": [{"success": True, "meta": meta, "results": [{"n": count}]}]}
        raise AssertionError(f"unexpected request {method} {path}")
    return call


class Cloudflare5128Readback(unittest.TestCase):
    def test_preflight_redacts_targets_and_never_claims_cleanup(self):
        manifest = fixture()
        raw = json.dumps(manifest).encode()
        seen_prefixes = []

        def list_prefix(target, prefix, access_key, secret_key):
            seen_prefixes.append(prefix)
            return []

        receipt = run_readback(manifest, raw, phase="preflight", environ=ENV,
                               api_json=mock_api(), list_prefix=list_prefix)
        self.assertNotIn("cleanup_complete", receipt)
        self.assertFalse(receipt["provider_writes"])
        self.assertFalse(receipt["readback_provider_writes"])
        self.assertEqual(receipt["byok_control_outcome_observation"]["totals"]["completed_count"], 0)
        self.assertEqual(receipt["tenant_residual_counts"], {"tenant": 0, "blob_meta": 0, "ac_meta": 0, "tenant_byok_config": 0, "tenant_byok_secret": 0})
        self.assertEqual(set(seen_prefixes), {"iad/AbCdEf0123456789/", "iad/ZyXwVu9876543210/", "issue-2165/run-123/"})
        serialized = json.dumps(receipt)
        for sensitive_target in (ACCOUNT, DATABASE, *TENANTS, ENDPOINT):
            self.assertNotIn(sensitive_target, serialized)
        self.assertEqual(receipt["source_sha256"], hashlib.sha256(raw).hexdigest())

    def test_postcleanup_requires_zero_residuals_exact_audit_and_archive_digest(self):
        manifest = fixture()
        raw = json.dumps(manifest).encode()
        archive = b'{"step":"receipt"}\n'

        def list_prefix(target, prefix, access_key, secret_key):
            if prefix == "issue-2165/run-123/":
                return [(manifest["audit_sink"]["r2_archive_key"], len(archive))]
            return []

        receipt = run_readback(manifest, raw, phase="postcleanup", environ=ENV,
                               api_json=mock_api(postcleanup=True), list_prefix=list_prefix,
                               get_archive=lambda *_: archive)
        self.assertTrue(receipt["cleanup_complete"])
        self.assertTrue(receipt["provider_writes"])
        self.assertFalse(receipt["readback_provider_writes"])
        self.assertEqual(receipt["audit_outbox_refs_present"], 3)
        self.assertEqual(receipt["audit_archive"]["sha256"], hashlib.sha256(archive).hexdigest())
        observation = receipt["byok_control_outcome_observation"]
        self.assertEqual(observation["totals"]["degrade_count"], 2)
        self.assertEqual(observation["totals"]["restore_count"], 2)
        self.assertEqual(observation["redacted_tenant_slots"]["tenant_a"]["degrade"]["count"], 1)
        self.assertEqual(observation["redacted_tenant_slots"]["tenant_b"]["restore"]["count"], 1)
        self.assertEqual(observation["window"], {"started_at_ms": WINDOW_START, "ended_at_ms": WINDOW_END})
        self.assertNotIn("p99", json.dumps(observation).lower())
        for tenant_id in TENANTS:
            self.assertNotIn(tenant_id, json.dumps(receipt))

    def test_effective_target_access_is_bound_to_protected_account(self):
        manifest = fixture()
        env = {**ENV, "B083_CF_ACCOUNT_ID": "c" * 32}
        with self.assertRaisesRegex(ReadbackError, "(?i)account"):
            validate_manifest(manifest, env)

        api = mock_api()
        def wrong_database(method, path, token, payload=None):
            result = api(method, path, token, payload)
            if path.endswith(f"/d1/database/{DATABASE}"):
                result["result"]["uuid"] = "c" * 32
            return result
        with self.assertRaisesRegex(ReadbackError, "D1 target"):
            run_readback(manifest, b"{}", phase="preflight", environ=ENV, api_json=wrong_database,
                         list_prefix=lambda *_: [])

    def test_wrong_cloudflare_account_and_production_marker_fail_closed(self):
        for account in ("6a1fc1c626fc2628823e60b9db01f5cd", "b" * 32, "not-an-account"):
            manifest = fixture()
            manifest["cloudflare"]["account_id"] = account
            with self.subTest(account=account), self.assertRaises(ReadbackError):
                validate_manifest(manifest, {**ENV, "B083_CF_ACCOUNT_ID": account})

    def test_prefixes_cannot_escape_to_another_tenant_or_bucket_scope(self):
        for prefix in ("", "iad/*/", "iad/../", "iad/short/", "/iad/AbCdEf0123456789/"):
            manifest = fixture()
            manifest["cloudflare"]["r2_prefixes"][0]["prefix"] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ReadbackError):
                validate_manifest(manifest, ENV)

    def test_missing_or_ambiguous_d1_readonly_metadata_fails_closed(self):
        with self.assertRaisesRegex(ReadbackError, "metadata"):
            run_readback(fixture(), b"{}", phase="preflight", environ=ENV,
                         api_json=mock_api(bad_meta=True), list_prefix=lambda *_: [])

    def test_postcleanup_requires_exact_audit_refs_and_zero_r2_objects(self):
        manifest = fixture()
        with self.assertRaisesRegex(ReadbackError, "audit"):
            run_readback(manifest, b"{}", phase="postcleanup", environ=ENV,
                         api_json=mock_api(postcleanup=True, audit_present=False),
                         list_prefix=lambda target, prefix, *_: [(manifest["audit_sink"]["r2_archive_key"], 12)] if prefix.startswith("issue-2165/") else [],
                         get_archive=lambda *_: b"receipt")
        with self.assertRaisesRegex(ReadbackError, "residual"):
            run_readback(manifest, b"{}", phase="postcleanup", environ=ENV,
                         api_json=mock_api(postcleanup=True),
                         list_prefix=lambda target, prefix, *_: ([ ("some-key", 1) ] if prefix.startswith("iad/") else [(manifest["audit_sink"]["r2_archive_key"], 12)]),
                         get_archive=lambda *_: b"receipt")

    def test_receipt_ref_metadata_must_be_unique_and_bound(self):
        manifest = fixture()
        manifest["audit_outbox_refs"][1]["request_id"] = manifest["audit_outbox_refs"][0]["request_id"]
        with self.assertRaisesRegex(ReadbackError, "duplicate"):
            validate_manifest(manifest, ENV)
        manifest = fixture()
        manifest["cloudflare"]["r2_prefixes"][1]["tenant_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(ReadbackError):
            validate_manifest(manifest, ENV)

    def test_lifecycle_window_is_bounded_and_integer(self):
        for window in (
            {"started_at_ms": WINDOW_END, "ended_at_ms": WINDOW_START},
            {"started_at_ms": True, "ended_at_ms": WINDOW_END},
            {"started_at_ms": WINDOW_START, "ended_at_ms": WINDOW_START + 60 * 60 * 1000 + 1},
        ):
            manifest = fixture()
            manifest["lifecycle_window"] = window
            with self.subTest(window=window), self.assertRaises(ReadbackError):
                validate_manifest(manifest, ENV)

    def test_postcleanup_requires_both_completed_actions_for_each_redacted_slot(self):
        manifest = fixture()
        api = mock_api(postcleanup=True)
        captured_transition_query = []

        def missing_restore(method, path, token, payload=None):
            result = api(method, path, token, payload)
            if method == "POST" and "byok_control_outcome" in payload.get("sql", ""):
                captured_transition_query.append(payload)
                result["result"][0]["results"] = [
                    row for row in result["result"][0]["results"] if not (
                        row["tenant_id"] == TENANTS[0] and row["action"] == "restore")
                ]
            return result

        with self.assertRaisesRegex(ReadbackError, "BYOK transition"):
            run_readback(manifest, b"{}", phase="postcleanup", environ=ENV,
                         api_json=missing_restore,
                         list_prefix=lambda target, prefix, *_: [(manifest["audit_sink"]["r2_archive_key"], 1)] if prefix.startswith("issue-2165/") else [],
                         get_archive=lambda *_: b"receipt")
        self.assertEqual(len(captured_transition_query), 1)
        query = captured_transition_query[0]
        self.assertEqual(query["params"], [*TENANTS, WINDOW_START, WINDOW_END])
        self.assertIn("action IN ('degrade', 'restore')", query["sql"])
        self.assertIn("outcome = 'completed'", query["sql"])
        self.assertIn("completed_at_ms >= ? AND completed_at_ms <= ?", query["sql"])

    def test_postcleanup_rejects_transition_outside_manifest_window(self):
        manifest = fixture()
        api = mock_api(postcleanup=True)

        def outside_window(method, path, token, payload=None):
            result = api(method, path, token, payload)
            if method == "POST" and "byok_control_outcome" in payload.get("sql", ""):
                result["result"][0]["results"][0]["completed_at_ms"] = WINDOW_END + 1
            return result

        with self.assertRaisesRegex(ReadbackError, "time contract"):
            run_readback(manifest, b"{}", phase="postcleanup", environ=ENV,
                         api_json=outside_window,
                         list_prefix=lambda target, prefix, *_: [(manifest["audit_sink"]["r2_archive_key"], 1)] if prefix.startswith("issue-2165/") else [],
                         get_archive=lambda *_: b"receipt")


if __name__ == "__main__":
    unittest.main()
