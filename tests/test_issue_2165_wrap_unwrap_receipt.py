"""Mocked offline checks for the protected #2165 wrap/unwrap collector."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import issue_2165_wrap_unwrap_receipt as wrap  # noqa: E402
import issue_2165_r2_audit_archive as audit_archive  # noqa: E402


ACCOUNT = "123456789012"
REGION = "us-east-1"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-2222-3333-4444-555555555555"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/kms-test"
TASKDEF = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/corelink:7"
TASK_ID = "a" * 32
APP_TASK = CLUSTER.replace(":cluster/", ":task/") + "/" + TASK_ID
RUNTIME_ROLE = f"arn:aws:iam::{ACCOUNT}:role/kms-runtime"
CUSTODIAN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/kms-custodian"
PREFLIGHT_ROLE = f"arn:aws:iam::{ACCOUNT}:role/kms-preflight"


def fixtures():
    app_image = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/corelink@sha256:" + "a" * 64
    operator_image = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/operator@sha256:" + "b" * 64
    operator_taskdef = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/issue-2165-operator:2"
    cf_account = "51284495e71acdb5a7677e7383ab026b"
    tenants = ["disposable-tenant-a", "disposable-tenant-b"]
    manifest = {
        "schema": wrap.MANIFEST_SCHEMA,
        "environment": wrap.ENVIRONMENT,
        "aws": {
            "account_id": ACCOUNT, "region": REGION, "cmk_provider": "aws", "cmk_arn": KEY,
            "runtime_role_arn": RUNTIME_ROLE, "custodian_role_arn": CUSTODIAN_ROLE,
            "cluster_arn": CLUSTER, "task_definition_arn": TASKDEF, "image_uri": app_image,
        },
        "operator": {
            "task_definition_arn": operator_taskdef, "image_uri": operator_image,
            "operator_role_arn": f"arn:aws:iam::{ACCOUNT}:role/kms-operator",
        },
        "custodian_authority": {
            "ref": "restricted://root/kms-custody/2165", "cmk_arn": KEY,
            "custodian_role_arn": CUSTODIAN_ROLE,
        },
        "disposable_tenants": tenants,
        "lifecycle_window": {"started_at_ms": 1790769600000, "ended_at_ms": 1790773200000},
        "cloudflare": {
            "account_alias": "cf5128", "account_id": cf_account,
            "d1": {"binding": "B083_D1", "database_id": "d1-kms-test", "region": "weur"},
        },
    }
    env = {
        "B083_AWS_ACCOUNT_ID": ACCOUNT, "B083_AWS_REGION": REGION,
        "B083_KMS_KEY_ARN": KEY, "B083_AWS_RUNTIME_ROLE_ARN": RUNTIME_ROLE, "B083_AWS_CUSTODIAN_ROLE_ARN": CUSTODIAN_ROLE,
        "B083_AWS_CLUSTER_ARN": CLUSTER, "B083_AWS_TASK_DEFINITION_ARN": TASKDEF,
        "B083_IMAGE_URI": app_image, "B083_AWS_OPERATOR_TASK_DEFINITION_ARN": operator_taskdef,
        "B083_AWS_OPERATOR_IMAGE_URI": operator_image, "B083_AWS_OPERATOR_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/kms-operator",
        "B083_CUSTODIAN_REF": "restricted://root/kms-custody/2165",
        "B083_CF_ACCOUNT_ID": cf_account, "B083_D1_DATABASE_ID": "d1-kms-test", "B083_D1_REGION": "weur",
        "B083_CF_API_TOKEN": "secret-token-do-not-output", "B083_AWS_PREFLIGHT_ROLE_ARN": PREFLIGHT_ROLE,
        "GITHUB_RUN_ID": "42",
    }
    rows = []
    for slot, digest in (("tenant_a", "1" * 64), ("tenant_b", "2" * 64)):
        rows.extend([
            {"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "activate", "status": 202,
             "request_started_at_utc": "2026-09-30T12:00:10Z", "observed_at_utc": "2026-09-30T12:00:11Z"},
            {"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "cas-put", "status": 201,
             "observed_at_utc": "2026-09-30T12:00:30Z", "digest": digest},
            {"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "cas-get", "status": 200,
             "observed_at_utc": "2026-09-30T12:00:40Z", "digest": digest},
        ])
    rows.append({"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": "tenant_b_to_a", "step": "cross-tenant-deny", "status": 403,
                 "observed_at_utc": "2026-09-30T12:00:41Z", "digest": "1" * 64})
    raw_response = "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) + "\n"
    provenance = {
        "task_arn": CLUSTER.replace(":cluster/", ":task/") + "/" + "c" * 32,
        "cluster_arn": CLUSTER, "task_definition_arn": operator_taskdef,
        "image_uri": operator_image, "image_digest": "sha256:" + "b" * 64,
        "execute_response_sha256": hashlib.sha256(raw_response.encode()).hexdigest(),
        "response_rows_sha256": hashlib.sha256(wrap._canonical(rows)).hexdigest(),
    }
    runtime_source = {"provenance": provenance, "raw_response": raw_response, "response_rows": rows}
    caller = {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/kms-preflight/i2165-preflight-42"}
    task_readback = {"tasks": [{"taskArn": APP_TASK, "clusterArn": CLUSTER, "taskDefinitionArn": TASKDEF, "lastStatus": "RUNNING",
                                 "containers": [{"name": "corelink", "lastStatus": "RUNNING", "imageDigest": "sha256:" + "a" * 64}]}], "failures": []}
    cloudtrail = {"Events": []}
    time_by_event = {"Encrypt": "2026-09-30T12:00:01Z", "Decrypt": "2026-09-30T12:00:29Z"}
    for tenant, suffix in zip(tenants, ("a", "b"), strict=True):
        for action in ("Encrypt", "Decrypt"):
            event_id = f"event-{action.lower()}-{suffix}-0123456789"
            if action == "Encrypt":
                actor = {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/kms-custodian/i2165-custodian-42",
                         "principalId": "AROA:custodian",
                         "sessionContext": {"sessionIssuer": {"arn": CUSTODIAN_ROLE}}}
            else:
                actor = {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/kms-runtime/ecs-session",
                         "principalId": "AROA:" + TASK_ID,
                         "sessionContext": {"sessionIssuer": {"arn": RUNTIME_ROLE}}}
            inner = {"eventID": event_id, "eventName": action, "eventTime": time_by_event[action],
                     "eventSource": "kms.amazonaws.com", "awsRegion": REGION, "recipientAccountId": ACCOUNT,
                     "responseElements": {},
                     "userIdentity": actor,
                     "requestParameters": {"keyId": KEY, "encryptionContext": {"tenant_id": tenant, "blob_hash": "tcs:v1"}}}
            cloudtrail["Events"].append({"EventId": event_id, "EventName": action, "EventTime": time_by_event[action],
                                         "EventSource": "kms.amazonaws.com", "CloudTrailEvent": json.dumps(inner)})
    d1_rows = []
    for index, tenant in enumerate(tenants):
        wrapped = base64.b64encode(b"wrapped-tcs-" + bytes([index])).decode()
        d1_rows.append({"tenant_id": tenant, "tcs_wrapped": wrapped, "secret_cmk_key_id": KEY, "tcs_version": 1,
                        "wrapped_at_ms": 1790769605000, "mode": "byok", "crypto_mode": "convergent",
                        "cmk_provider": "aws", "config_cmk_key_id": KEY, "cmk_region": REGION, "state": "active"})
    payload = {"success": True, "result": [{"success": True, "meta": {"changed_db": False, "rows_written": 0, "changes": 0}, "results": d1_rows}]}
    def d1_api(method, path, token, query):
        assert method == "POST" and "d1-kms-test/query" in path
        assert token == env["B083_CF_API_TOKEN"]
        return payload
    def cf_api(method, path, token):
        assert method == "GET" and path == "/user/tokens/verify"
        assert token == env["B083_CF_API_TOKEN"]
        return {"success": True, "result": {"status": "active", "id": "f" * 32}}
    return manifest, env, runtime_source, cloudtrail, caller, task_readback, d1_api, cf_api


class WrapUnwrapReceiptTests(unittest.TestCase):
    def make_receipt(self):
        manifest, env, runtime_source, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        return wrap.build_receipt(manifest, env, runtime_source, cloudtrail, caller, APP_TASK, task_readback,
                                  d1_api=d1_api, cf_api=cf_api)

    def test_builds_one_redacted_wrap_unwrap_row_from_all_sources(self):
        receipt, evidence = self.make_receipt()
        self.assertEqual(receipt["step"], "wrap_unwrap")
        self.assertEqual(receipt["source"]["kind"], "cloudtrail")
        self.assertEqual(len(evidence["selected_cloudtrail_event_ids"]), 4)
        self.assertEqual(evidence["d1_tcs_readback_rows"][0]["wrapped_length"], len(b"wrapped-tcs-\x00"))
        self.assertTrue(receipt["source"]["event_ref"].startswith("kms-encrypt:"))
        self.assertNotIn("disposable-tenant-a", json.dumps(receipt))
        self.assertNotIn("secret-token-do-not-output", json.dumps(receipt))

    def test_wrap_unwrap_event_reference_is_archive_compatible(self):
        receipt, _ = self.make_receipt()
        rows = []
        for step in sorted(audit_archive.SOURCE_STEPS):
            if step == "wrap_unwrap":
                rows.append(receipt)
            else:
                rows.append({"step": step, "occurred_at_utc": "2026-09-30T12:00:00Z",
                             "source": {"kind": "runtime", "event_ref": f"source:{step}", "digest": "b" * 64}})
        validated = audit_archive.validate_source_receipts(rows)
        observed = next(row for row in validated if row["step"] == "wrap_unwrap")
        self.assertEqual(observed, receipt)

    def test_rejects_wrong_app_task_or_immutable_image(self):
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        task_readback["tasks"][0]["taskArn"] = CLUSTER.replace(":cluster/", ":task/") + "/" + "e" * 32
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "app task ARN/cluster/task definition/immutable image"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)
        _, _, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        task_readback["tasks"][0]["containers"][0]["imageDigest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "immutable image"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)

    def test_rejects_cloudtrail_wrong_key_role_or_task(self):
        mutations = (
            lambda event: event["requestParameters"].update(keyId="arn:aws:kms:us-east-1:123456789012:key/other"),
            lambda event: event["userIdentity"]["sessionContext"]["sessionIssuer"].update(arn="arn:aws:iam::123456789012:role/other"),
            lambda event: event["userIdentity"].update(principalId="AROA:" + "d" * 32),
        )
        for mutate in mutations:
            manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
            altered = json.loads(cloudtrail["Events"][-1]["CloudTrailEvent"])
            # Keep the exact outer/inner event but tamper its authenticated identity.
            mutate(altered)
            cloudtrail["Events"][-1]["CloudTrailEvent"] = json.dumps(altered)
            with self.subTest(mutate=mutate), self.assertRaises(wrap.WrapUnwrapError):
                wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)

    def test_rejects_missing_encrypt_or_decrypt_events(self):
        for event_name in ("Encrypt", "Decrypt"):
            manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
            cloudtrail["Events"] = [row for row in cloudtrail["Events"] if row["EventName"] != event_name]
            with self.assertRaisesRegex(wrap.WrapUnwrapError, "missing exact custodian Encrypt/runtime-task Decrypt"):
                wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)

    def test_rejects_d1_wrong_key_duplicate_ciphertext_or_write_metadata(self):
        for mutation in (
            lambda rows: rows[0].update(secret_cmk_key_id="arn:wrong"),
            lambda rows: rows[1].update(tcs_wrapped=rows[0]["tcs_wrapped"]),
        ):
            manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
            payload = d1_api("POST", "https://unused/d1-kms-test/query", env["B083_CF_API_TOKEN"], {})
            mutation(payload["result"][0]["results"])
            with self.assertRaises(wrap.WrapUnwrapError):
                wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback,
                                   d1_api=lambda *args: payload, cf_api=cf_api)
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        payload = d1_api("POST", "https://unused/d1-kms-test/query", env["B083_CF_API_TOKEN"], {})
        payload["result"][0]["meta"]["rows_written"] = 1
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "zero-write"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback,
                               d1_api=lambda *args: payload, cf_api=cf_api)

    def test_rejects_cas_hash_mismatch_and_runtime_exec_tampering(self):
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        runtime["response_rows"][2]["digest"] = "f" * 64
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "raw response or row digest"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        runtime["response_rows"][2]["digest"] = "f" * 64
        raw = "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in runtime["response_rows"]) + "\n"
        runtime["raw_response"] = raw
        runtime["provenance"]["execute_response_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        runtime["provenance"]["response_rows_sha256"] = hashlib.sha256(wrap._canonical(runtime["response_rows"])).hexdigest()
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "roundtrip"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)

    def test_rejects_mismatched_activation_tenant_context(self):
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        inner = json.loads(cloudtrail["Events"][0]["CloudTrailEvent"])
        inner["requestParameters"]["encryptionContext"]["tenant_id"] = "another-tenant"
        cloudtrail["Events"][0]["CloudTrailEvent"] = json.dumps(inner)
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "missing exact custodian Encrypt/runtime-task Decrypt"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)

    def test_requires_protected_d1_and_preflight_bindings(self):
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        env["B083_D1_DATABASE_ID"] = "other"
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "D1 target"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)
        manifest, env, runtime, cloudtrail, caller, task_readback, d1_api, cf_api = fixtures()
        caller["Account"] = "000000000000"
        with self.assertRaisesRegex(wrap.WrapUnwrapError, "caller account"):
            wrap.build_receipt(manifest, env, runtime, cloudtrail, caller, APP_TASK, task_readback, d1_api=d1_api, cf_api=cf_api)


if __name__ == "__main__":
    unittest.main()
