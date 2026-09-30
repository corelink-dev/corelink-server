import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue_2165_provider_access as provider
import issue_2165_cf5128_readback as cf


ACCOUNT = "123456789012"
REGION = "us-east-1"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/i2165-runtime"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/cluster"
TASK_DEFINITION = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/i2165-app:1"
IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/corelink@sha256:" + "a" * 64
TASK = "0123456789abcdef0123456789abcdef"
TENANTS = ["11111111-2222-4333-8444-555555555555", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]
WINDOW = {"started_at_ms": 1_790_761_000_000, "ended_at_ms": 1_790_764_000_000}


def manifest():
    return {
        "schema": "corelink-issue-2165-kms-runtime-v1",
        "environment": "b083-kms-lifecycle",
        "aws": {"account_id": ACCOUNT, "region": REGION, "cmk_arn": KEY, "runtime_role_arn": ROLE, "cluster_arn": CLUSTER, "task_definition_arn": TASK_DEFINITION, "image_uri": IMAGE},
        "cloudflare": {
            "account_alias": "cf5128",
            "account_id": cf.APPROVED_ACCOUNT_ID,
            "d1": {"binding": "B083_D1", "database_id": "database-id", "region": "weur"},
        },
        "disposable_tenants": TENANTS,
        "lifecycle_window": WINDOW,
    }


def env():
    return {
        "B083_AWS_ACCOUNT_ID": ACCOUNT,
        "B083_AWS_REGION": REGION,
        "B083_KMS_KEY_ARN": KEY,
        "B083_AWS_RUNTIME_ROLE_ARN": ROLE,
        "B083_AWS_PREFLIGHT_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/i2165-preflight",
        "B083_AWS_CLUSTER_ARN": CLUSTER,
        "B083_AWS_TASK_DEFINITION_ARN": TASK_DEFINITION,
        "B083_IMAGE_URI": IMAGE,
        "B083_CF_ACCOUNT_ID": cf.APPROVED_ACCOUNT_ID,
        "B083_D1_DATABASE_ID": "database-id",
        "B083_D1_REGION": "weur",
        "B083_CF_API_TOKEN": "test-token",
    }


def timestamp(ms):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z")


def activations():
    return [
        {"slot": "tenant_a", "step": "activate", "status": 202, "request_started_at_utc": timestamp(WINDOW["started_at_ms"]), "observed_at_utc": timestamp(WINDOW["started_at_ms"] + 20_000)},
        {"slot": "tenant_b", "step": "activate", "status": 202, "request_started_at_utc": timestamp(WINDOW["started_at_ms"] + 20_000), "observed_at_utc": timestamp(WINDOW["started_at_ms"] + 40_000)},
    ]


def cloudtrail(offsets=(10_000, 30_000)):
    events = []
    for i, offset in enumerate(offsets, 1):
        event_id = f"event-{i}"
        event_time = timestamp(WINDOW["started_at_ms"] + offset)
        inner = {
            "eventID": event_id,
            "eventName": "DescribeKey",
            "eventSource": "kms.amazonaws.com",
            "eventTime": event_time,
            "awsRegion": REGION,
            "recipientAccountId": ACCOUNT,
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": f"AROATEST:{TASK}",
                "sessionContext": {"sessionIssuer": {"arn": ROLE}},
            },
            "requestParameters": {"keyId": KEY},
        }
        events.append({
            "EventId": event_id,
            "EventName": "DescribeKey",
            "EventTime": event_time,
            "EventSource": "kms.amazonaws.com",
            "CloudTrailEvent": json.dumps(inner),
        })
    return {"Events": events}


def d1_api(method, path, token, body):
    assert method == "POST"
    assert path == f"/accounts/{cf.APPROVED_ACCOUNT_ID}/d1/database/database-id/query"
    rows = [
        {"tenant_id": TENANTS[0], "mode": "byok", "cmk_provider": "aws", "cmk_key_id": KEY, "state": "pending", "updated_at_ms": WINDOW["started_at_ms"] + 15_000},
        {"tenant_id": TENANTS[1], "mode": "byok", "cmk_provider": "aws", "cmk_key_id": KEY, "state": "pending", "updated_at_ms": WINDOW["started_at_ms"] + 35_000},
    ]
    return {"success": True, "result": [{"success": True, "results": rows, "meta": {"changed_db": False, "rows_written": 0, "changes": 0}}]}


def caller():
    return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/i2165-preflight/i2165-test"}


def build():
    return provider.build_receipt(manifest(), env(), activations(), cloudtrail(),
                                  f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=d1_api, caller_identity=caller())


class ProviderAccessTests(unittest.TestCase):
    def test_correlates_runtime_describe_key_before_d1_activation_and_202(self):
        receipt = build()
        self.assertEqual(receipt["step"], "provider_access")
        self.assertEqual(receipt["source"]["kind"], "cloudtrail")
        self.assertIn("event-1/event-2", receipt["source"]["event_ref"])
        self.assertEqual(len(receipt["source"]["digest"]), 64)

    def test_rejects_d1_activation_before_provider_access(self):
        def bad_api(*args):
            payload = d1_api(*args)
            payload["result"][0]["results"][0]["updated_at_ms"] = WINDOW["started_at_ms"] + 5_000
            return payload
        with self.assertRaisesRegex(provider.ProviderAccessError, "DescribeKey"):
            provider.build_receipt(manifest(), env(), activations(), cloudtrail(),
                                   f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=bad_api, caller_identity=caller())

    def test_rejects_wrong_runtime_role_or_wrong_key_events(self):
        rows = cloudtrail()
        inner = json.loads(rows["Events"][0]["CloudTrailEvent"])
        inner["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = "arn:aws:iam::123456789012:role/other"
        rows["Events"][0]["CloudTrailEvent"] = json.dumps(inner)
        with self.assertRaisesRegex(provider.ProviderAccessError, "DescribeKey"):
            provider.build_receipt(manifest(), env(), activations(), rows,
                                   f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=d1_api, caller_identity=caller())

    def test_chooses_nearest_activation_bound_events_among_run_loop_describes(self):
        receipt = provider.build_receipt(
            manifest(), env(), activations(), cloudtrail((8_000, 10_000, 12_000, 30_000, 32_000)),
            f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=d1_api, caller_identity=caller())
        self.assertIn("event-3/event-5", receipt["source"]["event_ref"])

    def test_rejects_ambiguous_same_timestamp_runtime_describes(self):
        with self.assertRaisesRegex(provider.ProviderAccessError, "ambiguous"):
            provider.build_receipt(
                manifest(), env(), activations(), cloudtrail((10_000, 10_000, 30_000)),
                f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=d1_api, caller_identity=caller())

    def test_rejects_activation_not_202_and_d1_write_metadata_ambiguity(self):
        rows = activations()
        rows[1]["status"] = 200
        with self.assertRaisesRegex(provider.ProviderAccessError, "HTTP 202"):
            provider.build_receipt(manifest(), env(), rows, cloudtrail(),
                                   f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=d1_api, caller_identity=caller())
        def changed(*args):
            payload = d1_api(*args)
            payload["result"][0]["meta"]["rows_written"] = 1
            return payload
        with self.assertRaisesRegex(provider.ProviderAccessError, "zero-write"):
            provider.build_receipt(manifest(), env(), activations(), cloudtrail(),
                                   f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/cluster/{TASK}", d1_api=changed, caller_identity=caller())
