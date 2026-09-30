import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue_2165_failure_retry_receipt as fr
import issue_2165_cf5128_readback as cf


ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/i2165-runtime"
CONTROLLER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/i2165-controller"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/cluster"
TASKDEF = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/operator:1"
APP_TASKDEF = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1"
IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/operator@sha256:" + "a" * 64
APP_IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:" + "b" * 64
TENANTS = ["11111111-2222-4333-8444-555555555555", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]
START = 1_790_761_000_000


def ts(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z")


def manifest():
    return {"schema": "corelink-issue-2165-kms-runtime-v1", "environment": "b083-kms-lifecycle",
            "aws": {"account_id": ACCOUNT, "region": REGION, "cmk_arn": KEY, "runtime_role_arn": ROLE, "controller_role_arn": CONTROLLER_ROLE, "custodian_role_arn": f"arn:aws:iam::{ACCOUNT}:role/i2165-custodian", "cluster_arn": CLUSTER, "task_definition_arn": APP_TASKDEF, "image_uri": APP_IMAGE},
            "operator": {"task_definition_arn": TASKDEF, "image_uri": IMAGE, "entrypoint": "/usr/local/bin/issue-2165-operator", "container_name": "issue-2165-operator", "max_activation_request_ms": 30000},
            "cloudflare": {"account_alias": "cf5128", "account_id": cf.APPROVED_ACCOUNT_ID,
                           "d1": {"binding": "B083_D1", "database_id": "database-id", "region": "weur"}},
            "disposable_tenants": TENANTS,
            "lifecycle_window": {"started_at_ms": START, "ended_at_ms": START + 180000}}


def exec_evidence(phase, operator_task, app_task, inv, statuses, offsets, hashes=None):
    rows = []
    hashes = hashes or ["1" * 64, "2" * 64]
    for i, slot in enumerate(("tenant_a", "tenant_b")):
        begin, end = offsets[i]
        rows.append({"slot": slot, "step": "activate", "status": statuses[i],
                     "request_started_at_utc": ts(START + begin), "observed_at_utc": ts(START + end),
                     "request_body_sha256": hashes[i]})
    return {"task_arn": f"{CLUSTER.replace(':cluster/', ':task/')}/{operator_task}",
            "app_task_arn": f"{CLUSTER.replace(':cluster/', ':task/')}/{app_task}", "app_task_definition_arn": APP_TASKDEF, "app_image_uri": APP_IMAGE,
            "task_definition_arn": TASKDEF, "image_uri": IMAGE, "invocation_id": inv,
            "invocation_digest": ("3" if phase == "pre" else "4") * 64, "rows": rows}


def ct(event_id, name, at, *, error=None, task_id=None, response=None):
    inner = {"eventID": event_id, "eventName": name, "eventSource": "kms.amazonaws.com", "eventTime": ts(START + at),
             "awsRegion": REGION, "recipientAccountId": ACCOUNT,
             "userIdentity": {"type": "AssumedRole", "principalId": "AROATEST:" + (task_id or ("i2165-custodian-12345" if name == "CreateGrant" else "a" * 32)),
                              "sessionContext": {"sessionIssuer": {"arn": ROLE if name == "DescribeKey" else f"arn:aws:iam::{ACCOUNT}:role/i2165-custodian"}}},
             "requestParameters": {"keyId": KEY, "granteePrincipal": ROLE, "operations": ["Encrypt", "Decrypt", "DescribeKey"], "name": "issue-2165-12345"},
             "responseElements": response or {}}
    if error:
        inner["errorCode"] = error
    return {"EventId": event_id, "EventName": name, "EventTime": ts(START + at), "EventSource": "kms.amazonaws.com", "CloudTrailEvent": json.dumps(inner)}


def d1(rows):
    return {"success": True, "result": [{"success": True, "results": rows,
            "meta": {"changed_db": False, "rows_written": 0, "changes": 0}}]}


def public_d1(rows):
    ordered = sorted(rows, key=lambda r: r["tenant_id"])
    slots = [{"slot": f"tenant_{'a' if index == 0 else 'b'}", **{k: row.get(k) for k in ("mode", "cmk_provider", "state", "updated_at_ms")}}
             for index, row in enumerate(ordered)]
    sql = ("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms "
           "FROM tenant_byok_config WHERE tenant_id IN (?, ?) ORDER BY tenant_id")
    return {"observed_at_utc": ts(START), "endpoint": f"{cf.CF_API}/accounts/{cf.APPROVED_ACCOUNT_ID}/d1/database/database-id/query",
            "database_id": "database-id", "region": "weur", "query_sha256": __import__("hashlib").sha256(json.dumps({"sql": sql, "params": TENANTS}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "response_sha256": __import__("hashlib").sha256(json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "row_count": len(rows), "slot_states": slots,
            "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0}}


def exec_ct(event_id, phase, at, task_id):
    inner = {"eventID": event_id, "eventName": "ExecuteCommand", "eventSource": "ecs.amazonaws.com", "eventTime": ts(START + at),
             "awsRegion": REGION, "recipientAccountId": ACCOUNT,
             "userIdentity": {"type": "AssumedRole", "principalId": "AROA:workflow",
                              "sessionContext": {"sessionIssuer": {"arn": CONTROLLER_ROLE}}},
             "requestParameters": {"cluster": CLUSTER, "task": task_id, "container": "issue-2165-operator",
                                   "command": f"/usr/local/bin/issue-2165-operator --phase {phase}", "interactive": True}}
    return {"EventId": event_id, "EventName": "ExecuteCommand", "EventTime": ts(START + at),
            "EventSource": "ecs.amazonaws.com", "CloudTrailEvent": json.dumps(inner)}


def evidence():
    pre = exec_evidence("pre", "1" * 32, "2" * 32, "exec-pregrant", [501, 501], [(10000, 11000), (12000, 13000)])
    retry = exec_evidence("retry", "3" * 32, "4" * 32, "exec-retry", [202, 202], [(50000, 51000), (52000, 53000)])
    denies = {"Events": [exec_ct("exec-pregrant", "pregrant-deny", 9000, "1" * 32),
                          ct("deny-a", "DescribeKey", 10500, error="AccessDeniedException", task_id="2" * 32),
                          ct("deny-b", "DescribeKey", 12500, error="AccessDenied", task_id="2" * 32)]}
    retry_cloudtrail = {"Events": [exec_ct("exec-retry", "lifecycle", 49000, "3" * 32)]}
    grant = {"schema": "corelink.issue-2165-kms-custodian-receipt-v1", "stage": "grant", "run_id": "12345", "observed_at_utc": ts(START + 40000),
             "actions": [{"operation": "create-grant", "grant_id": "grant-123", "operations": ["Encrypt", "Decrypt", "DescribeKey"], "readback": "exact"}]}
    grant_ct = {"Events": [ct("grant-event", "CreateGrant", 40000, response={"grantId": "grant-123"})]}
    rows = [{"tenant_id": tenant, "mode": "byok", "cmk_provider": "aws", "cmk_key_id": KEY,
             "state": "pending", "updated_at_ms": START + when} for tenant, when in zip(TENANTS, (50500, 52500))]
    baseline = d1([])
    return pre, retry, denies, retry_cloudtrail, grant, grant_ct, baseline, d1([])


def post_d1_api(method, path, token, body):
    assert method == "POST"
    assert path == f"/accounts/{cf.APPROVED_ACCOUNT_ID}/d1/database/database-id/query"
    assert token == "test-token"
    assert body["params"] == TENANTS
    rows = [{"tenant_id": tenant, "mode": "byok", "cmk_provider": "aws", "cmk_key_id": KEY,
             "state": "pending", "updated_at_ms": START + when} for tenant, when in zip(TENANTS, (50500, 52500))]
    return d1(rows)


def build(parts=None, api=post_d1_api):
    parts = parts or evidence()
    env = {"GITHUB_RUN_ID": "12345", "B083_CF_API_TOKEN": "test-token", "B083_CF_ACCOUNT_ID": cf.APPROVED_ACCOUNT_ID,
           "B083_D1_DATABASE_ID": "database-id", "B083_D1_REGION": "weur"}
    return fr.build_receipt(manifest(), env, *parts, d1_api=api)


def test_builds_one_source_backed_retry_row_after_exact_denial_grant_and_d1_readback():
    receipt = build()
    assert receipt["step"] == "failure_retry"
    assert receipt["source"]["kind"] == "runtime"
    assert len(receipt["source"]["digest"]) == 64
    assert "11111111" not in json.dumps(receipt)


@pytest.mark.parametrize("mutate, message", [
    (lambda x: x[2]["Events"].__setitem__(slice(None), [e for e in x[2]["Events"] if e["EventName"] == "ExecuteCommand"]), "AccessDenied"),
    (lambda x: x[1]["rows"][0].update(request_body_sha256="9" * 64), "replay the exact pregrant request body"),
    (lambda x: x[4]["actions"][0].update(grant_id="wrong"), "CreateGrant"),
    (lambda x: x[7]["result"][0]["results"].append({"unexpected": True}), "D1"),
])
def test_rejects_missing_or_mismatched_failure_retry_proof(mutate, message):
    parts = evidence()
    mutate(parts)
    with pytest.raises(fr.FailureRetryError, match=message):
        build(parts)


def test_rejects_provider_construction_501_without_kms_access_denied():
    parts = evidence()
    for event in parts[2]["Events"]:
        inner = json.loads(event["CloudTrailEvent"])
        inner["errorCode"] = "InternalFailure"
        event["CloudTrailEvent"] = json.dumps(inner)
    with pytest.raises(fr.FailureRetryError, match="AccessDenied"):
        build(parts)


def test_requires_distinct_exec_invocation_and_bounded_retry_after_grant():
    parts = evidence()
    parts[1]["invocation_id"] = parts[0]["invocation_id"]
    with pytest.raises(fr.FailureRetryError, match="distinct authenticated ECS Exec"):
        build(parts)


def test_allows_unchanged_existing_inactive_baseline_rows():
    parts = list(evidence())
    inactive = [{"tenant_id": tenant, "mode": "byok", "cmk_provider": None, "cmk_key_id": None,
                 "state": "inactive", "updated_at_ms": START - 1000} for tenant in TENANTS]
    parts[6] = d1(inactive)
    parts[7] = d1(inactive)
    assert build(parts)["step"] == "failure_retry"


def test_accepts_sanitized_pregrant_row_summaries_without_tenant_ids():
    parts = list(evidence())
    inactive = [{"tenant_id": tenant, "mode": "byok", "cmk_provider": None, "cmk_key_id": None,
                 "state": "inactive", "updated_at_ms": START - 1000} for tenant in TENANTS]
    parts[6] = public_d1(inactive)
    parts[7] = public_d1(inactive)
    assert build(parts)["step"] == "failure_retry"
    assert TENANTS[0] not in json.dumps(parts[6])


def test_postretry_state_is_read_back_from_protected_d1_query():
    def empty(*_args):
        return d1([])
    with pytest.raises(fr.FailureRetryError, match="postretry D1"):
        build(api=empty)
