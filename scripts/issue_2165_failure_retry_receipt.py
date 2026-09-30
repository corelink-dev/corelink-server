#!/usr/bin/env python3
"""Validate source-backed pregrant denial and same-intent postgrant retry evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import issue_2165_cf5128_readback as cf


class FailureRetryError(ValueError):
    """Required authenticated failure/retry evidence is absent or inconsistent."""


def _time(value: Any, field: str) -> int:
    if not isinstance(value, str):
        raise FailureRetryError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FailureRetryError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise FailureRetryError(f"{field} must be UTC")
    return int(parsed.timestamp() * 1000)


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise FailureRetryError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _exec(value: Any, phase: str, target: dict[str, Any], status: int) -> dict[str, Any]:
    required = {"task_arn", "app_task_arn", "app_task_definition_arn", "app_image_uri", "task_definition_arn", "image_uri", "invocation_id", "invocation_digest", "rows"}
    if not isinstance(value, dict) or set(value) != required:
        raise FailureRetryError(f"{phase} authenticated ECS Exec evidence has an unknown shape")
    task = value["task_arn"]
    prefix = target["cluster_arn"].replace(":cluster/", ":task/") + "/"
    if not isinstance(task, str) or not task.startswith(prefix) or not re.fullmatch(r"[A-Fa-f0-9]{32}", task.rsplit("/", 1)[-1]):
        raise FailureRetryError(f"{phase} ECS task is outside the exact protected cluster")
    if value["task_definition_arn"] != target["operator_task_definition_arn"] or value["image_uri"] != target["operator_image_uri"]:
        raise FailureRetryError(f"{phase} operator task definition or immutable image differs from manifest")
    if not isinstance(value["invocation_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value["invocation_id"]):
        raise FailureRetryError(f"{phase} ECS Exec invocation ID is missing or malformed")
    _sha(value["invocation_digest"], f"{phase}.invocation_digest")
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) != 2:
        raise FailureRetryError(f"{phase} must contain exactly two tenant activation rows")
    by_slot: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"slot", "step", "status", "request_started_at_utc", "observed_at_utc", "request_body_sha256"}:
            raise FailureRetryError(f"{phase} activation rows must include request intent hash and bounded timestamps")
        slot = row["slot"]
        if slot not in {"tenant_a", "tenant_b"} or slot in by_slot or row["step"] != "activate" or row["status"] != status:
            raise FailureRetryError(f"{phase} must contain one expected activation status per tenant slot")
        start, done = _time(row["request_started_at_utc"], f"{phase}.request_started_at_utc"), _time(row["observed_at_utc"], f"{phase}.observed_at_utc")
        if not target["window_start"] <= start <= done <= target["window_end"] or done - start > target["max_request_ms"]:
            raise FailureRetryError(f"{phase} activation request is outside the bounded lifecycle window")
        by_slot[slot] = {**row, "start_ms": start, "done_ms": done}
    app_task = value["app_task_arn"]
    if not isinstance(app_task, str) or not app_task.startswith(prefix) or not re.fullmatch(r"[A-Fa-f0-9]{32}", app_task.rsplit("/", 1)[-1]):
        raise FailureRetryError(f"{phase} app task is outside the exact protected cluster")
    if value["app_task_definition_arn"] != target["app_task_definition_arn"] or value["app_image_uri"] != target["app_image_uri"]:
        raise FailureRetryError(f"{phase} app task definition or immutable image differs from manifest")
    return {"task_arn": task, "app_task_arn": app_task, "app_task_definition_arn": value["app_task_definition_arn"], "app_image_uri": value["app_image_uri"],
            "task_definition_arn": value["task_definition_arn"], "image_uri": value["image_uri"],
            "invocation_id": value["invocation_id"], "invocation_digest": value["invocation_digest"],
            "rows": [by_slot[x] for x in ("tenant_a", "tenant_b")]}


def _access_denied_events(value: Any, target: dict[str, Any], app_task_arn: str, intervals: list[tuple[int, int]]) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("Events"), list):
        raise FailureRetryError("pregrant CloudTrail LookupEvents response is malformed")
    task_id = app_task_arn.rsplit("/", 1)[-1]
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for outer in value["Events"]:
        if not isinstance(outer, dict) or outer.get("EventName") != "DescribeKey":
            continue
        try:
            inner = json.loads(outer["CloudTrailEvent"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        ident = inner.get("userIdentity", {})
        session = ident.get("sessionContext", {}) if isinstance(ident, dict) else {}
        issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
        params = inner.get("requestParameters", {})
        try:
            timestamp = _time(inner.get("eventTime"), "CloudTrail.eventTime")
        except FailureRetryError:
            continue
        if (inner.get("eventID") != outer.get("EventId") or inner.get("eventName") != "DescribeKey"
                or inner.get("eventSource") != "kms.amazonaws.com" or outer.get("EventSource") != "kms.amazonaws.com"
                or _time(outer.get("EventTime"), "CloudTrail.LookupEvents.EventTime") != timestamp
                or inner.get("awsRegion") != target["region"] or inner.get("recipientAccountId") != target["account"]
                or ident.get("type") != "AssumedRole" or issuer.get("arn") != target["runtime_role_arn"]
                or not str(ident.get("principalId", "")).endswith(":" + task_id)
                or not isinstance(params, dict) or params.get("keyId") != target["key_arn"]
                or inner.get("errorCode") not in {"AccessDenied", "AccessDeniedException"}):
            continue
        eid = outer.get("EventId")
        if not isinstance(eid, str) or not eid or eid in seen:
            raise FailureRetryError("pregrant CloudTrail event IDs must be unique")
        seen.add(eid)
        if any(a <= timestamp <= b for a, b in intervals):
            found.append({"event_id": eid, "time_ms": timestamp})
    selected = []
    for start, done in intervals:
        matches = [e for e in found if start <= e["time_ms"] <= done and e not in selected]
        if len(matches) != 1:
            raise FailureRetryError("each 501 must correlate to one exact runtime-role KMS DescribeKey AccessDenied")
        selected.append(matches[0])
    return selected


def _execute_command(value: Any, execution: dict[str, Any], target: dict[str, Any], phase: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("Events"), list):
        raise FailureRetryError(f"{phase} ECS ExecuteCommand CloudTrail lookup is malformed")
    matches = []
    task_id = execution["task_arn"].rsplit("/", 1)[-1]
    expected_command = f"{target['operator_entrypoint']} --phase {phase}"
    for outer in value["Events"]:
        if not isinstance(outer, dict) or outer.get("EventName") != "ExecuteCommand":
            continue
        try:
            inner = json.loads(outer["CloudTrailEvent"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        identity = inner.get("userIdentity", {})
        session = identity.get("sessionContext", {}) if isinstance(identity, dict) else {}
        issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
        params = inner.get("requestParameters", {})
        event_time = _time(inner.get("eventTime"), "ExecuteCommand.eventTime")
        if (inner.get("eventID") == outer.get("EventId") == execution["invocation_id"]
                and inner.get("eventName") == "ExecuteCommand" and inner.get("eventSource") == "ecs.amazonaws.com"
                and outer.get("EventSource") == "ecs.amazonaws.com" and inner.get("awsRegion") == target["region"]
                and inner.get("recipientAccountId") == target["account"] and identity.get("type") == "AssumedRole"
                and issuer.get("arn") == target["controller_role_arn"] and isinstance(params, dict)
                and params.get("cluster") in {target["cluster_arn"], target["cluster_arn"].rsplit("/", 1)[-1]}
                and params.get("task") in {execution["task_arn"], task_id}
                and params.get("container") == target["operator_container_name"]
                and params.get("command") == expected_command and params.get("interactive") is True):
            matches.append({"event_id": outer["EventId"], "time_ms": event_time})
    if len(matches) != 1:
        raise FailureRetryError(f"{phase} must match exactly one authenticated ECS ExecuteCommand event to task/container/phase")
    return matches[0]


def _d1_snapshot(payload: Any, tenants: list[str], key_arn: str, *, allow_empty: bool, d1_target: dict[str, Any] | None = None) -> dict[str, Any]:
    fields = {"tenant_id", "mode", "cmk_provider", "cmk_key_id", "state", "updated_at_ms"}
    try:
        if isinstance(payload, dict) and set(payload) == {"observed_at_utc", "endpoint", "database_id", "region", "query_sha256", "response_sha256", "row_count", "slot_states", "read_only_metadata"}:
            observed = _time(payload["observed_at_utc"], "D1.observed_at_utc")
            if d1_target is None or not d1_target["window_start"] <= observed <= d1_target["window_end"]:
                raise ValueError("public D1 summary timestamp is outside the protected target window")
            expected_path = f"/accounts/{d1_target['cf_account']}/d1/database/{d1_target['d1_database']}/query"
            expected_endpoint = cf.CF_API + expected_path
            sql = ("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms "
                   "FROM tenant_byok_config WHERE tenant_id IN (?, ?) ORDER BY tenant_id")
            expected_query_digest = hashlib.sha256(json.dumps({"sql": sql, "params": tenants}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if payload["endpoint"] != expected_endpoint or payload["database_id"] != d1_target["d1_database"] or payload["region"] != d1_target["d1_region"] or payload["query_sha256"] != expected_query_digest:
                raise ValueError("public D1 summary endpoint/query does not match the exact protected target")
            if not re.fullmatch(r"[a-f0-9]{64}", payload["query_sha256"]) or not re.fullmatch(r"[a-f0-9]{64}", payload["response_sha256"]):
                raise ValueError("public D1 summary hashes are malformed")
            if type(payload["row_count"]) is not int or payload["row_count"] not in {0, 2}:
                raise ValueError("public D1 summary row count is malformed")
            slot_states = payload["slot_states"]
            if not isinstance(slot_states, list) or len(slot_states) != payload["row_count"] or any(not isinstance(x, dict) or set(x) != {"mode", "cmk_provider", "state", "updated_at_ms", "slot"} or x.get("slot") not in {"tenant_a", "tenant_b"} for x in slot_states):
                raise ValueError("public D1 summary slot states are malformed")
            meta = payload["read_only_metadata"]
            rows = []
            for item in slot_states:
                # Public summaries intentionally omit tenant IDs and key identifiers.
                rows.append({"slot": item["slot"], "mode": item.get("mode"), "cmk_provider": item.get("cmk_provider"), "state": item.get("state"), "updated_at_ms": item.get("updated_at_ms")})
            if len({r["slot"] for r in rows}) != len(rows):
                raise ValueError("public D1 summary duplicates a tenant slot")
            if not allow_empty and payload["row_count"] != 2:
                raise ValueError("postretry summary is incomplete")
            if not allow_empty and any(r["mode"] != "byok" or r["cmk_provider"] != "aws" or r["state"] not in {"pending", "active"} or type(r["updated_at_ms"]) is not int for r in rows):
                raise ValueError("postretry summary does not show expected BYOK state")
            if meta != {"changed_db": False, "rows_written": 0, "changes": 0}:
                raise ValueError("public D1 summary does not prove zero-write SELECT")
            return {"rows": rows, "meta": meta, "response_sha256": payload["response_sha256"], "query_sha256": payload["query_sha256"], "observed_at_utc": payload["observed_at_utc"]}
        if isinstance(payload, dict) and set(payload) == {"observed_at_utc", "endpoint", "database_id", "region", "query_sha256", "response_sha256", "rows", "read_only_metadata"}:
            rows = payload["rows"]
            meta = payload["read_only_metadata"]
            if (not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) != fields for row in rows)
                    or not re.fullmatch(r"[a-f0-9]{64}", payload["response_sha256"])
                    or hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != payload["response_sha256"]
                    or not re.fullmatch(r"[a-f0-9]{64}", payload["query_sha256"])):
                raise ValueError("normalized D1 snapshot digest or rows mismatch")
        else:
            rows = cf._extract_select_rows(payload, fields)
            meta = payload["result"][0]["meta"]
    except Exception as exc:
        raise FailureRetryError("D1 evidence must be a successful zero-write SELECT readback") from exc
    if meta.get("changed_db") is not False or type(meta.get("rows_written")) is not int or meta["rows_written"] != 0 or type(meta.get("changes")) is not int or meta["changes"] != 0:
        raise FailureRetryError("D1 readback metadata must prove no mutation")
    if len(rows) > 2 or any(row.get("tenant_id") not in tenants for row in rows):
        raise FailureRetryError("D1 readback contains rows outside the two disposable tenants")
    if not allow_empty and len(rows) != 2:
        raise FailureRetryError("postretry D1 SELECT must prove one exact row for each tenant")
    if rows:
        if len(rows) != 2 or {r.get("tenant_id") for r in rows} != set(tenants):
            raise FailureRetryError("D1 SELECT must contain one exact row per tenant when rows exist")
        if not allow_empty:
            for row in rows:
                if row.get("mode") != "byok" or row.get("cmk_provider") != "aws" or row.get("cmk_key_id") != key_arn or row.get("state") not in {"pending", "active"} or type(row.get("updated_at_ms")) is not int:
                    raise FailureRetryError("postretry D1 rows do not prove the requested BYOK state")
    rows.sort(key=lambda row: row["tenant_id"])
    return {"rows": rows, "meta": {"changed_db": False, "rows_written": 0, "changes": 0}}


def _postretry_d1(manifest: dict[str, Any], env: dict[str, str], api: Any, target: dict[str, Any]) -> dict[str, Any]:
    cf_target = manifest.get("cloudflare")
    d1 = cf_target.get("d1") if isinstance(cf_target, dict) else None
    token = env.get("B083_CF_API_TOKEN", "")
    if (not isinstance(d1, dict) or cf_target.get("account_alias") != "cf5128" or cf_target.get("account_id") != cf.APPROVED_ACCOUNT_ID
            or d1.get("binding") != "B083_D1" or not token or env.get("B083_CF_ACCOUNT_ID") != cf_target.get("account_id")
            or env.get("B083_D1_DATABASE_ID") != d1.get("database_id") or env.get("B083_D1_REGION") != d1.get("region")):
        raise FailureRetryError("protected CF5128 D1 binding and read-only token are required for postretry readback")
    path = f"/accounts/{cf_target['account_id']}/d1/database/{d1['database_id']}/query"
    sql = ("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms "
           "FROM tenant_byok_config WHERE tenant_id IN (?, ?) ORDER BY tenant_id")
    payload = api("POST", path, token, {"sql": sql, "params": target["tenants"]})
    return _d1_snapshot(payload, target["tenants"], target["key_arn"], allow_empty=False)


def build_receipt(manifest: Any, env: dict[str, str], pregrant_exec_raw: Any, retry_exec_raw: Any,
                  pregrant_cloudtrail: Any, retry_cloudtrail: Any, grant_receipt: Any, grant_cloudtrail: Any,
                  d1_baseline: Any, d1_pregrant: Any, *, d1_api: Any, evidence_out: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema") != "corelink-issue-2165-kms-runtime-v1" or manifest.get("environment") != "b083-kms-lifecycle":
        raise FailureRetryError("manifest is not the protected #2165 lifecycle target")
    aws = manifest.get("aws")
    if not isinstance(aws, dict):
        raise FailureRetryError("manifest AWS binding is missing")
    operator = manifest.get("operator")
    tenants = manifest.get("disposable_tenants")
    window = manifest.get("lifecycle_window")
    if not isinstance(operator, dict) or not isinstance(tenants, list) or len(tenants) != 2 or len(set(tenants)) != 2 or not all(isinstance(x, str) for x in tenants):
        raise FailureRetryError("exactly two protected distinct tenants and operator task binding are required")
    try:
        window_start, window_end = window["started_at_ms"], window["ended_at_ms"]
    except (TypeError, KeyError):
        raise FailureRetryError("protected lifecycle window is missing")
    max_request = operator.get("max_activation_request_ms", 30000)
    max_retry_elapsed = operator.get("max_retry_elapsed_ms", 120000)
    if type(window_start) is not int or type(window_end) is not int or not 0 < window_end - window_start <= 3600000 or type(max_request) is not int or not 0 < max_request <= 120000 or type(max_retry_elapsed) is not int or not 0 < max_retry_elapsed <= 600000:
        raise FailureRetryError("protected lifecycle and activation time bounds are invalid")
    target = {"cluster_arn": aws.get("cluster_arn"), "operator_task_definition_arn": operator.get("task_definition_arn"),
              "operator_image_uri": operator.get("image_uri"), "app_task_definition_arn": aws.get("task_definition_arn"),
              "app_image_uri": aws.get("image_uri"), "runtime_role_arn": aws.get("runtime_role_arn"),
              "custodian_role_arn": aws.get("custodian_role_arn"), "controller_role_arn": aws.get("controller_role_arn"),
              "operator_entrypoint": operator.get("entrypoint"), "operator_container_name": operator.get("container_name"),
              "account": aws.get("account_id"), "region": aws.get("region"), "key_arn": aws.get("cmk_arn"),
              "tenants": tenants, "window_start": window_start, "window_end": window_end, "max_request_ms": max_request, "max_retry_elapsed_ms": max_retry_elapsed}
    cf_target = manifest.get("cloudflare")
    d1 = cf_target.get("d1") if isinstance(cf_target, dict) else None
    if isinstance(cf_target, dict) and isinstance(d1, dict):
        target.update({"cf_account": cf_target.get("account_id"), "d1_database": d1.get("database_id"), "d1_region": d1.get("region")})
    if not all(isinstance(target[k], str) and target[k] for k in ("cluster_arn", "operator_task_definition_arn", "operator_image_uri", "operator_entrypoint", "operator_container_name", "app_task_definition_arn", "app_image_uri", "runtime_role_arn", "custodian_role_arn", "controller_role_arn", "account", "region", "key_arn")) or any(not re.search(r"@sha256:[a-f0-9]{64}$", target[k]) for k in ("operator_image_uri", "app_image_uri")):
        raise FailureRetryError("protected AWS/operator task and digest-pinned image bindings are required")
    pre = _exec(pregrant_exec_raw, "pregrant", target, 501)
    retry = _exec(retry_exec_raw, "retry", target, 202)
    if pre["task_definition_arn"] != retry["task_definition_arn"] or pre["image_uri"] != retry["image_uri"] or pre["invocation_id"] == retry["invocation_id"] or pre["invocation_digest"] == retry["invocation_digest"]:
        raise FailureRetryError("retry must be a distinct authenticated ECS Exec invocation using the same exact operator task definition/image")
    for left, right in zip(pre["rows"], retry["rows"], strict=True):
        if left["request_body_sha256"] != right["request_body_sha256"]:
            raise FailureRetryError("postgrant activation must replay the exact pregrant request body for each tenant slot")
        if right["start_ms"] <= left["done_ms"]:
            raise FailureRetryError("postgrant retry request must start after the authenticated pregrant denial")
    pre_exec_event = _execute_command(pregrant_cloudtrail, pre, target, "pregrant-deny")
    retry_exec_event = _execute_command(retry_cloudtrail, retry, target, "lifecycle")
    if pre_exec_event["event_id"] == retry_exec_event["event_id"] or pre_exec_event["time_ms"] >= retry_exec_event["time_ms"]:
        raise FailureRetryError("pregrant and retry need distinct ordered ECS ExecuteCommand events")
    create_time = _time(grant_receipt.get("observed_at_utc"), "grant_receipt.observed_at_utc") if isinstance(grant_receipt, dict) else 0
    if not isinstance(grant_receipt, dict) or grant_receipt.get("schema") != "corelink.issue-2165-kms-custodian-receipt-v1" or grant_receipt.get("stage") != "grant":
        raise FailureRetryError("exact custodian CreateGrant receipt is required")
    actions = grant_receipt.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or actions[0].get("operation") != "create-grant" or actions[0].get("readback") != "exact" or set(actions[0].get("operations", [])) != {"Encrypt", "Decrypt", "DescribeKey"}:
        raise FailureRetryError("custodian receipt must read back exactly one scoped CreateGrant")
    grant_id = actions[0].get("grant_id")
    if not isinstance(grant_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", grant_id):
        raise FailureRetryError("CreateGrant receipt lacks a safe GrantId")
    grant_matches = []
    if not isinstance(grant_cloudtrail, dict) or not isinstance(grant_cloudtrail.get("Events"), list):
        raise FailureRetryError("custodian CreateGrant CloudTrail readback is required")
    run_id = grant_receipt.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id) or env.get("GITHUB_RUN_ID") != run_id:
        raise FailureRetryError("custodian grant receipt must match the protected workflow run ID")
    for outer in grant_cloudtrail["Events"]:
        if not isinstance(outer, dict) or outer.get("EventName") != "CreateGrant":
            continue
        try:
            inner = json.loads(outer["CloudTrailEvent"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        response = inner.get("responseElements", {})
        params = inner.get("requestParameters", {})
        identity = inner.get("userIdentity", {})
        session = identity.get("sessionContext", {}) if isinstance(identity, dict) else {}
        issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
        principal_id = identity.get("principalId", "") if isinstance(identity, dict) else ""
        if (inner.get("eventID") == outer.get("EventId") and inner.get("eventName") == "CreateGrant" and inner.get("eventSource") == "kms.amazonaws.com"
                and inner.get("awsRegion") == target["region"] and inner.get("recipientAccountId") == target["account"]
                and identity.get("type") == "AssumedRole" and issuer.get("arn") == target["custodian_role_arn"]
                and isinstance(principal_id, str) and principal_id.endswith(":i2165-custodian-" + run_id)
                and isinstance(params, dict) and params.get("keyId") == target["key_arn"] and params.get("granteePrincipal") == target["runtime_role_arn"]
                and params.get("name") == "issue-2165-" + run_id
                and set(params.get("operations", [])) == {"Encrypt", "Decrypt", "DescribeKey"} and isinstance(response, dict) and response.get("grantId") == grant_id):
            grant_matches.append({"event_id": outer["EventId"], "time_ms": _time(inner.get("eventTime"), "CreateGrant.eventTime")})
    if len(grant_matches) != 1:
        raise FailureRetryError("CloudTrail must contain exactly one custodian CreateGrant matching the receipt")
    grant_match = grant_matches[0]
    if grant_match["time_ms"] != create_time:
        raise FailureRetryError("CloudTrail CreateGrant must exactly match the custodian receipt event time, key, role, operations, and GrantId")
    retry_started = min(row["start_ms"] for row in retry["rows"])
    pre_intervals = [(row["start_ms"], row["done_ms"]) for row in pre["rows"]]
    denied = _access_denied_events(pregrant_cloudtrail, target, pre["app_task_arn"], pre_intervals)
    if not max(e["time_ms"] for e in denied) < grant_match["time_ms"] < retry_started:
        raise FailureRetryError("ordering must be runtime DescribeKey denial, then custodian grant, then same-intent retry")
    if max(row["done_ms"] for row in retry["rows"]) - min(row["start_ms"] for row in pre["rows"]) > target["max_retry_elapsed_ms"]:
        raise FailureRetryError("pregrant-to-retry elapsed time exceeds the protected retry bound")
    before_state = _d1_snapshot(d1_baseline, tenants, target["key_arn"], allow_empty=True, d1_target=target)
    pre_state = _d1_snapshot(d1_pregrant, tenants, target["key_arn"], allow_empty=True, d1_target=target)
    before_comparable = {k: v for k, v in before_state.items() if k != "observed_at_utc"}
    pre_comparable = {k: v for k, v in pre_state.items() if k != "observed_at_utc"}
    if before_comparable != pre_comparable or (before_state.get("observed_at_utc") and pre_state.get("observed_at_utc") and _time(before_state["observed_at_utc"], "baseline.observed_at_utc") > _time(pre_state["observed_at_utc"], "pregrant.observed_at_utc")):
        raise FailureRetryError("pregrant D1 baseline and post-denial snapshots must be identical")
    post_state = _postretry_d1(manifest, env, d1_api, target)
    if any(row["start_ms"] <= grant_match["time_ms"] for row in retry["rows"]):
        raise FailureRetryError("retry cannot start before the exact grant event")
    for slot_row in retry["rows"]:
        matching = next(r for r in post_state["rows"] if r["tenant_id"] == tenants[0 if slot_row["slot"] == "tenant_a" else 1])
        if not slot_row["start_ms"] <= matching["updated_at_ms"] <= slot_row["done_ms"]:
            raise FailureRetryError("D1 state change must fall inside its authenticated retry request interval")
    evidence = {"schema": "corelink.issue-2165-failure-retry-evidence.v1", "pregrant_exec": pregrant_exec_raw,
                "retry_exec": retry_exec_raw, "pregrant_cloudtrail": pregrant_cloudtrail, "retry_cloudtrail": retry_cloudtrail, "grant_receipt": grant_receipt,
                "grant_cloudtrail": grant_cloudtrail, "d1_baseline": d1_baseline, "d1_pregrant": d1_pregrant, "d1_postretry": post_state,
                "selected_denied_events": denied, "selected_grant_event": grant_match}
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source_ids = [pre_exec_event["event_id"], retry_exec_event["event_id"], grant_match["event_id"], *(event["event_id"] for event in denied)]
    ref = "failure-retry/" + "/".join(source_ids)
    if len(ref) > 256:
        raise FailureRetryError("source-backed failure_retry event reference exceeds archive bound")
    occurred = datetime.fromtimestamp(max(row["done_ms"] for row in retry["rows"]) / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    receipt = {"step": "failure_retry", "occurred_at_utc": occurred, "source": {"kind": "runtime", "event_ref": ref, "digest": digest}}
    if evidence_out is not None:
        evidence_out.append(evidence)
    return receipt


def _read(path: Path, temp: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.resolve().parent != temp or path.stat().st_mode & 0o077:
        raise FailureRetryError("protected evidence inputs must be regular mode-0600 files directly under RUNNER_TEMP")
    return json.loads(path.read_text(encoding="utf-8"))


def _write_private(path: Path, temp: Path, value: Any) -> None:
    if path.resolve().parent != temp:
        raise FailureRetryError("outputs must be directly under RUNNER_TEMP")
    fd, temporary = tempfile.mkstemp(prefix=".issue-2165-failure-retry-", dir=temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "pregrant-exec", "retry-exec", "pregrant-cloudtrail", "retry-cloudtrail", "grant-receipt", "grant-cloudtrail", "d1-baseline", "d1-pregrant", "output", "evidence"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
        names = ("manifest", "pregrant_exec", "retry_exec", "pregrant_cloudtrail", "retry_cloudtrail", "grant_receipt", "grant_cloudtrail", "d1_baseline", "d1_pregrant")
        paths = (args.manifest, args.pregrant_exec, args.retry_exec, args.pregrant_cloudtrail, args.retry_cloudtrail, args.grant_receipt, args.grant_cloudtrail, args.d1_baseline, args.d1_pregrant)
        loaded = dict(zip(names, (_read(path, temp) for path in paths), strict=True))
        evidence: list[dict[str, Any]] = []
        receipt = build_receipt(loaded["manifest"], dict(os.environ), loaded["pregrant_exec"], loaded["retry_exec"], loaded["pregrant_cloudtrail"], loaded["retry_cloudtrail"], loaded["grant_receipt"], loaded["grant_cloudtrail"], loaded["d1_baseline"], loaded["d1_pregrant"], d1_api=cf._api_json, evidence_out=evidence)
        for path, value in ((args.output, receipt), (args.evidence, evidence[0])):
            _write_private(path, temp, value)
        output = os.environ.get("GITHUB_OUTPUT")
        if not output:
            raise FailureRetryError("GITHUB_OUTPUT is required")
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("audit_source_receipt_json=" + json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        print("failure/retry evidence: PASS")
        return 0
    except (FailureRetryError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"failure/retry evidence: FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
