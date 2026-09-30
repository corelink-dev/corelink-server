#!/usr/bin/env python3
"""Correlate runtime-role KMS access with protected BYOK activation writes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import issue_2165_cf5128_readback as cf


class ProviderAccessError(ValueError):
    """Provider access evidence is incomplete or outside the bound target."""


def _utc_ms(value: Any, field: str) -> int:
    if not isinstance(value, str):
        raise ProviderAccessError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderAccessError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ProviderAccessError(f"{field} must be UTC")
    return int(parsed.timestamp() * 1000)


def _manifest(m: Any, env: dict[str, str]) -> dict[str, Any]:
    if not isinstance(m, dict) or m.get("schema") != "corelink-issue-2165-kms-runtime-v1" or m.get("environment") != "b083-kms-lifecycle":
        raise ProviderAccessError("manifest is not the protected #2165 lifecycle target")
    aws, cf_target = m.get("aws"), m.get("cloudflare")
    if not isinstance(aws, dict) or not isinstance(cf_target, dict):
        raise ProviderAccessError("manifest lacks AWS or Cloudflare target")
    account, region, key_arn, role_arn, cluster_arn, task_definition_arn, image_uri = (aws.get(x) for x in ("account_id", "region", "cmk_arn", "runtime_role_arn", "cluster_arn", "task_definition_arn", "image_uri"))
    if not all(isinstance(x, str) and x for x in (account, region, key_arn, role_arn, cluster_arn, task_definition_arn, image_uri)):
        raise ProviderAccessError("manifest AWS account/region/key/cluster/task definition/image/runtime role are required")
    if env.get("B083_AWS_ACCOUNT_ID") != account or env.get("B083_AWS_REGION") != region or env.get("B083_KMS_KEY_ARN") != key_arn or env.get("B083_AWS_RUNTIME_ROLE_ARN") != role_arn:
        raise ProviderAccessError("protected AWS identity bindings differ from manifest")
    if (env.get("B083_AWS_CLUSTER_ARN") != cluster_arn or env.get("B083_AWS_TASK_DEFINITION_ARN") != task_definition_arn
            or env.get("B083_IMAGE_URI") != image_uri or not re.search(r"@sha256:[a-f0-9]{64}$", image_uri)):
        raise ProviderAccessError("protected app task definition/image/cluster bindings differ from manifest")
    preflight_role = env.get("B083_AWS_PREFLIGHT_ROLE_ARN", "")
    if not preflight_role.startswith(f"arn:aws:iam::{account}:role/"):
        raise ProviderAccessError("protected readback role is outside the target AWS account")
    if not key_arn.startswith(f"arn:aws:kms:{region}:{account}:key/"):
        raise ProviderAccessError("CMK ARN is outside the exact protected account/region")
    tenants = m.get("disposable_tenants")
    if not isinstance(tenants, list) or len(tenants) != 2 or len(set(tenants)) != 2 or any(not isinstance(x, str) or not x for x in tenants):
        raise ProviderAccessError("exactly two distinct disposable tenants are required")
    window = m.get("lifecycle_window")
    start, end = (window.get(x) for x in ("started_at_ms", "ended_at_ms")) if isinstance(window, dict) else (None, None)
    if type(start) is not int or type(end) is not int or not 0 < end - start <= 60 * 60 * 1000:
        raise ProviderAccessError("manifest lifecycle window must be ordered and <=60 minutes")
    if (cf_target.get("account_alias") != "cf5128" or cf_target.get("account_id") != cf.APPROVED_ACCOUNT_ID
            or cf_target.get("account_id") == cf.PRODUCTION_ACCOUNT_ID or env.get("B083_CF_ACCOUNT_ID") != cf_target.get("account_id")):
        raise ProviderAccessError("protected isolated CF5128 target binding is missing")
    d1 = cf_target.get("d1")
    if not isinstance(d1, dict) or d1.get("binding") != "B083_D1" or env.get("B083_D1_DATABASE_ID") != d1.get("database_id") or env.get("B083_D1_REGION") != d1.get("region"):
        raise ProviderAccessError("protected D1 database/region binding differs from manifest")
    if not env.get("B083_CF_API_TOKEN"):
        raise ProviderAccessError("protected CF5128 read-only token is required")
    return {"account": account, "region": region, "key_arn": key_arn, "role_arn": role_arn,
            "cluster_arn": cluster_arn, "task_definition_arn": task_definition_arn, "image_uri": image_uri,
            "preflight_role": preflight_role, "tenants": tenants, "start": start, "end": end, "cf": cf_target, "d1": d1}


def _activation_rows(value: Any, target: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise ProviderAccessError("exactly two authenticated activation observations are required")
    by_slot: dict[str, dict[str, Any]] = {}
    for row in value:
        if not isinstance(row, dict) or set(row) != {"slot", "step", "status", "request_started_at_utc", "observed_at_utc"}:
            raise ProviderAccessError("activation rows must contain only slot, step, status, request-start UTC, and observed UTC")
        slot = row["slot"]
        if slot not in {"tenant_a", "tenant_b"} or row["step"] != "activate" or row["status"] != 202 or slot in by_slot:
            raise ProviderAccessError("both tenant activation routes must return one HTTP 202")
        stamp = _utc_ms(row["observed_at_utc"], "activation.observed_at_utc")
        started = _utc_ms(row["request_started_at_utc"], "activation.request_started_at_utc")
        if not target["start"] <= started <= stamp <= target["end"]:
            raise ProviderAccessError("activation timestamp is outside the protected lifecycle window")
        by_slot[slot] = {**row, "time_ms": stamp, "start_ms": started}
    return [by_slot[slot] for slot in ("tenant_a", "tenant_b")]


def _cloudtrail_events(value: Any, target: dict[str, Any], app_task_arn: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("Events"), list):
        raise ProviderAccessError("CloudTrail LookupEvents response is malformed")
    expected_task_prefix = target["cluster_arn"].replace(":cluster/", ":task/") + "/"
    if not app_task_arn.startswith(expected_task_prefix):
        raise ProviderAccessError("app task ARN is outside the exact protected ECS cluster")
    task_id = app_task_arn.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Fa-f0-9]{32}", task_id):
        raise ProviderAccessError("app task ARN must identify the exact started ECS task")
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for outer in value["Events"]:
        if not isinstance(outer, dict) or outer.get("EventName") != "DescribeKey":
            continue
        try:
            inner = json.loads(outer["CloudTrailEvent"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        identity = inner.get("userIdentity", {})
        session = identity.get("sessionContext", {}) if isinstance(identity, dict) else {}
        issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
        principal = identity.get("principalId", "") if isinstance(identity, dict) else ""
        event_time = _utc_ms(inner.get("eventTime"), "CloudTrail.eventTime")
        outer_time = _utc_ms(outer.get("EventTime"), "CloudTrail.LookupEvents.EventTime")
        request = inner.get("requestParameters", {})
        if not isinstance(request, dict):
            continue
        if (inner.get("eventID") != outer.get("EventId") or event_time != outer_time or inner.get("eventName") != "DescribeKey"
                or inner.get("eventSource") != "kms.amazonaws.com" or outer.get("EventSource") != "kms.amazonaws.com"
                or inner.get("awsRegion") != target["region"]
                or inner.get("recipientAccountId") != target["account"] or identity.get("type") != "AssumedRole"
                or issuer.get("arn") != target["role_arn"]
                or not isinstance(principal, str) or not principal.endswith(":" + task_id)
                or request.get("keyId") != target["key_arn"]):
            continue
        event_id = outer.get("EventId")
        if not isinstance(event_id, str) or not event_id or event_id in seen:
            raise ProviderAccessError("CloudTrail DescribeKey event IDs must be unique and nonempty")
        seen.add(event_id)
        if not target["start"] <= event_time <= target["end"]:
            continue
        selected.append({"event_id": event_id, "event_time_ms": event_time})
    selected.sort(key=lambda row: row["event_time_ms"])
    if not selected:
        raise ProviderAccessError("runtime-role DescribeKey events for the bound task are missing")
    return selected


def _activation_d1_rows(api: Callable[..., dict[str, Any]], target: dict[str, Any], token: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    d1 = target["d1"]
    path = f"/accounts/{target['cf']['account_id']}/d1/database/{d1['database_id']}/query"
    sql = ("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms "
           "FROM tenant_byok_config WHERE tenant_id IN (?, ?) ORDER BY tenant_id")
    params = list(target["tenants"])
    payload = api("POST", path, token, {"sql": sql, "params": params})
    try:
        rows = cf._extract_select_rows(payload, {"tenant_id", "mode", "cmk_provider", "cmk_key_id", "state", "updated_at_ms"})
    except cf.ReadbackError as exc:
        raise ProviderAccessError("D1 activation readback did not prove a zero-write exact-row SELECT") from exc
    meta = payload["result"][0]["meta"]
    if meta.get("changed_db") is not False or type(meta.get("rows_written")) is not int or meta["rows_written"] != 0 or type(meta.get("changes")) is not int or meta["changes"] != 0:
        raise ProviderAccessError("D1 activation readback must prove zero-write SELECT metadata")
    if len(rows) != 2:
        raise ProviderAccessError("D1 must return exactly one activation config row per disposable tenant")
    ordered = []
    for tenant, activation in zip(target["tenants"], ("tenant_a", "tenant_b"), strict=True):
        row = next((r for r in rows if r["tenant_id"] == tenant), None)
        if not row or row["mode"] != "byok" or row["cmk_provider"] != "aws" or row["cmk_key_id"] != target["key_arn"] or row["state"] not in {"pending", "active"} or type(row["updated_at_ms"]) is not int:
            raise ProviderAccessError("D1 row does not prove the exact active/pending AWS BYOK target")
        ordered.append({"slot": activation, "updated_at_ms": row["updated_at_ms"]})
    return ordered, {"endpoint": cf.CF_API + path, "sql": sql, "params": params,
                    "response": rows, "meta": {"changed_db": False, "rows_written": 0, "changes": 0}}


def build_receipt(manifest: Any, env: dict[str, str], activations_raw: Any, cloudtrail: Any,
                  app_task_arn: str, *, d1_api: Callable[..., dict[str, Any]], caller_identity: Any,
                  evidence_out: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    target = _manifest(manifest, env)
    if not isinstance(caller_identity, dict) or caller_identity.get("Account") != target["account"]:
        raise ProviderAccessError("AWS caller identity account does not match the protected target")
    caller_arn = caller_identity.get("Arn", "")
    caller_role_name = target["preflight_role"].rsplit("/", 1)[-1]
    caller_pattern = rf"arn:aws:sts::{re.escape(target["account"])}:assumed-role/{re.escape(caller_role_name)}/[A-Za-z0-9+=,.@_-]{{2,128}}"
    if not isinstance(caller_arn, str) or not re.fullmatch(caller_pattern, caller_arn):
        raise ProviderAccessError("CloudTrail read caller is not the protected preflight role")
    activations = _activation_rows(activations_raw, target)
    candidate_events = _cloudtrail_events(cloudtrail, target, app_task_arn)
    activation_rows, d1_evidence = _activation_d1_rows(d1_api, target, env["B083_CF_API_TOKEN"])
    events = []
    for index, (d1row, activation) in enumerate(zip(activation_rows, activations, strict=True)):
        if not activation["start_ms"] <= d1row["updated_at_ms"] <= activation["time_ms"]:
            raise ProviderAccessError(f"tenant slot {index} D1 activation write is outside its authenticated HTTP request interval")
        eligible = [row for row in candidate_events
                    if activation["start_ms"] <= row["event_time_ms"] <= d1row["updated_at_ms"]]
        if not eligible:
            raise ProviderAccessError(f"tenant slot {index} has no runtime-role DescribeKey between activation start and D1 write")
        latest = max(row["event_time_ms"] for row in eligible)
        nearest = [row for row in eligible if row["event_time_ms"] == latest]
        if len(nearest) != 1 or any(nearest[0]["event_id"] == prior["event_id"] for prior in events):
            raise ProviderAccessError(f"tenant slot {index} has an ambiguous or reused DescribeKey event")
        events.append(nearest[0])
    restricted = {"events": events, "activations": activations, "d1": d1_evidence,
                  "app_task_arn": app_task_arn, "runtime_role_arn": target["role_arn"],
                  "task_definition_arn": target["task_definition_arn"], "image_uri": target["image_uri"],
                  "readback_caller_arn": caller_arn}
    digest = hashlib.sha256(json.dumps(restricted, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ref = "kms-describe/" + "/".join(event["event_id"] for event in events) + "/d1-config/" + digest[:16]
    receipt = {"step": "provider_access", "occurred_at_utc": datetime.fromtimestamp(max(row["updated_at_ms"] for row in activation_rows) / 1000, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source": {"kind": "cloudtrail", "event_ref": ref, "digest": digest}}
    if evidence_out is not None:
        evidence_out.append({"schema": "corelink.issue-2165-provider-access-evidence.v1",
                             "cloudtrail_raw": cloudtrail, "activation_rows": activations_raw,
                             "d1_evidence": d1_evidence, "selected_events": events,
                             "app_task_arn": app_task_arn, "task_definition_arn": target["task_definition_arn"],
                             "image_uri": target["image_uri"], "readback_caller_arn": caller_arn,
                             "receipt": receipt})
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--activations", required=True, type=Path)
    parser.add_argument("--cloudtrail", required=True, type=Path)
    parser.add_argument("--caller-identity", required=True, type=Path)
    parser.add_argument("--app-task-arn", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
        inputs = [args.manifest, args.activations, args.cloudtrail, args.caller_identity]
        if any(p.is_symlink() or p.resolve().parent != temp or p.stat().st_mode & 0o077 for p in inputs):
            raise ProviderAccessError("protected input files must be mode 0600 directly under RUNNER_TEMP")
        if args.output.resolve().parent != temp or args.evidence.resolve().parent != temp:
            raise ProviderAccessError("outputs must be directly under RUNNER_TEMP")
        manifest, activations, cloudtrail, caller_identity = (json.loads(p.read_text(encoding="utf-8")) for p in inputs)
        evidence: list[dict[str, Any]] = []
        receipt = build_receipt(manifest, dict(os.environ), activations, cloudtrail, args.app_task_arn,
                                d1_api=cf._api_json, caller_identity=caller_identity, evidence_out=evidence)
        for path, body in ((args.output, receipt), (args.evidence, evidence[0])):
            temp_output = path.with_suffix(path.suffix + ".tmp")
            temp_output.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            temp_output.chmod(0o600)
            temp_output.replace(path)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("audit_source_receipt_json=" + json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        print("provider access evidence: PASS")
        return 0
    except Exception as exc:
        print(f"provider access evidence: FAIL ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
