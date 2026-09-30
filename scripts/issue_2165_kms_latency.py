#!/usr/bin/env python3
"""Build a redacted offline latency receipt from protected #2165 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


BUNDLE_SCHEMA = "corelink.issue-2165-kms-cycle-bundle.v1"
CLOUDTRAIL_SCHEMA = "corelink-issue-2165-cloudtrail-latency-v1"
INPUT_SCHEMA = "corelink.issue-2165-kms-latency-input.v1"
OUTPUT_SCHEMA = "corelink-issue-2165-kms-lifecycle-samples-v1"
MANIFEST_SCHEMA = "corelink-issue-2165-kms-runtime-v1"
ENVIRONMENT = "b083-kms-lifecycle"
WINDOW_LIMIT_MS = 60 * 60 * 1000
LATENCY_LIMIT_MS = 300_000
TENANT_SLOTS = ("tenant_a", "tenant_b")
EXPECTED_CYCLES = tuple(range(1, 11))
CF5128_ACCOUNT_ID = "51284495e71acdb5a7677e7383ab026b"
PRODUCTION_CF_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GITHUB_RUN_ID = re.compile(r"^[0-9]{1,36}$")


class LatencyError(ValueError):
    """Input evidence is missing, inconsistent, or outside the frozen contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _d1_query_hash(target: dict[str, Any], action: str) -> str:
    sql = (
        "SELECT token, tenant_id, epoch, action, cmk_provider, cmk_key_id, outcome, completed_at_ms "
        "FROM byok_control_outcome WHERE tenant_id IN (?, ?) AND cmk_provider = ? AND cmk_key_id = ? "
        "AND action = ? AND outcome = 'completed' AND completed_at_ms >= ? AND completed_at_ms <= ? "
        "ORDER BY completed_at_ms, tenant_id"
    )
    params = [*target["tenants"], "aws", target["key_arn"], action, target["window_start_ms"], target["window_end_ms"]]
    return _sha256({"sql": sql, "params": params})


def _need(obj: Any, key: str, kind: type, where: str) -> Any:
    if not isinstance(obj, dict):
        raise LatencyError(f"{where} must be an object")
    result = obj.get(key)
    if not isinstance(result, kind) or (kind is str and not result.strip()):
        raise LatencyError(f"{where}.{key} is missing or malformed")
    return result


def _timestamp(value: Any, where: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise LatencyError(f"{where} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LatencyError(f"{where} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LatencyError(f"{where} must be an explicit UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _epoch_ms(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000


def _from_epoch_ms(value: int) -> datetime:
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)


def _assumed_role_matches(caller_arn: str, role_arn: str) -> bool:
    if not isinstance(caller_arn, str) or not isinstance(role_arn, str):
        return False
    parts = caller_arn.split(":assumed-role/", 1)
    return len(parts) == 2 and parts[1].split("/", 1)[0] == role_arn.rsplit("/", 1)[-1]


def _check_protected_manifest(manifest: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("environment") != ENVIRONMENT:
        raise LatencyError("protected manifest schema/environment is not the #2165 lifecycle target")
    aws = _need(manifest, "aws", dict, "manifest")
    cloudflare = _need(manifest, "cloudflare", dict, "manifest")
    account_id = _need(aws, "account_id", str, "manifest.aws")
    region = _need(aws, "region", str, "manifest.aws")
    key_arn = _need(aws, "cmk_arn", str, "manifest.aws")
    custodian_role = _need(aws, "custodian_role_arn", str, "manifest.aws")
    if aws.get("cmk_provider") != "aws":
        raise LatencyError("manifest AWS CMK provider must be aws")
    for name, value in (
        ("B083_AWS_ACCOUNT_ID", account_id),
        ("B083_AWS_REGION", region),
        ("B083_KMS_KEY_ARN", key_arn),
        ("B083_AWS_CUSTODIAN_ROLE_ARN", custodian_role),
    ):
        if env.get(name) != value:
            raise LatencyError(f"protected {name} does not match the manifest")
    if not key_arn.startswith(f"arn:aws:kms:{region}:{account_id}:key/"):
        raise LatencyError("manifest CMK ARN is outside its protected AWS account/region")

    if cloudflare.get("account_alias") != "cf5128":
        raise LatencyError("manifest Cloudflare account alias must be cf5128")
    cf_account = _need(cloudflare, "account_id", str, "manifest.cloudflare")
    if cf_account != CF5128_ACCOUNT_ID or cf_account == PRODUCTION_CF_ACCOUNT_ID:
        raise LatencyError("manifest Cloudflare account is not the isolated CF5128 target")
    d1 = _need(cloudflare, "d1", dict, "manifest.cloudflare")
    database_id = _need(d1, "database_id", str, "manifest.cloudflare.d1")
    d1_region = _need(d1, "region", str, "manifest.cloudflare.d1")
    for name, value in (("B083_CF_ACCOUNT_ID", cf_account), ("B083_D1_DATABASE_ID", database_id), ("B083_D1_REGION", d1_region)):
        if env.get(name) != value:
            raise LatencyError(f"protected {name} does not match the manifest")
    tenants = manifest.get("disposable_tenants")
    if not isinstance(tenants, list) or len(tenants) != 2 or any(not isinstance(item, str) or not item for item in tenants) or len(set(tenants)) != 2:
        raise LatencyError("manifest must bind exactly two distinct disposable tenant identifiers")
    window = _need(manifest, "lifecycle_window", dict, "manifest")
    start, end = window.get("started_at_ms"), window.get("ended_at_ms")
    if type(start) is not int or type(end) is not int or start >= end or end - start > WINDOW_LIMIT_MS:
        raise LatencyError("manifest lifecycle window must be ordered and at most 60 minutes")
    if env.get("GITHUB_RUN_ID", "") == "" or not GITHUB_RUN_ID.fullmatch(env["GITHUB_RUN_ID"]):
        raise LatencyError("protected GITHUB_RUN_ID must be a numeric run identifier")
    return {
        "aws_account_id": account_id,
        "aws_region": region,
        "key_arn": key_arn,
        "custodian_role_arn": custodian_role,
        "cf_account_id": cf_account,
        "database_id": database_id,
        "d1_region": d1_region,
        "tenants": tenants,
        "window_start_ms": start,
        "window_end_ms": end,
        "run_id": env["GITHUB_RUN_ID"],
    }


def _verify_attestations(bundle: dict[str, Any], cloudtrail: dict[str, Any], target: dict[str, Any]) -> None:
    run_id = target["run_id"]
    if bundle.get("schema") != BUNDLE_SCHEMA or bundle.get("run_id") != run_id:
        raise LatencyError("cycle bundle schema/run_id does not match the protected run")
    if cloudtrail.get("schema") != CLOUDTRAIL_SCHEMA or cloudtrail.get("run_id") != run_id:
        raise LatencyError("CloudTrail input schema/run_id does not match the protected run")
    window = bundle.get("window")
    if not isinstance(window, dict) or window.get("started_at_ms") != target["window_start_ms"] or window.get("ended_at_ms") != target["window_end_ms"]:
        raise LatencyError("cycle bundle lifecycle window does not match the protected manifest")
    aws = bundle.get("target")
    if not isinstance(aws, dict) or aws.get("cmk_key_arn") != target["key_arn"]:
        raise LatencyError("cycle bundle AWS target metadata does not match the protected manifest")
    if aws.get("cmk_provider") != "aws":
        raise LatencyError("cycle bundle CMK provider is not aws")
    if aws.get("tenant_ids") != target["tenants"] or aws.get("redacted_tenant_slots") != list(TENANT_SLOTS):
        raise LatencyError("cycle bundle tenant slot map does not match the protected manifest")

    ct_source = cloudtrail.get("source")
    events = cloudtrail.get("events")
    if not isinstance(ct_source, dict) or not isinstance(events, list):
        raise LatencyError("CloudTrail event source metadata and events are required")
    if ct_source.get("method") != "LookupEvents" or ct_source.get("account_id") != target["aws_account_id"] or ct_source.get("region") != target["aws_region"]:
        raise LatencyError("CloudTrail input identity/region metadata is not trusted for this target")
    caller_arn = ct_source.get("caller_arn", "")
    if not _assumed_role_matches(caller_arn, target["custodian_role_arn"]) or not caller_arn.startswith(f"arn:aws:sts::{target['aws_account_id']}:assumed-role/"):
        raise LatencyError("CloudTrail input caller does not match the protected custodian role")
    start_utc = _timestamp(ct_source.get("window_start_utc"), "cloudtrail.source.window_start_utc")
    end_utc = _timestamp(ct_source.get("window_end_utc"), "cloudtrail.source.window_end_utc")
    if _epoch_ms(start_utc) != target["window_start_ms"] or _epoch_ms(end_utc) != target["window_end_ms"]:
        raise LatencyError("CloudTrail lookup time bounds differ from the protected lifecycle window")
    digest = ct_source.get("response_sha256")
    if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest) or _sha256(events) != digest:
        raise LatencyError("CloudTrail source response digest is missing or does not match its event records")


def _unwrap_event(row: Any, target: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        raise LatencyError("CloudTrail event row must be an object")
    outer_id = row.get("EventId")
    outer_name = row.get("EventName")
    outer_time = row.get("EventTime")
    raw = row.get("CloudTrailEvent")
    if not isinstance(raw, str):
        raise LatencyError("CloudTrail LookupEvents row is missing nested event JSON")
    try:
        inner = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LatencyError("CloudTrail nested event JSON is invalid") from exc
    if not isinstance(inner, dict):
        raise LatencyError("CloudTrail nested event must be an object")
    inner_id, inner_name = inner.get("eventID"), inner.get("eventName")
    when = _timestamp(inner.get("eventTime"), "CloudTrail eventTime")
    if not isinstance(outer_id, str) or not outer_id or outer_id != inner_id:
        raise LatencyError("CloudTrail outer EventId does not match nested eventID")
    if outer_name != inner_name:
        raise LatencyError("CloudTrail outer EventName does not match nested eventName")
    if _timestamp(outer_time, "CloudTrail LookupEvents EventTime") != when:
        raise LatencyError("CloudTrail outer EventTime does not match nested eventTime")
    if row.get("EventSource") != inner.get("eventSource") or inner.get("eventSource") != "kms.amazonaws.com" or inner.get("awsRegion") != target["aws_region"]:
        raise LatencyError("CloudTrail event source or region does not match the protected target")
    if inner.get("recipientAccountId") != target["aws_account_id"]:
        raise LatencyError("CloudTrail event recipient account does not match the protected account")
    if inner.get("recipientAccountId") != target["aws_account_id"]:
        raise LatencyError("CloudTrail event recipient account does not match the protected account")
    if outer_name not in {"RevokeGrant", "CreateGrant"}:
        return None
    params = inner.get("requestParameters")
    if not isinstance(params, dict):
        raise LatencyError("CloudTrail grant event request parameters are malformed")
    if params.get("keyId") != target["key_arn"]:
        return None
    identity = inner.get("userIdentity")
    if not isinstance(identity, dict) or identity.get("accountId") != target["aws_account_id"] or identity.get("type") != "AssumedRole":
        raise LatencyError("CloudTrail event actor is not an assumed role in the protected account")
    session = identity.get("sessionContext")
    issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
    if not isinstance(issuer, dict) or issuer.get("arn") != target["custodian_role_arn"]:
        raise LatencyError("CloudTrail event actor role does not match the protected custodian")
    if outer_name == "RevokeGrant":
        grant_id = params.get("grantId")
    else:
        grant_id = (inner.get("responseElements") or {}).get("grantId")
        if params.get("name") != f"issue-2165-{run_id}":
            raise LatencyError("CreateGrant event name does not bind the protected run")
    if not isinstance(grant_id, str) or not grant_id:
        raise LatencyError("CloudTrail event lacks the exact GrantId")
    return {"event_id": outer_id, "event_name": outer_name, "event_time_ms": _epoch_ms(when), "grant_id": grant_id}


def _verify_d1_action_source(source: Any, rows: list[dict[str, Any]], action: str, target: dict[str, Any]) -> dict[str, str]:
    if not isinstance(source, dict):
        raise LatencyError("each cycle transition must include authenticated D1 source metadata")
    expected_endpoint = f"https://api.cloudflare.com/client/v4/accounts/{target['cf_account_id']}/d1/database/{target['database_id']}/query"
    if any(source.get(field) != expected for field, expected in (
        ("method", "parameterized-select-post"), ("account_alias", "cf5128"),
        ("endpoint", expected_endpoint), ("account_id", target["cf_account_id"]), ("database_id", target["database_id"]),
        ("d1_region", target["d1_region"]),
    )):
        raise LatencyError("D1 source endpoint/account/database does not match protected CF5128 target")
    metadata = source.get("read_only_metadata")
    if not isinstance(metadata, dict) or metadata.get("changed_db") is not False or type(metadata.get("rows_written")) is not int or metadata["rows_written"] != 0 or type(metadata.get("changes")) is not int or metadata["changes"] != 0:
        raise LatencyError("D1 source metadata does not attest zero-write SELECT")
    observed = _timestamp(source.get("observed_at_utc"), "d1_source.observed_at_utc")
    if not _from_epoch_ms(target["window_start_ms"]) <= observed <= _from_epoch_ms(target["window_end_ms"]):
        raise LatencyError("D1 source read timestamp is outside the protected lifecycle window")
    query_digest = source.get("query_sha256")
    response_digest = source.get("response_sha256")
    selected_digest = source.get("selected_rows_sha256")
    token_set_digest = source.get("selected_token_set_sha256")
    cf_token_identity_digest = source.get("cf_token_identity_sha256")
    for name, digest in (("query_sha256", query_digest), ("response_sha256", response_digest), ("selected_rows_sha256", selected_digest), ("selected_token_set_sha256", token_set_digest)):
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            raise LatencyError(f"D1 source {name} must be a SHA-256 digest")
    if cf_token_identity_digest is not None and (not isinstance(cf_token_identity_digest, str) or not HEX_SHA256.fullmatch(cf_token_identity_digest)):
        raise LatencyError("D1 source cf_token_identity_sha256 must be a SHA-256 digest")
    if query_digest != _d1_query_hash(target, action):
        raise LatencyError("D1 query digest does not match the exact bounded transition SELECT")
    if selected_digest != _sha256(rows):
        raise LatencyError("D1 selected row digest does not match the paired transition rows")
    expected_token_digest = hashlib.sha256("\n".join(sorted(row["token"] for row in rows)).encode()).hexdigest()
    if token_set_digest != expected_token_digest:
        raise LatencyError("D1 selected token-set digest does not match the paired transition rows")
    return {
        "query_sha256": query_digest,
        "response_sha256": response_digest,
        "selected_rows_sha256": selected_digest,
        "selected_token_set_sha256": token_set_digest,
        **({"cf_token_identity_sha256": cf_token_identity_digest} if cf_token_identity_digest is not None else {}),
    }


def _verify_cycle_bundle(bundle: dict[str, Any], cloudtrail: dict[str, Any], target: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]]]:
    raw_events = cloudtrail["events"]
    event_by_id: dict[str, dict[str, Any]] = {}
    all_grants: set[tuple[str, str]] = set()
    seen_raw_event_ids: set[str] = set()
    for row in raw_events:
        if not isinstance(row, dict) or not isinstance(row.get("EventId"), str) or not row["EventId"]:
            raise LatencyError("CloudTrail source contains an event without an exact EventId")
        if row["EventId"] in seen_raw_event_ids:
            raise LatencyError("CloudTrail event IDs must be unique")
        seen_raw_event_ids.add(row["EventId"])
        outer_instant = _timestamp(row.get("EventTime"), "CloudTrail LookupEvents EventTime")
        if not _from_epoch_ms(target["window_start_ms"]) <= outer_instant <= _from_epoch_ms(target["window_end_ms"]):
            raise LatencyError("CloudTrail response includes an event outside the lifecycle window")
        event = _unwrap_event(row, target, target["run_id"])
        if event is None:
            continue
        if event["event_id"] in event_by_id:
            raise LatencyError("CloudTrail event IDs must be unique")
        grant_event_key = (event["event_name"], event["grant_id"])
        if grant_event_key in all_grants:
            raise LatencyError("CloudTrail GrantId cannot repeat for the same mutation type")
        event_by_id[event["event_id"]] = event
        all_grants.add(grant_event_key)

    cycles = bundle.get("cycles")
    if not isinstance(cycles, list) or len(cycles) != len(EXPECTED_CYCLES):
        raise LatencyError("cycle bundle must contain exactly ten cycles")
    expected_grant_ids = bundle.get("grant_ids")
    if not isinstance(expected_grant_ids, list) or len(expected_grant_ids) != 11 or any(not isinstance(g, str) or not g for g in expected_grant_ids) or len(set(expected_grant_ids)) != 11:
        raise LatencyError("cycle bundle must bind eleven distinct initial/restored GrantIds")
    if bundle.get("final_grant_id") != expected_grant_ids[-1]:
        raise LatencyError("cycle bundle final GrantId does not match the final restoration")
    by_cycle: dict[int, dict[str, Any]] = {}
    for cycle in cycles:
        if not isinstance(cycle, dict) or type(cycle.get("cycle")) is not int or cycle["cycle"] not in EXPECTED_CYCLES:
            raise LatencyError("cycle identifiers must be the exact sequence 1 through 10")
        if cycle["cycle"] in by_cycle:
            raise LatencyError("cycle identifiers must be unique")
        by_cycle[cycle["cycle"]] = cycle
    if set(by_cycle) != set(EXPECTED_CYCLES):
        raise LatencyError("cycle bundle is missing a cycle")

    result: dict[str, list[dict[str, Any]]] = {"revoke_degrade": [], "restore_active": []}
    d1_digests: list[dict[str, str]] = []
    used_event_ids: set[str] = set()
    used_epochs: set[tuple[str, int]] = set()
    used_tokens: set[str] = set()
    start_ms, end_ms = target["window_start_ms"], target["window_end_ms"]
    previous_restore_end_ms = start_ms
    for cycle_no in EXPECTED_CYCLES:
        cycle = by_cycle[cycle_no]
        cycle_started = _timestamp(cycle.get("cycle_started_at_utc"), "cycle.cycle_started_at_utc")
        cycle_started_ms = _epoch_ms(cycle_started)
        if not _from_epoch_ms(start_ms) <= cycle_started <= _from_epoch_ms(end_ms) or cycle_started_ms <= previous_restore_end_ms:
            raise LatencyError("cycle start timestamp is outside the protected lifecycle window")
        revoke, restore = cycle.get("revoke"), cycle.get("restore")
        if not isinstance(revoke, dict) or not isinstance(restore, dict):
            raise LatencyError("each cycle must contain revoke and restore provider actions")
        if revoke.get("provider_readback") != "absent" or restore.get("provider_readback") != "exact":
            raise LatencyError("provider action readbacks must confirm revoke absent and restore exact")
        revoke_started = _timestamp(revoke.get("started_at_utc"), "cycle.revoke.started_at_utc")
        revoke_ended = _timestamp(revoke.get("ended_at_utc"), "cycle.revoke.ended_at_utc")
        restore_started = _timestamp(restore.get("started_at_utc"), "cycle.restore.started_at_utc")
        restore_ended = _timestamp(restore.get("ended_at_utc"), "cycle.restore.ended_at_utc")
        revoke_start_ms, revoke_ms = _epoch_ms(revoke_started), _epoch_ms(revoke_ended)
        restore_start_ms, restore_ms = _epoch_ms(restore_started), _epoch_ms(restore_ended)
        if not start_ms <= revoke_start_ms <= revoke_ms <= end_ms or not start_ms <= restore_start_ms <= restore_ms <= end_ms or cycle_started > revoke_started or revoke_ms >= restore_start_ms:
            raise LatencyError("provider action timestamps are outside the run window or unordered")
        previous_restore_end_ms = restore_ms
        if revoke.get("grant_id") != expected_grant_ids[cycle_no - 1] or restore.get("grant_id") != expected_grant_ids[cycle_no]:
            raise LatencyError("cycle action GrantIds do not follow the protected grant handoff chain")
        for action_name, action, d1_result, expected_d1_action, event_name, direction in (
            ("revoke", revoke, cycle.get("degrade_rows"), "degrade", "RevokeGrant", "revoke_degrade"),
            ("restore", restore, cycle.get("restore_rows"), "restore", "CreateGrant", "restore_active"),
        ):
            grant_id = action.get("grant_id")
            if not isinstance(grant_id, str) or not grant_id:
                raise LatencyError("provider action GrantId is required")
            matches = [ev for ev in event_by_id.values() if ev["event_name"] == event_name and ev["grant_id"] == grant_id]
            if len(matches) != 1:
                raise LatencyError("each provider GrantId must match exactly one CloudTrail event")
            event = matches[0]
            if event["event_id"] in used_event_ids:
                raise LatencyError("CloudTrail event cannot be paired more than once")
            used_event_ids.add(event["event_id"])
            if not start_ms <= event["event_time_ms"] <= end_ms:
                raise LatencyError("CloudTrail mutation event is outside the lifecycle window")
            action_start_ms, action_end_ms = (revoke_start_ms, revoke_ms) if action_name == "revoke" else (restore_start_ms, restore_ms)
            if not action_start_ms <= event["event_time_ms"] <= action_end_ms:
                raise LatencyError("CloudTrail event time must fall inside its exact provider action receipt")
            if not isinstance(d1_result, dict) or not isinstance(d1_result.get("rows"), list) or len(d1_result["rows"]) != 2:
                raise LatencyError("each provider action must have one D1 row for each tenant slot")
            d1_rows = d1_result["rows"]
            d1_digests.append(_verify_d1_action_source(d1_result.get("d1_source"), d1_rows, expected_d1_action, target))
            slot_rows: dict[str, dict[str, Any]] = {}
            for index, row in enumerate(d1_rows):
                if not isinstance(row, dict):
                    raise LatencyError("D1 action rows must be objects")
                slot = TENANT_SLOTS[index]
                if slot in slot_rows:
                    raise LatencyError("D1 action has a duplicate tenant slot")
                slot_rows[slot] = row
            if set(slot_rows) != set(TENANT_SLOTS):
                raise LatencyError("D1 action is missing a tenant slot")
            for slot in TENANT_SLOTS:
                row = slot_rows[slot]
                expected_fields = {"token", "tenant_id", "epoch", "action", "cmk_provider", "cmk_key_id", "outcome", "completed_at_ms"}
                if set(row) != expected_fields:
                    raise LatencyError("D1 transition row has missing or unexpected fields")
                tenant_id = target["tenants"][TENANT_SLOTS.index(slot)]
                if row.get("tenant_id") != tenant_id:
                    raise LatencyError("D1 tenant ID does not match its protected tenant slot")
                if row.get("action") != expected_d1_action or row.get("outcome") != "completed":
                    raise LatencyError("D1 transition action/outcome does not match the provider direction")
                if row.get("cmk_provider") != "aws" or row.get("cmk_key_id") != target["key_arn"]:
                    raise LatencyError("D1 transition row does not bind the exact protected CMK")
                if not isinstance(row.get("token"), str) or not row["token"] or type(row.get("epoch")) is not int or row["epoch"] < 0:
                    raise LatencyError("D1 transition token/epoch is malformed")
                row_key = (slot, row["epoch"])
                if row_key in used_epochs or row["token"] in used_tokens:
                    raise LatencyError("D1 transition epochs and tokens must be unique per tenant/run")
                used_epochs.add(row_key)
                used_tokens.add(row["token"])
                completed_ms = row.get("completed_at_ms")
                if type(completed_ms) is not int or not start_ms <= completed_ms <= end_ms:
                    raise LatencyError("D1 transition completion timestamp is outside the lifecycle window")
                if event["event_time_ms"] > completed_ms:
                    raise LatencyError("D1 transition completed before its matching CloudTrail event")
                if action_name == "revoke" and completed_ms > restore_start_ms:
                    raise LatencyError("degrade transition must complete before the restore action")
                if action_name == "restore" and completed_ms < restore_ms:
                    raise LatencyError("restore transition must complete after the CreateGrant action")
                sample = {
                    "cycle": cycle_no,
                    "tenant_slot": slot,
                    "latency_ms": completed_ms - event["event_time_ms"],
                    "cloudtrail_event_ref": hashlib.sha256(event["event_id"].encode()).hexdigest(),
                    "cloudtrail_event_id": event["event_id"],
                    "cloudtrail_event_at_utc": _from_epoch_ms(event["event_time_ms"]).isoformat().replace("+00:00", "Z"),
                    "transition_completed_at_utc": _from_epoch_ms(completed_ms).isoformat().replace("+00:00", "Z"),
                }
                if sample["latency_ms"] < 0:
                    raise LatencyError("latency cannot be negative")
                result[direction].append(sample)

    if used_event_ids != set(event_by_id):
        raise LatencyError("CloudTrail input contains missing, duplicate, or unpaired mutation events")
    for direction in result.values():
        if len(direction) != 20:
            raise LatencyError("each direction must contain exactly 20 paired samples")
    token_identities = {item["cf_token_identity_sha256"] for item in d1_digests if "cf_token_identity_sha256" in item}
    if token_identities and (len(token_identities) != 1 or len(token_identities) != len({item.get("cf_token_identity_sha256") for item in d1_digests})):
        raise LatencyError("D1 source token identity changed within the lifecycle readback")
    return result, d1_digests


def _nearest_rank_p99(values: list[int]) -> int:
    if not values:
        raise LatencyError("p99 requires at least one sample")
    ordered = sorted(values)
    rank = (99 * len(ordered) + 99) // 100
    return ordered[rank - 1]


def verify(manifest: dict[str, Any], bundle: dict[str, Any], cloudtrail: dict[str, Any], environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate source bindings and return a redacted paired-sample artifact."""
    env = os.environ if environ is None else environ
    target = _check_protected_manifest(manifest, env)
    _verify_attestations(bundle, cloudtrail, target)
    samples, d1_digests = _verify_cycle_bundle(bundle, cloudtrail, target)
    summary: dict[str, Any] = {
        "schema": OUTPUT_SCHEMA,
        "run_id": target["run_id"],
        "window_ms": {"start": target["window_start_ms"], "end": target["window_end_ms"]},
        "directions": {},
        "source_digests": {
            "cycle_bundle_sha256": _sha256(bundle),
            "cloudtrail_events_sha256": cloudtrail["source"]["response_sha256"],
            "d1_response_sha256": _sha256([item["response_sha256"] for item in d1_digests]),
            "d1_query_sha256": _sha256([item["query_sha256"] for item in d1_digests]),
            "d1_selected_rows_sha256": _sha256([item["selected_rows_sha256"] for item in d1_digests]),
            "d1_selected_token_set_sha256": _sha256([item["selected_token_set_sha256"] for item in d1_digests]),
        },
    }
    for direction, rows in samples.items():
        latencies = [row["latency_ms"] for row in rows]
        p99 = _nearest_rank_p99(latencies)
        if p99 > LATENCY_LIMIT_MS:
            raise LatencyError("p99 latency exceeds 300000ms")
        summary["directions"][direction] = {
            "n": len(rows),
            "p99_ms": p99,
            "max_ms": max(latencies),
            "samples": sorted(rows, key=lambda row: (row["cycle"], row["tenant_slot"])),
        }
    summary["artifact_sha256"] = hashlib.sha256(_canonical(summary)).hexdigest()
    all_samples = [row for direction in summary["directions"].values() for row in direction["samples"]]
    event_ids = sorted({row["cloudtrail_event_id"] for row in all_samples})
    if len(all_samples) != 40 or len(event_ids) != 20:
        raise LatencyError("source receipt requires 40 paired samples bound to 20 exact CloudTrail event IDs")
    completed = max(_timestamp(row["transition_completed_at_utc"], "D1 transition completion") for row in all_samples)
    event_ref = "cloudtrail:" + ":".join(event_ids[:2] + event_ids[-2:])
    summary["audit_source_receipt"] = {
        "step": "revoke_restore",
        "occurred_at_utc": completed.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": {"kind": "cloudtrail", "event_ref": event_ref, "digest": summary["artifact_sha256"]},
    }
    return summary


def _read_private_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise LatencyError("protected evidence input must be a regular non-symlink file")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise LatencyError("protected evidence input permissions must be 0600 or stricter")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LatencyError("protected evidence input could not be read as JSON") from exc
    if not isinstance(value, dict):
        raise LatencyError("protected evidence input must be a JSON object")
    return value


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise LatencyError("output artifact path already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".lifecycle-samples-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="protected runtime manifest JSON (mode 0600)")
    parser.add_argument("--input", required=True, type=Path, help="protected combined cycle bundle and CloudTrail input JSON (mode 0600)")
    parser.add_argument("--output", type=Path, default=Path("lifecycle-samples.json"))
    args = parser.parse_args(argv)
    try:
        manifest = _read_private_json(args.manifest)
        evidence = _read_private_json(args.input)
        if evidence.get("schema") != INPUT_SCHEMA or evidence.get("run_id") != os.environ.get("GITHUB_RUN_ID") or not isinstance(evidence.get("cycle_bundle"), dict) or not isinstance(evidence.get("cloudtrail"), dict):
            raise LatencyError("combined input schema must contain cycle_bundle and cloudtrail source records")
        artifact = verify(manifest, evidence["cycle_bundle"], evidence["cloudtrail"])
        _write_private_json(args.output, artifact)
    except LatencyError as exc:
        parser.error(str(exc))
    print(json.dumps({"artifact": args.output.name, "schema": OUTPUT_SCHEMA, "run_id": artifact["run_id"], "n_per_direction": 20, "artifact_sha256": artifact["artifact_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
