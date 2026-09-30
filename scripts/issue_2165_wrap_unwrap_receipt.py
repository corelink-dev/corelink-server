#!/usr/bin/env python3
"""Build one source-backed #2165 BYOK wrap/unwrap receipt.

This collector performs only fixed, parameterized, read-only D1 SELECTs. It
requires actual operator ECS Exec CAS round-trips, a protected custodian KMS
Encrypt event, runtime-task KMS Decrypt events, and D1 wrapped-TCS metadata.
The shipped `TcsResolver` unwraps `tenant_byok_secret.tcs_wrapped` with
`{tenant_id, blob_hash: tcs:vN}` in `storage/byok_cas/part-00.rs`; native CAS
convergent encryption then uses local AEAD (`part-00-tail.rs`), so this receipt
does not claim a KMS Encrypt per CAS request. The custodian Encrypt event is
the separately approved TCS wrapping action. Raw source material is kept only
in a mode-0600 RUNNER_TEMP evidence file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import issue_2165_cf5128_readback as cf


SCHEMA = "corelink.issue-2165-wrap-unwrap-input-v1"
RECEIPT_SCHEMA = "corelink.issue-2165-wrap-unwrap-receipt-v1"
MANIFEST_SCHEMA = "corelink-issue-2165-kms-runtime-v1"
ENVIRONMENT = "b083-kms-lifecycle"
ROLE_SESSION = re.compile(r"^arn:aws:sts::([0-9]{12}):assumed-role/([^/]+)/([^/]+)$")
TASK_ID = re.compile(r"^[A-Fa-f0-9]{32}$")
EVENT_ID = re.compile(r"^[A-Za-z0-9-]{8,128}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
TENANT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MAX_INPUT_BYTES = 16 * 1024 * 1024


class WrapUnwrapError(ValueError):
    """Evidence does not establish a real bounded BYOK roundtrip."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _utc_ms(value: Any, where: str) -> int:
    if not isinstance(value, str):
        raise WrapUnwrapError(f"{where} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WrapUnwrapError(f"{where} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise WrapUnwrapError(f"{where} must be UTC")
    return int(parsed.timestamp() * 1000)


def _read_private(path: Path, label: str, temp: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.resolve().parent != temp:
        raise WrapUnwrapError(f"{label} must be a regular file directly under RUNNER_TEMP")
    if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_size > MAX_INPUT_BYTES:
        raise WrapUnwrapError(f"{label} must be mode 0600 and within the bounded input size")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WrapUnwrapError(f"{label} must contain valid JSON") from exc


def _manifest(m: Any, env: dict[str, str]) -> dict[str, Any]:
    if not isinstance(m, dict) or m.get("schema") != MANIFEST_SCHEMA or m.get("environment") != ENVIRONMENT:
        raise WrapUnwrapError("protected manifest schema/environment is not the #2165 target")
    aws = m.get("aws")
    op = m.get("operator")
    cf_target = m.get("cloudflare")
    if not all(isinstance(x, dict) for x in (aws, op, cf_target)):
        raise WrapUnwrapError("manifest must bind AWS, operator, and CF5128 targets")
    account, region, key_arn, role = (aws.get(k) for k in ("account_id", "region", "cmk_arn", "runtime_role_arn"))
    if not all(isinstance(x, str) and x for x in (account, region, key_arn, role)) or aws.get("cmk_provider") != "aws":
        raise WrapUnwrapError("exact AWS account, region, CMK, and runtime role are required")
    if not re.fullmatch(r"[0-9]{12}", account) or region != "us-east-1" or not key_arn.startswith(f"arn:aws:kms:{region}:{account}:key/"):
        raise WrapUnwrapError("CMK must be the exact same-account us-east-1 key ARN")
    for name, value in (("B083_AWS_ACCOUNT_ID", account), ("B083_AWS_REGION", region), ("B083_KMS_KEY_ARN", key_arn), ("B083_AWS_RUNTIME_ROLE_ARN", role), ("B083_AWS_CUSTODIAN_ROLE_ARN", aws.get("custodian_role_arn"))):
        if env.get(name) != value:
            raise WrapUnwrapError(f"protected {name} does not match manifest")
    cluster = aws.get("cluster_arn")
    task_definition = aws.get("task_definition_arn")
    image_uri = aws.get("image_uri")
    if (not isinstance(cluster, str) or not isinstance(task_definition, str) or not isinstance(image_uri, str)
            or not re.fullmatch(rf"arn:aws:ecs:{re.escape(region)}:{account}:cluster/[A-Za-z0-9_-]+", cluster)
            or not re.fullmatch(rf"arn:aws:ecs:{re.escape(region)}:{account}:task-definition/[A-Za-z0-9_-]+:[0-9]+", task_definition)
            or not re.search(r"@sha256:[a-f0-9]{64}$", image_uri)):
        raise WrapUnwrapError("manifest app task/image binding is incomplete or mutable")
    if env.get("B083_AWS_CLUSTER_ARN") != cluster or env.get("B083_AWS_TASK_DEFINITION_ARN") != task_definition or env.get("B083_IMAGE_URI") != image_uri:
        raise WrapUnwrapError("protected app cluster/task/image bindings differ from manifest")
    tenants = m.get("disposable_tenants")
    if not isinstance(tenants, list) or len(tenants) != 2 or len(set(tenants)) != 2 or any(not isinstance(t, str) or not TENANT_ID.fullmatch(t) for t in tenants):
        raise WrapUnwrapError("manifest must bind exactly two distinct disposable tenant IDs")
    window = m.get("lifecycle_window")
    start, end = (window.get(x) for x in ("started_at_ms", "ended_at_ms")) if isinstance(window, dict) else (None, None)
    if type(start) is not int or type(end) is not int or start >= end or end - start > 3_600_000:
        raise WrapUnwrapError("protected lifecycle window must be ordered and no longer than 60 minutes")
    custodian = aws.get("custodian_role_arn")
    authority = m.get("custodian_authority")
    if (not isinstance(custodian, str) or not isinstance(authority, dict) or authority.get("ref") != env.get("B083_CUSTODIAN_REF")
            or not isinstance(authority.get("ref"), str) or not authority["ref"].startswith("restricted://")
            or authority.get("cmk_arn") != key_arn or authority.get("custodian_role_arn") != custodian):
        raise WrapUnwrapError("restricted custodian authority must bind the exact CMK and custodian role")
    operator_taskdef = op.get("task_definition_arn")
    operator_image = op.get("image_uri")
    operator_role = op.get("operator_role_arn")
    if (not isinstance(operator_taskdef, str) or not isinstance(operator_image, str) or not isinstance(operator_role, str)
            or operator_taskdef == task_definition or operator_role in {role, custodian}
            or not re.search(r"@sha256:[a-f0-9]{64}$", operator_image)):
        raise WrapUnwrapError("operator task, immutable image, and distinct no-KMS role are required")
    if (env.get("B083_AWS_OPERATOR_TASK_DEFINITION_ARN") != operator_taskdef
            or env.get("B083_AWS_OPERATOR_IMAGE_URI") != operator_image
            or env.get("B083_AWS_OPERATOR_ROLE_ARN") != operator_role):
        raise WrapUnwrapError("protected operator task/image bindings differ from manifest")
    cf_account = cf_target.get("account_id")
    d1 = cf_target.get("d1")
    if (cf_target.get("account_alias") != "cf5128" or cf_account != cf.APPROVED_ACCOUNT_ID or cf_account == cf.PRODUCTION_ACCOUNT_ID
            or env.get("B083_CF_ACCOUNT_ID") != cf_account or not isinstance(d1, dict)
            or d1.get("binding") != "B083_D1" or env.get("B083_D1_DATABASE_ID") != d1.get("database_id")
            or env.get("B083_D1_REGION") != d1.get("region")):
        raise WrapUnwrapError("CF5128 D1 target must match protected account/database/region")
    if not env.get("B083_CF_API_TOKEN"):
        raise WrapUnwrapError("protected read-only CF5128 token is required")
    run_id = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[0-9]{1,36}", run_id):
        raise WrapUnwrapError("protected workflow run ID is missing or malformed")
    return {"account": account, "region": region, "key_arn": key_arn, "runtime_role": role,
            "custodian_role": custodian, "authority_ref": authority["ref"], "cluster": cluster,
            "task_definition": task_definition, "image_uri": image_uri, "operator_task_definition": operator_taskdef,
            "operator_image_uri": operator_image, "operator_role": operator_role, "tenants": tenants,
            "start_ms": start, "end_ms": end, "cf_account": cf_account, "d1": d1,
            "run_id": run_id}


def _runtime_rows(source: Any, target: dict[str, Any], app_task_arn: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(source, dict) or set(source) != {"provenance", "raw_response", "response_rows"}:
        raise WrapUnwrapError("runtime source must be exact restricted ECS Exec evidence")
    provenance, raw, rows = source["provenance"], source["raw_response"], source["response_rows"]
    if not isinstance(provenance, dict) or not isinstance(raw, str) or not isinstance(rows, list):
        raise WrapUnwrapError("runtime ECS Exec provenance/response is malformed")
    operator_task_arn = provenance.get("task_arn")
    expected_operator_prefix = target["cluster"].replace(":cluster/", ":task/") + "/"
    if (not isinstance(operator_task_arn, str) or not operator_task_arn.startswith(expected_operator_prefix)
            or not TASK_ID.fullmatch(operator_task_arn.rsplit("/", 1)[-1])
            or provenance.get("cluster_arn") != target["cluster"]
            or provenance.get("task_definition_arn") != target["operator_task_definition"]
            or provenance.get("image_uri") != target["operator_image_uri"]
            or provenance.get("image_digest") != target["operator_image_uri"].rsplit("@", 1)[-1]):
        raise WrapUnwrapError("ECS Exec source is not the exact protected operator task/image")
    if (provenance.get("execute_response_sha256") != hashlib.sha256(raw.encode()).hexdigest()
            or provenance.get("response_rows_sha256") != hashlib.sha256(_canonical(rows)).hexdigest()):
        raise WrapUnwrapError("ECS Exec raw response or row digest does not match source provenance")
    task_prefix = target["cluster"].replace(":cluster/", ":task/") + "/"
    if not isinstance(app_task_arn, str) or not app_task_arn.startswith(task_prefix) or not TASK_ID.fullmatch(app_task_arn.rsplit("/", 1)[-1]):
        raise WrapUnwrapError("app task ARN must identify one exact ECS task in the protected cluster")
    try:
        parsed_rows = [json.loads(line) for line in raw.splitlines() if line]
    except json.JSONDecodeError as exc:
        raise WrapUnwrapError("raw ECS Exec response must be sanitized sidecar JSONL") from exc
    if parsed_rows != rows or len(rows) != 7:
        raise WrapUnwrapError("raw ECS Exec response must match exactly seven recorded lifecycle route rows")
    expected: dict[tuple[str, str], int] = {
        ("tenant_a", "activate"): 202, ("tenant_b", "activate"): 202,
        ("tenant_a", "cas-put"): None, ("tenant_b", "cas-put"): None,
        ("tenant_a", "cas-get"): 200, ("tenant_b", "cas-get"): 200,
        ("tenant_b_to_a", "cross-tenant-deny"): 403,
    }
    seen: set[tuple[str, str]] = set()
    by_slot: dict[str, dict[str, dict[str, Any]]] = {"tenant_a": {}, "tenant_b": {}}
    for row in rows:
        if not isinstance(row, dict) or row.get("schema") != "corelink.issue-2165-sidecar.v1" or row.get("phase") != "lifecycle":
            raise WrapUnwrapError("CAS proof must come from the exact lifecycle sidecar response schema")
        key = (row.get("slot"), row.get("step"))
        if key not in expected or key in seen or row.get("status") not in ({200, 201} if key[1] == "cas-put" else {expected[key]}):
            raise WrapUnwrapError("sidecar lifecycle rows must uniquely prove both activations, CAS round-trips, and tenant denial")
        seen.add(key)
        if key[1] == "activate" and set(row) != {"schema", "phase", "slot", "step", "status", "request_started_at_utc", "observed_at_utc"}:
            raise WrapUnwrapError("activation rows must contain only bounded authenticated request metadata")
        if key[1] in {"cas-put", "cas-get"}:
            if set(row) != {"schema", "phase", "slot", "step", "status", "observed_at_utc", "digest"} or not isinstance(row.get("digest"), str) or not SHA256.fullmatch(row["digest"]):
                raise WrapUnwrapError("CAS PUT/GET rows must expose only a valid byte digest and bounded metadata")
            by_slot[key[0]][key[1]] = row
        elif key[1] == "activate":
            if row.get("request_started_at_utc") is None:
                raise WrapUnwrapError("activation row lacks its authenticated request start")
        for timestamp_key in (("request_started_at_utc", "observed_at_utc") if key[1] == "activate" else ("observed_at_utc",)):
            moment = _utc_ms(row.get(timestamp_key), f"sidecar.{timestamp_key}")
            if not target["start_ms"] <= moment <= target["end_ms"]:
                raise WrapUnwrapError("sidecar lifecycle timestamp is outside the exact protected window")
    if seen != set(expected):
        raise WrapUnwrapError("sidecar lifecycle proof is incomplete")
    for tenant_slot in ("tenant_a", "tenant_b"):
        put, get = by_slot[tenant_slot]["cas-put"], by_slot[tenant_slot]["cas-get"]
        if put["digest"] != get["digest"] or _utc_ms(put["observed_at_utc"], "CAS PUT time") > _utc_ms(get["observed_at_utc"], "CAS GET time"):
            raise WrapUnwrapError("each tenant CAS PUT/GET must be a real ordered byte/hash roundtrip")
        activation = next(row for row in rows if row.get("slot") == tenant_slot and row.get("step") == "activate")
        if _utc_ms(activation["observed_at_utc"], "activation response") > _utc_ms(put["observed_at_utc"], "CAS PUT time"):
            raise WrapUnwrapError("tenant CAS roundtrip must follow the authenticated BYOK activation")
    return provenance, rows


def _verify_app_task_readback(value: Any, target: dict[str, Any], task_arn: str) -> dict[str, Any]:
    task_id = task_arn.rsplit("/", 1)[-1]
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), list) or value.get("failures"):
        raise WrapUnwrapError("app task readback must be an exact successful DescribeTasks response")
    tasks = value["tasks"]
    if len(tasks) != 1:
        raise WrapUnwrapError("app task readback must identify exactly one task")
    task = tasks[0]
    if not isinstance(task, dict):
        raise WrapUnwrapError("app task readback row must be an object")
    containers = task.get("containers") if isinstance(task, dict) else None
    if (task.get("taskArn") != task_arn or task.get("clusterArn") != target["cluster"]
            or task.get("taskDefinitionArn") != target["task_definition"] or task.get("lastStatus") != "RUNNING"
            or not isinstance(containers, list) or len(containers) != 1
            or containers[0].get("lastStatus") != "RUNNING"
            or containers[0].get("imageDigest") != target["image_uri"].rsplit("@", 1)[-1]):
        raise WrapUnwrapError("app task ARN/cluster/task definition/immutable image readback is not exact")
    expected_prefix = target["cluster"].replace(":cluster/", ":task/") + "/"
    if not task_arn.startswith(expected_prefix) or not TASK_ID.fullmatch(task_id):
        raise WrapUnwrapError("app task ARN is not a canonical task in the exact protected cluster")
    container = containers[0]
    return {"task_arn": task_arn, "cluster_arn": target["cluster"], "task_definition_arn": target["task_definition"],
            "image_uri": target["image_uri"], "image_digest": container["imageDigest"],
            "last_status": "RUNNING"}


def _caller_is_preflight(caller: Any, target: dict[str, Any], env: dict[str, str]) -> str:
    if not isinstance(caller, dict) or caller.get("Account") != target["account"]:
        raise WrapUnwrapError("CloudTrail lookup caller account is not the exact protected AWS account")
    preflight = env.get("B083_AWS_PREFLIGHT_ROLE_ARN", "")
    arn = caller.get("Arn", "")
    match = ROLE_SESSION.fullmatch(arn) if isinstance(arn, str) else None
    if (not isinstance(preflight, str) or not preflight.startswith(f"arn:aws:iam::{target['account']}:role/")
            or not match or match.group(1) != target["account"] or match.group(2) != preflight.rsplit("/", 1)[-1]):
        raise WrapUnwrapError("CloudTrail input must be fetched by the protected preflight read-only role")
    return arn


def _cloudtrail_events(raw: Any, target: dict[str, Any], app_task_arn: str, caller: Any, env: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    caller_arn = _caller_is_preflight(caller, target, env)
    if not isinstance(raw, dict) or not isinstance(raw.get("Events"), list):
        raise WrapUnwrapError("CloudTrail LookupEvents response is malformed")
    runtime_task_id = app_task_arn.rsplit("/", 1)[-1]
    runtime_name = target["runtime_role"].rsplit("/", 1)[-1]
    custodian_name = target["custodian_role"].rsplit("/", 1)[-1]
    run_id = target["run_id"]
    selected: dict[str, list[dict[str, Any]]] = {"Encrypt": [], "Decrypt": []}
    seen: set[str] = set()
    for outer in raw["Events"]:
        if not isinstance(outer, dict):
            raise WrapUnwrapError("CloudTrail entries must be objects")
        event_id = outer.get("EventId")
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id) or event_id in seen:
            raise WrapUnwrapError("CloudTrail EventIds must be unique provider identifiers")
        seen.add(event_id)
        if outer.get("EventName") not in selected:
            continue
        raw_inner = outer.get("CloudTrailEvent")
        try:
            inner = json.loads(raw_inner) if isinstance(raw_inner, str) else None
        except json.JSONDecodeError as exc:
            raise WrapUnwrapError("KMS CloudTrail event JSON is malformed") from exc
        if not isinstance(inner, dict):
            raise WrapUnwrapError("KMS CloudTrail event JSON is missing")
        event_time = _utc_ms(inner.get("eventTime"), "CloudTrail.eventTime")
        if (inner.get("eventID") != event_id or inner.get("eventName") != outer.get("EventName")
                or _utc_ms(outer.get("EventTime"), "LookupEvents.EventTime") != event_time
                or inner.get("eventSource") != "kms.amazonaws.com" or outer.get("EventSource") != "kms.amazonaws.com"
                or inner.get("awsRegion") != target["region"] or inner.get("recipientAccountId") != target["account"]):
            raise WrapUnwrapError("KMS CloudTrail outer/inner event identity, region, or account mismatch")
        if inner.get("errorCode") is not None:
            continue
        if not target["start_ms"] <= event_time <= target["end_ms"]:
            continue
        identity = inner.get("userIdentity", {})
        session = identity.get("sessionContext", {}) if isinstance(identity, dict) else {}
        issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
        request = inner.get("requestParameters", {})
        if not isinstance(request, dict) or request.get("keyId") not in {target["key_arn"], target["key_arn"].rsplit("/", 1)[-1]}:
            continue
        context = request.get("encryptionContext")
        if not isinstance(context, dict):
            continue
        tenant_id, blob_hash = context.get("tenant_id"), context.get("blob_hash")
        tenant_slot = {tenant: f"tenant_{chr(97 + index)}" for index, tenant in enumerate(target["tenants"])}.get(tenant_id)
        if tenant_slot is None or not isinstance(blob_hash, str) or not re.fullmatch(r"tcs:v[1-9][0-9]{0,9}", blob_hash):
            continue
        if identity.get("type") != "AssumedRole" or identity.get("accountId") != target["account"]:
            continue
        issuer_arn = issuer.get("arn") if isinstance(issuer, dict) else None
        principal = identity.get("principalId", "")
        if outer["EventName"] == "Encrypt":
            actor = identity.get("arn", "")
            match = ROLE_SESSION.fullmatch(actor) if isinstance(actor, str) else None
            if (issuer_arn != target["custodian_role"] or not match or match.group(2) != custodian_name
                    or match.group(3) != f"i2165-custodian-{run_id}"):
                continue
        else:
            if (issuer_arn != target["runtime_role"] or not isinstance(principal, str)
                    or not principal.endswith(":" + runtime_task_id)):
                continue
        selected[outer["EventName"]].append({"event_id": event_id, "tenant_slot": tenant_slot, "event_time_ms": event_time,
                                             "key_arn": target["key_arn"], "encryption_context": {"tenant_id": tenant_id, "blob_hash": blob_hash},
                                             "actor_issuer_arn": issuer_arn})
    for action in ("Encrypt", "Decrypt"):
        by_tenant = {event["tenant_slot"] for event in selected[action]}
        if by_tenant != {"tenant_a", "tenant_b"}:
            raise WrapUnwrapError(f"missing exact custodian Encrypt/runtime-task Decrypt CloudTrail events for both tenant slots ({action})")
        if any(sum(event["tenant_slot"] == slot for event in selected[action]) != 1 for slot in ("tenant_a", "tenant_b")):
            raise WrapUnwrapError(f"CloudTrail {action} event is ambiguous or duplicated for a tenant slot")
    selected["lookup_caller_arn"] = [{"arn": caller_arn}]  # retained only in the restricted evidence bundle
    return selected


def _decode_wrapped(value: Any) -> bytes:
    if isinstance(value, str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise WrapUnwrapError("D1 tcs_wrapped must be a valid base64 BLOB") from exc
        if not decoded or base64.b64encode(decoded).decode("ascii") != value:
            raise WrapUnwrapError("D1 wrapped TCS BLOB is empty or noncanonical")
        return decoded
    if isinstance(value, list) and value and all(type(item) is int and 0 <= item <= 255 for item in value):
        return bytes(value)
    if isinstance(value, dict) and value.get("type") == "Buffer" and isinstance(value.get("data"), list):
        return _decode_wrapped(value["data"])
    raise WrapUnwrapError("D1 tcs_wrapped representation is unsupported")


def _d1_tcs_rows(api: Callable[..., dict[str, Any]], target: dict[str, Any], token: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sql = ("SELECT s.tenant_id AS tenant_id, s.tcs_wrapped AS tcs_wrapped, s.cmk_key_id AS secret_cmk_key_id, "
           "s.tcs_version AS tcs_version, s.wrapped_at_ms AS wrapped_at_ms, c.mode AS mode, "
           "c.crypto_mode AS crypto_mode, c.cmk_provider AS cmk_provider, c.cmk_key_id AS config_cmk_key_id, "
           "c.cmk_region AS cmk_region, c.state AS state FROM tenant_byok_secret AS s "
           "JOIN tenant_byok_config AS c ON c.tenant_id = s.tenant_id "
           "WHERE s.tenant_id IN (?, ?) ORDER BY s.tenant_id")
    params = list(target["tenants"])
    path = f"/accounts/{target['cf_account']}/d1/database/{target['d1']['database_id']}/query"
    try:
        payload = api("POST", path, token, {"sql": sql, "params": params})
        rows = cf._extract_select_rows(payload, {"tenant_id", "tcs_wrapped", "secret_cmk_key_id", "tcs_version", "wrapped_at_ms", "mode", "crypto_mode", "cmk_provider", "config_cmk_key_id", "cmk_region", "state"})
    except cf.ReadbackError as exc:
        raise WrapUnwrapError("D1 SELECT did not return authoritative zero-write wrapped-TCS metadata") from exc
    meta = payload["result"][0]["meta"]
    if meta.get("changed_db") is not False or type(meta.get("rows_written")) is not int or meta["rows_written"] != 0 or type(meta.get("changes")) is not int or meta["changes"] != 0:
        raise WrapUnwrapError("wrapped-TCS D1 readback must prove zero-write SELECT metadata")
    if len(rows) != 2:
        raise WrapUnwrapError("D1 must return exactly one joined tenant secret/config row per disposable tenant")
    ordered: list[dict[str, Any]] = []
    for tenant, slot in zip(target["tenants"], ("tenant_a", "tenant_b"), strict=True):
        row = next((candidate for candidate in rows if candidate.get("tenant_id") == tenant), None)
        if (row is None or row.get("mode") != "byok" or row.get("crypto_mode") != "convergent" or row.get("cmk_provider") != "aws"
                or row.get("secret_cmk_key_id") != target["key_arn"] or row.get("config_cmk_key_id") != target["key_arn"]
                or row.get("cmk_region") != target["region"] or row.get("state") != "active"
                or type(row.get("tcs_version")) is not int or row["tcs_version"] < 1
                or type(row.get("wrapped_at_ms")) is not int or not target["start_ms"] <= row["wrapped_at_ms"] <= target["end_ms"]):
            raise WrapUnwrapError("D1 tenant_byok_secret/config does not prove exact active CMK-wrapped TCS metadata")
        wrapped = _decode_wrapped(row.get("tcs_wrapped"))
        ordered.append({"slot": slot, "tenant_id": tenant, "tcs_version": row["tcs_version"],
                        "wrapped_at_ms": row["wrapped_at_ms"], "wrapped_length": len(wrapped),
                        "wrapped_sha256": hashlib.sha256(wrapped).hexdigest(), "cmk_key_id": row["secret_cmk_key_id"],
                        "cmk_region": row["cmk_region"], "crypto_mode": row["crypto_mode"]})
    if ordered[0]["wrapped_sha256"] == ordered[1]["wrapped_sha256"]:
        raise WrapUnwrapError("tenant-bound TCS ciphertexts must be distinct under tenant-specific encryption contexts")
    return ordered, {"method": "parameterized-select-post", "endpoint": cf.CF_API + path,
                     "sql": sql, "params": params, "rows": rows,
                     "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0}}


def build_receipt(manifest: Any, env: dict[str, str], runtime_source: Any, cloudtrail: Any,
                  caller_identity: Any, app_task_arn: str, app_task_readback: Any, *, d1_api: Callable[..., dict[str, Any]],
                  cf_api: Callable[..., dict[str, Any]] = cf._api_json) -> tuple[dict[str, Any], dict[str, Any]]:
    target = _manifest(manifest, env)
    app_task = _verify_app_task_readback(app_task_readback, target, app_task_arn)
    provenance, route_rows = _runtime_rows(runtime_source, target, app_task_arn)
    identity = _caller_is_preflight(caller_identity, target, env)
    events = _cloudtrail_events(cloudtrail, target, app_task_arn, caller_identity, env)
    token = env["B083_CF_API_TOKEN"]
    token_state = cf_api("GET", "/user/tokens/verify", token)
    token_identity = cf._verify_token_result(token_state.get("result"))
    d1_rows, d1_source = _d1_tcs_rows(d1_api, target, token)
    event_rows = events["Encrypt"] + events["Decrypt"]
    for d1row in d1_rows:
        slot = d1row["slot"]
        enc = next(event for event in events["Encrypt"] if event["tenant_slot"] == slot)
        dec = next(event for event in events["Decrypt"] if event["tenant_slot"] == slot)
        expected_context = {"tenant_id": d1row["tenant_id"], "blob_hash": f"tcs:v{d1row['tcs_version']}"}
        if enc["encryption_context"] != expected_context or dec["encryption_context"] != expected_context:
            raise WrapUnwrapError("KMS Encrypt/Decrypt context does not bind the exact D1 tenant and TCS version")
        if not target["start_ms"] <= enc["event_time_ms"] <= d1row["wrapped_at_ms"] <= target["end_ms"]:
            raise WrapUnwrapError("custodian TCS Encrypt event does not precede its exact D1 wrapped_at_ms")
        activate = next(row for row in route_rows if row.get("slot") == slot and row.get("step") == "activate")
        get_row = next(row for row in route_rows if row.get("slot") == slot and row.get("step") == "cas-get")
        if not (_utc_ms(activate["observed_at_utc"], "activation response") <= dec["event_time_ms"] <= _utc_ms(get_row["observed_at_utc"], "CAS GET response")):
            raise WrapUnwrapError("runtime TCS Decrypt event does not fall between activation and CAS roundtrip readback")
    cas_rows = [row for row in route_rows if row.get("step") in {"cas-put", "cas-get"}]
    redacted_route_hash = hashlib.sha256(_canonical(cas_rows)).hexdigest()
    restricted = {
        "schema": "corelink.issue-2165-wrap-unwrap-source-evidence-v1",
        "manifest_target": {"aws_account_id": target["account"], "region": target["region"], "cmk_arn": target["key_arn"], "runtime_role_arn": target["runtime_role"], "custodian_role_arn": target["custodian_role"], "custodian_authority_ref": target["authority_ref"], "tenant_ids": target["tenants"]},
        "app_task": app_task, "operator_provenance": provenance,
        "cas_route_rows": route_rows, "d1_tcs_rows": d1_source,
        "kms_events": cloudtrail, "selected_kms_events": event_rows,
        "lookup_caller_arn": identity, "cf_token_identity": token_identity,
    }
    evidence_digest = hashlib.sha256(_canonical(restricted)).hexdigest()
    event_ids = sorted(event["event_id"] for event in event_rows)
    if len(set(event_ids)) != 4:
        raise WrapUnwrapError("exactly four distinct tenant-bound KMS Encrypt/Decrypt CloudTrail events are required")
    encrypt_refs = ".".join(hashlib.sha256(event["event_id"].encode()).hexdigest()[:16] for event in sorted(events["Encrypt"], key=lambda e: e["tenant_slot"]))
    decrypt_refs = ".".join(hashlib.sha256(event["event_id"].encode()).hexdigest()[:16] for event in sorted(events["Decrypt"], key=lambda e: e["tenant_slot"]))
    ref = ("kms-encrypt:" + encrypt_refs
           + "/kms-decrypt:" + decrypt_refs
           + "/ecs-task:" + hashlib.sha256(app_task_arn.encode()).hexdigest()[:16]
           + "/exec:" + provenance["execute_response_sha256"][:16]
           + "/d1:" + hashlib.sha256(_canonical(d1_rows)).hexdigest()[:16]
           + "/cas:" + redacted_route_hash[:16])
    cas_get_times = [_utc_ms(row["observed_at_utc"], "CAS GET time") for row in cas_rows if row.get("step") == "cas-get"]
    receipt = {"step": "wrap_unwrap", "occurred_at_utc": datetime.fromtimestamp(max(cas_get_times) / 1000, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
               "source": {"kind": "cloudtrail", "event_ref": ref, "digest": evidence_digest}}
    evidence = {**restricted, "token_identity": token_identity, "d1_tcs_readback_rows": d1_rows,
                "receipt": receipt, "query_sha256": hashlib.sha256(_canonical({"sql": d1_source["sql"], "params": d1_source["params"]})).hexdigest(),
                "cas_rows_sha256": redacted_route_hash, "selected_cloudtrail_event_ids": event_ids}
    return receipt, evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--runtime-source", required=True, type=Path)
    parser.add_argument("--cloudtrail", required=True, type=Path)
    parser.add_argument("--caller-identity", required=True, type=Path)
    parser.add_argument("--app-task-readback", required=True, type=Path)
    parser.add_argument("--app-task-arn", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
        inputs = [args.manifest, args.runtime_source, args.cloudtrail, args.caller_identity, args.app_task_readback]
        if not temp.is_dir() or any(p.resolve().parent != temp for p in inputs + [args.output, args.evidence]):
            raise WrapUnwrapError("all private inputs/outputs must be directly under RUNNER_TEMP")
        manifest, runtime_source, cloudtrail, caller, task_readback = (_read_private(p, label, temp) for p, label in zip(inputs, ("manifest", "runtime source", "CloudTrail source", "caller identity", "app task readback"), strict=True))
        receipt, evidence = build_receipt(manifest, dict(os.environ), runtime_source, cloudtrail, caller, args.app_task_arn, task_readback, d1_api=cf._api_json)
        for path, value in ((args.output, receipt), (args.evidence, evidence)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(_canonical(value) + b"\n")
        output = os.environ.get("GITHUB_OUTPUT", "")
        if not output:
            raise WrapUnwrapError("GITHUB_OUTPUT is required")
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("audit_source_receipt_json=" + json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        print("wrap/unwrap source evidence: PASS")
        return 0
    except Exception as exc:
        print(f"wrap/unwrap source evidence: BLOCKED ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
