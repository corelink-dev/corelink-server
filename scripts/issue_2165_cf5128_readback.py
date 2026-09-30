#!/usr/bin/env python3
"""Read-only Cloudflare 5128 readback for the Issue #2165 lifecycle.

The protected manifest is supplied by the controller. Cloudflare API calls
are read-only; D1 uses its native POST query route only for fixed SELECTs.
R2 uses only ListObjectsV2 and GetObject against manifest-bound prefixes/keys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "corelink-issue-2165-cf5128-readback-v1"
MANIFEST_SCHEMA = "corelink-issue-2165-kms-runtime-v1"
ENVIRONMENT = "b083-kms-lifecycle"
PRODUCTION_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
APPROVED_ACCOUNT_ID = "51284495e71acdb5a7677e7383ab026b"
ACCOUNT_ID_RE = re.compile(r"^[a-f0-9]{32}$")
DATABASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
TENANT_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9_-]{16}$")
REGIONS = frozenset({"iad", "lhr", "nrt", "sam", "syd"})
TABLES = ("tenant", "blob_meta", "ac_meta", "tenant_byok_config", "tenant_byok_secret")
AUDIT_BUCKET = "audit_outbox"
CF_API = "https://api.cloudflare.com/client/v4"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ReadbackError(ValueError):
    """The target or an authoritative readback failed a bounded contract."""


def _need(obj: Any, key: str, kind: type, where: str) -> Any:
    if not isinstance(obj, dict):
        raise ReadbackError(f"{where} must be an object")
    value = obj.get(key)
    if not isinstance(value, kind) or (kind is str and not value.strip()):
        raise ReadbackError(f"{where}.{key} is missing or malformed")
    return value


def _no_prod(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            _no_prod(key)
            _no_prod(nested)
    elif isinstance(value, list):
        for nested in value:
            _no_prod(nested)
    elif isinstance(value, str) and value.casefold() in {"prod6a", "production", "prod"}:
        raise ReadbackError("production target markers are forbidden")


def validate_manifest(manifest: dict[str, Any], environ: dict[str, str]) -> dict[str, Any]:
    """Validate only the CF slice needed by this readback before network access."""
    _no_prod(manifest)
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("environment") != ENVIRONMENT:
        raise ReadbackError("manifest schema/environment is not the protected #2165 target")
    cf = _need(manifest, "cloudflare", dict, "manifest")
    if cf.get("account_alias") != "cf5128":
        raise ReadbackError("Cloudflare target alias must be cf5128")
    account = _need(cf, "account_id", str, "cloudflare")
    if not ACCOUNT_ID_RE.fullmatch(account) or account != APPROVED_ACCOUNT_ID or account == PRODUCTION_ACCOUNT_ID:
        raise ReadbackError("Cloudflare target account is not an approved isolated account")
    if environ.get("B083_CF_ACCOUNT_ID") != account:
        raise ReadbackError("protected B083_CF_ACCOUNT_ID does not match the manifest")
    d1 = _need(cf, "d1", dict, "cloudflare")
    if d1.get("binding") != "B083_D1":
        raise ReadbackError("D1 target must bind B083_D1")
    database_id = _need(d1, "database_id", str, "cloudflare.d1")
    if not DATABASE_ID_RE.fullmatch(database_id):
        raise ReadbackError("D1 database identifier is malformed")
    region = _need(d1, "region", str, "cloudflare.d1")
    if environ.get("B083_D1_DATABASE_ID") != database_id or environ.get("B083_D1_REGION") != region:
        raise ReadbackError("protected D1 target bindings do not match the manifest")
    r2 = _need(cf, "r2", dict, "cloudflare")
    if r2.get("binding") != "B083_R2" or r2.get("region") != "auto":
        raise ReadbackError("R2 target must bind B083_R2 in auto region")
    endpoint = _need(r2, "endpoint", str, "cloudflare.r2")
    bucket = _need(r2, "bucket", str, "cloudflare.r2")
    if not BUCKET_RE.fullmatch(bucket):
        raise ReadbackError("R2 bucket identifier is malformed")
    expected_endpoint = f"https://{account}.r2.cloudflarestorage.com"
    if endpoint != expected_endpoint or environ.get("B083_R2_S3_ENDPOINT") != endpoint:
        raise ReadbackError("protected R2 endpoint does not match the isolated account")

    tenants = _need(manifest, "disposable_tenants", list, "manifest")
    if len(tenants) != 2 or any(not isinstance(x, str) or not TENANT_ID_RE.fullmatch(x) for x in tenants) or len(set(tenants)) != 2:
        raise ReadbackError("manifest must bind exactly two distinct disposable tenant UUIDs")
    prefixes = _need(cf, "r2_prefixes", list, "cloudflare")
    if len(prefixes) < 2:
        raise ReadbackError("cloudflare.r2_prefixes must contain exact disposable prefixes for both tenants")
    normalized: list[dict[str, str]] = []
    tenant_regions: set[tuple[str, str]] = set()
    seen_prefixes: set[str] = set()
    for index, item in enumerate(prefixes):
        where = f"cloudflare.r2_prefixes[{index}]"
        tenant_id = _need(item, "tenant_id", str, where)
        region_name = _need(item, "region", str, where)
        prefix = _need(item, "prefix", str, where)
        if tenant_id not in tenants or region_name not in REGIONS:
            raise ReadbackError(f"{where} is outside the exact tenant/region target")
        match = re.fullmatch(re.escape(region_name) + r"/([A-Za-z0-9_-]{16})/", prefix)
        if not match or not PREFIX_RE.fullmatch(match.group(1)):
            raise ReadbackError(f"{where}.prefix must be an exact region/opaque-tenant-prefix path")
        pair = (tenant_id, region_name)
        if pair in tenant_regions:
            raise ReadbackError("duplicate tenant/region R2 prefix")
        if prefix in seen_prefixes:
            raise ReadbackError("R2 tenant prefixes must be unique")
        tenant_regions.add(pair)
        seen_prefixes.add(prefix)
        normalized.append({"tenant_id": tenant_id, "region": region_name, "prefix": prefix})
    if {tenant_id for tenant_id, _ in tenant_regions} != set(tenants):
        raise ReadbackError("R2 prefix inventory must cover each disposable tenant exactly once")

    audit_sink = _need(manifest, "audit_sink", dict, "manifest")
    if audit_sink.get("kind") != "d1-audit-outbox+r2-archive" or audit_sink.get("durable") is not True:
        raise ReadbackError("audit sink must be the approved durable D1 outbox plus R2 archive")
    if audit_sink.get("d1_table") != "audit_outbox" or audit_sink.get("d1_columns") != ["id", "tenant_id", "digest", "request_id", "event_type", "payload_json", "enqueued_at", "emitted_at"]:
        raise ReadbackError("audit sink D1 table/columns do not match the approved outbox schema")
    if audit_sink.get("r2_bucket") != bucket:
        raise ReadbackError("audit archive must use the exact approved R2 bucket")
    sink_ref = _need(audit_sink, "target_id", str, "audit_sink")
    if environ.get("B083_AUDIT_SINK_REF") != sink_ref:
        raise ReadbackError("protected B083_AUDIT_SINK_REF does not match the manifest")
    archive_key = _need(audit_sink, "r2_archive_key", str, "audit_sink")
    if not re.fullmatch(r"issue-2165/[A-Za-z0-9_-]{1,80}/audit/receipts\.ndjson", archive_key):
        raise ReadbackError("audit_sink.r2_archive_key must be the exact per-run archive path")
    audit_refs = _need(manifest, "audit_outbox_refs", list, "manifest")
    if len(audit_refs) > 10:
        raise ReadbackError("at most ten exact D1 audit references may be read")
    seen_refs: set[tuple[str, str]] = set()
    seen_request_ids: set[str] = set()
    for index, ref in enumerate(audit_refs):
        where = f"audit_outbox_refs[{index}]"
        request_id = _need(ref, "request_id", str, where)
        event_type = _need(ref, "event_type", str, where)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", request_id) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", event_type):
            raise ReadbackError(f"{where} contains an unsafe audit reference")
        if (request_id, event_type) in seen_refs or request_id in seen_request_ids:
            raise ReadbackError("duplicate D1 audit reference")
        seen_refs.add((request_id, event_type))
        seen_request_ids.add(request_id)
    window = _need(manifest, "lifecycle_window", dict, "manifest")
    window_start = window.get("started_at_ms")
    window_end = window.get("ended_at_ms")
    if type(window_start) is not int or type(window_end) is not int or window_start >= window_end:
        raise ReadbackError("lifecycle_window must contain ordered integer epoch-millisecond bounds")
    if window_end - window_start > 60 * 60 * 1000:
        raise ReadbackError("lifecycle_window must not exceed 60 minutes")
    return {"account_id": account, "database_id": database_id, "d1_region": region,
            "endpoint": endpoint, "bucket": bucket, "tenants": tenants,
            "r2_prefixes": normalized, "audit_refs": audit_refs,
            "archive_key": archive_key,
            "lifecycle_window": {"started_at_ms": window_start, "ended_at_ms": window_end}}


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ReadbackError("manifest must be a regular protected file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("cannot read protected manifest JSON") from exc
    if not isinstance(value, dict):
        raise ReadbackError("protected manifest must be a JSON object")
    return value, raw


def _api_json(method: str, path: str, token: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(CF_API + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                raise ReadbackError("Cloudflare readback returned a non-success HTTP status")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReadbackError(f"Cloudflare readback unavailable ({type(exc).__name__})") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ReadbackError("Cloudflare readback response exceeded the size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReadbackError("Cloudflare readback JSON is malformed") from exc
    if not isinstance(value, dict) or value.get("success") is not True or not isinstance(value.get("result"), (dict, list)):
        raise ReadbackError("Cloudflare readback response shape is unknown or unsuccessful")
    return value


def _verify_token_result(result: Any) -> dict[str, Any]:
    # Cloudflare's token verification endpoint returns identity/status only; it
    # does not return policy scopes. Effective access is established separately
    # by successful exact-account D1 query and R2 bucket metadata readbacks.
    if not isinstance(result, dict) or result.get("status") != "active":
        raise ReadbackError("Cloudflare token status is not authoritatively active")
    token_id = result.get("id")
    if not isinstance(token_id, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", token_id):
        raise ReadbackError("Cloudflare token identity readback is missing or malformed")
    return {"active": True, "identity_sha256": hashlib.sha256(token_id.encode()).hexdigest()}


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def _signing_key(secret: str, date: str) -> bytes:
    key = _hmac_sha256(("AWS4" + secret).encode(), date.encode())
    key = _hmac_sha256(key, b"auto")
    key = _hmac_sha256(key, b"s3")
    return _hmac_sha256(key, b"aws4_request")


def _s3_request(method: str, target: dict[str, Any], path: str, query: dict[str, str], access_key: str, secret_key: str) -> bytes:
    endpoint = target["endpoint"]
    parsed = urllib.parse.urlsplit(endpoint)
    encoded_path = "/" + "/".join(urllib.parse.quote(part, safe="-_.~") for part in path.split("/") if part)
    pairs = sorted((urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~")) for k, v in query.items())
    canonical_query = "&".join(f"{k}={v}" for k, v in pairs)
    host = parsed.netloc
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{hashlib.sha256(b'').hexdigest()}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join((method, encoded_path, canonical_query, canonical_headers, signed_headers, hashlib.sha256(b"").hexdigest()))
    scope = f"{date}/auto/s3/aws4_request"
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()))
    signature = hmac.new(_signing_key(secret_key, date), string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    url = urllib.parse.urlunsplit((parsed.scheme, host, encoded_path, canonical_query, ""))
    request = urllib.request.Request(url, headers={"Host": host, "x-amz-date": amz_date,
                              "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
                              "Authorization": authorization}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                raise ReadbackError("R2 readback returned a non-success HTTP status")
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReadbackError(f"R2 readback unavailable ({type(exc).__name__})") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise ReadbackError("R2 readback response exceeded the size limit")
    return data


def r2_list_prefix(target: dict[str, Any], prefix: str, access_key: str, secret_key: str) -> list[tuple[str, int]]:
    objects: list[tuple[str, int]] = []
    continuation: str | None = None
    while True:
        query = {"list-type": "2", "max-keys": "1000", "prefix": prefix}
        if continuation is not None:
            query["continuation-token"] = continuation
        data = _s3_request("GET", target, f"{target['bucket']}", query, access_key, secret_key)
        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise ReadbackError("R2 object listing XML is malformed") from exc
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        truncated = root.findtext("s3:IsTruncated", namespaces=ns)
        if truncated not in {"true", "false"}:
            raise ReadbackError("R2 listing pagination state is missing")
        for node in root.findall("s3:Contents", ns):
            key, size = node.findtext("s3:Key", namespaces=ns), node.findtext("s3:Size", namespaces=ns)
            if not isinstance(key, str) or not key.startswith(prefix) or not size or not size.isdigit():
                raise ReadbackError("R2 listing returned an object outside the exact prefix or malformed metadata")
            objects.append((key, int(size)))
        if truncated == "false":
            return objects
        continuation = root.findtext("s3:NextContinuationToken", namespaces=ns)
        if not continuation or len(objects) > 100000:
            raise ReadbackError("R2 listing pagination is incomplete or exceeds the bounded object limit")


def _archive_digest(target: dict[str, Any], access_key: str, secret_key: str) -> dict[str, Any]:
    key = target["archive_key"]
    data = _s3_request("GET", target, f"{target['bucket']}/{key}", {}, access_key, secret_key)
    if not data:
        raise ReadbackError("retained audit archive is empty")
    return {"present": True, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run_readback(manifest: dict[str, Any], source_bytes: bytes, *, phase: str,
                 environ: dict[str, str] | None = None,
                 api_json: Callable[..., dict[str, Any]] | None = None,
                 list_prefix: Callable[..., list[tuple[str, int]]] | None = None,
                 get_archive: Callable[..., bytes] | None = None) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    target = validate_manifest(manifest, env)
    token = env.get("B083_CF_API_TOKEN", "")
    access_key = env.get("B083_R2_READONLY_ACCESS_KEY_ID", "")
    secret_key = env.get("B083_R2_READONLY_SECRET_ACCESS_KEY", "")
    if not token:
        raise ReadbackError("protected B083_CF_API_TOKEN is required")
    if not access_key or not secret_key:
        raise ReadbackError("bucket-scoped R2 read-only credentials are required")
    if phase not in {"preflight", "postcleanup"}:
        raise ReadbackError("phase must be preflight or postcleanup")

    do_api = api_json or _api_json
    # Token validation and target metadata readbacks are HTTP GET only.
    verify = do_api("GET", "/user/tokens/verify", token)
    token_state = verify.get("result")
    token_summary = _verify_token_result(token_state)
    d1_meta = do_api("GET", f"/accounts/{target['account_id']}/d1/database/{target['database_id']}", token).get("result")
    if not isinstance(d1_meta, dict) or d1_meta.get("uuid") != target["database_id"] or not d1_meta.get("name"):
        raise ReadbackError("D1 target metadata does not match the protected database")
    bucket_meta = do_api("GET", f"/accounts/{target['account_id']}/r2/buckets/{urllib.parse.quote(target['bucket'], safe='')}", token).get("result")
    if not isinstance(bucket_meta, dict) or bucket_meta.get("name") != target["bucket"]:
        raise ReadbackError("R2 target metadata does not match the protected bucket")
    counts = _d1_counts_with_api(target, token, do_api)
    transitions = _d1_transition_observation(target, token, do_api, require_positive=phase == "postcleanup")
    do_list = list_prefix or r2_list_prefix
    r2_residuals: list[int] = []
    for item in target["r2_prefixes"]:
        objects = do_list(target, item["prefix"], access_key, secret_key)
        r2_residuals.append(len(objects))
    archive_objects = do_list(target, "issue-2165/" + target["archive_key"].split("/")[1] + "/", access_key, secret_key)
    archive: dict[str, Any] = {"present": False, "sha256": None, "size_bytes": 0}
    if phase == "postcleanup":
        if target["archive_key"] not in {key for key, _ in archive_objects}:
            raise ReadbackError("retained per-run audit archive is absent from its exact prefix")
        data = (get_archive or _get_archive)(target, access_key, secret_key)
        if not data:
            raise ReadbackError("retained audit archive is empty")
        archive = {"present": True, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    elif archive_objects:
        raise ReadbackError("preflight found a per-run audit archive before lifecycle issuance")

    if phase == "preflight":
        if any(counts[t] != 0 for t in TABLES) or any(r2_residuals) or counts["audit_outbox_refs_present"]:
            raise ReadbackError("preflight found pre-existing disposable tenant, storage, or audit references")
    else:
        if any(counts[t] != 0 for t in TABLES) or any(r2_residuals):
            raise ReadbackError("postcleanup found residual disposable tenant rows or R2 objects")
        if counts["audit_outbox_refs_present"] != counts["audit_outbox_refs_expected"]:
            raise ReadbackError("postcleanup is missing exact durable D1 audit references")

    target_metadata = {k: target[k] for k in ("account_id", "database_id", "d1_region", "endpoint", "bucket", "tenants", "r2_prefixes", "audit_refs", "archive_key", "lifecycle_window")}
    receipt = {"schema": SCHEMA, "environment": ENVIRONMENT, "account_alias": "cf5128",
            "phase": phase, "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "target_sha256": hashlib.sha256(json.dumps(target_metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "token": token_summary,
            "observed_capabilities": {"account_bound_d1_select": True,
                                      "account_bound_r2_bucket_metadata": True,
                                      "bucket_prefix_list": True},
            "provider_http_methods": ["GET", "POST"], "d1_query_mode": "parameterized-select-only-post",
            "provider_writes": phase == "postcleanup", "readback_provider_writes": False,
            "tenant_residual_counts": {k: counts[k] for k in TABLES},
            "r2_tenant_prefix_residual_counts": r2_residuals,
            "audit_outbox_refs_present": counts["audit_outbox_refs_present"],
            "audit_outbox_refs_expected": counts["audit_outbox_refs_expected"],
            "audit_archive": archive,
            "byok_control_outcome_observation": transitions}
    if phase == "postcleanup":
        receipt["cleanup_complete"] = True
    return receipt


def _d1_counts_with_api(target: dict[str, Any], token: str, api: Callable[..., dict[str, Any]]) -> dict[str, int]:
    tenants = target["tenants"]
    placeholder = ",".join("?" for _ in tenants)
    counts: dict[str, int] = {}
    for table in TABLES:
        counts[table] = _extract_count(api("POST", f"/accounts/{target['account_id']}/d1/database/{target['database_id']}/query", token,
            {"sql": f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id IN ({placeholder})", "params": tenants}))
    for ref in target["audit_refs"]:
        value = _extract_count(api("POST", f"/accounts/{target['account_id']}/d1/database/{target['database_id']}/query", token,
            {"sql": "SELECT COUNT(*) AS n FROM audit_outbox WHERE request_id = ? AND event_type = ?", "params": [ref["request_id"], ref["event_type"]]}))
        if value not in {0, 1}:
            raise ReadbackError("D1 exact audit reference count is not unique")
        counts["audit_outbox_refs_present"] = counts.get("audit_outbox_refs_present", 0) + value
    counts["audit_outbox_refs_expected"] = len(target["audit_refs"])
    return counts


def _d1_transition_observation(target: dict[str, Any], token: str,
                               api: Callable[..., dict[str, Any]], *,
                               require_positive: bool) -> dict[str, Any]:
    window = target["lifecycle_window"]
    sql = (
        "SELECT tenant_id, action, outcome, completed_at_ms FROM byok_control_outcome "
        "WHERE tenant_id IN (?, ?) AND action IN ('degrade', 'restore') "
        "AND outcome = 'completed' AND completed_at_ms >= ? AND completed_at_ms <= ? "
        "ORDER BY completed_at_ms, tenant_id"
    )
    payload = api("POST", f"/accounts/{target['account_id']}/d1/database/{target['database_id']}/query", token,
                  {"sql": sql, "params": [*target["tenants"], window["started_at_ms"], window["ended_at_ms"]]})
    rows = _extract_select_rows(payload, {"tenant_id", "action", "outcome", "completed_at_ms"})
    slot_events: dict[str, dict[str, list[int]]] = {
        "tenant_a": {"degrade": [], "restore": []},
        "tenant_b": {"degrade": [], "restore": []},
    }
    tenant_slots = {target["tenants"][0]: "tenant_a", target["tenants"][1]: "tenant_b"}
    for row in rows:
        tenant_id = row.get("tenant_id")
        action = row.get("action")
        outcome = row.get("outcome")
        completed_at = row.get("completed_at_ms")
        if (tenant_id not in tenant_slots or action not in {"degrade", "restore"}
                or outcome != "completed" or type(completed_at) is not int
                or not window["started_at_ms"] <= completed_at <= window["ended_at_ms"]):
            raise ReadbackError("BYOK transition row is outside the exact action, tenant, outcome, or time contract")
        slot_events[tenant_slots[tenant_id]][action].append(completed_at)
    slots: dict[str, Any] = {}
    total_degrade = total_restore = 0
    all_times: list[int] = []
    for slot, actions in slot_events.items():
        slot_summary: dict[str, Any] = {}
        for action, timestamps in actions.items():
            timestamps.sort()
            if require_positive and not timestamps:
                raise ReadbackError("postcleanup is missing a completed BYOK transition for a tenant slot")
            slot_summary[action] = {
                "count": len(timestamps),
                "earliest_completed_at_ms": timestamps[0] if timestamps else None,
                "latest_completed_at_ms": timestamps[-1] if timestamps else None,
            }
            if action == "degrade":
                total_degrade += len(timestamps)
            else:
                total_restore += len(timestamps)
            all_times.extend(timestamps)
        slots[slot] = slot_summary
    return {
        "window": dict(window),
        "redacted_tenant_slots": slots,
        "totals": {
            "degrade_count": total_degrade,
            "restore_count": total_restore,
            "completed_count": total_degrade + total_restore,
            "earliest_completed_at_ms": min(all_times) if all_times else None,
            "latest_completed_at_ms": max(all_times) if all_times else None,
        },
    }


def _extract_select_rows(payload: dict[str, Any], expected_fields: set[str]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ReadbackError("D1 transition query failed")
    result = payload.get("result")
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ReadbackError("D1 transition query result shape is unknown")
    block = result[0]
    meta, rows = block.get("meta"), block.get("results")
    if block.get("success") is not True or not isinstance(meta, dict) or meta.get("changed_db") is not False:
        raise ReadbackError("D1 transition read-only metadata is missing or ambiguous")
    if any(type(meta.get(k)) is not int or meta[k] != 0 for k in ("rows_written", "changes")):
        raise ReadbackError("D1 transition read-only write metadata is missing or nonzero")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) != expected_fields for row in rows):
        raise ReadbackError("D1 transition rows are missing, malformed, or contain unexpected fields")
    return rows


def _extract_count(payload: dict[str, Any]) -> int:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ReadbackError("D1 query failed")
    result = payload.get("result")
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ReadbackError("D1 query result shape is unknown")
    block = result[0]
    meta, rows = block.get("meta"), block.get("results")
    if block.get("success") is not True or not isinstance(meta, dict) or meta.get("changed_db") is not False:
        raise ReadbackError("D1 read-only metadata is missing or ambiguous")
    if any(type(meta.get(k)) is not int or meta[k] != 0 for k in ("rows_written", "changes")):
        raise ReadbackError("D1 read-only write metadata is missing or nonzero")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or type(rows[0].get("n")) is not int or rows[0]["n"] < 0:
        raise ReadbackError("D1 count result is not one exact integer")
    return rows[0]["n"]


def _get_archive(target: dict[str, Any], access_key: str, secret_key: str) -> bytes:
    return _s3_request("GET", target, f"{target['bucket']}/{target['archive_key']}", {}, access_key, secret_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("preflight", "postcleanup"))
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest, raw = _read_manifest(args.manifest)
        receipt = run_readback(manifest, raw, phase=args.phase)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.receipt, flags, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
    except (ReadbackError, OSError) as exc:
        # Errors are intentionally generic and never include request headers, ids, or response bodies.
        print(f"Issue #2165 Cloudflare readback: BLOCKED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
