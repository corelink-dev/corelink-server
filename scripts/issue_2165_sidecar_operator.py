#!/usr/bin/env python3
"""Bounded test operator for Issue #2165 BYOK and native CAS routes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from blake3 import blake3
except ImportError:  # image pin is mandatory; missing package stops before any request
    blake3 = None

TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 4096
MAX_CAS_BLOB_BYTES = 128
MAX_LIFETIME_MS = 15 * 60 * 1000
ADMISSION_DOMAIN = b"corelink/staging-load-admission-auth/v2\0"
PRIVATE_V4 = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
SCHEMA = "corelink.issue-2165-sidecar.v1"
CAS_STATE_DIR = "/run/issue-2165"
CAS_STATE_PATH = "/run/issue-2165/objects.json"
PHASES = {
    "pregrant-deny": ("activate", 501),
    "lifecycle": ("activate", 202),
    "cleanup": ("deactivate", 200),
}


class OperatorError(ValueError):
    """Fixed-message fail-closed sidecar error."""


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value != value.strip() or "\n" in value or "\r" in value:
        raise OperatorError(f"required environment value is invalid: {name}")
    return value


def _admission(scenario: str = "byok", now_ms: int | None = None) -> str:
    key = _required_env("CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY")
    run_id = _required_env("ISSUE_2165_RUN_ID")
    sha = _required_env("ISSUE_2165_TARGET_DEPLOYMENT_SHA")
    if len(key.encode()) < 32:
        raise OperatorError("staging admission key is too short")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise OperatorError("run id is not canonical")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise OperatorError("deployment SHA is not canonical")
    if scenario not in {"byok", "cas"}:
        raise OperatorError("admission scenario is unsupported")
    issued = int(time.time() * 1000) if now_ms is None else now_ms
    expires = issued + 60_000
    if issued < 0 or expires - issued > MAX_LIFETIME_MS:
        raise OperatorError("admission lifetime is invalid")
    nonce = secrets.token_hex(32)
    payload = f"v2.{run_id}.{scenario}.staging.{sha}.{issued}.{expires}.{nonce}"
    tag = hmac.new(key.encode(), ADMISSION_DOMAIN + payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{tag}"


def _origin() -> str:
    origin = _required_env("ISSUE_2165_APP_ORIGIN")
    parsed = urlsplit(origin)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        raise OperatorError("app origin must be a private task IPv4 address") from None
    if (
        parsed.scheme != "http"
        or not isinstance(address, ipaddress.IPv4Address)
        or not any(address in network for network in PRIVATE_V4)
        or port != 50051
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise OperatorError("app origin must be a private task IPv4 address on port 50051")
    return f"http://{address}:50051"


def _ensure_unexpired(credential: str, now_ms: int | None = None) -> None:
    parts = credential.split(".")
    if len(parts) != 9 or parts[0] != "v2":
        raise OperatorError("admission credential is malformed")
    try:
        issued, expires = int(parts[5]), int(parts[6])
    except ValueError:
        raise OperatorError("admission lifetime is invalid") from None
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if issued >= expires or expires - issued > MAX_LIFETIME_MS or issued > now or now >= expires:
        raise OperatorError("admission credential is expired or not yet valid")


def _http(method: str, route: str, headers: dict[str, str], body: bytes | None = None) -> tuple[int, bytes, str]:
    request_headers = dict(headers)
    if body is not None:
        request_headers["content-length"] = str(len(body))
    request = Request(_origin() + route, data=body, headers=request_headers, method=method)
    request_started_at_utc = _timestamp()
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise OperatorError("response exceeded bound")
            return int(response.status), payload, request_started_at_utc
    except HTTPError as error:
        payload = error.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise OperatorError("response exceeded bound") from None
        return int(error.code), payload, request_started_at_utc
    except (URLError, TimeoutError, OSError) as error:
        del error
        raise OperatorError("loopback request failed") from None


def _request(route: str, body: dict[str, str], admission: str) -> tuple[int, str, str]:
    internal = _required_env("CORELINK_INTERNAL_AUTH_KEY")
    if len(internal.encode()) < 32:
        raise OperatorError("internal auth key is too short")
    _ensure_unexpired(admission)
    request_body = json.dumps(body, separators=(",", ":")).encode()
    status, _, request_started_at_utc = _http(
        "POST",
        route,
        {
            "content-type": "application/json",
            "x-corelink-internal-auth": internal,
            "x-corelink-staging-load-admission": admission,
        },
        request_body,
    )
    return status, request_started_at_utc, hashlib.sha256(request_body).hexdigest()


def _activate_body(slot_index: int) -> dict[str, str]:
    key_id = _required_env("ISSUE_2165_CMK_KEY_ID")
    region = _required_env("ISSUE_2165_CMK_REGION")
    if slot_index not in {0, 1}:
        raise OperatorError("activation tenant slot is invalid")
    wrapped_a = _required_env("ISSUE_2165_TCS_WRAPPED_B64_A")
    wrapped_b = _required_env("ISSUE_2165_TCS_WRAPPED_B64_B")
    if wrapped_a == wrapped_b:
        raise OperatorError("tenant-bound wrapped TCS secrets must be distinct")
    ciphertext = wrapped_a if slot_index == 0 else wrapped_b
    if len(key_id) > 2048 or len(region) > 64 or len(ciphertext) > 8192:
        raise OperatorError("activation input exceeds bound")
    try:
        decoded = base64.b64decode(ciphertext, validate=True)
    except (ValueError, base64.binascii.Error):
        raise OperatorError("wrapped ciphertext is invalid") from None
    if not decoded or base64.b64encode(decoded).decode() != ciphertext:
        raise OperatorError("wrapped ciphertext is invalid")
    return {
        "mode": "byok",
        "crypto_mode": "convergent",
        "cmk_provider": "aws",
        "cmk_key_id": key_id,
        "cmk_region": region,
        "tcs_wrapped_b64": ciphertext,
    }


def _tenants() -> tuple[str, str]:
    raw = _required_env("ISSUE_2165_TENANTS_JSON")
    if len(raw) > 1024:
        raise OperatorError("tenant list exceeds bound")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError:
        raise OperatorError("tenant list is invalid") from None
    if (
        not isinstance(values, list)
        or len(values) != 2
        or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) for value in values)
        or values[0] == values[1]
    ):
        raise OperatorError("tenant list must contain two distinct valid IDs")
    return values[0], values[1]


def _cas_config() -> tuple[tuple[str, str], int]:
    if blake3 is None:
        raise OperatorError("pinned BLAKE3 implementation is unavailable")
    pat_a = _required_env("ISSUE_2165_PAT_A")
    pat_b = _required_env("ISSUE_2165_PAT_B")
    if len(pat_a.encode()) < 32 or len(pat_b.encode()) < 32 or pat_a == pat_b:
        raise OperatorError("disposable tenant PATs are invalid")
    quota_raw = _required_env("ISSUE_2165_STORAGE_QUOTA_BYTES")
    if not re.fullmatch(r"[1-9][0-9]{0,18}", quota_raw):
        raise OperatorError("storage quota is unavailable or invalid")
    quota = int(quota_raw)
    if quota < MAX_CAS_BLOB_BYTES or quota > 2**63 - 1:
        raise OperatorError("storage quota is smaller than the test blob or exceeds bound")
    return (pat_a, pat_b), quota


def _headers(tenant: str, pat: str, quota: int) -> dict[str, str]:
    return {
        "authorization": f"Bearer {pat}",
        "x-corelink-tenant-id": tenant,
        "x-corelink-scope": "cas:rw",
        "x-corelink-storage-quota-bytes": str(quota),
    }


def _cas_request(
    method: str,
    auth_tenant: str,
    path_tenant: str,
    digest: str,
    pat: str,
    quota: int,
    *,
    data: bytes | None = None,
    admission: str | None = None,
) -> tuple[int, bytes]:
    headers = _headers(auth_tenant, pat, quota)
    if method in {"PUT", "GET"}:
        headers["accept"] = "application/octet-stream"
    if method == "PUT":
        headers["content-type"] = "application/octet-stream"
    if admission is not None:
        _ensure_unexpired(admission)
        headers["x-corelink-staging-load-admission"] = admission
    status, payload, _ = _http(method, f"/v1/cas/{path_tenant}/{digest}", headers, data)
    return status, payload


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _row(
    phase: str,
    slot: str,
    step: str,
    route: str,
    status: int,
    digest: str | None = None,
    request_started_at_utc: str | None = None,
    request_body_sha256: str | None = None,
) -> dict[str, str | int]:
    row: dict[str, str | int] = {
        "schema": SCHEMA,
        "phase": phase,
        "slot": slot,
        "step": step,
        "route": route,
        "status": status,
        "observed_at_utc": _timestamp(),
    }
    if digest is not None:
        row["digest"] = digest
    if request_started_at_utc is not None:
        row["request_started_at_utc"] = request_started_at_utc
    if request_body_sha256 is not None:
        row["request_body_sha256"] = request_body_sha256
    return row


def _state_file() -> str:
    return CAS_STATE_PATH


def _check_state_dir() -> None:
    try:
        directory = os.lstat(CAS_STATE_DIR)
    except OSError:
        raise OperatorError("private CAS cleanup state directory is unavailable") from None
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or directory.st_mode & 0o077:
        raise OperatorError("private CAS cleanup state directory permissions are unsafe")


def _save_state(tenants: tuple[str, str], activated: list[str], objects: list[dict[str, str]]) -> None:
    _check_state_dir()
    if (
        any(tenant not in tenants for tenant in activated)
        or len(set(activated)) != len(activated)
        or any(item.get("tenant") not in tenants or not re.fullmatch(r"[0-9a-f]{64}", item.get("hash", "")) for item in objects)
    ):
        raise OperatorError("CAS cleanup handle is invalid")
    payload = json.dumps(
        {"schema": "corelink.issue-2165-cas-cleanup.v1", "activated": activated, "objects": objects},
        separators=(",", ":"),
    ).encode()
    fd, temp_path = tempfile.mkstemp(prefix="objects.", dir=CAS_STATE_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, _state_file())
        os.chmod(_state_file(), 0o600)
    except OSError:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise OperatorError("CAS cleanup handle could not be stored") from None


def _load_state(tenants: tuple[str, str]) -> tuple[list[str], list[dict[str, str]]]:
    _check_state_dir()
    path = _state_file()
    try:
        file_stat = os.lstat(path)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_mode & 0o077
            or file_stat.st_size > 4096
        ):
            raise OperatorError("CAS cleanup handle file is unsafe")
        with open(path, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except OperatorError:
        raise
    except (OSError, json.JSONDecodeError):
        raise OperatorError("CAS cleanup handles are unavailable") from None
    if not isinstance(payload, dict) or set(payload) != {"schema", "activated", "objects"} or payload["schema"] != "corelink.issue-2165-cas-cleanup.v1":
        raise OperatorError("CAS cleanup handles are invalid")
    activated = payload["activated"]
    if not isinstance(activated, list) or any(not isinstance(t, str) or t not in tenants for t in activated) or len(set(activated)) != len(activated):
        raise OperatorError("BYOK cleanup handles are invalid")
    objects = payload["objects"]
    if not isinstance(objects, list) or len(objects) > 2:
        raise OperatorError("CAS cleanup handles exceed the two-tenant bound")
    seen: set[str] = set()
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"tenant", "hash"}:
            raise OperatorError("CAS cleanup handle is invalid")
        tenant, digest = item["tenant"], item["hash"]
        if tenant not in tenants or tenant in seen or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise OperatorError("CAS cleanup handle is invalid")
        seen.add(tenant)
    return activated, objects


def _activation(phase: str, tenants: tuple[str, str], action: str, expected: int) -> list[dict[str, str | int]]:
    route = "/v1/admin/byok/activate" if action == "activate" else "/v1/admin/byok/deactivate"
    rows = []
    for index, tenant in enumerate(tenants):
        body = ({**_activate_body(index), "tenant": tenant} if action == "activate"
                else {"tenant": tenant, "action": "cancel"})
        credential = _admission("byok")
        status, request_started_at_utc, request_body_sha256 = _request(route, body, credential)
        if status != expected:
            raise OperatorError(f"BYOK route returned unexpected status {status}")
        rows.append(_row(
            phase,
            f"tenant_{'a' if index == 0 else 'b'}",
            action,
            route,
            status,
            request_started_at_utc=request_started_at_utc,
            request_body_sha256=request_body_sha256 if action == "activate" else None,
        ))
    return rows


def _lifecycle_cas(tenants: tuple[str, str], pats: tuple[str, str], quota: int) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    objects: list[dict[str, str]] = []
    activated: list[str] = []
    _check_state_dir()
    if os.path.exists(_state_file()):
        raise OperatorError("prior CAS cleanup state must be cleared first")
    for index, tenant in enumerate(tenants):
        credential = _admission("byok")
        activation_body = _activate_body(index)
        status, request_started_at_utc, request_body_sha256 = _request("/v1/admin/byok/activate", {**activation_body, "tenant": tenant}, credential)
        if status != 202:
            raise OperatorError(f"BYOK activate returned unexpected status {status}")
        activated.append(tenant)
        _save_state(tenants, activated, objects)
        rows.append(_row(
            "lifecycle",
            f"tenant_{'a' if index == 0 else 'b'}",
            "activate",
            "/v1/admin/byok/activate",
            status,
            request_started_at_utc=request_started_at_utc,
            request_body_sha256=request_body_sha256,
        ))
    for index, (tenant, pat) in enumerate(zip(tenants, pats, strict=True)):
        slot = f"tenant_{'a' if index == 0 else 'b'}"
        blob = secrets.token_bytes(32)
        digest = blake3(blob).hexdigest()
        objects.append({"tenant": tenant, "hash": digest})
        _save_state(tenants, activated, objects)
        admission = _admission("cas")
        put_status, put_body = _cas_request("PUT", tenant, tenant, digest, pat, quota, data=blob, admission=admission)
        if put_status not in {200, 201}:
            raise OperatorError("CAS PUT returned unexpected status")
        if put_body.strip() != digest.encode():
            raise OperatorError("CAS PUT status or returned digest did not match")
        rows.append(_row("lifecycle", slot, "cas-put", "/v1/cas/{tenant}/{hash}", put_status, digest))
        get_status, get_body = _cas_request("GET", tenant, tenant, digest, pat, quota)
        if get_status != 200 or get_body != blob or blake3(get_body).hexdigest() != digest:
            raise OperatorError("CAS GET bytes or digest did not match")
        rows.append(_row("lifecycle", slot, "cas-get", "/v1/cas/{tenant}/{hash}", get_status, digest))
    cross_status, _ = _cas_request("GET", tenants[1], tenants[0], objects[0]["hash"], pats[1], quota)
    if cross_status != 403:
        raise OperatorError("cross-tenant CAS read was not denied")
    rows.append(_row("lifecycle", "tenant_b_to_a", "cross-tenant-deny", "/v1/cas/{tenant}/{hash}", cross_status, objects[0]["hash"]))
    return rows


def _cleanup_cas(tenants: tuple[str, str], pats: tuple[str, str], quota: int) -> tuple[list[dict[str, str | int]], list[str]]:
    activated, objects = _load_state(tenants)
    rows: list[dict[str, str | int]] = []
    for item in objects:
        tenant = item["tenant"]
        index = tenants.index(tenant)
        slot = f"tenant_{'a' if index == 0 else 'b'}"
        digest = item["hash"]
        delete_status, _ = _cas_request("DELETE", tenant, tenant, digest, pats[index], quota)
        if delete_status != 204:
            raise OperatorError("CAS exact-object delete returned unexpected status")
        rows.append(_row("cleanup", slot, "cas-delete", "/v1/cas/{tenant}/{hash}", delete_status, digest))
        readback_status, _ = _cas_request("GET", tenant, tenant, digest, pats[index], quota)
        if readback_status != 404:
            raise OperatorError("CAS exact-object readback was not absent")
        rows.append(_row("cleanup", slot, "cas-delete-readback", "/v1/cas/{tenant}/{hash}", readback_status, digest))
    return rows, activated


def run_phase(phase: str) -> list[dict[str, str | int]]:
    if phase not in PHASES:
        raise OperatorError("phase is unsupported")
    # Validate all injected configuration before making any network request.
    _required_env("CORELINK_INTERNAL_AUTH_KEY")
    tenants = _tenants()
    pats, quota = _cas_config()
    _origin()
    if phase == "pregrant-deny":
        return _activation(phase, tenants, "activate", 501)
    if phase == "lifecycle":
        return _lifecycle_cas(tenants, pats, quota)
    rows, activated = _cleanup_cas(tenants, pats, quota)
    for tenant in activated:
        index = tenants.index(tenant)
        credential = _admission("byok")
        status, _request_started_at_utc, _request_body_sha256 = _request("/v1/admin/byok/deactivate", {"tenant": tenant, "action": "cancel"}, credential)
        if status != 200:
            raise OperatorError(f"BYOK cancel returned unexpected status {status}")
        rows.append(_row(phase, f"tenant_{'a' if index == 0 else 'b'}", "deactivate", "/v1/admin/byok/deactivate", status))
    try:
        os.unlink(_state_file())
    except OSError:
        raise OperatorError("CAS cleanup state could not be removed") from None
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=tuple(PHASES))
    args = parser.parse_args(argv)
    try:
        for row in run_phase(args.phase):
            print(json.dumps(row, sort_keys=True, separators=(",", ":")))
    except OperatorError as error:
        print(f"issue-2165-operator: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
