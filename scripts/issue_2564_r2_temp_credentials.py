#!/usr/bin/env python3
"""Issue bucket-scoped temporary R2 credentials for the protected R2 run.

The Cloudflare API bearer and parent access-key identifier are bootstrap-only.
This program never sends either to the selected test process or writes them to
disk, workflow outputs, artifacts, or receipts. The protected operator lane
must independently establish parent-key identity/account provenance before
dispatch. The parent can be account-wide; the API request always constrains the
returned temporary credentials to this one disposable bucket. Absent inputs
and failed API classification fail closed before the temporary-credential POST.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import quote
from urllib.parse import urlsplit

API = "https://api.cloudflare.com/client/v4"
TTL_SECONDS = 7200
PROFILE = "r2"
RUNNER = ("bash", "scripts/run-real-ignored-harnesses.sh", PROFILE)
EXPECTED_ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd"
EXPECTED_BUCKET = "corelink-b068-r2-2564-20260927-staging"
R2_WRITE_GROUP = "Workers R2 Storage Write"
ACCOUNT_SCOPE = "com.cloudflare.api.account"
PARENT_KEY_RE = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
RECEIPT_RE = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, repr=False)
class TemporaryCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str

    def __repr__(self) -> str:
        return "TemporaryCredentials([REDACTED])"


class BootstrapError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def provider_json(
    method: str,
    path: str,
    bearer: str,
    *,
    body: Mapping[str, object] | None = None,
    opener=None,
) -> tuple[int, dict | None]:
    """Bounded Cloudflare API call; response bodies/errors never reach output."""
    if not path.startswith("/") or ".." in path or not bearer:
        raise BootstrapError("invalid Cloudflare API request")
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        API + path,
        data=encoded,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if encoded is not None else {}),
        },
        method=method,
    )
    client = opener or urllib.request.build_opener(NoRedirect)
    try:
        with client.open(request, timeout=15) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise BootstrapError("Cloudflare API response exceeded size limit")
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as error:
                raise BootstrapError("Cloudflare API response was invalid") from error
            if not isinstance(payload, dict):
                raise BootstrapError("Cloudflare API response was invalid")
            return response.status, payload
    except urllib.error.HTTPError as error:
        # Never read/log provider error body, request headers, or credentials.
        return error.code, None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise BootstrapError("Cloudflare API request failed") from error


def _successful(status: int, payload: dict | None) -> dict:
    if status != 200 or not isinstance(payload, dict) or payload.get("success") is not True:
        raise BootstrapError("Cloudflare API authority readback failed")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise BootstrapError("Cloudflare API authority metadata was invalid")
    return result


def classify_bearer_r2_write(
    *, account_id: str, bearer: str, fetch: Callable[..., tuple[int, dict | None]] = provider_json
) -> None:
    """Verify token status; enforce token detail policy only when readable."""
    if account_id != EXPECTED_ACCOUNT or not bearer.strip():
        raise BootstrapError("missing isolated account or protected Cloudflare token")
    status, verification = fetch("GET", "/user/tokens/verify", bearer)
    token = _successful(status, verification)
    token_id = token.get("id")
    if token.get("status") != "active" or not isinstance(token_id, str) or not re.fullmatch(r"[0-9a-f]{32}", token_id):
        raise BootstrapError("Cloudflare bootstrap token is not an active API token")

    status, detail_payload = fetch(
        "GET", f"/user/tokens/{quote(token_id, safe='')}", bearer
    )
    # Cloudflare may deny reading one's own policy metadata with 403. The
    # target account and parent-key receipt gates plus the exact scoped POST
    # remain required; a 403 here is not evidence that the temp endpoint fails.
    if status == 403:
        return
    detail = _successful(status, detail_payload)
    if detail.get("id") != token_id:
        raise BootstrapError("Cloudflare token metadata identity mismatch")
    policies = detail.get("policies")
    if not isinstance(policies, list) or len(policies) != 1:
        raise BootstrapError("Cloudflare bootstrap token policy is not a single R2 grant")
    policy = policies[0]
    if not isinstance(policy, dict) or policy.get("effect") != "allow":
        raise BootstrapError("Cloudflare bootstrap token policy is not an allow grant")
    resources = policy.get("resources")
    if not isinstance(resources, dict) or resources != {ACCOUNT_SCOPE: account_id}:
        raise BootstrapError("Cloudflare bootstrap token is not limited to the selected account")
    groups = policy.get("permission_groups")
    if not isinstance(groups, list) or len(groups) != 1:
        raise BootstrapError("Cloudflare bootstrap token has unexpected permissions")
    group = groups[0]
    if not isinstance(group, dict) or group.get("name") != R2_WRITE_GROUP:
        raise BootstrapError("Cloudflare bootstrap token lacks the exact R2 write permission")


def request_temporary_credentials(
    *,
    account_id: str,
    bucket: str,
    parent_access_key_id: str,
    bearer: str,
    fetch: Callable[..., tuple[int, dict | None]] = provider_json,
) -> TemporaryCredentials:
    """Request only Object R/W credentials for one bucket, for 7200 seconds."""
    if account_id != EXPECTED_ACCOUNT:
        raise BootstrapError("wrong Cloudflare account for this R2 profile")
    if bucket != EXPECTED_BUCKET:
        raise BootstrapError("wrong disposable R2 target for this profile")
    if not PARENT_KEY_RE.fullmatch(parent_access_key_id):
        raise BootstrapError("missing or invalid parent R2 access-key identifier")
    if not bearer:
        raise BootstrapError("missing protected Cloudflare bootstrap token")
    path = f"/accounts/{account_id}/r2/temp-access-credentials"
    request_body = {
        "bucket": bucket,
        "parentAccessKeyId": parent_access_key_id,
        "permission": "object-read-write",
        "ttlSeconds": TTL_SECONDS,
    }
    status, payload = fetch("POST", path, bearer, body=request_body)
    result = _successful(status, payload)
    key_id = result.get("accessKeyId")
    secret = result.get("secretAccessKey")
    session = result.get("sessionToken")
    if not all(isinstance(value, str) and value.strip() for value in (key_id, secret, session)):
        raise BootstrapError("Cloudflare did not return a complete temporary credential trio")
    return TemporaryCredentials(key_id, secret, session)


def verify_parent_scope_receipt(env: Mapping[str, str], parent_access_key_id: str) -> None:
    """Bind the external official parent-key identity readback to the request."""
    if env.get("R2_PARENT_SCOPE_CONFIRMED_ACCESS_KEY_ID") != parent_access_key_id:
        raise BootstrapError("parent R2 key lacks matching protected identity readback")
    if env.get("R2_PARENT_SCOPE_CONFIRMED_BUCKET") != EXPECTED_BUCKET:
        raise BootstrapError("parent R2 readback is not bound to this disposable target")
    if not RECEIPT_RE.fullmatch(env.get("R2_PARENT_SCOPE_RECEIPT_SHA256", "")):
        raise BootstrapError("parent R2 identity receipt digest is missing or invalid")


def run_r2_profile(
    env: Mapping[str, str],
    *,
    emit: Callable[[str], None],
    run: Callable[..., subprocess.CompletedProcess[str]],
    fetch: Callable[..., tuple[int, dict | None]] = provider_json,
    cwd: Path,
) -> int:
    """Classify, request, mask, and hand only the temporary trio to the runner."""
    if env.get("REAL_HARNESS_PROFILE") != PROFILE:
        raise BootstrapError("temporary R2 credentials are restricted to profile r2")
    if env.get("D1_DATABASE_ID") != "test":
        raise BootstrapError("R2 profile requires the inert D1 parser fixture")
    account_id = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    bucket = env.get("R2_TEST_BUCKET", "").strip()
    bearer = env.get("CF_API_TOKEN", "").strip()
    parent_access_key_id = env.get("R2_S3_ACCESS_KEY_ID", "").strip()
    endpoint = urlsplit(env.get("R2_S3_ENDPOINT", "").strip())
    if (
        endpoint.scheme != "https"
        or endpoint.hostname != f"{account_id}.r2.cloudflarestorage.com"
        or endpoint.port is not None
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        raise BootstrapError("R2 S3 endpoint does not match the isolated account")
    if env.get("R2_S3_SECRET_ACCESS_KEY", ""):
        raise BootstrapError("parent R2 secret must not be passed to the bootstrap")
    if not parent_access_key_id:
        raise BootstrapError("missing parent R2 access-key identifier")
    verify_parent_scope_receipt(env, parent_access_key_id)

    classify_bearer_r2_write(account_id=account_id, bearer=bearer, fetch=fetch)
    credentials = request_temporary_credentials(
        account_id=account_id,
        bucket=bucket,
        parent_access_key_id=parent_access_key_id,
        bearer=bearer,
        fetch=fetch,
    )
    child_env = dict(env)
    child_env["CF_API_TOKEN"] = "test"
    child_env["D1_DATABASE_ID"] = "test"
    child_env["R2_S3_ACCESS_KEY_ID"] = credentials.access_key_id
    child_env["R2_S3_SECRET_ACCESS_KEY"] = credentials.secret_access_key
    child_env["R2_S3_SESSION_TOKEN"] = credentials.session_token
    for name in (
        "R2_PARENT_SCOPE_CONFIRMED_ACCESS_KEY_ID",
        "R2_PARENT_SCOPE_CONFIRMED_BUCKET",
        "R2_PARENT_SCOPE_RECEIPT_SHA256",
    ):
        child_env.pop(name, None)
    try:
        for value in (bearer, parent_access_key_id, credentials.access_key_id, credentials.secret_access_key, credentials.session_token):
            if value:
                emit(f"::add-mask::{value}")
        result = run(list(RUNNER), cwd=cwd, env=child_env, check=False, text=True)
        return result.returncode
    finally:
        child_env.clear()
        del credentials


def main() -> int:
    try:
        return run_r2_profile(
            os.environ,
            emit=lambda line: print(line, flush=True),
            run=subprocess.run,
            cwd=Path(os.environ.get("GITHUB_WORKSPACE", ".")),
        )
    except (BootstrapError, OSError, TypeError, ValueError):
        print("R2 temporary credential bootstrap failed closed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
