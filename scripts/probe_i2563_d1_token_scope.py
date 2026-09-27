#!/usr/bin/env python3
"""Status-only, read-only credential boundary for the isolated #2563 D1 run."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable


ACCOUNT = "51284495e71acdb5a7677e7383ab026b"
OLD_ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd"
DB_NAME_PREFIX = "corelink-issue-2563-d1-"
API = "https://api.cloudflare.com/client/v4"


class ScopeError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def provider_get(url: str, token: str) -> tuple[int, dict | None]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ScopeError("provider metadata response too large")
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as error:
                raise ScopeError("provider metadata response invalid") from error
            if not isinstance(payload, dict):
                raise ScopeError("provider metadata response invalid")
            return response.status, payload
    except urllib.error.HTTPError as error:
        # Do not read or log the provider response body or request headers.
        return error.code, None
    except urllib.error.URLError as error:
        raise ScopeError("provider identity request failed") from error


def verify_scope(
    account: str,
    database_id: str,
    token: str,
    fetch: Callable[[str, str], tuple[int, dict | None]] = provider_get,
) -> None:
    if account != ACCOUNT:
        raise ScopeError("wrong D1 account binding")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", database_id):
        raise ScopeError("invalid disposable D1 identifier")
    if not token:
        raise ScopeError("missing D1 token")

    old_status, _ = fetch(f"{API}/accounts/{OLD_ACCOUNT}/d1/database", token)
    if old_status != 403:
        raise ScopeError("D1 token is not denied on the production-containing account")

    target_status, payload = fetch(
        f"{API}/accounts/{ACCOUNT}/d1/database/{database_id}", token
    )
    if target_status != 200 or not isinstance(payload, dict) or payload.get("success") is not True:
        raise ScopeError("isolated D1 target is not readable")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ScopeError("isolated D1 target metadata is invalid")
    if database_id not in (result.get("uuid"), result.get("id")):
        raise ScopeError("isolated D1 target identifier mismatch")
    if not isinstance(result.get("name"), str) or not result["name"].startswith(DB_NAME_PREFIX):
        raise ScopeError("D1 target is not exclusive to #2563")


def self_test() -> None:
    database_id = "11111111-2222-4333-8444-555555555555"
    target = {"success": True, "result": {"uuid": database_id, "name": DB_NAME_PREFIX + "fixture"}}

    def fetch(old_status: int = 403, target_status: int = 200, target_data: dict | None = target):
        def run(url: str, _token: str) -> tuple[int, dict | None]:
            if url == f"{API}/accounts/{OLD_ACCOUNT}/d1/database":
                return old_status, None
            if url == f"{API}/accounts/{ACCOUNT}/d1/database/{database_id}":
                return target_status, target_data
            raise ScopeError("unexpected fixture URL")
        return run

    verify_scope(ACCOUNT, database_id, "fixture-token", fetch())
    rejected = (
        (OLD_ACCOUNT, database_id, fetch()),
        (ACCOUNT, database_id, fetch(old_status=200)),
        (ACCOUNT, database_id, fetch(old_status=401)),
        (ACCOUNT, database_id, fetch(target_status=403)),
        (ACCOUNT, database_id, fetch(target_data={"success": True, "result": {"uuid": database_id, "name": "shared"}})),
        (ACCOUNT, database_id, fetch(target_data={"success": True, "result": {"uuid": "wrong", "name": DB_NAME_PREFIX + "fixture"}})),
    )
    for account, target_id, case in rejected:
        try:
            verify_scope(account, target_id, "fixture-token", case)
        except ScopeError:
            continue
        raise ScopeError("negative scope fixture was accepted")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
        elif len(sys.argv) == 1:
            verify_scope(
                os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
                os.environ.get("D1_DATABASE_ID", ""),
                os.environ.get("CF_API_TOKEN", ""),
            )
        else:
            raise ScopeError("unknown probe mode")
    except ScopeError as error:
        print(f"i2563 D1 scope: FAIL: {error}", file=sys.stderr)
        return 1
    print("i2563 D1 scope: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
