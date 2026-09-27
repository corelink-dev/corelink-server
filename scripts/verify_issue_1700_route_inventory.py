#!/usr/bin/env python3
"""Fail-closed, read-only route inventory gate for staging deployment issue #1700."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CANONICAL_HOST = "staging.corelink.humangr.com"
ZONE_NAME = "humangr.com"
ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
API_ROOT = "https://api.cloudflare.com/client/v4"
MAX_ITEMS = 1000
MAX_RESPONSE_BYTES = 2_000_000
ID_RE = re.compile(r"^[0-9a-f]{32}$")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class InventoryError(ValueError):
    """The provider response or route pattern is unsafe or incomplete."""


def _valid_dns_name(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    return all(DNS_LABEL_RE.fullmatch(label) for label in labels)


def _host_can_match_canonical(host: str) -> bool:
    wildcard = host.startswith("*")
    suffix = host[1:] if wildcard else host
    if suffix.startswith("."):
        zone_candidate = suffix[1:]
    else:
        zone_candidate = suffix
    if not _valid_dns_name(zone_candidate):
        raise InventoryError("route hostname is malformed")
    if zone_candidate != ZONE_NAME and not zone_candidate.endswith("." + ZONE_NAME):
        raise InventoryError("route hostname is outside the canonical zone")
    if wildcard:
        # Keep the leading dot in *.example forms: that form does not match
        # the apex. A bare leading * follows the provider's suffix semantics.
        return CANONICAL_HOST.endswith(suffix.lower())
    return host.lower() == CANONICAL_HOST


def route_matches_canonical(pattern: Any) -> bool:
    """Parse the chartered Cloudflare route grammar and match its hostname."""
    if not isinstance(pattern, str) or not pattern:
        raise InventoryError("route pattern is missing or not a nonempty string")
    try:
        pattern.encode("ascii")
    except UnicodeEncodeError as error:
        raise InventoryError("route pattern must be ASCII") from error
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in pattern):
        raise InventoryError("route pattern contains whitespace or control bytes")
    if any(char in pattern for char in "?#\\@"):
        raise InventoryError("route pattern contains an unsupported delimiter")

    if pattern.startswith("http://"):
        pattern = pattern[len("http://") :]
    elif pattern.startswith("https://"):
        pattern = pattern[len("https://") :]
    elif "://" in pattern:
        raise InventoryError("route scheme is unsupported")

    host, separator, path = pattern.partition("/")
    if not host or ":" in host or host.startswith(".") or host.endswith("."):
        raise InventoryError("route hostname is malformed or includes a port")
    if host.count("*") > 1 or ("*" in host and not host.startswith("*")):
        raise InventoryError("route hostname wildcard is unsupported")
    if "*" in host and len(host) == 1:
        raise InventoryError("route hostname wildcard has no suffix")

    if separator:
        route_path = "/" + path
        if not route_path.startswith("/"):
            raise InventoryError("route path is malformed")
        if route_path.count("*") > 1 or (
            "*" in route_path and not route_path.endswith("*")
        ):
            raise InventoryError("route path wildcard is unsupported")
    elif "*" in pattern and "*" not in host:
        raise InventoryError("route path wildcard requires a path")

    normalized_host = host.lower()
    return _host_can_match_canonical(normalized_host)


def _check_pagination(envelope: dict[str, Any], result: list[Any], label: str) -> None:
    info = envelope.get("result_info")
    if not isinstance(info, dict):
        raise InventoryError(f"{label} pagination metadata is incomplete")
    page = info.get("page")
    per_page = info.get("per_page")
    count = info.get("count")
    total_count = info.get("total_count")
    total_pages = info.get("total_pages")
    if (
        type(page) is not int
        or page != 1
        or type(per_page) is not int
        or per_page < 1
        or type(count) is not int
        or count != len(result)
        or type(total_count) is not int
        or total_count != len(result)
        or type(total_pages) is not int
        or total_pages != 1
        or len(result) > min(per_page, MAX_ITEMS)
    ):
        raise InventoryError(f"{label} inventory is incomplete or exceeds the bound")


def validate_envelope(payload: Any, label: str) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise InventoryError(f"{label} API response was unsuccessful or malformed")
    result = payload.get("result")
    if not isinstance(result, list):
        raise InventoryError(f"{label} result is not a list")
    _check_pagination(payload, result, label)
    return result, payload


def validate_zone_inventory(payload: Any) -> str:
    zones, envelope = validate_envelope(payload, "zone")
    if len(zones) != 1:
        raise InventoryError("canonical zone is absent or ambiguous")
    zone = zones[0]
    if not isinstance(zone, dict):
        raise InventoryError("zone entry is malformed")
    zone_id = zone.get("id")
    account = zone.get("account")
    if (
        zone.get("name") != ZONE_NAME
        or not isinstance(zone_id, str)
        or not ID_RE.fullmatch(zone_id)
        or not isinstance(account, dict)
        or account.get("id") != ACCOUNT_ID
    ):
        raise InventoryError("zone identity or account scope does not match staging")
    return zone_id


def validate_route_inventory(payload: Any) -> list[dict[str, Any]]:
    routes, _ = validate_envelope(payload, "route")
    checked: list[dict[str, Any]] = []
    for route in routes:
        if (
            not isinstance(route, dict)
            or "pattern" not in route
            or "script" not in route
        ):
            raise InventoryError("route entry is malformed or incomplete")
        if route["script"] is not None and not isinstance(route["script"], str):
            raise InventoryError("route Worker target is malformed")
        checked.append(route)
    return checked


def _get_json(token: str, path: str) -> Any:
    request = urllib.request.Request(
        f"{API_ROOT}/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise InventoryError("Cloudflare read-only inventory request failed") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise InventoryError("Cloudflare inventory response exceeds the byte bound")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise InventoryError(
            "Cloudflare inventory response is not valid JSON"
        ) from error


def read_route_inventory(token: str) -> list[dict[str, Any]]:
    if not token:
        raise InventoryError("Cloudflare token input is absent")
    zone_query = urllib.parse.urlencode({"name": ZONE_NAME, "per_page": MAX_ITEMS})
    zone_id = validate_zone_inventory(_get_json(token, f"zones?{zone_query}"))
    route_query = urllib.parse.urlencode({"per_page": MAX_ITEMS})
    return validate_route_inventory(
        _get_json(token, f"zones/{zone_id}/workers/routes?{route_query}")
    )


def verify_route_free_from_payloads(
    zone_payload: Any, route_payload: Any
) -> dict[str, int]:
    zone_id = validate_zone_inventory(zone_payload)
    if not ID_RE.fullmatch(zone_id):
        raise InventoryError("canonical zone identifier is malformed")
    routes = validate_route_inventory(route_payload)
    canonical_count = sum(route_matches_canonical(route["pattern"]) for route in routes)
    if canonical_count:
        raise InventoryError("canonical staging host route exists; refusing deploy")
    return {
        "route_count": len(routes),
        "canonical_staging_route_count": canonical_count,
    }


def verify_route_free(token: str) -> dict[str, int]:
    if not token:
        raise InventoryError("Cloudflare token input is absent")
    zone_query = urllib.parse.urlencode({"name": ZONE_NAME, "per_page": MAX_ITEMS})
    zone_payload = _get_json(token, f"zones?{zone_query}")
    zone_id = validate_zone_inventory(zone_payload)
    route_query = urllib.parse.urlencode({"per_page": MAX_ITEMS})
    route_payload = _get_json(token, f"zones/{zone_id}/workers/routes?{route_query}")
    return verify_route_free_from_payloads(zone_payload, route_payload)


def main() -> int:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    try:
        receipt = verify_route_free(token)
    except InventoryError as error:
        print(
            f"::error::issue-1700 staging route inventory rejected: {error}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
