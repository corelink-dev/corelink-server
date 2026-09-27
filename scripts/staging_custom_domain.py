#!/usr/bin/env python3
"""Preview and publish the exact #1700 staging Worker Custom Domain."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

if __package__:
    from .verify_issue_1700_route_inventory import (
        InventoryError,
        route_matches_canonical,
        validate_route_inventory,
    )
else:
    from verify_issue_1700_route_inventory import (
        InventoryError,
        route_matches_canonical,
        validate_route_inventory,
    )

API_ROOT = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
ZONE_ID = "73f57f6d508beea67e2f78bea11d3c25"
ZONE_NAME = "humangr.com"
HOSTNAME = "staging.corelink.humangr.com"
WORKER = "corelink-staging"
MAX_RESPONSE_BYTES = 2_000_000
DNS_PAGE_SIZE = 100
DOMAIN_PAGE_SIZE = 100
ID_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


class DomainError(ValueError):
    """The provider state is incomplete, conflicting, or outside the charter."""


def _success_list(payload: Any, label: str) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DomainError(f"{label} response was unsuccessful or malformed")
    if payload.get("errors") not in (None, []) or payload.get("messages") not in (
        None,
        [],
    ):
        raise DomainError(f"{label} response contains provider errors or messages")
    rows = payload.get("result")
    if not isinstance(rows, list) or len(rows) > 1000:
        raise DomainError(f"{label} result is malformed or over the inventory bound")
    return rows, payload


def _validate_page(
    payload: dict[str, Any],
    rows: list[Any],
    per_page: int,
    label: str,
    *,
    allow_missing_total_pages: bool = False,
) -> None:
    info = payload.get("result_info")
    if not isinstance(info, dict):
        raise DomainError(f"{label} pagination metadata is missing")
    count, page = info.get("count"), info.get("page")
    size, pages, total = (
        info.get("per_page"),
        info.get("total_pages"),
        info.get("total_count"),
    )
    if (
        type(count) is not int
        or count != len(rows)
        or type(page) is not int
        or page != 1
        or type(size) is not int
        or size != per_page
        or ("total_pages" not in info and not allow_missing_total_pages)
        or ("total_pages" in info and (type(pages) is not int or pages != 1))
        or type(total) is not int
        or total < count
        or len(rows) >= per_page
    ):
        raise DomainError(
            f"{label} inventory is incomplete or exceeds the one-page bound"
        )


def validate_zone(
    payload: Any, supplied_zone_id: str, supplied_account_id: str
) -> None:
    if supplied_account_id != ACCOUNT_ID or supplied_zone_id != ZONE_ID:
        raise DomainError("configured account or zone is not the pinned staging target")
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DomainError("zone identity response was unsuccessful or malformed")
    if payload.get("errors") not in (None, []) or payload.get("messages") not in (
        None,
        [],
    ):
        raise DomainError("zone identity response contains provider errors or messages")
    zone = payload.get("result")
    if not isinstance(zone, dict) or (
        zone.get("id") != ZONE_ID
        or zone.get("name") != ZONE_NAME
        or not isinstance(zone.get("account"), dict)
        or zone["account"].get("id") != ACCOUNT_ID
    ):
        raise DomainError(
            "provider zone does not match the pinned staging account and zone"
        )


def validate_dns(payload: Any) -> list[dict[str, Any]]:
    rows, envelope = _success_list(payload, "DNS")
    _validate_page(
        envelope,
        rows,
        DNS_PAGE_SIZE,
        "DNS",
        allow_missing_total_pages=True,
    )
    checked: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise DomainError("DNS record entry is malformed")
        if (
            row.get("name") != HOSTNAME
            or not isinstance(row.get("id"), str)
            or not ID_RE.fullmatch(row["id"])
            or row.get("type") not in {"A", "AAAA", "CNAME"}
            or type(row.get("proxied")) is not bool
            or not isinstance(row.get("content"), str)
            or not row["content"]
        ):
            raise DomainError(
                "DNS record is malformed or conflicts with the exact staging hostname"
            )
        checked.append(row)
    return checked


def validate_domains(payload: Any) -> list[dict[str, Any]]:
    rows, envelope = _success_list(payload, "Worker Custom Domain")
    _validate_page(
        envelope,
        rows,
        DOMAIN_PAGE_SIZE,
        "Worker Custom Domain",
        allow_missing_total_pages=True,
    )
    checked: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise DomainError("Worker Custom Domain entry is malformed")
        if (
            row.get("hostname") != HOSTNAME
            or not isinstance(row.get("id"), str)
            or not ID_RE.fullmatch(row["id"])
            or not isinstance(row.get("cert_id"), str)
            or not UUID_RE.fullmatch(row["cert_id"])
            or not isinstance(row.get("service"), str)
            or not row["service"]
            or row.get("zone_id") != ZONE_ID
            or row.get("zone_name") != ZONE_NAME
        ):
            raise DomainError(
                "Worker Custom Domain entry is malformed or not pinned to staging"
            )
        checked.append(row)
    return checked


def validate_subdomain(payload: Any) -> None:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DomainError("Worker subdomain response was unsuccessful or malformed")
    if payload.get("errors") not in (None, []) or payload.get("messages") not in (
        None,
        [],
    ):
        raise DomainError(
            "Worker subdomain response contains provider errors or messages"
        )
    result = payload.get("result")
    if not isinstance(result, dict) or (
        result.get("enabled") is not False
        or result.get("previews_enabled") is not False
    ):
        raise DomainError(
            "staging Worker workers.dev or preview endpoint is enabled or unreadable"
        )


def assess_state(
    zone_payload: Any,
    route_payload: Any,
    domains_payload: Any,
    dns_payload: Any,
    subdomain_payload: Any,
    supplied_zone_id: str = ZONE_ID,
    supplied_account_id: str = ACCOUNT_ID,
) -> dict[str, Any]:
    validate_zone(zone_payload, supplied_zone_id, supplied_account_id)
    validate_subdomain(subdomain_payload)
    try:
        if not isinstance(route_payload, dict) or (
            route_payload.get("errors") not in (None, [])
            or route_payload.get("messages") not in (None, [])
        ):
            raise DomainError("route inventory contains provider errors or messages")
        routes = validate_route_inventory(route_payload)
        route_matches = sum(
            route_matches_canonical(route["pattern"]) for route in routes
        )
    except InventoryError as error:
        raise DomainError(
            f"route inventory is malformed or incomplete: {error}"
        ) from error
    if route_matches:
        raise DomainError(
            "a host-matching Worker Route exists; refusing Custom Domain attach"
        )
    domains = validate_domains(domains_payload)
    dns = validate_dns(dns_payload)
    if len(domains) > 1:
        raise DomainError("multiple Worker Custom Domains match the staging hostname")
    if len(dns) > 1:
        raise DomainError("multiple DNS records occupy the staging hostname")
    if not domains:
        if dns:
            raise DomainError(
                "a DNS record already occupies the staging hostname without its Custom Domain"
            )
        return {
            "action": "attach-custom-domain",
            "hostname": HOSTNAME,
            "worker": WORKER,
            "zone_name": ZONE_NAME,
            "zone_id": ZONE_ID,
            "account_id": ACCOUNT_ID,
            "custom_domain_count": 0,
            "dns_record_count": 0,
            "route_count": len(routes),
            "canonical_route_count": 0,
        }
    domain = domains[0]
    if domain.get("service") != WORKER:
        raise DomainError(
            "existing Custom Domain maps the staging hostname to another Worker"
        )
    if any(not record["proxied"] for record in dns):
        raise DomainError(
            "existing Custom Domain has an unproxied or conflicting DNS record"
        )
    if not dns:
        return {
            "action": "await-provider-dns",
            "hostname": HOSTNAME,
            "worker": WORKER,
            "custom_domain_id": domain["id"],
            "certificate_id": domain["cert_id"],
            "custom_domain_count": 1,
            "dns_record_count": 0,
            "route_count": len(routes),
            "canonical_route_count": 0,
        }
    return {
        "action": "already-exact",
        "hostname": HOSTNAME,
        "worker": WORKER,
        "custom_domain_id": domain["id"],
        "certificate_id": domain["cert_id"],
        "custom_domain_count": 1,
        "dns_record_count": len(dns),
        "dns_record_ids": sorted(record["id"] for record in dns),
        "route_count": len(routes),
        "canonical_route_count": 0,
    }


def _read_json(token: str, path: str) -> Any:
    req = urllib.request.Request(
        f"{API_ROOT}/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise DomainError("Cloudflare read request failed") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DomainError("Cloudflare response exceeded the byte bound")
    try:
        return json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise DomainError("Cloudflare returned malformed JSON") from error


def _request_json(
    token: str, path: str, method: str, body: dict[str, Any] | None = None
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{API_ROOT}/{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise DomainError(
            f"Cloudflare {method} request failed; reconcile provider state before retry"
        ) from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DomainError("Cloudflare response exceeded the byte bound")
    try:
        return json.loads(raw, object_pairs_hook=_unique_object) if raw else {}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise DomainError("Cloudflare returned malformed JSON") from error


def _validate_mutation_envelope(payload: Any, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DomainError(f"{label} response was unsuccessful or malformed")
    if payload.get("errors") not in (None, []) or payload.get("messages") not in (
        None,
        [],
    ):
        raise DomainError(f"{label} response contains provider errors or messages")
    return payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _inventory(token: str, account_id: str, zone_id: str) -> tuple[Any, ...]:
    zone = _read_json(token, f"zones/{zone_id}")
    zone_query = urllib.parse.urlencode(
        {"hostname": HOSTNAME, "page": 1, "per_page": DOMAIN_PAGE_SIZE}
    )
    domains = _read_json(token, f"accounts/{account_id}/workers/domains?{zone_query}")
    dns_query = urllib.parse.urlencode(
        {"name": HOSTNAME, "page": 1, "per_page": DNS_PAGE_SIZE}
    )
    dns = _read_json(token, f"zones/{zone_id}/dns_records?{dns_query}")
    routes = _read_json(token, f"zones/{zone_id}/workers/routes")
    subdomain = _read_json(
        token, f"accounts/{account_id}/workers/scripts/{WORKER}/subdomain"
    )
    root_settings = _read_json(
        token, f"accounts/{account_id}/workers/scripts/{WORKER}/settings"
    )
    signup_settings = _read_json(
        token, f"accounts/{account_id}/workers/scripts/corelink-signup-staging/settings"
    )
    return zone, routes, domains, dns, subdomain, root_settings, signup_settings


def runtime_binding_gaps(root_payload: Any, signup_payload: Any) -> list[str]:
    topology_path = Path(__file__).resolve().parents[1] / "infra/staging/topology.json"
    try:
        topology = json.loads(topology_path.read_text(encoding="utf-8"))
        required = topology["required_secret_names"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise DomainError("staging topology secret contract is unreadable") from error
    gaps: list[str] = []
    for worker, payload in (
        (WORKER, root_payload),
        ("corelink-signup-staging", signup_payload),
    ):
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise DomainError(
                f"{worker} settings readback was unsuccessful or malformed"
            )
        if payload.get("errors") not in (None, []) or payload.get("messages") not in (
            None,
            [],
        ):
            raise DomainError(
                f"{worker} settings readback contains provider errors or messages"
            )
        result = payload.get("result")
        bindings = result.get("bindings") if isinstance(result, dict) else None
        if not isinstance(bindings, list) or len(bindings) > 1000:
            raise DomainError(
                f"{worker} binding inventory is malformed or over the bound"
            )
        names: set[str] = set()
        for binding in bindings:
            if (
                not isinstance(binding, dict)
                or not isinstance(binding.get("name"), str)
                or not isinstance(binding.get("type"), str)
            ):
                raise DomainError(f"{worker} binding entry is malformed")
            if binding["name"] in names:
                raise DomainError(f"{worker} has duplicate binding names")
            names.add(binding["name"])
        expected = required.get(worker)
        if not isinstance(expected, list) or any(
            not isinstance(name, str) for name in expected
        ):
            raise DomainError(f"{worker} secret contract is malformed")
        secret_names = {
            binding["name"]
            for binding in bindings
            if binding.get("type") == "secret_text"
            and isinstance(binding.get("name"), str)
        }
        gaps.extend(f"{worker}:{name}" for name in expected if name not in secret_names)
    return gaps


def validate_request_signal_settings(root_payload: Any) -> None:
    if not isinstance(root_payload, dict) or root_payload.get("success") is not True:
        raise DomainError("root Worker settings readback was unsuccessful or malformed")
    if root_payload.get("errors") not in (None, []) or root_payload.get(
        "messages"
    ) not in (
        None,
        [],
    ):
        raise DomainError(
            "root Worker settings readback contains provider errors or messages"
        )
    result = root_payload.get("result")
    expected = [
        "nodejs_compat",
        "enable_request_signal",
        "request_signal_passthrough",
    ]
    flags = result.get("compatibility_flags") if isinstance(result, dict) else None
    if (
        not isinstance(flags, list)
        or any(not isinstance(flag, str) for flag in flags)
        or len(flags) != len(expected)
        or set(flags) != set(expected)
    ):
        raise DomainError(
            "root Worker request-signal compatibility flags are absent or unexpected"
        )


def _readiness() -> tuple[bool, str]:
    req = urllib.request.Request(
        f"https://{HOSTNAME}/health", headers={"Accept": "application/json"}
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=10) as response:
            if response.status != 200:
                return False, "http-status"
            raw = response.read(4096)
            payload = json.loads(raw)
            if not isinstance(payload, dict) or payload.get("status") != "ok":
                return False, "health-contract"
            return True, "healthy"
    except urllib.error.HTTPError as error:
        return False, f"http-{error.code}"
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return False, "tls-dns-or-health-unavailable"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _detach_created(token: str, domain_id: str, certificate_id: str) -> bool:
    path = f"accounts/{ACCOUNT_ID}/workers/domains/{urllib.parse.quote(domain_id, safe='')}"
    current = _read_json(token, path)
    try:
        current = _validate_mutation_envelope(current, "Custom Domain rollback read")
    except DomainError:
        return False
    domain = current.get("result")
    if not isinstance(domain, dict) or (
        domain.get("id") != domain_id
        or domain.get("cert_id") != certificate_id
        or domain.get("hostname") != HOSTNAME
        or domain.get("service") != WORKER
        or domain.get("zone_id") != ZONE_ID
        or domain.get("zone_name") != ZONE_NAME
    ):
        return False
    try:
        _validate_mutation_envelope(
            _request_json(token, path, "DELETE"), "Custom Domain rollback"
        )
    except DomainError:
        return False
    try:
        remaining = assess_state(*_inventory(token, ACCOUNT_ID, ZONE_ID)[:5])
    except DomainError:
        return False
    return remaining["action"] == "attach-custom-domain"


def run(
    mode: str, token: str, account_id: str, zone_id: str, receipt_path: Path
) -> dict[str, Any]:
    if not token:
        raise DomainError("CF_API_TOKEN is absent")
    inventory = _inventory(token, account_id, zone_id)
    validate_request_signal_settings(inventory[5])
    binding_gaps = runtime_binding_gaps(inventory[5], inventory[6])
    plan = assess_state(
        *inventory[:5], supplied_zone_id=zone_id, supplied_account_id=account_id
    )
    plan["missing_runtime_secret_bindings"] = binding_gaps
    plan["runtime_secret_bindings_ready"] = not binding_gaps
    if mode == "preview":
        plan["mode"] = "preview"
        plan["provider_mutation_performed"] = False
    elif mode == "publish":
        if binding_gaps:
            raise DomainError(
                "required staging runtime secret bindings are absent: "
                + ", ".join(binding_gaps)
            )
        if plan["action"] == "attach-custom-domain":
            # Close the inventory-to-attach race with a second complete read.
            # A collision or a newly missing runtime binding requires a new preview.
            fresh_inventory = _inventory(token, account_id, zone_id)
            fresh_plan = assess_state(
                *fresh_inventory[:5],
                supplied_zone_id=zone_id,
                supplied_account_id=account_id,
            )
            fresh_gaps = runtime_binding_gaps(fresh_inventory[5], fresh_inventory[6])
            validate_request_signal_settings(fresh_inventory[5])
            if fresh_plan["action"] != "attach-custom-domain" or fresh_gaps:
                raise DomainError(
                    "provider state or required bindings changed after preview; rerun preview"
                )
            try:
                response = _request_json(
                    token,
                    f"accounts/{ACCOUNT_ID}/workers/domains",
                    "PUT",
                    {
                        "hostname": HOSTNAME,
                        "service": WORKER,
                        "zone_id": ZONE_ID,
                        "zone_name": ZONE_NAME,
                    },
                )
                response = _validate_mutation_envelope(response, "Custom Domain attach")
            except DomainError:
                _write_receipt(
                    receipt_path,
                    {
                        "action": "attach-outcome-unknown",
                        "hostname": HOSTNAME,
                        "worker": WORKER,
                        "zone_id": ZONE_ID,
                        "account_id": ACCOUNT_ID,
                        "provider_mutation_performed": "unknown",
                        "reconcile_before_retry": True,
                        "mode": mode,
                    },
                )
                raise
            created = response.get("result")
            if not isinstance(created, dict) or (
                created.get("hostname") != HOSTNAME
                or created.get("service") != WORKER
                or created.get("zone_id") != ZONE_ID
                or created.get("zone_name") != ZONE_NAME
                or not isinstance(created.get("id"), str)
                or not ID_RE.fullmatch(created["id"])
                or not isinstance(created.get("cert_id"), str)
                or not UUID_RE.fullmatch(created["cert_id"])
            ):
                _write_receipt(
                    receipt_path,
                    {
                        "action": "attach-response-unexpected",
                        "hostname": HOSTNAME,
                        "worker": WORKER,
                        "zone_id": ZONE_ID,
                        "account_id": ACCOUNT_ID,
                        "provider_mutation_performed": "unknown",
                        "reconcile_before_retry": True,
                        "mode": mode,
                    },
                )
                raise DomainError(
                    "Custom Domain attach returned an unexpected target; inspect before retry"
                )
            domain_id, cert_id = created["id"], created["cert_id"]
            dns_visible = False
            post_attach_problem = False
            for _ in range(18):
                try:
                    current_inventory = _inventory(token, account_id, zone_id)
                    current = assess_state(
                        *current_inventory[:5],
                        supplied_zone_id=zone_id,
                        supplied_account_id=account_id,
                    )
                except DomainError:
                    post_attach_problem = True
                    break
                if (
                    current["action"] == "already-exact"
                    and current.get("custom_domain_id") == domain_id
                ):
                    dns_visible = True
                    break
                if (
                    current["action"] != "await-provider-dns"
                    or current.get("custom_domain_id") != domain_id
                ):
                    break
                time.sleep(10)
            healthy = False
            health_result = "dns-not-ready"
            if dns_visible:
                for _ in range(90):
                    healthy, health_result = _readiness()
                    if healthy:
                        break
                    time.sleep(10)
            if not dns_visible or not healthy or post_attach_problem:
                try:
                    rolled_back = _detach_created(token, domain_id, cert_id)
                except DomainError:
                    rolled_back = False
                plan = {
                    "action": "publication-failed",
                    "hostname": HOSTNAME,
                    "worker": WORKER,
                    "custom_domain_id": domain_id,
                    "certificate_id": cert_id,
                    "dns_visible": dns_visible,
                    "post_attach_inventory_conflict": post_attach_problem,
                    "health_result": health_result,
                    "rollback_detached_created_domain": rolled_back,
                    "certificate_cleanup": "provider_certificate_id_retained_in_custody_receipt",
                    "provider_mutation_performed": True,
                    "mode": mode,
                }
                _write_receipt(receipt_path, plan)
                raise DomainError(
                    "publication did not reach verified DNS/TLS health; receipt records exact rollback/certificate custody state"
                )
            plan = {
                **current,
                "missing_runtime_secret_bindings": binding_gaps,
                "runtime_secret_bindings_ready": True,
                "action": "published-and-health-verified",
                "provider_mutation_performed": True,
                "created_by_run": True,
                "health_result": health_result,
                "authenticated_readiness": "separate-protected-i1675-probe-required",
                "certificate_cleanup": "retained_active_domain_no_cleanup_due",
                "mode": mode,
            }
        else:
            healthy, health_result = _readiness()
            plan["action"] = (
                "already-exact-health-verified"
                if healthy
                else "already-exact-health-pending"
            )
            plan["provider_mutation_performed"] = False
            plan["health_result"] = health_result
            plan["authenticated_readiness"] = "separate-protected-i1675-probe-required"
            plan["mode"] = mode
            if not healthy:
                raise DomainError(
                    "exact existing Custom Domain is intact but HTTPS /health is not ready"
                )
    else:
        raise DomainError("unsupported mode")
    _write_receipt(receipt_path, plan)
    return plan


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("preview", "publish"), required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("CF_API_TOKEN", "")
    account_id = os.environ.get("STAGING_CF_ACCOUNT_ID", "")
    zone_id = os.environ.get("CF_ZONE_ID", "")
    try:
        receipt = run(args.mode, token, account_id, zone_id, args.receipt)
    except DomainError as error:
        print(
            f"::error::issue-1700 Custom Domain gate rejected: {error}", file=sys.stderr
        )
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
