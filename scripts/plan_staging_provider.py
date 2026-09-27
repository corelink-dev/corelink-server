#!/usr/bin/env python3
"""Create a redacted, read-only Cloudflare staging plan for #1700.

The command deliberately has no write endpoint.  It validates the exact
staging contract, verifies that the existing isolated base resources are
present, and proves that the credential can read the DNS and Worker-route
surfaces that a later reviewed apply would need.  It never serializes a token,
account ID, zone ID, or provider resource ID into its receipt.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ORIGIN = "https://staging.corelink.humangr.com"
HOSTNAME = "staging.corelink.humangr.com"


def provider_get(token: str, path: str) -> tuple[bool, Any]:
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        try:
            payload = json.load(error)
        except (json.JSONDecodeError, OSError):
            payload = {}
        errors = payload.get("errors", []) if isinstance(payload, dict) else []
        codes = sorted(str(item.get("code", "unknown")) for item in errors if isinstance(item, dict))
        return False, {"http_status": error.code, "provider_error_codes": codes or ["unknown"]}
    except urllib.error.URLError:
        return False, {"transport": "unavailable"}
    if not isinstance(payload, dict) or payload.get("success") is not True:
        errors = payload.get("errors", []) if isinstance(payload, dict) else []
        codes = sorted(str(item.get("code", "unknown")) for item in errors if isinstance(item, dict))
        return False, {"provider_error_codes": codes or ["unknown"]}
    return True, payload.get("result")


def require_contract(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    budget = contract.get("budget", {})
    lifecycle = contract.get("lifecycle", {})
    if contract.get("issue") != 1700 or contract.get("canonical_origin") != ORIGIN:
        failures.append("canonical-target")
    if contract.get("deployment_state") != "unprovisioned":
        failures.append("deployment-state")
    if (budget.get("max_load_run"), budget.get("max_endurance_run"), budget.get("monthly_cap")) != (25, 50, 250):
        failures.append("budget-caps")
    if budget.get("enforce_before_apply") is not True:
        failures.append("budget-enforcement")
    if lifecycle.get("lease_ttl_hours") != 24 or lifecycle.get("idle_teardown_after_hours") != 2:
        failures.append("lease-or-idle-teardown")
    teardown = lifecycle.get("teardown", {})
    if teardown.get("manual_only") is not True or teardown.get("fail_closed") is not True:
        failures.append("teardown-boundary")
    cloudflare = contract.get("cloudflare", {})
    if cloudflare.get("zone_name") != "humangr.com":
        failures.append("zone-boundary")
    if cloudflare.get("route") != HOSTNAME or (
        cloudflare.get("root_worker"),
        cloudflare.get("signup_worker"),
        cloudflare.get("synthetic_receiver_worker"),
    ) != ("corelink-staging", "corelink-signup-staging", "corelink-synthetic-pager-staging"):
        failures.append("route-boundary")
    resource_names = contract.get("outputs", {}).get("resource_names", [])
    if not resource_names or any(not isinstance(name, str) or not name.endswith("-staging") for name in resource_names):
        failures.append("resource-isolation")
    return failures


def name_present(result: Any, expected: str, field: str) -> bool:
    items = result if isinstance(result, list) else result.get("result", []) if isinstance(result, dict) else []
    return any(isinstance(item, dict) and item.get(field) == expected for item in items)


def result_items(result: Any) -> list[dict[str, Any]]:
    items = result if isinstance(result, list) else result.get("result", []) if isinstance(result, dict) else []
    return [item for item in items if isinstance(item, dict)]


def canonical_dns_present(result: Any) -> bool:
    return any(item.get("name") == HOSTNAME for item in result_items(result))


def canonical_route_present(result: Any) -> bool:
    return any(
        item.get("pattern", "").split("/", 1)[0].lower() == HOSTNAME
        for item in result_items(result)
        if isinstance(item.get("pattern"), str)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=Path("infra/staging/topology.json"))
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    zone = os.environ.get("CF_ZONE_ID", "")
    if not token or not account or not zone:
        print("::error::Cloudflare account, token, or zone input is absent", file=sys.stderr)
        return 1
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    contract_failures = require_contract(contract)
    if contract_failures:
        print(f"::error::staging contract rejected: {', '.join(contract_failures)}", file=sys.stderr)
        return 1

    cloudflare = contract["cloudflare"]
    summary: dict[str, Any] = {
        "schema_version": 1,
        "receipt_type": "cloudflare_staging_read_only_plan",
        "issue": 1700,
        "target": ORIGIN,
        "scope": "staging-only",
        "mutation_performed": False,
        "budget": {"max_load_run_usd": 25, "max_endurance_run_usd": 50, "monthly_cap_usd": 250},
        "lifecycle": {"lease_ttl_hours": 24, "idle_teardown_after_hours": 2},
        "checks": {},
    }
    checks: dict[str, Any] = summary["checks"]

    def check(key: str, path: str, predicate: Any = None) -> bool:
        ok, result = provider_get(token, path)
        present = ok if predicate is None else ok and bool(predicate(result))
        checks[key] = {"ok": present}
        if not ok:
            checks[key]["error"] = result
        return present

    d1 = cloudflare["d1"][0]
    check("d1", f"accounts/{account}/d1/database/{d1['database_id']}")
    for resource in cloudflare["r2"]:
        encoded = urllib.parse.quote(resource["bucket_name"], safe="")
        check(f"r2:{resource['bucket_name']}", f"accounts/{account}/r2/buckets/{encoded}")
    for resource in cloudflare["kv"]:
        encoded = urllib.parse.quote(resource["namespace_title"], safe="")
        check(
            f"kv:{resource['namespace_title']}",
            f"accounts/{account}/storage/kv/namespaces?title={encoded}",
            lambda result, name=resource["namespace_title"]: name_present(result, name, "title"),
        )
    for resource in cloudflare["queues"]:
        for queue_name in (resource["queue_name"], resource["dead_letter_queue"]):
            encoded = urllib.parse.quote(queue_name, safe="")
            check(
                f"queue:{queue_name}",
                f"accounts/{account}/queues?name={encoded}",
                lambda result, name=queue_name: name_present(result, name, "queue_name"),
            )
    dns_query = urllib.parse.urlencode({"name": HOSTNAME})
    dns_ok, dns_result = provider_get(token, f"zones/{zone}/dns_records?{dns_query}")
    checks["dns-read"] = {"ok": dns_ok}
    if dns_ok:
        dns_present = canonical_dns_present(dns_result)
        checks["staging-dns"] = {
            "ok": not dns_present,
            "state": "present" if dns_present else "absent",
        }
    else:
        checks["dns-read"]["error"] = dns_result

    routes_ok, routes_result = provider_get(token, f"zones/{zone}/workers/routes")
    checks["worker-routes-read"] = {"ok": routes_ok}
    if routes_ok:
        # Cloudflare exposes routes only as a zone-wide list. This receipt
        # discards it and requires the canonical staging host to remain empty
        # until the separately reviewed bootstrap publishes its exact routes.
        route_present = canonical_route_present(routes_result)
        checks["staging-worker-route"] = {
            "ok": not route_present,
            "state": "present" if route_present else "absent",
        }
    else:
        checks["worker-routes-read"]["error"] = routes_result

    for worker in (cloudflare["root_worker"], cloudflare["signup_worker"], cloudflare["synthetic_receiver_worker"]):
        # /scripts/{name} downloads raw JavaScript. /settings is JSON and
        # proves existence without copying code into the runner or receipt.
        ok, result = provider_get(token, f"accounts/{account}/workers/scripts/{urllib.parse.quote(worker, safe='')}/settings")
        key = f"worker-settings:{worker}"
        if ok:
            checks[key] = {"ok": True, "state": "present"}
        elif "10007" in result.get("provider_error_codes", []):
            checks[key] = {"ok": True, "state": "absent"}
        else:
            checks[key] = {"ok": False, "error": result}

    failures = sorted(key for key, result in checks.items() if not result["ok"])
    summary["plan_state"] = "ready-for-reviewed-apply" if not failures else "blocked"
    summary["blocking_checks"] = failures
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        print(f"::error::staging plan failed closed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("staging plan succeeded; no provider mutation was performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
