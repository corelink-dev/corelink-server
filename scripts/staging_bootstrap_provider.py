#!/usr/bin/env python3
"""Read-only provider boundary checks for the #1700 staging bootstrap."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from scripts import render_staging_wrangler as renderer


def get(token: str, path: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        raise RuntimeError("Cloudflare staging readback failed") from error
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise RuntimeError("Cloudflare staging readback failed")
    return payload


def route_pairs(result: Any) -> set[tuple[str, str]]:
    items = result if isinstance(result, list) else []
    pairs: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        pattern = item.get("pattern")
        script = item.get("script")
        if isinstance(pattern, str) and pattern.split("/", 1)[0].lower() == renderer.CANONICAL_HOST:
            if not isinstance(script, str) or "prod" in script.lower():
                raise RuntimeError("canonical staging route has an unsafe Worker target")
            pairs.add((pattern, script))
    return pairs


def expected_worker_bindings(topology: renderer.StagingTopologyAdapter, worker: str) -> set[str]:
    settings = topology.settings_for(worker)
    names = set(settings.get("vars", {}))
    cloudflare = topology.cloudflare
    for family, name_key in (
        ("d1", "binding"),
        ("r2", "binding"),
        ("kv", "binding"),
        ("durable_objects", "binding"),
        ("service_bindings", "binding"),
    ):
        for entry in cloudflare.get(family, []):
            if family == "d1":
                bindings = entry.get("bindings", [])
                names.update(
                    item[name_key] for item in bindings if item.get("worker") == worker
                )
            elif entry.get("worker") == worker:
                names.add(entry[name_key])
    for queue in cloudflare.get("queues", []):
        if queue.get("consumer_worker") == worker:
            names.add(queue["producer_binding"])
    return names


def read_worker_bindings(
    topology: renderer.StagingTopologyAdapter,
    token: str,
    account: str,
    worker: str,
) -> None:
    encoded_worker = urllib.parse.quote(worker, safe="")
    payload = get(
        token,
        f"accounts/{urllib.parse.quote(account, safe='')}/workers/scripts/{encoded_worker}/settings",
    )
    result = payload.get("result")
    bindings = result.get("bindings") if isinstance(result, dict) else None
    if not isinstance(bindings, list):
        raise RuntimeError("staging Worker binding readback is unavailable")
    actual = {
        item.get("name")
        for item in bindings
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    expected = expected_worker_bindings(topology, worker)
    secret_names = set(topology.required_secret_names.get(worker, []))
    if not expected.issubset(actual) or actual - expected - secret_names:
        raise RuntimeError("staging Worker bindings do not match the typed topology")
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        name = binding.get("name")
        if isinstance(name, str) and ("prod" in name.lower() or "production" in name.lower()):
            raise RuntimeError("staging Worker binding has a production name")
        if name == "ENVIRONMENT" and binding.get("text") != "staging":
            raise RuntimeError("staging Worker environment readback is invalid")
        if name == "R2_S3_ENDPOINT" and binding.get("text") != os.environ.get("STAGING_R2_S3_ENDPOINT"):
            raise RuntimeError("staging R2 endpoint readback does not match the validated endpoint")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("preflight", "quarantine", "postflight"), required=True)
    args = parser.parse_args(argv)

    try:
        topology = renderer.StagingTopologyAdapter.from_file()
        # Exercise the same strict origin and R2 endpoint guards used to render
        # the Wrangler files before any provider mutation is permitted.
        if topology.canonical_origin != renderer.CANONICAL_ORIGIN:
            raise renderer.ContractError("canonical staging origin rejected")
        renderer._provider_endpoint(os.environ.get("STAGING_R2_S3_ENDPOINT", ""))
        token = os.environ.get("STAGING_CF_API_TOKEN", "")
        account = os.environ.get("STAGING_CF_ACCOUNT_ID", "")
        zone = os.environ.get("CF_ZONE_ID", "")
        if not token or not account or not zone:
            raise RuntimeError("required staging provider input names are absent")

        zone_result = get(token, f"zones/{urllib.parse.quote(zone, safe='')}").get("result")
        if not isinstance(zone_result, dict) or zone_result.get("name") != "humangr.com":
            raise RuntimeError("configured zone is not the canonical staging zone")
        zone_account = zone_result.get("account")
        if not isinstance(zone_account, dict) or zone_account.get("id") != account:
            raise RuntimeError("configured staging account does not own the canonical zone")

        routes = get(token, f"zones/{urllib.parse.quote(zone, safe='')}/workers/routes").get("result")
        actual = route_pairs(routes)
        workers = topology.workers
        expected = {
            (f"{renderer.CANONICAL_HOST}/*", workers[0]),
        }
        if args.phase in {"preflight", "quarantine"} and actual:
            raise RuntimeError("canonical staging route set must remain empty during quarantine")
        if args.phase == "postflight" and actual != expected:
            raise RuntimeError("provider route readback does not match the exact staging route set")

        script_result = get(
            token,
            f"accounts/{urllib.parse.quote(account, safe='')}/workers/scripts",
        ).get("result")
        script_items = script_result if isinstance(script_result, list) else []
        deployed = {
            item.get("id") or item.get("name")
            for item in script_items
            if isinstance(item, dict)
        }
        deployed_staging = deployed.intersection(workers)
        if args.phase == "preflight" and deployed_staging:
            raise RuntimeError("staging Worker names already exist; refusing to overwrite them")
        if args.phase in {"quarantine", "postflight"} and deployed_staging != set(workers):
            raise RuntimeError("provider Worker readback is missing a canonical staging Worker")
        if args.phase in {"quarantine", "postflight"}:
            for worker in workers:
                read_worker_bindings(topology, token, account, worker)

        print(json.dumps({
            "schema_version": 1,
            "phase": args.phase,
            "target": topology.canonical_origin,
            "scope": "staging-only",
            "worker_count": len(deployed_staging),
            "route_count": len(actual),
            "route_set": "empty" if not actual else "exact-canonical-staging-root",
            "provider_mutation_performed": False,
        }, sort_keys=True))
    except (OSError, TypeError, ValueError, RuntimeError, renderer.ContractError) as error:
        print(f"staging provider boundary rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
