#!/usr/bin/env python3
"""Read-only provider boundary checks for the #1700 staging bootstrap."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from scripts import render_staging_wrangler as renderer
from scripts import staging_custom_domain as custom_domain
from scripts import staging_deployment_guard as staging_guard
from scripts.verify_issue_1700_route_inventory import (
    InventoryError,
    route_matches_canonical,
    validate_route_inventory,
)
from scripts.staging_deployment_guard import (
    DeploymentError,
    validate_worker_settings,
)


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


def route_pairs(result: Any) -> set[tuple[str, str | None]]:
    try:
        items = validate_route_inventory({"success": True, "result": result})
        matching: set[tuple[str, str | None]] = set()
        for item in items:
            if route_matches_canonical(item["pattern"]):
                script = item.get("script")
                if not isinstance(script, str) or "prod" in script.lower():
                    raise RuntimeError("canonical staging route has an unsafe Worker target")
                matching.add((item["pattern"], script))
        return matching
    except (InventoryError, TypeError) as error:
        raise RuntimeError("Worker Route inventory is malformed or incomplete") from error


def validate_postflight_custom_domain(
    inventory: tuple[Any, ...], account: str, zone: str
) -> dict[str, Any]:
    if len(inventory) != 7:
        raise RuntimeError("provider Custom Domain inventory is malformed")
    plan = custom_domain.assess_state(
        *inventory[:5], supplied_zone_id=zone, supplied_account_id=account
    )
    if plan["action"] != "already-exact":
        raise RuntimeError("provider Custom Domain readback is not exact and ready")
    custom_domain.validate_request_signal_settings(inventory[5])
    if custom_domain.runtime_binding_gaps(inventory[5], inventory[6]):
        raise RuntimeError("provider runtime secret names are incomplete")
    return plan


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
    if worker == "corelink-signup-staging":
        secret_names.update({"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"})
    if not expected.issubset(actual) or actual - expected - secret_names:
        raise RuntimeError("staging Worker bindings do not match the typed topology")
    b216_names = actual & {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
    if b216_names and (
        worker != "corelink-signup-staging"
        or b216_names != {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
    ):
        raise RuntimeError("B-216 alert bindings are outside the explicit signup-only scope")
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


def _b216_alert_secret_values(environment: dict[str, str], enabled: bool) -> dict[str, str]:
    """Validate and return B-216 secret values only under explicit opt-in."""
    endpoint_name = "STAGING_DSR_DLQ_ALERT_ENDPOINT"
    token_name = "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN"
    authorized_host_name = "STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST"
    endpoint = environment.get(endpoint_name, "")
    token = environment.get(token_name, "")
    authorized_host = environment.get(authorized_host_name, "")
    if not isinstance(endpoint, str) or not isinstance(token, str):
        raise RuntimeError("B-216 staging alert secret sources are malformed")
    if not enabled:
        if endpoint or token:
            raise RuntimeError("B-216 alert bindings require explicit protected opt-in")
        return {}
    if (
        not endpoint.strip()
        or not token.strip()
        or endpoint != endpoint.strip()
        or token != token.strip()
    ):
        raise RuntimeError("both B-216 staging alert secret sources are required")
    if any(char in token for char in "\r\n"):
        raise RuntimeError("B-216 staging alert bearer token is malformed")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        hostname = parsed.hostname or ""
        parsed.port  # Force malformed port syntax to fail closed.
        authorized = urllib.parse.urlsplit(f"//{authorized_host}")
        authorized_hostname = authorized.hostname or ""
        authorized_port = authorized.port
    except ValueError as error:
        raise RuntimeError("B-216 staging alert endpoint is invalid") from error
    try:
        ipaddress.ip_address(authorized_hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
    labels = authorized_hostname.split(".")
    if (
        not authorized_host
        or authorized_hostname != authorized_host
        or authorized_hostname != authorized_hostname.lower()
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        or is_ip_address
        or authorized_port is not None
        or authorized.username is not None
        or authorized.password is not None
        or authorized.path
        or authorized.query
        or authorized.fragment
        or authorized_hostname.endswith(".workers.dev")
        or authorized_hostname == "workers.dev"
        or parsed.scheme != "https"
        or hostname != authorized_hostname
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        raise RuntimeError("B-216 alert endpoint must match the owner-authorized HTTPS receiver root")
    return {
        "DSR_DLQ_ALERT_ENDPOINT": endpoint,
        "DSR_DLQ_ALERT_AUTH_TOKEN": token,
    }


def validate_b216_alert_authority(
    receipt_path: Path,
    receipt_sha256: str,
    owner_ack_ref: str,
    endpoint: str,
    sha: str,
    *,
    now: datetime | None = None,
) -> dict[str, str]:
    """Require a fresh exact receiver route readback and issue acknowledgement."""
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_sha256):
        raise RuntimeError("B-216 receiver authority receipt digest is malformed")
    if not re.fullmatch(
        r"https://github\.com/HuGR-dev/corelink-server/issues/1678#issuecomment-[1-9][0-9]*",
        owner_ack_ref,
    ):
        raise RuntimeError("B-216 owner acknowledgement reference is absent or malformed")
    raw = receipt_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != receipt_sha256:
        raise RuntimeError("B-216 receiver authority receipt digest does not match")
    try:
        receipt = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("B-216 receiver authority receipt is malformed") from error
    expected = {
        "repository": "HuGR-dev/corelink-server",
        "ref": "refs/heads/main",
        "sha": sha,
        "account_id": "51284495e71acdb5a7677e7383ab026b",
        "worker_name": "corelink-dsr-b216-alert-receiver-20260927",
        "status": "complete",
    }
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
        raise RuntimeError("B-216 receiver authority receipt target is not exact")
    worker = receipt.get("worker")
    if (
        not isinstance(worker, dict)
        or worker.get("exists") is not True
        or not isinstance(worker.get("inventory_count"), int)
        or worker["inventory_count"] < 1
    ):
        raise RuntimeError("B-216 receiver authority receipt Worker readback is incomplete")
    routes = receipt.get("routes")
    subdomain = receipt.get("subdomain")
    if (
        not isinstance(routes, dict)
        or routes.get("status") != "known"
        or not isinstance(routes.get("pattern_sha256"), list)
        or routes.get("count") != len(routes["pattern_sha256"])
        or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in routes["pattern_sha256"])
        or not isinstance(subdomain, dict)
        or subdomain.get("status") != "known"
        or subdomain.get("enabled") is not False
        or subdomain.get("previews_enabled") is not False
    ):
        raise RuntimeError("B-216 receiver authority readback does not prove a reachable custom route")
    try:
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        endpoint_host = parsed_endpoint.hostname or ""
        captured = datetime.fromisoformat(str(receipt.get("captured_at", "")).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise RuntimeError("B-216 receiver authority timestamp or endpoint is malformed") from error
    if captured.tzinfo is None:
        raise RuntimeError("B-216 receiver authority timestamp has no timezone")
    current = now or datetime.now(timezone.utc)
    age = (current - captured.astimezone(timezone.utc)).total_seconds()
    route_digest = hashlib.sha256(f"{endpoint_host}/*".encode("utf-8")).hexdigest()
    if age < -60 or age > 30 * 60 or route_digest not in routes["pattern_sha256"]:
        raise RuntimeError("B-216 receiver authority receipt is stale or does not match the endpoint host")
    return {
        "receipt_sha256": receipt_sha256,
        "owner_ack_ref": owner_ack_ref,
    }


def plan_missing_secret_values(
    secret_names: dict[str, set[str]],
    environment: dict[str, str],
    *,
    enable_b216_alert: bool = False,
) -> dict[str, dict[str, str]]:
    """Build a values-only plan for absent names; never overwrite a live secret."""
    workers = {
        "corelink-staging": {
            "CLERK_ISSUER_URL": "STAGING_CLERK_ISSUER_URL",
            "CLERK_SECRET_KEY": "STAGING_CLERK_SECRET_KEY",
            "CLOUDFLARE_ACCOUNT_ID": "STAGING_CF_ACCOUNT_ID",
            "R2_S3_ACCESS_KEY_ID": "STAGING_R2_S3_ACCESS_KEY_ID",
            "R2_S3_SECRET_ACCESS_KEY": "STAGING_R2_S3_SECRET_ACCESS_KEY",
        },
        "corelink-signup-staging": {
            "CLERK_SECRET_KEY": "STAGING_CLERK_SECRET_KEY",
            "CLERK_WEBHOOK_SECRET": "STAGING_CLERK_WEBHOOK_SECRET",
            "DSR_DLQ_REDRIVE_AUTH_KEY": "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY",
            "ERASURE_SALT_KEY": "STAGING_ERASURE_SALT_KEY",
        },
        "corelink-synthetic-pager-staging": {},
    }
    generated = {
        "corelink-staging": {"CORELINK_ADMIN_AUTH_KEY", "PAT_SIGNING_KEY"},
        "corelink-signup-staging": set(),
        "corelink-synthetic-pager-staging": set(),
    }
    required = {
        "corelink-staging": {
            "CLERK_ISSUER_URL", "CLERK_SECRET_KEY",
            "CLOUDFLARE_ACCOUNT_ID", "CORELINK_ADMIN_AUTH_KEY",
            "CORELINK_ERASE_AUTH_KEY", "CORELINK_INTERNAL_AUTH_KEY",
            "PAT_SIGNING_KEY", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
        },
        "corelink-signup-staging": {
            "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
            "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
        },
        "corelink-synthetic-pager-staging": set(),
    }
    if set(secret_names) != set(workers):
        raise RuntimeError("existing Worker secret inventory is incomplete")
    optional_b216 = {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
    if any(
        not isinstance(names, set)
        or names - required[worker] - (optional_b216 if worker == "corelink-signup-staging" else set())
        for worker, names in secret_names.items()
    ):
        raise RuntimeError("existing Worker secret inventory has unexpected names")
    for worker, names in secret_names.items():
        optional_b216 = {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
        allowed = required[worker] | (optional_b216 if worker == "corelink-signup-staging" else set())
        if not names.issubset(allowed):
            raise RuntimeError("existing Worker secret inventory is malformed")

    b216_values = _b216_alert_secret_values(environment, enable_b216_alert)
    b216_names = {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
    already_bound = secret_names["corelink-signup-staging"] & b216_names
    if already_bound and already_bound != b216_names:
        raise RuntimeError("existing B-216 alert secret-name pair is incomplete")

    # These credentials are shared between root and signup. If only one Worker
    # has a name already, the value cannot be copied or reconciled safely.
    plan: dict[str, dict[str, str]] = {worker: {} for worker in workers}
    for shared in ("CORELINK_INTERNAL_AUTH_KEY", "CORELINK_ERASE_AUTH_KEY"):
        present = [shared in secret_names[worker] for worker in workers if worker != "corelink-synthetic-pager-staging"]
        if len(set(present)) != 1:
            raise RuntimeError("shared staging secret is present on only one Worker")
        if not present[0]:
            value = secrets.token_hex(32)
            plan["corelink-staging"][shared] = value
            plan["corelink-signup-staging"][shared] = value

    for worker, names in workers.items():
        missing = required[worker] - secret_names[worker]
        for name in sorted(missing):
            if name in {"CORELINK_INTERNAL_AUTH_KEY", "CORELINK_ERASE_AUTH_KEY"}:
                continue
            if name in generated[worker]:
                plan[worker][name] = secrets.token_hex(32)
                continue
            source_name = names.get(name)
            value = environment.get(source_name, "") if source_name else ""
            if not isinstance(value, str) or not value.strip():
                raise RuntimeError(f"required staging secret source is absent: {source_name or name}")
            plan[worker][name] = value
    if enable_b216_alert and not already_bound:
        plan["corelink-signup-staging"].update(b216_values)
    return plan


def validate_existing_worker_inventory(
    topology: renderer.StagingTopologyAdapter,
    worker_token: str,
    account: str,
) -> None:
    if tuple(topology.workers) != (
        "corelink-staging",
        "corelink-signup-staging",
        "corelink-synthetic-pager-staging",
    ):
        raise RuntimeError("staging Worker target set differs from the frozen three-Worker set")
    topology_json = json.loads(Path("infra/staging/topology.json").read_text(encoding="utf-8"))
    for worker in topology.workers:
        encoded = urllib.parse.quote(worker, safe="")
        settings = get(
            worker_token,
            f"accounts/{urllib.parse.quote(account, safe='')}/workers/scripts/{encoded}/settings",
        )
        read_worker_bindings(topology, worker_token, account, worker)
        if worker == "corelink-staging":
            try:
                validate_worker_settings(settings, topology_json)
            except DeploymentError as error:
                raise RuntimeError("root Worker compatibility settings do not match staging") from error


def _worker_path(account: str, worker: str, resource: str) -> str:
    return (
        f"accounts/{urllib.parse.quote(account, safe='')}/workers/scripts/"
        f"{urllib.parse.quote(worker, safe='')}/{resource}"
    )


def _wrangler_environment(token: str) -> dict[str, str]:
    """Give Wrangler only process basics and its scoped provider credential."""
    allowed = ("PATH", "HOME", "CI", "COREPACK_HOME", "PNPM_HOME")
    environment = {name: os.environ[name] for name in allowed if os.environ.get(name)}
    environment["CLOUDFLARE_API_TOKEN"] = token
    return environment


def _deploy_exact_version(
    token: str, config: Path, worker: str, version: str, marker: str
) -> None:
    result = subprocess.run(
        [
            "pnpm", "exec", "wrangler", "versions", "deploy", f"{version}@100%",
            "--name", worker, "--message", marker, "--yes", "--config", str(config),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_wrangler_environment(token),
    )
    if result.returncode != 0:
        raise RuntimeError("exact staging Worker version deployment failed")


def _deployment_state(token: str, account: str, worker: str) -> tuple[dict[str, Any], str]:
    payload = get(token, _worker_path(account, worker, "deployments"))
    try:
        return staging_guard._latest(payload.get("result"))
    except (DeploymentError, AttributeError, TypeError) as error:
        raise RuntimeError("Worker deployment preimage is incomplete or ambiguous") from error


def _secret_names(token: str, account: str, worker: str) -> set[str]:
    payload = get(token, _worker_path(account, worker, "secrets"))
    rows = payload.get("result")
    if not isinstance(rows, list) or len(rows) > 64:
        raise RuntimeError("Worker secret-name inventory is incomplete or unbounded")
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
            raise RuntimeError("Worker secret-name inventory is malformed")
        if row["name"] in names:
            raise RuntimeError("Worker secret-name inventory contains duplicates")
        names.add(row["name"])
    return names


def _version_for_marker(token: str, account: str, worker: str, marker: str, prior: str) -> str:
    payload = get(token, _worker_path(account, worker, "versions"))
    rows = payload.get("result")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10:
        raise RuntimeError("new Worker version inventory is incomplete or unbounded")
    matches = [
        item.get("id")
        for item in rows
        if isinstance(item, dict)
        and isinstance(item.get("annotations"), dict)
        and item["annotations"].get("workers/message") == marker
    ]
    if len(matches) != 1 or not isinstance(matches[0], str) or matches[0] == prior:
        raise RuntimeError("staged Worker secret version is not uniquely attributable")
    return matches[0]


def _active_exact_marker(
    token: str, account: str, worker: str, marker: str, expected_version: str | None = None
) -> tuple[str, str] | None:
    row, version_id = _deployment_state(token, account, worker)
    annotations = row.get("annotations")
    if (
        not isinstance(annotations, dict)
        or annotations.get("workers/message") != marker
        or (expected_version is not None and version_id != expected_version)
    ):
        return None
    return row["id"], version_id


def apply_existing_secret_updates(
    config_dir: Path,
    receipt_path: Path,
    run_id: str,
    sha: str,
    *,
    enable_b216_alert: bool = False,
    authority_receipt_path: Path | None = None,
    authority_receipt_sha256: str = "",
    owner_ack_ref: str = "",
) -> dict[str, Any]:
    """Add only missing secrets to existing Workers with versioned rollback."""
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("protected staging operation identity is malformed")
    worker_token = os.environ.get("STAGING_CF_WORKER_API_TOKEN", "")
    route_token = os.environ.get("STAGING_CF_ROUTE_READ_TOKEN", "")
    account = os.environ.get("STAGING_CF_ACCOUNT_ID", "")
    zone = os.environ.get("CF_ZONE_ID", "")
    if not all((worker_token, route_token, account, zone)):
        raise RuntimeError("required staging-scoped provider input names are absent")
    b216_values = _b216_alert_secret_values(dict(os.environ), enable_b216_alert)
    authority = {}
    if enable_b216_alert:
        if authority_receipt_path is None:
            raise RuntimeError("B-216 receiver authority readback is required before opt-in")
        authority = validate_b216_alert_authority(
            authority_receipt_path,
            authority_receipt_sha256,
            owner_ack_ref,
            b216_values["DSR_DLQ_ALERT_ENDPOINT"],
            sha,
        )
    topology = renderer.StagingTopologyAdapter.from_file()
    renderer._provider_endpoint(os.environ.get("STAGING_R2_S3_ENDPOINT", ""))
    if account != custom_domain.ACCOUNT_ID or zone != custom_domain.ZONE_ID:
        raise RuntimeError("protected staging account or zone differs from the frozen target")

    zone_payload = get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}").get("result")
    if (
        not isinstance(zone_payload, dict)
        or zone_payload.get("name") != "humangr.com"
        or not isinstance(zone_payload.get("account"), dict)
        or zone_payload["account"].get("id") != account
    ):
        raise RuntimeError("read-only route token does not prove the canonical staging zone")
    route_rows = get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}/workers/routes").get("result")
    routes = route_pairs(route_rows)
    if routes:
        raise RuntimeError("canonical staging route set must remain empty")
    validate_existing_worker_inventory(topology, worker_token, account)

    names = {worker: _secret_names(worker_token, account, worker) for worker in topology.workers}
    expected_names = {worker: set(topology.required_secret_names.get(worker, [])) for worker in topology.workers}
    existing_alert_pair = names["corelink-signup-staging"] & {
        "DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"
    }
    if enable_b216_alert or existing_alert_pair:
        expected_names["corelink-signup-staging"].update(
            {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
        )
    if any(names[worker] - expected_names[worker] for worker in topology.workers):
        raise RuntimeError("existing Worker has an unapproved staging secret name")
    environment = dict(os.environ)
    plans = plan_missing_secret_values(
        names, environment, enable_b216_alert=enable_b216_alert
    )
    preimages: dict[str, dict[str, str]] = {}
    for worker in topology.workers:
        row, version = _deployment_state(worker_token, account, worker)
        preimages[worker] = {
            "deployment_id": row["id"],
            "version_id": version,
        }

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "operation": "update-existing-secrets",
        "run_id": run_id,
        "sha": sha,
        "target": "staging-only",
        "b216_dsr_alert_opt_in": enable_b216_alert,
        "b216_authority_receipt_sha256": authority.get("receipt_sha256"),
        "b216_owner_ack_ref": authority.get("owner_ack_ref"),
        "route_count": len(route_rows),
        "canonical_staging_route_count": 0,
        "preimages": preimages,
        "workers": {},
        "staging": {"unknown_workers": []},
        "rollback": {
            "attempted": False,
            "confirmed_workers": [],
            "unknown_active_workers": [],
        },
        "provider_mutation_performed": False,
    }
    staged: dict[str, str] = {}
    activated: list[str] = []
    unknown_active_workers: set[str] = set()
    unknown_staged_workers: set[str] = set()
    staging_in_flight_worker: str | None = None
    staging_upload_confirmed = False
    temp_paths: list[Path] = []
    try:
        for worker in topology.workers:
            plan = plans[worker]
            if not plan:
                receipt["workers"][worker] = {"changed": False, "secret_names": sorted(names[worker])}
                continue
            config = config_dir / f"{worker}.toml"
            if not config.is_file():
                raise RuntimeError("rendered Worker config is missing")
            marker = f"issue-1700-secrets-{run_id}-{sha}-{worker}"
            file_descriptor, file_name = tempfile.mkstemp(prefix="issue-1700-secrets-", dir=config_dir)
            os.close(file_descriptor)
            secret_file = Path(file_name)
            temp_paths.append(secret_file)
            secret_file.chmod(0o600)
            secret_file.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
            receipt["workers"][worker] = {
                "changed": True,
                "status": "secret-upload-outcome-unknown",
                "marker": marker,
            }
            staging_in_flight_worker = worker
            staging_upload_confirmed = False
            receipt["provider_mutation_performed"] = "unknown"
            completed = subprocess.run(
                [
                    "pnpm", "exec", "wrangler", "versions", "secret", "bulk",
                    str(secret_file), "--name", worker, "--message", marker,
                    "--config", str(config),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=_wrangler_environment(worker_token),
            )
            if completed.returncode != 0:
                raise RuntimeError("staging secret version upload failed")
            staging_upload_confirmed = True
            receipt["provider_mutation_performed"] = True
            receipt["workers"][worker]["status"] = "staged-version-readback-pending"
            try:
                candidate = _version_for_marker(
                    worker_token, account, worker, marker, preimages[worker]["version_id"]
                )
            except Exception:
                unknown_staged_workers.add(worker)
                raise
            staged[worker] = candidate
            staging_in_flight_worker = None
            receipt["workers"][worker] = {
                "changed": True,
                "status": "staged-inactive",
                "secret_names": sorted(names[worker] | set(plan)),
                "candidate_version_id": candidate,
                "marker": marker,
            }

        # No Worker has received traffic on its staged candidate until every
        # missing source has been validated and every candidate version exists.
        for worker in topology.workers:
            candidate = staged.get(worker)
            if candidate is None:
                continue
            marker = receipt["workers"][worker]["marker"]
            current_row, current_version = _deployment_state(worker_token, account, worker)
            if current_row["id"] != preimages[worker]["deployment_id"] or current_version != preimages[worker]["version_id"]:
                raise RuntimeError("Worker changed after preflight; refusing candidate activation")
            _deploy_exact_version(
                worker_token, config_dir / f"{worker}.toml", worker, candidate, marker
            )
            activated.append(worker)
            active = _active_exact_marker(worker_token, account, worker, marker, candidate)
            if active is None:
                raise RuntimeError("Worker candidate readback is not exact")
            receipt["workers"][worker]["deployment_id"] = active[0]

        routes_after = route_pairs(
            get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}/workers/routes").get("result")
        )
        if routes_after:
            raise RuntimeError("canonical staging route appeared during secret update")
        for worker in topology.workers:
            final_names = _secret_names(worker_token, account, worker)
            if final_names != expected_names[worker]:
                raise RuntimeError("Worker secret-name postflight differs from the exact topology")
        validate_existing_worker_inventory(topology, worker_token, account)
        receipt["provider_mutation_performed"] = bool(staged)
        receipt["postflight"] = "passed"
    except Exception as error:
        if staging_in_flight_worker is not None:
            unknown_staged_workers.add(staging_in_flight_worker)
            if not staging_upload_confirmed:
                receipt["provider_mutation_performed"] = "unknown"
        if unknown_staged_workers:
            receipt["staging"]["unknown_workers"] = sorted(unknown_staged_workers)
            receipt["rollback"]["requires_operator_intervention"] = True
        # A transport error can follow a successful provider commit. Discover
        # every run-marked active candidate before considering rollback.
        for worker, candidate in staged.items():
            marker = receipt["workers"][worker]["marker"]
            try:
                current_row, current_version = _deployment_state(worker_token, account, worker)
            except Exception:
                receipt["postflight"] = "failed-unknown-active-state"
                unknown_active_workers.add(worker)
                continue
            if current_row.get("id") == preimages[worker]["deployment_id"] and current_version == preimages[worker]["version_id"]:
                continue
            annotations = current_row.get("annotations")
            if (
                current_version == candidate
                and isinstance(annotations, dict)
                and annotations.get("workers/message") == marker
            ):
                if worker not in activated:
                    activated.append(worker)
            else:
                receipt["postflight"] = "failed-unknown-active-state"
                unknown_active_workers.add(worker)
                receipt["rollback"]["blocked_worker"] = worker
        if unknown_active_workers:
            receipt["rollback"]["unknown_active_workers"] = sorted(unknown_active_workers)
            receipt["rollback"]["requires_operator_intervention"] = True
        if activated:
            receipt["rollback"]["attempted"] = True
            for worker in reversed(activated):
                candidate = staged[worker]
                marker = receipt["workers"][worker]["marker"]
                try:
                    if _active_exact_marker(worker_token, account, worker, marker, candidate) is None:
                        receipt["rollback"]["blocked_worker"] = worker
                        unknown_active_workers.add(worker)
                        receipt["rollback"]["unknown_active_workers"] = sorted(unknown_active_workers)
                        receipt["rollback"]["requires_operator_intervention"] = True
                        receipt["postflight"] = "failed-unknown-active-state"
                        break
                    rollback_marker = f"issue-1700-secrets-rollback-{run_id}-{sha}-{worker}"
                    _deploy_exact_version(
                        worker_token,
                        config_dir / f"{worker}.toml",
                        worker,
                        preimages[worker]["version_id"],
                        rollback_marker,
                    )
                    row, active_version = _deployment_state(worker_token, account, worker)
                except Exception:
                    receipt["rollback"]["blocked_worker"] = worker
                    unknown_active_workers.add(worker)
                    receipt["rollback"]["unknown_active_workers"] = sorted(unknown_active_workers)
                    receipt["rollback"]["requires_operator_intervention"] = True
                    receipt["rollback"]["status"] = "failed-rollback-unverified"
                    receipt["postflight"] = "failed-unknown-active-state"
                    break
                if (
                    row.get("id") == preimages[worker]["deployment_id"]
                    or active_version != preimages[worker]["version_id"]
                    or not isinstance(row.get("annotations"), dict)
                    or row["annotations"].get("workers/message") != rollback_marker
                ):
                    receipt["rollback"]["blocked_worker"] = worker
                    unknown_active_workers.add(worker)
                    receipt["rollback"]["unknown_active_workers"] = sorted(unknown_active_workers)
                    receipt["rollback"]["requires_operator_intervention"] = True
                    receipt["rollback"]["status"] = "failed-rollback-unverified"
                    receipt["postflight"] = "failed-unknown-active-state"
                    break
                receipt["rollback"]["confirmed_workers"].append(worker)
            else:
                if unknown_active_workers:
                    receipt["postflight"] = "failed-unknown-active-state"
                else:
                    receipt["postflight"] = "failed-rolled-back"
            if "blocked_worker" not in receipt["rollback"]:
                try:
                    rollback_routes = route_pairs(
                        get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}/workers/routes").get("result")
                    )
                    if rollback_routes:
                        receipt["rollback"]["route_guard"] = "failed"
                        receipt["postflight"] = "failed-rollback-unverified"
                    else:
                        receipt["rollback"]["route_guard"] = "passed"
                except Exception:
                    receipt["rollback"]["route_guard"] = "unavailable"
                    receipt["postflight"] = "failed-rollback-unverified"
        else:
            if unknown_active_workers:
                receipt["postflight"] = "failed-unknown-active-state"
            elif unknown_staged_workers:
                receipt["postflight"] = "failed-staged-version-unknown"
            else:
                receipt["postflight"] = "failed-before-activation"
        receipt["error"] = str(error) if isinstance(error, RuntimeError) else "staging update failed"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        raise RuntimeError("staging existing-secret update did not pass; inspect redacted receipt") from error
    finally:
        for path in temp_paths:
            try:
                path.write_bytes(b"\0" * path.stat().st_size)
                path.unlink()
            except OSError:
                pass
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def plan_existing_secret_names(
    topology: renderer.StagingTopologyAdapter,
    secret_names: dict[str, set[str]],
) -> dict[str, dict[str, list[str]]]:
    """Name-only update-existing-secrets delta; never reads or emits values.

    Every state the protected apply path could not reconcile without guessing
    is refused here as well, so a passing plan never hides an ambiguity.
    """
    workers = tuple(topology.workers)
    if workers != (
        "corelink-staging",
        "corelink-signup-staging",
        "corelink-synthetic-pager-staging",
    ):
        raise RuntimeError("staging Worker target set differs from the frozen three-Worker set")
    if set(secret_names) != set(workers):
        raise RuntimeError("existing Worker secret inventory is incomplete")
    b216_names = {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
    plan: dict[str, dict[str, list[str]]] = {}
    for worker in workers:
        names = secret_names[worker]
        if not isinstance(names, set) or any(not isinstance(name, str) for name in names):
            raise RuntimeError("existing Worker secret inventory is malformed")
        required = set(topology.required_secret_names.get(worker, []))
        allowed = required | (b216_names if worker == "corelink-signup-staging" else set())
        if names - allowed:
            raise RuntimeError(f"existing Worker {worker} has an unapproved staging secret name")
        plan[worker] = {
            "secret_names": sorted(names),
            "missing_secret_names": sorted(required - names),
        }
    alert_pair = secret_names["corelink-signup-staging"] & b216_names
    if alert_pair and alert_pair != b216_names:
        raise RuntimeError("existing B-216 alert secret-name pair is incomplete")
    for shared in ("CORELINK_INTERNAL_AUTH_KEY", "CORELINK_ERASE_AUTH_KEY"):
        if (shared in secret_names["corelink-staging"]) != (
            shared in secret_names["corelink-signup-staging"]
        ):
            raise RuntimeError("shared staging secret is present on only one Worker")
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=(
            "preflight", "quarantine", "postflight",
            "update-existing-preflight", "update-existing-postflight",
            "update-existing-apply",
        ),
        required=True,
    )
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--sha")
    parser.add_argument("--b216-authority-receipt", type=Path)
    parser.add_argument("--b216-authority-sha256", default="")
    parser.add_argument("--b216-owner-ack-ref", default="")
    parser.add_argument(
        "--enable-b216-dsr-alert",
        action="store_true",
        help="explicitly bind the approved fixed B-216 alert receiver to staging signup",
    )
    parser.add_argument(
        "--existing-worker-plan",
        action="store_true",
        help=(
            "read-only preflight only: when every canonical staging Worker already "
            "exists, emit a name-only update-existing-secrets plan instead of refusing"
        ),
    )
    args = parser.parse_args(argv)
    if args.existing_worker_plan and args.phase != "preflight":
        parser.error("--existing-worker-plan is valid only with --phase preflight")

    if args.phase == "update-existing-apply":
        if not all((args.config_dir, args.receipt, args.run_id, args.sha)):
            parser.error("update-existing-apply requires --config-dir, --receipt, --run-id, and --sha")
        try:
            receipt = apply_existing_secret_updates(
                args.config_dir, args.receipt, args.run_id, args.sha,
                enable_b216_alert=args.enable_b216_dsr_alert,
                authority_receipt_path=args.b216_authority_receipt,
                authority_receipt_sha256=args.b216_authority_sha256,
                owner_ack_ref=args.b216_owner_ack_ref,
            )
            print(json.dumps(receipt, sort_keys=True))
            return 0
        except (OSError, TypeError, ValueError, RuntimeError, renderer.ContractError) as error:
            print(f"staging existing-secret update rejected: {error}", file=sys.stderr)
            return 1

    try:
        topology = renderer.StagingTopologyAdapter.from_file()
        # Exercise the same strict origin and R2 endpoint guards used to render
        # the Wrangler files before any provider mutation is permitted.
        if topology.canonical_origin != renderer.CANONICAL_ORIGIN:
            raise renderer.ContractError("canonical staging origin rejected")
        renderer._provider_endpoint(os.environ.get("STAGING_R2_S3_ENDPOINT", ""))
        update_existing = args.phase.startswith("update-existing-")
        route_token = os.environ.get(
            "STAGING_CF_ROUTE_READ_TOKEN" if update_existing else "STAGING_CF_API_TOKEN", ""
        )
        worker_token = os.environ.get("STAGING_CF_WORKER_API_TOKEN", "") if update_existing else route_token
        account = os.environ.get("STAGING_CF_ACCOUNT_ID", "")
        zone = os.environ.get("CF_ZONE_ID", "")
        if not route_token or not account or not zone or (update_existing and not worker_token):
            raise RuntimeError("required staging provider input names are absent")

        zone_result = get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}").get("result")
        if not isinstance(zone_result, dict) or zone_result.get("name") != "humangr.com":
            raise RuntimeError("configured zone is not the canonical staging zone")
        zone_account = zone_result.get("account")
        if not isinstance(zone_account, dict) or zone_account.get("id") != account:
            raise RuntimeError("configured staging account does not own the canonical zone")

        routes = get(route_token, f"zones/{urllib.parse.quote(zone, safe='')}/workers/routes").get("result")
        actual = route_pairs(routes)
        workers = topology.workers
        token = route_token
        if actual:
            raise RuntimeError("canonical staging route set must remain empty during quarantine")
        if args.phase == "postflight":
            inventory = custom_domain._inventory(token, account, zone)
            validate_postflight_custom_domain(inventory, account, zone)

        existing_plan: dict[str, dict[str, list[str]]] | None = None
        if update_existing:
            validate_existing_worker_inventory(topology, worker_token, account)
            deployed_staging = set(workers)
        else:
            script_result = get(
                token,
                f"accounts/{urllib.parse.quote(account, safe='')}/workers/scripts",
            ).get("result")
            # A malformed listing is not proof that no Worker exists.
            if not isinstance(script_result, list) or any(
                not isinstance(item, dict)
                or not isinstance(item.get("id") or item.get("name"), str)
                for item in script_result
            ):
                raise RuntimeError("Worker script inventory is malformed")
            deployed = {item.get("id") or item.get("name") for item in script_result}
            deployed_staging = deployed.intersection(workers)
            if args.phase == "preflight" and deployed_staging:
                if not args.existing_worker_plan:
                    raise RuntimeError("staging Worker names already exist; refusing to overwrite them")
                if deployed_staging != set(workers):
                    raise RuntimeError(
                        "staging Worker set is only partially present; refusing an ambiguous existing-Worker plan"
                    )
                existing_plan = plan_existing_secret_names(
                    topology,
                    {worker: _secret_names(token, account, worker) for worker in workers},
                )
            if args.phase in {"quarantine", "postflight"} and deployed_staging != set(workers):
                raise RuntimeError("provider Worker readback is missing a canonical staging Worker")
            if args.phase in {"quarantine", "postflight"}:
                for worker in workers:
                    read_worker_bindings(topology, token, account, worker)

        receipt: dict[str, Any] = {
            "schema_version": 1,
            "phase": args.phase,
            "target": topology.canonical_origin,
            "scope": "staging-only",
            "worker_count": len(deployed_staging),
            "route_count": len(actual),
            "route_set": "empty" if not actual else "canonical-staging-conflict",
            "custom_domain_count": len(inventory[2]["result"]) if args.phase == "postflight" else 0,
            "provider_mutation_performed": False,
        }
        if args.existing_worker_plan:
            receipt["existing_workers"] = "all-present" if existing_plan is not None else "absent"
            receipt["next_operation"] = (
                "update-existing-secrets" if existing_plan is not None else "quarantine-apply"
            )
            receipt["secret_values_read"] = False
            if existing_plan is not None:
                receipt["update_existing_secrets_plan"] = existing_plan
        print(json.dumps(receipt, sort_keys=True))
    except (OSError, TypeError, ValueError, RuntimeError, renderer.ContractError) as error:
        print(f"staging provider boundary rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
