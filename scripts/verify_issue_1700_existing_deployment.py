#!/usr/bin/env python3
"""Read-only proof for an already-active route-free staging deployment."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from . import staging_deployment_guard as staging_guard
    from .staging_deployment_guard import (
        DeploymentError,
        validate_route_receipt,
        validate_worker_settings,
    )
    from .verify_issue_1700_route_inventory import (
        InventoryError,
        verify_route_free,
    )
except ImportError:  # pragma: no cover - exercised by the script entry point
    import staging_deployment_guard as staging_guard
    from staging_deployment_guard import (
        DeploymentError,
        validate_route_receipt,
        validate_worker_settings,
    )
    from verify_issue_1700_route_inventory import (
        InventoryError,
        verify_route_free,
    )

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
WORKER_NAME = "corelink-staging"
DIAGNOSTICS_CONTRACT = "issue1700-candidate-runtime-diagnostics-v1"
DIAGNOSTICS_ERROR = "candidate runtime diagnostics input is malformed or exceeds limits"
DIAGNOSTICS_MAX_BYTES = 262144
DIAGNOSTICS_MAX_ITEMS = 256
# Fixed root topology names only; values and unknown binding names never leave capture.
DIAGNOSTICS_BINDINGS = frozenset("""
ENVIRONMENT R2_S3_ENDPOINT D1_DATABASE_ID SENTRY_RELEASE
R2_AC_BUCKET R2_AC_REGION R2_CAS_BUCKET R2_CAS_REGION R2_CHUNK_BUCKET R2_CHUNK_REGION
EDGE_PUBLIC_READ EDGE_ASYNC_METER EDGE_DO_METER OCI_PUBLIC_DEDUP_ENABLED
OCI_UPSTREAM_ON_MISS AUDIT_DRAIN_BATCH_LIMIT AUDIT_DRAIN_LEASE_ENABLED EDGE_FIND_MISSING
SYNTHETIC_DRILL_ENABLED SYNTHETIC_DRILL_PROVIDER_MODE CONFIG_DB CAS_BUCKET AC_BUCKET_IAD
CHUNK_BUCKET_IAD MANIFEST_BUCKET_IAD METADATA_KV CLERK_JWKS_KV NEGATIVE_CACHE_KV
CORELINK_SERVER ROLLOUT_DO EVENT_LOG_DO REPLICATION_COORDINATOR_DO
REQUEST_METER_COORDINATOR_DO REQUEST_METER_SHARD_DO DSR_QUEUE SCHEDULED_DRILL_DELIVERY
CLERK_ISSUER_URL CLERK_SECRET_KEY CLOUDFLARE_ACCOUNT_ID CORELINK_ADMIN_AUTH_KEY
CORELINK_ERASE_AUTH_KEY CORELINK_INTERNAL_AUTH_KEY PAT_SIGNING_KEY
R2_S3_ACCESS_KEY_ID R2_S3_SECRET_ACCESS_KEY
""".split())
DIAGNOSTICS_BINDING_TYPES = frozenset((
    "plain_text", "secret_text", "d1", "durable_object_namespace", "service",
    "r2_bucket", "kv_namespace", "queue", "other",
))


def _bound_diagnostics_input(payload: Any) -> None:
    remaining = 4096

    def visit(value: Any, depth: int = 0) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            raise DeploymentError(DIAGNOSTICS_ERROR)
        if isinstance(value, (dict, list)):
            if len(value) > DIAGNOSTICS_MAX_ITEMS:
                raise DeploymentError(DIAGNOSTICS_ERROR)
            if isinstance(value, dict):
                for key in value:
                    if not isinstance(key, str) or len(key) > 256:
                        raise DeploymentError(DIAGNOSTICS_ERROR)
            for item in value.values() if isinstance(value, dict) else value:
                visit(item, depth + 1)
        elif isinstance(value, str):
            if len(value) > 8192:
                raise DeploymentError(DIAGNOSTICS_ERROR)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DeploymentError(DIAGNOSTICS_ERROR)
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise DeploymentError(DIAGNOSTICS_ERROR)

    visit(payload)


def capture_candidate_diagnostics(
    version: Any, settings: Any, *, expected_version_id: str,
    expected_deployment_id: str, expected_sha: str, marker: str,
) -> dict[str, Any]:
    """Sanitize already-read evidence; observations do not grant runtime acceptance.

    Wrangler 4.145 versions view JSON is unwrapped, with resources.bindings an
    array (secret_text is filtered). Settings supplies a separate API result.
    False observation booleans imply absence only when their source is available.
    """
    if (
        not isinstance(expected_sha, str) or not SHA_RE.fullmatch(expected_sha)
        or not isinstance(expected_version_id, str) or not UUID_RE.fullmatch(expected_version_id)
        or not isinstance(expected_deployment_id, str) or not UUID_RE.fullmatch(expected_deployment_id)
        or not isinstance(marker, str)
        or not re.fullmatch(rf"issue-1700-route-free-[1-9][0-9]{{0,19}}-{expected_sha}", marker)
    ):
        raise DeploymentError(DIAGNOSTICS_ERROR)
    _bound_diagnostics_input(version)
    _bound_diagnostics_input(settings)

    def object_field(parent: dict, key: str) -> dict:
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise DeploymentError(DIAGNOSTICS_ERROR)
        return value

    def array_field(parent: dict, key: str) -> tuple[str, list]:
        value = parent.get(key)
        if value is None:
            return "unavailable", []
        if not isinstance(value, list):
            raise DeploymentError(DIAGNOSTICS_ERROR)
        return "available", value

    def strings(values: list) -> None:
        if any(not isinstance(value, str) for value in values):
            raise DeploymentError(DIAGNOSTICS_ERROR)

    if (
        not isinstance(version, dict) or not isinstance(version.get("id"), str)
        or not UUID_RE.fullmatch(version["id"])
        or not isinstance(settings, dict) or settings.get("success") is not True
        or settings.get("errors") not in (None, [])
        or settings.get("messages") not in (None, [])
        or not isinstance(settings.get("result"), dict)
    ):
        raise DeploymentError(DIAGNOSTICS_ERROR)
    resources = object_field(version, "resources")
    script = object_field(resources, "script")
    annotations = object_field(version, "annotations")
    if "workers/message" in annotations and not isinstance(annotations["workers/message"], str):
        raise DeploymentError(DIAGNOSTICS_ERROR)
    marker_status = "available" if "workers/message" in annotations else "unavailable"
    handlers_status, handlers = array_field(script, "handlers")
    named_status, named = array_field(script, "named_handlers")
    strings(handlers)
    names = set()
    for entry in named:
        if not isinstance(entry, dict):
            raise DeploymentError(DIAGNOSTICS_ERROR)
        _status, values = array_field(entry, "handlers")
        strings(values)
        if "name" not in entry:
            named_status = "unavailable"
            continue
        if not isinstance(entry["name"], str) or entry["name"] in names:
            raise DeploymentError(DIAGNOSTICS_ERROR)
        names.add(entry["name"])
    inventories, binding_sources, bindings_by_source = {}, {}, {}
    for source, payload in (("version", resources), ("settings", settings["result"])):
        status, bindings = array_field(payload, "bindings")
        indexed = {}
        for binding in bindings:
            if (
                not isinstance(binding, dict) or not isinstance(binding.get("name"), str)
                or not isinstance(binding.get("type"), str) or binding["name"] in indexed
                or (binding["type"] == "plain_text" and "text" in binding
                    and not isinstance(binding["text"], str))
            ):
                raise DeploymentError(DIAGNOSTICS_ERROR)
            indexed[binding["name"]] = binding
        binding_sources[source] = status
        bindings_by_source[source] = indexed
        inventories[source] = [
            {"name": name, "type": indexed[name]["type"]
             if indexed[name]["type"] in DIAGNOSTICS_BINDING_TYPES else "other"}
            for name in sorted(indexed.keys() & DIAGNOSTICS_BINDINGS)
        ]
    # Prefer version-bound values; settings is the fallback only when that whole
    # optional version field is unavailable. Never inspect secret values.
    source = "version" if binding_sources["version"] == "available" else "settings"
    effective = bindings_by_source[source]
    expected_values = {
        "ENVIRONMENT": "staging", "SENTRY_RELEASE": expected_sha,
        "D1_DATABASE_ID": "d72a6b39-6a48-4338-bfda-1111dda98604",
        "R2_S3_ENDPOINT": f"https://{ACCOUNT_ID}.r2.cloudflarestorage.com",
    }
    values_status = {
        name: ("unavailable" if name not in effective else
               "not_plain_text" if effective[name]["type"] != "plain_text" else
               "available" if "text" in effective[name] else "unavailable")
        for name in expected_values
    }
    return {
        "contract": DIAGNOSTICS_CONTRACT,
        "expected_version_id": expected_version_id,
        "expected_deployment_id": expected_deployment_id,
        "expected_sha": expected_sha,
        "identity_matches": version["id"] == expected_version_id,
        "exact_run_marker": annotations.get("workers/message") == marker,
        "sources": {
            "version": "unwrapped", "settings": "api_result",
            "run_marker": marker_status,
            "default_handlers": handlers_status, "named_exports": named_status,
            "bindings": binding_sources,
            "effective_variables": source if binding_sources[source] == "available" else "unavailable",
        },
        "default_handlers": {name: name in handlers for name in ("fetch", "scheduled", "queue")},
        "named_exports": {name: name in names for name in ("CoreLinkServer", "ContainerProxy", "StagingD1BindingProxy")},
        "bindings": inventories,
        "effective_variables_status": values_status,
        "effective_variables_match": {
            name: values_status[name] == "available" and effective[name].get("text") == value
            for name, value in expected_values.items()
        },
    }


def _read_diagnostics_json(path: Path) -> Any:
    try:
        with path.open("rb") as stream:
            raw = stream.read(DIAGNOSTICS_MAX_BYTES + 1)
        if len(raw) > DIAGNOSTICS_MAX_BYTES:
            raise DeploymentError(DIAGNOSTICS_ERROR)
        return json.loads(raw)
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        raise DeploymentError(DIAGNOSTICS_ERROR) from error


def _write_diagnostics_receipt(path: Path, receipt: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".candidate-diagnostics-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(receipt, sort_keys=True) + "\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise DeploymentError(f"{label} is malformed")
    return value


def validate_workflow_run(payload: Any, run_id: str, rollout_sha: str) -> None:
    if (
        not isinstance(payload, dict)
        or payload.get("id") != int(run_id)
        or payload.get("event") != "workflow_dispatch"
        or payload.get("status") != "completed"
        or payload.get("head_sha") != rollout_sha
    ):
        raise DeploymentError("original rollout workflow run identity is not exact")


def validate_rollout_log(
    text: str, run_id: str, rollout_sha: str, image_digest: str, version_id: str
) -> None:
    if not isinstance(text, str):
        raise DeploymentError("original rollout log is unreadable")
    marker = f"issue-1700-route-free-{run_id}-{rollout_sha}"
    if (
        not RUN_ID_RE.fullmatch(run_id)
        or not SHA_RE.fullmatch(rollout_sha)
        or not IMAGE_RE.fullmatch(image_digest)
        or not UUID_RE.fullmatch(version_id)
        or marker not in text
        or f"Current Version ID: {version_id}" not in text
    ):
        raise DeploymentError(
            "original rollout log does not bind the exact run and SHA"
        )
    # Wrangler's immutable job log repeats the digest in the rendered image URL.
    # Bind it only on the structured deployment-result line and require the
    # exact current-version result in the same original deploy step.
    step_prefix = "deploy\tDeploy root with container rollout and no route\t"
    step_lines = [line for line in text.splitlines() if line.startswith(step_prefix)]
    digest_lines = [
        line
        for line in step_lines
        if image_digest in line
        and re.search(r"\bdigest:\s*" + re.escape(image_digest) + r"(?:\s|$)", line)
    ]
    version_lines = [
        line for line in step_lines if f"Current Version ID: {version_id}" in line
    ]
    if (
        len(digest_lines) != 1
        or digest_lines[0].count(image_digest) != 1
        or len(version_lines) != 1
    ):
        raise DeploymentError(
            "original deploy step does not uniquely bind its version and image digest"
        )


def _read_preimage(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise DeploymentError("preimage receipt is malformed")
    preimage = payload.get("preimage", payload)
    if not isinstance(preimage, dict):
        raise DeploymentError("preimage receipt is malformed")
    return {
        "deployment_id": _require_uuid(
            preimage.get("deployment_id"), "preimage deployment ID"
        ),
        "version_id": _require_uuid(preimage.get("version_id"), "preimage version ID"),
    }


def select_candidate(deployments: Any, preimage_payload: Any) -> dict[str, str]:
    """Select only the latest full-traffic change; the full marker is checked later."""
    preimage = _read_preimage(preimage_payload)
    try:
        row, version_id = guard_latest(deployments)
    except DeploymentError:
        raise
    if (
        row.get("id") == preimage["deployment_id"]
        and version_id == preimage["version_id"]
    ):
        raise DeploymentError("no new active candidate deployment exists")
    if version_id == preimage["version_id"]:
        raise DeploymentError("active version changed without a new version ID")
    return {
        "deployment_id": _require_uuid(row.get("id"), "candidate deployment ID"),
        "version_id": version_id,
    }


def guard_latest(payload: Any) -> tuple[dict[str, Any], str]:
    # Reuse the original deploy guard's bounded, timestamp-based single-active check.
    return staging_guard._latest(payload)


def _require_full_marker(version: Any, version_id: str, marker: str) -> None:
    if not isinstance(version, dict) or version.get("id") != version_id:
        raise DeploymentError("full Worker Version readback has the wrong identity")
    annotations = version.get("annotations")
    if (
        not isinstance(annotations, dict)
        or annotations.get("workers/message") != marker
    ):
        raise DeploymentError("full Worker Version marker differs from this run")


def _truncated_list_marker_matches(list_payload: Any, marker: str) -> bool:
    try:
        row, _version_id = guard_latest(list_payload)
    except DeploymentError:
        return False
    annotations = row.get("annotations")
    message = (
        annotations.get("workers/message") if isinstance(annotations, dict) else None
    )
    if not isinstance(message, str):
        return False
    return message == marker or (
        message.endswith("...")
        and len(message) > 18
        and marker.startswith(message[:-3])
    )


def verify_candidate(
    deployments: Any,
    version: Any,
    preimage_payload: Any,
    marker: str,
    expected_deployment_id: str,
    expected_version_id: str,
) -> dict[str, str]:
    preimage = _read_preimage(preimage_payload)
    row, version_id = guard_latest(deployments)
    deployment_id = _require_uuid(row.get("id"), "active deployment ID")
    if (
        deployment_id == preimage["deployment_id"]
        or version_id == preimage["version_id"]
    ):
        raise DeploymentError("active deployment is still the preimage")
    if deployment_id != _require_uuid(
        expected_deployment_id, "selected deployment ID"
    ) or version_id != _require_uuid(expected_version_id, "selected version ID"):
        raise DeploymentError("active deployment changed after candidate selection")
    if not _truncated_list_marker_matches(deployments, marker):
        raise DeploymentError("deployment-list marker is unrelated to this run")
    _require_full_marker(version, version_id, marker)
    if not any(
        isinstance(item, dict)
        and item.get("id") == preimage["deployment_id"]
        and isinstance(item.get("versions"), list)
        and len(item["versions"]) == 1
        and isinstance(item["versions"][0], dict)
        and item["versions"][0].get("version_id") == preimage["version_id"]
        and item["versions"][0].get("percentage") == 100
        for item in deployments
    ):
        raise DeploymentError("exact active preimage is absent from deployment history")
    return {"deployment_id": deployment_id, "version_id": version_id}


def verify_rollback(
    deployments: Any,
    version: Any,
    preimage_payload: Any,
    routes: Any,
    marker: str,
) -> dict[str, Any]:
    preimage = _read_preimage(preimage_payload)
    row, version_id = guard_latest(deployments)
    deployment_id = _require_uuid(row.get("id"), "rollback deployment ID")
    if (
        deployment_id == preimage["deployment_id"]
        or version_id != preimage["version_id"]
    ):
        raise DeploymentError(
            "rollback did not restore the exact recorded preimage version"
        )
    if not isinstance(version, dict) or version.get("id") != preimage["version_id"]:
        raise DeploymentError("rollback version readback does not match the preimage")
    receipt = preimage_payload
    rollback = receipt.get("rollback") if isinstance(receipt, dict) else None
    candidate = receipt.get("candidate") if isinstance(receipt, dict) else None
    candidate_marker = candidate.get("marker") if isinstance(candidate, dict) else None
    expected_marker = (
        candidate_marker.replace(
            "issue-1700-route-free-", "issue-1700-route-free-rollback-", 1
        )
        if isinstance(candidate_marker, str)
        else None
    )
    if (
        marker != expected_marker
        or not isinstance(rollback, dict)
        or rollback.get("marker") != marker
        or rollback.get("target_version_id") != preimage["version_id"]
        or rollback.get("attempted") is not True
        or not _truncated_list_marker_matches(deployments, marker)
    ):
        raise DeploymentError("rollback readback is not attributable to this run")
    route_receipt = validate_route_receipt(routes)
    return {
        "deployment_id": deployment_id,
        "version_id": version_id,
        "marker": marker,
        "confirmed": True,
        "route_inventory": route_receipt,
    }


def validate_existing_deployment(
    deployments: Any,
    version: Any,
    settings: Any,
    topology: Any,
    routes: Any,
    workflow_run: Any,
    rollout_log: str,
    *,
    current_sha: str,
    rollout_sha: str,
    rollout_run_id: str,
    deployment_id: str,
    version_id: str,
    preimage_deployment_id: str,
    preimage_version_id: str,
    image_digest: str,
) -> dict[str, Any]:
    """Validate current provider readbacks against the immutable rollout run."""
    if not SHA_RE.fullmatch(current_sha) or not SHA_RE.fullmatch(rollout_sha):
        raise DeploymentError("workflow or rollout source SHA is malformed")
    if not RUN_ID_RE.fullmatch(rollout_run_id):
        raise DeploymentError("rollout run ID is malformed")
    deployment_id = _require_uuid(deployment_id, "active deployment ID")
    version_id = _require_uuid(version_id, "active version ID")
    preimage_deployment_id = _require_uuid(
        preimage_deployment_id, "preimage deployment ID"
    )
    preimage_version_id = _require_uuid(preimage_version_id, "preimage version ID")
    if deployment_id == preimage_deployment_id or version_id == preimage_version_id:
        raise DeploymentError("active rollout unexpectedly equals its preimage")

    if not isinstance(deployments, list) or not 2 <= len(deployments) <= 10:
        raise DeploymentError("deployment inventory is malformed or exceeds its bound")
    rows: list[dict[str, Any]] = []
    for row in deployments:
        if not isinstance(row, dict):
            raise DeploymentError("deployment inventory contains a malformed entry")
        row_id = _require_uuid(row.get("id"), "deployment inventory ID")
        versions = row.get("versions")
        if (
            not isinstance(versions, list)
            or len(versions) != 1
            or not isinstance(versions[0], dict)
            or type(versions[0].get("percentage")) is not int
            or versions[0]["percentage"] != 100
        ):
            raise DeploymentError(
                "deployment inventory contains split or invalid traffic"
            )
        row_version = _require_uuid(
            versions[0].get("version_id"), "deployment version ID"
        )
        created_on = row.get("created_on")
        if not isinstance(created_on, str):
            raise DeploymentError("deployment timestamp is malformed")
        rows.append({"id": row_id, "version_id": row_version, "created_on": created_on})
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise DeploymentError("deployment inventory contains duplicate IDs")
    try:
        timestamps = [
            datetime.fromisoformat(row["created_on"].replace("Z", "+00:00"))
            for row in rows
        ]
    except ValueError as error:
        raise DeploymentError("deployment timestamp is malformed") from error
    if any(timestamp.tzinfo is None for timestamp in timestamps):
        raise DeploymentError("deployment timestamp has no timezone")
    latest_timestamp = max(timestamps)
    latest = [
        row for row, timestamp in zip(rows, timestamps) if timestamp == latest_timestamp
    ]
    if len(latest) != 1:
        raise DeploymentError("latest deployment is ambiguous")
    active = latest[0]
    if active["id"] != deployment_id or active["version_id"] != version_id:
        raise DeploymentError("active deployment differs from the reviewed rollout")
    if not any(
        row["id"] == preimage_deployment_id
        and row["version_id"] == preimage_version_id
        and row["id"] != active["id"]
        for row in rows
    ):
        raise DeploymentError("recorded preimage is absent from deployment history")

    if not isinstance(version, dict) or version.get("id") != version_id:
        raise DeploymentError("active version readback has the wrong identity")
    expected_marker = f"issue-1700-route-free-{rollout_run_id}-{rollout_sha}"
    annotations = version.get("annotations")
    if (
        not isinstance(annotations, dict)
        or annotations.get("workers/message") != expected_marker
    ):
        raise DeploymentError("full active version marker differs from the rollout run")
    if not _truncated_list_marker_matches(deployments, expected_marker):
        raise DeploymentError(
            "deployment-list marker is unrelated to the rollout version"
        )
    resources = version.get("resources")
    runtime = resources.get("script_runtime") if isinstance(resources, dict) else None
    containers = runtime.get("containers") if isinstance(runtime, dict) else None
    if not isinstance(containers, list) or not containers:
        raise DeploymentError("active version has no Container runtime binding")
    settings_receipt = validate_worker_settings(settings, topology)
    if (
        not isinstance(runtime, dict)
        or runtime.get("compatibility_date") != settings_receipt["compatibility_date"]
        or not isinstance(runtime.get("compatibility_flags"), list)
        or set(runtime["compatibility_flags"])
        != set(settings_receipt["compatibility_flags"])
        or len(runtime["compatibility_flags"])
        != len(settings_receipt["compatibility_flags"])
    ):
        raise DeploymentError("active version and settings endpoint disagree")
    route_receipt = validate_route_receipt(routes)

    validate_workflow_run(workflow_run, rollout_run_id, rollout_sha)
    validate_rollout_log(
        rollout_log, rollout_run_id, rollout_sha, image_digest, version_id
    )

    return {
        "account_id": ACCOUNT_ID,
        "worker_name": WORKER_NAME,
        "verification_sha": current_sha,
        "rollout_sha": rollout_sha,
        "rollout_run_id": int(rollout_run_id),
        "deployment_id": deployment_id,
        "version_id": version_id,
        "preimage_deployment_id": preimage_deployment_id,
        "preimage_version_id": preimage_version_id,
        "container_image_digest": image_digest,
        **settings_receipt,
        **route_receipt,
        "verification": "existing-route-free-rollout",
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeploymentError(
            "verification evidence is unreadable or malformed"
        ) from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    diagnostics = commands.add_parser("capture-candidate-diagnostics")
    diagnostics.add_argument("--version", type=Path, required=True)
    diagnostics.add_argument("--settings", type=Path, required=True)
    diagnostics.add_argument("--expected-version-id", required=True)
    diagnostics.add_argument("--expected-deployment-id", required=True)
    diagnostics.add_argument("--expected-sha", required=True)
    diagnostics.add_argument("--marker", required=True)
    diagnostics.add_argument("--receipt", type=Path, required=True)
    select = commands.add_parser("select-candidate")
    select.add_argument("--deployments", type=Path, required=True)
    select.add_argument("--preimage", type=Path, required=True)
    select.add_argument("--output", type=Path, required=True)
    candidate = commands.add_parser("verify-candidate")
    candidate.add_argument("--deployments", type=Path, required=True)
    candidate.add_argument("--version", type=Path, required=True)
    candidate.add_argument("--preimage", type=Path, required=True)
    candidate.add_argument("--marker", required=True)
    candidate.add_argument("--expected-deployment-id", required=True)
    candidate.add_argument("--expected-version-id", required=True)
    candidate.add_argument("--rollback-marker")
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--receipt", type=Path, required=True)
    rollback = commands.add_parser("verify-rollback")
    rollback.add_argument("--deployments", type=Path, required=True)
    rollback.add_argument("--version", type=Path, required=True)
    rollback.add_argument("--preimage", type=Path, required=True)
    rollback.add_argument("--routes", type=Path, required=True)
    rollback.add_argument("--receipt", type=Path, required=True)
    rollback.add_argument("--marker", required=True)
    existing = commands.add_parser("verify-existing")
    existing.add_argument("--deployments", type=Path, required=True)
    existing.add_argument("--version", type=Path, required=True)
    existing.add_argument("--settings", type=Path, required=True)
    existing.add_argument("--topology", type=Path, required=True)
    existing.add_argument("--routes", type=Path)
    existing.add_argument("--workflow-run", type=Path, required=True)
    existing.add_argument("--rollout-log", type=Path, required=True)
    existing.add_argument("--receipt", type=Path, required=True)
    existing.add_argument("--current-sha", required=True)
    existing.add_argument("--rollout-sha", required=True)
    existing.add_argument("--rollout-run-id", required=True)
    existing.add_argument("--deployment-id", required=True)
    existing.add_argument("--version-id", required=True)
    existing.add_argument("--preimage-deployment-id", required=True)
    existing.add_argument("--preimage-version-id", required=True)
    existing.add_argument("--image-digest", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "capture-candidate-diagnostics":
            receipt = capture_candidate_diagnostics(
                _read_diagnostics_json(args.version),
                _read_diagnostics_json(args.settings),
                expected_version_id=args.expected_version_id,
                expected_deployment_id=args.expected_deployment_id,
                expected_sha=args.expected_sha,
                marker=args.marker,
            )
            _write_diagnostics_receipt(args.receipt, receipt)
        elif args.command == "select-candidate":
            result = select_candidate(
                _read_json(args.deployments), _read_json(args.preimage)
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("a", encoding="utf-8") as stream:
                stream.write(f"candidate_deployment_id={result['deployment_id']}\n")
                stream.write(f"candidate_version_id={result['version_id']}\n")
            receipt = result
        elif args.command == "verify-candidate":
            result = verify_candidate(
                _read_json(args.deployments),
                _read_json(args.version),
                _read_json(args.preimage),
                args.marker,
                args.expected_deployment_id,
                args.expected_version_id,
            )
            receipt_payload = _read_json(args.receipt)
            if not isinstance(receipt_payload, dict):
                raise DeploymentError("deployment receipt is malformed")
            receipt_payload["candidate"] = {**result, "marker": args.marker}
            if args.rollback_marker is not None:
                preimage_payload = _read_json(args.preimage)
                expected_rollback_marker = args.marker.replace(
                    "issue-1700-route-free-", "issue-1700-route-free-rollback-", 1
                )
                if args.rollback_marker != expected_rollback_marker:
                    raise DeploymentError(
                        "rollback marker does not match this candidate run"
                    )
                receipt_payload["rollback"] = {
                    "target_version_id": _read_preimage(preimage_payload)["version_id"],
                    "marker": args.rollback_marker,
                    "attempted": True,
                }
            args.receipt.write_text(json.dumps(receipt_payload, sort_keys=True) + "\n")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("a", encoding="utf-8") as stream:
                stream.write(f"candidate_deployment_id={result['deployment_id']}\n")
                stream.write(f"candidate_version_id={result['version_id']}\n")
            receipt = result
        elif args.command == "verify-rollback":
            receipt_payload = _read_json(args.receipt)
            if not isinstance(receipt_payload, dict):
                raise DeploymentError("deployment receipt is malformed")
            result = verify_rollback(
                _read_json(args.deployments),
                _read_json(args.version),
                receipt_payload,
                _read_json(args.routes),
                args.marker,
            )
            receipt_payload["rollback"] = {**receipt_payload["rollback"], **result}
            args.receipt.write_text(json.dumps(receipt_payload, sort_keys=True) + "\n")
            receipt = result
        else:
            rollout_log = args.rollout_log.read_text(encoding="utf-8")
            routes = (
                _read_json(args.routes)
                if args.routes is not None
                else verify_route_free(os.environ.get("CLOUDFLARE_API_TOKEN", ""))
            )
            receipt = validate_existing_deployment(
                _read_json(args.deployments),
                _read_json(args.version),
                _read_json(args.settings),
                _read_json(args.topology),
                routes,
                _read_json(args.workflow_run),
                rollout_log,
                current_sha=args.current_sha,
                rollout_sha=args.rollout_sha,
                rollout_run_id=args.rollout_run_id,
                deployment_id=args.deployment_id,
                version_id=args.version_id,
                preimage_deployment_id=args.preimage_deployment_id,
                preimage_version_id=args.preimage_version_id,
                image_digest=args.image_digest,
            )
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    except (DeploymentError, InventoryError, OSError) as error:
        if args.command == "capture-candidate-diagnostics":
            print(f"::error::{DIAGNOSTICS_ERROR}", file=sys.stderr)
            return 1
        print(
            f"::error::existing staging deployment verification rejected: {error}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
