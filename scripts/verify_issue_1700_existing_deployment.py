#!/usr/bin/env python3
"""Read-only proof for an already-active route-free staging deployment."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
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
        if args.command == "select-candidate":
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
        print(
            f"::error::existing staging deployment verification rejected: {error}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
