#!/usr/bin/env python3
"""Fail-closed state checks for the protected #1700 route-free deploy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
MAX_DEPLOYMENTS = 10
ROOT_WORKER = "corelink-staging"


class DeploymentError(ValueError):
    """Provider deployment state is malformed or cannot be safely attributed."""


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise DeploymentError(f"{label} is malformed")
    return value


def _deployment_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_DEPLOYMENTS:
        raise DeploymentError("deployment inventory is malformed or exceeds its bound")
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in payload:
        if not isinstance(row, dict):
            raise DeploymentError("deployment entry is malformed")
        deployment_id = _uuid(row.get("id"), "deployment id")
        if deployment_id in seen_ids:
            raise DeploymentError("deployment inventory contains duplicate ids")
        seen_ids.add(deployment_id)
        created_on = row.get("created_on")
        if not isinstance(created_on, str):
            raise DeploymentError("deployment timestamp is malformed")
        try:
            created = datetime.fromisoformat(created_on.replace("Z", "+00:00"))
        except ValueError as error:
            raise DeploymentError("deployment timestamp is malformed") from error
        if created.tzinfo is None:
            raise DeploymentError("deployment timestamp has no timezone")
        rows.append({**row, "_created": created})
    latest_time = max(row["_created"] for row in rows)
    latest = [row for row in rows if row["_created"] == latest_time]
    if len(latest) != 1:
        raise DeploymentError("latest deployment is ambiguous")
    return [latest[0]]


def _single_full_traffic_version(row: dict[str, Any]) -> str:
    versions = row.get("versions")
    if not isinstance(versions, list) or len(versions) != 1:
        raise DeploymentError("current deployment is split or malformed")
    version = versions[0]
    if not isinstance(version, dict) or type(version.get("percentage")) not in (
        int,
        float,
    ):
        raise DeploymentError("current deployment version is malformed")
    if version["percentage"] != 100:
        raise DeploymentError("current deployment does not serve exactly 100% traffic")
    return _uuid(version.get("version_id"), "Worker version id")


def _latest(payload: Any) -> tuple[dict[str, Any], str]:
    row = _deployment_rows(payload)[0]
    version_id = _single_full_traffic_version(row)
    return row, version_id


def capture_preimage(payload: Any) -> dict[str, str]:
    row, version_id = _latest(payload)
    return {
        "deployment_id": _uuid(row.get("id"), "deployment id"),
        "version_id": version_id,
        "created_on": row["created_on"],
    }


def classify_after_deploy(
    payload: Any, preimage: dict[str, str], marker: str
) -> tuple[str, str | None]:
    row, version_id = _latest(payload)
    if row.get("id") == preimage.get("deployment_id") and version_id == preimage.get(
        "version_id"
    ):
        return "unchanged", None
    annotations = row.get("annotations")
    if (
        not isinstance(annotations, dict)
        or annotations.get("workers/message") != marker
        or version_id == preimage.get("version_id")
    ):
        raise DeploymentError(
            "latest deployment is neither the preimage nor this run's exact candidate"
        )
    return "candidate", version_id


def require_candidate_current(
    payload: Any, candidate_version_id: str, marker: str
) -> None:
    row, version_id = _latest(payload)
    annotations = row.get("annotations")
    if (
        version_id != _uuid(candidate_version_id, "candidate version id")
        or not isinstance(annotations, dict)
        or annotations.get("workers/message") != marker
    ):
        raise DeploymentError(
            "refusing rollback because the current deployment is not this run's candidate"
        )


def require_rollback_current(
    payload: Any, preimage: dict[str, str], marker: str
) -> None:
    row, version_id = _latest(payload)
    annotations = row.get("annotations")
    if (
        version_id != _uuid(preimage.get("version_id"), "preimage version id")
        or row.get("id") == preimage.get("deployment_id")
        or not isinstance(annotations, dict)
        or annotations.get("workers/message") != marker
    ):
        raise DeploymentError(
            "rollback readback does not prove the exact preimage serves 100%"
        )


def validate_worker_settings(payload: Any, topology: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DeploymentError("Worker settings response is unsuccessful or malformed")
    if payload.get("errors") not in (None, []) or payload.get("messages") not in (
        None,
        [],
    ):
        raise DeploymentError("Worker settings response contains provider errors")
    try:
        expected = topology["cloudflare"]["root_worker_settings"]
        expected_flags = expected["compatibility_flags"]
        expected_date = expected["compatibility_date"]
    except (KeyError, TypeError) as error:
        raise DeploymentError(
            "root Worker compatibility contract is malformed"
        ) from error
    result = payload.get("result")
    actual_flags = (
        result.get("compatibility_flags") if isinstance(result, dict) else None
    )
    if (
        not isinstance(expected_flags, list)
        or any(not isinstance(flag, str) for flag in expected_flags)
        or not isinstance(actual_flags, list)
        or any(not isinstance(flag, str) for flag in actual_flags)
        or len(actual_flags) != len(expected_flags)
        or set(actual_flags) != set(expected_flags)
        or result.get("compatibility_date") != expected_date
    ):
        raise DeploymentError(
            "deployed Worker compatibility settings do not match staging"
        )
    return {
        "compatibility_date": expected_date,
        "compatibility_flags": sorted(expected_flags),
    }


def validate_route_receipt(payload: Any) -> dict[str, int]:
    if (
        not isinstance(payload, dict)
        or type(payload.get("route_count")) is not int
        or payload["route_count"] < 0
        or type(payload.get("canonical_staging_route_count")) is not int
        or payload["canonical_staging_route_count"] != 0
    ):
        raise DeploymentError(
            "route inventory receipt is malformed or has a host match"
        )
    return {
        "route_count": payload["route_count"],
        "canonical_staging_route_count": 0,
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeploymentError(
            "provider state file is unreadable or malformed"
        ) from error


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--deployments", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--receipt", type=Path, required=True)
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--deployments", type=Path, required=True)
    candidate.add_argument("--preimage", type=Path, required=True)
    candidate.add_argument("--marker", required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--receipt", type=Path, required=True)
    candidate_check = commands.add_parser("assert-candidate")
    candidate_check.add_argument("--deployments", type=Path, required=True)
    candidate_check.add_argument("--version-id", required=True)
    candidate_check.add_argument("--marker", required=True)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--deployments", type=Path, required=True)
    rollback.add_argument("--preimage", type=Path, required=True)
    rollback.add_argument("--candidate-version-id", required=True)
    rollback.add_argument("--candidate-marker", required=True)
    rollback.add_argument("--rollback-marker", required=True)
    rollback.add_argument("--receipt", type=Path, required=True)
    verify_rollback = commands.add_parser("verify-rollback")
    verify_rollback.add_argument("--deployments", type=Path, required=True)
    verify_rollback.add_argument("--preimage", type=Path, required=True)
    verify_rollback.add_argument("--marker", required=True)
    verify_rollback.add_argument("--routes", type=Path, required=True)
    verify_rollback.add_argument("--receipt", type=Path, required=True)
    verified = commands.add_parser("record-success")
    verified.add_argument("--response", type=Path, required=True)
    verified.add_argument("--topology", type=Path, required=True)
    verified.add_argument("--routes", type=Path, required=True)
    verified.add_argument("--receipt", type=Path, required=True)
    settings = commands.add_parser("settings")
    settings.add_argument("--response", type=Path, required=True)
    settings.add_argument("--topology", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "capture":
            preimage = capture_preimage(_read_json(args.deployments))
            _write_json(args.receipt, {"preimage": preimage})
            _output(
                args.output,
                {
                    "preimage_deployment_id": preimage["deployment_id"],
                    "preimage_version_id": preimage["version_id"],
                },
            )
        elif args.command == "candidate":
            receipt = _read_json(args.receipt)
            preimage = receipt.get("preimage") if isinstance(receipt, dict) else None
            if not isinstance(preimage, dict):
                raise DeploymentError("preimage receipt is malformed")
            state, version_id = classify_after_deploy(
                _read_json(args.deployments), preimage, args.marker
            )
            receipt.update({"rollout_state": state, "candidate_version_id": version_id})
            _write_json(args.receipt, receipt)
            _output(
                args.output,
                {
                    "rollout_state": state,
                    "candidate_version_id": version_id or "",
                },
            )
        elif args.command == "assert-candidate":
            require_candidate_current(
                _read_json(args.deployments), args.version_id, args.marker
            )
        elif args.command == "rollback":
            receipt = _read_json(args.receipt)
            preimage = receipt.get("preimage") if isinstance(receipt, dict) else None
            if not isinstance(preimage, dict):
                raise DeploymentError("preimage receipt is malformed")
            require_candidate_current(
                _read_json(args.deployments),
                args.candidate_version_id,
                args.candidate_marker,
            )
            receipt["rollback"] = {
                "target_version_id": preimage["version_id"],
                "marker": args.rollback_marker,
                "attempted": True,
            }
            _write_json(args.receipt, receipt)
        elif args.command == "verify-rollback":
            receipt = _read_json(args.receipt)
            preimage = receipt.get("preimage") if isinstance(receipt, dict) else None
            if not isinstance(preimage, dict):
                raise DeploymentError("preimage receipt is malformed")
            require_rollback_current(
                _read_json(args.deployments), preimage, args.marker
            )
            route_receipt = validate_route_receipt(_read_json(args.routes))
            rollback_receipt = receipt.get("rollback")
            if not isinstance(rollback_receipt, dict) or (
                rollback_receipt.get("marker") != args.marker
                or rollback_receipt.get("target_version_id")
                != preimage.get("version_id")
                or rollback_receipt.get("attempted") is not True
            ):
                raise DeploymentError("rollback intent receipt does not match readback")
            rollback_receipt["confirmed"] = True
            rollback_receipt["route_inventory"] = route_receipt
            _write_json(args.receipt, receipt)
        elif args.command == "record-success":
            receipt = _read_json(args.receipt)
            if not isinstance(receipt, dict):
                raise DeploymentError("deployment receipt is malformed")
            receipt["provider_postflight"] = {
                **validate_worker_settings(
                    _read_json(args.response), _read_json(args.topology)
                ),
                **validate_route_receipt(_read_json(args.routes)),
                "verified": True,
            }
            _write_json(args.receipt, receipt)
        elif args.command == "settings":
            result = validate_worker_settings(
                _read_json(args.response), _read_json(args.topology)
            )
            print(json.dumps(result, sort_keys=True))
    except (DeploymentError, KeyError, TypeError, ValueError) as error:
        print(f"staging deployment guard rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
