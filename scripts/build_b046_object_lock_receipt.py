#!/usr/bin/env python3
"""Build the redacted, target-bound receipt for the protected B-046 proof."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Mapping


SCHEMA = "corelink.b046.s3-object-lock-protected-proof.v2"
EXPECTED_REPOSITORY_ID = "1232040291"
EXPECTED_REPOSITORY = "HuGR-dev/corelink-server"
MAX_COST_USD_MICROS = 5_000_000
EXPECTED_BUCKET_PREFIX = "corelink-object-lock-probe-b046"
DIGEST_SUMMARY = re.compile(r"^([0-9]+)/([0-9]+) digest files valid$")
LOG_SUMMARY = re.compile(r"^([0-9]+)/([0-9]+) log files valid$")


class ReceiptError(ValueError):
    """Protected proof inputs do not establish the approved target contract."""


def _required(values: Mapping[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value or value != value.strip() or "\n" in value or "\r" in value:
        raise ReceiptError(f"required proof input {key} is missing or malformed")
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptError("retention expiry is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ReceiptError("retention expiry must be timezone-aware UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def validate_digest_output(output: str) -> None:
    """Require nonempty, fully valid CloudTrail digest and log summaries."""
    if re.search(r"\bINVALID\b", output, re.IGNORECASE):
        raise ReceiptError("CloudTrail validation output contains an invalid file")
    summaries = [line.strip() for line in output.splitlines()]
    for expression, label in ((DIGEST_SUMMARY, "digest"), (LOG_SUMMARY, "log")):
        matches = [match for line in summaries if (match := expression.fullmatch(line))]
        if len(matches) != 1:
            raise ReceiptError(f"CloudTrail validation output must contain one {label} summary")
        valid, total = (int(part) for part in matches[0].groups())
        if total < 1 or valid != total:
            raise ReceiptError(f"CloudTrail {label} files are missing or not all valid")


def build_receipt(
    values: Mapping[str, str], *, digest_validation_output: str,
    reconciliation: Mapping[str, object],
) -> dict[str, object]:
    validate_digest_output(digest_validation_output)
    repository = _required(values, "GITHUB_REPOSITORY")
    repository_id = _required(values, "GITHUB_REPOSITORY_ID")
    if repository != EXPECTED_REPOSITORY or repository_id != EXPECTED_REPOSITORY_ID:
        raise ReceiptError("proof must come from the canonical protected repository")

    run_id = _required(values, "B046_SOURCE_RUN_ID")
    attempt = _required(values, "B046_SOURCE_ATTEMPT")
    commit = _required(values, "B046_SOURCE_SHA")
    if not run_id.isdigit() or not attempt.isdigit() or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReceiptError("workflow run identity is malformed")
    if int(run_id) < 1 or int(attempt) < 1:
        raise ReceiptError("source run identity is malformed")
    if _required(values, "B046_CHECKED_OUT_SHA") != _required(values, "GITHUB_SHA"):
        raise ReceiptError("reconciliation verifier SHA does not match its checkout")
    reconcile_run_id = _required(values, "GITHUB_RUN_ID")
    reconcile_attempt = _required(values, "GITHUB_RUN_ATTEMPT")
    reconcile_sha = _required(values, "GITHUB_SHA")
    if (
        not reconcile_run_id.isdigit() or not reconcile_attempt.isdigit()
        or int(reconcile_run_id) <= int(run_id) or int(reconcile_attempt) < 1
        or not re.fullmatch(r"[0-9a-f]{40}", reconcile_sha)
    ):
        raise ReceiptError("reconciliation workflow run identity is malformed or not later than source")
    server_url = _required(values, "GITHUB_SERVER_URL")
    if server_url != "https://github.com":
        raise ReceiptError("proof workflow server is not canonical GitHub")
    workflow_url = f"{server_url}/{repository}/actions/runs/{run_id}"

    configured_account = _required(values, "AWS_ACCOUNT_ID")
    actual_account = _required(values, "B046_ACTUAL_ACCOUNT_ID")
    region = _required(values, "AWS_REGION")
    actual_region = _required(values, "B046_ACTUAL_REGION")
    if not re.fullmatch(r"[0-9]{12}", configured_account) or actual_account != configured_account:
        raise ReceiptError("observed account does not match the approved account")
    if actual_region != region or not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]+", region):
        raise ReceiptError("observed region does not match the approved region")

    bucket_prefix = _required(values, "AWS_BUCKET_PREFIX")
    if bucket_prefix != EXPECTED_BUCKET_PREFIX:
        raise ReceiptError("probe bucket prefix is not the fixed B-046 synthetic prefix")
    bucket = _required(values, "B046_BUCKET")
    expected_bucket = f"{bucket_prefix}-{run_id}-{attempt}"
    key = f"audit/probe-{run_id}/synthetic.txt"
    if bucket != expected_bucket or len(bucket) > 63:
        raise ReceiptError("probe bucket does not match the approved run-bound prefix")
    if _required(values, "B046_KEY") != key:
        raise ReceiptError("probe object key does not match the expected synthetic key")

    cost_text = _required(values, "COST_CEILING_USD_MICROS")
    if not re.fullmatch(r"[1-9][0-9]*", cost_text):
        raise ReceiptError("approved cost ceiling is malformed")
    cost_ceiling = int(cost_text)
    if cost_ceiling > MAX_COST_USD_MICROS:
        raise ReceiptError("approved cost ceiling exceeds the repository limit")

    expected_reconciliation = {
        "put_event_id", "put_request_id", "delete_event_id", "delete_request_id",
        "put_event_time", "delete_event_time",
        "validated_log_sha256", "put_validated_log_uri_sha256",
        "delete_validated_log_uri_sha256", "events_share_validated_log",
        "validated_log_uri_sha256",
    }
    if set(reconciliation) != expected_reconciliation:
        raise ReceiptError("trail reconciliation has unexpected or missing fields")
    for field in ("put_event_id", "put_request_id", "delete_event_id", "delete_request_id"):
        if not isinstance(reconciliation.get(field), str) or not reconciliation[field]:
            raise ReceiptError(f"trail reconciliation is missing {field}")
    try:
        put_time = dt.datetime.fromisoformat(str(reconciliation["put_event_time"]).replace("Z", "+00:00"))
        delete_time = dt.datetime.fromisoformat(str(reconciliation["delete_event_time"]).replace("Z", "+00:00"))
        expiry_time = dt.datetime.fromisoformat(_utc_timestamp(_required(values, "B046_RETAIN_UNTIL")).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ReceiptError("trail reconciliation event times are malformed") from exc
    if any(value.tzinfo is None or value.utcoffset() != dt.timedelta(0) for value in (put_time, delete_time, expiry_time)):
        raise ReceiptError("trail event and retention times must be UTC")
    if put_time > delete_time or delete_time >= expiry_time:
        raise ReceiptError("denied DeleteObject is not after PutObject and before expiry")
    for field in ("validated_log_sha256", "validated_log_uri_sha256"):
        hashes = reconciliation.get(field)
        if not isinstance(hashes, list) or not hashes or not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes
        ):
            raise ReceiptError(f"trail reconciliation has invalid {field}")
    approved_uri_hashes = reconciliation["validated_log_uri_sha256"]
    for field in ("put_validated_log_uri_sha256", "delete_validated_log_uri_sha256"):
        value = reconciliation.get(field)
        if not isinstance(value, str) or value not in approved_uri_hashes:
            raise ReceiptError(f"{field} does not refer to a validator-approved log URI")

    receipt: dict[str, object] = {
        "schema_version": 2,
        "schema": SCHEMA,
        "workflow_url": workflow_url,
        "source_probe": {
            "workflow_url": workflow_url,
            "run_id": run_id,
            "run_attempt": attempt,
            "commit": commit,
        },
        "reconciliation": {
            "workflow_url": f"{server_url}/{repository}/actions/runs/{reconcile_run_id}",
            "run_id": reconcile_run_id,
            "run_attempt": reconcile_attempt,
            "commit": reconcile_sha,
        },
        "commit": commit,
        "run_id": run_id,
        "run_attempt": attempt,
        "repository_id": repository_id,
        "technical_scope": "root-authorized-synthetic-prelaunch-only",
        "target": {
            "account_id_sha256": _sha256(actual_account),
            "region": region,
            "bucket_name_sha256": _sha256(bucket),
            "object_key_sha256": _sha256(key),
            "object_version_sha256": _sha256(_required(values, "B046_VERSION")),
            "probe_role_arn_sha256": _sha256(_required(values, "AWS_ROLE_ARN")),
            "workload_writer_role_arn_sha256": _sha256(_required(values, "AWS_WRITER_ROLE_ARN")),
            "region_matches_configured_target": True,
        },
        "bucket": {
            "versioning_enabled": True,
            "object_lock_enabled": True,
            "default_retention_mode": "COMPLIANCE",
            "default_retention_days": 1,
        },
        "object": {
            "put_request_id": reconciliation["put_request_id"],
            "delete_request_id": reconciliation["delete_request_id"],
            "put_event_time": put_time.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "delete_event_time": delete_time.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "put_data_event_id": reconciliation["put_event_id"],
            "delete_denial_data_event_id": reconciliation["delete_event_id"],
            "put_validated_log_uri_sha256": reconciliation["put_validated_log_uri_sha256"],
            "delete_validated_log_uri_sha256": reconciliation["delete_validated_log_uri_sha256"],
            "retention_mode": "COMPLIANCE",
            "retain_until": _utc_timestamp(_required(values, "B046_RETAIN_UNTIL")),
            "legal_hold": "ON",
        },
        "delete_control": {
            "action": "s3:DeleteObjectVersion",
            "effective_permission": "iam_simulated_allow",
            "scope_note": "simulation is not proof against unmodeled organization/resource policy context",
            "same_version_pre_expiry_denied": True,
        },
        "cloudtrail_digest_validation": "passed",
        "cloudtrail_digest_output_sha256": _sha256(digest_validation_output),
        "cloudtrail_trail_arn_sha256": _sha256(_required(values, "AWS_TRAIL_ARN")),
        "cloudtrail_log_bucket_sha256": _sha256(_required(values, "AWS_LOG_BUCKET")),
        "cloudtrail_log_prefix_sha256": _sha256(_required(values, "AWS_LOG_PREFIX")),
        "probe_window_start": _required(values, "B046_PROBE_WINDOW_START"),
        "cloudtrail_validated_log_uri_sha256": sorted(approved_uri_hashes),
        "cloudtrail_validated_log_content_sha256": sorted(reconciliation["validated_log_sha256"]),
        "cost_ceiling_usd_micros": cost_ceiling,
        "cost_owner": _required(values, "COST_OWNER"),
        "cleanup_owner": _required(values, "CLEANUP_OWNER"),
        "cleanup_due": "after_retention_and_legal_hold_release",
        "synthetic_only": True,
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest-validation-output", type=Path, required=True)
    parser.add_argument("--reconciliation-output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.is_symlink() or (args.output.exists() and not args.output.is_file()):
        raise SystemExit("receipt output must be a regular non-symlink file")
    try:
        digest_output = args.digest_validation_output.read_text(encoding="utf-8")
        reconciliation = json.loads(args.reconciliation_output.read_text(encoding="utf-8"))
        if not isinstance(reconciliation, dict):
            raise ReceiptError("trail reconciliation output must be an object")
        receipt = build_receipt(
            os.environ, digest_validation_output=digest_output,
            reconciliation=reconciliation,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ReceiptError) as exc:
        raise SystemExit(f"B-046 proof receipt refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
