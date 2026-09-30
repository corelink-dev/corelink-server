#!/usr/bin/env python3
"""Validate three source-backed KMS custody lifecycle receipts offline.

Inputs are the protected manifest, mode-0600 receipts emitted by
issue_2165_kms_custodian.py, the raw CloudTrail LookupEvents response, and the
STS caller identity captured in the same custodian-role session. This program
never calls a provider and never treats a local digest as a provider event ID.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from issue_2165_kms_runtime import ContractError, validate_manifest

RUN_ID = re.compile(r"^[0-9]{1,36}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
EVENT_ID = re.compile(r"^[A-Za-z0-9-]{8,128}$")
ROLE_SESSION = re.compile(r"^arn:aws:sts::([0-9]{12}):assumed-role/([^/]+)/([^/]+)$")
RECEIPT_SCHEMA = "corelink.issue-2165-kms-custodian-receipt-v1"
REQUIRED_STAGES = ("rotate", "schedule", "cancel", "grant")


class CustodianReceiptError(ValueError):
    """Custody evidence is missing, inconsistent, or not provider-backed."""


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise CustodianReceiptError(f"{field} must be an ISO-8601 UTC timestamp")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CustodianReceiptError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if when.tzinfo is None or when.utcoffset().total_seconds() != 0:
        raise CustodianReceiptError(f"{field} must be UTC")
    return when.astimezone(timezone.utc)


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _read_private_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CustodianReceiptError(f"{label} must be a mode-0600 regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CustodianReceiptError(f"{label} must be readable JSON") from exc


def _receipt(folder: Path, stage: str, run_id: str) -> dict[str, Any]:
    paths = {
        "rotate": folder / "key-rotate" / "custodian-rotate-receipt.json",
        "schedule": folder / "key-schedule" / "custodian-schedule-receipt.json",
        "cancel": folder / "key-cancel" / "custodian-cancel-receipt.json",
        "grant": folder / "initial-grant" / "custodian-grant-receipt.json",
    }
    body = _read_private_json(paths[stage], f"{stage} custodian helper receipt")
    if not isinstance(body, dict) or body.get("schema") != RECEIPT_SCHEMA or body.get("stage") != stage or body.get("run_id") != run_id:
        raise CustodianReceiptError(f"{stage} helper receipt has wrong schema, stage, or run")
    observed = _timestamp(body.get("observed_at_utc"), f"{stage} receipt observed_at_utc")
    actions = body.get("actions")
    if not isinstance(actions, list) or not all(isinstance(action, dict) for action in actions):
        raise CustodianReceiptError(f"{stage} helper receipt must contain an action list")
    if body.get("receipt_sha256") != _canonical_digest({"stage": stage, "run_id": run_id, "actions": actions}):
        raise CustodianReceiptError(f"{stage} helper receipt digest does not match its emitted action summary")
    expected = {
        "rotate": ("rotate-key-on-demand", {"completed", "in-progress"}),
        "schedule": ("schedule-key-deletion", {"PendingDeletion"}),
        "cancel": ("cancel-key-deletion", {"Enabled"}),
        "grant": ("create-grant", {"exact"}),
    }
    operation, readbacks = expected[stage]
    if stage == "cancel":
        if (len(actions) != 2
                or actions[0].get("operation") != "cancel-key-deletion"
                or actions[0].get("key_arn") is None
                or actions[0].get("readback") != "Disabled"
                or actions[1].get("operation") != "enable-key"
                or actions[1].get("key_arn") != actions[0].get("key_arn")
                or actions[1].get("readback") != "Enabled"):
            raise CustodianReceiptError("cancel receipt must prove exact-key CancelKeyDeletion Disabled then EnableKey Enabled")
    elif len(actions) != 1 or actions[0].get("operation") != operation or actions[0].get("readback") not in readbacks:
        raise CustodianReceiptError(f"{stage} helper receipt lacks the exact successful provider readback")
    action = actions[0]
    if stage == "grant" and (set(action.get("operations", [])) != {"Encrypt", "Decrypt", "DescribeKey"} or not isinstance(action.get("grant_id"), str)):
        raise CustodianReceiptError("grant receipt must name the exact grant with only Encrypt, Decrypt, and DescribeKey")
    return {"body": body, "action": action, "observed_at": observed, "digest": body["receipt_sha256"]}


def _event_rows(cloudtrail: Any, manifest: dict[str, Any], caller: Any, run_id: str, start: datetime, end: datetime, now: datetime) -> list[dict[str, Any]]:
    aws = manifest["aws"]
    caller_arn = caller.get("Arn") if isinstance(caller, dict) else None
    caller_account = caller.get("Account") if isinstance(caller, dict) else None
    match = ROLE_SESSION.fullmatch(caller_arn or "")
    if caller_account != aws["account_id"] or not match or match.group(1) != aws["account_id"] or match.group(2) != aws["custodian_role_arn"].rsplit("/", 1)[-1] or match.group(3) != f"i2165-custodian-{run_id}":
        raise CustodianReceiptError("STS caller must be the exact custodian role and this run's session")
    if not isinstance(cloudtrail, dict) or not isinstance(cloudtrail.get("Events"), list):
        raise CustodianReceiptError("CloudTrail input must be the raw LookupEvents Events array")
    normalized = []
    seen_ids: set[str] = set()
    for outer in cloudtrail["Events"]:
        if not isinstance(outer, dict):
            raise CustodianReceiptError("CloudTrail event entries must be objects")
        raw = outer.get("CloudTrailEvent")
        if not isinstance(raw, str):
            raise CustodianReceiptError("CloudTrail LookupEvents event lacks nested event JSON")
        try:
            inner = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CustodianReceiptError("CloudTrail nested event JSON is invalid") from exc
        if not isinstance(inner, dict):
            raise CustodianReceiptError("CloudTrail nested event must be an object")
        event_id, name = outer.get("EventId"), outer.get("EventName")
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id) or event_id in seen_ids:
            raise CustodianReceiptError("CloudTrail provider EventIds must be valid and unique")
        seen_ids.add(event_id)
        when = _timestamp(outer.get("EventTime"), "LookupEvents EventTime")
        nested_when = _timestamp(inner.get("eventTime"), "nested CloudTrail eventTime")
        if inner.get("eventID") != event_id or inner.get("eventName") != name or nested_when != when:
            raise CustodianReceiptError("CloudTrail outer and nested event identity/time disagree")
        if outer.get("EventSource") != "kms.amazonaws.com" or inner.get("eventSource") != "kms.amazonaws.com" or inner.get("awsRegion") != aws["region"] or inner.get("recipientAccountId") != aws["account_id"]:
            continue
        if not start <= when <= end or when > now:
            continue
        identity = inner.get("userIdentity")
        session = identity.get("sessionContext") if isinstance(identity, dict) else None
        issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
        actor = ROLE_SESSION.fullmatch(identity.get("arn", "")) if isinstance(identity, dict) else None
        if (not isinstance(identity, dict) or identity.get("type") != "AssumedRole" or identity.get("accountId") != aws["account_id"]
                or not isinstance(issuer, dict) or issuer.get("arn") != aws["custodian_role_arn"]
                or not actor or actor.group(1) != aws["account_id"] or actor.group(2) != aws["custodian_role_arn"].rsplit("/", 1)[-1]
                or actor.group(3) != f"i2165-custodian-{run_id}"):
            continue
        params = inner.get("requestParameters")
        if not isinstance(params, dict):
            continue
        requested_key = params.get("keyId")
        if requested_key not in (aws["cmk_arn"], aws["cmk_arn"].split("/key/")[-1]):
            continue
        normalized.append({"event_id": event_id, "event_name": name, "time": when, "inner": inner, "params": params})
    return normalized


def _one(events: list[dict[str, Any]], name: str, predicate=lambda event: True) -> dict[str, Any]:
    found = [event for event in events if event["event_name"] == name and predicate(event)]
    if len(found) != 1:
        raise CustodianReceiptError(f"expected exactly one authenticated {name} event for the protected key and run")
    return found[0]


def build_receipts(manifest: dict[str, Any], env: dict[str, str], receipt_dir: Path, cloudtrail: Any, caller: Any, *, customer_key_readback: Any, now: datetime | None = None) -> list[dict[str, Any]]:
    """Return exactly the three source-backed custody lifecycle rows."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    run_id = env.get("GITHUB_RUN_ID", "")
    if not RUN_ID.fullmatch(run_id):
        raise CustodianReceiptError("GITHUB_RUN_ID must be an exact numeric workflow run id")
    try:
        validate_manifest(manifest, now=current, environ=env)
    except ContractError as exc:
        raise CustodianReceiptError("protected target manifest failed validation") from exc
    authority = manifest.get("custodian_authority")
    authority_ref = authority.get("ref") if isinstance(authority, dict) else None
    if (not isinstance(authority_ref, str) or not authority_ref.startswith("restricted://")
            or authority_ref != env.get("B083_CUSTODIAN_REF")
            or authority.get("cmk_arn") != manifest["aws"]["cmk_arn"]
            or authority.get("custodian_role_arn") != manifest["aws"]["custodian_role_arn"]):
        raise CustodianReceiptError("restricted custodian authority must bind the exact CMK and role")
    key_readback = customer_key_readback.get("KeyMetadata") if isinstance(customer_key_readback, dict) else None
    if (not isinstance(key_readback, dict) or key_readback.get("Arn") != manifest["aws"]["cmk_arn"]
            or key_readback.get("AWSAccountId") != manifest["aws"]["account_id"]
            or key_readback.get("KeyManager") != "CUSTOMER" or key_readback.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or key_readback.get("KeySpec") != "SYMMETRIC_DEFAULT" or key_readback.get("KeyState") != "Enabled"):
        raise CustodianReceiptError("mode-0600 CMK DescribeKey readback must prove the exact customer-managed Enabled key")
    window = manifest.get("lifecycle_window")
    if not isinstance(window, dict) or type(window.get("started_at_ms")) is not int or type(window.get("ended_at_ms")) is not int:
        raise CustodianReceiptError("protected lifecycle_window is required")
    start = datetime.fromtimestamp(window["started_at_ms"] / 1000, timezone.utc)
    end = datetime.fromtimestamp(window["ended_at_ms"] / 1000, timezone.utc)
    if start >= end or end - start > timedelta(hours=1) or not start <= current <= end:
        raise CustodianReceiptError("custodian receipt collection must run inside the bounded lifecycle window")
    receipts = {stage: _receipt(receipt_dir, stage, run_id) for stage in REQUIRED_STAGES}
    for stage, receipt in receipts.items():
        if not start <= receipt["observed_at"] <= end or receipt["observed_at"] > current:
            raise CustodianReceiptError(f"{stage} helper receipt time is outside the current protected lifecycle window")
    events = _event_rows(cloudtrail, manifest, caller, run_id, start, end, current)
    key_arn = manifest["aws"]["cmk_arn"]

    def key_metadata(event: dict[str, Any]) -> dict[str, Any]:
        response = event["inner"].get("responseElements")
        metadata = response.get("keyMetadata") if isinstance(response, dict) else None
        if not isinstance(metadata, dict):
            metadata = response.get("KeyMetadata") if isinstance(response, dict) else None
        return metadata if isinstance(metadata, dict) else {}

    rotate_call = _one(events, "RotateKeyOnDemand")
    rotate_statuses = [e for e in events if e["event_name"] == "GetKeyRotationStatus" and e["time"] > rotate_call["time"]]
    rotate_status = _one(rotate_statuses, "GetKeyRotationStatus", lambda e: (e["inner"].get("responseElements") or {}).get("keyRotationEnabled") is True)
    if rotate_status["time"] > receipts["rotate"]["observed_at"]:
        # The helper file is written after both provider readbacks.
        raise CustodianReceiptError("rotation CloudTrail status must precede its helper receipt")

    schedule = _one(events, "ScheduleKeyDeletion")
    cancel = _one(events, "CancelKeyDeletion", lambda e: e["time"] > schedule["time"])
    enable = _one(events, "EnableKey", lambda e: e["time"] > cancel["time"])
    post_cancel_describes = [e for e in events if e["event_name"] == "DescribeKey" and e["time"] > enable["time"]]
    enabled_readbacks = [e for e in post_cancel_describes if key_metadata(e).get("keyState", key_metadata(e).get("KeyState")) == "Enabled"]
    if not enabled_readbacks:
        raise CustodianReceiptError("EnableKey must be followed by an authenticated exact-key Enabled DescribeKey readback")
    restored = min(enabled_readbacks, key=lambda event: (event["time"], event["event_id"]))
    if (schedule["time"] > receipts["schedule"]["observed_at"]
            or receipts["schedule"]["observed_at"] >= cancel["time"]
            or cancel["time"] > enable["time"]
            or enable["time"] > restored["time"]
            or receipts["cancel"]["observed_at"] < restored["time"]):
        raise CustodianReceiptError("deletion schedule receipt must precede cancellation receipt")
    cancel_actions = receipts["cancel"]["body"]["actions"]
    if (cancel_actions[0].get("key_arn") != key_arn or cancel_actions[1].get("key_arn") != key_arn
            or receipts["cancel"]["action"].get("readback") != "Disabled"
            or cancel_actions[1].get("readback") != "Enabled"):
        raise CustodianReceiptError("cancel receipt must bind CancelKeyDeletion and EnableKey to the exact CMK")
    if receipts["schedule"]["action"].get("deletion_executed") is not False:
        raise CustodianReceiptError("schedule receipt must explicitly confirm that deletion did not execute")

    grant_action = receipts["grant"]["action"]
    grant_id = grant_action.get("grant_id")
    grant_event = _one(events, "CreateGrant", lambda e: (e["inner"].get("responseElements") or {}).get("grantId") == grant_id)
    if grant_event["params"].get("name") != f"issue-2165-{run_id}" or grant_event["params"].get("granteePrincipal") != manifest["aws"]["runtime_role_arn"] or set(grant_event["params"].get("operations", [])) != {"Encrypt", "Decrypt", "DescribeKey"}:
        raise CustodianReceiptError("CloudTrail CreateGrant differs from exact run, runtime role, key, or three allowed operations")
    if grant_event["time"] > receipts["grant"]["observed_at"]:
        raise CustodianReceiptError("CreateGrant CloudTrail event must precede its helper receipt")

    initial_describes = [e for e in events if e["event_name"] == "DescribeKey" and e["time"] < rotate_call["time"]]
    def customer_key(event: dict[str, Any]) -> bool:
        metadata = key_metadata(event)
        return metadata.get("arn", metadata.get("Arn")) == key_arn and metadata.get("keyManager", metadata.get("KeyManager")) == "CUSTOMER"
    customer = _one(initial_describes, "DescribeKey", customer_key)

    rows_data = [
        ("customer_create_or_import", customer["time"], [customer], {"authority_ref": authority_ref, "cmk_arn": key_arn, "key_manager": "CUSTOMER", "describe_key_readback_sha256": _canonical_digest(key_readback)}),
        ("rotate", rotate_status["time"], [rotate_call, rotate_status], {"helper_receipt_sha256": receipts["rotate"]["digest"], "rotation_enabled": True}),
        ("deletion_schedule", restored["time"], [schedule, cancel, enable, restored], {"schedule_receipt_sha256": receipts["schedule"]["digest"], "cancel_receipt_sha256": receipts["cancel"]["digest"], "restored_state": "Enabled", "deletion_executed": False}),
    ]
    rows = []
    for step, when, selected, claims in rows_data:
        event_refs = [event["event_id"] for event in selected]
        provider_events = [{"event_id": event["event_id"], "event_name": event["event_name"],
                            "event_time_utc": event["time"].isoformat().replace("+00:00", "Z"),
                            "request_parameters": event["params"],
                            "response_elements": event["inner"].get("responseElements"),
                            "session_issuer_arn": manifest["aws"]["custodian_role_arn"]} for event in selected]
        evidence = {"step": step, "run_id": run_id, "account_id": manifest["aws"]["account_id"], "region": manifest["aws"]["region"], "cmk_arn": key_arn, "custodian_role_arn": manifest["aws"]["custodian_role_arn"], "provider_event_ids": event_refs, "provider_events": provider_events, "claims": claims}
        rows.append({"step": step, "occurred_at_utc": when.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "source": {"kind": "cloudtrail", "event_ref": "cloudtrail:" + "/".join(event_refs), "digest": _canonical_digest(evidence)}})
    if len({row["source"]["event_ref"] for row in rows}) != 3:
        raise CustodianReceiptError("each lifecycle row must use a distinct provider event reference")
    return rows


def _input_file(path: Path, label: str, runner_temp: str) -> Any:
    if path.resolve().parent != Path(runner_temp).resolve():
        raise CustodianReceiptError(f"{label} must reside directly under RUNNER_TEMP")
    return _read_private_json(path, label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--receipt-dir", required=True, type=Path)
    parser.add_argument("--cloudtrail", required=True, type=Path)
    parser.add_argument("--caller-identity", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        runner_temp = os.environ.get("RUNNER_TEMP", "")
        if not runner_temp or not os.environ.get("B083_TARGET_MANIFEST_SECRET_ARN"):
            raise CustodianReceiptError("protected manifest provenance and RUNNER_TEMP are required")
        if args.receipt_dir.is_symlink() or not args.receipt_dir.is_dir() or args.receipt_dir.resolve().parent != Path(runner_temp).resolve():
            raise CustodianReceiptError("custodian receipts must be in a private direct child of RUNNER_TEMP")
        manifest = _input_file(args.manifest, "manifest", runner_temp)
        cloudtrail = _input_file(args.cloudtrail, "CloudTrail LookupEvents response", runner_temp)
        caller = _input_file(args.caller_identity, "STS caller identity", runner_temp)
        customer_key = _input_file(Path(runner_temp) / "customer-cmk-before.json", "customer CMK DescribeKey readback", runner_temp)
        rows = build_receipts(manifest, dict(os.environ), args.receipt_dir, cloudtrail, caller, customer_key_readback=customer_key)
        if args.output.resolve().parent != Path(runner_temp).resolve():
            raise CustodianReceiptError("output must reside directly under RUNNER_TEMP")
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(args.output)
        print("custodian source receipts: PASS")
        return 0
    except Exception as exc:
        print(f"custodian source receipts: FAIL ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
