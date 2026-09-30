#!/usr/bin/env python3
"""Verify a failure-safe KMS cleanup Cancel→EnableKey CloudTrail sequence."""

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
ROLE_SESSION = re.compile(r"^arn:aws:sts::([0-9]{12}):assumed-role/([^/]+)/([^/]+)$")


class CleanupReceiptError(ValueError):
    """Cleanup telemetry does not prove the exact ordered rollback."""


def _utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise CleanupReceiptError(f"{field} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CleanupReceiptError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise CleanupReceiptError(f"{field} must be UTC")
    return parsed.astimezone(timezone.utc)


def _private_json(path: Path, label: str, runner_temp: Path) -> Any:
    if path.is_symlink() or path.resolve().parent != runner_temp.resolve() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CleanupReceiptError(f"{label} must be a mode-0600 direct child of RUNNER_TEMP")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CleanupReceiptError(f"{label} must be readable JSON") from exc


def _key_for_event(event: dict[str, Any], key_arn: str) -> bool:
    params = event.get("requestParameters")
    if not isinstance(params, dict):
        return False
    requested = params.get("keyId")
    return requested in (key_arn, key_arn.split("/key/")[-1])


def verify_cleanup_rollback(
    manifest: dict[str, Any], env: dict[str, str], receipt: Any,
    cloudtrail: Any, caller: Any, *, now: datetime | None = None,
) -> dict[str, Any]:
    """Prove exact-run CancelKeyDeletion→EnableKey→Enabled DescribeKey."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    run_id = env.get("GITHUB_RUN_ID", "")
    if not RUN_ID.fullmatch(run_id):
        raise CleanupReceiptError("GITHUB_RUN_ID must be an exact numeric workflow run id")
    try:
        # Cleanup is a recovery path, so the target manifest may have expired
        # after the failed lifecycle run. Exact protected target bindings remain
        # mandatory; only the TTL admission check is relaxed.
        validate_manifest(manifest, now=current, environ=env, allow_expired=True)
    except ContractError as exc:
        raise CleanupReceiptError("protected target manifest failed validation") from exc
    aws = manifest["aws"]
    custodian = aws["custodian_role_arn"]
    preflight_role = env.get("B083_AWS_PREFLIGHT_ROLE_ARN", "")
    caller_arn = caller.get("Arn") if isinstance(caller, dict) else None
    caller_account = caller.get("Account") if isinstance(caller, dict) else None
    match = ROLE_SESSION.fullmatch(caller_arn or "")
    if (caller_account != aws["account_id"] or not match or match.group(1) != aws["account_id"]
            or not preflight_role or match.group(2) != preflight_role.rsplit("/", 1)[-1]
            or match.group(3) != f"i2165-cleanup-readback-{run_id}"):
        raise CleanupReceiptError("STS caller must be this run's exact read-only preflight session")
    if not isinstance(receipt, dict) or receipt.get("schema") != "corelink.issue-2165-kms-custodian-receipt-v1" or receipt.get("stage") != "cleanup-rollback" or receipt.get("run_id") != run_id:
        raise CleanupReceiptError("cleanup rollback receipt has wrong schema, stage, or run")
    observed = _utc(receipt.get("observed_at_utc"), "cleanup receipt observed_at_utc")
    receipt_digest = receipt.get("receipt_sha256")
    if not isinstance(receipt_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", receipt_digest):
        raise CleanupReceiptError("cleanup rollback receipt must carry its exact helper SHA-256")
    actions = receipt.get("actions")
    if not isinstance(actions, list) or not all(isinstance(item, dict) for item in actions):
        raise CleanupReceiptError("cleanup receipt actions must be an array")
    cancel_actions = [item for item in actions if item.get("operation") == "cancel-key-deletion"]
    if not cancel_actions:
        raise CleanupReceiptError("cleanup rollback receipt does not record a key cancellation")
    if len(cancel_actions) != 1:
        raise CleanupReceiptError("cleanup receipt must contain exactly one key cancellation")
    cancel_action = cancel_actions[0]
    enable_actions = [item for item in actions if item.get("operation") == "enable-key"]
    if (cancel_action.get("key_arn", aws["cmk_arn"]) != aws["cmk_arn"] or cancel_action.get("readback") != "Disabled"
            or len(enable_actions) != 1 or enable_actions[0].get("key_arn", aws["cmk_arn"]) != aws["cmk_arn"]
            or enable_actions[0].get("readback") != "Enabled"):
        raise CleanupReceiptError("cleanup helper receipt does not bind Cancel and Enable to the exact CMK")
    if not isinstance(cloudtrail, dict) or not isinstance(cloudtrail.get("Events"), list):
        raise CleanupReceiptError("CloudTrail input must contain an Events array")
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for outer in cloudtrail["Events"]:
        if not isinstance(outer, dict) or not isinstance(outer.get("CloudTrailEvent"), str):
            raise CleanupReceiptError("CloudTrail events must include nested event JSON")
        try:
            inner = json.loads(outer["CloudTrailEvent"])
        except json.JSONDecodeError as exc:
            raise CleanupReceiptError("nested CloudTrail event JSON is malformed") from exc
        if not isinstance(inner, dict):
            raise CleanupReceiptError("nested CloudTrail event must be an object")
        event_id = outer.get("EventId")
        name = outer.get("EventName")
        when = _utc(outer.get("EventTime"), "LookupEvents EventTime")
        if not isinstance(event_id, str) or len(event_id) < 8 or event_id in seen:
            raise CleanupReceiptError("CloudTrail EventIds must be valid and unique")
        seen.add(event_id)
        if inner.get("eventID") != event_id or inner.get("eventName") != name or _utc(inner.get("eventTime"), "nested eventTime") != when:
            raise CleanupReceiptError("CloudTrail outer and nested event identity/time disagree")
        identity = inner.get("userIdentity")
        session = identity.get("sessionContext") if isinstance(identity, dict) else None
        issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
        actor = ROLE_SESSION.fullmatch(identity.get("arn", "")) if isinstance(identity, dict) else None
        if (outer.get("EventSource") != "kms.amazonaws.com" or inner.get("eventSource") != "kms.amazonaws.com"
                or inner.get("awsRegion") != aws["region"] or inner.get("recipientAccountId") != aws["account_id"]
                or not isinstance(identity, dict) or identity.get("type") != "AssumedRole"
                or identity.get("accountId") != aws["account_id"] or not isinstance(issuer, dict)
                or issuer.get("arn") != custodian or not actor or actor.group(1) != aws["account_id"]
                or actor.group(2) != custodian.rsplit("/", 1)[-1] or actor.group(3) != f"i2165-key-cleanup-{run_id}"
                or not _key_for_event(inner, aws["cmk_arn"])):
            continue
        if when > current or when < observed - timedelta(minutes=5) or when > observed:
            continue
        events.append({"id": event_id, "name": name, "time": when, "inner": inner})
    cancels = [event for event in events if event["name"] == "CancelKeyDeletion"]
    if len(cancels) != 1:
        raise CleanupReceiptError("missing or ambiguous authenticated CancelKeyDeletion CloudTrail event")
    cancel = cancels[0]
    enables = [event for event in events if event["name"] == "EnableKey" and event["time"] > cancel["time"]]
    if len(enables) != 1:
        raise CleanupReceiptError("missing or ambiguous ordered EnableKey CloudTrail event")
    enable = enables[0]
    describes = [event for event in events if event["name"] == "DescribeKey" and event["time"] > enable["time"]]
    enabled = [event for event in describes if ((event["inner"].get("responseElements") or {}).get("keyMetadata") or {}).get("keyState") == "Enabled"]
    if len(enabled) != 1:
        raise CleanupReceiptError("missing or ambiguous exact-key Enabled DescribeKey CloudTrail readback")
    ids = [cancel["id"], enable["id"], enabled[0]["id"]]
    if len(set(ids)) != 3:
        raise CleanupReceiptError("cleanup rollback CloudTrail events must have distinct EventIds")
    payload = {"run_id": run_id, "key_arn": aws["cmk_arn"], "event_ids": ids, "events_utc": [event["time"].isoformat() for event in (cancel, enable, enabled[0])], "enabled": True}
    return {"cancel_performed": True, "run_id": run_id, "event_ref": "cloudtrail:" + "/".join(ids), "digest": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "readback": "Enabled"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "receipt", "cloudtrail", "caller-identity", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
        if not runner_temp.is_dir() or not os.environ.get("B083_TARGET_MANIFEST_SECRET_ARN"):
            raise CleanupReceiptError("protected manifest provenance and RUNNER_TEMP are required")
        values = {name: _private_json(getattr(args, name.replace("-", "_")), name, runner_temp) for name in ("manifest", "receipt", "cloudtrail", "caller-identity")}
        result = verify_cleanup_rollback(values["manifest"], dict(os.environ), values["receipt"], values["cloudtrail"], values["caller-identity"])
        if args.output.resolve().parent != runner_temp.resolve():
            raise CleanupReceiptError("output must reside directly under RUNNER_TEMP")
        args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        args.output.chmod(0o600)
        print("KMS cleanup CloudTrail readback: PASS" if result["cancel_performed"] else "KMS cleanup CloudTrail readback: not required")
        return 0
    except Exception as exc:
        print(f"KMS cleanup CloudTrail readback: FAIL ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
