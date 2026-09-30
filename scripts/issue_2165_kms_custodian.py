#!/usr/bin/env python3
"""Narrow KMS custodian operations for the protected Issue #2165 test CMK.

This helper assumes the workflow has already assumed the protected custodian
OIDC role. It never switches roles, emits grant tokens, or calls DeleteKey.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from issue_2165_kms_runtime import ContractError, validate_manifest

STAGES = ("grant", "revoke", "restore", "rotate", "schedule", "cancel", "cleanup")
OPERATIONS = ("Encrypt", "Decrypt", "DescribeKey")
GRANT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class CustodianError(ContractError):
    """The custodian identity, approval, or live key state is unsafe."""


def _utc(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise CustodianError(f"{name} must be an ISO-8601 UTC timestamp")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CustodianError(f"{name} must be an ISO-8601 UTC timestamp") from exc
    if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
        raise CustodianError(f"{name} must be an ISO-8601 UTC timestamp")
    return instant


def _aws(service: str, *args: str, runner: Callable[..., Any] = subprocess.run, allow_empty: bool = False) -> dict[str, Any]:
    region = os.environ.get("B083_AWS_REGION", "")
    if not region:
        raise CustodianError("protected B083_AWS_REGION is required")
    try:
        result = runner(["aws", service, *args, "--region", region, "--output", "json"], check=True, capture_output=True, text=True, timeout=45)
        value = {} if allow_empty and not result.stdout.strip() else json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise CustodianError(f"bounded AWS {service} call failed: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise CustodianError(f"AWS {service} response must be a JSON object")
    return value


def _assumed_role_matches(caller_arn: str, role_arn: str) -> bool:
    assumed = caller_arn.split(":assumed-role/", 1)
    return len(assumed) == 2 and assumed[1].split("/", 1)[0] == role_arn.rsplit("/", 1)[-1]


def _identity(m: dict[str, Any], runner: Callable[..., Any]) -> None:
    identity = _aws("sts", "get-caller-identity", runner=runner)
    if identity.get("Account") != m["aws"]["account_id"] or not _assumed_role_matches(identity.get("Arn", ""), m["aws"]["custodian_role_arn"]):
        raise CustodianError("caller must be the exact protected custodian OIDC role in the bound account")


def _key(m: dict[str, Any], runner: Callable[..., Any]) -> dict[str, Any]:
    arn = m["aws"]["cmk_arn"]
    key = _aws("kms", "describe-key", "--key-id", arn, runner=runner).get("KeyMetadata", {})
    if key.get("Arn") != arn or key.get("AWSAccountId") != m["aws"]["account_id"] or key.get("KeyManager") != "CUSTOMER" or key.get("KeyUsage") != "ENCRYPT_DECRYPT" or key.get("KeySpec") != "SYMMETRIC_DEFAULT":
        raise CustodianError("live key must be the exact account-owned symmetric encrypt/decrypt CMK from the protected manifest")
    return key


def _cancel_and_enable(m: dict[str, Any], runner: Callable[..., Any]) -> dict[str, Any]:
    """Cancel a schedule, re-enable its disabled key, and verify restoration."""
    arn = m["aws"]["cmk_arn"]
    _aws("kms", "cancel-key-deletion", "--key-id", arn, runner=runner, allow_empty=True)
    after_cancel = _key(m, runner)
    if after_cancel.get("KeyState") != "Disabled":
        raise CustodianError("CancelKeyDeletion must read back Disabled before the explicit EnableKey rollback")
    _aws("kms", "enable-key", "--key-id", arn, runner=runner, allow_empty=True)
    for attempt in range(30):
        restored = _key(m, runner)
        if restored.get("KeyState") == "Enabled":
            return restored
        if restored.get("KeyState") != "Disabled":
            raise CustodianError("EnableKey rollback returned an unexpected CMK state")
        if attempt < 29:
            time.sleep(1)
    raise CustodianError("EnableKey rollback did not read back Enabled within the bounded wait")


def _grants(m: dict[str, Any], runner: Callable[..., Any]) -> list[dict[str, Any]]:
    rows = _aws("kms", "list-grants", "--key-id", m["aws"]["cmk_arn"], runner=runner).get("Grants", [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CustodianError("KMS ListGrants response is malformed")
    return rows


def _exact_grant(row: dict[str, Any], m: dict[str, Any]) -> bool:
    return (
        row.get("GranteePrincipal") == m["aws"]["runtime_role_arn"]
        and set(row.get("Operations", [])) == set(OPERATIONS)
        and row.get("KeyId") == m["aws"]["cmk_arn"]
        and row.get("Name") == f"issue-2165-{os.environ.get('GITHUB_RUN_ID', '')}"
    )


def _run_id() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id):
        raise CustodianError("GITHUB_RUN_ID must be a bounded opaque run identifier")
    return run_id


def _grant(m: dict[str, Any], runner: Callable[..., Any]) -> tuple[str, dict[str, Any]]:
    run_id = _run_id()
    all_grants = _grants(m, runner)
    current = [g for g in all_grants if g.get("GranteePrincipal") == m["aws"]["runtime_role_arn"]]
    if current:
        raise CustodianError("grant/restore requires zero existing grants for the exact runtime role")
    response = _aws("kms", "create-grant", "--key-id", m["aws"]["cmk_arn"], "--grantee-principal", m["aws"]["runtime_role_arn"], "--operations", *OPERATIONS, "--name", f"issue-2165-{run_id}", runner=runner)
    grant_id = response.get("GrantId")
    if not isinstance(grant_id, str) or not GRANT_ID.fullmatch(grant_id):
        raise CustodianError("CreateGrant returned no valid GrantId")
    try:
        readback = [g for g in _grants(m, runner) if g.get("GrantId") == grant_id]
    except CustodianError:
        # The exact CreateGrant response gives us a narrow rollback handle. Do
        # not retry CreateGrant when readback is unavailable.
        _aws("kms", "revoke-grant", "--key-id", m["aws"]["cmk_arn"], "--grant-id", grant_id, runner=runner, allow_empty=True)
        raise
    if len(readback) != 1 or not _exact_grant(readback[0], m):
        # Roll back only the GrantId returned by this exact CreateGrant call.
        _aws("kms", "revoke-grant", "--key-id", m["aws"]["cmk_arn"], "--grant-id", grant_id, runner=runner)
        raise CustodianError("CreateGrant readback did not match the exact runtime principal and operations")
    return grant_id, {"operation": "create-grant", "grant_id": grant_id, "operations": list(OPERATIONS), "readback": "exact"}


def _grant_id_from_env() -> str:
    value = os.environ.get("B083_ISSUE2165_GRANT_ID", "")
    if not GRANT_ID.fullmatch(value):
        raise CustodianError("protected exact B083_ISSUE2165_GRANT_ID is required")
    return value


def _revoke_one(m: dict[str, Any], grant_id: str, runner: Callable[..., Any]) -> dict[str, Any]:
    if not GRANT_ID.fullmatch(grant_id):
        raise CustodianError("grant ID is malformed")
    matches = [g for g in _grants(m, runner) if g.get("GrantId") == grant_id]
    if not matches:
        return {"operation": "revoke-grant", "grant_id": grant_id, "readback": "absent"}
    if len(matches) != 1 or not _exact_grant(matches[0], m):
        raise CustodianError("refusing to revoke a grant not owned by this run and exact runtime role")
    _aws("kms", "revoke-grant", "--key-id", m["aws"]["cmk_arn"], "--grant-id", grant_id, runner=runner, allow_empty=True)
    if any(g.get("GrantId") == grant_id for g in _grants(m, runner)):
        raise CustodianError("RevokeGrant response was not confirmed by ListGrants readback")
    return {"operation": "revoke-grant", "grant_id": grant_id, "readback": "absent"}


def _schedule_approval(m: dict[str, Any], now: datetime | None = None) -> tuple[int, datetime]:
    approval = m.get("approval", {})
    deletion = m.get("key_deletion", {})
    if approval.get("schedule_key_deletion") is not True or deletion.get("disposable_key_ownership_approved") is not True:
        raise CustodianError("schedule requires explicit owner approval and disposable-key ownership approval")
    ref = deletion.get("ownership_approval_ref")
    if not isinstance(ref, str) or not ref.startswith("restricted://"):
        raise CustodianError("schedule requires a restricted root ownership approval reference")
    days = deletion.get("pending_window_days")
    if type(days) is not int or not 7 <= days <= 30:
        raise CustodianError("key_deletion.pending_window_days must be an AWS supported 7–30 day window")
    cancel_by = _utc(deletion.get("cancel_by"), "key_deletion.cancel_by")
    current = now or datetime.now(timezone.utc)
    if not current < cancel_by < current + timedelta(days=days):
        raise CustodianError("cancel_by must be future and before the scheduled deletion date")
    _rollback_proof_approval(m, days, cancel_by, current)
    return days, cancel_by


def _rollback_proof_approval(
    m: dict[str, Any], days: int, cancel_by: datetime, current: datetime
) -> None:
    """Require a protected, reviewed rollback proof bound to this exact run/key."""
    deletion = m.get("key_deletion", {})
    proof = deletion.get("rollback_proof")
    if not isinstance(proof, dict) or proof.get("status") != "PASS" or proof.get("reviewed") is not True:
        raise CustodianError("schedule requires a reviewed source-backed rollback proof")
    source_ref = proof.get("source_ref")
    if not isinstance(source_ref, str) or not source_ref.startswith("restricted://"):
        raise CustodianError("rollback proof requires a restricted source reference")
    source_digest = proof.get("source_sha256")
    if not isinstance(source_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", source_digest):
        raise CustodianError("rollback proof source digest must be lowercase SHA-256")
    if proof.get("cmk_arn") != m["aws"]["cmk_arn"]:
        raise CustodianError("rollback proof is bound to a different CMK")
    github_sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", github_sha) or proof.get("approved_github_sha") != github_sha:
        raise CustodianError("rollback proof is not approved for this exact GitHub SHA")
    run_namespace = m.get("run_namespace")
    if not isinstance(run_namespace, str) or not run_namespace or proof.get("run_namespace") != run_namespace:
        raise CustodianError("rollback proof is bound to a different run namespace")
    if type(proof.get("pending_window_days")) is not int or proof["pending_window_days"] != days:
        raise CustodianError("rollback proof pending window does not match the approved deletion window")
    proof_cancel_by = _utc(proof.get("cancel_by"), "key_deletion.rollback_proof.cancel_by")
    if proof_cancel_by != cancel_by:
        raise CustodianError("rollback proof cancellation deadline does not match the manifest")
    reviewed_at = _utc(proof.get("reviewed_at_utc"), "key_deletion.rollback_proof.reviewed_at_utc")
    expires_at = _utc(proof.get("expires_at_utc"), "key_deletion.rollback_proof.expires_at_utc")
    if reviewed_at > current:
        raise CustodianError("rollback proof review timestamp is in the future")
    if expires_at <= current or expires_at < cancel_by:
        raise CustodianError("rollback proof is expired or does not cover the cancellation window")


def _cancel_deadline(m: dict[str, Any], now: datetime | None = None) -> datetime:
    deletion = m.get("key_deletion", {})
    if deletion.get("disposable_key_ownership_approved") is not True or not isinstance(deletion.get("ownership_approval_ref"), str) or not deletion["ownership_approval_ref"].startswith("restricted://"):
        raise CustodianError("cancel requires the restricted disposable-key ownership approval")
    deadline = _utc(deletion.get("cancel_by"), "key_deletion.cancel_by")
    if (now or datetime.now(timezone.utc)) >= deadline:
        raise CustodianError("key deletion cancellation deadline has passed; escalate to root custodian")
    return deadline


def _write_receipt(stage: str, run_id: str, actions: list[dict[str, Any]], evidence_dir: Path) -> None:
    # Store only action identifiers and readback summaries; never retain raw AWS
    # output, grant tokens, caller credentials, or the protected manifest.
    canonical = json.dumps({"stage": stage, "run_id": run_id, "actions": actions}, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"custodian-{stage}-receipt.json"
    payload = {"schema": "corelink.issue-2165-kms-custodian-receipt-v1", "stage": stage, "run_id": run_id, "observed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "receipt_sha256": digest, "actions": actions}
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def run_stage(stage: str, m: dict[str, Any], evidence_dir: Path, runner: Callable[..., Any] = subprocess.run) -> str | None:
    if stage not in STAGES:
        raise CustodianError("stage must be one of grant, revoke, restore, rotate, schedule, cancel, cleanup")
    _identity(m, runner)
    _run_id()
    key = _key(m, runner)
    actions: list[dict[str, Any]] = []
    grant_id: str | None = None
    if stage == "grant":
        if key.get("KeyState") != "Enabled":
            raise CustodianError("grant requires the exact CMK to be Enabled")
        grant_id, action = _grant(m, runner)
        actions.append(action)
    elif stage == "restore":
        if key.get("KeyState") != "Enabled":
            raise CustodianError("restore grant requires the exact CMK to be Enabled")
        grant_id, action = _grant(m, runner)
        actions.append({**action, "operation": "restore-grant"})
    elif stage == "revoke":
        actions.append(_revoke_one(m, _grant_id_from_env(), runner))
    elif stage == "cleanup":
        ids_raw = os.environ.get("B083_ISSUE2165_GRANT_IDS", "")
        if ids_raw:
            try:
                ids = json.loads(ids_raw)
            except json.JSONDecodeError as exc:
                raise CustodianError("B083_ISSUE2165_GRANT_IDS must be a JSON array") from exc
            if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids) or any(not isinstance(item, str) or not GRANT_ID.fullmatch(item) for item in ids):
                raise CustodianError("cleanup grant IDs must be a non-empty unique list of exact GrantIds")
        elif os.environ.get("B083_ISSUE2165_GRANT_ID"):
            ids = [_grant_id_from_env()]
        else:
            ids = []
        actions.extend(_revoke_one(m, item, runner) for item in ids)
        if key.get("KeyState") == "PendingDeletion":
            _cancel_deadline(m)
            _cancel_and_enable(m, runner)
            rollback_actions = [
                {"operation": "cancel-key-deletion", "key_arn": m["aws"]["cmk_arn"], "readback": "Disabled"},
                {"operation": "enable-key", "key_arn": m["aws"]["cmk_arn"], "readback": "Enabled"},
            ]
            actions.extend(rollback_actions)
            # Persist the exact successful recovery pair before any later
            # cleanup work can fail, so the read-only verifier can bind it.
            _write_receipt("cleanup-rollback", os.environ["GITHUB_RUN_ID"], rollback_actions, evidence_dir)
        elif key.get("KeyState") != "Enabled":
            raise CustodianError("cleanup will not operate on an unexpected CMK state")
    elif stage == "rotate":
        approval = m.get("approval", {})
        if key.get("KeyState") != "Enabled" or approval.get("rotate_key") is not True:
            raise CustodianError("rotate requires an Enabled key, automatic rotation enabled, and explicit owner approval")
        status = _aws("kms", "get-key-rotation-status", "--key-id", m["aws"]["cmk_arn"], runner=runner)
        if status.get("KeyId") != m["aws"]["cmk_arn"] or type(status.get("KeyRotationEnabled")) is not bool:
            raise CustodianError("GetKeyRotationStatus returned malformed or wrong-key rotation status")
        if status["KeyRotationEnabled"] is not True:
            raise CustodianError("rotate requires automatic rotation enabled by exact GetKeyRotationStatus readback")
        before = _aws("kms", "list-key-rotations", "--key-id", m["aws"]["cmk_arn"], runner=runner)
        rotations_before = before.get("Rotations", [])
        if not isinstance(rotations_before, list) or any(not isinstance(row, dict) for row in rotations_before):
            raise CustodianError("ListKeyRotations returned a malformed pre-rotation response")
        before_count = sum(row.get("RotationType") == "ON_DEMAND" for row in rotations_before)
        response = _aws("kms", "rotate-key-on-demand", "--key-id", m["aws"]["cmk_arn"], runner=runner, allow_empty=True)
        if response.get("KeyId") not in (None, m["aws"]["cmk_arn"]):
            raise CustodianError("RotateKeyOnDemand returned a different key")
        after_status = _aws("kms", "get-key-rotation-status", "--key-id", m["aws"]["cmk_arn"], runner=runner)
        if after_status.get("KeyId") != m["aws"]["cmk_arn"] or type(after_status.get("KeyRotationEnabled")) is not bool or after_status["KeyRotationEnabled"] is not True:
            raise CustodianError("post-rotation GetKeyRotationStatus did not confirm the exact enabled key")
        after = _aws("kms", "list-key-rotations", "--key-id", m["aws"]["cmk_arn"], runner=runner)
        rotations_after = after.get("Rotations", [])
        if not isinstance(rotations_after, list) or any(not isinstance(row, dict) for row in rotations_after):
            raise CustodianError("ListKeyRotations returned a malformed post-rotation response")
        key_id = m["aws"]["cmk_arn"].split("/key/", 1)[-1]
        new_rotation = any(row.get("RotationType") == "ON_DEMAND" and row.get("KeyId") in (m["aws"]["cmk_arn"], key_id) for row in rotations_after) and sum(row.get("RotationType") == "ON_DEMAND" for row in rotations_after) > before_count
        started = after_status.get("OnDemandRotationStartDate")
        if not new_rotation and not isinstance(started, (int, float)):
            raise CustodianError("RotateKeyOnDemand lacked an in-progress status or new ON_DEMAND ListKeyRotations readback")
        actions.append({"operation": "rotate-key-on-demand", "readback": "completed" if new_rotation else "in-progress"})
    elif stage == "schedule":
        days, cancel_by = _schedule_approval(m)
        if key.get("KeyState") != "Enabled":
            raise CustodianError("schedule requires the exact CMK to be Enabled")
        if any(g.get("GranteePrincipal") == m["aws"]["runtime_role_arn"] for g in _grants(m, runner)):
            raise CustodianError("schedule is forbidden while any runtime grant remains")
        scheduled = _aws(
            "kms", "schedule-key-deletion", "--key-id", m["aws"]["cmk_arn"],
            "--pending-window-in-days", str(days), runner=runner,
        )
        if scheduled.get("KeyId") not in (None, m["aws"]["cmk_arn"]):
            raise CustodianError("ScheduleKeyDeletion returned a different key")
        pending = _aws("kms", "describe-key", "--key-id", m["aws"]["cmk_arn"], runner=runner).get("KeyMetadata", {})
        if pending.get("Arn") != m["aws"]["cmk_arn"] or pending.get("KeyState") != "PendingDeletion":
            raise CustodianError("ScheduleKeyDeletion did not read back PendingDeletion for the exact CMK")
        actions.append({
            "operation": "schedule-key-deletion", "key_arn": m["aws"]["cmk_arn"],
            "pending_window_days": days,
            "cancel_by": cancel_by.isoformat().replace("+00:00", "Z"),
            "readback": "PendingDeletion",
        })
    elif stage == "cancel":
        deadline = _cancel_deadline(m)
        if key.get("KeyState") != "PendingDeletion":
            raise CustodianError("cancel requires the exact CMK to be PendingDeletion")
        _cancel_and_enable(m, runner)
        actions.extend([
            {"operation": "cancel-key-deletion", "key_arn": m["aws"]["cmk_arn"], "cancel_by": deadline.isoformat().replace("+00:00", "Z"), "readback": "Disabled"},
            {"operation": "enable-key", "key_arn": m["aws"]["cmk_arn"], "readback": "Enabled"},
        ])
    _write_receipt(stage, os.environ["GITHUB_RUN_ID"], actions, evidence_dir)
    return grant_id


def _load_manifest(path: Path, stage: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CustodianError("manifest must be a regular protected file")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not os.environ.get("B083_TARGET_MANIFEST_SECRET_ARN") or not runner_temp or path.parent.resolve() != Path(runner_temp).resolve():
        raise CustodianError("manifest must come from protected Secrets Manager and reside directly under RUNNER_TEMP")
    if path.stat().st_mode & 0o077:
        raise CustodianError("manifest file permissions must exclude group and other access")
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CustodianError("protected runtime manifest is unreadable JSON") from exc
    if not isinstance(m, dict):
        raise CustodianError("protected runtime manifest must be a JSON object")
    validate_manifest(m, environ=os.environ, allow_expired=(stage == "cleanup"))
    return m


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = _load_manifest(args.manifest, args.stage)
        output = os.environ.get("GITHUB_OUTPUT")
        if args.stage in {"grant", "restore"} and (not output or not Path(output).is_file()):
            raise CustodianError("an existing GITHUB_OUTPUT file is required before creating a grant")
        grant_id = run_stage(args.stage, manifest, args.evidence_dir)
        if grant_id:
            try:
                with open(output, "a", encoding="utf-8") as stream:
                    stream.write(f"grant_id={grant_id}\n")
            except OSError:
                # The grant was created by this invocation; roll back only its
                # response GrantId if the protected job handoff cannot be made.
                _revoke_one(manifest, grant_id, subprocess.run)
                raise CustodianError("could not publish exact GrantId handoff; attempted exact-grant rollback")
        return 0
    except (CustodianError, OSError) as exc:
        print(f"custodian blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
