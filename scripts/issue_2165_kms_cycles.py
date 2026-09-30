#!/usr/bin/env python3
"""Run ten bounded real KMS revoke/restore cycles and read D1 outcomes.

The workflow must assume the protected custodian OIDC role before invoking this
program. It records restricted evidence only; it never claims an audit:// ref
or computes lifecycle latency percentiles.
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

import issue_2165_cf5128_readback as cf_readback
import issue_2165_kms_custodian as custodian
from issue_2165_kms_runtime import ContractError, validate_manifest

SCHEMA = "corelink.issue-2165-kms-cycle-bundle.v1"
TENANT_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
ROW_FIELDS = {"token", "tenant_id", "epoch", "action", "cmk_provider", "cmk_key_id", "outcome", "completed_at_ms"}
CF_API = cf_readback.CF_API


class CycleError(ContractError):
    """The protected target or one bounded lifecycle cycle failed closed."""


def validate_cycle_manifest(m: dict[str, Any], env: dict[str, str], now: datetime | None = None) -> dict[str, Any]:
    """Validate the runtime/CF target and the cycle-specific key/window binding."""
    validate_manifest(m, environ=env)
    try:
        target = cf_readback.validate_manifest(m, env)
    except cf_readback.ReadbackError as exc:
        raise CycleError(f"Cloudflare/D1 target contract failed: {exc}") from exc
    aws = m.get("aws", {})
    if aws.get("cmk_provider") != "aws" or aws.get("cmk_arn") != env.get("B083_KMS_KEY_ARN"):
        raise CycleError("manifest must bind cmk_provider=aws and the exact protected B083_KMS_KEY_ARN")
    if aws.get("cmk_arn") != m.get("aws", {}).get("cmk_arn"):
        raise CycleError("manifest key ARN is inconsistent")
    if not isinstance(m.get("lifecycle_window"), dict):
        raise CycleError("lifecycle_window is required for bounded cycles")
    window = m["lifecycle_window"]
    start, end = window.get("started_at_ms"), window.get("ended_at_ms")
    if type(start) is not int or type(end) is not int or start >= end or end - start > 60 * 60 * 1000:
        raise CycleError("lifecycle_window must have ordered integer UTC epoch-ms bounds within 60 minutes")
    current_ms = int((now or datetime.now(timezone.utc)).timestamp() * 1000)
    if not start <= current_ms <= end:
        raise CycleError("current time must be inside the protected lifecycle_window")
    target["key_arn"] = aws["cmk_arn"]
    return target


def _read_manifest(path: Path, env: dict[str, str]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CycleError("manifest must be a regular protected file")
    runner_temp = env.get("RUNNER_TEMP")
    if not env.get("B083_TARGET_MANIFEST_SECRET_ARN") or not runner_temp or path.parent.resolve() != Path(runner_temp).resolve():
        raise CycleError("manifest must come from protected Secrets Manager and reside directly under RUNNER_TEMP")
    if path.stat().st_mode & 0o077:
        raise CycleError("manifest file permissions must exclude group and other access")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CycleError("protected runtime manifest is unreadable JSON") from exc
    if not isinstance(value, dict):
        raise CycleError("protected runtime manifest must be a JSON object")
    return value


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _transition_query(target: dict[str, Any], action: str, api: Callable[..., dict[str, Any]], token: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if action not in {"degrade", "restore"}:
        raise CycleError("D1 action must be the frozen degrade or restore enum")
    sql = (
        "SELECT token, tenant_id, epoch, action, cmk_provider, cmk_key_id, outcome, completed_at_ms "
        "FROM byok_control_outcome WHERE tenant_id IN (?, ?) AND cmk_provider = ? AND cmk_key_id = ? "
        "AND action = ? AND outcome = 'completed' AND completed_at_ms >= ? AND completed_at_ms <= ? "
        "ORDER BY completed_at_ms, tenant_id"
    )
    window = target["lifecycle_window"]
    params = [*target["tenants"], "aws", target["key_arn"], action, window["started_at_ms"], window["ended_at_ms"]]
    path = f"/accounts/{target['account_id']}/d1/database/{target['database_id']}/query"
    query_body = {"sql": sql, "params": params}
    payload = api(
        "POST",
        path,
        token,
        query_body,
    )
    try:
        rows = cf_readback._extract_select_rows(payload, ROW_FIELDS)
    except cf_readback.ReadbackError as exc:
        raise CycleError("D1 transition readback did not prove read-only query metadata and exact row shape") from exc
    seen_tokens: set[tuple[str, str]] = set()
    seen_epochs: set[tuple[str, int]] = set()
    for row in rows:
        if (
            row.get("tenant_id") not in target["tenants"]
            or row.get("action") != action
            or row.get("cmk_provider") != "aws"
            or row.get("cmk_key_id") != target["key_arn"]
            or row.get("outcome") != "completed"
            or not isinstance(row.get("token"), str)
            or not TOKEN.fullmatch(row["token"])
            or type(row.get("epoch")) is not int
            or row["epoch"] < 0
            or type(row.get("completed_at_ms")) is not int
            or not window["started_at_ms"] <= row["completed_at_ms"] <= window["ended_at_ms"]
        ):
            raise CycleError("D1 transition row is outside the exact tenant/key/action/outcome/window contract")
        token_key = (row["tenant_id"], row["token"])
        epoch_key = (row["tenant_id"], row["epoch"])
        if token_key in seen_tokens or epoch_key in seen_epochs:
            raise CycleError("D1 transition token and epoch must be unique within each tenant readback")
        seen_tokens.add(token_key)
        seen_epochs.add(epoch_key)
    meta = payload["result"][0]["meta"]
    query_digest = hashlib.sha256(json.dumps(query_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    response_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source = {
        "method": "parameterized-select-post",
        "account_alias": "cf5128",
        "endpoint": CF_API + path,
        "account_id": target["account_id"],
        "database_id": target["database_id"],
        "d1_region": target["d1_region"],
        "query_sha256": query_digest,
        "response_sha256": response_digest,
        "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0},
        "observed_at_utc": _utc(),
    }
    if meta.get("changed_db") is not False or type(meta.get("rows_written")) is not int or meta["rows_written"] != 0 or type(meta.get("changes")) is not int or meta["changes"] != 0:
        raise CycleError("D1 source metadata does not prove this was a SELECT-only query")
    return rows, source


def _snapshot(action: str, tenants: list[str], seen: set[tuple[str, str, int]], seen_tokens: set[tuple[str, str]], seen_epochs: set[tuple[str, int]], deadline: float, api: Callable[..., dict[str, Any]], token: str, target: dict[str, Any], monotonic: Callable[[], float], sleeper: Callable[[float], None]) -> dict[str, Any]:
    while True:
        if monotonic() >= deadline:
            raise CycleError("timed out waiting for one completed D1 transition row per tenant")
        rows, source = _transition_query(target, action, api, token)
        candidates: dict[str, list[dict[str, Any]]] = {tenant: [] for tenant in tenants}
        for row in rows:
            key = (row["tenant_id"], row["token"], row["epoch"])
            if ((row["tenant_id"], row["token"]) in seen_tokens or (row["tenant_id"], row["epoch"]) in seen_epochs) and key not in seen:
                raise CycleError("D1 transition token or epoch collided with an earlier lifecycle row")
            if key not in seen:
                candidates[row["tenant_id"]].append(row)
        if any(len(candidates[tenant]) > 1 for tenant in tenants):
            raise CycleError("D1 transition produced ambiguous new rows for a tenant slot")
        if all(len(candidates[tenant]) == 1 for tenant in tenants):
            chosen = [candidates[tenant][0] for tenant in tenants]
            for row in chosen:
                seen.add((row["tenant_id"], row["token"], row["epoch"]))
                seen_tokens.add((row["tenant_id"], row["token"]))
                seen_epochs.add((row["tenant_id"], row["epoch"]))
            source["selected_rows_sha256"] = hashlib.sha256(json.dumps(chosen, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            source["selected_token_set_sha256"] = hashlib.sha256("\n".join(sorted(row["token"] for row in chosen)).encode()).hexdigest()
            return {"rows": chosen, "d1_source": source}
        if monotonic() >= deadline:
            raise CycleError("timed out waiting for one completed D1 transition row per tenant")
        sleeper(min(2.0, max(0.0, deadline - monotonic())))


def _record_action(stage: str, manifest: dict[str, Any], run_id: str, grant_id: str | None, folder: Path, stage_runner: Callable[..., str | None]) -> dict[str, Any]:
    if grant_id is not None:
        os.environ["B083_ISSUE2165_GRANT_ID"] = grant_id
    receipt_dir = folder / stage
    receipt_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipt_dir.chmod(0o700)
    started = _utc()
    returned_id = stage_runner(stage, manifest, receipt_dir)
    ended = _utc()
    receipt_path = receipt_dir / f"custodian-{stage}-receipt.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CycleError("custodian action receipt is missing after provider operation") from exc
    if receipt.get("schema") != "corelink.issue-2165-kms-custodian-receipt-v1" or receipt.get("stage") != stage or receipt.get("run_id") != run_id:
        raise CycleError("custodian action receipt does not match the exact stage and run")
    if not isinstance(receipt.get("receipt_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", receipt["receipt_sha256"]):
        raise CycleError("custodian action receipt digest is missing or malformed")
    new_id = returned_id if stage == "restore" else None
    if stage == "restore" and (not isinstance(new_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", new_id)):
        raise CycleError("custodian restore did not return an exact verified GrantId")
    actions = receipt.get("actions")
    expected_operation = "restore-grant" if stage == "restore" else "revoke-grant"
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict) or actions[0].get("operation") != expected_operation:
        raise CycleError("custodian receipt did not confirm exactly one requested provider action")
    if stage == "restore" and actions[0].get("grant_id") != new_id:
        raise CycleError("custodian grant receipt GrantId differs from the returned protected GrantId")
    return {"stage": stage, "grant_id": new_id or grant_id, "started_at_utc": started, "ended_at_utc": ended, "custodian_receipt_ref": str(receipt_path.relative_to(folder)), "custodian_receipt_sha256": receipt.get("receipt_sha256"), "provider_readback": actions[0].get("readback")}


def run_cycles(manifest: dict[str, Any], evidence_dir: Path, *, environ: dict[str, str] | None = None, stage_runner: Callable[..., str | None] | None = None, aws_runner: Callable[..., Any] = subprocess.run, api_json: Callable[..., dict[str, Any]] | None = None, monotonic: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep, utc_now: Callable[[], str] = _utc) -> dict[str, Any]:
    """Run exactly ten revoke/degrade/restore/restore cycles; providers are injectable for tests."""
    env = os.environ if environ is None else environ
    target = validate_cycle_manifest(manifest, env)
    token = env.get("B083_CF_API_TOKEN", "")
    if not token:
        raise CycleError("protected B083_CF_API_TOKEN is required for SELECT-only D1 readback")
    initial_grant = env.get("B083_ISSUE2165_GRANT_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", initial_grant):
        raise CycleError("protected exact B083_ISSUE2165_GRANT_ID is required")
    run_id = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id):
        raise CycleError("GITHUB_RUN_ID must be a bounded opaque run identifier")
    do_stage = stage_runner or (lambda stage, item, directory: custodian.run_stage(stage, item, directory, runner=aws_runner))
    do_api = api_json or cf_readback._api_json
    started_mono = monotonic()
    window = target["lifecycle_window"]
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    global_deadline = started_mono + min(55 * 60, max(0.0, (window["ended_at_ms"] - now_ms) / 1000))
    tenants = list(target["tenants"])
    seen: set[tuple[str, str, int]] = set()
    seen_tokens: set[tuple[str, str]] = set()
    seen_epochs: set[tuple[str, int]] = set()
    all_grant_ids = [initial_grant]
    current_grant = initial_grant
    cycles: list[dict[str, Any]] = []
    runner_temp = env.get("RUNNER_TEMP")
    if not runner_temp or evidence_dir.is_symlink() or not evidence_dir.resolve().is_relative_to(Path(runner_temp).resolve()):
        raise CycleError("restricted lifecycle evidence must remain under RUNNER_TEMP")
    folder = evidence_dir / "custodian-actions"
    evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence_dir.chmod(0o700)
    output_path = env.get("GITHUB_OUTPUT", "")
    if not output_path or not Path(output_path).is_file():
        raise CycleError("existing GITHUB_OUTPUT is required before lifecycle mutation")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    folder.chmod(0o700)
    mutation_in_progress = False
    current_cycle = 0
    current_stage = "baseline"
    try:
        # Baseline exact rows before mutating; pre-existing transitions cannot
        # be mistaken for results of one of the ten cycle actions.
        for action in ("degrade", "restore"):
            baseline_rows, _baseline_source = _transition_query(target, action, do_api, token)
            for row in baseline_rows:
                pair = (row["tenant_id"], row["token"], row["epoch"])
                if pair in seen or (row["tenant_id"], row["token"]) in seen_tokens or (row["tenant_id"], row["epoch"]) in seen_epochs:
                    raise CycleError("baseline D1 rows contain duplicate token/epoch values")
                seen.add(pair)
                seen_tokens.add((row["tenant_id"], row["token"]))
                seen_epochs.add((row["tenant_id"], row["epoch"]))
        for index in range(1, 11):
            current_cycle = index
            cycle_dir = folder / f"cycle-{index:02d}"
            cycle_started = utc_now()
            current_stage = "revoke"
            mutation_in_progress = True
            revoke = _record_action("revoke", manifest, run_id, current_grant, cycle_dir, do_stage)
            mutation_in_progress = False
            degrade_deadline = min(global_deadline, monotonic() + 300.0)
            current_stage = "degrade-readback"
            degrade_rows = _snapshot("degrade", tenants, seen, seen_tokens, seen_epochs, degrade_deadline, do_api, token, target, monotonic, sleeper)
            current_stage = "restore"
            mutation_in_progress = True
            restore = _record_action("restore", manifest, run_id, None, cycle_dir, do_stage)
            mutation_in_progress = False
            restored_grant = restore["grant_id"]
            if restored_grant in all_grant_ids:
                raise CycleError("custodian returned a duplicate GrantId for a restore cycle")
            all_grant_ids.append(restored_grant)
            restore_deadline = min(global_deadline, monotonic() + 300.0)
            current_stage = "restore-readback"
            restore_rows = _snapshot("restore", tenants, seen, seen_tokens, seen_epochs, restore_deadline, do_api, token, target, monotonic, sleeper)
            cycles.append({"cycle": index, "cycle_started_at_utc": cycle_started, "revoke": revoke, "degrade_rows": degrade_rows, "restore": restore, "restore_rows": restore_rows})
            current_grant = restored_grant
            if monotonic() >= global_deadline:
                raise CycleError("ten-cycle run exceeded its bounded 55-minute/lifecycle-window limit")
        bundle = {"schema": SCHEMA, "run_id": run_id, "created_at_utc": utc_now(), "window": dict(window), "target": {"cmk_provider": "aws", "cmk_key_arn": target["key_arn"], "redacted_tenant_slots": ["tenant_a", "tenant_b"], "tenant_ids": tenants}, "cycles": cycles, "grant_ids": all_grant_ids, "final_grant_id": current_grant, "audit_claims": [], "latency_claims": []}
        _write_bundle(evidence_dir / "lifecycle-cycle-bundle.json", bundle)
        _write_outputs(env, all_grant_ids, current_grant)
        return bundle
    except BaseException as exc:
        # Reconcile only IDs observed from provider responses, plus grants with
        # this run's exact generated name and runtime principal. Never retry a
        # timed-out CreateGrant or revoke another grant.
        reconcile_ids = list(all_grant_ids)
        try:
            rows = custodian._grants(manifest, aws_runner)
            for row in rows:
                if row.get("GranteePrincipal") == manifest["aws"]["runtime_role_arn"] and row.get("Name") == f"issue-2165-{run_id}" and row.get("Operations") and set(row["Operations"]) == {"Encrypt", "Decrypt", "DescribeKey"}:
                    gid = row.get("GrantId")
                    if isinstance(gid, str) and gid not in reconcile_ids:
                        reconcile_ids.append(gid)
        except BaseException:
            pass
        cleanup_result = "not-attempted-ambiguous-provider-mutation" if mutation_in_progress else "not-attempted"
        try:
            if mutation_in_progress and current_stage == "revoke":
                raise CycleError("provider mutation outcome is ambiguous; no automatic retry or rollback was attempted")
            os.environ["B083_ISSUE2165_GRANT_IDS"] = json.dumps(reconcile_ids, separators=(",", ":"))
            do_stage("cleanup", manifest, folder / "failure-cleanup")
            cleanup_result = "exact-known-grants-cleaned"
        except BaseException as cleanup_error:
            cleanup_result = f"blocked:{type(cleanup_error).__name__}"
        _write_bundle(evidence_dir / "lifecycle-cycle-reconciliation.json", {"schema": SCHEMA, "run_id": run_id, "created_at_utc": utc_now(), "failed_cycle": current_cycle, "failed_stage": current_stage, "completed_cycles": len(cycles), "known_grant_ids": reconcile_ids, "last_known_grant_id": current_grant, "failure_type": type(exc).__name__, "cleanup_result": cleanup_result, "partial_cycles": cycles, "audit_claims": [], "latency_claims": []})
        raise


def _write_bundle(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_outputs(env: dict[str, str], grant_ids: list[str], final_grant_id: str) -> None:
    path = env.get("GITHUB_OUTPUT")
    if not path or not Path(path).is_file():
        raise CycleError("existing GITHUB_OUTPUT is required for protected grant handoff")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(f"grant_ids_json={json.dumps(grant_ids, separators=(',', ':'))}\nfinal_grant_id={final_grant_id}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = _read_manifest(args.manifest, os.environ)
        validate_cycle_manifest(manifest, os.environ)
        run_cycles(manifest, args.evidence_dir)
        return 0
    except (CycleError, OSError) as exc:
        print(f"lifecycle cycles blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
