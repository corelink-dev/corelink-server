#!/usr/bin/env python3
"""Credentialless readiness audit for issue #1650/B-068.

This verifier reads only the reviewed manifest, workflow text, and redacted
owner packet. It never reads Actions secrets, contacts a provider, dispatches a
workflow, or authorizes a real harness. ``blocked`` is the expected state until
an owner records every protected input, isolated resource, and cleanup receipt.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs/handoff/2026-09-22-i1650-real-integration-readiness.json"
MANIFEST = ROOT / "scripts/real-ignored-harness-manifest.json"
WORKFLOW = ROOT / ".github/workflows/real-ignored-harnesses.yml"
BOOTSTRAP = ROOT / "scripts/issue_2564_r2_temp_credentials.py"
PROFILES = ("d1", "r2", "stripe", "neon")
REQUIRED_RESOURCES = {
    "d1": (
        ("Cloudflare account", "provider account", "dedicated test account; no production writes"),
        ("D1 database", "D1 database", "dedicated integration database"),
    ),
    "r2": (
        ("Cloudflare account", "provider account", "dedicated test account; no production writes"),
        ("D1 database", "D1 database", "dedicated integration database for audit path"),
        ("R2 test bucket", "R2 bucket", "dedicated disposable bucket; cleanup after receipt"),
    ),
    "stripe": (
        ("HuGR wallet broker test reference", "wallet broker account", "stripe-prod-test only; test mode"),
        ("Starter test price", "Stripe price", "test-mode price_* only"),
    ),
    "neon": (
        ("Neon shadow database", "PostgreSQL database", "staging shadow branch; disposable tenant data only"),
    ),
}
FORBIDDEN = ("-----BEGIN ", "github_pat_", "ghp_", "gho_", "sk_live_", "whsec_")


def fail(message: str) -> None:
    raise ValueError(message)


def walk(value: Any, path: str = "packet") -> None:
    if isinstance(value, str):
        upper = value.upper()
        for marker in FORBIDDEN:
            if marker.upper() in upper:
                fail(f"{path} contains credential material")
    elif isinstance(value, dict):
        for key, child in value.items():
            walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            walk(child, f"{path}[{i}]")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def validate_packet(packet: dict[str, Any], manifest: dict[str, Any], workflow: str, bootstrap: str) -> bool:
    walk(packet)
    if packet.get("schema_version") != "i1650.real-integration-readiness.v2":
        fail("unsupported packet schema")
    if packet.get("issue") != 1650 or packet.get("credentialless") is not True:
        fail("packet is not bound to issue 1650 and credentialless")
    if packet.get("status") not in {"blocked", "ready"}:
        fail("packet status must be blocked or ready")
    if packet.get("redaction") != {"secret_values_recorded": False, "private_material_present": False}:
        fail("redaction contract drifted")
    policy = packet.get("dispatch_policy")
    required_policy = {"manual_only", "protected_ref", "environment", "approval_required", "dispatch_authorized", "production_mutation_allowed"}
    if not isinstance(policy, dict) or set(policy) != required_policy:
        fail("dispatch policy is incomplete")
    if policy != {**policy, "manual_only": True, "protected_ref": "refs/heads/main", "environment": "real-integration", "approval_required": True, "dispatch_authorized": False, "production_mutation_allowed": False}:
        fail("dispatch policy is not fail-closed")
    profiles = packet.get("profiles")
    manifest_profiles = manifest.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        fail("profile set drifted")
    if not isinstance(manifest_profiles, dict) or set(manifest_profiles) != set(PROFILES):
        fail("executor manifest profile set drifted")
    r2_required = manifest_profiles["r2"].get("required_env", ())
    if not isinstance(r2_required, list) or r2_required.count("R2_S3_SESSION_TOKEN") != 1:
        fail("R2 executor manifest must require exactly one derived session token")
    if 'R2_S3_SESSION_TOKEN: ""' not in workflow:
        fail("R2 session token must start empty in the executor workflow")
    if "secrets.R2_S3_SESSION_TOKEN" in workflow or "vars.R2_S3_SESSION_TOKEN" in workflow:
        fail("R2 session token must never use a persistent GitHub binding")
    for marker in (
        'python3 -S scripts/issue_2564_r2_temp_credentials.py',
        '"R2_S3_SESSION_TOKEN"] = credentials.session_token',
        'run(list(RUNNER), cwd=cwd, env=child_env',
    ):
        if marker not in (workflow if marker.startswith("python3") else bootstrap):
            fail("R2 session token must be issued in memory and passed only to the child runner")
    for profile in PROFILES:
        item = profiles[profile]
        if not isinstance(item, dict):
            fail(f"{profile} packet shape is invalid")
        expected = list(manifest_profiles[profile].get("required_env", ()))
        # The session token is a derived, per-run credential. It belongs in
        # the executor's runtime contract, never in persistent readiness bindings.
        if profile == "r2":
            expected.remove("R2_S3_SESSION_TOKEN")
        env = item.get("environment")
        if item.get("status") not in {"blocked", "ready"} or not isinstance(env, list):
            fail(f"{profile} packet shape is invalid")
        if [entry.get("name") for entry in env if isinstance(entry, dict)] != expected or any(not isinstance(entry, dict) for entry in env):
            fail(f"{profile} environment inventory does not match executor manifest")
        if any(set(entry) != {"name", "kind", "scope", "status"} for entry in env):
            fail(f"{profile} environment entry shape drifted")
        if any(entry["status"] not in {"missing", "verified"} for entry in env):
            fail(f"{profile} environment status is invalid")
        resources = item.get("resources")
        cleanup = item.get("cleanup")
        if not isinstance(resources, list) or not isinstance(cleanup, list) or not cleanup or any(not isinstance(x, str) or not x.strip() for x in cleanup):
            fail(f"{profile} resource/cleanup inventory is incomplete")
        if any(not isinstance(resource, dict) for resource in resources):
            fail(f"{profile} resource entry shape is invalid")
        actual_resources = [
            tuple(resource.get(key) for key in ("name", "kind", "scope"))
            for resource in resources
        ]
        if actual_resources != list(REQUIRED_RESOURCES[profile]):
            fail(f"{profile} resource identity, kind, or test-only scope differs from the reviewed profile")
        for resource in resources:
            if set(resource) != {"name", "kind", "scope", "status", "evidence_ref"}:
                fail(f"{profile} resource entry shape drifted")
            if any(not isinstance(resource[key], str) or not resource[key].strip() for key in ("name", "kind", "scope")):
                fail(f"{profile} resource identity is incomplete")
            if resource["status"] not in {"missing", "verified"}:
                fail(f"{profile} resource status is invalid")
            reference = resource["evidence_ref"]
            if resource["status"] == "verified" and (not isinstance(reference, str) or not reference.strip()):
                fail(f"{profile} verified resource has no redacted evidence reference")
            if resource["status"] == "missing" and reference is not None:
                fail(f"{profile} missing resource must not carry a verification reference")
        cleanup_receipt = item.get("cleanup_receipt")
        if not isinstance(cleanup_receipt, dict) or set(cleanup_receipt) != {"status", "owner_reviewed", "evidence_ref"}:
            fail(f"{profile} cleanup receipt shape is invalid")
        if cleanup_receipt["status"] not in {"missing", "verified"} or not isinstance(cleanup_receipt["owner_reviewed"], bool):
            fail(f"{profile} cleanup receipt status is invalid")
        receipt_ref = cleanup_receipt["evidence_ref"]
        if cleanup_receipt["status"] == "verified":
            if not cleanup_receipt["owner_reviewed"] or not isinstance(receipt_ref, str) or not receipt_ref.strip():
                fail(f"{profile} verified cleanup receipt lacks owner review or a redacted evidence reference")
        elif cleanup_receipt["owner_reviewed"] or receipt_ref is not None:
            fail(f"{profile} missing cleanup receipt must not claim review or evidence")
        blockers = item.get("blockers")
        if not isinstance(blockers, list) or any(not isinstance(x, str) or not x.strip() for x in blockers):
            fail(f"{profile} blockers are invalid")
        ready = item["status"] == "ready"
        if ready and (
            blockers
            or any(x["status"] != "verified" for x in env)
            or any(x["status"] != "verified" for x in resources)
            or cleanup_receipt["status"] != "verified"
        ):
            fail(f"{profile} claims ready without verified inputs, resources, and cleanup evidence")
    if packet["status"] == "ready" and any(profiles[p]["status"] != "ready" for p in PROFILES):
        fail("packet claims ready while a profile is blocked")

    # The real executor itself must remain a manual, protected, credentialed
    # lane. This audit does not run it and does not accept automatic triggers.
    if not re.search(r"(?m)^\s{2}workflow_dispatch:\s*(?:\{\})?\s*$", workflow):
        fail("real executor is missing workflow_dispatch")
    for event in ("pull_request", "pull_request_target", "push", "schedule", "workflow_call"):
        if re.search(rf"(?m)^\s{{2}}{event}:\s*", workflow):
            fail(f"real executor has automatic trigger: {event}")
    for marker in ("environment: ${{ inputs.profile == 'd1' && 'real-d1-2563' || 'real-integration' }}", 'test "$GITHUB_REF" = "refs/heads/main"', 'persist-credentials: false', 'python3 scripts/verify_real_ignored_harnesses.py'):
        if marker not in workflow:
            fail(f"real executor missing safety marker: {marker}")
    if re.search(r"(?m)^\s*if:\s*.*secrets\.", workflow):
        fail("workflow condition interpolates a secret")
    if any(token in workflow for token in ("CORELINK_PAT_SIGNING_KEY_HEX", "emit_e2e_seed", "PAT_PLAINTEXT", "SEED_SQL")):
        fail("forbidden PAT seed input reached the real executor")
    return packet["status"] == "ready"


def mutation_checks(packet: dict[str, Any], manifest: dict[str, Any], workflow: str, bootstrap: str) -> None:
    """Prove READY rejects missing resources and owner-reviewed cleanup evidence."""
    expect_rejected(
        "D1 routed to shared environment",
        packet,
        manifest,
        workflow.replace("environment: ${{ inputs.profile == 'd1' && 'real-d1-2563' || 'real-integration' }}", "environment: real-integration", 1), bootstrap,
    )
    missing_session = copy.deepcopy(manifest)
    missing_session["profiles"]["r2"]["required_env"].remove("R2_S3_SESSION_TOKEN")
    expect_rejected("manifest omits derived R2 session token", packet, missing_session, workflow, bootstrap)
    expect_rejected("persistent session-token binding", packet, manifest, workflow + "\n      R2_S3_SESSION_TOKEN: ${{ secrets.R2_S3_SESSION_TOKEN }}\n", bootstrap)
    expect_rejected("persistent session-token variable binding", packet, manifest, workflow + "\n      R2_S3_SESSION_TOKEN: ${{ vars.R2_S3_SESSION_TOKEN }}\n", bootstrap)
    expect_rejected("session token not initialized empty", packet, manifest, workflow.replace('R2_S3_SESSION_TOKEN: ""', "", 1), bootstrap)
    expect_rejected("session token not issued in memory", packet, manifest, workflow, bootstrap.replace('"R2_S3_SESSION_TOKEN"] = credentials.session_token', '"R2_S3_SESSION_TOKEN"] = os.environ["R2_S3_SESSION_TOKEN"]', 1))
    ready_packet = copy.deepcopy(packet)
    ready_packet["status"] = "ready"
    for profile in PROFILES:
        item = ready_packet["profiles"][profile]
        item["status"] = "ready"
        item["blockers"] = []
        for entry in item["environment"]:
            entry["status"] = "verified"
        for resource in item["resources"]:
            resource["status"] = "verified"
            resource["evidence_ref"] = "synthetic://resource-evidence"
        item["cleanup_receipt"] = {
            "status": "verified",
            "owner_reviewed": True,
            "evidence_ref": "synthetic://cleanup-receipt",
        }
    if not validate_packet(ready_packet, manifest, workflow, bootstrap):
        fail("complete synthetic readiness fixture did not validate")
    for profile in PROFILES:
        missing_resource = copy.deepcopy(ready_packet)
        resource = missing_resource["profiles"][profile]["resources"][0]
        resource["status"] = "missing"
        resource["evidence_ref"] = None
        expect_rejected(f"{profile} ready with a missing resource", missing_resource, manifest, workflow, bootstrap)
        missing_cleanup = copy.deepcopy(ready_packet)
        missing_cleanup["profiles"][profile]["cleanup_receipt"] = {
            "status": "missing",
            "owner_reviewed": False,
            "evidence_ref": None,
        }
        expect_rejected(f"{profile} ready without owner-reviewed cleanup", missing_cleanup, manifest, workflow, bootstrap)

    production_scope = copy.deepcopy(ready_packet)
    production_scope["profiles"]["d1"]["resources"][0]["scope"] = "production account; production writes allowed"
    expect_rejected("ready profile with production resource scope", production_scope, manifest, workflow, bootstrap)


def expect_rejected(label: str, packet: dict[str, Any], manifest: dict[str, Any], workflow: str, bootstrap: str) -> None:
    try:
        validate_packet(packet, manifest, workflow, bootstrap)
    except ValueError:
        return
    fail(f"readiness mutation was accepted: {label}")


def validate() -> bool:
    packet = load(PACKET)
    manifest = load(MANIFEST)
    workflow = WORKFLOW.read_text(encoding="utf-8")
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    mutation_checks(packet, manifest, workflow, bootstrap)
    return validate_packet(packet, manifest, workflow, bootstrap)

def main() -> int:
    try:
        ready = validate()
    except (OSError, ValueError) as exc:
        print(f"I1650 real integration readiness: CONTRACT FAILED: {exc}", file=sys.stderr)
        return 1
    if ready:
        print("I1650 real integration readiness: READY (owner approval and dispatch still required)")
    else:
        print("I1650 real integration readiness: BLOCKED (missing external resources/credentials/cleanup evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
