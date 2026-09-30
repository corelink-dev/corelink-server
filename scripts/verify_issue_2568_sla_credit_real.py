#!/usr/bin/env python3
"""Static and redacted-receipt guards for the #2568 operator workflow."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/issue-2568-sla-credit-real.yml"
WORKER = "scripts/issue_2568_sla_credit_worker.ts"
OPERATOR = "scripts/issue_2568_sla_credit_real.py"
TESTS = "tests/test_issue_2568_sla_credit_real.py"
WP150_PATH = "docs/campaigns/remediation/wp150-workflow-ownership.md"
WP150_SHA256 = "cb9bb10177faf2fd578e1cc23163015f8c2913e360e8f2880dcd2afc71904e15"
SECRET_REGISTRY_PATH = "docs/internal/secrets-checklist.md"
SECRET_REGISTRY_SHA256 = "4d3cbad537f0ec07f00cdc34336f41000822c60febbf178dd9fe16a48ea52af7"
LEAF_PATHS = frozenset({
    ".actionlint.yaml",
    WORKFLOW,
    OPERATOR,
    WORKER,
    "scripts/verify_issue_2568_sla_credit_real.py",
    TESTS,
    WP150_PATH,
    SECRET_REGISTRY_PATH,
})
CORRECTION_PATHS = frozenset({
    WORKFLOW,
    OPERATOR,
    WORKER,
    "scripts/verify_issue_2568_sla_credit_real.py",
    TESTS,
    "apps/signup-worker/src/webhooks/sla_credit_cron.ts",
    "apps/signup-worker/tests/sla_credit_cron.test.ts",
})
FULL_SHA = re.compile(r"[0-9a-f]{40}")
SOURCE_SHA = os.environ.get("I2568_EXPECTED_SHA", "")
SOURCE_DIGESTS = {
    "apps/signup-worker/src/webhooks/sla_credit_cron.ts": "fd78c94df2358135f776ebdf5335b3d4c08d249540632b6262cae73506e5a9e3",
    "migrations/d1/0055_tenant_billing.sql": "f5420ceac080d92ae5dab05cf6209525d767de3408828bda46134e9323e8d93d",
    "migrations/d1/0117_sla_credit_ledger.sql": "658469f4102b6ef424af7dda29c8febcbf1058a677426be24da9306282c3454e",
}
PROVIDER_CREDENTIAL_BINDINGS = {
    "CF_I2568_API_TOKEN": "secrets.CF_I2568_API_TOKEN",
    "STRIPE_SECRET_KEY": "secrets.STRIPE_SECRET_KEY",
    "STRIPE_TEST_ACCOUNT_ID": "vars.STRIPE_TEST_ACCOUNT_ID",
    "I2568_PROVIDER_APPROVED": "vars.I2568_PROVIDER_APPROVED",
}
REQUIRED_WORKFLOW = (
    "workflow_dispatch:", "contents: read", "ubuntu-24.04", "timeout-minutes: 25",
    "stripe-test", "CF_I2568_API_TOKEN", "STRIPE_SECRET_KEY", "STRIPE_TEST_ACCOUNT_ID",
    "credentialless", "full-real", "expected_sha", "I2568_CONFIRMATION",
    "I2568_EXPECTED_SHA", "refs/heads/codex/support03-enterprise-credit-correction",
    "--candidate-diff-base", "--candidate-sha",
    "provider:", "static:", "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
)
REQUIRED_OPERATOR = (
    "rk_test_", "STRIPE_TEST_ACCOUNT_ID", "STRIPE_ACCOUNT_SHA256", "GITHUB_REF",
    "GITHUB_REPOSITORY", "livemode", "auto_advance", "pending_invoice_items_behavior",
    "cleanup", "Idempotency-Key", "metadata[corelink_issue]", "metadata[corelink_run]",
    "SOURCE_DIGESTS", "CF_ACCOUNT", "WORKER_NAME",
    "parent.invoice_item_details.invoice_item", "d1_migrations", "__scheduled",
    "workers_dev = false", "preview_urls = false", "I2568_TEST_OBSERVATION_JSON",
    "_create_wp2_customer", "_fresh_main_acceptance",
)
REQUIRED_WORKER = (
    "runSlaCreditSweep", "providerFromEnv", "recordCanonicalSlaObservation",
    'status: 404', "async scheduled", "result.ok", "result.failed !== 0", "result.blocked !== 0",
)
FORBIDDEN = (
    "sk_live_", "sk_test_", "workers_dev = true", "preview_urls = true",
    "stripe listen", "stripe fixtures", "card_number", "card[number]",
    "/v1/payment_intents", "/v1/subscriptions", "finalize", "send_invoice",
    "--ip 0.0.0.0", "0.0.0.0",
)
SENSITIVE_KEY = re.compile(r"(?i)(?:sk_(?:live|test)_|rk_(?:live|test)_)[A-Za-z0-9]{8,}")


class VerificationError(ValueError):
    pass


def validate_candidate_paths(paths: list[str] | tuple[str, ...] | set[str],
                             branch_ref: str = "refs/heads/codex/support03-issue-2568") -> None:
    expected = (CORRECTION_PATHS if branch_ref == "refs/heads/codex/support03-enterprise-credit-correction"
                else LEAF_PATHS if branch_ref == "refs/heads/codex/support03-issue-2568" else None)
    if expected is None or len(paths) != len(expected) or frozenset(paths) != expected:
        raise VerificationError("candidate diff does not match the exact owned leaf paths")


def validate_wp150_manifest(data: bytes, mode: int) -> None:
    if mode != 0o100644 or hashlib.sha256(data).hexdigest() != WP150_SHA256:
        raise VerificationError("WP150 manifest differs from the exact root-authorized content or mode")


def validate_secret_registry(data: bytes, mode: int) -> None:
    if mode != 0o100644 or hashlib.sha256(data).hexdigest() != SECRET_REGISTRY_SHA256:
        raise VerificationError("secret registry differs from the exact root-authorized content or mode")
    if b"`CF_I2568_API_TOKEN`" not in data:
        raise VerificationError("secret registry does not register the #2568 provider credential")


def validate_provider_credential_bindings(bindings: dict[str, str], references: list[str] | None = None) -> None:
    if bindings != PROVIDER_CREDENTIAL_BINDINGS:
        raise VerificationError("provider credential bindings contain an unregistered or missing credential")
    expected_references = set(PROVIDER_CREDENTIAL_BINDINGS.values())
    if references is not None and (len(references) != len(expected_references)
                                   or set(references) != expected_references):
        raise VerificationError("provider job references an unregistered or duplicate credential")


def validate_candidate_diff(root: Path, base_sha: str, candidate_sha: str) -> None:
    if not FULL_SHA.fullmatch(base_sha) or not FULL_SHA.fullmatch(candidate_sha):
        raise VerificationError("candidate diff base and head must be full lowercase commit SHAs")
    try:
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
        ancestor = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", base_sha, candidate_sha],
                                 check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        paths = subprocess.check_output(["git", "-C", str(root), "diff", "--name-only", "--no-renames",
                                         f"{base_sha}...{candidate_sha}"], text=True, stderr=subprocess.DEVNULL).splitlines()
        tree_entry = subprocess.check_output(["git", "-C", str(root), "ls-tree", candidate_sha, "--", WP150_PATH],
                                             text=True, stderr=subprocess.DEVNULL).strip().split()
        manifest_bytes = subprocess.check_output(["git", "-C", str(root), "show", f"{candidate_sha}:{WP150_PATH}"],
                                                 stderr=subprocess.DEVNULL)
        registry_entry = subprocess.check_output(["git", "-C", str(root), "ls-tree", candidate_sha, "--", SECRET_REGISTRY_PATH],
                                                 text=True, stderr=subprocess.DEVNULL).strip().split()
        registry_bytes = subprocess.check_output(["git", "-C", str(root), "show", f"{candidate_sha}:{SECRET_REGISTRY_PATH}"],
                                                 stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VerificationError("cannot establish the exact candidate diff against current main") from exc
    if head != candidate_sha or ancestor.returncode != 0:
        raise VerificationError("candidate head or current-main ancestry does not match the selected immutable SHA")
    validate_candidate_paths(paths, os.environ.get("GITHUB_REF", ""))
    if len(tree_entry) != 4 or tree_entry[0] != "100644" or tree_entry[3] != WP150_PATH:
        raise VerificationError("candidate WP150 manifest mode or path is not the authorized regular file")
    validate_wp150_manifest(manifest_bytes, int(tree_entry[0], 8))
    if len(registry_entry) != 4 or registry_entry[0] != "100644" or registry_entry[3] != SECRET_REGISTRY_PATH:
        raise VerificationError("candidate secret registry mode or path is not the authorized regular file")
    validate_secret_registry(registry_bytes, int(registry_entry[0], 8))


def need_text(root: Path, relative: str, required: tuple[str, ...]) -> str:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"missing or unsafe required file: {relative}")
    text = path.read_text(encoding="utf-8")
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise VerificationError(f"{relative}: missing required markers {missing!r}")
    return text


def validate_source_manifest(source: dict[str, str], digests: dict[str, str]) -> None:
    if not FULL_SHA.fullmatch(SOURCE_SHA) or source.get("source_sha") != SOURCE_SHA:
        raise VerificationError("frozen canonical source SHA mismatch")
    if digests != SOURCE_DIGESTS:
        raise VerificationError("frozen canonical source digest manifest mismatch")


def validate_receipt(receipt: dict[str, Any]) -> None:
    if receipt.get("issue") != 2568 or receipt.get("redacted") is not True:
        raise VerificationError("receipt issue/redaction marker mismatch")
    if receipt.get("mode") != "test":
        raise VerificationError("receipt mode is not test")
    def check_keys(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                lowered = str(key).casefold()
                if lowered in {"raw_response", "stripe_secret_key", "cf_i2568_api_token", "token", "credential_value"}:
                    raise VerificationError("receipt contains a forbidden raw response or credential field")
                check_keys(nested)
        elif isinstance(value, list):
            for nested in value:
                check_keys(nested)
    check_keys(receipt)
    flattened = json.dumps(receipt, sort_keys=True)
    if SENSITIVE_KEY.search(flattened):
        raise VerificationError("receipt contains a Stripe secret value")


def validate_provider_receipt(receipt: dict[str, Any]) -> None:
    validate_receipt(receipt)
    if receipt.get("schema") != "corelink.issue-2568.sla-credit-real.v1":
        raise VerificationError("provider receipt schema is not the actual #2568 format")
    if receipt.get("status") != "closure_ready_pending_root_credential_revocation":
        raise VerificationError("provider receipt is partial or did not reach the closure-ready state")
    if not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("candidate_sha", ""))):
        raise VerificationError("provider receipt candidate SHA is missing")
    operator = receipt.get("operator")
    if (not isinstance(operator, dict) or operator.get("branch") != "main"
            or operator.get("head_sha") != receipt.get("candidate_sha")
            or not re.fullmatch(r"[0-9a-f]{64}", str(operator.get("operator_file_sha256", "")))):
        raise VerificationError("provider receipt does not bind the exact operator implementation")
    if receipt.get("canonical_source_sha") != receipt.get("candidate_sha") or receipt.get("canonical_source_sha") != SOURCE_SHA or receipt.get("canonical_source_digests") != SOURCE_DIGESTS:
        raise VerificationError("provider receipt canonical source identity is incomplete")
    if receipt.get("stripe_test_account_id_sha256") != "e9678dceccdaa37a7259379096e82875f6ae0c694f9a461a28691c79eceb33ad":
        raise VerificationError("provider receipt Stripe account binding hash is incorrect")
    checks = receipt.get("checks")
    required_checks = {"gate_false_no_provider_effect", "canonical_credit_applied", "replay_singular", "next_invoice_reconciled"}
    if not isinstance(checks, dict) or not required_checks.issubset(checks) or any(checks.get(key) != "pass" for key in required_checks):
        raise VerificationError("provider receipt is missing complete acceptance checks")
    capability = receipt.get("capability_probe")
    cap_checks = capability.get("checks") if isinstance(capability, dict) else None
    required_cap_checks = {"stripe_account_binding", "restricted_test_key_prefix", "owned_pending_item_included_once"}
    if (not isinstance(capability, dict) or capability.get("cleanup_succeeded") is not True
            or not isinstance(cap_checks, dict) or not required_cap_checks.issubset(cap_checks)
            or any(cap_checks.get(key) != "pass" for key in required_cap_checks)
            or capability.get("provider_effects") != [
                "owned_test_customer_created", "owned_negative_one_usd_minor_invoice_item_created",
                "owned_nonadvancing_draft_invoice_created",
            ]
            or capability.get("cleanup") != {"attempted": True, "succeeded": True, "absence_verified": True}
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", str(capability.get(key, "")))
                   for key in ("customer_sha256", "invoice_item_sha256", "draft_invoice_sha256"))):
        raise VerificationError("provider receipt lacks actual WP1 capability and cleanup proof")
    worker = receipt.get("persistent_worker")
    if (not isinstance(worker, dict) or worker.get("workers_dev") is not False
            or worker.get("preview_urls") is not False or worker.get("gate") is not False
            or worker.get("routes") != [] or worker.get("crons") != []
            or worker.get("source_sha") != SOURCE_SHA
            or worker.get("operator_sha") != receipt.get("candidate_sha")
            or worker.get("operator_file_sha256") != operator.get("operator_file_sha256")
            or worker.get("bindings_verified") is not True
            or worker.get("route_configuration") != "wrangler_config_has_no_routes_or_services"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(worker.get("version_id_sha256", "")))):
        raise VerificationError("provider receipt persistent Worker was not private and gate-false")
    invocations = receipt.get("private_invocations")
    if (not isinstance(invocations, list) or len(invocations) != 3
            or [row.get("gate") for row in invocations] != [False, True, True]
            or invocations[2].get("replay") is not True
            or len({row.get("session_sha256") for row in invocations}) != 3
            or any(row.get("result") != "scheduled_http_200"
                   or row.get("process_terminated") is not True
                   or row.get("canonical_source_sha") != SOURCE_SHA
                   or row.get("operator_sha") != receipt.get("candidate_sha")
                   or row.get("persistent_worker_version_sha256") != worker.get("version_id_sha256")
                   or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("session_sha256", "")))
                   for row in invocations)):
        raise VerificationError("provider receipt lacks gate-false, enabled and exact replay private invocations")
    credit = receipt.get("credit")
    if not isinstance(credit, dict) or (credit.get("service_period") != "2026-08" or credit.get("tier") != "enterprise"
            or credit.get("monthly_fee_minor") != 10000 or credit.get("availability_percent") != 99.49
            or credit.get("credit_percent") != 5 or credit.get("amount_minor") != 500
            or credit.get("currency") != "USD" or credit.get("gate_false_provider_effects") != 0):
        raise VerificationError("provider receipt does not prove canonical credit arithmetic and disabled-gate negative")
    replay = receipt.get("replay")
    if (not isinstance(replay, dict) or replay.get("same_observation") is not True
            or replay.get("same_canonical_sweep") is not True or replay.get("provider_objects") != 1
            or replay.get("d1_counts_before") != replay.get("d1_counts_after")):
        raise VerificationError("provider receipt lacks singular exact replay proof")
    invoice = receipt.get("invoice")
    if (not isinstance(invoice, dict) or invoice.get("status") != "draft" or invoice.get("auto_advance") is not False
            or invoice.get("credit_line_count") != 1 or invoice.get("credit_line_amount_minor") != -500):
        raise VerificationError("provider receipt lacks the next nonadvancing draft invoice reconciliation")
    d1 = receipt.get("d1")
    counts = d1.get("row_counts") if isinstance(d1, dict) else None
    if (not isinstance(d1, dict) or d1.get("name") != "corelink-i2568-sla-credit-test-20260928"
            or d1.get("account") != "51284495e71acdb5a7677e7383ab026b"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(d1.get("uuid_sha256", "")))
            or not isinstance(counts, dict) or counts.get("sla_monthly_observations") != 1
            or counts.get("sla_monthly_measurements") != 1 or counts.get("sla_credit_ledger") != 1
            or counts.get("sla_credit_outbox") != 1 or counts.get("sla_credit_reconciliation") != 1
            or counts.get("sla_credit_audit_events") != 2
            or d1.get("migration_history") != ["0055_tenant_billing", "0117_sla_credit_ledger"]
            or d1.get("migration_sha256") != {
                "0055_tenant_billing.sql": "f5420ceac080d92ae5dab05cf6209525d767de3408828bda46134e9323e8d93d",
                "0117_sla_credit_ledger.sql": "658469f4102b6ef424af7dda29c8febcbf1058a677426be24da9306282c3454e",
            }):
        raise VerificationError("provider receipt lacks exact D1 migration and row-count proof")
    cleanup = receipt.get("cleanup")
    if (not isinstance(cleanup, dict) or cleanup.get("succeeded") is not True or cleanup.get("gate_final") is not False
            or cleanup.get("private_preview_sessions_terminated") is not True
            or cleanup.get("pre_cleanup_receipt_written") is not True
            or cleanup.get("credential_revocation") != "root_action_required"):
        raise VerificationError("provider receipt lacks fail-closed final cleanup state")
    stripe_cleanup = cleanup.get("stripe_objects")
    cf_cleanup = cleanup.get("cloudflare_targets")
    if (not isinstance(stripe_cleanup, dict) or stripe_cleanup.get("succeeded") is not True or stripe_cleanup.get("absence_verified") is not True
            or not isinstance(cf_cleanup, dict) or cf_cleanup.get("worker_absent") is not True or cf_cleanup.get("database_absent") is not True
            or cleanup.get("private_runtime_files_removed") is not True
            or stripe_cleanup.get("attempted") is not True
            or cf_cleanup.get("worker_deleted") is not True
            or cf_cleanup.get("database_deleted") is not True):
        raise VerificationError("provider receipt does not prove owned-resource cleanup and absence")
    timestamps = receipt.get("timestamps_utc")
    if (not isinstance(timestamps, dict) or not timestamps.get("started")
            or not timestamps.get("provider_proof_complete") or not timestamps.get("finished")):
        raise VerificationError("provider receipt lacks actual bounded run timestamps")


def verify(root: Path = ROOT) -> None:
    if not FULL_SHA.fullmatch(SOURCE_SHA):
        raise VerificationError("exact protected-main source SHA is missing")
    workflow = need_text(root, WORKFLOW, REQUIRED_WORKFLOW)
    operator = need_text(root, OPERATOR, REQUIRED_OPERATOR)
    worker = need_text(root, WORKER, REQUIRED_WORKER)
    runtime = need_text(root, "apps/signup-worker/src/webhooks/sla_credit_cron.ts", (
        "CONTRACT_TIERS", "evaluateSlaCredit", "enterprise: { target: 99.95 }",
        "LEFT JOIN sla_monthly_measurements AS m", "tier_not_in_launch_sla",
    ))
    tier_table = re.search(r"const CONTRACT_TIERS[^=]*=\s*\{(?P<body>.*?)\n\};", runtime, re.DOTALL)
    if (not tier_table or re.search(r"\b(?:free|solo|starter|pro|max)\s*:", tier_table.group("body"))
            or 'observation.tier !== "enterprise"' not in worker
            or '"tier": "enterprise"' not in operator
            or '"tier": "starter"' in operator):
        raise VerificationError("Enterprise-only runtime/operator policy guard drifted")
    test_source = need_text(root, "apps/signup-worker/tests/sla_credit_cron.test.ts", (
        'tier: "enterprise"', 'for (const tier of ["free", "solo", "starter", "pro", "max"])',
        'expect(db.ledger.size).toBe(0)', 'expect(db.outbox.size).toBe(0)',
        'expect(applyCredit).not.toHaveBeenCalled()',
        'blocks legacy due credits for all excluded tiers before replay or provider I/O',
        'expect(reconcileCredit).not.toHaveBeenCalled()',
    ))
    if test_source.count('for (const tier of ["free", "solo", "starter", "pro", "max"])') < 3:
        raise VerificationError("evaluator, new-sweep, and legacy-retry negatives are required")
    need_text(root, TESTS, (
        "test_wrong_account_rejected_before_provider_request",
        "test_live_or_unrestricted_key_rejected_before_provider_request",
        "test_foreign_customer_cleanup_refused_without_delete",
        "test_cloudflare_preexisting_worker_target_fails_without_delete",
        "test_cloudflare_auth_failure_fails_without_delete",
        "test_stripe_invoice_line_shapes_are_mutually_consistent",
        "test_partial_receipt_cannot_claim_full_provider_pass",
        "test_candidate_gate_accepts_exact_eight_and_rejects_missing_or_foreign",
        "test_wp150_manifest_gate_rejects_arbitrary_content_or_mode",
        "test_secret_registry_registers_i2568_and_denies_unknown_credential",
        "test_detached_candidate_uses_immutable_sha_and_github_ref",
        "test_stale_protected_main_fails_before_provider_write",
        "test_main_advance_before_wp2_customer_prevents_stripe_write",
        "test_main_advance_before_final_acceptance_denies_closure",
        "test_main_advance_before_replay_prevents_invocation",
        "test_main_advance_before_draft_invoice_prevents_stripe_write",
    ))
    expected_leaf_paths = {
        ".actionlint.yaml", WORKFLOW, OPERATOR, WORKER,
        "scripts/verify_issue_2568_sla_credit_real.py", TESTS,
        WP150_PATH,
        SECRET_REGISTRY_PATH,
    }
    if LEAF_PATHS != expected_leaf_paths:
        raise VerificationError("frozen eight-path candidate catalog drift")
    manifest = root / WP150_PATH
    if manifest.is_symlink() or not manifest.is_file():
        raise VerificationError("missing or unsafe root-authorized WP150 manifest")
    validate_wp150_manifest(manifest.read_bytes(), manifest.stat().st_mode & 0o777 | 0o100000)
    secret_registry = root / SECRET_REGISTRY_PATH
    if secret_registry.is_symlink() or not secret_registry.is_file():
        raise VerificationError("missing or unsafe root-authorized secret registry")
    validate_secret_registry(secret_registry.read_bytes(), secret_registry.stat().st_mode & 0o777 | 0o100000)
    for marker in FORBIDDEN:
        if marker in workflow or marker in operator or marker in worker:
            raise VerificationError(f"forbidden provider surface present: {marker}")
    if re.search(r"(?m)^\s*schedule\s*:", workflow):
        raise VerificationError("provider workflow must be manual only")
    if re.search(r"(?m)^\s*(?:push|pull_request)\s*:", workflow):
        raise VerificationError("provider workflow must not run on push or pull_request")
    if "environment: stripe-test" not in workflow:
        raise VerificationError("provider operation is not bound to stripe-test")
    if workflow.count('ref: ${{ inputs.expected_sha }}') != 4 or 'ref: 5fabd93e98d805a39319fcb6a22c9ee5267fafd4' in workflow:
        raise VerificationError("canonical checkouts must use the exact candidate SHA")
    static = re.search(r"(?ms)^  static:\n(.*?)(?=^  provider:\n)", workflow)
    provider = re.search(r"(?ms)^  provider:\n(.*)$", workflow)
    if not static or not provider:
        raise VerificationError("whole-leaf static and provider jobs are required")
    static_text = static.group(1)
    if ("inputs.mode == 'credentialless'" not in static_text
            or "refs/heads/codex/support03-issue-2568" not in static_text
            or "refs/heads/codex/support03-enterprise-credit-correction" not in static_text
            or "inputs.mode == 'full-real'" not in static_text
            or "refs/heads/main" not in static_text
            or "only frozen leaf paths for pre-merge checks" not in static_text
            or "exact fresh protected main for post-merge provider mode" not in static_text):
        raise VerificationError("static job must separate pre-merge credentialless and post-merge main checks")
    if "secrets." in static.group(1) or "vars." in static.group(1) or "environment:" in static.group(1):
        raise VerificationError("credentialless job is bound to provider authority")
    provider_text = provider.group(1)
    if ("needs: static" not in provider_text or "inputs.mode == 'full-real'" not in provider_text
            or "refs/heads/main" not in provider_text
            or "exact fresh protected main before provider work" not in provider_text
            or "timeout-minutes: 25" not in provider_text or "cancel-in-progress: false" not in workflow):
        raise VerificationError("provider job is not serial, full-real-only, or bounded")
    observed_credential_bindings = {
        name: f"{namespace}.{reference}"
        for name, namespace, reference in re.findall(
            r"(?m)^\s+([A-Z][A-Z0-9_]+):\s+\$\{\{\s*(secrets|vars)\.([A-Z][A-Z0-9_]*)\s*\}\}\s*$",
            provider_text,
        )
    }
    observed_credential_references = [
        f"{namespace}.{reference}"
        for namespace, reference in re.findall(r"\$\{\{\s*(secrets|vars)\.([A-Z][A-Z0-9_]*)\s*\}\}", provider_text)
    ]
    validate_provider_credential_bindings(observed_credential_bindings, observed_credential_references)
    if "CF_I2568_API_TOKEN" in static.group(1) or "STRIPE_SECRET_KEY" in static.group(1):
        raise VerificationError("provider credentials are reachable from the credentialless job")
    if "--ip 127.0.0.1" not in operator and '"127.0.0.1"' not in operator:
        raise VerificationError("private scheduled transport is not loopback-only")
    if "workers/subdomain" not in operator or "preview_urls" not in operator:
        raise VerificationError("account subdomain and preview topology preflight is missing")
    if ("customer = _create_wp2_customer(expected_sha, stripe, owned)" not in operator
            or "if _fresh_main_acceptance(receipt, expected_sha):" not in operator
            or "replay_session = _with_fresh_main(expected_sha, _scheduled_preview" not in operator
            or "invoice = _with_fresh_main(expected_sha, stripe.request" not in operator):
        raise VerificationError("fresh-main checks are not wired to provider effects and final closure acceptance")
    for relative in SOURCE_DIGESTS:
        path = root / "canonical-source" / relative
        # Credentialless mode verifies the separate frozen checkout when it is
        # present; static CI itself checks the pinned checkout declaration.
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_DIGESTS[relative]:
            raise VerificationError(f"canonical source digest drift: {relative}")


def self_test() -> None:
    validate_source_manifest({"source_sha": SOURCE_SHA}, dict(SOURCE_DIGESTS))
    for source, digests in (
        ({"source_sha": "0" * 40}, dict(SOURCE_DIGESTS)),
        ({"source_sha": SOURCE_SHA}, {**SOURCE_DIGESTS, "migration.sql": "0" * 64}),
    ):
        try:
            validate_source_manifest(source, digests)
        except VerificationError:
            pass
        else:
            raise VerificationError("source drift negative control was ineffective")
    valid = {"issue": 2568, "mode": "test", "redacted": True, "checks": {}}
    validate_receipt(valid)
    for key, value in (("raw_response", {"secret": "private"}), ("stripe_secret_key", "rk_test_badbadbad")):
        try:
            validate_receipt({**valid, key: value})
        except VerificationError:
            pass
        else:
            raise VerificationError(f"receipt negative control was ineffective: {key}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--candidate-diff-base")
    parser.add_argument("--candidate-sha")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
        verify(args.root.resolve())
        if (args.candidate_diff_base is None) != (args.candidate_sha is None):
            raise VerificationError("candidate diff validation requires both base and candidate SHAs")
        if args.candidate_diff_base is not None and args.candidate_sha is not None:
            validate_candidate_diff(args.root.resolve(), args.candidate_diff_base, args.candidate_sha)
        if args.receipt:
            value = json.loads(args.receipt.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise VerificationError("receipt must be a JSON object")
            validate_provider_receipt(value)
    except (OSError, json.JSONDecodeError, VerificationError) as exc:
        print(f"#2568 SLA credit verifier: FAIL: {exc}", file=sys.stderr)
        return 1
    print("#2568 SLA credit verifier: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
