#!/usr/bin/env python3
"""Static fail-closed guard for #2666's BYOK synthetic teardown adapter."""
from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "crates/corelink-container/src/byok_control_transition.rs"
PROOF = ROOT / "crates/corelink-container/src/byok_control_transition_ownership_tests.rs"
WORKFLOW = ROOT / ".github/workflows/issue-2666-byok-teardown.yml"

control = CONTROL.read_text()
proof = PROOF.read_text()
workflow = WORKFLOW.read_text()

required_control = (
    "prepare_staging_synthetic_activation",
    "resolve_staging_synthetic_tenant",
    "validate_staging_synthetic_baseline",
    "staging_synthetic_tenant_ref",
    "StagingByokPendingTeardownLocator",
    "StagingByokTeardownError",
    "byok_pending_synthetic_v1",
    "source_generation=0",
    "activation.phase='aborted'",
    "config.state='inactive'",
    "gate.current_generation=0",
    "secret_history.tcs_wrapped IS NOT NULL",
)
required_proof = (
    "synthetic_tenant_ref_matches_worker_fixture_vector",
    "0106591dc8ab4f03e23dc578aeb3e20fb7436e93284540e0d457e448e92959f0",
    "exact_pending_synthetic_activation_cancels_and_reads_back_empty_baseline",
    "published_partial_synthetic_activation_is_not_cancelled_as_pending",
    "cancellation_batch_failure_rolls_back_without_success_or_purge",
    "cancellation_readback_residue_cannot_return_success",
    "synthetic_activation_rejects_wrong_reference_and_preexisting_byok_state",
    "wrong tenant cannot resolve the exact locator",
    "replayed cancellation cannot claim a new success",
)
required_workflow = (
    "pull_request:",
    "github.repository_id == vars.CORELINK_SERVER_REPO_ID",
    "github.event.pull_request.head.repo.full_name == github.repository",
    "ref: ${{ github.event.pull_request.head.sha }}",
    "EXPECTED_HEAD: ${{ github.event.pull_request.head.sha }}",
    "EXPECTED_BASE: ${{ github.event.pull_request.base.sha }}",
    "persist-credentials: false",
    "scripts/verify_issue_2666_byok_teardown.py",
    "cargo check --locked --package corelink-server --lib",
    "byok_control_transition::ownership_tests::",
)
missing = [value for value in required_control if value not in control]
missing += [value for value in required_proof if value not in proof]
missing += [value for value in required_workflow if value not in workflow]

adapter_start = control.find(
    "pub(crate) async fn cancel_staging_pending_activation_and_readback("
)
adapter_end = control.find(
    "async fn verify_staging_cancellation_readback(", adapter_start
)
if adapter_start < 0 or adapter_end < 0:
    missing.append("bounded BYOK cancellation adapter body")
else:
    adapter = control[adapter_start:adapter_end]
    for forbidden in ("self.shred(", "commit_activation_preemption(", "append_preemption_purge("):
        if forbidden in adapter:
            missing.append(f"forbidden teardown call {forbidden}")

expected_base = os.environ.get("EXPECTED_BASE")
expected_head = os.environ.get("EXPECTED_HEAD", "HEAD")
if expected_base:
    changed = subprocess.run(
        ["git", "diff", "--name-only", expected_base, expected_head],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    allowed = {
        ".github/workflows/issue-2666-byok-teardown.yml",
        "crates/corelink-container/src/byok_control_transition.rs",
        "crates/corelink-container/src/byok_control_transition_ownership_tests.rs",
        "scripts/verify_issue_2666_byok_teardown.py",
    }
    if set(changed) != allowed:
        missing.append("exact four-file #2666 ownership census")

if missing:
    print("issue-2666 BYOK teardown verification failed: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
print("issue-2666 BYOK teardown verification: PASS")
