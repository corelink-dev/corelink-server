#!/usr/bin/env python3
"""Static checks for B-251's hosted provenance boundary."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
D02_COMMIT = "f88c6ca41868f6a02e78ba9f4357d3abf67da4be"
SAME_REPOSITORY = "${{ github.repository }}"


def verify(root: Path = ROOT) -> None:
    workflow = (root / ".github/workflows/b251-d03-read-only-probe.yml").read_text()
    collector = (root / "scripts/collect_b251_provenance.py").read_text()
    operation = (root / "crates/corelink-billing/tests/b251_identity_operation.rs").read_text()
    probe = (root / "scripts/run_b251_latency_probe.py").read_text()
    for forbidden in ("d02_seed:", "d02_failure:", "d02_blob:", "d03_seed:", "d03_failure:", "d03_blob:"):
        if forbidden in workflow:
            raise ValueError(f"workflow still accepts manual identity input: {forbidden}")
    required = (
        "workflow_dispatch:", "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'", "github.ref_protected == true",
        "ref: ${{ github.event.pull_request.head.sha }}",
        D02_COMMIT,
        "collect_b251_provenance.py",
        "test_b251_provenance_contract.py",
    )
    for text in required:
        if text not in workflow:
            raise ValueError(f"workflow contract missing {text}")
    # The D02 commit SHA is the integrity pin; the checkout must fetch it from
    # the repository running the workflow. A literal owner/name would keep
    # pointing at an organisation that can disappear or be re-registered.
    live_lines = [line.strip() for line in workflow.splitlines() if not line.lstrip().startswith("#")]
    repositories = [line.split(":", 1)[1].strip() for line in live_lines if line.startswith("repository:")]
    d02_refs = [line for line in live_lines if line == f"ref: {D02_COMMIT}"]
    if not d02_refs:
        raise ValueError("workflow no longer checks out the D02 producer commit")
    if repositories != [SAME_REPOSITORY] * len(d02_refs):
        raise ValueError(
            f"every D02 producer checkout must set repository: {SAME_REPOSITORY}; found {repositories}"
        )
    for forbidden in ("id-token: write", "attestations: write", "attest-build-provenance@"):
        if forbidden in workflow:
            raise ValueError(f"B-251 workflow exceeds read-only permissions: {forbidden}")
    for text in (
        "cargo", "B251_OPERATION_TRANSCRIPT_HEX", "D02_COMMIT", "OPERATION_SEED_HEX", "mutation"
    ):
        if text not in collector:
            raise ValueError(f"collector contract missing {text}")
    for text in ("try_acquire", "InMemoryAtomicQuotaChecker", "% 900", "1_000 +", "1 +"):
        if text not in operation:
            raise ValueError(f"checker operation contract missing {text}")
    if 'record["production_latency_measured"] is not False' not in probe:
        raise ValueError("existing latency receipt must retain its production boundary")


if __name__ == "__main__":
    verify()
    print("B-251 provenance contract: PASS")
