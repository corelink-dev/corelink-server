#!/usr/bin/env python3
"""Validate the explicit CI pack catalog and its fail-closed invariants."""

from __future__ import annotations

import argparse
import hashlib
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs/internal/ci-issue-packs.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED = {
    "pack_id",
    "issue",
    "changed_surfaces",
    "required_focused_jobs",
    "focused_checks",
    "admission_checks",
    "negative_controls",
    "exact_sha",
    "budget",
    "escalation_policy",
    "global_suite_escalation_triggers",
    "merge_evidence",
}
JOB_IDS = {
    "issue-pack",
}
CHECK_IDS = {
    "actionlint",
    "ci-pack-contract",
    "rust-worker-three-arm",
    "python-mutants-receipt",
    "python-mutants-shards",
    "cargo-mutants-v27-inventory",
    "python-b170-owner-actions",
    "rust-b122-phase-regions",
    "python-sla-credit-real",
}
REQUIRED_PACK_CHECKS = {
    "issue-2440-ci-scoping": {"actionlint", "ci-pack-contract"},
    "issue-2437-worker-three-arm": {"ci-pack-contract", "rust-worker-three-arm"},
    "issue-1948-mutants-receipt": {"actionlint", "ci-pack-contract", "python-mutants-receipt"},
    "issue-2457-mutants-shards": {"actionlint", "ci-pack-contract", "python-mutants-shards", "cargo-mutants-v27-inventory"},
    "issue-1677-b170-owner-actions": {"ci-pack-contract", "python-b170-owner-actions"},
    "issue-1667-phase-regions": {"actionlint", "ci-pack-contract", "rust-b122-phase-regions"},
}
REQUIRED_PACK_CHECKS["issue-2568-sla-credit-real"] = {"actionlint", "ci-pack-contract", "python-sla-credit-real"}
REQUIRED_PACK_JOBS = {pack_id: {"issue-pack"} for pack_id in REQUIRED_PACK_CHECKS}
TARGET_BASE_RULE = (
    "required workflow_dispatch input target_base_sha; must equal merge-base(candidate_sha, "
    "trusted_main_sha) and differ from candidate_sha; bootstrap when candidate_sha equals "
    "trusted_main_sha uses candidate first parent"
)


SLA_CREDIT_HASHES = {'.actionlint.yaml': '2e1ad216236818322adb7baed2e25dcc836cd7a030493fd799f4d4fc06702576',
 '.github/workflows/issue-2568-sla-credit-real.yml': '67031ad29cdcbef2efa7d6385c298f3aa240440545db81e53d490b9df58ee195',
 'docs/campaigns/remediation/wp150-workflow-ownership.md': 'cb9bb10177faf2fd578e1cc23163015f8c2913e360e8f2880dcd2afc71904e15',
 'docs/internal/secrets-checklist.md': '4d3cbad537f0ec07f00cdc34336f41000822c60febbf178dd9fe16a48ea52af7',
 'scripts/issue_2568_sla_credit_real.py': '3a41577dec203d3fa4f18924de6af92224ca5ae35f5b2231551e25a00b8ca0d2',
 'scripts/issue_2568_sla_credit_worker.ts': '4cf891a4ba1030e03db9401df4a312c75204a08bf7be774a8f634a1bc89e2d62',
 'scripts/verify_issue_2568_sla_credit_real.py': 'bca4fc394e00694eb2bf95e2418a5f90005cace3c426133e862eae868d20bab4',
 'tests/test_issue_2568_sla_credit_real.py': '392514070165cf8442f41c82237000831ae313c20d6a0d92d70c0b5dc0214df5'}


def validate_workflow_contract(workflow_text: str) -> list[str]:
    actionlint_condition = "if: inputs.pack_id == 'issue-2440-ci-scoping' || inputs.pack_id == 'issue-2437-worker-three-arm' || inputs.pack_id == 'issue-1948-mutants-receipt' || inputs.pack_id == 'issue-2457-mutants-shards' || inputs.pack_id == 'issue-1667-phase-regions' || inputs.pack_id == 'issue-2568-sla-credit-real'"
    required = (
        "github.ref == 'refs/heads/main' && github.ref_protected",
        "path: candidate",
        'ACTUAL_SHA="$(git -C candidate rev-parse HEAD)"',
        "issue-2440-ci-scoping|issue-2437-worker-three-arm|issue-1948-mutants-receipt|issue-2457-mutants-shards|issue-1677-b170-owner-actions|issue-1667-phase-regions|issue-2568-sla-credit-real",
        "id: sla-credit-authorization",
        "id: python-sla-credit-real",
        "--pack-id issue-2568-sla-credit-real --candidate-root candidate --run-self-test",
        "python3 -I scripts/backlog_verify.py",
        "python3 -I scripts/verify_i2176_grpc_deny_gate.py",
        "python3 -I scripts/verify_i2574_grpc_diagnostic_policy.py",
        "ref: 5fabd93e98d805a39319fcb6a22c9ee5267fafd4",
        "path: canonical-source",
        "verify-source --source-root ../canonical-source",
        "verify-wrapper --source-root ../canonical-source",
        "python3 -I scripts/verify_issue_2568_sla_credit_real.py --self-test",
        "python3 -I tests/test_issue_2568_sla_credit_real.py",
        "issue-2568-sla-credit-real) workflows=(.github/workflows/issue-2568-sla-credit-real.yml) ;;",
        "id: actionlint",
        "id: ci-pack-contract",
        "id: rust-worker-three-arm",
        "id: python-mutants-receipt",
        "id: python-mutants-shards",
        "id: cargo-mutants-v27-inventory",
        "id: python-b170-owner-actions",
        "id: rust-b122-phase-regions",
        actionlint_condition,
        "if: inputs.pack_id == 'issue-2437-worker-three-arm'",
        "if: inputs.pack_id == 'issue-1948-mutants-receipt'",
        "if: inputs.pack_id == 'issue-2457-mutants-shards'",
        "if: inputs.pack_id == 'issue-1677-b170-owner-actions'",
        "if: inputs.pack_id == 'issue-1667-phase-regions'",
        "timeout-minutes: 15",
        "timeout-minutes: 10",
        "cargo test --package corelink-worker --features tower-middleware --lib three_arm_ -- --nocapture",
        "python3 -m unittest -q tests/test_i1863_mutants_hosted_receipt.py",
        "python3 -m scripts.verify_i1863_mutants_hosted",
        "python3 -m scripts.verify_i1666_mutants_evidence",
        "tests/test_i2457_mutants_shards.py",
        "cargo mutants --version | grep -Fx 'cargo-mutants 27.0.0'",
        "cargo mutants --workspace --no-config --no-shuffle --minimum-test-timeout=600 --sharding=round-robin --shard 0/1 --list --json > \"${RUNNER_TEMP}/full-inventory.json\"",
        "python3 scripts/verify_i2457_mutants_shards.py build-inventory",
        "python3 -S scripts/verify_b170_owner_actions.py",
        "grep -Fq 'docs/customer/dpa-onboarding.md'",
        "grep -Fq 'lighthouse enterprise customer'",
        "python3 -S scripts/verify_i1667_b122_phase_regions.py",
        "tests/test_i1667_b122_phase_regions.py",
        "cargo test --locked --package corelink-container --lib nested_reentry_of_the_same_phase_records_once -- --nocapture",
        "cargo test --locked --package corelink-container --lib put_records_the_store_phase_exactly_once -- --nocapture",
        "cargo test --locked --package corelink-container --lib get_records_the_store_phase_across_spawn_blocking -- --nocapture",
        "--candidate-root candidate",
        "TRUSTED_MAIN_SHA: ${{ github.sha }}",
        '--trusted-main-sha "$TRUSTED_MAIN_SHA"',
        'if [[ "$PACK_ID" == issue-2440-ci-scoping && "$ACTUAL_SHA" == "$TRUSTED_MAIN_SHA" ]]; then',
        'EXPECTED_BASE="$(git -C candidate rev-parse HEAD^)"',
        '[[ "$TARGET_BASE_SHA" == "$EXPECTED_BASE" ]]',
    )
    errors = [f"central workflow is missing required contract: {item}" for item in required if item not in workflow_text]
    if workflow_text.find("id: sla-credit-authorization") >= workflow_text.find("id: python-sla-credit-real"):
        errors.append("SLA credit authorization must precede candidate execution")
    normalized_workflow = re.sub(r"[ \t]*\\[ \t]*\r?\n[ \t]*", " ", workflow_text)
    cargo_mutants_lines = [line.strip() for line in normalized_workflow.splitlines() if "cargo mutants" in line]
    expected_cargo_mutants_lines = [
        "cargo mutants --version | grep -Fx 'cargo-mutants 27.0.0'",
        "cargo mutants --workspace --no-config --no-shuffle --minimum-test-timeout=600 --sharding=round-robin --shard 0/1 --list --json > \"${RUNNER_TEMP}/full-inventory.json\"",
    ]
    if cargo_mutants_lines != expected_cargo_mutants_lines:
        errors.append("central workflow must run only the pinned denominator-one v27 inventory commands")
    forbidden = (
        "--baseline",
        "upload-artifact",
        "download-artifact",
        "repo-token",
        "secrets.",
        "github.token",
        "GITHUB_TOKEN",
        "id-token:",
        "aws-actions/",
        "azure/",
        "google-github-actions/",
        "cloudflare/",
    )
    found = [token for token in forbidden if token in workflow_text]
    if found:
        errors.append("central workflow contains forbidden inventory-pack controls: " + ", ".join(found))
    if workflow_text.count(actionlint_condition) != 2:
        errors.append("issue packs must run actionlint at both install and validation steps")
    triggers = mapping_child_keys(workflow_text, "on")
    if triggers != ["workflow_dispatch"]:
        errors.append(f"central issue pack workflow must have only workflow_dispatch triggers; found {triggers}")
    return errors


def mapping_child_keys(document: str, parent_key: str) -> list[str]:
    """Return direct two-space-indented keys from a top-level YAML mapping block."""
    lines = document.splitlines()
    parent_line = re.compile(rf"^{re.escape(parent_key)}:\s*(?:#.*)?$")
    child_line = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):(?:\s|$)")
    start = next((index for index, line in enumerate(lines) if parent_line.fullmatch(line)), None)
    if start is None:
        return []
    keys: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        match = child_line.match(line)
        if match:
            keys.append(match.group(1))
    return keys


def valid_sha_pair(expected: str, actual: str) -> bool:
    return bool(SHA_RE.fullmatch(expected) and SHA_RE.fullmatch(actual) and expected == actual)


def target_base_matches(
    target_base: str,
    candidate: str,
    trusted_main: str,
    merge_base: str,
    pack_id: str,
    first_parent: str | None = None,
) -> bool:
    if not all(SHA_RE.fullmatch(value) for value in (target_base, candidate, trusted_main, merge_base)):
        return False
    if target_base == candidate:
        return False
    if pack_id == "issue-2440-ci-scoping" and candidate == trusted_main:
        return bool(first_parent and SHA_RE.fullmatch(first_parent) and target_base == first_parent)
    return target_base == merge_base


def select_pack(catalog: dict, pack_id: str) -> list[dict]:
    return [pack for pack in catalog.get("packs", []) if isinstance(pack, dict) and pack.get("pack_id") == pack_id]


def paths_outside_pack(changed: list[str], surfaces: list[str]) -> list[str]:
    return [path for path in changed if not any(fnmatch.fnmatchcase(path, pattern) for pattern in surfaces)]


def validate(catalog: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        return ["unsupported catalog schema"]
    packs = catalog.get("packs")
    if not isinstance(packs, list) or not packs:
        return ["packs must be a non-empty list"]
    seen: set[str] = set()
    for index, pack in enumerate(packs):
        prefix = f"packs[{index}]"
        if not isinstance(pack, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = REQUIRED - pack.keys()
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(sorted(missing))}")
            continue
        pack_id = pack["pack_id"]
        if not isinstance(pack_id, str) or not re.fullmatch(r"issue-[0-9]+-[a-z0-9-]+", pack_id):
            errors.append(f"{prefix}.pack_id is invalid")
        elif pack_id in seen:
            errors.append(f"duplicate pack_id: {pack_id}")
        else:
            seen.add(pack_id)
        if not isinstance(pack["issue"], int) or pack["issue"] <= 0:
            errors.append(f"{prefix}.issue must be a positive integer")
        for field in ("changed_surfaces", "required_focused_jobs", "focused_checks", "admission_checks", "negative_controls", "global_suite_escalation_triggers", "merge_evidence"):
            value = pack[field]
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
                errors.append(f"{prefix}.{field} must be a non-empty list of strings")
        workflow_files = pack.get("workflow_files_to_lint")
        if not isinstance(workflow_files, list) or not all(isinstance(path, str) and path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")) for path in workflow_files):
            errors.append(f"{prefix}.workflow_files_to_lint must be a list of workflow paths")
        if not set(pack["required_focused_jobs"] if isinstance(pack["required_focused_jobs"], list) else []) <= JOB_IDS:
            errors.append(f"{prefix}.required_focused_jobs contains an unknown job")
        if not set(pack["focused_checks"] if isinstance(pack["focused_checks"], list) else []) <= CHECK_IDS:
            errors.append(f"{prefix}.focused_checks contains an unknown check")
        if pack_id in REQUIRED_PACK_JOBS and set(pack["required_focused_jobs"]) != REQUIRED_PACK_JOBS[pack_id]:
            errors.append(f"{prefix}.required_focused_jobs weakens the immutable job baseline")
        if pack_id in REQUIRED_PACK_CHECKS and set(pack["focused_checks"]) != REQUIRED_PACK_CHECKS[pack_id]:
            errors.append(f"{prefix}.focused_checks weakens the immutable focused-check baseline")
        exact = pack["exact_sha"]
        if not isinstance(exact, dict) or exact.get("source") != "required workflow_dispatch input candidate_sha" or exact.get("binding") != "must equal HEAD of the isolated candidate checkout, controlled by the protected-main workflow" or exact.get("target_base_source") != "required workflow_dispatch input target_base_sha" or exact.get("target_base_sha") != TARGET_BASE_RULE:
            errors.append(f"{prefix}.exact_sha must bind required dispatch inputs to the checked-out SHA")
        budget = pack["budget"]
        if not isinstance(budget, dict):
            errors.append(f"{prefix}.budget must be an object")
        else:
            job_timeout = budget.get("job_timeout_minutes")
            step_timeout = budget.get("step_timeout_minutes")
            cost_cap = budget.get("max_billable_minutes_per_dispatch")
            if budget.get("runner") != "ubuntu-24.04" or not isinstance(job_timeout, int) or not 1 <= job_timeout <= 15 or not isinstance(step_timeout, int) or not 1 <= step_timeout <= job_timeout or not isinstance(cost_cap, int) or not 1 <= cost_cap <= job_timeout or budget.get("matrix_limit") != 1 or budget.get("max_concurrent_dispatches_per_pack_and_sha") != 1:
                errors.append(f"{prefix}.budget exceeds the declared hosted-runner cap")
        escalation = pack["escalation_policy"]
        if not isinstance(escalation, dict) or not set(escalation.get("critical_surfaces", [])) >= {"workflow", "security", "release", "core"} or escalation.get("required_jobs_for_this_pack") != pack["required_focused_jobs"] or escalation.get("protected_main_full_suite_required_after_merge") is not True:
            errors.append(f"{prefix}.escalation_policy weakens a critical-surface gate")
        if pack.get("issue") and isinstance(pack_id, str) and str(pack["issue"]) not in pack_id:
            errors.append(f"{prefix}.pack_id does not name its issue")
    return errors


def self_test(catalog: dict) -> list[str]:
    failures: list[str] = []
    if validate(catalog):
        return ["canonical catalog is invalid"]
    unknown = json.loads(json.dumps(catalog))
    unknown["packs"][0]["pack_id"] = "unknown"
    if not validate(unknown):
        failures.append("unknown pack ID was accepted")
    if select_pack(catalog, "unknown"):
        failures.append("unlisted pack ID resolved to a pack")
    missing = json.loads(json.dumps(catalog))
    del missing["packs"][0]["negative_controls"]
    if not validate(missing):
        failures.append("pack missing negative controls was accepted")
    oversized = json.loads(json.dumps(catalog))
    oversized["packs"][0]["budget"]["job_timeout_minutes"] = 60
    if not validate(oversized):
        failures.append("over-cap timeout was accepted")
    unbounded = json.loads(json.dumps(catalog))
    unbounded["packs"][0]["focused_checks"].append("full-suite-skipped")
    if not validate(unbounded):
        failures.append("unknown focused job was accepted")
    downgraded = json.loads(json.dumps(catalog))
    downgraded["packs"][0]["escalation_policy"]["protected_main_full_suite_required_after_merge"] = False
    if not validate(downgraded):
        failures.append("critical-surface downgrade was accepted")
    removed_check = json.loads(json.dumps(catalog))
    removed_check["packs"][0]["focused_checks"].remove("actionlint")
    if not validate(removed_check):
        failures.append("required focused check removal was accepted")
    removed_job = json.loads(json.dumps(catalog))
    removed_job["packs"][0]["required_focused_jobs"].clear()
    if not validate(removed_job):
        failures.append("required focused job removal was accepted")
    wrong_sha = json.loads(json.dumps(catalog))
    wrong_sha["packs"][0]["exact_sha"]["binding"] = "best effort branch name"
    if not validate(wrong_sha):
        failures.append("weak SHA binding was accepted")
    wrong_base_rule = json.loads(json.dumps(catalog))
    wrong_base_rule["packs"][0]["exact_sha"]["target_base_sha"] = "any ancestor is acceptable"
    if not validate(wrong_base_rule):
        failures.append("weakened target-base rule was accepted")
    if valid_sha_pair("a" * 40, "b" * 40) or valid_sha_pair("not-a-sha", "not-a-sha"):
        failures.append("malformed or mismatched candidate SHA was accepted")
    if not target_base_matches("a" * 40, "b" * 40, "c" * 40, "a" * 40, "issue-2437-worker-three-arm"):
        failures.append("the actual merge-base was rejected")
    if target_base_matches("b" * 40, "b" * 40, "c" * 40, "b" * 40, "issue-2437-worker-three-arm"):
        failures.append("candidate-as-base was accepted")
    if target_base_matches("c" * 40, "d" * 40, "e" * 40, "a" * 40, "issue-2437-worker-three-arm"):
        failures.append("later-ancestor instead of merge-base was accepted")
    if not target_base_matches("a" * 40, "b" * 40, "b" * 40, "b" * 40, "issue-2440-ci-scoping", "a" * 40):
        failures.append("bootstrap first-parent base was rejected")
    if target_base_matches("b" * 40, "b" * 40, "b" * 40, "b" * 40, "issue-2440-ci-scoping", "a" * 40):
        failures.append("bootstrap candidate-as-base was accepted")
    canonical_workflow = (ROOT / ".github/workflows/issue-ci-pack.yml").read_text(encoding="utf-8")
    if validate_workflow_contract(canonical_workflow):
        failures.append("canonical workflow failed its static contract")
    for marker in (
        "id: sla-credit-authorization",
        "python3 -I scripts/backlog_verify.py",
        "python3 -I scripts/verify_i2176_grpc_deny_gate.py",
        "python3 -I scripts/verify_i2574_grpc_diagnostic_policy.py",
        "ref: 5fabd93e98d805a39319fcb6a22c9ee5267fafd4",
    ):
        if not validate_workflow_contract(canonical_workflow.replace(marker, "removed-control", 1)):
            failures.append(f"SLA credit missing trusted control was accepted: {marker}")
    authorization = canonical_workflow.index("id: sla-credit-authorization")
    execution = canonical_workflow.index("id: python-sla-credit-real")
    wrong_order = canonical_workflow[:authorization] + canonical_workflow[authorization:].replace(
        "id: sla-credit-authorization", "id: python-sla-credit-real", 1)
    wrong_order = wrong_order[:execution] + wrong_order[execution:].replace(
        "id: python-sla-credit-real", "id: sla-credit-authorization", 1)
    if not validate_workflow_contract(wrong_order):
        failures.append("SLA credit execution before authorization was accepted")
    for trigger in ("push", "schedule"):
        automatic_workflow = canonical_workflow.replace(
            "\n  workflow_dispatch:\n", f"\n  workflow_dispatch:\n  {trigger}:\n", 1
        )
        if not validate_workflow_contract(automatic_workflow):
            failures.append(f"workflow {trigger} trigger mutation was accepted")
    unbound_workflow = (ROOT / ".github/workflows/issue-ci-pack.yml").read_text(encoding="utf-8").replace(
        'ACTUAL_SHA="$(git -C candidate rev-parse HEAD)"', "ACTUAL_SHA=$EXPECTED_SHA"
    )
    if not validate_workflow_contract(unbound_workflow):
        failures.append("workflow losing the candidate SHA binding was accepted")
    missing_inventory_workflow = canonical_workflow.replace("id: cargo-mutants-v27-inventory", "id: removed-inventory-check", 1)
    if not validate_workflow_contract(missing_inventory_workflow):
        failures.append("workflow losing the v27 inventory check was accepted")
    mutating_inventory_workflow = canonical_workflow.replace(
        "--shard 0/1 --list --json", "--shard 0/1 --baseline=skip --list --json", 1
    )
    if not validate_workflow_contract(mutating_inventory_workflow):
        failures.append("workflow adding a mutation control was accepted")
    extra_cargo_mutants_workflow = canonical_workflow.replace(
        "cargo mutants --version | grep -Fx 'cargo-mutants 27.0.0'",
        "cargo mutants --package corelink-server",
        1,
    )
    if not validate_workflow_contract(extra_cargo_mutants_workflow):
        failures.append("workflow adding an unrelated cargo-mutants command was accepted")
    multiline_cargo_mutants_workflow = canonical_workflow + "\n      - run: |\n          cargo \\\n            mutants --package corelink-server\n"
    if not validate_workflow_contract(multiline_cargo_mutants_workflow):
        failures.append("workflow adding a multiline cargo-mutants command was accepted")
    token_workflow = canonical_workflow.replace("timeout-minutes: 10", "env: {GITHUB_TOKEN: leaked}\n        timeout-minutes: 10", 1)
    if not validate_workflow_contract(token_workflow):
        failures.append("workflow adding a credential route was accepted")
    actionlint_omitted = (ROOT / ".github/workflows/issue-ci-pack.yml").read_text(encoding="utf-8").replace(
        "if: inputs.pack_id == 'issue-2440-ci-scoping' || inputs.pack_id == 'issue-2437-worker-three-arm' || inputs.pack_id == 'issue-1948-mutants-receipt' || inputs.pack_id == 'issue-2457-mutants-shards' || inputs.pack_id == 'issue-1667-phase-regions' || inputs.pack_id == 'issue-2568-sla-credit-real'",
        "if: inputs.pack_id == 'issue-2440-ci-scoping' || inputs.pack_id == 'issue-2437-worker-three-arm' || inputs.pack_id == 'issue-2457-mutants-shards' || inputs.pack_id == 'issue-1667-phase-regions'",
        1,
    )
    if not validate_workflow_contract(actionlint_omitted):
        failures.append("workflow omitting issue 1948 from one actionlint step was accepted")
    if not paths_outside_pack(["crates/corelink-server/src/lib.rs"], catalog["packs"][0]["changed_surfaces"]):
        failures.append("out-of-pack changed file was accepted")
    issue_1948 = select_pack(catalog, "issue-1948-mutants-receipt")
    if len(issue_1948) != 1:
        failures.append("issue 1948 pack is missing or ambiguous")
    else:
        pack_1948 = issue_1948[0]
        expected_surfaces = {
            ".github/workflows/issue-1863-mutants-contract.yml",
            ".github/workflows/issue-ci-pack.yml",
            "scripts/verify_i1863_mutants_hosted.py",
            "tests/test_i1863_mutants_hosted_receipt.py",
        }
        if set(pack_1948["changed_surfaces"]) != expected_surfaces:
            failures.append("issue 1948 changed-file boundary is not the exact reviewed surface")
        if set(pack_1948["workflow_files_to_lint"]) != {
            ".github/workflows/issue-1863-mutants-contract.yml",
            ".github/workflows/issue-ci-pack.yml",
        }:
            failures.append("issue 1948 actionlint boundary is not the exact reviewed workflow surface")
        if not paths_outside_pack([".github/workflows/unrelated.yml"], pack_1948["changed_surfaces"]):
            failures.append("issue 1948 accepted an unrelated changed path")
        unlinted_workflow = ".github/workflows/issue-1863-mutants-hosted.yml"
        if unlinted_workflow in pack_1948["workflow_files_to_lint"] or not paths_outside_pack(
            [unlinted_workflow], pack_1948["changed_surfaces"]
        ):
            failures.append("issue 1948 accepted an out-of-scope, unlinted workflow")
    return failures


def authorize_sla_credit_tree(root: Path, changed: list[str]) -> list[str]:
    errors = []
    if len(changed) != len(SLA_CREDIT_HASHES) or set(changed) != set(SLA_CREDIT_HASHES):
        errors.append("SLA credit candidate must change exactly the eight frozen files")
    for relative, digest in SLA_CREDIT_HASHES.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errors.append(f"SLA credit candidate content is not authorized: {relative}")
        entry = subprocess.run(["git", "ls-tree", "HEAD", "--", relative], cwd=root,
                               check=True, capture_output=True, text=True).stdout.split()
        if len(entry) != 4 or entry[0] != "100644" or entry[1] != "blob" or entry[3] != relative:
            errors.append(f"SLA credit candidate mode is not authorized: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--actual-sha", required=True)
    parser.add_argument("--target-base-sha", required=True)
    parser.add_argument("--trusted-main-sha", required=True)
    parser.add_argument("--pack-id", required=True)
    parser.add_argument("--candidate-root", default=".")
    parser.add_argument("--run-self-test", action="store_true")
    args = parser.parse_args()
    if (
        not valid_sha_pair(args.candidate_sha, args.actual_sha)
        or not SHA_RE.fullmatch(args.target_base_sha)
        or not SHA_RE.fullmatch(args.trusted_main_sha)
    ):
        print("expected candidate, base, and trusted-main SHA must be full 40-character hex IDs", file=sys.stderr)
        return 1
    if args.candidate_sha != args.actual_sha:
        print("candidate SHA does not match the exact dispatched revision", file=sys.stderr)
        return 1
    if args.target_base_sha == args.candidate_sha:
        print("target base SHA must differ from the candidate SHA", file=sys.stderr)
        return 1
    try:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read canonical pack catalog: {exc}", file=sys.stderr)
        return 1
    problems = validate(catalog)
    try:
        workflow_text = (ROOT / ".github/workflows/issue-ci-pack.yml").read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read trusted issue pack workflow: {exc}", file=sys.stderr)
        return 1
    problems.extend(validate_workflow_contract(workflow_text))
    if problems:
        print("invalid issue CI pack catalog:", *problems, sep="\n- ", file=sys.stderr)
        return 1
    selected = select_pack(catalog, args.pack_id)
    if len(selected) != 1:
        print(f"unknown or ambiguous pack ID: {args.pack_id}", file=sys.stderr)
        return 1
    changed = subprocess.run(
        ["git", "diff", "--name-only", args.target_base_sha, args.candidate_sha],
        cwd=Path(args.candidate_root).resolve(),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if args.pack_id == "issue-2568-sla-credit-real":
        errors = authorize_sla_credit_tree(Path(args.candidate_root).resolve(), changed)
        if errors:
            print("SLA credit trusted authorization failed:", *errors, sep="\n- ", file=sys.stderr)
            return 1
    allowed = selected[0]["changed_surfaces"]
    unexpected = paths_outside_pack(changed, allowed)
    if unexpected:
        print("changed-file boundary exceeded:", *unexpected, sep="\n- ", file=sys.stderr)
        return 1
    workflow_changes = {path for path in changed if path.startswith(".github/workflows/")}
    linted_workflows = set(selected[0]["workflow_files_to_lint"])
    if workflow_changes - linted_workflows:
        print("changed workflow files are not covered by actionlint:", *(sorted(workflow_changes - linted_workflows)), sep="\n- ", file=sys.stderr)
        return 1
    merge_base = subprocess.run(
        ["git", "merge-base", args.trusted_main_sha, args.candidate_sha],
        cwd=Path(args.candidate_root).resolve(),
        check=False,
        capture_output=True,
        text=True,
    )
    if merge_base.returncode != 0:
        print("candidate and trusted main have no merge-base", file=sys.stderr)
        return 1
    first_parent = None
    if args.pack_id == "issue-2440-ci-scoping" and args.candidate_sha == args.trusted_main_sha:
        first_parent_result = subprocess.run(
            ["git", "rev-parse", f"{args.candidate_sha}^"],
            cwd=Path(args.candidate_root).resolve(),
            check=False,
            capture_output=True,
            text=True,
        )
        if first_parent_result.returncode != 0:
            print("bootstrap candidate has no first parent", file=sys.stderr)
            return 1
        first_parent = first_parent_result.stdout.strip()
    if not target_base_matches(
        args.target_base_sha,
        args.candidate_sha,
        args.trusted_main_sha,
        merge_base.stdout.strip(),
        args.pack_id,
        first_parent,
    ):
        print("target base SHA does not bind to the actual candidate/main boundary", file=sys.stderr)
        return 1
    if args.run_self_test:
        failures = self_test(catalog)
        if failures:
            print("adversarial pack checks failed:", *failures, sep="\n- ", file=sys.stderr)
            return 1
    print(f"valid pack {args.pack_id}: candidate={args.candidate_sha} base={args.target_base_sha} files={len(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
