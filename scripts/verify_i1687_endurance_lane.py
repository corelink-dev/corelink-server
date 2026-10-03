#!/usr/bin/env python3
"""Fail-closed static contract for the bounded #1687 endurance lane."""

from __future__ import annotations

import re
from pathlib import Path


CANONICAL_TARGET = "https://staging.corelink.humangr.com"
WORKFLOW = Path(".github/workflows/endurance-2h-nightly.yml")
SCENARIO = Path("tests/load/k6/scenarios/endurance-24h.js")
# The repository-ID literal is rendered from config/github-identity.json by
# scripts/sync_workflow_repository_guards.py, which owns its value.
PROTECTED_DISPATCH = re.compile(
    r"github\.repository_id == '[0-9]+' && "
    r"github\.event_name == 'workflow_dispatch' && "
    r"github\.ref == 'refs/heads/main' && github\.ref_protected"
)


class LaneContractError(ValueError):
    """The workflow cannot prove the bounded operator lane contract."""


def verify_workflow(text: str) -> list[str]:
    errors: list[str] = []
    if "workflow_dispatch:" not in text:
        errors.append("workflow_dispatch trigger is missing")
    if len(PROTECTED_DISPATCH.findall(text)) != 2:
        errors.append("measurement and baseline jobs must require a protected canonical dispatch")
    if "    environment: staging" not in text:
        errors.append("the measurement job must use the protected staging environment")
    if "run-bounded-endurance" not in text:
        errors.append("the operator confirmation phrase is missing")
    if text.count("persist-credentials: false") != 2:
        errors.append("both checkouts must prevent GitHub credentials from persisting")
    for job_name in ("endurance-2h", "baseline-drift-check"):
        boundary = re.search(
            rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            text,
        )
        if boundary is None or re.search(r"(?m)^    runs-on:\s*ubuntu-24\.04\s*$", boundary.group("body")) is None:
            errors.append(f"{job_name} must use GitHub-hosted ubuntu-24.04")
    if re.search(r"^\s+schedule:", text, re.MULTILINE):
        errors.append("schedule trigger would make the lane unattended")
    if "CANONICAL_TARGET='https://staging.corelink.humangr.com'" not in text:
        errors.append("owner approved canonical target is missing")
    if 'TARGET_HOST="${K6_TARGET_HOST%/}"' not in text:
        errors.append("target normalization is missing")
    if 'K6_TARGET_HOST:             ${{ steps.target_host.outputs.target_host }}' not in text:
        errors.append("runtime does not consume the checked target output")
    if "K6_TARGET_HOST: ${{ secrets.K6_TARGET_HOST }}" not in text:
        errors.append("preflight does not read the environment secret")
    for env_name, secret_name in (
        ("K6_TARGET_IDENTITY_RECEIPT", "K6_TARGET_IDENTITY_RECEIPT"),
        ("K6_STAGING_LOAD_ADMISSION_KEY", "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY"),
    ):
        if f"{env_name}: ${{{{ secrets.{secret_name} }}}}" not in text:
            errors.append(f"preflight does not bind required staging secret {secret_name}")
    if "scripts/validate_load_target_receipt.py" not in text:
        errors.append("preflight does not validate the owner-issued staging identity receipt")
    if "VUS:                        '50'" not in text:
        errors.append("runtime population is not pinned to 50 VUs")
    if "K6_RUN_ID:                  ${{ github.run_id }}" not in text:
        errors.append("runtime does not receive the exact GitHub run id")
    if '"vus": int(os.environ["VUS"])' not in text:
        errors.append("receipt does not bind the effective VU population")
    timeout = re.search(r"timeout-minutes:\s*(\d+)", text)
    if timeout is None or int(timeout.group(1)) > 145:
        errors.append("job timeout is absent or exceeds the 145 minute bound")
    if "timeout --signal=TERM --kill-after=60s 130m k6 run" not in text:
        errors.append("k6 command has no bounded graceful timeout")
    for marker in (
        '"schema": "corelink.endurance-lane-receipt.v1"',
        '"run_id": "${GITHUB_RUN_ID}"',
        '"run_attempt": "${GITHUB_RUN_ATTEMPT}"',
        '"sha": "${GITHUB_SHA}"',
        '"runner_name": "${RUNNER_NAME}"',
        '"artifact_sha256": hashes',
    ):
        if marker not in text:
            errors.append(f"receipt marker missing: {marker}")
    for marker in (
        "corelink.endurance-heartbeat.v1",
        "heartbeat &",
        "checkpoint-prepared",
        "checkpoint-running",
        "checkpoint-completed",
        "checkpoint-teardown",
        "if: always()",
    ):
        if marker not in text:
            errors.append(f"lifecycle marker missing: {marker}")
    teardown = text.split("- name: teardown synthetic staging state", 1)[-1].split("- name: write receipt and teardown checkpoint", 1)[0]
    if "id: teardown" not in teardown or "if: always() && steps.target_host.outcome == 'success'" not in teardown:
        errors.append("run-scoped teardown must run after any load outcome once target identity is accepted")
    if (
        "continue-on-error: true" in teardown
        or "admission key is required" not in teardown
        or "HTTP_STATUS=$(timeout 30s curl --silent --show-error --max-redirs 0" not in teardown
        or "Authorization: Bearer" in teardown
        or "test \"${HTTP_STATUS}\" = '200'" not in teardown
    ):
        errors.append("failed, redirected, or unconfigured cleanup must fail the lane")
    for marker in (
        "staging_load_lifecycle_auth.py --version v1",
        "--run-id \"$GITHUB_RUN_ID\" --scenario endurance-2h --deployment-sha \"$TARGET_DEPLOYMENT_SHA\"",
        "x-corelink-staging-load-admission: ${CREDENTIAL}",
        "/_internal/staging/load-tests/endurance-2h/teardown",
        "/_internal/staging/load-tests/endurance-2h/seal",
    ):
        if marker not in text:
            errors.append(f"lifecycle identity/auth marker missing: {marker}")
    if "K6_AUTH_BEARER" in text or "K6_STAGING_TEARDOWN_TOKEN" in text:
        errors.append("legacy static workload or teardown credential remains")
    if '"teardown_status": os.environ["TEARDOWN_STATUS"]' not in text:
        errors.append("receipt must record the teardown outcome")
    if '"teardown_deletion_proven": os.environ["TEARDOWN_DELETION_PROVEN"] == "true"' not in text:
        errors.append("receipt must bind deletion proof to a validated server receipt")
    if "TEARDOWN_DELETION_PROVEN: ${{ steps.teardown.outputs.deletion_proven || 'false' }}" not in text:
        errors.append("lane receipt must default deletion proof to false")
    if '"${RUNNER_TEMP}/teardown-receipt.json"' not in teardown:
        errors.append("teardown response must be retained for validation")
    if "scripts/validate_load_teardown_receipt.py" not in teardown:
        errors.append("teardown response must pass the exact receipt validator")
    if '"tests/load/results/endurance-2h/teardown-receipt-${GITHUB_RUN_ID}.json"' not in teardown:
        errors.append("validated teardown receipt must be retained in the run artifact")
    if 'echo "deletion_proven=true" >> "$GITHUB_OUTPUT"' not in teardown:
        errors.append("deletion proof must be emitted only after response validation")
    if "-name 'teardown-receipt-*.json'" not in text:
        errors.append("teardown receipt must be covered by the artifact digest")
    if text.find("- name: teardown synthetic staging state") > text.find("- name: write receipt and teardown checkpoint"):
        errors.append("receipt must be written after the teardown attempt")
    seal = text.split("- name: seal synthetic staging state", 1)[-1].split("- name: teardown synthetic staging state", 1)[0]
    for marker in (
        "staging_load_lifecycle_auth.py --validate-seal",
        "seal-receipt-${GITHUB_RUN_ID}.json",
        "--max-redirs 0",
    ):
        if marker not in seal:
            errors.append(f"seal receipt validation marker missing: {marker}")
    if 'test "${CONFIRM}" = "run-bounded-endurance"' not in text:
        errors.append("dispatch must require the exact bounded endurance confirmation")
    if 'test "${DURATION}" = \'2h\'' not in text:
        errors.append("the dispatch duration must be fixed at two hours")
    if "b125-audit-capacity" not in text or "run-b125-audit-capacity" not in text:
        errors.append("the controlled capacity profile must use its separate exact confirmation")
    if 'K6_B125_AUDIT_CAPACITY_PROFILE: ${{ github.event.inputs.workload_profile == \'b125-audit-capacity\' && \'1\' || \'0\' }}' not in text:
        errors.append("runtime must derive the capacity profile only from the allowlisted input")
    if "inputs.workload_profile == 'mixed'" not in text:
        errors.append("capacity runs must not contaminate the mixed-profile rolling baseline")
    if "sha256sum" not in text:
        errors.append("artifact digest is missing")
    if "K6_TARGET_HOST: ${{ secrets.K6_TARGET_HOST }}" in text and "k6 run" in text:
        # The secret is allowed only as preflight input. The command must use
        # the step output, otherwise an arbitrary environment URL can bypass it.
        run_block = text.split("- name: run k6 endurance 2h", 1)[-1]
        if "secrets.K6_TARGET_HOST" in run_block:
            errors.append("k6 run receives the unchecked target secret")
    if "campaign-ci" in text or "manifesto" in text or "manifest" in text.lower():
        errors.append("campaign or remote manifest wiring leaked into the lane")
    return errors


def verify_scenario(text: str) -> list[str]:
    """Require run-scoped mutation IDs so teardown cannot sweep other runs."""
    errors: list[str] = []
    for marker in (
        "const RUN_ID = __ENV.K6_RUN_ID || '';",
        "if (!/^\\d{1,20}$/.test(RUN_ID))",
        "_run_${RUN_ID}_endurance_",
        "evt_load_endurance_${RUN_ID}_${idx}",
    ):
        if marker not in text:
            errors.append(f"scenario run-scope marker missing: {marker}")
    if text.count("'x-corelink-load-test-run-id': RUN_ID") != 2:
        errors.append("all scenario and memory-poll requests must carry the current run ID")
    if "evt_load_endurance_${idx}" in text:
        errors.append("webhook event ids must be unique to the current run")
    if "${tenant.tenant_id}_endurance_${idx}_" in text:
        errors.append("CAS writes must be namespaced to the current run")
    for marker in (
        "K6_B125_AUDIT_CAPACITY_PROFILE",
        "executor: 'constant-arrival-rate'",
        "rate: 1",
        "timeUnit: '1s'",
        "preAllocatedVUs: MAX_VUS",
        "maxVUs: MAX_VUS",
        "_run_${RUN_ID}_endurance_",
        "function b125CapacityIter",
        "doCasWrite(tenant)",
        "b125_capacity_write_non_2xx_total",
        "res.status >= 200 && res.status < 300",
    ):
        if marker not in text:
            errors.append(f"controlled B-125 load profile marker missing: {marker}")
    return errors


def verify_path(root: Path = Path(".")) -> None:
    try:
        text = (root / WORKFLOW).read_text(encoding="utf-8")
        scenario = (root / SCENARIO).read_text(encoding="utf-8")
    except OSError as exc:
        raise LaneContractError(f"lane input is unreadable: {exc}") from exc
    errors = verify_workflow(text) + verify_scenario(scenario)
    if errors:
        raise LaneContractError("; ".join(errors))


if __name__ == "__main__":
    verify_path()
    print("i1687 endurance lane contract: PASS")
