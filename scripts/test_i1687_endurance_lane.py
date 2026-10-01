#!/usr/bin/env python3
"""Contract and mutation tests for issue #1687's bounded lane."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_i1687_endurance_lane import verify_path, verify_scenario, verify_workflow  # noqa: E402
from validate_load_teardown_receipt import (  # noqa: E402
    SCHEMA as TEARDOWN_SCHEMA,
    TeardownReceiptError,
    parse_receipt,
    validate as validate_teardown_receipt,
)


def workflow_text() -> str:
    return (Path(__file__).resolve().parents[1] / ".github/workflows/endurance-2h-nightly.yml").read_text()


def test_contract_is_green() -> None:
    verify_path(Path(__file__).resolve().parents[1])


def test_mutations_cannot_escape_run_scoped_state() -> None:
    scenario = (Path(__file__).resolve().parents[1] / "tests/load/k6/scenarios/endurance-24h.js").read_text()
    mutations = (
        ("'x-corelink-load-test-run-id': RUN_ID", "'x-corelink-load-test-run-id': 'shared'"),
        ("_run_${RUN_ID}_endurance_", "_endurance_"),
        ("evt_load_endurance_${RUN_ID}_${idx}", "evt_load_endurance_${idx}"),
        ("if (!/^\\d{1,20}$/.test(RUN_ID))", "if (false)"),
    )
    for old, new in mutations:
        mutated = scenario.replace(old, new, 1)
        assert mutated != scenario
        assert verify_scenario(mutated), f"run-scope mutation escaped: {old}"


def test_mutations_fail_closed() -> None:
    source = workflow_text()
    mutations = (
        ("workflow_dispatch:", "schedule:"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("    environment: staging", "    environment: production"),
        ("CANONICAL_TARGET='https://staging.corelink.humangr.com'", "CANONICAL_TARGET='https://evil.example'"),
        ("scripts/validate_load_target_receipt.py", "scripts/skip_load_target_receipt.py"),
        ('K6_TARGET_HOST:             ${{ steps.target_host.outputs.target_host }}', 'K6_TARGET_HOST: ${{ secrets.K6_TARGET_HOST }}'),
        ("timeout --signal=TERM --kill-after=60s 130m k6 run", "k6 run"),
        ("VUS:                        '50'", "VUS:                        '500'"),
        ('"artifact_sha256": hashes', '"artifact_sha256": {}'),
        ("corelink.endurance-heartbeat.v1", "corelink.heartbeat.v0"),
        ("checkpoint-teardown", "teardown"),
        ("admission key is required; refusing unmanaged synthetic state", "cleanup token optional"),
        ("test \"${HTTP_STATUS}\" = '200'", "test \"${HTTP_STATUS}\" = '302'"),
        ('"run_id": "${GITHUB_RUN_ID}"', '"run_id": "*"'),
        ('"teardown_status": os.environ["TEARDOWN_STATUS"]', '"teardown_status": "passed"'),
        (
            '"teardown_deletion_proven": os.environ["TEARDOWN_DELETION_PROVEN"] == "true"',
            '"teardown_deletion_proven": True',
        ),
        ('test "${CONFIRM}" = "run-bounded-endurance"', 'test "${CONFIRM}" = "yes"'),
        ('test "${DURATION}" = \'2h\'', 'test "${DURATION}" = \'30s\''),
    )
    for old, new in mutations:
        mutated = source.replace(old, new, 1)
        assert old != new and mutated != source
        assert verify_workflow(mutated), f"mutation escaped: {old}"

    # Scope the repeated `if` guard to the teardown step. A first global match
    # mutates the seal step and does not exercise the verifier's cleanup gate.
    teardown = source.split("- name: teardown synthetic staging state", 1)[1].split(
        "- name: write receipt and teardown checkpoint", 1
    )[0]
    changed_teardown = teardown.replace(
        "if: always() && steps.target_host.outcome == 'success'", "if: always()", 1
    )
    assert changed_teardown != teardown
    assert verify_workflow(
        source.replace(teardown, changed_teardown, 1)
    ), "run-scoped teardown mutation escaped"
    changed_teardown = teardown.replace(
        "HTTP_STATUS=$(timeout 30s curl --silent --show-error --max-redirs 0",
        "HTTP_STATUS=$(curl --silent --show-error --max-redirs 0",
        1,
    )
    assert changed_teardown != teardown
    assert verify_workflow(
        source.replace(teardown, changed_teardown, 1)
    ), "teardown timeout mutation escaped"


def test_arbitrary_target_is_rejected_even_with_a_trailing_slash() -> None:
    source = workflow_text()
    mutated = source.replace(
        "CANONICAL_TARGET='https://staging.corelink.humangr.com'",
        "CANONICAL_TARGET='https://staging.corelink.humangr.com/evil'",
        1,
    )
    errors = verify_workflow(mutated)
    assert any("canonical target" in error for error in errors)


def test_schedule_is_rejected() -> None:
    source = workflow_text()
    errors = verify_workflow(source.replace("on:\n  # No unattended", "on:\n  schedule:\n    - cron: '0 0 * * *'\n  # No unattended", 1))
    assert any("unattended" in error for error in errors)


def test_unprotected_dispatch_is_rejected() -> None:
    source = workflow_text()
    guard = (
        "github.repository == 'HuGR-dev/corelink-server' && "
        "github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main' && github.ref_protected"
    )
    mutated = source.replace(guard, "github.event_name == 'workflow_dispatch'", 1)
    errors = verify_workflow(mutated)
    assert any("protected canonical dispatch" in error for error in errors)


def teardown_receipt() -> dict[str, object]:
    return {
        "schema": TEARDOWN_SCHEMA,
        "run_id": "1234567890123",
        "scenario": "endurance-2h",
        "target_deployment_sha": "a" * 40,
        "inventory_complete": True,
        "resources": {
            "cas_objects": {"inventory": 2, "attempted": 2, "deleted": 2, "remaining": 0},
            "webhook_idempotency_rows": {"inventory": 1, "attempted": 1, "deleted": 1, "remaining": 0},
            "dsr_jobs": {"inventory": 0, "attempted": 0, "deleted": 0, "remaining": 0},
            "audit_entries": {"inventory": 2, "attempted": 2, "deleted": 2, "remaining": 0},
        },
        "cross_run_deletions": 0,
    }


def test_exact_teardown_receipt_is_accepted() -> None:
    result = validate_teardown_receipt(
        teardown_receipt(),
        run_id="1234567890123",
        scenario="endurance-2h",
        deployment_sha="a" * 40,
    )
    assert result["cross_run_deletions"] == 0
    assert result["resources"] == teardown_receipt()["resources"]


def test_teardown_receipt_mismatches_and_partial_cleanup_fail_closed() -> None:
    mutations = (
        ("run_id", "9999999999999"),
        ("scenario", "load-test"),
        ("target_deployment_sha", "b" * 40),
        ("inventory_complete", False),
        ("cross_run_deletions", 1),
    )
    for field, value in mutations:
        receipt = teardown_receipt()
        receipt[field] = value
        try:
            validate_teardown_receipt(
                receipt,
                run_id="1234567890123",
                scenario="endurance-2h",
                deployment_sha="a" * 40,
            )
        except TeardownReceiptError:
            pass
        else:
            raise AssertionError(f"teardown receipt mutation escaped: {field}")

    for field, value in (("deleted", 1), ("remaining", 1), ("attempted", 1)):
        receipt = teardown_receipt()
        resource_counts = receipt["resources"]["cas_objects"]
        resource_counts[field] = value
        try:
            validate_teardown_receipt(
                receipt,
                run_id="1234567890123",
                scenario="endurance-2h",
                deployment_sha="a" * 40,
            )
        except TeardownReceiptError:
            pass
        else:
            raise AssertionError(f"partial teardown mutation escaped: {field}")


def test_teardown_receipt_rejects_unbound_or_incomplete_inventory() -> None:
    receipt = teardown_receipt()
    receipt["personal_data"] = "must never be uploaded"
    try:
        validate_teardown_receipt(
            receipt,
            run_id="1234567890123",
            scenario="endurance-2h",
            deployment_sha="a" * 40,
        )
    except TeardownReceiptError:
        pass
    else:
        raise AssertionError("unbound receipt field escaped")

    for resource_change in ("cas_objects", "webhook_idempotency_rows", "dsr_jobs", "audit_entries"):
        receipt = teardown_receipt()
        del receipt["resources"][resource_change]
        try:
            validate_teardown_receipt(
                receipt,
                run_id="1234567890123",
                scenario="endurance-2h",
                deployment_sha="a" * 40,
            )
        except TeardownReceiptError:
            pass
        else:
            raise AssertionError(f"omitted resource class escaped: {resource_change}")

    receipt = teardown_receipt()
    receipt["resources"]["unrecognized_state"] = {"inventory": 0, "attempted": 0, "deleted": 0, "remaining": 0}
    try:
        validate_teardown_receipt(
            receipt,
            run_id="1234567890123",
            scenario="endurance-2h",
            deployment_sha="a" * 40,
        )
    except TeardownReceiptError:
        pass
    else:
        raise AssertionError("unknown resource class escaped")


def test_teardown_receipt_parser_rejects_duplicate_keys() -> None:
    for text in ('{"run_id":"1","run_id":"2"}', '{"resources":{"cas_objects":{},"cas_objects":{}}}'):
        try:
            parse_receipt(text)
        except TeardownReceiptError:
            pass
        else:
            raise AssertionError("duplicate JSON key escaped")


if __name__ == "__main__":
    for name, function in sorted(globals().items()):
        if name.startswith("test_"):
            function()
    print("i1687 endurance lane contract and mutations: PASS")
