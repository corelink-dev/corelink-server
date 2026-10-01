from __future__ import annotations

import copy
import hashlib
import sys
import unittest
import datetime as dt
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from issue_2165_image_budget import (  # noqa: E402
    CAP_USD,
    MAX_COMPONENTS,
    MONEY_TOLERANCE_USD,
    RESERVE_USD,
    BudgetError,
    admit_budget,
    validate_budget,
    validate_cleanup_deadline,
)
from issue_2165_cleanup_tasks import TASK_DESIRED_STATUSES, TaskSnapshotError, parse_describe_response, validate_task_snapshots  # noqa: E402
from verify_issue_2165_ecr_image_build import ContractError, validate  # noqa: E402


class ImageBuildContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (ROOT / ".github/workflows/issue-2165-ecr-image-build.yml").read_text()
        self.runtime = (ROOT / "scripts/issue_2165_kms_runtime.py").read_text()
        self.cleanup_tasks = (ROOT / "scripts/issue_2165_cleanup_tasks.py").read_text()

    def test_current_image_and_runtime_contract(self) -> None:
        validate(self.workflow, self.runtime, self.cleanup_tasks)

    def test_rejects_missing_cap_or_cleanup_role(self) -> None:
        for marker in ("cap_bytes=$((20 * 1000 * 1000 * 1000))", "IMAGE_CLEANUP_ROLE_ARN: ${{ vars.B083_AWS_IMAGE_CLEANUP_ROLE_ARN }}", '"countNumber":1'):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime, self.cleanup_tasks)

    def test_rejects_broad_delete_or_cleanup_of_under_cap_success(self) -> None:
        with self.assertRaisesRegex(ContractError, "each have one exact-tag"):
            validate(self.workflow.replace('aws ecr batch-delete-image', 'aws ecr batch-delete-image\n          aws ecr batch-delete-image'), self.runtime, self.cleanup_tasks)
        condition = " || steps.image-size.outputs.within_cap == 'false'"
        with self.assertRaises(ContractError):
            validate(self.workflow.replace(condition, ""), self.runtime, self.cleanup_tasks)

    def test_rejects_single_task_policy_or_foreign_tasks(self) -> None:
        for marker in ("MAX_CONCURRENT_TASKS = 2", "active.difference(allowed_existing)"):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow, self.runtime.replace(marker, ""), self.cleanup_tasks)

    def test_budget_requires_finite_exact_remaining_and_five_dollar_reserve(self) -> None:
        self.assertEqual(validate_budget("10", "10", "5", "0"), (10, 10, 5, 0))
        for values in (
            ("15", "5", "0.01", "0"),
            ("14", "6", "1.01", "0"),
            ("14", "6", "0.5", "0.6"),
            ("21", "-1", "1", "0"),
            ("1", "18", "1", "0"),
            ("-1", "21", "1", "0"),
            ("NaN", "NaN", "1", "0"),
            ("Infinity", "-Infinity", "1", "0"),
            ("bad", "19", "1", "0"),
            (True, "19", "1", "0"),
            ("10", "10", "5", "NaN"),
        ):
            with self.subTest(values=values), self.assertRaises(BudgetError):
                validate_budget(*values)

    def test_cleanup_deadline_covers_full_build_timeout_but_stays_within_24_hours(self) -> None:
        now = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
        self.assertEqual(validate_cleanup_deadline("2026-10-01T02:00:00Z", now), now + dt.timedelta(hours=2))
        for deadline in ("2026-10-01T01:50:00Z", "2026-10-02T01:00:00Z", "2026-09-30T23:00:00Z", "2026-10-01T02:00:00", "invalid"):
            with self.subTest(deadline=deadline), self.assertRaises(BudgetError):
                validate_cleanup_deadline(deadline, now)

    def test_cleanup_mode_requires_exact_manifest_preimage_and_idle_task_gates(self) -> None:
        for marker in (
            'lease["app_digest"] == os.environ["APP_DIGEST"]',
            'lease["operator_digest"] == os.environ["OPERATOR_DIGEST"]',
            'lease["owner"] == os.environ["GITHUB_ACTOR"]',
            "imageTag=\"$SOURCE_SHA\"",
            "python3 scripts/issue_2165_cleanup_tasks.py \"$cluster\"",
            "postread:$postread_at",
            'lease["cleanup_operation_ref"] == "cleanup-successful-images"',
            'lease["cleanup_deadline_at"]',
            "if: always()\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime, self.cleanup_tasks)

    def test_spend_admission_goes_through_exactly_one_dual_mode_validator(self) -> None:
        for marker in (
            "from issue_2165_image_budget import BudgetError, admit_budget, validate_cleanup_deadline",
            'admit_budget(lease["budget"], lease["proposed_operation"], now)',
            'assert lease["proposed_operation"]["cleanup"]["deadline_at"] == lease["cleanup_deadline_at"]',
            "except BudgetError as exc:",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime, self.cleanup_tasks)
        call = 'admit_budget(lease["budget"], lease["proposed_operation"], now)'
        for mutated in (
            self.workflow.replace(call, call + "\n              validate_budget(1, 19, 1, 0)"),
            self.workflow.replace(call, call + "\n              admit_budget(lease[\"budget\"], {}, now)"),
        ):
            with self.subTest(mutated=mutated.count("budget(")), self.assertRaisesRegex(ContractError, "exactly one admit_budget"):
                validate(mutated, self.runtime, self.cleanup_tasks)


class CleanupTaskSnapshotTests(unittest.TestCase):
    cluster = "arn:aws:ecs:us-east-1:046797548582:cluster/i2165-b083-20260930-fab9cc09-cluster"
    task = "arn:aws:ecs:us-east-1:046797548582:task/i2165-b083-20260930-fab9cc09-cluster/0123456789abcdef"

    def test_pending_filter_is_excluded_because_it_is_a_last_status(self) -> None:
        self.assertEqual(TASK_DESIRED_STATUSES, ("RUNNING", "STOPPED"))

    def test_empty_running_and_stopped_lists_are_idle(self) -> None:
        # ListTasks' documented response omits failures when there are none.
        validate_task_snapshots({"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": []}}, [], self.cluster)

    def test_failed_list_or_describe_response_cannot_prove_idleness(self) -> None:
        listed = {"RUNNING": {"taskArns": [], "failures": [{"reason": "MISSING"}]}, "STOPPED": {"taskArns": []}}
        with self.assertRaisesRegex(TaskSnapshotError, "reported failures"):
            validate_task_snapshots(listed, [], self.cluster)
        with self.assertRaisesRegex(TaskSnapshotError, "reported failures"):
            parse_describe_response({"tasks": [], "failures": [{"reason": "MISSING"}]})
        self.assertEqual(parse_describe_response({"tasks": []}), [])

    def test_stopped_desired_but_running_last_status_blocks_deletion(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        described = [{"taskArn": self.task, "clusterArn": self.cluster, "desiredStatus": "STOPPED", "lastStatus": "RUNNING"}]
        with self.assertRaisesRegex(TaskSnapshotError, "not terminal"):
            validate_task_snapshots(listed, described, self.cluster)

    def test_stopped_desired_and_stopped_last_status_is_terminal(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        described = [{"taskArn": self.task, "clusterArn": self.cluster, "desiredStatus": "STOPPED", "lastStatus": "STOPPED"}]
        validate_task_snapshots(listed, described, self.cluster)

    def test_incomplete_or_cross_cluster_describe_fails_closed(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        with self.assertRaisesRegex(TaskSnapshotError, "incomplete"):
            validate_task_snapshots(listed, [], self.cluster)
        described = [{"taskArn": self.task, "clusterArn": "arn:aws:ecs:us-east-1:046797548582:cluster/other", "lastStatus": "STOPPED"}]
        with self.assertRaisesRegex(TaskSnapshotError, "outside"):
            validate_task_snapshots(listed, described, self.cluster)


# --- dual-mode budget admission ------------------------------------------------
# Every record below is a SYNTHETIC test fixture (synthetic:// refs, hashes of
# fixed labels) and describes no real campaign state -- except
# partial_inventory_from_2026_10_01_proposal(), which exists to be DENIED.

NOW = dt.datetime(2026, 10, 2, tzinfo=dt.timezone.utc)


def _sha(label: str) -> str:
    return hashlib.sha256(f"synthetic-test-fixture:{label}".encode()).hexdigest()


def _component(
    operation_id: str,
    *,
    provider: str = "aws",
    units: float = 1,
    unit: str = "key-month",
    price: float = 1.0,
    computed: float | None = None,
    status: str = "live",
    start: str = "2026-10-01T00:00:00Z",
    end: str = "2026-10-31T00:00:00Z",
) -> dict:
    return {
        "operation_id": operation_id,
        "provider": provider,
        "source_receipt_ref": f"synthetic://receipts/{operation_id}.json",
        "source_receipt_sha256": _sha(operation_id),
        "starts_at": start,
        "end_or_expiry_at": end,
        "max_billable_units": units,
        "billable_unit": unit,
        "unit_price_usd": price,
        "price_date": "2026-09-30",
        "pricing_source": "synthetic://pricing/fixture",
        "computed_max_usd": units * price if computed is None else computed,
        "cleanup": {"owner": "synthetic-owner", "action": f"delete {operation_id}", "deadline_at": end},
        "status": status,
    }


def _empty_budget() -> dict:
    return {
        "cap_usd": 20.0,
        "reserve_usd": 5.0,
        "actual_usd": None,
        "actual_receipt_ref": None,
        "actual_checked_at": None,
        "known_pending_commitments_usd": None,
        "commitments_receipt_ref": None,
        "complete_campaign_upper_bound_usd": None,
        "upper_bound_receipt_ref": None,
        "upper_bound_checked_at": None,
        "reserve_backing": None,
        "included_commitments": [],
    }


def upper_budget(ledger: list[dict] | None = None) -> dict:
    if ledger is None:
        ledger = [
            _component("synthetic-kms-key"),
            _component(
                "synthetic-compute", provider="cloudflare", units=100000, unit="instance-second",
                price=0.00000778, status="completed", start="2026-09-30T00:00:00Z", end="2026-10-01T12:00:00Z",
            ),
            _component(
                "synthetic-do-requests", provider="cloudflare", units=3, unit="million-requests", price=0.1,
                status="reserved", start="2026-10-02T01:00:00Z", end="2026-10-09T00:00:00Z",
            ),
        ]
    budget = _empty_budget()
    budget.update(
        complete_campaign_upper_bound_usd=sum(item["computed_max_usd"] for item in ledger),
        upper_bound_receipt_ref="synthetic://receipts/upper-bound.json",
        upper_bound_checked_at="2026-10-01T23:30:00Z",
        reserve_backing=_component(
            "synthetic-object-lock", units=1, unit="retention-ceiling", price=5.0, status="held"
        ),
        included_commitments=ledger,
    )
    return budget


def actual_budget() -> dict:
    budget = _empty_budget()
    budget.update(
        actual_usd=6.5,
        actual_receipt_ref="synthetic://receipts/actual.json",
        actual_checked_at="2026-10-01T23:30:00Z",
        known_pending_commitments_usd=1.0,
        commitments_receipt_ref="synthetic://receipts/pending.json",
    )
    return budget


def proposal(**overrides) -> dict:
    fields = dict(
        units=0.7, unit="GB-month", price=0.1, computed=0.07, status="reserved",
        start="2026-10-02T01:00:00Z", end="2026-10-03T00:00:00Z",
    )
    fields.update(overrides)
    return _component("synthetic-ecr-images", **fields)


def partial_inventory_from_2026_10_01_proposal() -> dict:
    """The real, PARTIAL #2165 inventory as described by the 2026-10-01 proposal.

    Transcribed from i2165-upper-bound-budget-schema-proposal-20261001.md and
    i2165-handoff-checkpoint-20261001.md. Only what that evidence states is
    filled in; everything it leaves unknown is null. The $14.0708855 modeled
    subtotal is $5 held Object Lock ceiling + $0.30342 v9 model + $7.3674655
    historic compute + $1 CMK + $0.40 secret; the $5 hold is what the reserve
    backs, so it sits in reserve_backing, not the ledger. Plus the live, unspent
    $1 v11 reservation, and the unreserved $0.07 ECR estimate as the proposal.
    This is NOT a ledger and claims no completeness: it exists to be denied.
    """
    decision = (
        "corelink-golive-v9-budget-decision-20261001.json",
        "76dd8104eca4a02ef9f9a9fc5818bf9ede9e4c54e3a19f10c691d871f16008bd",
    )

    def row(operation_id, receipt, *, provider=None, computed=None, units=None, unit=None, price=None,
            source=None, start=None, status=None):
        return {
            "operation_id": operation_id, "provider": provider,
            "source_receipt_ref": receipt[0], "source_receipt_sha256": receipt[1],
            "starts_at": start, "end_or_expiry_at": None,
            "max_billable_units": units, "billable_unit": unit, "unit_price_usd": price,
            "price_date": None, "pricing_source": source, "computed_max_usd": computed,
            "cleanup": None, "status": status,
        }

    budget = _empty_budget()
    budget.update(
        # What an operator would type from the arithmetic: $14.0708855 - $5 hold + $1 v11.
        complete_campaign_upper_bound_usd=10.0708855,
        reserve_backing=row(
            "i1877-s3-object-lock-hold",
            (
                "i2165-spend-reconcile-20261001/s3-object-lock-reconciled-36741245684-1/redacted-proof.json",
                "47c74fba6414ab7c43df020bff73ad8ccd7e08fb519e14da6f6e0ebec1caedc8",
            ),
            provider="aws", computed=5.0, status="held",
        ),
        included_commitments=[
            row("i1700-v9-model", decision, computed=0.30342),
            row("i1700-historic-container-compute", decision, provider="cloudflare", computed=7.3674655,
                unit="instance-second", price=0.00000778),
            row("i2165-target-cmk", decision, provider="aws", computed=1.0, units=1, unit="key-month", price=1.0,
                source="https://aws.amazon.com/kms/pricing/", start="2026-09-26T23:20:20Z", status="live"),
            row("i2165-target-secret", decision, provider="aws", computed=0.40, units=1, unit="secret-month",
                price=0.40, source="https://aws.amazon.com/secrets-manager/pricing/",
                start="2026-09-30T21:34:57Z", status="live"),
            row(
                "i1700-v11-reservation",
                (
                    "i1700-post-source-provider-charter-20261001/charter.json",
                    "4b31cfb77a4b2544ff3087f325c0a2e8de81d4e32d74a0b76467a5ab1e9ae1bd",
                ),
                computed=1.0, status="reserved",
            ),
            row("i1700-historic-do-v3-v4-request-windows", decision, provider="cloudflare"),
            row("i1700-historic-do-storage-reserve", decision, provider="cloudflare"),
        ],
    )
    return budget


def partial_inventory_ecr_proposal() -> dict:
    return {
        "operation_id": "i2165-ecr-image-build", "provider": "aws",
        "source_receipt_ref": "i2165-spend-reconcile-20261001/final-budget-reconciliation.json",
        "source_receipt_sha256": "6a60bb350ad0e1b8b897c4360c96b4796b2602bc8fd2d0465d7be208875852b6",
        "starts_at": None, "end_or_expiry_at": None, "max_billable_units": None, "billable_unit": "GB-month",
        "unit_price_usd": 0.10, "price_date": None, "pricing_source": "https://aws.amazon.com/ecr/pricing/",
        "computed_max_usd": 0.07, "cleanup": None, "status": "reserved",
    }


class DualModeBudgetAdmissionTests(unittest.TestCase):
    def denial_of(self, budget: object, proposed: dict) -> BudgetError:
        with self.assertRaises(BudgetError) as caught:
            admit_budget(budget, proposed, NOW)
        return caught.exception

    def assertDenied(self, budget: object, proposed: dict, *expected: str) -> BudgetError:
        denial = self.denial_of(budget, proposed)
        self.assertEqual(set(denial.reasons), set(expected), str(denial))
        return denial

    def _ledger_change(self, index: int, **change) -> dict:
        budget = upper_budget()
        budget["included_commitments"][index].update(change)
        return budget

    def test_hard_constants(self) -> None:
        self.assertEqual((CAP_USD, RESERVE_USD), (Decimal("20"), Decimal("5")))

    # -- admits ------------------------------------------------------------------
    def test_upper_bound_mode_admits_complete_synthetic_ledger(self) -> None:
        admission = admit_budget(upper_budget(), proposal(), NOW)
        self.assertEqual(admission.mode, "upper_bound")
        # The fixture's bound is a binary64 sum (2.0780000000000003): admission keeps
        # the larger of declared and exact, never rounding the commitment down.
        self.assertTrue(Decimal("2.078") <= admission.committed_usd <= Decimal("2.078") + MONEY_TOLERANCE_USD)
        self.assertEqual(admission.proposal_usd, Decimal("0.07"))
        self.assertEqual(admission.headroom_usd, CAP_USD - RESERVE_USD - admission.committed_usd - Decimal("0.07"))

    def test_actual_mode_admits_with_unchanged_arithmetic(self) -> None:
        admission = admit_budget(actual_budget(), proposal(), NOW)
        self.assertEqual(admission.mode, "actual")
        self.assertEqual(admission.committed_usd, Decimal("7.5"))
        self.assertEqual(admission.headroom_usd, Decimal("7.43"))

    def test_upper_bound_admits_exactly_at_cap_minus_reserve_and_denies_one_microdollar_over(self) -> None:
        exact = upper_budget([_component("synthetic-fill", price=14.93)])
        self.assertEqual(admit_budget(exact, proposal(), NOW).headroom_usd, Decimal("0"))
        over = upper_budget([_component("synthetic-fill", price=14.930001)])
        self.assertDenied(over, proposal(), "bound.over_budget")

    def test_actual_admits_exactly_at_cap_minus_reserve_and_denies_over(self) -> None:
        budget = actual_budget()
        budget["actual_usd"] = 13.93
        self.assertEqual(admit_budget(budget, proposal(), NOW).headroom_usd, Decimal("0"))
        budget["actual_usd"] = 13.930001
        self.assertDenied(budget, proposal(), "actual.over_budget")

    def test_float_noise_within_tolerance_is_accepted(self) -> None:
        noisy = _component("synthetic-noisy", units=3, price=0.1)
        self.assertEqual(noisy["computed_max_usd"], 0.30000000000000004)
        admit_budget(upper_budget([noisy]), proposal(), NOW)

    def test_tolerance_never_loosens_admission(self) -> None:
        # Declared max and bound sit within tolerance of the exact product, but the
        # exact product is over the envelope: admission must use the larger figure.
        item = _component("synthetic-fill", price=14.9300000005, computed=14.93)
        budget = upper_budget([item])
        self.assertEqual(budget["complete_campaign_upper_bound_usd"], 14.93)
        self.assertDenied(budget, proposal(), "bound.over_budget")

    # -- basis -----------------------------------------------------------------
    def test_neither_actual_nor_bound_is_denied(self) -> None:
        self.assertDenied(_empty_budget(), proposal(), "basis.none")

    def test_actual_in_upper_mode_without_receipt_is_denied(self) -> None:
        budget = upper_budget()
        budget["actual_usd"] = 3.0
        self.assertDenied(budget, proposal(), "actual.without_receipt", "basis.ambiguous")

    def test_actual_and_bound_together_are_ambiguous_even_with_receipt(self) -> None:
        budget = upper_budget()
        budget.update(actual_usd=3.0, actual_receipt_ref="synthetic://receipts/actual.json")
        self.assertDenied(budget, proposal(), "basis.ambiguous")

    def test_actual_zero_is_denied_with_or_without_receipt(self) -> None:
        budget = actual_budget()
        budget["actual_usd"] = 0
        self.assertDenied(budget, proposal(), "actual.zero")
        budget["actual_receipt_ref"] = None
        self.assertDenied(budget, proposal(), "actual.zero", "actual.without_receipt")

    def test_upper_mode_rejects_actual_only_fields(self) -> None:
        for field, value in (("actual_receipt_ref", "synthetic://x"), ("known_pending_commitments_usd", 0.0)):
            budget = upper_budget()
            budget[field] = value
            with self.subTest(field=field):
                self.assertDenied(budget, proposal(), "basis.ambiguous")

    # -- actual mode -------------------------------------------------------------
    def test_actual_mode_denials(self) -> None:
        cases = (
            ({"actual_receipt_ref": None}, ("actual.without_receipt",)),
            ({"actual_receipt_ref": "  "}, ("actual.without_receipt",)),
            ({"actual_usd": 21.0}, ("actual.out_of_range",)),
            ({"actual_usd": -1.0}, ("number.negative",)),
            ({"actual_usd": float("nan")}, ("number.non_finite",)),
            ({"known_pending_commitments_usd": None}, ("actual.commitments_unknown",)),
            ({"commitments_receipt_ref": None}, ("actual.commitments_without_receipt",)),
            ({"actual_checked_at": "2026-10-01T21:59:59Z"}, ("time.stale",)),
            ({"actual_checked_at": None}, ("time.missing",)),
            ({"included_commitments": [_component("synthetic-kms-key")]}, ("basis.ambiguous",)),
            ({"reserve_backing": _component("synthetic-object-lock", status="held")}, ("basis.ambiguous",)),
            ({"upper_bound_receipt_ref": "synthetic://x"}, ("basis.ambiguous",)),
        )
        for change, expected in cases:
            budget = actual_budget()
            budget.update(change)
            with self.subTest(change=change):
                self.assertDenied(budget, proposal(), *expected)

    # -- hard constants ----------------------------------------------------------
    def test_cap_and_reserve_denials(self) -> None:
        cases = (
            ({"cap_usd": 0}, "cap.non_positive"),
            ({"cap_usd": -20.0}, "cap.non_positive"),
            ({"cap_usd": None}, "cap.missing"),
            ({"cap_usd": 25.0}, "cap.not_hard_constant"),
            ({"cap_usd": float("inf")}, "number.non_finite"),
            ({"reserve_usd": -1.0}, "reserve.negative"),
            ({"reserve_usd": 0}, "reserve.not_hard_constant"),
            ({"reserve_usd": None}, "reserve.missing"),
        )
        for change, reason in cases:
            for factory in (upper_budget, actual_budget):
                budget = factory()
                budget.update(change)
                with self.subTest(change=change, mode=factory.__name__):
                    self.assertDenied(budget, proposal(), reason)

    # -- upper mode: completeness ------------------------------------------------
    def test_incompleteness_is_denied_by_name(self) -> None:
        cases = (
            ({"max_billable_units": None}, "incomplete.unknown_units"),
            ({"billable_unit": ""}, "incomplete.unknown_units"),
            ({"end_or_expiry_at": None}, "incomplete.open_ended_lifetime"),
            ({"starts_at": None}, "incomplete.unknown_lifetime"),
            ({"cleanup": None}, "incomplete.missing_cleanup"),
            ({"cleanup": "delete later"}, "incomplete.missing_cleanup"),
            ({"unit_price_usd": None}, "incomplete.unknown_price"),
            ({"pricing_source": None}, "incomplete.unknown_price"),
            ({"price_date": None}, "incomplete.unknown_price"),
            ({"provider": None}, "incomplete.unknown_provider"),
            ({"computed_max_usd": None}, "incomplete.unknown_max"),
        )
        for change, reason in cases:
            with self.subTest(change=change):
                self.assertDenied(self._ledger_change(0, **change), proposal(), reason)

    def test_cleanup_fields_each_required(self) -> None:
        for field in ("owner", "action", "deadline_at"):
            budget = upper_budget()
            budget["included_commitments"][0]["cleanup"][field] = None
            with self.subTest(field=field):
                self.assertDenied(budget, proposal(), "incomplete.missing_cleanup")

    def test_cleanup_after_expiry_is_denied(self) -> None:
        budget = upper_budget()
        budget["included_commitments"][0]["cleanup"]["deadline_at"] = "2026-11-01T00:00:00Z"
        self.assertDenied(budget, proposal(), "component.cleanup_after_expiry")

    def test_cleanup_deadline_before_start_is_denied(self) -> None:
        budget = upper_budget()
        budget["included_commitments"][0]["cleanup"]["deadline_at"] = "2026-09-30T23:59:59Z"
        self.assertDenied(budget, proposal(), "cleanup.deadline_before_start")
        # The proposal is checked the same way.
        bad = proposal()
        bad["cleanup"]["deadline_at"] = "2026-10-02T00:59:59Z"
        self.assertDenied(upper_budget(), bad, "cleanup.deadline_before_start")
        # Boundary: a deadline exactly at start is not before it.
        budget = upper_budget()
        budget["included_commitments"][0]["cleanup"]["deadline_at"] = "2026-10-01T00:00:00Z"
        admit_budget(budget, proposal(), NOW)

    def test_uncompleted_record_past_its_lifetime_is_denied(self) -> None:
        budget = self._ledger_change(0, starts_at="2026-09-01T00:00:00Z", end_or_expiry_at="2026-10-01T00:00:00Z")
        budget["included_commitments"][0]["cleanup"]["deadline_at"] = "2026-10-01T00:00:00Z"
        self.assertDenied(budget, proposal(), "incomplete.lifetime_elapsed")

    def test_empty_or_null_ledger_is_denied(self) -> None:
        for ledger in ([], None):
            budget = upper_budget()
            budget["included_commitments"] = ledger
            with self.subTest(ledger=ledger):
                self.assertDenied(budget, proposal(), "incomplete.empty_ledger")

    # -- upper mode: identity and dedup ------------------------------------------
    def test_duplicate_operation_id_is_denied(self) -> None:
        budget = upper_budget()
        budget["included_commitments"][1]["operation_id"] = "synthetic-kms-key"
        self.assertDenied(budget, proposal(), "component.duplicate_operation_id")

    def test_reservation_and_its_completion_cannot_both_count(self) -> None:
        reserved = _component("synthetic-op", status="reserved", start="2026-10-02T01:00:00Z")
        completed = _component("synthetic-op", status="completed", units=0.5)
        self.assertDenied(upper_budget([reserved, completed]), proposal(), "component.duplicate_operation_id")
        # The replacement alone is admitted.
        admit_budget(upper_budget([completed]), proposal(), NOW)

    def test_proposal_already_reserved_in_ledger_is_counted_once(self) -> None:
        budget = upper_budget([_component("synthetic-ecr-images", status="reserved", start="2026-10-02T01:00:00Z")])
        self.assertDenied(budget, proposal(), "component.duplicate_operation_id")

    def test_ambiguous_operation_ids_are_denied(self) -> None:
        for operation_id in ("Synthetic-KMS-Key", " synthetic-kms-key", "", None, "ab", 7):
            with self.subTest(operation_id=operation_id):
                self.assertDenied(
                    self._ledger_change(0, operation_id=operation_id), proposal(), "component.ambiguous_operation_id"
                )

    def test_receipt_sha256_must_be_64_lowercase_hex(self) -> None:
        good = _sha("x")
        for value in (good[:63], good + "0", good.upper(), "g" * 64, None, ""):
            with self.subTest(value=value):
                self.assertDenied(
                    self._ledger_change(0, source_receipt_sha256=value), proposal(), "component.receipt_sha256_invalid"
                )
        self.assertDenied(self._ledger_change(0, source_receipt_ref=""), proposal(), "component.receipt_ref_missing")

    def test_provider_and_status_are_closed_sets(self) -> None:
        self.assertDenied(self._ledger_change(0, provider="azure"), proposal(), "component.invalid_provider")
        self.assertDenied(self._ledger_change(0, status="pending"), proposal(), "component.invalid_status")
        self.assertDenied(self._ledger_change(0, status=None), proposal(), "incomplete.unknown_status")
        self.assertDenied(upper_budget(), proposal(status="live"), "proposal.not_reserved")

    # -- upper mode: arithmetic ---------------------------------------------------
    def test_computed_max_must_equal_units_times_price(self) -> None:
        self.assertDenied(
            upper_budget([_component("synthetic-kms-key", computed=1.01)]), proposal(),
            "component.computed_max_mismatch",
        )
        drift = float(Decimal("1") + 2 * MONEY_TOLERANCE_USD)
        self.assertDenied(
            upper_budget([_component("synthetic-kms-key", computed=drift)]), proposal(),
            "component.computed_max_mismatch",
        )
        self.assertDenied(upper_budget(), proposal(computed=0.08), "component.computed_max_mismatch")

    def test_bound_must_equal_component_sum(self) -> None:
        for delta in (0.01, -0.01, 2e-9):
            budget = upper_budget()
            budget["complete_campaign_upper_bound_usd"] += delta
            with self.subTest(delta=delta):
                self.assertDenied(budget, proposal(), "bound.sum_mismatch")

    def test_bound_over_cap_minus_reserve_is_denied(self) -> None:
        budget = upper_budget([_component("synthetic-big", price=15.5)])
        self.assertDenied(budget, proposal(), "bound.over_budget")

    def test_non_finite_negative_and_malformed_numbers_are_denied(self) -> None:
        cases = (
            ({"max_billable_units": float("nan")}, "number.non_finite"),
            ({"unit_price_usd": float("inf")}, "number.non_finite"),
            ({"computed_max_usd": float("-inf")}, "number.non_finite"),
            ({"unit_price_usd": -1.0}, "number.negative"),
            ({"max_billable_units": -1}, "number.negative"),
            ({"max_billable_units": 0}, "number.non_positive"),
            ({"max_billable_units": "1"}, "number.malformed"),
            ({"max_billable_units": True}, "number.malformed"),
        )
        for change, reason in cases:
            with self.subTest(change=change):
                self.assertDenied(self._ledger_change(0, **change), proposal(), reason)
        for value, reason in ((float("nan"), "number.non_finite"), (-2.0, "number.negative"), (0, "bound.non_positive")):
            budget = upper_budget()
            budget["complete_campaign_upper_bound_usd"] = value
            with self.subTest(bound=value):
                self.assertIn(reason, self.denial_of(budget, proposal()).reasons)

    def test_lifetime_and_time_denials(self) -> None:
        inverted = self._ledger_change(0, starts_at="2026-11-02T00:00:00Z", end_or_expiry_at="2026-11-01T00:00:00Z")
        inverted["included_commitments"][0]["cleanup"]["deadline_at"] = "2026-11-01T00:00:00Z"
        # With end before start, a deadline at end is also before start: both are named.
        self.assertDenied(inverted, proposal(), "component.lifetime_inverted", "cleanup.deadline_before_start")
        self.assertDenied(self._ledger_change(0, starts_at="2026-10-01T00:00:00"), proposal(), "time.not_utc")
        self.assertDenied(self._ledger_change(0, starts_at="yesterday"), proposal(), "time.malformed")
        self.assertDenied(self._ledger_change(0, price_date="2026-10-03"), proposal(), "time.future")
        self.assertDenied(self._ledger_change(0, price_date="2026/09/30"), proposal(), "time.malformed")
        for checked, reason in (
            ("2026-10-01T21:59:59Z", "time.stale"),
            ("2026-10-02T00:00:01Z", "time.future"),
            (None, "time.missing"),
        ):
            budget = upper_budget()
            budget["upper_bound_checked_at"] = checked
            with self.subTest(checked=checked):
                self.assertDenied(budget, proposal(), reason)
        with self.assertRaises(BudgetError) as caught:
            admit_budget(upper_budget(), proposal(), NOW.replace(tzinfo=None))
        self.assertEqual(caught.exception.reasons, ("time.not_utc",))

    def test_upper_bound_receipt_required(self) -> None:
        budget = upper_budget()
        budget["upper_bound_receipt_ref"] = None
        self.assertDenied(budget, proposal(), "upper.receipt_missing")

    def test_closed_schema(self) -> None:
        budget = upper_budget()
        budget["remaining_usd"] = 15.0
        self.assertDenied(budget, proposal(), "schema.unknown_field")
        budget = upper_budget()
        del budget["upper_bound_checked_at"]
        self.assertDenied(budget, proposal(), "schema.missing_field", "time.missing")
        self.assertDenied(self._ledger_change(0, note="x"), proposal(), "schema.unknown_field")
        self.assertDenied([], proposal(), "schema.not_object")
        budget = upper_budget()
        budget["included_commitments"] = {"a": 1}
        self.assertDenied(budget, proposal(), "schema.not_list")

    def test_too_many_components_is_denied(self) -> None:
        ledger = [_component(f"synthetic-op-{index:04d}", price=0.01) for index in range(MAX_COMPONENTS + 1)]
        self.assertDenied(upper_budget(ledger), proposal(), "component.too_many")

    # -- reserve counted once -----------------------------------------------------
    def test_reserve_backing_is_required_held_and_within_reserve(self) -> None:
        budget = upper_budget()
        budget["reserve_backing"] = None
        self.assertDenied(budget, proposal(), "reserve.backing_missing")
        budget = upper_budget()
        budget["reserve_backing"]["status"] = "live"
        self.assertDenied(budget, proposal(), "reserve.backing_not_held")
        budget = upper_budget()
        budget["reserve_backing"].update(unit_price_usd=6.0, computed_max_usd=6.0)
        self.assertDenied(budget, proposal(), "reserve.insufficient")

    def test_reserve_cannot_be_counted_again_in_the_ledger(self) -> None:
        held = upper_budget()["reserve_backing"]
        same_receipt = dict(held, operation_id="synthetic-object-lock-again", status="live")
        same_operation = dict(held, source_receipt_sha256=_sha("other"), status="live")
        for name, item in (("same receipt", same_receipt), ("same operation", same_operation)):
            budget = upper_budget([_component("synthetic-kms-key"), item])
            with self.subTest(name=name):
                self.assertDenied(budget, proposal(), "reserve.double_counted")
        relabelled_hold = _component("synthetic-other-hold", status="held")
        self.assertDenied(upper_budget([relabelled_hold]), proposal(), "reserve.held_outside_reserve")

    # -- the real partial inventory -------------------------------------------------
    def test_real_partial_inventory_from_proposal_is_denied_as_incomplete(self) -> None:
        modeled = Decimal("14.0708855") + Decimal("1") + Decimal("0.07")
        self.assertEqual(modeled, Decimal("15.1408855"))
        # The arithmetic alone would fit once the $5 hold is the reserve: incompleteness,
        # not the cap, is what must deny it.
        self.assertLessEqual(modeled - RESERVE_USD, CAP_USD - RESERVE_USD)
        denial = self.denial_of(partial_inventory_from_2026_10_01_proposal(), partial_inventory_ecr_proposal())
        self.assertIn("incomplete", denial.categories)
        for reason in ("incomplete.unknown_units", "incomplete.open_ended_lifetime", "incomplete.missing_cleanup"):
            self.assertIn(reason, denial.reasons)
        self.assertNotIn("bound.over_budget", denial.reasons)
        self.assertIn("i1700-historic-do-v3-v4-request-windows", str(denial))

    def test_real_partial_inventory_with_hold_also_in_ledger_is_a_double_count(self) -> None:
        budget = partial_inventory_from_2026_10_01_proposal()
        hold = copy.deepcopy(budget["reserve_backing"])
        hold.update(operation_id="i1877-object-lock-in-subtotal", status="live")
        budget["included_commitments"].append(hold)
        budget["complete_campaign_upper_bound_usd"] = 15.0708855
        denial = self.denial_of(budget, partial_inventory_ecr_proposal())
        self.assertIn("reserve.double_counted", denial.reasons)


if __name__ == "__main__":
    unittest.main()
