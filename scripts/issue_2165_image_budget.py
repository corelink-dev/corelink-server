"""Admission gate for Issue 2165 spend: one validator, two admission modes.

The campaign is capped at ``CAP_USD`` ($20) with ``RESERVE_USD`` ($5) held
back. ``admit_budget`` admits a proposed operation on exactly one basis, chosen
by which budget field is non-null -- never both, never neither:

* actual mode -- ``actual_usd`` is a source-backed cumulative charge carrying
  ``actual_receipt_ref``. Admission is the pre-existing arithmetic
  ``actual + known_pending_commitments + proposal <= cap - reserve``, decided
  by ``validate_budget`` (arithmetic unchanged; its errors now carry reasons).
* upper-bound mode -- ``actual_usd`` stays null because no attributable actual
  exists, and ``complete_campaign_upper_bound_usd`` is the sum of an itemised
  ledger of finite, receipt-bound commitments. Admission is
  ``bound + proposal <= cap - reserve``. This mode claims nothing about actual
  charges, balance, or invoice totals.

The reserve is counted once. It is subtracted from the cap, and the one held
ceiling it backs (``reserve_backing``) is named so that the same operation or
receipt appearing again in the ledger or as the proposal is a denial, and a
``held`` record is accepted only in that slot.

Every way of not having a number is a named denial (``BudgetError.reasons``);
nothing defaults to zero. What this gate cannot see: an operation that was never
entered into the ledger at all. Exhaustiveness of the inventory is attested by
the receipt behind ``upper_bound_receipt_ref``; the gate checks that every entry
is bounded, unique and internally consistent, not that the list is complete.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

CAP_USD = Decimal("20")
RESERVE_USD = Decimal("5")
CHECK_MAX_AGE = dt.timedelta(hours=2)
MAX_COMPONENTS = 256

# JSON numbers decode to IEEE-754 binary64, and Decimal(str(x)) recovers the
# author's literal whenever it has at most 15 significant digits, so most
# ledgers compare exactly. A product or sum computed in binary64 and written
# back can carry representation noise: below $32 one binary64 ulp is at most
# 2**-48 (~3.6e-15 USD), so a product is off by a few ulp and a sum of
# MAX_COMPONENTS terms by under 1e-12. The tolerance is 1e-9 USD: at least 1000x
# that noise and 10**7x below one cent, so it cannot hide a mispriced component.
# It applies only to the two equality checks (computed max, bound == sum). The
# admission inequality uses the LARGEST of the declared and exact figures, so the
# tolerance can only make admission stricter, never looser.
MONEY_TOLERANCE_USD = Decimal("0.000000001")

BUDGET_FIELDS = (
    "cap_usd",
    "reserve_usd",
    "actual_usd",
    "actual_receipt_ref",
    "actual_checked_at",
    "known_pending_commitments_usd",
    "commitments_receipt_ref",
    "complete_campaign_upper_bound_usd",
    "upper_bound_receipt_ref",
    "upper_bound_checked_at",
    "reserve_backing",
    "included_commitments",
)
ACTUAL_ONLY_FIELDS = (
    "actual_receipt_ref",
    "actual_checked_at",
    "known_pending_commitments_usd",
    "commitments_receipt_ref",
)
UPPER_ONLY_FIELDS = (
    "upper_bound_receipt_ref",
    "upper_bound_checked_at",
    "reserve_backing",
)
COMPONENT_FIELDS = (
    "operation_id",
    "provider",
    "source_receipt_ref",
    "source_receipt_sha256",
    "starts_at",
    "end_or_expiry_at",
    "max_billable_units",
    "billable_unit",
    "unit_price_usd",
    "price_date",
    "pricing_source",
    "computed_max_usd",
    "cleanup",
    "status",
)
CLEANUP_FIELDS = ("owner", "action", "deadline_at")
PROVIDERS = frozenset({"aws", "cloudflare", "github"})
LEDGER_STATUSES = frozenset({"reserved", "live", "completed"})
RESERVE_STATUS = "held"
PROPOSAL_STATUS = "reserved"
COMPLETED_STATUS = "completed"

# Lower-case only: two identifiers that differ only by case or padding cannot
# both be written, so one operation cannot hide under two spellings.
_OPERATION_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{2,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class BudgetError(ValueError):
    """Raised when spend inputs are absent, malformed, inconsistent, or over budget.

    ``reasons`` names every denial found as stable dotted codes that never carry
    input values; ``reason`` is the first one and ``categories`` their prefixes.
    """

    def __init__(self, message: str, reason: str = "budget.invalid", reasons: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.reasons: tuple[str, ...] = tuple(reasons) or (reason,)
        self.reason = self.reasons[0]

    @property
    def categories(self) -> frozenset[str]:
        return frozenset(reason.split(".", 1)[0] for reason in self.reasons)


@dataclass(frozen=True)
class Commitment:
    """One parsed ledger record. ``None`` fields already produced a denial."""

    where: str
    operation_id: str | None
    source_receipt_sha256: str | None
    status: str | None
    declared_max_usd: Decimal | None
    exact_max_usd: Decimal | None

    def conservative_max(self) -> Decimal | None:
        values = [v for v in (self.declared_max_usd, self.exact_max_usd) if v is not None]
        return max(values) if values else None


@dataclass(frozen=True)
class Admission:
    mode: str
    committed_usd: Decimal
    proposal_usd: Decimal
    headroom_usd: Decimal


class _Denials:
    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, reason: str, where: str) -> None:
        self.items.append((reason, where))

    def __bool__(self) -> bool:
        return bool(self.items)

    def raise_if_any(self) -> None:
        if self.items:
            reasons = tuple(dict.fromkeys(reason for reason, _ in self.items))
            detail = "; ".join(f"{where}: {reason}" for reason, where in self.items)
            raise BudgetError(f"budget admission denied: {detail}", reasons=reasons)


def _money(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise BudgetError("boolean is not a monetary amount", "number.malformed")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BudgetError("monetary amount is malformed", "number.malformed") from exc
    if not amount.is_finite():
        raise BudgetError("monetary amount must be finite", "number.non_finite")
    return amount


def validate_budget(
    spent_value: Any, remaining_value: Any, estimate_value: Any, commitments_value: Any
) -> tuple[Decimal, Decimal, Decimal, Decimal]:
    spent, remaining, estimate, commitments = map(
        _money, (spent_value, remaining_value, estimate_value, commitments_value)
    )
    cap, reserve, zero = CAP_USD, RESERVE_USD, Decimal("0")
    if not zero <= spent <= cap:
        raise BudgetError("cumulative spend must be between zero and the $20 cap", "actual.out_of_range")
    if remaining != cap - spent or remaining < reserve:
        raise BudgetError("remaining must equal $20 minus spend and preserve the $5 reserve", "actual.over_budget")
    if not zero <= commitments:
        raise BudgetError("campaign commitments must be known and nonnegative", "actual.commitments_unknown")
    if not zero < estimate or estimate + commitments > remaining - reserve:
        raise BudgetError("estimate must be positive and fit below the held $5 reserve", "actual.over_budget")
    return spent, remaining, estimate, commitments


def validate_cleanup_deadline(value: Any, now: dt.datetime) -> dt.datetime:
    if not isinstance(value, str) or now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise BudgetError("cleanup deadline and admission time must be UTC timestamps", "time.not_utc")
    try:
        deadline = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise BudgetError("cleanup deadline is malformed", "time.malformed") from exc
    if deadline.tzinfo is None or deadline.utcoffset() != dt.timedelta(0):
        raise BudgetError("cleanup deadline must be UTC", "time.not_utc")
    if not now + dt.timedelta(hours=2) <= deadline <= now + dt.timedelta(hours=24):
        raise BudgetError(
            "cleanup deadline must leave the full build window and expire within 24 hours", "cleanup.deadline_window"
        )
    return deadline


def _closed(raw: Any, fields: tuple[str, ...], where: str, denials: _Denials) -> Mapping[str, Any] | None:
    if not isinstance(raw, Mapping):
        denials.add("schema.not_object", where)
        return None
    for name in fields:
        if name not in raw:
            denials.add("schema.missing_field", f"{where}.{name}")
    for name in raw:
        if name not in fields:
            denials.add("schema.unknown_field", where)
    return raw


def _number(
    raw: Any,
    where: str,
    denials: _Denials,
    *,
    null_reason: str,
    positive: bool = False,
    negative_reason: str = "number.negative",
    zero_reason: str = "number.non_positive",
) -> Decimal | None:
    if raw is None:
        denials.add(null_reason, where)
        return None
    # JSON numbers only (or Decimal from parse_float=Decimal): a quoted "5" is a
    # type confusion, not a number.
    if isinstance(raw, bool) or not isinstance(raw, (int, float, Decimal)):
        denials.add("number.malformed", where)
        return None
    value = Decimal(str(raw))
    if not value.is_finite():
        denials.add("number.non_finite", where)
        return None
    if value < 0:
        denials.add(negative_reason, where)
        return None
    if positive and value == 0:
        denials.add(zero_reason, where)
        return None
    return value


def _text(raw: Any, where: str, denials: _Denials, reason: str) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        denials.add(reason, where)
        return None
    return raw


def _utc(raw: Any, where: str, denials: _Denials, null_reason: str) -> dt.datetime | None:
    if raw is None:
        denials.add(null_reason, where)
        return None
    if not isinstance(raw, str):
        denials.add("time.malformed", where)
        return None
    try:
        value = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        denials.add("time.malformed", where)
        return None
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        denials.add("time.not_utc", where)
        return None
    return value


def _fresh(raw: Any, where: str, now: dt.datetime, denials: _Denials) -> None:
    checked = _utc(raw, where, denials, "time.missing")
    if checked is None:
        return
    if checked > now:
        denials.add("time.future", where)
    elif now - checked > CHECK_MAX_AGE:
        denials.add("time.stale", where)


def _price_date(raw: Any, where: str, now: dt.datetime, denials: _Denials) -> None:
    if raw is None:
        denials.add("incomplete.unknown_price", where)
        return
    try:
        if not isinstance(raw, str) or len(raw) != 10:
            raise ValueError(raw)
        value = dt.date.fromisoformat(raw)
    except ValueError:
        denials.add("time.malformed", where)
        return
    if value > now.date():
        denials.add("time.future", where)


def _commitment(raw: Any, where: str, now: dt.datetime, denials: _Denials) -> Commitment:
    record = _closed(raw, COMPONENT_FIELDS, where, denials)
    if record is None:
        return Commitment(where, None, None, None, None, None)

    operation_id = record.get("operation_id")
    if isinstance(operation_id, str) and _OPERATION_ID.fullmatch(operation_id):
        where = f"{where}[{operation_id}]"
    else:
        denials.add("component.ambiguous_operation_id", where)
        operation_id = None

    provider = record.get("provider")
    if provider is None:
        denials.add("incomplete.unknown_provider", where)
    elif provider not in PROVIDERS:
        denials.add("component.invalid_provider", where)

    _text(record.get("source_receipt_ref"), f"{where}.source_receipt_ref", denials, "component.receipt_ref_missing")
    receipt_sha = record.get("source_receipt_sha256")
    if not (isinstance(receipt_sha, str) and _SHA256.fullmatch(receipt_sha)):
        denials.add("component.receipt_sha256_invalid", where)
        receipt_sha = None

    starts = _utc(record.get("starts_at"), f"{where}.starts_at", denials, "incomplete.unknown_lifetime")
    ends = _utc(record.get("end_or_expiry_at"), f"{where}.end_or_expiry_at", denials, "incomplete.open_ended_lifetime")
    if starts is not None and ends is not None and ends <= starts:
        denials.add("component.lifetime_inverted", where)

    status = record.get("status")
    if status is None:
        denials.add("incomplete.unknown_status", where)
    elif status not in LEDGER_STATUSES and status != RESERVE_STATUS:
        denials.add("component.invalid_status", where)
        status = None
    # A record past its bounded lifetime that is not completed may still be
    # accruing: its bound no longer covers it until it is reconciled.
    if ends is not None and status is not None and status != COMPLETED_STATUS and ends <= now:
        denials.add("incomplete.lifetime_elapsed", where)

    units = _number(
        record.get("max_billable_units"), f"{where}.max_billable_units", denials,
        null_reason="incomplete.unknown_units", positive=True,
    )
    _text(record.get("billable_unit"), f"{where}.billable_unit", denials, "incomplete.unknown_units")
    price = _number(
        record.get("unit_price_usd"), f"{where}.unit_price_usd", denials,
        null_reason="incomplete.unknown_price", positive=True,
    )
    _price_date(record.get("price_date"), f"{where}.price_date", now, denials)
    _text(record.get("pricing_source"), f"{where}.pricing_source", denials, "incomplete.unknown_price")
    declared = _number(
        record.get("computed_max_usd"), f"{where}.computed_max_usd", denials,
        null_reason="incomplete.unknown_max", positive=True,
    )

    cleanup = record.get("cleanup")
    if not isinstance(cleanup, Mapping):
        denials.add("incomplete.missing_cleanup", f"{where}.cleanup")
    elif _closed(cleanup, CLEANUP_FIELDS, f"{where}.cleanup", denials) is not None:
        _text(cleanup.get("owner"), f"{where}.cleanup.owner", denials, "incomplete.missing_cleanup")
        _text(cleanup.get("action"), f"{where}.cleanup.action", denials, "incomplete.missing_cleanup")
        deadline = _utc(cleanup.get("deadline_at"), f"{where}.cleanup.deadline_at", denials, "incomplete.missing_cleanup")
        # Billing is bounded by end_or_expiry_at; a later cleanup would bill
        # outside the declared lifetime.
        if deadline is not None and ends is not None and deadline > ends:
            denials.add("component.cleanup_after_expiry", where)

    exact = None
    if units is not None and price is not None:
        exact = units * price
        if declared is not None and abs(declared - exact) > MONEY_TOLERANCE_USD:
            denials.add("component.computed_max_mismatch", where)
    return Commitment(where, operation_id, receipt_sha, status, declared, exact)


def admit_budget(budget: Any, proposed_operation: Any, now: dt.datetime) -> Admission:
    """Admit ``proposed_operation`` against ``budget`` or raise ``BudgetError``."""
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise BudgetError("admission time must be a UTC timestamp", "time.not_utc")
    denials = _Denials()
    record = _closed(budget, BUDGET_FIELDS, "budget", denials)
    if record is None:
        denials.raise_if_any()
    assert record is not None

    cap = _number(
        record.get("cap_usd"), "cap_usd", denials, null_reason="cap.missing", positive=True,
        negative_reason="cap.non_positive", zero_reason="cap.non_positive",
    )
    if cap is not None and cap != CAP_USD:
        denials.add("cap.not_hard_constant", "cap_usd")
    reserve = _number(record.get("reserve_usd"), "reserve_usd", denials, null_reason="reserve.missing",
                      negative_reason="reserve.negative")
    if reserve is not None and reserve != RESERVE_USD:
        denials.add("reserve.not_hard_constant", "reserve_usd")

    proposal = _commitment(proposed_operation, "proposed_operation", now, denials)
    if proposal.status is not None and proposal.status != PROPOSAL_STATUS:
        denials.add("proposal.not_reserved", proposal.where)

    actual_raw = record.get("actual_usd")
    bound_raw = record.get("complete_campaign_upper_bound_usd")
    actual = None
    if actual_raw is not None:
        actual = _number(actual_raw, "actual_usd", denials, null_reason="actual.missing")
        # Zero is the placeholder this gate exists to refuse: the campaign has
        # held billable resources since 2026-09-26, so $0 cannot be source-backed.
        if actual is not None and actual == 0:
            denials.add("actual.zero", "actual_usd")
        _text(record.get("actual_receipt_ref"), "actual_receipt_ref", denials, "actual.without_receipt")
    if actual_raw is None and bound_raw is None:
        denials.add("basis.none", "budget")
        denials.raise_if_any()
    if actual_raw is not None and bound_raw is not None:
        denials.add("basis.ambiguous", "budget")
        denials.raise_if_any()
    if actual_raw is not None:
        return _admit_actual(record, actual, proposal, now, denials)
    return _admit_upper_bound(record, proposal, now, denials)


def _admit_actual(
    record: Mapping[str, Any], actual: Decimal | None, proposal: Commitment, now: dt.datetime, denials: _Denials
) -> Admission:
    for name in UPPER_ONLY_FIELDS:
        if record.get(name) is not None:
            denials.add("basis.ambiguous", name)
    if record.get("included_commitments") not in (None, []):
        denials.add("basis.ambiguous", "included_commitments")
    pending = _number(
        record.get("known_pending_commitments_usd"), "known_pending_commitments_usd", denials,
        null_reason="actual.commitments_unknown",
    )
    _text(record.get("commitments_receipt_ref"), "commitments_receipt_ref", denials, "actual.commitments_without_receipt")
    _fresh(record.get("actual_checked_at"), "actual_checked_at", now, denials)
    denials.raise_if_any()
    assert actual is not None and pending is not None
    proposal_usd = proposal.conservative_max()
    assert proposal_usd is not None
    try:
        validate_budget(actual, CAP_USD - actual, proposal_usd, pending)
    except BudgetError as exc:
        denials.add(exc.reason, "actual_usd")
    denials.raise_if_any()
    committed = actual + pending
    return Admission("actual", committed, proposal_usd, CAP_USD - RESERVE_USD - committed - proposal_usd)


def _admit_upper_bound(
    record: Mapping[str, Any], proposal: Commitment, now: dt.datetime, denials: _Denials
) -> Admission:
    for name in ACTUAL_ONLY_FIELDS:
        if record.get(name) is not None:
            denials.add("basis.ambiguous", name)
    bound = _number(
        record.get("complete_campaign_upper_bound_usd"), "complete_campaign_upper_bound_usd", denials,
        null_reason="bound.missing", positive=True, zero_reason="bound.non_positive",
    )
    _text(record.get("upper_bound_receipt_ref"), "upper_bound_receipt_ref", denials, "upper.receipt_missing")
    _fresh(record.get("upper_bound_checked_at"), "upper_bound_checked_at", now, denials)

    backing = None
    if record.get("reserve_backing") is None:
        denials.add("reserve.backing_missing", "reserve_backing")
    else:
        backing = _commitment(record.get("reserve_backing"), "reserve_backing", now, denials)
        if backing.status is not None and backing.status != RESERVE_STATUS:
            denials.add("reserve.backing_not_held", backing.where)
        backing_max = backing.conservative_max()
        if backing_max is not None and backing_max > RESERVE_USD:
            denials.add("reserve.insufficient", backing.where)

    raw_ledger = record.get("included_commitments")
    if raw_ledger is None or raw_ledger == []:
        denials.add("incomplete.empty_ledger", "included_commitments")
        raw_ledger = []
    elif not isinstance(raw_ledger, list):
        denials.add("schema.not_list", "included_commitments")
        raw_ledger = []
    elif len(raw_ledger) > MAX_COMPONENTS:
        denials.add("component.too_many", "included_commitments")
    ledger = [
        _commitment(item, f"included_commitments[{index}]", now, denials) for index, item in enumerate(raw_ledger)
    ]

    for entry in ledger:
        if entry.status == RESERVE_STATUS:
            denials.add("reserve.held_outside_reserve", entry.where)
    seen: set[str] = set()
    for entry in [*ledger, proposal]:
        if entry.operation_id is None:
            continue
        if entry.operation_id in seen:
            denials.add("component.duplicate_operation_id", entry.where)
        seen.add(entry.operation_id)
    if backing is not None:
        for entry in [*ledger, proposal]:
            same_operation = backing.operation_id is not None and entry.operation_id == backing.operation_id
            same_receipt = (
                backing.source_receipt_sha256 is not None
                and entry.source_receipt_sha256 == backing.source_receipt_sha256
            )
            if same_operation or same_receipt:
                denials.add("reserve.double_counted", entry.where)

    declared = [entry.declared_max_usd for entry in ledger]
    if ledger and bound is not None and all(value is not None for value in declared):
        if abs(bound - sum(declared, Decimal("0"))) > MONEY_TOLERANCE_USD:
            denials.add("bound.sum_mismatch", "complete_campaign_upper_bound_usd")

    denials.raise_if_any()
    assert bound is not None
    exact = [entry.exact_max_usd for entry in ledger]
    committed = max(bound, sum(declared, Decimal("0")), sum(exact, Decimal("0")))
    proposal_usd = proposal.conservative_max()
    assert proposal_usd is not None
    if committed + proposal_usd > CAP_USD - RESERVE_USD:
        denials.add("bound.over_budget", "complete_campaign_upper_bound_usd")
    denials.raise_if_any()
    return Admission("upper_bound", committed, proposal_usd, CAP_USD - RESERVE_USD - committed - proposal_usd)
