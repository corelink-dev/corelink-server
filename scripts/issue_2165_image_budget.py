"""Validate the protected cumulative-spend envelope for Issue 2165 image builds."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal, InvalidOperation
from typing import Any


class BudgetError(ValueError):
    """Raised when protected spend inputs are absent, malformed, or over budget."""


def _money(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise BudgetError("boolean is not a monetary amount")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BudgetError("monetary amount is malformed") from exc
    if not amount.is_finite():
        raise BudgetError("monetary amount must be finite")
    return amount


def validate_budget(
    spent_value: Any, remaining_value: Any, estimate_value: Any, commitments_value: Any
) -> tuple[Decimal, Decimal, Decimal, Decimal]:
    spent, remaining, estimate, commitments = map(
        _money, (spent_value, remaining_value, estimate_value, commitments_value)
    )
    cap, reserve, zero = Decimal("20"), Decimal("5"), Decimal("0")
    if not zero <= spent <= cap:
        raise BudgetError("cumulative spend must be between zero and the $20 cap")
    if remaining != cap - spent or remaining < reserve:
        raise BudgetError("remaining must equal $20 minus spend and preserve the $5 reserve")
    if not zero <= commitments:
        raise BudgetError("campaign commitments must be known and nonnegative")
    if not zero < estimate or estimate + commitments > remaining - reserve:
        raise BudgetError("estimate must be positive and fit below the held $5 reserve")
    return spent, remaining, estimate, commitments


def validate_cleanup_deadline(value: Any, now: dt.datetime) -> dt.datetime:
    if not isinstance(value, str) or now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise BudgetError("cleanup deadline and admission time must be UTC timestamps")
    try:
        deadline = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise BudgetError("cleanup deadline is malformed") from exc
    if deadline.tzinfo is None or deadline.utcoffset() != dt.timedelta(0):
        raise BudgetError("cleanup deadline must be UTC")
    if not now + dt.timedelta(hours=2) <= deadline <= now + dt.timedelta(hours=24):
        raise BudgetError("cleanup deadline must leave the full build window and expire within 24 hours")
    return deadline
