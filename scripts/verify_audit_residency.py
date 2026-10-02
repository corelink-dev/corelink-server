#!/usr/bin/env python3
"""Fail-closed auditor for the audit-outbox residency predicate (B-127).

The old ``INNER JOIN`` check answered only for rows that still had a tenant.
This tool instead reads one aggregate over the *full* ``audit_outbox``
population. Customer rows partition as satisfied, violated, or unevaluable;
the canonical ``_public`` namespace is accounted for separately, never
silently removed from the denominator. Public rows with an unexpected region
or event type are unevaluable, not an automatic exception.
An unevaluable row is evidence that the predicate cannot be proven; it is a
failing result, never a clean result.

A retained DSR-erasure orphan (``erased_orphan_rows``: no tenant row, but the
tenant has a ``dsr_erasure_log`` entry) is NOT unevaluable under the #1669
policy B owner decision of 2026-10-01: it is classified in its own
``erased_lineage_exception`` state. That state is never ``satisfied`` and never
``COMPLIANT``; a population whose only non-satisfied customer rows are erased
lineage reports ``DOCUMENTED_EXCEPTION``. The aggregate SQL is unchanged, so
the raw ``unevaluable_rows`` count still includes those rows; ``partition()``
is the classification that separates them.

The command is read-only.  Use ``--input`` to validate a saved Cloudflare D1
JSON response, or provide credentials plus ``--database-id`` for one live
read.  It never loads, writes, or prints credentials.

Exit status: 0 compliant or documented exception; 1 violated or unevaluable;
2 indeterminate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, NoReturn


CANONICAL_REGIONS = ("wnam", "enam", "weur", "sam", "apac", "afr")
_REGIONS_SQL = ", ".join(f"'{region}'" for region in CANONICAL_REGIONS)
PUBLIC_EVENTS = (
    "corelink.cas.read.attempted",
    "corelink.cas.read.served",
    "corelink.cas.write.attempted",
    "corelink.cas.write.committed",
    "public.revoke",
    "corelink.signup.pilot_reserved.v1",
    "corelink.signup.pilot_token_rejected.v1",
    "corelink.signup.pilot_rate_limited.v1",
)
_PUBLIC_EVENTS_SQL = ", ".join(f"'{event}'" for event in PUBLIC_EVENTS)

# ``EXISTS`` is intentional: an erased tenant can have one row per erased
# backend, and joining that table would multiply audit rows and corrupt the
# denominator this control is protecting.
RESIDENCY_SQL = f"""
WITH classified AS (
    SELECT
        a.tenant_id,
        a.region AS audit_region,
        t.tenant_id AS joined_tenant_id,
        CASE
            WHEN a.tenant_id = '_public'
              AND a.region = 'wnam'
              AND a.event_type IN ({_PUBLIC_EVENTS_SQL})
                THEN 'reserved_public'
            WHEN a.tenant_id = '_public' THEN 'unevaluable'
            WHEN t.tenant_id IS NULL
              OR a.region IS NULL
              OR t.primary_region IS NULL
              OR a.region NOT IN ({_REGIONS_SQL})
              OR t.primary_region NOT IN ({_REGIONS_SQL})
                THEN 'unevaluable'
            WHEN a.region = t.primary_region THEN 'satisfied'
            ELSE 'violated'
        END AS residency_state,
        CASE WHEN a.tenant_id != '_public' AND t.tenant_id IS NULL
                  AND EXISTS (
                      SELECT 1 FROM dsr_erasure_log AS d
                      WHERE d.tenant_id = a.tenant_id
                  )
             THEN 1 ELSE 0 END AS erased_orphan
    FROM audit_outbox AS a
    LEFT JOIN tenant AS t ON t.tenant_id = a.tenant_id
)
SELECT
    COUNT(*) AS total_rows,
    SUM(tenant_id != '_public') AS customer_rows,
    SUM(tenant_id = '_public') AS public_rows,
    SUM(residency_state = 'reserved_public') AS reserved_public_rows,
    SUM(tenant_id = '_public' AND residency_state = 'unevaluable')
        AS invalid_public_rows,
    SUM(residency_state = 'satisfied') AS satisfied_rows,
    SUM(residency_state = 'violated') AS violated_rows,
    SUM(residency_state = 'unevaluable') AS unevaluable_rows,
    SUM(tenant_id != '_public' AND residency_state = 'unevaluable')
        AS customer_unevaluable_rows,
    SUM(tenant_id != '_public' AND joined_tenant_id IS NULL) AS orphan_rows,
    COUNT(DISTINCT CASE WHEN tenant_id != '_public' AND joined_tenant_id IS NULL THEN tenant_id END)
        AS orphan_tenants,
    SUM(erased_orphan) AS erased_orphan_rows,
    COUNT(DISTINCT CASE WHEN erased_orphan = 1 THEN tenant_id END)
        AS erased_orphan_tenants,
    SUM(tenant_id != '_public' AND joined_tenant_id IS NULL) - SUM(erased_orphan)
        AS unexplained_orphan_rows,
    COUNT(DISTINCT CASE WHEN tenant_id != '_public' AND joined_tenant_id IS NULL AND erased_orphan = 0
                        THEN tenant_id END) AS unexplained_orphan_tenants,
    SUM(audit_region = 'weur') AS weur_audit_rows,
    SUM(audit_region = 'weur' AND tenant_id != '_public' AND joined_tenant_id IS NULL)
        AS weur_orphan_rows,
    (SELECT COUNT(*) FROM tenant WHERE primary_region = 'weur') AS weur_tenants,
    (SELECT COUNT(*) FROM dsr_erasure_log) AS erasure_log_rows
FROM classified
""".strip()

COUNT_FIELDS = (
    "total_rows",
    "customer_rows",
    "public_rows",
    "reserved_public_rows",
    "invalid_public_rows",
    "satisfied_rows",
    "violated_rows",
    "unevaluable_rows",
    "customer_unevaluable_rows",
    "orphan_rows",
    "orphan_tenants",
    "erased_orphan_rows",
    "erased_orphan_tenants",
    "unexplained_orphan_rows",
    "unexplained_orphan_tenants",
    "weur_audit_rows",
    "weur_orphan_rows",
    "weur_tenants",
    "erasure_log_rows",
)


COMPLIANT = "COMPLIANT"
DOCUMENTED_EXCEPTION = "DOCUMENTED_EXCEPTION"
FAILED = "FAILED"
PASSING_STATES = (COMPLIANT, DOCUMENTED_EXCEPTION)
ERASED_LINEAGE_POLICY = (
    "#1669 policy B, owner decision 2026-10-01: rows orphaned by a recorded DSR "
    "erasure are retained Art. 5(2) audit evidence and a documented exception "
    "(erased lineage), not non-compliant and not satisfied"
)
FAILED_REASON = "known violations or unevaluable rows exist; neither may be reported compliant"
DOCUMENTED_EXCEPTION_REASON = (
    "no violated or unevaluable rows; the only non-satisfied customer rows are erased "
    "lineage retained under the #1669 policy B documented exception, never reported compliant"
)
COMPLIANT_REASON = "all customer rows are satisfied and all public rows meet the reserved-namespace contract"
STATE_FIELDS = ("satisfied", "violated", "erased_lineage_exception", "unevaluable", "reserved_public")


class Indeterminate(ValueError):
    """Evidence is absent, malformed, partial, or otherwise not trustworthy."""


@dataclass(frozen=True)
class Counts:
    total_rows: int
    customer_rows: int
    public_rows: int
    reserved_public_rows: int
    invalid_public_rows: int
    satisfied_rows: int
    violated_rows: int
    unevaluable_rows: int
    customer_unevaluable_rows: int
    orphan_rows: int
    orphan_tenants: int
    erased_orphan_rows: int
    erased_orphan_tenants: int
    unexplained_orphan_rows: int
    unexplained_orphan_tenants: int
    weur_audit_rows: int
    weur_orphan_rows: int
    weur_tenants: int
    erasure_log_rows: int


def _count(row: dict[str, Any], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Indeterminate(f"D1 result field {field!r} is missing or not a non-negative integer")
    return value


def parse_d1_response(payload: object) -> Counts:
    """Parse exactly one successful D1 query result; never default missing counts."""
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise Indeterminate("D1 response is missing success=true")
    result = payload.get("result")
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise Indeterminate("D1 response must contain exactly one result set")
    result_set = result[0]
    if result_set.get("success") is not True:
        raise Indeterminate("D1 result set is missing success=true")
    rows = result_set.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Indeterminate("D1 response must contain exactly one aggregate row")
    row = rows[0]
    if set(row) != set(COUNT_FIELDS):
        raise Indeterminate("D1 aggregate row fields are missing or unexpected")
    return Counts(**{field: _count(row, field) for field in COUNT_FIELDS})


def assess(counts: Counts, *, environment: str) -> tuple[str, str]:
    """Return the explicit state and reason after checking partition invariants."""
    if counts.total_rows == 0:
        raise Indeterminate("audit_outbox population is empty; no residency claim is proven")
    if counts.customer_rows + counts.public_rows != counts.total_rows:
        raise Indeterminate("customer and public populations do not equal the full audit_outbox population")
    if counts.reserved_public_rows + counts.invalid_public_rows != counts.public_rows:
        raise Indeterminate("valid and invalid public rows do not partition the public namespace")
    if counts.satisfied_rows + counts.violated_rows + counts.customer_unevaluable_rows != counts.customer_rows:
        raise Indeterminate("three-state customer partition does not equal its population")
    if counts.customer_unevaluable_rows + counts.invalid_public_rows != counts.unevaluable_rows:
        raise Indeterminate("public and customer unevaluable rows do not equal the failing bucket")
    if counts.satisfied_rows + counts.violated_rows + counts.unevaluable_rows + counts.reserved_public_rows != counts.total_rows:
        raise Indeterminate("all residency states do not equal the full audit_outbox population")
    if counts.orphan_rows > counts.customer_unevaluable_rows:
        raise Indeterminate("orphan rows escaped the unevaluable bucket")
    if counts.erased_orphan_rows > counts.orphan_rows:
        raise Indeterminate("erased-orphan rows exceed the orphan denominator")
    if counts.erased_orphan_tenants > counts.orphan_tenants:
        raise Indeterminate("erased-orphan tenants exceed the orphan denominator")
    if counts.unexplained_orphan_rows != counts.orphan_rows - counts.erased_orphan_rows:
        raise Indeterminate("unexplained-orphan count does not conserve the orphan denominator")
    if counts.unexplained_orphan_tenants != counts.orphan_tenants - counts.erased_orphan_tenants:
        raise Indeterminate("unexplained-orphan tenant count does not conserve the orphan denominator")
    if counts.weur_orphan_rows > counts.weur_audit_rows:
        raise Indeterminate("weur orphan count exceeds the weur audit population")
    if environment == "production" and counts.erasure_log_rows == 0:
        raise Indeterminate("production DSR-erasure control is empty; orphan classification is unproven")
    states = partition(counts)
    if states["violated"] or states["unevaluable"]:
        return (FAILED, FAILED_REASON)
    if states["erased_lineage_exception"]:
        return (DOCUMENTED_EXCEPTION, DOCUMENTED_EXCEPTION_REASON)
    return (COMPLIANT, COMPLIANT_REASON)


def partition(counts: Counts) -> dict[str, int]:
    """Disjoint, exhaustive residency states under the #1669 policy B contract.

    Only rows counted by ``erased_orphan_rows`` leave the failing bucket: the
    unexplained orphans, the other unevaluable customer rows and the invalid
    public rows stay ``unevaluable``. Callers must run the ``assess`` partition
    invariants first; this function re-checks conservation and fails closed.
    """
    unevaluable = counts.unevaluable_rows - counts.erased_orphan_rows
    if unevaluable < 0 or counts.erased_orphan_rows > counts.customer_unevaluable_rows:
        raise Indeterminate("erased-lineage rows exceed the customer unevaluable bucket")
    states = {
        "satisfied": counts.satisfied_rows,
        "violated": counts.violated_rows,
        "erased_lineage_exception": counts.erased_orphan_rows,
        "unevaluable": unevaluable,
        "reserved_public": counts.reserved_public_rows,
    }
    if sum(states.values()) != counts.total_rows:
        raise Indeterminate("policy-B residency states do not equal the full audit_outbox population")
    return states


def _live_payload(account_id: str, token: str, database_id: str, timeout: int) -> object:
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{database_id}/query",
        data=json.dumps({"sql": RESIDENCY_SQL}).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Indeterminate(f"live D1 query unavailable or malformed: {exc}") from exc


def _indeterminate(message: str) -> NoReturn:
    print(f"status=INDETERMINATE reason={message}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=("production", "staging", "test"), required=True)
    parser.add_argument("--input", type=Path, help="saved raw Cloudflare D1 JSON response")
    parser.add_argument("--database-id", help="D1 database UUID for a read-only live query")
    parser.add_argument("--account-id", default=os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
    parser.add_argument("--api-token", default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument("--timeout-seconds", type=int, default=20)
    args = parser.parse_args(argv)

    if not 1 <= args.timeout_seconds <= 60:
        _indeterminate("timeout must be between 1 and 60 seconds")
    if args.input and args.database_id:
        _indeterminate("choose exactly one evidence source: --input or --database-id")
    if not args.input and not args.database_id:
        _indeterminate("missing evidence source: provide --input or --database-id")

    try:
        if args.input:
            payload = json.loads(args.input.read_text(encoding="utf-8"))
        else:
            if not args.account_id or not args.api_token:
                raise Indeterminate("live query requires account ID and API token")
            payload = _live_payload(args.account_id, args.api_token, args.database_id, args.timeout_seconds)
        counts = parse_d1_response(payload)
        state, reason = assess(counts, environment=args.environment)
    except (OSError, json.JSONDecodeError, Indeterminate) as exc:
        _indeterminate(str(exc))

    print(
        json.dumps(
            {
                "environment": args.environment,
                "status": state,
                "reason": reason,
                "counts": asdict(counts),
                "states": partition(counts),
                "exception_policy": ERASED_LINEAGE_POLICY,
            },
            sort_keys=True,
        )
    )
    return 0 if state in PASSING_STATES else 1


if __name__ == "__main__":
    raise SystemExit(main())
