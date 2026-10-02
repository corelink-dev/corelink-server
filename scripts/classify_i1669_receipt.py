#!/usr/bin/env python3
"""Classify a retained, redacted #1669 aggregate receipt without D1 access.

Under the #1669 policy B owner decision (2026-10-01) the DSR-erased orphans are
their own class with the ``DOCUMENTED_EXCEPTION_ERASED_LINEAGE`` disposition:
preserved, not satisfied, not unevaluable, never compliant. For a v2 receipt,
the unexplained orphans whose opaque row reference is in the owner-attested
ledger (owner decision 2026-10-02) are the
``owner_attested_prelaunch_test_traffic`` class with the
``DOCUMENTED_EXCEPTION_OWNER_ATTESTED_NOT_LOG_CONFIRMED`` disposition; the
attestation is recomputed from the receipt's references and the current
ledger, and applies only when the receipt's database is the production D1 the
owner decision covers. Every other unexplained orphan remains unevaluable and
keeps the issue open; v1 receipts carry no references, so all of their
unexplained orphans do.

A receipt's recorded verdict is verified under the rule it was written with:
schema v1 predates policy B, so a v1 verdict is checked against
``assess_pre_policy_b`` and kept exactly as recorded (``source_status``). The
current-policy reading is reported separately as ``current_policy_status`` and
never changes ``overall_disposition``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_i1669_readonly", ROOT / "scripts" / "probe_i1669_readonly.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("issue-1669 probe schema is unavailable")
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)


class ReceiptError(ValueError):
    """The saved aggregate receipt cannot support a trustworthy classification."""


RECEIPT_FIELDS = {
    "schema",
    "issue",
    "mode",
    "captured_at",
    "account_id_sha256",
    "database_id_sha256",
    "queries",
    "counts",
    "status",
    "reason",
    "receipt_sha256",
}
# v2 adds the owner-attestation block; v1 receipts (before 2026-10-02) lack it.
RECEIPT_FIELDS_V2 = RECEIPT_FIELDS | {"attestation"}
QUERY_FIELDS = {"name", "query_sha256", "response_sha256", "row_count"}
RESIDUAL_FIELDS = {"residual_rows", "row_refs"}
OWNER_ATTESTED_DISPOSITION = "DOCUMENTED_EXCEPTION_OWNER_ATTESTED_NOT_LOG_CONFIRMED"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _nonnegative_fields(value: object, fields: tuple[str, ...], label: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ReceiptError(f"{label} fields are missing or unexpected")
    result: dict[str, int] = {}
    for name in fields:
        count = value[name]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ReceiptError(f"{label}.{name} is not a non-negative integer")
        result[name] = count
    return result


def classify(receipt: object, ledger: Any = None) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt is not an object")
    schema = receipt.get("schema")
    is_v2 = schema == PROBE.RECEIPT_SCHEMA_V2
    if set(receipt) != (RECEIPT_FIELDS_V2 if is_v2 else RECEIPT_FIELDS):
        raise ReceiptError("receipt fields are missing or unexpected")
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_sha256", None)
    expected = hashlib.sha256(_canonical(unsigned)).hexdigest()
    if not isinstance(digest, str) or digest != expected:
        raise ReceiptError("receipt digest does not match its contents")
    if (
        schema not in (PROBE.RECEIPT_SCHEMA_V1, PROBE.RECEIPT_SCHEMA_V2)
        or receipt.get("issue") != 1669
        or receipt.get("mode") != "production_read_only"
    ):
        raise ReceiptError("receipt schema, issue, or evidence mode is unexpected")
    captured_at = receipt.get("captured_at")
    try:
        timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ReceiptError("receipt capture time is malformed") from exc
    if timestamp.tzinfo is None:
        raise ReceiptError("receipt capture time must include a timezone")
    for name in ("account_id_sha256", "database_id_sha256"):
        if not isinstance(receipt[name], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[name]):
            raise ReceiptError(f"receipt {name} is malformed")

    queries = receipt.get("queries")
    expected_names = tuple(PROBE.QUERY_ALLOWLIST) if is_v2 else PROBE.AGGREGATE_QUERY_NAMES
    if not isinstance(queries, list) or len(queries) != len(expected_names):
        raise ReceiptError("receipt does not contain the complete query allowlist")
    for item, name in zip(queries, expected_names, strict=True):
        if not isinstance(item, dict) or set(item) != QUERY_FIELDS:
            raise ReceiptError(f"receipt query {name} fields are missing or unexpected")
        if item.get("name") != name:
            raise ReceiptError("receipt query order or name is unexpected")
        if item.get("query_sha256") != PROBE._hash(PROBE.QUERY_ALLOWLIST[name]):
            raise ReceiptError(f"receipt query hash does not match {name}")
        if not isinstance(item.get("query_sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", item["query_sha256"]
        ):
            raise ReceiptError(f"receipt query hash is malformed for {name}")
        if not isinstance(item.get("response_sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", item["response_sha256"]
        ):
            raise ReceiptError(f"receipt response hash is malformed for {name}")
        row_count = item.get("row_count")
        if name == "residual_refs":
            if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0:
                raise ReceiptError("receipt query residual_refs row count is malformed")
        elif isinstance(row_count, bool) or not isinstance(row_count, int) or row_count != 1:
            raise ReceiptError(f"receipt query {name} is not a single aggregate row")

    counts = receipt.get("counts")
    if not isinstance(counts, dict) or set(counts) != set(expected_names):
        raise ReceiptError("receipt aggregate set is incomplete or unexpected")
    attestation = None
    if is_v2:
        residual = counts["residual_refs"]
        if not isinstance(residual, dict) or set(residual) != RESIDUAL_FIELDS:
            raise ReceiptError("receipt residual reference fields are missing or unexpected")
        refs = residual["row_refs"]
        if (
            not isinstance(refs, list)
            or refs != sorted(refs)
            or len(set(refs)) != len(refs)
            or not all(isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{64}", ref) for ref in refs)
        ):
            raise ReceiptError("receipt residual references are not sorted unique SHA-256 hex")
        if len(refs) > PROBE.RESIDENCY.MAX_RESIDUAL_REFS:
            raise ReceiptError("receipt residual references exceed the enumeration bound")
        if residual["residual_rows"] != len(refs) or queries[-1]["row_count"] != len(refs):
            raise ReceiptError("receipt residual row count does not match its references")
        in_scope = receipt["database_id_sha256"] == PROBE.RESIDENCY.database_id_digest(
            PROBE.RESIDENCY.OWNER_ATTESTED_DATABASE_ID
        )
        if not in_scope:
            # The owner decision covers the production D1 only.
            if receipt.get("attestation") is not None:
                raise ReceiptError("receipt applies the owner attestation outside the production D1 it covers")
        else:
            try:
                # Recomputed from the references and the CURRENT ledger: the
                # probe's own attestation block is checked against this, never
                # trusted.
                attestation = PROBE.RESIDENCY.attest(
                    refs, ledger if ledger is not None else PROBE.RESIDENCY.load_ledger()
                )
            except PROBE.RESIDENCY.Indeterminate as exc:
                raise ReceiptError(f"owner attestation is indeterminate: {exc}") from exc
            if receipt.get("attestation") != attestation.summary():
                raise ReceiptError("receipt attestation does not match its references and the current ledger")
    residency = _nonnegative_fields(counts["residency"], PROBE.RESIDENCY.COUNT_FIELDS, "residency")
    population = _nonnegative_fields(counts["population"], PROBE.POPULATION_FIELDS, "population")
    completeness = _nonnegative_fields(
        counts["backfill_completeness"], PROBE.BACKFILL_FIELDS, "backfill_completeness"
    )
    model = PROBE.RESIDENCY.Counts(**residency)
    if (
        model.orphan_tenants > model.orphan_rows
        or model.erased_orphan_tenants > model.erased_orphan_rows
        or model.unexplained_orphan_tenants > model.unexplained_orphan_rows
    ):
        raise ReceiptError("tenant counts exceed their orphan row counts")
    try:
        # The current policy (B + owner attestation) and, separately, the rule
        # the receipt was written under: v1 receipts predate policy B and are
        # verified against the pre-policy-B rule, exactly as recorded.
        state, reason = PROBE.RESIDENCY.assess(model, environment="production", attestation=attestation)
        if is_v2:
            recorded_state, recorded_reason, verdict_rule = state, reason, "policy_b_owner_attestation"
        else:
            recorded_state, recorded_reason = PROBE.RESIDENCY.assess_pre_policy_b(model, environment="production")
            verdict_rule = "pre_policy_b"
    except PROBE.RESIDENCY.Indeterminate as exc:
        raise ReceiptError(f"residency partition is indeterminate: {exc}") from exc
    total = model.total_rows
    if population["audit_rows"] != total or population["blank_tenant_rows"]:
        raise ReceiptError("population aggregate does not reconcile with residency")
    if not 1 <= population["audit_tenants"] <= population["audit_rows"]:
        raise ReceiptError("population tenant count is outside its audit row bounds")
    if completeness["audit_rows"] != total:
        raise ReceiptError("backfill denominator does not reconcile with residency")
    backfill_partition = (
        completeness["orphan_rows"]
        + completeness["joinable_rows"]
        + completeness["reserved_public_rows"]
        + completeness["invalid_public_rows"]
    )
    if backfill_partition != total:
        raise ReceiptError("backfill completeness partition is partial")
    for key in ("orphan_rows", "reserved_public_rows", "invalid_public_rows", "erased_orphan_rows"):
        if completeness[key] != residency[key]:
            raise ReceiptError(f"backfill {key} does not reconcile with residency")
    if receipt.get("status") != recorded_state or receipt.get("reason") != recorded_reason:
        raise ReceiptError("receipt verdict does not match its counts")

    attested_rows = attestation.attested_rows if attestation is not None else 0
    unattested_rows = model.unexplained_orphan_rows - attested_rows
    classes = [
        {
            "class": "satisfied_customer",
            "rows": model.satisfied_rows,
            "tenants": None,
            "disposition": "PROVEN",
        },
        {
            "class": "violated_customer",
            "rows": model.violated_rows,
            "tenants": None,
            "disposition": "FAIL_CLOSED_INVESTIGATE",
        },
        {
            "class": "erased_orphan_retained_audit",
            "rows": model.erased_orphan_rows,
            "tenants": model.erased_orphan_tenants,
            "disposition": "DOCUMENTED_EXCEPTION_ERASED_LINEAGE",
        },
        {
            "class": PROBE.RESIDENCY.OWNER_ATTESTED_CATEGORY,
            "rows": attested_rows,
            "tenants": None,
            "disposition": OWNER_ATTESTED_DISPOSITION,
        },
        {
            "class": "unexplained_orphan",
            "rows": unattested_rows,
            # Tenant counts cannot be split by attestation from references.
            "tenants": model.unexplained_orphan_tenants if attested_rows == 0 else None,
            "disposition": "PRESERVE_AND_REQUIRE_RESTRICTED_OWNER_RECONCILIATION",
        },
        {
            "class": "other_unevaluable_customer",
            "rows": model.customer_unevaluable_rows - model.orphan_rows,
            "tenants": None,
            "disposition": "FAIL_CLOSED_INVESTIGATE",
        },
        {
            "class": "reserved_public",
            "rows": model.reserved_public_rows,
            "tenants": None,
            "disposition": "VALID_SYSTEM_NAMESPACE",
        },
        {
            "class": "invalid_public",
            "rows": model.invalid_public_rows,
            "tenants": None,
            "disposition": "FAIL_CLOSED_INVESTIGATE",
        },
    ]
    if sum(item["rows"] for item in classes) != total:
        raise ReceiptError("disposition classes do not conserve the full population")
    by_class = {item["class"]: item["rows"] for item in classes}
    states = PROBE.RESIDENCY.partition(model, attestation)
    category = PROBE.RESIDENCY.OWNER_ATTESTED_CATEGORY
    if (
        states["erased_lineage_exception"] != by_class["erased_orphan_retained_audit"]
        or states[category] != by_class[category]
        or states["unevaluable"]
        != (
            by_class["unexplained_orphan"]
            + by_class["other_unevaluable_customer"]
            + by_class["invalid_public"]
        )
    ):
        raise ReceiptError("disposition classes do not match the policy-B residency states")
    # The disposition follows the verdict the receipt RECORDED (verified under
    # its own rule); the current-policy re-reading is reported separately and
    # never upgrades a historical receipt.
    if recorded_state == PROBE.RESIDENCY.COMPLIANT:
        overall = "COMPLIANT"
    elif recorded_state == PROBE.RESIDENCY.DOCUMENTED_EXCEPTION:
        overall = "DOCUMENTED_EXCEPTION"
    else:
        overall = "KEEP_OPEN"
    return {
        "schema": "corelink.issue-1669.aggregate-classification.v2",
        "issue": 1669,
        "receipt_sha256": digest,
        "receipt_schema": schema,
        "verdict_rule": verdict_rule,
        "source_status": recorded_state,
        "source_reason": recorded_reason,
        "current_policy_status": state,
        "classification_scope": "aggregate_counts_only",
        "exception_policy": PROBE.RESIDENCY.ERASED_LINEAGE_POLICY,
        "attestation": attestation.summary() if attestation is not None else None,
        "tenant_identity_dispositions_complete": (
            unattested_rows == 0
            and (attestation is not None or model.unexplained_orphan_tenants == 0)
            and (attestation is None or attestation.attested_refs_missing == 0)
        ),
        "states": states,
        "classes": classes,
        "overall_disposition": overall,
    }


def verify_sidecar(receipt_path: Path, sidecar_path: Path) -> str:
    if receipt_path.is_symlink() or sidecar_path.is_symlink():
        raise ReceiptError("receipt and checksum sidecar must not be symlinks")
    try:
        line = sidecar_path.read_text(encoding="utf-8").strip()
        expected, separator, artifact_name = line.partition("  ")
        actual = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ReceiptError("receipt or checksum sidecar is unavailable") from exc
    if not separator or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ReceiptError("checksum sidecar is malformed")
    if Path(artifact_name).name != receipt_path.name or actual != expected:
        raise ReceiptError("receipt does not match its artifact checksum")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "receipt", type=Path, help="redacted receipt downloaded from the hosted evidence run"
    )
    parser.add_argument(
        "--sha256", required=True, type=Path, help="matching artifact checksum sidecar"
    )
    args = parser.parse_args()
    try:
        artifact_sha256 = verify_sidecar(args.receipt, args.sha256)
        report = classify(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ReceiptError) as exc:
        print(f"status=INDETERMINATE reason={exc}", file=sys.stderr)
        return 2
    report["artifact_sha256"] = artifact_sha256
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_disposition"] in ("COMPLIANT", "DOCUMENTED_EXCEPTION") else 1


if __name__ == "__main__":
    raise SystemExit(main())
