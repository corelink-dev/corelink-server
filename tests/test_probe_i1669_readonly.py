"""Adversarial fixtures for the issue #1669 aggregate reconciliation."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_i1669_readonly", ROOT / "scripts" / "probe_i1669_readonly.py"
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def aggregate_fixture(*, invalid_public_region: bool = False) -> tuple[dict, dict]:
    """Return both aggregates over a population containing every row class."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (
            tenant_id TEXT NOT NULL,
            region TEXT NOT NULL,
            event_type TEXT NOT NULL
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL, backend TEXT, outcome TEXT);
        INSERT INTO tenant VALUES ('tenant-e', 'enam');
        INSERT INTO tenant VALUES ('tenant-w', 'wnam');
        INSERT INTO audit_outbox VALUES ('tenant-e', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('tenant-w', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('erased-tenant', 'weur', 'customer.event');
        INSERT INTO audit_outbox VALUES ('unexplained-tenant', 'apac', 'customer.event');
        INSERT INTO audit_outbox VALUES ('_public', 'wnam', 'public.revoke');
        INSERT INTO dsr_erasure_log VALUES ('erased-tenant', 'd1', 'erased');
        """
    )
    if invalid_public_region:
        connection.execute(
            "UPDATE audit_outbox SET region = 'enam' WHERE tenant_id = '_public'"
        )

    residency_cursor = connection.execute(probe.RESIDENCY.RESIDENCY_SQL)
    residency = dict(zip((column[0] for column in residency_cursor.description), residency_cursor.fetchone(), strict=True))
    backfill_cursor = connection.execute(probe.BACKFILL_COMPLETENESS_SQL)
    backfill = dict(zip((column[0] for column in backfill_cursor.description), backfill_cursor.fetchone(), strict=True))
    return residency, backfill


def test_public_namespace_is_a_separate_backfill_partition() -> None:
    residency, backfill = aggregate_fixture()

    assert residency["total_rows"] == 5
    assert residency["orphan_rows"] == 2
    assert residency["reserved_public_rows"] == 1
    assert residency["violated_rows"] == 1
    assert backfill == {
        "audit_rows": 5,
        "orphan_rows": 2,
        "joinable_rows": 2,
        "reserved_public_rows": 1,
        "invalid_public_rows": 0,
        "erased_orphan_rows": 1,
    }
    assert backfill["orphan_rows"] == residency["orphan_rows"]
    assert backfill["reserved_public_rows"] == residency["reserved_public_rows"]
    assert backfill["invalid_public_rows"] == residency["invalid_public_rows"]
    assert backfill["erased_orphan_rows"] == residency["erased_orphan_rows"]
    assert (
        backfill["orphan_rows"]
        + backfill["joinable_rows"]
        + backfill["reserved_public_rows"]
        == residency["total_rows"]
    )


def test_invalid_public_region_still_reconciles_as_invalid_public() -> None:
    residency, backfill = aggregate_fixture(invalid_public_region=True)

    assert residency["invalid_public_rows"] == 1
    assert residency["violated_rows"] == 1
    assert residency["unevaluable_rows"] == 3
    assert backfill["orphan_rows"] == residency["orphan_rows"]
    assert backfill["reserved_public_rows"] == residency["reserved_public_rows"]
    assert backfill["invalid_public_rows"] == residency["invalid_public_rows"]
    assert backfill["erased_orphan_rows"] == residency["erased_orphan_rows"]


def test_backfill_allowlist_requires_explicit_system_scope_bucket() -> None:
    assert "a.tenant_id = '_public'" in probe.BACKFILL_COMPLETENESS_SQL
    assert "reserved_public_rows" in probe.BACKFILL_FIELDS


def _policy_b_population(*, unexplained: int) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL, region TEXT NOT NULL, event_type TEXT NOT NULL
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL, backend TEXT, outcome TEXT);
        INSERT INTO tenant VALUES ('tenant-e', 'enam');
        INSERT INTO audit_outbox VALUES ('row-live', 'tenant-e', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('row-erased', 'erased-tenant', 'weur', 'customer.event');
        INSERT INTO audit_outbox VALUES ('row-public', '_public', 'wnam', 'public.revoke');
        INSERT INTO dsr_erasure_log VALUES ('erased-tenant', 'd1', 'erased');
        """
    )
    for n in range(unexplained):
        connection.execute(
            "INSERT INTO audit_outbox VALUES (?, 'unexplained-tenant', 'apac', 'customer.event')",
            (f"unexplained-row-{n:02d}",),
        )
    return connection


def _ledger(*row_ids: str):
    residency = probe.RESIDENCY
    return residency.Ledger(refs=frozenset(residency.row_ref(i) for i in row_ids), sha256="e" * 64)


PRODUCTION_DB = probe.RESIDENCY.OWNER_ATTESTED_DATABASE_ID
STAGING_DB = "00000000-1111-2222-3333-444444444444"


def _run_against(
    connection: sqlite3.Connection, tmp_path: Path, monkeypatch, ledger, *, database_id: str = PRODUCTION_DB, tamper=None
) -> tuple[int, dict, str]:
    def fake_request(account_id: str, token: str, database_id: str, query: str):
        assert query in probe.QUERY_ALLOWLIST.values()
        cursor = connection.execute(query)
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
        if tamper is not None:
            tamper(query, rows)
        payload = {"success": True, "result": [{"success": True, "results": rows}]}
        return payload, "d" * 64

    monkeypatch.setattr(probe, "_request", fake_request)
    output = tmp_path / "receipt.json"
    code = probe.run("a" * 32, database_id, "token", output, ledger=ledger)
    text = output.read_text(encoding="utf-8")
    return code, json.loads(text), text


def test_erased_lineage_only_population_exits_0_as_documented_exception(tmp_path: Path, monkeypatch) -> None:
    # #1669 policy B: erased lineage is its own passing exception state and the
    # receipt names it; it is never written as COMPLIANT.
    code, receipt, _ = _run_against(_policy_b_population(unexplained=0), tmp_path, monkeypatch, _ledger())
    assert code == 0
    assert receipt["status"] == "DOCUMENTED_EXCEPTION"
    assert receipt["schema"] == "corelink.issue-1669.read-only-residency.v2"
    assert receipt["counts"]["residency"]["erased_orphan_rows"] == 1


def test_unexplained_orphan_beside_erased_lineage_exits_1(tmp_path: Path, monkeypatch) -> None:
    code, receipt, _ = _run_against(_policy_b_population(unexplained=1), tmp_path, monkeypatch, _ledger())
    assert code == 1
    assert receipt["status"] == "FAILED"
    assert receipt["counts"]["residency"]["unexplained_orphan_rows"] == 1


def test_attested_residual_exits_0_and_the_receipt_holds_no_raw_identifier(tmp_path: Path, monkeypatch) -> None:
    ids = [f"unexplained-row-{n:02d}" for n in range(3)]
    code, receipt, text = _run_against(_policy_b_population(unexplained=3), tmp_path, monkeypatch, _ledger(*ids))
    assert (code, receipt["status"]) == (0, "DOCUMENTED_EXCEPTION")
    attestation = receipt["attestation"]
    assert (attestation["attested_rows"], attestation["unattested_rows"], attestation["attested_refs_missing"]) == (3, 0, 0)
    assert attestation["log_confirmed"] is False
    assert receipt["queries"][-1] == {**receipt["queries"][-1], "name": "residual_refs", "row_count": 3}
    for raw in (*ids, "unexplained-tenant", "erased-tenant", "row-erased"):
        assert raw not in text


def test_a_row_outside_the_attested_ledger_exits_1(tmp_path: Path, monkeypatch) -> None:
    ids = [f"unexplained-row-{n:02d}" for n in range(2)]  # third row is not attested
    code, receipt, _ = _run_against(_policy_b_population(unexplained=3), tmp_path, monkeypatch, _ledger(*ids))
    assert (code, receipt["status"]) == (1, "FAILED")
    assert receipt["attestation"]["unattested_rows"] == 1


def test_a_vanished_attested_row_is_reported_and_exits_1(tmp_path: Path, monkeypatch) -> None:
    ledger = _ledger("unexplained-row-00", "a-row-that-is-gone")
    code, receipt, _ = _run_against(_policy_b_population(unexplained=1), tmp_path, monkeypatch, ledger)
    assert (code, receipt["status"], receipt["reason"]) == (1, "FAILED", probe.RESIDENCY.ATTESTED_MISSING_REASON)
    assert receipt["attestation"]["attested_refs_missing"] == 1


def test_an_oversized_residual_is_indeterminate_not_truncated(tmp_path: Path, monkeypatch) -> None:
    code, receipt, _ = _run_against(_policy_b_population(unexplained=65), tmp_path, monkeypatch, _ledger())
    assert (code, receipt["status"]) == (2, "INDETERMINATE")
    # Pins LIMIT MAX+1: with LIMIT MAX the read would be truncated silently and
    # only a later reconciliation would fire, for a different reason.
    assert "exceeds 64 rows" in receipt["reason"]


def test_the_attestation_is_never_applied_to_a_non_production_database(tmp_path: Path, monkeypatch) -> None:
    # Review fix 2: the owner decision covers the production D1 only. Against
    # any other database the ledger is not consulted, even when it would match.
    ids = [f"unexplained-row-{n:02d}" for n in range(3)]
    code, receipt, _ = _run_against(
        _policy_b_population(unexplained=3), tmp_path, monkeypatch, _ledger(*ids), database_id=STAGING_DB
    )
    assert (code, receipt["status"], receipt["reason"]) == (1, "FAILED", probe.RESIDENCY.FAILED_REASON)
    assert receipt["attestation"] is None


def test_backfill_erased_rows_must_reconcile_with_residency(tmp_path: Path, monkeypatch) -> None:
    def tamper(query: str, rows: list[dict]) -> None:
        if query is probe.BACKFILL_COMPLETENESS_SQL:
            rows[0]["erased_orphan_rows"] = 0

    code, receipt, _ = _run_against(
        _policy_b_population(unexplained=0), tmp_path, monkeypatch, _ledger(), tamper=tamper
    )
    assert (code, receipt["status"]) == (2, "INDETERMINATE")
    assert receipt["reason"] == "backfill completeness does not reconcile with residency"


def test_the_probe_refuses_an_allowlist_that_drifted_from_its_pinned_hashes(monkeypatch) -> None:
    drifted = dict(probe.QUERY_ALLOWLIST)
    drifted["residency"] = drifted["residency"] + " "
    monkeypatch.setattr(probe, "QUERY_ALLOWLIST", drifted)
    try:
        probe._validate_allowlist()
    except probe.ProbeError as exc:
        assert "pinned v2 hashes" in str(exc)
    else:
        raise AssertionError("a drifted allowlist was accepted")


def test_an_orphan_whose_d1_erasure_failed_is_residual_not_erased_lineage(tmp_path: Path, monkeypatch) -> None:
    connection = _policy_b_population(unexplained=0)
    connection.execute("INSERT INTO audit_outbox VALUES ('failed-row', 'failed-tenant', 'enam', 'customer.event')")
    connection.execute("INSERT INTO dsr_erasure_log VALUES ('failed-tenant', 'd1', 'failed')")
    code, receipt, _ = _run_against(connection, tmp_path, monkeypatch, _ledger())
    residency = receipt["counts"]["residency"]
    assert (residency["erased_orphan_rows"], residency["unexplained_orphan_rows"]) == (1, 1)
    assert receipt["counts"]["residual_refs"]["residual_rows"] == 1
    assert (code, receipt["status"]) == (1, "FAILED")


def test_residual_refs_query_is_allowlisted_and_read_only() -> None:
    assert probe.QUERY_ALLOWLIST["residual_refs"] is probe.RESIDENCY.RESIDUAL_REFS_SQL
    assert tuple(probe.QUERY_ALLOWLIST)[:3] == probe.AGGREGATE_QUERY_NAMES
    probe._validate_allowlist()
