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
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL);
        INSERT INTO tenant VALUES ('tenant-e', 'enam');
        INSERT INTO tenant VALUES ('tenant-w', 'wnam');
        INSERT INTO audit_outbox VALUES ('tenant-e', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('tenant-w', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('erased-tenant', 'weur', 'customer.event');
        INSERT INTO audit_outbox VALUES ('unexplained-tenant', 'apac', 'customer.event');
        INSERT INTO audit_outbox VALUES ('_public', 'wnam', 'public.revoke');
        INSERT INTO dsr_erasure_log VALUES ('erased-tenant');
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


def _policy_b_population(*, unexplained: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (
            tenant_id TEXT NOT NULL, region TEXT NOT NULL, event_type TEXT NOT NULL
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL);
        INSERT INTO tenant VALUES ('tenant-e', 'enam');
        INSERT INTO audit_outbox VALUES ('tenant-e', 'enam', 'customer.event');
        INSERT INTO audit_outbox VALUES ('erased-tenant', 'weur', 'customer.event');
        INSERT INTO audit_outbox VALUES ('_public', 'wnam', 'public.revoke');
        INSERT INTO dsr_erasure_log VALUES ('erased-tenant');
        """
    )
    if unexplained:
        connection.execute(
            "INSERT INTO audit_outbox VALUES ('unexplained-tenant', 'apac', 'customer.event')"
        )
    return connection


def _run_against(connection: sqlite3.Connection, tmp_path: Path, monkeypatch) -> tuple[int, dict]:
    def fake_request(account_id: str, token: str, database_id: str, query: str):
        assert query in probe.QUERY_ALLOWLIST.values()
        cursor = connection.execute(query)
        row = dict(zip((c[0] for c in cursor.description), cursor.fetchone(), strict=True))
        payload = {"success": True, "result": [{"success": True, "results": [row]}]}
        return payload, "d" * 64

    monkeypatch.setattr(probe, "_request", fake_request)
    output = tmp_path / "receipt.json"
    code = probe.run("a" * 32, "00000000-0000-0000-0000-000000000000", "token", output)
    return code, json.loads(output.read_text(encoding="utf-8"))


def test_erased_lineage_only_population_exits_0_as_documented_exception(tmp_path: Path, monkeypatch) -> None:
    # #1669 policy B: erased lineage is its own passing exception state and the
    # receipt names it; it is never written as COMPLIANT.
    code, receipt = _run_against(_policy_b_population(unexplained=False), tmp_path, monkeypatch)
    assert code == 0
    assert receipt["status"] == "DOCUMENTED_EXCEPTION"
    assert receipt["counts"]["residency"]["erased_orphan_rows"] == 1


def test_unexplained_orphan_beside_erased_lineage_exits_1(tmp_path: Path, monkeypatch) -> None:
    code, receipt = _run_against(_policy_b_population(unexplained=True), tmp_path, monkeypatch)
    assert code == 1
    assert receipt["status"] == "FAILED"
    assert receipt["counts"]["residency"]["unexplained_orphan_rows"] == 1
