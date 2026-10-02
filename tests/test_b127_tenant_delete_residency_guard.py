"""Focused SQLite controls for the B-127 tenant-delete guard."""

from __future__ import annotations

import importlib.util
import re
import sqlite3
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/d1/0122_b127_tenant_delete_residency_guard.sql"
SIGNUP_E2E = ROOT / "scripts/e2e-clerk-signup.sh"
CLASSIFIER = ROOT / "scripts/b127_residual_classification.sql"
REPORT = ROOT / "reports/go-live/2026-09-09-b127-residual-classification.md"


def database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT NOT NULL);
        CREATE TABLE audit_outbox (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, region TEXT NOT NULL);
        CREATE TABLE dsr_requested (dsr_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);
        """
    )
    connection.executescript(MIGRATION.read_text(encoding="utf-8"))
    return connection


def seed(connection: sqlite3.Connection, tenant_id: str, *, audit: bool = True) -> None:
    connection.execute("INSERT INTO tenant VALUES (?, 'enam')", (tenant_id,))
    if audit:
        connection.execute(
            "INSERT INTO audit_outbox VALUES (?, ?, 'enam')",
            (f"audit-{tenant_id}", tenant_id),
        )


def test_direct_delete_cannot_orphan_retained_audit() -> None:
    connection = database()
    seed(connection, "test-tenant")

    with pytest.raises(sqlite3.IntegrityError, match="residency_unprovable"):
        connection.execute("DELETE FROM tenant WHERE tenant_id = 'test-tenant'")

    assert connection.execute(
        "SELECT COUNT(*) FROM tenant WHERE tenant_id = 'test-tenant'"
    ).fetchone() == (1,)


def test_durable_dsr_anchor_authorizes_delete_and_retains_audit() -> None:
    connection = database()
    seed(connection, "erased-tenant")
    connection.execute("INSERT INTO dsr_requested VALUES ('dsr-1', 'erased-tenant')")

    connection.execute("DELETE FROM tenant WHERE tenant_id = 'erased-tenant'")

    assert connection.execute(
        "SELECT COUNT(*) FROM audit_outbox WHERE tenant_id = 'erased-tenant'"
    ).fetchone() == (1,)


def test_tenant_without_audit_history_can_be_deleted() -> None:
    connection = database()
    seed(connection, "empty-tenant", audit=False)

    connection.execute("DELETE FROM tenant WHERE tenant_id = 'empty-tenant'")

    assert connection.execute(
        "SELECT COUNT(*) FROM tenant WHERE tenant_id = 'empty-tenant'"
    ).fetchone() == (0,)


def test_guard_contains_both_causal_predicates() -> None:
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "exists (\n    select 1 from audit_outbox" in sql
    assert "not exists (\n    select 1 from dsr_requested" in sql
    assert "before delete on tenant" in sql


def test_signup_e2e_uses_dsr_cleanup_instead_of_direct_d1_deletes() -> None:
    script = SIGNUP_E2E.read_text(encoding="utf-8")
    assert 'FROM dsr_requested WHERE tenant_id = \'${TENANT_ID}\'' in script
    assert 'DELETE FROM tenant WHERE tenant_id' not in script
    assert 'DELETE FROM pat WHERE tenant_id' not in script
    assert 'Clerk user.deleted → DSR owns cleanup' in script
    assert 'fail "Clerk DELETE returned ${delete_resp} (non-200)' in script
    assert 'cleanup is unproven' in script


def test_residual_classifier_is_redacted_read_only_and_deterministic() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY);
        CREATE TABLE audit_outbox (
            tenant_id TEXT, region TEXT, event_type TEXT,
            enqueued_at INTEGER, emitted_at INTEGER
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT, backend TEXT, outcome TEXT);
        CREATE TABLE tenant_storage_state (
            tenant_id TEXT, region TEXT, bytes_used INTEGER,
            created_at_ms INTEGER, updated_at_ms INTEGER
        );
        CREATE TABLE usage_daily (
            tenant_id TEXT, reads INTEGER, writes INTEGER,
            hits INTEGER, misses INTEGER
        );
        INSERT INTO audit_outbox VALUES
            ('raw-secret-b', 'weur', 'write', 20, 21),
            ('raw-secret-a', 'wnam', 'read', 10, 11),
            ('_public', 'wnam', 'public.revoke', 30, 31);
        INSERT INTO tenant_storage_state VALUES
            ('raw-secret-b', 'lhr', 19, 20, 22),
            ('_public', 'iad', 244377715, 5, 30);
        INSERT INTO usage_daily VALUES
            ('raw-secret-b', 1, 1, 1, 0);
        """
    )
    cursor = connection.execute(CLASSIFIER.read_text(encoding="utf-8"))
    columns = tuple(column[0] for column in cursor.description)
    rows = cursor.fetchall()

    assert "tenant_id" not in columns
    by_alias = {row[0]: row for row in rows}
    assert set(by_alias) == {"orphan_1", "orphan_2", "reserved_public"}
    assert by_alias["orphan_1"][1] == "unexplained_tenant"
    assert by_alias["orphan_2"][1] == "unexplained_tenant"
    assert by_alias["reserved_public"][1] == "reserved_namespace"
    assert by_alias["reserved_public"][4] == 1
    assert by_alias["reserved_public"][8] == "iad"
    assert by_alias["reserved_public"][9] == 1
    assert by_alias["reserved_public"][10] == 244377715
    assert "raw-secret-a" not in repr(rows)
    assert "raw-secret-b" not in repr(rows)
    assert all(value != "_public" for row in rows for value in row)

    executable = CLASSIFIER.read_text(encoding="utf-8").lower()
    assert " delete " not in executable
    assert " update " not in executable
    assert " insert " not in executable


def _verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_audit_residency_for_b127_guard", ROOT / "scripts/verify_audit_residency.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _erasure_database(*log_rows: tuple) -> sqlite3.Connection:
    """Two orphan tenants; 'gone-b' carries the given erasure-log rows."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (
            id TEXT PRIMARY KEY, tenant_id TEXT, region TEXT, event_type TEXT,
            enqueued_at INTEGER, emitted_at INTEGER
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT, backend TEXT, outcome TEXT);
        CREATE TABLE tenant_storage_state (
            tenant_id TEXT, region TEXT, bytes_used INTEGER,
            created_at_ms INTEGER, updated_at_ms INTEGER
        );
        CREATE TABLE usage_daily (
            tenant_id TEXT, reads INTEGER, writes INTEGER,
            hits INTEGER, misses INTEGER
        );
        INSERT INTO audit_outbox VALUES
            ('row-a', 'gone-a', 'wnam', 'read', 10, 11),
            ('row-b1', 'gone-b', 'weur', 'write', 20, 21),
            ('row-b2', 'gone-b', 'weur', 'read', 22, 23);
        """
    )
    connection.executemany("INSERT INTO dsr_erasure_log VALUES ('gone-b', ?, ?)", log_rows)
    return connection


@pytest.mark.parametrize(
    ("log_rows", "gone_b_in_residual"),
    [
        ((("d1", "erased"),), False),
        ((("d1", "failed"), ("d1", "erased")), False),
        ((("d1", "partial_failure"),), True),
        ((("d1", "failed"),), True),
        ((("d1", "not_applicable"),), True),  # legal hold: data preserved
        ((("d1", "pseudonymized"),), True),
        ((("d1", "bogus"),), True),
        ((("d1", None),), True),
        (((None, "erased"),), True),
        ((("stripe", "erased"),), True),
        ((), True),
    ],
)
def test_residual_classifier_uses_the_completed_d1_erasure_condition(log_rows: tuple, gone_b_in_residual: bool) -> None:
    connection = _erasure_database(*log_rows)
    rows = connection.execute(CLASSIFIER.read_text(encoding="utf-8")).fetchall()
    unexplained = [row for row in rows if row[1] == "unexplained_tenant"]
    assert len(unexplained) == (2 if gone_b_in_residual else 1)
    classified_rows = sum(row[4] for row in unexplained)
    # Same residual as the verifier's RESIDUAL_REFS_SQL: the two definitions cannot drift.
    verifier_rows = connection.execute(_verifier().RESIDUAL_REFS_SQL).fetchall()
    assert classified_rows == len(verifier_rows) == (3 if gone_b_in_residual else 1)


def assert_report_reconciled(report: str) -> None:
    required_equations = (
        "84,932 = 84,801 customer-scoped + 131 reserved `_public`",
        "84,801 = 81,262 satisfied + 0 violated + 3,539 unevaluable",
        "3,539 = 3,526 DSR-erased / 170 tenants + 13 unexplained / 4 tenants",
        "144 = 131 reserved `_public` + 13 unexplained tenant rows",
    )
    for equation in required_equations:
        assert equation in report

    rows = re.findall(
        r"^\| `(orphan_[1-4]|reserved_public)` \| "
        r"`(unexplained_tenant|reserved_namespace)` \| \*\*(\d+)\*\* \|",
        report,
        re.MULTILINE,
    )
    observed = {alias: (classification, int(count)) for alias, classification, count in rows}
    assert observed == {
        "orphan_1": ("unexplained_tenant", 4),
        "orphan_2": ("unexplained_tenant", 1),
        "orphan_3": ("unexplained_tenant", 4),
        "orphan_4": ("unexplained_tenant", 4),
        "reserved_public": ("reserved_namespace", 131),
    }
    assert sum(count for alias, (_, count) in observed.items() if alias.startswith("orphan_")) == 13
    assert observed["reserved_public"][1] + 13 == 144
    assert "orphan_5" not in report


def test_report_reconciles_corrected_live_classifier_counts() -> None:
    assert_report_reconciled(REPORT.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("old", "new"),
    (
        ("84,932 = 84,801 customer-scoped + 131", "84,932 = 84,800 customer-scoped + 132"),
        ("| `orphan_4` | `unexplained_tenant` | **4** |", "| `orphan_4` | `unexplained_tenant` | **5** |"),
        ("| `reserved_public` | `reserved_namespace` |", "| `reserved_public` | `unexplained_tenant` |"),
    ),
)
def test_report_reconciliation_mutations_fail(old: str, new: str) -> None:
    report = REPORT.read_text(encoding="utf-8")
    mutated = report.replace(old, new, 1)
    assert mutated != report
    with pytest.raises(AssertionError):
        assert_report_reconciled(mutated)
