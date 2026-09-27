#!/usr/bin/env python3
"""Production-SQL acceptance checks for #2708's staging seal contract."""

import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = [
    ROOT / "migrations/d1/0147_staging_load_test_run_ownership.sql",
    ROOT / "migrations/d1/0149_staging_load_test_r2_intents.sql",
    ROOT / "migrations/d1/0151_staging_load_test_teardown_receipts.sql",
]
SHA = "a" * 40
CLASSES = (
    "cas_reference", "webhook_inbox", "webhook_effect", "dsr_artifact",
    "dsr_obligation", "audit_evidence", "billing_audit", "signup_artifact",
    "byok_artifact",
)


def database():
    connection = sqlite3.connect(":memory:")
    initialize(connection)
    return connection


def initialize(connection):
    connection.execute("PRAGMA foreign_keys = ON")
    for migration in MIGRATIONS:
        connection.executescript(migration.read_text())


def run(connection, run_id="1", scenario="cas", sha=SHA, state="open"):
    connection.execute(
        "INSERT INTO staging_load_test_runs "
        "(run_id, scenario, target_environment, target_deployment_sha, state, admitted_at_ms) "
        "VALUES (?, ?, 'staging', ?, ?, 1)",
        (run_id, scenario, sha, state),
    )


def resource(connection, run_id="1", scenario="cas", resource_class="cas_reference", ref="b" * 64):
    connection.execute(
        "INSERT INTO staging_load_test_resources "
        "(run_id, scenario, resource_class, receipt_ref, opaque_handle, disposition, state, registered_at_ms) "
        "VALUES (?, ?, ?, ?, ?, 'retained', 'registered', 1)",
        (run_id, scenario, resource_class, ref, f"handle-{ref}"),
    )


def seal_batch(connection, run_id="1", scenario="cas", sha=SHA):
    """Execute the route's D1-batch semantics against the shipped migrations."""
    with connection:
        for resource_class in CLASSES:
            connection.execute(
                "INSERT INTO staging_load_test_resource_scans "
                "(run_id, scenario, resource_class, state, observed_count, scanned_at_ms) "
                "SELECT ?, ?, ?, 'complete', "
                "(SELECT count(*) FROM staging_load_test_resources WHERE run_id=? AND scenario=? AND resource_class=?), 2 "
                "WHERE EXISTS (SELECT 1 FROM staging_load_test_runs WHERE run_id=? AND scenario=? "
                "AND target_environment='staging' AND target_deployment_sha=? AND state='open') "
                "ON CONFLICT(run_id, scenario, resource_class) DO UPDATE SET "
                "state=excluded.state, observed_count=excluded.observed_count, scanned_at_ms=excluded.scanned_at_ms",
                (run_id, scenario, resource_class, run_id, scenario, resource_class, run_id, scenario, sha),
            )
        connection.execute(
            "UPDATE staging_load_test_runs SET state=CASE WHEN "
            "(SELECT count(*) FROM staging_load_test_resources WHERE run_id=? AND scenario=?) <= 256 "
            "THEN 'sealed' ELSE 'over_budget' END "
            "WHERE run_id=? AND scenario=? AND target_environment='staging' "
            "AND target_deployment_sha=? AND state='open'",
            (run_id, scenario, run_id, scenario, sha),
        )


class SealProductionSqlTests(unittest.TestCase):
    def test_zero_inventory_emits_the_complete_zero_census(self):
        connection = database()
        run(connection)
        seal_batch(connection)
        rows = dict(connection.execute("SELECT resource_class, observed_count FROM staging_load_test_resource_scans"))
        self.assertEqual(set(rows), set(CLASSES))
        self.assertEqual(set(rows.values()), {0})

    def test_zero_and_mixed_inventory_seals_all_nine_classes_without_touching_other_run(self):
        connection = database()
        run(connection)
        run(connection, run_id="2", sha="c" * 40)
        resource(connection, resource_class="cas_reference")
        resource(connection, resource_class="webhook_inbox", ref="d" * 64)
        seal_batch(connection)
        self.assertEqual(connection.execute("SELECT state FROM staging_load_test_runs WHERE run_id='1'").fetchone()[0], "sealed")
        self.assertEqual(connection.execute("SELECT state FROM staging_load_test_runs WHERE run_id='2'").fetchone()[0], "open")
        rows = connection.execute("SELECT resource_class, observed_count FROM staging_load_test_resource_scans WHERE run_id='1' ORDER BY resource_class").fetchall()
        self.assertEqual(len(rows), 9)
        self.assertEqual(dict(rows)["cas_reference"], 1)
        self.assertEqual(dict(rows)["webhook_inbox"], 1)
        self.assertEqual(sum(dict(rows).values()), 2)

    def test_over_budget_and_unresolved_r2_roll_back_every_scan(self):
        connection = database()
        run(connection)
        for number in range(257):
            resource(connection, ref=f"{number:064x}")
        connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            seal_batch(connection)
        self.assertEqual(connection.execute("SELECT state FROM staging_load_test_runs WHERE run_id='1'").fetchone()[0], "open")
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans WHERE run_id='1'").fetchone()[0], 0)

        connection = database()
        run(connection)
        connection.execute(
            "INSERT INTO staging_load_test_r2_intents "
            "(operation_id, run_id, scenario, target_deployment_sha, resource_class, receipt_ref, opaque_handle, disposition, state, prepared_at_ms) "
            "VALUES (?, '1', 'cas', ?, 'cas_reference', ?, 'intent-handle', 'retained', 'prepared', 1)",
            ("e" * 64, SHA, "f" * 64),
        )
        connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            seal_batch(connection)
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans").fetchone()[0], 0)

        connection = database()
        run(connection)
        connection.execute(
            "INSERT INTO staging_load_test_r2_intents "
            "(operation_id, run_id, scenario, target_deployment_sha, resource_class, receipt_ref, opaque_handle, disposition, state, prepared_at_ms) "
            "VALUES (?, '1', 'cas', ?, 'cas_reference', ?, 'quarantine-handle', 'retained', 'quarantined', 1)",
            ("1" * 64, SHA, "2" * 64),
        )
        connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            seal_batch(connection)
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans").fetchone()[0], 0)

    def test_wrong_identity_and_terminal_run_do_not_create_scans(self):
        connection = database()
        run(connection)
        seal_batch(connection, sha="b" * 40)
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans").fetchone()[0], 0)
        connection.execute("UPDATE staging_load_test_runs SET state='failed' WHERE run_id='1'")
        connection.commit()
        seal_batch(connection)
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans").fetchone()[0], 0)

    def test_sealed_census_is_frozen_and_late_writes_are_rejected(self):
        connection = database()
        run(connection)
        seal_batch(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            resource(connection)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE staging_load_test_resource_scans SET observed_count=9 "
                "WHERE run_id='1' AND scenario='cas' AND resource_class='cas_reference'"
            )
        before = connection.execute("SELECT resource_class, observed_count, scanned_at_ms FROM staging_load_test_resource_scans ORDER BY resource_class").fetchall()
        seal_batch(connection)  # replay is a no-op once the state is sealed
        after = connection.execute("SELECT resource_class, observed_count, scanned_at_ms FROM staging_load_test_resource_scans ORDER BY resource_class").fetchall()
        self.assertEqual(after, before)
        self.assertEqual(connection.execute("SELECT count(*) FROM staging_load_test_resource_scans").fetchone()[0], 9)

    def test_two_connections_serialize_seal_and_leave_replay_readonly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "staging.sqlite"
            first = sqlite3.connect(path, timeout=0.1, isolation_level=None)
            initialize(first)
            run(first)
            first.commit()
            second = sqlite3.connect(path, timeout=0.1, isolation_level=None)
            # Force the competing seal to meet SQLite's real write boundary.
            first.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                second.execute("BEGIN IMMEDIATE")
            first.execute("ROLLBACK")
            seal_batch(second)
            before = second.execute("SELECT resource_class, observed_count, scanned_at_ms FROM staging_load_test_resource_scans ORDER BY resource_class").fetchall()
            seal_batch(second)
            after = second.execute("SELECT resource_class, observed_count, scanned_at_ms FROM staging_load_test_resource_scans ORDER BY resource_class").fetchall()
            self.assertEqual(after, before)
            self.assertEqual(second.execute("SELECT state FROM staging_load_test_runs WHERE run_id='1'").fetchone()[0], "sealed")
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
