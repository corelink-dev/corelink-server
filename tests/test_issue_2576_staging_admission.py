"""SQLite adversarial contract for #2576's v1 and v2 admission batches."""

import hashlib
import os
import re
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN_SQL = (ROOT / "migrations/d1/0147_staging_load_test_run_ownership.sql").read_text(encoding="utf-8")
V1_NONCE_SQL = (ROOT / "migrations/d1/0148_staging_load_test_admission_nonce.sql").read_text(encoding="utf-8")
V2_NONCE_SQL = (ROOT / "migrations/d1/0152_staging_load_test_request_nonces.sql").read_text(encoding="utf-8")
SOURCE = (ROOT / "crates/corelink-container/src/storage/staging_load_test_admission.rs").read_text(encoding="utf-8")


def sql_constant(name: str) -> str:
    match = re.search(rf'const {name}: &str = "([^\"]+)";', SOURCE, re.DOTALL)
    if match is None:
        raise AssertionError(f"missing {name}")
    return re.sub(r"\\\n\s*", "", match.group(1))


def run(run_id: str, sha: str, state: str = "open", admitted: int = 1_000) -> tuple[object, ...]:
    return (run_id, "cas", "staging", sha, state, admitted)


def nonce(digest: str, run_id: str, sha: str, issued: int = 900, expires: int = 1_800, admitted: int = 1_000) -> tuple[object, ...]:
    return (digest, run_id, "cas", "staging", sha, issued, expires, admitted)


class AdmissionMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(RUN_SQL)
        self.db.executescript(V1_NONCE_SQL)
        self.db.executescript(V2_NONCE_SQL)

    def add_run(self, value: tuple[object, ...]) -> None:
        self.db.execute("INSERT INTO staging_load_test_runs VALUES (?, ?, ?, ?, ?, ?)", value)

    def add_v1_nonce(self, value: tuple[object, ...]) -> None:
        self.db.execute("INSERT INTO staging_load_test_admission_nonces VALUES (?, ?, ?, ?, ?, ?, ?, ?)", value)

    def add_v2_nonce(self, value: tuple[object, ...]) -> None:
        self.db.execute("INSERT INTO staging_load_test_request_nonces VALUES (?, ?, ?, ?, ?, ?, ?, ?)", value)

    def prepare_run_for_seal(self, run_id: str, scanned_at: int = 1_001) -> None:
        for resource_class in (
            "cas_reference",
            "webhook_inbox",
            "webhook_effect",
            "dsr_artifact",
            "dsr_obligation",
            "audit_evidence",
            "billing_audit",
            "signup_artifact",
            "byok_artifact",
        ):
            self.db.execute(
                "INSERT INTO staging_load_test_resource_scans VALUES (?, 'cas', ?, 'complete', 0, ?)",
                (run_id, resource_class, scanned_at),
            )

    def test_v1_prefix_is_unchanged_and_one_use(self) -> None:
        self.assertEqual("0148_staging_load_test_admission_nonce.sql", ROOT.joinpath("migrations/d1/0148_staging_load_test_admission_nonce.sql").name)
        self.add_run(run("100001", "a" * 40))
        self.add_v1_nonce(nonce("b" * 64, "100001", "a" * 40))
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_v1_nonce(nonce("c" * 64, "100001", "a" * 40))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE staging_load_test_admission_nonces SET issued_at_ms = 1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM staging_load_test_admission_nonces")

    def test_v2_digest_only_append_only_and_allows_fresh_requests(self) -> None:
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(staging_load_test_request_nonces)")}
        self.assertNotIn("nonce", columns)
        self.assertNotIn("credential", columns)
        self.add_run(run("100002", "a" * 40))
        self.add_v2_nonce(nonce("b" * 64, "100002", "a" * 40))
        self.add_v2_nonce(nonce("c" * 64, "100002", "a" * 40, admitted=1_001))
        self.assertEqual(self.db.execute("SELECT count(*) FROM staging_load_test_request_nonces").fetchone(), (2,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE staging_load_test_request_nonces SET issued_at_ms = 1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM staging_load_test_request_nonces")

    def test_v2_trigger_requires_exact_open_identity_even_without_foreign_keys(self) -> None:
        self.db.execute("PRAGMA foreign_keys = OFF")
        self.add_run(run("100003", "a" * 40))
        for index, state in enumerate(("sealed", "teardown_started", "reconciled", "failed"), start=1):
            run_id = str(100_100 + index)
            self.add_run(run(run_id, "b" * 40, state))
            with self.subTest(state=state), self.assertRaises(sqlite3.IntegrityError):
                self.add_v2_nonce(nonce("c" * 64, run_id, "b" * 40))
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_v2_nonce(nonce("d" * 64, "100003", "e" * 40))
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_v2_nonce(nonce("e" * 64, "100004", "a" * 40))

    def test_actual_v1_adapter_statements_remain_one_use_and_atomic(self) -> None:
        run_sql, nonce_sql = sql_constant("SQL_INSERT_RUN"), sql_constant("SQL_INSERT_NONCE")
        self.assertRegex(SOURCE, r"V1 => \(SQL_INSERT_RUN, SQL_INSERT_NONCE\)")
        digest = hashlib.sha256(b"corelink/staging-load-admission-nonce/v1\0" + bytes.fromhex("01" * 32)).hexdigest()
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100020", "cas", "a" * 40, 1_000))
        self.db.execute(nonce_sql, (digest, "100020", "cas", "a" * 40, 900, 1_800, 1_000))
        self.db.commit()
        self.assertEqual(self.db.execute("SELECT nonce_digest FROM staging_load_test_admission_nonces").fetchone(), (digest,))
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100021", "cas", "b" * 40, 1_000))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(nonce_sql, (digest, "100021", "cas", "b" * 40, 900, 1_800, 1_000))
        self.db.rollback()
        self.assertIsNone(self.db.execute("SELECT run_id FROM staging_load_test_runs WHERE run_id = '100021'").fetchone())

    def test_actual_v2_adapter_statements_keep_run_identity_and_roll_back_second_failure(self) -> None:
        run_sql, nonce_sql = sql_constant("SQL_INSERT_RUN_V2"), sql_constant("SQL_INSERT_REQUEST_NONCE")
        self.assertIn("ON CONFLICT(run_id, scenario) DO NOTHING", run_sql)
        self.assertNotIn("UPDATE", run_sql)
        self.assertNotIn("REPLACE", run_sql)
        self.assertRegex(SOURCE, r"let \(run_sql, nonce_sql\) = match admission\.version \{[\s\S]*?V2 => \(SQL_INSERT_RUN_V2, SQL_INSERT_REQUEST_NONCE\)")
        self.assertRegex(SOURCE, r"let run_params = vec!\[\s*json!\(admission\.run_id\),\s*json!\(scenario\),\s*json!\(admission\.target_deployment_sha\),\s*json!\(now_ms\),")
        self.assertRegex(SOURCE, r"let nonce_params = vec!\[\s*json!\(admission\.nonce_digest\),\s*json!\(admission\.run_id\),\s*json!\(scenario\),\s*json!\(admission\.target_deployment_sha\),\s*json!\(admission\.issued_at_ms\),\s*json!\(admission\.expires_at_ms\),\s*json!\(now_ms\),")
        digest_one = hashlib.sha256(b"corelink/staging-load-admission-nonce/v2\0" + bytes.fromhex("01" * 32)).hexdigest()
        digest_two = hashlib.sha256(b"corelink/staging-load-admission-nonce/v2\0" + bytes.fromhex("02" * 32)).hexdigest()
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100030", "cas", "a" * 40, 1_000))
        self.db.execute(nonce_sql, (digest_one, "100030", "cas", "a" * 40, 900, 1_800, 1_000))
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100030", "cas", "a" * 40, 1_001))
        self.db.execute(nonce_sql, (digest_two, "100030", "cas", "a" * 40, 900, 1_800, 1_001))
        self.db.commit()
        self.assertEqual(self.db.execute("SELECT admitted_at_ms FROM staging_load_test_runs WHERE run_id = '100030'").fetchone(), (1_000,))
        self.assertEqual(self.db.execute("SELECT count(*) FROM staging_load_test_request_nonces WHERE run_id = '100030'").fetchone(), (2,))
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100031", "cas", "b" * 40, 1_000))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(nonce_sql, (digest_one, "100031", "cas", "b" * 40, 900, 1_800, 1_000))
        self.db.rollback()
        self.assertIsNone(self.db.execute("SELECT run_id FROM staging_load_test_runs WHERE run_id = '100031'").fetchone())

    def test_admit_and_seal_serialization_orders_fail_closed_after_seal(self) -> None:
        run_sql, nonce_sql = sql_constant("SQL_INSERT_RUN_V2"), sql_constant("SQL_INSERT_REQUEST_NONCE")
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100050", "cas", "a" * 40, 1_000))
        self.db.execute(nonce_sql, ("a" * 64, "100050", "cas", "a" * 40, 900, 1_800, 1_000))
        self.db.commit()
        self.prepare_run_for_seal("100050")
        self.db.execute("UPDATE staging_load_test_runs SET state = 'sealed' WHERE run_id = '100050'")
        self.assertEqual(self.db.execute("SELECT state FROM staging_load_test_runs WHERE run_id = '100050'").fetchone(), ("sealed",))
        self.assertEqual(self.db.execute("SELECT count(*) FROM staging_load_test_request_nonces WHERE run_id = '100050'").fetchone(), (1,))

        self.add_run(run("100051", "b" * 40))
        self.prepare_run_for_seal("100051")
        self.db.execute("UPDATE staging_load_test_runs SET state = 'sealed' WHERE run_id = '100051'")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute(run_sql, ("100051", "cas", "b" * 40, 1_002))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(nonce_sql, ("b" * 64, "100051", "cas", "b" * 40, 900, 1_800, 1_002))
        self.db.rollback()
        self.assertEqual(self.db.execute("SELECT count(*) FROM staging_load_test_request_nonces WHERE run_id = '100051'").fetchone(), (0,))

    def test_two_connections_race_fresh_and_same_nonces(self) -> None:
        descriptor, database_path = tempfile.mkstemp(prefix="issue-2576-", suffix=".sqlite")
        os.close(descriptor)
        try:
            setup = sqlite3.connect(database_path)
            setup.executescript(RUN_SQL)
            setup.executescript(V1_NONCE_SQL)
            setup.executescript(V2_NONCE_SQL)
            setup.close()
            run_sql, nonce_sql = sql_constant("SQL_INSERT_RUN_V2"), sql_constant("SQL_INSERT_REQUEST_NONCE")

            def race(run_id: str, digests: tuple[str, str]) -> list[str]:
                barrier = threading.Barrier(2)

                def admit(digest: str) -> str:
                    connection = sqlite3.connect(database_path, timeout=5)
                    connection.execute("PRAGMA busy_timeout = 5000")
                    try:
                        barrier.wait()
                        connection.execute("BEGIN IMMEDIATE")
                        connection.execute(run_sql, (run_id, "cas", "a" * 40, 1_000))
                        connection.execute(nonce_sql, (digest, run_id, "cas", "a" * 40, 900, 1_800, 1_000))
                        connection.commit()
                        return "accepted"
                    except sqlite3.IntegrityError:
                        connection.rollback()
                        return "replayed"
                    finally:
                        connection.close()

                threads = [threading.Thread(target=lambda digest=digest: outcomes.append(admit(digest))) for digest in digests]
                outcomes: list[str] = []
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                return outcomes

            self.assertEqual(sorted(race("100040", ("a" * 64, "b" * 64))), ["accepted", "accepted"])
            self.assertEqual(sorted(race("100041", ("c" * 64, "c" * 64))), ["accepted", "replayed"])
            readback = sqlite3.connect(database_path)
            self.assertEqual(readback.execute("SELECT count(*) FROM staging_load_test_request_nonces WHERE run_id = '100040'").fetchone(), (2,))
            self.assertEqual(readback.execute("SELECT count(*) FROM staging_load_test_request_nonces WHERE run_id = '100041'").fetchone(), (1,))
            readback.close()
        finally:
            os.unlink(database_path)


if __name__ == "__main__":
    unittest.main()
