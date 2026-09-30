from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FENCE = ROOT / "scripts/verify-signup-worker-dsr-redrive-schema.sh"
OPERATOR_PATH = ROOT / "scripts/apply_staging_b216_dsr_schema.py"
SPEC = importlib.util.spec_from_file_location("b216_schema_operator", OPERATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
OPERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPERATOR)


class DsrSchemaFenceTests(unittest.TestCase):
    def test_operator_target_comes_only_from_reviewed_topology(self) -> None:
        self.assertIsNone(OPERATOR.require_target())

    def test_operator_stops_on_migration_preimage_disagreement(self) -> None:
        OPERATOR.validate_preimage(set(), set())
        all_names = set(OPERATOR.MIGRATIONS)
        all_objects = set().union(*OPERATOR.SCHEMA_OBJECTS.values())
        OPERATOR.validate_preimage(all_names, all_objects)
        with self.assertRaisesRegex(RuntimeError, "partial or inconsistent"):
            OPERATOR.validate_preimage({"0138_dsr_dlq_delivery_receipts.sql"}, set())
        with self.assertRaisesRegex(RuntimeError, "partial or inconsistent"):
            OPERATOR.validate_preimage(set(), {"dsr_dlq_delivery_receipts"})

    def test_offline_operator_contract_checks_only_reviewed_target_and_migration_bytes(self) -> None:
        result = subprocess.run(
            ["python3", "-B", str(OPERATOR_PATH), "--check-contract"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no provider was contacted", result.stdout)

    def test_temporary_wrangler_config_contains_only_two_fixed_migrations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b216-isolated-config-") as temp:
            root = Path(temp)
            config_path = OPERATOR.prepare_isolated_config(root)
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            migrations = sorted(path.name for path in (root / "migrations").iterdir())
        self.assertEqual(
            migrations,
            ["0138_dsr_dlq_delivery_receipts.sql", "0145_dsr_dlq_redrive_authority.sql"],
        )
        self.assertEqual(config["d1_databases"][0]["database_name"], "corelink-config-staging")
        self.assertEqual(config["d1_databases"][0]["database_id"], "d72a6b39-6a48-4338-bfda-1111dda98604")
        self.assertEqual(config["d1_databases"][0]["binding"], "CONFIG_DB")
        self.assertEqual(config["account_id"], "6a1fc1c626fc2628823e60b9db01f5cd")

    def test_real_wrangler_local_schema_response_passes_fence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b216-real-wrangler-") as temp:
            root = Path(temp)
            config = OPERATOR.prepare_isolated_config(root)
            persist = root / "d1-state"
            command = [
                "npx", "--yes", "wrangler@4.145.0", "d1", "migrations", "apply", "CONFIG_DB",
                "--local", "--config", str(config), "--persist-to", str(persist),
            ]
            env = os.environ.copy()
            for name in OPERATOR.TOKEN_ENV_NAMES:
                env.pop(name, None)
            apply = subprocess.run(command, cwd=ROOT, env=env, check=False, text=True, capture_output=True)
            self.assertEqual(apply.returncode, 0, apply.stderr)
            env["B216_DSR_SCHEMA_WRANGLER_VERSION"] = "4.145.0"
            fence = subprocess.run(
                ["bash", str(FENCE), "--config", str(config), "--local", "--persist-to", str(persist)],
                cwd=ROOT,
                env=env,
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(fence.returncode, 0, fence.stderr)
            delete_0138 = subprocess.run(
                [
                    "npx", "--yes", "wrangler@4.145.0", "d1", "execute", "CONFIG_DB",
                    "--local", "--config", str(config), "--persist-to", str(persist),
                    "--command", "DELETE FROM d1_migrations WHERE name = '0138_dsr_dlq_delivery_receipts.sql'",
                    "--json",
                ],
                cwd=ROOT,
                env=env,
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(delete_0138.returncode, 0, delete_0138.stderr)
            broken_fence = subprocess.run(
                ["bash", str(FENCE), "--config", str(config), "--local", "--persist-to", str(persist)],
                cwd=ROOT,
                env=env,
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(broken_fence.returncode, 0)
        self.assertIn("migration 0138", broken_fence.stderr)
        self.assertIn("migrations 0138 and 0145", fence.stdout)

    def test_frozen_migrations_create_the_exact_schema_checked_by_operator(self) -> None:
        database = sqlite3.connect(":memory:")
        database.row_factory = sqlite3.Row
        database.execute("CREATE TABLE d1_migrations (name TEXT PRIMARY KEY)")
        for name in OPERATOR.MIGRATIONS:
            database.executescript((ROOT / "migrations/d1" / name).read_text(encoding="utf-8"))
            database.execute("INSERT INTO d1_migrations (name) VALUES (?)", (name,))
        migration_names = {
            row[0]
            for row in database.execute(
                "SELECT name FROM d1_migrations WHERE name IN (?, ?)",
                tuple(OPERATOR.MIGRATIONS),
            )
        }
        objects = {
            (row["type"], row["name"])
            for row in database.execute("SELECT type, name FROM sqlite_master")
        }
        receipt_columns = {
            row["name"] for row in database.execute("PRAGMA table_info(dsr_dlq_delivery_receipts)")
        }
        redrive_columns = {
            row["name"] for row in database.execute("PRAGMA table_info(dsr_dlq_redrive_envelopes)")
        }
        self.assertEqual(migration_names, set(OPERATOR.MIGRATIONS))
        self.assertIn(("table", "dsr_dlq_delivery_receipts"), objects)
        self.assertIn(("index", "idx_dsr_dlq_delivery_receipts_status_updated"), objects)
        self.assertIn(("table", "dsr_dlq_redrive_envelopes"), objects)
        self.assertIn(("table", "dsr_dlq_redrive_audit"), objects)
        self.assertEqual(
            receipt_columns,
            {"event_id", "status", "paging_claimed", "requeue_claimed", "updated_at_ms"},
        )
        self.assertEqual(
            redrive_columns,
            {"event_id", "dsr_id", "tenant_id", "queued_at_ms", "legal_hold", "requeue_count", "state", "actor_ref", "approval_ref", "expires_at_ms", "claim_expires_at_ms", "updated_at_ms"},
        )


if __name__ == "__main__":
    unittest.main()
