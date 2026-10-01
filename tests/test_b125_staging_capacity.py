"""Offline contract tests for the run-attributable staging B-125 profile."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "b125_staging_capacity_query", ROOT / "scripts/b125_staging_capacity_query.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class B125StagingCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            "CREATE TABLE audit_outbox (tenant_id TEXT, region TEXT, digest TEXT, enqueued_at INTEGER, emitted_at INTEGER)"
        )
        self.db.executemany(
            "INSERT INTO audit_outbox VALUES (?,?,?,?,?)",
            [
                ("synthetic-a", "enam", "synthetic_run_1230_endurance_other", 10, 20),
                ("preexisting", "enam", "other", 5, None),
            ],
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_run_markers_are_canonical_and_noninjectable(self) -> None:
        for run_id in ("0", "01", "1; DROP TABLE audit_outbox", "1' OR 1=1 --", "9" * 21):
            with self.assertRaises(ValueError):
                module.result_sql(run_id)
        sql = module.result_sql("123")
        self.assertIn("_run_123_endurance_", sql)
        self.assertNotIn("_run_1230_endurance_", sql)
        self.assertIn("LIMIT 3", sql)
        self.assertNotIn("canonical_jcs", sql)
        self.assertNotIn("payload_json", sql)

    def test_preflight_and_result_sql_return_only_small_run_scoped_aggregates(self) -> None:
        preflight = self.db.execute(module.preflight_sql("123")).fetchone()
        self.assertEqual(preflight[0], 0)
        self.assertEqual(preflight[1], 1)
        self.db.executemany(
            "INSERT INTO audit_outbox VALUES (?,?,?,?,?)",
            [
                ("synthetic-b", "enam", "synthetic_run_123_endurance_0_1_1", 3600000 + 10, 3600000 + 30),
                ("synthetic-b", "enam", "synthetic_run_123_endurance_0_1_2", 3600000 + 20, None),
                ("synthetic-c", "weur", "synthetic_run_123_endurance_0_2_1", 7200000 + 10, 7200000 + 5),
            ],
        )

        sql = module.result_sql("123")
        cursor = self.db.execute(sql)
        rows = cursor.fetchall()
        columns = [entry[0] for entry in cursor.description]
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows), rows[0][columns.index("hour_bucket_count")])
        results = [dict(zip(columns, row, strict=True)) for row in rows]
        self.assertEqual(sum(row["audit_arrivals"] for row in results), 3)
        self.assertEqual(sum(row["sealed_rows"] for row in results), 2)
        self.assertEqual(sum(row["unsealed_rows"] for row in results), 1)
        self.assertEqual(sum(row["negative_latency_rows"] for row in results), 1)
        self.assertEqual({row["partition_count"] for row in results}, {1})
        self.assertEqual({row["run_audit_rows"] for row in results}, {3})
        self.assertEqual({row["run_unsealed_rows"] for row in results}, {1})
        self.assertEqual({row["unsealed_rows_after"] for row in results}, {2})
        self.assertNotIn("tenant_id", columns)
        self.assertNotIn("digest", columns)
        self.assertNotIn("region", columns)
        self.assertNotIn("synthetic", json.dumps(results))

    def test_staging_target_and_auth_names_match_existing_authority_sources(self) -> None:
        topology = json.loads((ROOT / "infra/staging/topology.json").read_text())
        operator = (ROOT / "scripts/issue_1652_b072_operator.py").read_text()
        workflow = (ROOT / ".github/workflows/endurance-2h-nightly.yml").read_text()
        import re

        operator_account = re.search(r'^ACCOUNT_ID = "([0-9a-f]{32})"$', operator, re.MULTILINE)
        self.assertIsNotNone(operator_account)
        self.assertEqual(module.STAGING_ACCOUNT_ID, operator_account.group(1))
        self.assertEqual(module.STAGING_ORIGIN, topology["canonical_origin"])
        self.assertEqual(module.STAGING_DATABASE_ID, topology["cloudflare"]["root_worker_settings"]["vars"]["D1_DATABASE_ID"])
        self.assertIn(f'STAGING_D1_ID = "{module.STAGING_DATABASE_ID}"', operator)
        self.assertIn("STAGING_ACCOUNT_ID", (ROOT / "scripts/b125_staging_capacity_query.py").read_text())
        for name in (
            "K6_TARGET_HOST",
            "K6_TARGET_IDENTITY_RECEIPT",
            "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY",
        ):
            self.assertIn(name, workflow)

    def test_capacity_profile_is_controlled_and_remains_inside_existing_staging_lifecycle(self) -> None:
        workflow = (ROOT / ".github/workflows/endurance-2h-nightly.yml").read_text()
        scenario = (ROOT / "tests/load/k6/scenarios/endurance-24h.js").read_text()
        self.assertIn("workload_profile:", workflow)
        self.assertIn("capacity_confirmation:", workflow)
        self.assertIn("run-b125-audit-capacity", workflow)
        self.assertIn("/_internal/staging/load-tests/endurance-2h/seal", workflow)
        self.assertIn("/_internal/staging/load-tests/endurance-2h/teardown", workflow)
        self.assertIn("inputs.workload_profile == 'mixed'", workflow)
        self.assertIn("executor: 'constant-arrival-rate'", scenario)
        self.assertIn("rate: 1", scenario)
        self.assertIn("timeUnit: '1s'", scenario)
        self.assertIn("_run_${RUN_ID}_endurance_", scenario)
        self.assertIn("function b125CapacityIter", scenario)
        self.assertIn("doCasWrite(tenant)", scenario)


if __name__ == "__main__":
    unittest.main()
