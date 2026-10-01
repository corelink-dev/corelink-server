"""Small in-memory oracle for the bounded B-125 attribution SELECT."""

from __future__ import annotations

import importlib.util
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "b125_attribution_query", ROOT / "scripts/b125_attribution_query.py"
)
query_module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(query_module)


class B125AttributionQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            """
            CREATE TABLE audit_outbox (
              id TEXT PRIMARY KEY, tenant_id TEXT, region TEXT, sequence_number INTEGER,
              chain_hash TEXT, emitted_at INTEGER, enqueued_at INTEGER,
              epoch_id INTEGER, algorithm_id INTEGER, link_key_id INTEGER,
              archived_at INTEGER, quarantined_at INTEGER, quarantine_reason TEXT
            );
            CREATE TABLE audit_chain_head (
              tenant_id TEXT, region TEXT, next_sequence INTEGER, head_hash TEXT,
              head_signature TEXT, PRIMARY KEY(tenant_id, region)
            );
            CREATE TABLE audit_chain_legacy_tail_resolution (
              tenant_id TEXT, region TEXT, resolution_version INTEGER, tail_sequence INTEGER,
              selected_row_id TEXT, selected_chain_hash TEXT, checkpoint_head_hash TEXT,
              checkpoint_next_sequence INTEGER, checkpoint_head_signature TEXT,
              candidate_count INTEGER, resolution_signature TEXT,
              PRIMARY KEY(tenant_id, region)
            );
            """
        )
        self.db.executemany(
            "INSERT INTO audit_outbox VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                # One structurally resolved legacy duplicated genesis tail.
                ("selected", "tenant-a", "enam", 0, "head-a", 1, 1, 0, 0, None, 1, None, None),
                ("loser", "tenant-a", "enam", 0, "fork-a", 1, 1, 0, 0, None, None, 2, "sequence_gap:expected=1,found=0"),
                # A unique signed tail.
                ("unique", "tenant-b", "weur", 4, "head-b", 20, 10, 1, 1, 7, 20, None, None),
                # Duplicate group with one live and one quarantined row.
                ("live", "tenant-c", "sam", 5, "fork-c1", 10, 9, 1, 1, 7, None, None, None),
                ("quarantined", "tenant-c", "sam", 5, "fork-c2", 10, 9, 1, 1, 7, None, 10, "chain_head_discontinuity:seq=5"),
                # A negative latency row in an unsealed population bin.
                ("negative", "tenant-d", "afr", 6, "hash-d", 3, 4, None, 8, None, None, None, None),
                # A sealed, unquarantined tail without a head is still counted.
                ("headless", "tenant-e", "apac", 9, "hash-e", 12, 5, 2, 0, None, None, None, None),
                ("old-fork-1", "tenant-f", "wnam", 2, "fork-f1", 20, 10, 0, 0, None, None, 11, "link_hash_mismatch:seq=2"),
                ("old-fork-2", "tenant-f", "wnam", 2, "fork-f2", 20, 10, 0, 0, None, None, 11, "link_hash_mismatch:seq=2"),
                # A unique highest sequence can still disagree with a signed head.
                ("unique-mismatch", "tenant-g", "afr", 7, "tail-g", 20, 10, 2, 0, None, 20, None, None),
            ],
        )
        self.db.executemany(
            "INSERT INTO audit_chain_head VALUES (?,?,?,?,?)",
            [
                ("tenant-a", "enam", 1, "head-a", "signature-a"),
                ("tenant-b", "weur", 5, "head-b", "signature-b"),
                ("tenant-c", "sam", 6, "head-c", "signature-c"),
                ("tenant-empty", "afr", 0, "empty-head", "signature-empty"),
                ("tenant-g", "afr", 8, "different-signed-head", "signature-g"),
            ],
        )
        self.db.execute(
            "INSERT INTO audit_chain_legacy_tail_resolution VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "tenant-a", "enam", 1, 0, "selected", "head-a", "head-a", 1,
                "signature-a", 2, "resolution-signature",
            ),
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_fixed_bounded_bins_include_quarantine_and_actual_tail_semantics(self) -> None:
        rows = self.db.execute(query_module.ATTRIBUTION_SQL).fetchall()
        columns = [entry[0] for entry in self.db.execute(query_module.ATTRIBUTION_SQL).description]
        receipt = [dict(zip(columns, row, strict=True)) for row in rows]
        self.assertEqual(len(receipt), 35)
        self.assertLessEqual(len(receipt), 64)
        self.assertNotIn("tenant_id", columns)
        self.assertNotIn("chain_hash", columns)
        self.assertNotIn("quarantine_reason", columns)

        head = next(row for row in receipt if row["section"] == "heads")
        self.assertEqual(head["chain_heads"], 5)
        self.assertEqual(head["missing_tail_heads"], 1)
        self.assertEqual(head["tail_without_head_partitions"], 3)
        self.assertEqual(head["unique_signed_tail_matches"], 1)
        self.assertEqual(head["unique_tail_hash_mismatches"], 1)
        self.assertEqual(head["ambiguous_tail_heads"], 2)
        self.assertEqual(head["ambiguous_one_checkpoint_match"], 1)
        self.assertEqual(head["structurally_resolved_legacy_genesis"], 1)
        self.assertEqual(head["unresolved_ambiguous_tail_heads"], 1)

        reasons = {row["reason_bin"]: row for row in receipt if row["section"] == "reason"}
        self.assertEqual(reasons["sequence_gap"]["row_count"], 1)
        self.assertEqual(reasons["chain_head_discontinuity"]["row_count"], 1)
        self.assertEqual(reasons["not_quarantined"]["row_count"], 6)

        duplicate = {row["duplicate_bin"]: row for row in receipt if row["section"] == "duplicate"}
        self.assertEqual(duplicate["all_quarantined"]["duplicate_groups"], 1)
        self.assertEqual(duplicate["all_quarantined"]["duplicate_rows"], 2)
        self.assertEqual(duplicate["mixed"]["duplicate_groups"], 2)
        self.assertEqual(duplicate["mixed"]["duplicate_rows"], 4)

        class_bins = [row for row in receipt if row["section"] == "class"]
        self.assertEqual(sum(row["row_count"] for row in class_bins), 10)
        self.assertEqual(sum(row["negative_latency_rows"] for row in class_bins), 1)

    def test_sql_is_one_read_only_statement_without_unbounded_row_values(self) -> None:
        sql = query_module.ATTRIBUTION_SQL
        self.assertNotIn(";", sql)
        self.assertTrue(sql.lstrip().startswith("WITH"))
        self.assertNotRegex(sql.upper(), r"\b(INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|PRAGMA|ATTACH|DETACH)\b")
        self.assertNotRegex(sql.lower(), r"\b(payload_json|canonical_jcs|digest|prev_hash)\b")


if __name__ == "__main__":
    unittest.main()
