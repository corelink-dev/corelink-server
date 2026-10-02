"""Offline checks for the redacted issue #1669 receipt classifier."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "classify_i1669_receipt", ROOT / "scripts" / "classify_i1669_receipt.py"
)
assert SPEC and SPEC.loader
classifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = classifier
SPEC.loader.exec_module(classifier)


def receipt_fixture() -> dict:
    probe = classifier.PROBE
    receipt = {
        "schema": "corelink.issue-1669.read-only-residency.v1",
        "issue": 1669,
        "mode": "production_read_only",
        "captured_at": "2026-09-22T06:58:04.555886+00:00",
        "account_id_sha256": "a" * 64,
        "database_id_sha256": "b" * 64,
        # A schema-v1 receipt: the three aggregates only (pre owner attestation).
        "queries": [
            {
                "name": name,
                "query_sha256": probe._hash(probe.QUERY_ALLOWLIST[name]),
                "response_sha256": "c" * 64,
                "row_count": 1,
            }
            for name in probe.AGGREGATE_QUERY_NAMES
        ],
        "counts": {
            "residency": {
                "total_rows": 5,
                "customer_rows": 4,
                "public_rows": 1,
                "reserved_public_rows": 1,
                "invalid_public_rows": 0,
                "satisfied_rows": 1,
                "violated_rows": 1,
                "unevaluable_rows": 2,
                "customer_unevaluable_rows": 2,
                "orphan_rows": 2,
                "orphan_tenants": 2,
                "erased_orphan_rows": 1,
                "erased_orphan_tenants": 1,
                "unexplained_orphan_rows": 1,
                "unexplained_orphan_tenants": 1,
                "weur_audit_rows": 1,
                "weur_orphan_rows": 1,
                "weur_tenants": 0,
                "erasure_log_rows": 1,
            },
            "population": {"audit_rows": 5, "audit_tenants": 5, "blank_tenant_rows": 0},
            "backfill_completeness": {
                "audit_rows": 5,
                "orphan_rows": 2,
                "joinable_rows": 2,
                "reserved_public_rows": 1,
                "invalid_public_rows": 0,
                "erased_orphan_rows": 1,
            },
        },
        "status": "FAILED",
        "reason": "known violations or unevaluable rows exist; neither may be reported compliant",
    }
    receipt["receipt_sha256"] = probe._hash(receipt)
    return receipt


def resign(receipt: dict) -> None:
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = classifier.PROBE._hash(receipt)


def erased_only_fixture(status: str, reason: str) -> dict:
    """A population whose only non-satisfied customer rows are DSR-erased orphans."""
    receipt = receipt_fixture()
    receipt["counts"]["residency"].update(
        {
            "satisfied_rows": 3,
            "violated_rows": 0,
            "unevaluable_rows": 1,
            "customer_unevaluable_rows": 1,
            "orphan_rows": 1,
            "orphan_tenants": 1,
            "erased_orphan_rows": 1,
            "erased_orphan_tenants": 1,
            "unexplained_orphan_rows": 0,
            "unexplained_orphan_tenants": 0,
        }
    )
    receipt["counts"]["backfill_completeness"].update(
        {"orphan_rows": 1, "joinable_rows": 3, "erased_orphan_rows": 1}
    )
    receipt["status"] = status
    receipt["reason"] = reason
    resign(receipt)
    return receipt


RESIDENCY = classifier.PROBE.RESIDENCY
AUTHORITY = "https://github.com/HuGR-dev/corelink-server/issues/1669#issuecomment-5959812722"


def ledger_of(*row_ids: str, sha: str = "e" * 64):
    return RESIDENCY.Ledger(refs=frozenset(RESIDENCY.row_ref(i) for i in row_ids), sha256=sha)


def v2_fixture(residual_ids: tuple[str, ...], ledger, status: str, reason: str, attestation: dict | None = None) -> dict:
    """Schema-v2 receipt: 2 satisfied, 1 erased orphan, len(residual_ids) unexplained, 1 reserved _public."""
    probe = classifier.PROBE
    unexplained = len(residual_ids)
    refs = sorted(RESIDENCY.row_ref(i) for i in residual_ids)
    customer = 3 + unexplained
    receipt = receipt_fixture()
    receipt["schema"] = probe.RECEIPT_SCHEMA_V2
    receipt["queries"] = [
        {
            "name": name,
            "query_sha256": probe._hash(query),
            "response_sha256": "c" * 64,
            "row_count": unexplained if name == "residual_refs" else 1,
        }
        for name, query in probe.QUERY_ALLOWLIST.items()
    ]
    receipt["counts"]["residency"].update(
        {
            "total_rows": customer + 1,
            "customer_rows": customer,
            "satisfied_rows": 2,
            "violated_rows": 0,
            "unevaluable_rows": 1 + unexplained,
            "customer_unevaluable_rows": 1 + unexplained,
            "orphan_rows": 1 + unexplained,
            "orphan_tenants": 1 + (1 if unexplained else 0),
            "erased_orphan_rows": 1,
            "erased_orphan_tenants": 1,
            "unexplained_orphan_rows": unexplained,
            "unexplained_orphan_tenants": 1 if unexplained else 0,
        }
    )
    receipt["counts"]["population"].update({"audit_rows": customer + 1, "audit_tenants": 3})
    receipt["counts"]["backfill_completeness"].update(
        {"audit_rows": customer + 1, "orphan_rows": 1 + unexplained, "joinable_rows": 2, "erased_orphan_rows": 1}
    )
    receipt["counts"]["residual_refs"] = {"residual_rows": unexplained, "row_refs": refs}
    receipt["attestation"] = attestation if attestation is not None else RESIDENCY.attest(refs, ledger).summary()
    receipt["status"] = status
    receipt["reason"] = reason
    resign(receipt)
    return receipt


class OwnerAttestationTests(unittest.TestCase):
    def test_all_attested_rows_are_their_own_documented_exception_never_compliant(self) -> None:
        ledger = ledger_of("row-a")
        receipt = v2_fixture(("row-a",), ledger, "DOCUMENTED_EXCEPTION", RESIDENCY.DOCUMENTED_EXCEPTION_REASON)
        report = classifier.classify(receipt, ledger=ledger)
        classes = {item["class"]: item for item in report["classes"]}

        self.assertEqual(report["source_status"], "DOCUMENTED_EXCEPTION")
        self.assertEqual(report["overall_disposition"], "DOCUMENTED_EXCEPTION")
        attested = classes["owner_attested_prelaunch_test_traffic"]
        self.assertEqual(attested["rows"], 1)
        self.assertEqual(attested["disposition"], "DOCUMENTED_EXCEPTION_OWNER_ATTESTED_NOT_LOG_CONFIRMED")
        self.assertEqual(classes["unexplained_orphan"]["rows"], 0)
        self.assertEqual(classes["erased_orphan_retained_audit"]["rows"], 1)
        self.assertEqual(report["states"]["owner_attested_prelaunch_test_traffic"], 1)
        self.assertEqual(report["states"]["violated"], 0)
        self.assertEqual(report["attestation"]["authority"], AUTHORITY)
        self.assertIs(report["attestation"]["log_confirmed"], False)
        self.assertTrue(report["tenant_identity_dispositions_complete"])

    def test_rejects_attested_population_relabelled_compliant(self) -> None:
        ledger = ledger_of("row-a")
        receipt = v2_fixture(("row-a",), ledger, "COMPLIANT", RESIDENCY.COMPLIANT_REASON)
        with self.assertRaisesRegex(classifier.ReceiptError, "verdict does not match"):
            classifier.classify(receipt, ledger=ledger)

    def test_a_14th_unattested_row_keeps_the_issue_open(self) -> None:
        ledger = ledger_of("row-a")
        receipt = v2_fixture(("row-a", "row-b"), ledger, "FAILED", RESIDENCY.FAILED_REASON)
        report = classifier.classify(receipt, ledger=ledger)
        classes = {item["class"]: item for item in report["classes"]}
        self.assertEqual(report["overall_disposition"], "KEEP_OPEN")
        self.assertEqual(classes["owner_attested_prelaunch_test_traffic"]["rows"], 1)
        self.assertEqual(classes["unexplained_orphan"]["rows"], 1)
        self.assertFalse(report["tenant_identity_dispositions_complete"])

    def test_a_missing_attested_reference_is_reported_and_keeps_the_issue_open(self) -> None:
        ledger = ledger_of("row-a", "row-gone")
        receipt = v2_fixture(("row-a",), ledger, "FAILED", RESIDENCY.ATTESTED_MISSING_REASON)
        report = classifier.classify(receipt, ledger=ledger)
        self.assertEqual(report["overall_disposition"], "KEEP_OPEN")
        self.assertEqual(report["attestation"]["attested_refs_missing"], 1)
        self.assertFalse(report["tenant_identity_dispositions_complete"])

    def test_rejects_a_probe_attestation_block_that_does_not_recompute(self) -> None:
        ledger = ledger_of("row-a")
        forged = RESIDENCY.attest([RESIDENCY.row_ref("row-a")], ledger).summary()
        forged["attested_refs_missing"] = 0
        forged["unattested_rows"] = 0
        forged["attested_rows"] = 2
        receipt = v2_fixture(("row-a",), ledger, "DOCUMENTED_EXCEPTION", RESIDENCY.DOCUMENTED_EXCEPTION_REASON, forged)
        with self.assertRaisesRegex(classifier.ReceiptError, "attestation does not match"):
            classifier.classify(receipt, ledger=ledger)

    def test_rejects_a_receipt_bound_to_a_different_ledger_version(self) -> None:
        receipt = v2_fixture(("row-a",), ledger_of("row-a", sha="1" * 64), "DOCUMENTED_EXCEPTION",
                             RESIDENCY.DOCUMENTED_EXCEPTION_REASON)
        with self.assertRaisesRegex(classifier.ReceiptError, "attestation does not match"):
            classifier.classify(receipt, ledger=ledger_of("row-a", sha="2" * 64))

    def test_rejects_raw_row_ids_in_place_of_references(self) -> None:
        ledger = ledger_of("row-a")
        receipt = v2_fixture(("row-a",), ledger, "DOCUMENTED_EXCEPTION", RESIDENCY.DOCUMENTED_EXCEPTION_REASON)
        receipt["counts"]["residual_refs"]["row_refs"] = ["row-a"]
        resign(receipt)
        with self.assertRaisesRegex(classifier.ReceiptError, "SHA-256 hex"):
            classifier.classify(receipt, ledger=ledger)

    def test_rejects_references_that_do_not_reconcile_with_the_unexplained_count(self) -> None:
        ledger = ledger_of("row-a")
        receipt = v2_fixture(("row-a",), ledger, "DOCUMENTED_EXCEPTION", RESIDENCY.DOCUMENTED_EXCEPTION_REASON)
        receipt["counts"]["residency"]["unexplained_orphan_rows"] = 2
        receipt["counts"]["residency"]["orphan_rows"] = 3
        receipt["counts"]["residency"]["customer_unevaluable_rows"] = 3
        receipt["counts"]["residency"]["unevaluable_rows"] = 3
        receipt["counts"]["residency"]["satisfied_rows"] = 1
        receipt["counts"]["backfill_completeness"].update({"orphan_rows": 3, "joinable_rows": 1})
        resign(receipt)
        with self.assertRaisesRegex(classifier.ReceiptError, "do not reconcile"):
            classifier.classify(receipt, ledger=ledger)

    def test_v1_receipt_never_applies_the_attestation(self) -> None:
        report = classifier.classify(receipt_fixture(), ledger=ledger_of("anything"))
        self.assertIsNone(report["attestation"])
        classes = {item["class"]: item for item in report["classes"]}
        self.assertEqual(classes["owner_attested_prelaunch_test_traffic"]["rows"], 0)
        self.assertEqual(classes["unexplained_orphan"]["rows"], 1)


class ReceiptClassifierTests(unittest.TestCase):
    def test_classifies_orphans_with_exception_or_owner_hold_disposition(self) -> None:
        report = classifier.classify(receipt_fixture())
        classes = {item["class"]: item for item in report["classes"]}

        self.assertEqual(report["overall_disposition"], "KEEP_OPEN")
        self.assertFalse(report["tenant_identity_dispositions_complete"])
        self.assertEqual(
            classes["erased_orphan_retained_audit"]["disposition"],
            "DOCUMENTED_EXCEPTION_ERASED_LINEAGE",
        )
        self.assertEqual(classes["unexplained_orphan"]["rows"], 1)
        self.assertEqual(
            classes["unexplained_orphan"]["disposition"],
            "PRESERVE_AND_REQUIRE_RESTRICTED_OWNER_RECONCILIATION",
        )
        self.assertEqual(sum(item["rows"] for item in report["classes"]), 5)
        self.assertEqual(report["states"]["erased_lineage_exception"], 1)
        self.assertEqual(report["states"]["unevaluable"], 1)

    def test_erased_only_population_is_documented_exception_not_compliant(self) -> None:
        residency = classifier.PROBE.RESIDENCY
        report = classifier.classify(
            erased_only_fixture(residency.DOCUMENTED_EXCEPTION, residency.DOCUMENTED_EXCEPTION_REASON)
        )
        classes = {item["class"]: item for item in report["classes"]}

        self.assertEqual(report["source_status"], "DOCUMENTED_EXCEPTION")
        self.assertEqual(report["overall_disposition"], "DOCUMENTED_EXCEPTION")
        self.assertNotIn("COMPLIANT", (report["source_status"], report["overall_disposition"]))
        self.assertEqual(classes["erased_orphan_retained_audit"]["rows"], 1)
        self.assertEqual(classes["satisfied_customer"]["rows"], 3)
        self.assertEqual(
            report["states"],
            {
                "satisfied": 3,
                "violated": 0,
                "erased_lineage_exception": 1,
                "owner_attested_prelaunch_test_traffic": 0,
                "unevaluable": 0,
                "reserved_public": 1,
            },
        )
        self.assertIn("policy B", report["exception_policy"])

    def test_rejects_erased_lineage_relabelled_compliant(self) -> None:
        residency = classifier.PROBE.RESIDENCY
        receipt = erased_only_fixture(residency.COMPLIANT, residency.COMPLIANT_REASON)

        with self.assertRaisesRegex(classifier.ReceiptError, "verdict does not match"):
            classifier.classify(receipt)

    def test_rejects_documented_exception_claimed_over_an_unexplained_orphan(self) -> None:
        residency = classifier.PROBE.RESIDENCY
        receipt = receipt_fixture()
        receipt["status"] = residency.DOCUMENTED_EXCEPTION
        receipt["reason"] = residency.DOCUMENTED_EXCEPTION_REASON
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "verdict does not match"):
            classifier.classify(receipt)

    def test_pre_policy_b_failed_receipt_with_unexplained_rows_still_classifies(self) -> None:
        # Receipts written before policy B carry the unchanged FAILED reason; a
        # population that still has unexplained orphans must keep verifying.
        receipt = receipt_fixture()
        self.assertEqual(
            receipt["reason"],
            "known violations or unevaluable rows exist; neither may be reported compliant",
        )
        report = classifier.classify(receipt)
        self.assertEqual(report["source_status"], "FAILED")
        self.assertEqual(report["overall_disposition"], "KEEP_OPEN")

    def test_rejects_receipt_with_changed_counts(self) -> None:
        receipt = receipt_fixture()
        receipt["counts"]["residency"]["unexplained_orphan_rows"] = 0

        with self.assertRaisesRegex(classifier.ReceiptError, "digest"):
            classifier.classify(receipt)

    def test_rejects_backfill_partition_mismatch_even_with_valid_digest(self) -> None:
        receipt = receipt_fixture()
        receipt["counts"]["backfill_completeness"]["joinable_rows"] = 1
        receipt["receipt_sha256"] = classifier.PROBE._hash(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )

        with self.assertRaisesRegex(classifier.ReceiptError, "partition is partial"):
            classifier.classify(receipt)

    def test_verifies_downloaded_artifact_checksum_sidecar(self) -> None:
        payload = b"retained receipt bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "issue-1669-read-only-receipt.json"
            sidecar = Path(directory) / "issue-1669-read-only-receipt.sha256"
            receipt.write_bytes(payload)
            sidecar.write_text(f"{digest}  artifacts/{receipt.name}\n", encoding="utf-8")

            self.assertEqual(classifier.verify_sidecar(receipt, sidecar), digest)
            sidecar.write_text(f"{'0' * 64}  artifacts/{receipt.name}\n", encoding="utf-8")
            with self.assertRaisesRegex(classifier.ReceiptError, "artifact checksum"):
                classifier.verify_sidecar(receipt, sidecar)

    def test_rejects_redigested_row_identity_field(self) -> None:
        receipt = receipt_fixture()
        receipt["tenant_id"] = "private-row-identity"
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "fields are missing or unexpected"):
            classifier.classify(receipt)

    def test_rejects_redigested_missing_receipt_field(self) -> None:
        receipt = receipt_fixture()
        del receipt["reason"]
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "fields are missing or unexpected"):
            classifier.classify(receipt)

    def test_rejects_redigested_query_payload_field(self) -> None:
        receipt = receipt_fixture()
        receipt["queries"][0]["payload"] = {"email": "private-row-payload"}
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "query residency fields"):
            classifier.classify(receipt)

    def test_rejects_redigested_missing_query_field(self) -> None:
        receipt = receipt_fixture()
        del receipt["queries"][0]["response_sha256"]
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "query residency fields"):
            classifier.classify(receipt)

    def test_rejects_boolean_aggregate_row_count(self) -> None:
        for invalid_row_count in (True, 1.0, "1"):
            with self.subTest(row_count=invalid_row_count):
                receipt = receipt_fixture()
                receipt["queries"][0]["row_count"] = invalid_row_count
                resign(receipt)

                with self.assertRaisesRegex(classifier.ReceiptError, "single aggregate row"):
                    classifier.classify(receipt)

    def test_rejects_zero_orphan_rows_with_positive_tenant_count(self) -> None:
        receipt = receipt_fixture()
        counts = receipt["counts"]
        residency = counts["residency"]
        residency.update(
            {
                "satisfied_rows": 3,
                "violated_rows": 1,
                "unevaluable_rows": 0,
                "customer_unevaluable_rows": 0,
                "orphan_rows": 0,
                "orphan_tenants": 1,
                "erased_orphan_rows": 0,
                "erased_orphan_tenants": 0,
                "unexplained_orphan_rows": 0,
                "unexplained_orphan_tenants": 1,
                "weur_audit_rows": 0,
                "weur_orphan_rows": 0,
            }
        )
        counts["backfill_completeness"].update(
            {"orphan_rows": 0, "joinable_rows": 4, "erased_orphan_rows": 0}
        )
        receipt["status"] = "COMPLIANT"
        receipt["reason"] = (
            "all customer rows are satisfied and all public rows meet the reserved-namespace contract"
        )
        resign(receipt)

        with self.assertRaisesRegex(classifier.ReceiptError, "tenant counts exceed"):
            classifier.classify(receipt)

    def test_rejects_each_orphan_tenant_count_above_its_row_count(self) -> None:
        for tenant_field in (
            "orphan_tenants",
            "erased_orphan_tenants",
            "unexplained_orphan_tenants",
        ):
            with self.subTest(tenant_field=tenant_field):
                receipt = receipt_fixture()
                receipt["counts"]["residency"][tenant_field] = 3
                resign(receipt)

                with self.assertRaisesRegex(classifier.ReceiptError, "tenant counts exceed"):
                    classifier.classify(receipt)

    def test_rejects_population_tenant_count_above_audit_rows(self) -> None:
        for audit_tenants in (0, 6):
            with self.subTest(audit_tenants=audit_tenants):
                receipt = receipt_fixture()
                receipt["counts"]["population"]["audit_tenants"] = audit_tenants
                resign(receipt)

                with self.assertRaisesRegex(classifier.ReceiptError, "outside its audit row bounds"):
                    classifier.classify(receipt)


if __name__ == "__main__":
    unittest.main()
