#!/usr/bin/env python3
"""Focused fail-closed tests for the bounded owner-action packet."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_owner_action_packets", ROOT / "scripts/verify_owner_action_packets.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class OwnerActionPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(MODULE.PACKET.read_text(encoding="utf-8"))

    def test_exact_closed_population_passes(self) -> None:
        self.assertEqual(MODULE.check_data(self.data), {"items": 29, "population": 29})

    def test_b111_hermetic_cli_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, "-S", "scripts/verify_owner_action_packets.py", "--id", "B-111"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("owner-action packet: PASS: 29 item(s)", result.stdout)

    def test_b054_cli_reports_readiness_scope(self) -> None:
        result = subprocess.run(
            [sys.executable, "-S", "scripts/verify_owner_action_packets.py", "--id", "B-054"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "B-054 evidence: FIXTURE_READINESS_ONLY; rotation=BLOCKED; "
            "revocation_recovery=NOT_EXECUTED; retention=NOT_EXECUTED; "
            "audit_linkage=NOT_EXECUTED",
            result.stdout,
        )

    def test_b012_packet_preserves_distinct_ci_blockers(self) -> None:
        self.assertEqual(
            MODULE.check_data(self.data, "B-012"),
            {"items": 29, "population": 29},
        )
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-012")
        self.assertEqual((item["owner"], item["status"]), ("tl", "done"))
        mutations = (
            ("procedure", 0, "GitHub App", "credential"),
            ("procedure", 2, "online runner labelled corelink", "online builder"),
            ("procedure", 3, "approval-required", "suppressed"),
            ("procedure", 3, "Dependabot", "bot"),
            ("procedure", 4, "zero-job run", "workflow run"),
            ("credentials", None, "administration:read", "contents:read"),
            ("item_schema", None, "job_count", "check_count"),
        )
        for field, index, before, after in mutations:
            with self.subTest(field=field, index=index, before=before):
                mutated = copy.deepcopy(self.data)
                item = next(entry for entry in mutated["items"] if entry["id"] == "B-012")
                if field == "procedure":
                    item[field][index] = item[field][index].replace(before, after, 1)
                elif field == "credentials":
                    boundary = item["inputs_and_credentials_boundary"]
                    boundary[field] = boundary[field].replace(before, after, 1)
                else:
                    item["evidence"][field] = item["evidence"][field].replace(before, after, 1)
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-012")

        stale_open = copy.deepcopy(self.data)
        stale_item = next(entry for entry in stale_open["items"] if entry["id"] == "B-012")
        stale_item["status"] = "open"
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(stale_open, "B-012")

    def test_b013_reconciled_closure_matches_backlog(self) -> None:
        self.assertEqual(
            MODULE.check_data(self.data, "B-013"),
            {"items": 29, "population": 29},
        )
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-013")
        self.assertEqual((item["owner"], item["status"]), ("tl", "done"))

        stale = copy.deepcopy(self.data)
        stale_item = next(entry for entry in stale["items"] if entry["id"] == "B-013")
        stale_item.update(owner="owner", status="open")
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(stale, "B-013")

    def test_b065_closed_evidence_is_source_bound_and_read_only(self) -> None:
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-065")
        evidence = item["evidence"]
        self.assertEqual(evidence["required_fields"], MODULE.B065_EVIDENCE_REQUIRED_FIELDS)
        self.assertEqual((item["owner"], item["status"]), ("tl", "done"))
        self.assertEqual(evidence["path"], MODULE.B065_CLOSURE_EVIDENCE_PATH)
        schema = evidence["item_schema"]
        for marker in (
            "source_original.sha256", "destination_inventory[]", "api_version (v1 or v2)",
            "signup_worker", "corelink_prd_container", "resolution.mode=observed_disabled",
            "correlation.possible=false", "duplicate_events_resolved remains false",
        ):
            self.assertIn(marker, schema)
        self.assertEqual(MODULE.check_data(self.data, "B-065"), {"items": 29, "population": 29})

        for name, mutation in (
            ("legacy single retained ID", lambda entry: entry["evidence"].update(required_fields=[
                "schema_version", "captured_at", "account", "retired_endpoint_id",
                "retained_endpoint_id", "retired_at", "billing_health_runs",
                "duplicate_events_resolved", "operator",
            ])),
            ("missing no-mutation path", lambda entry: entry["evidence"].update(
                item_schema=entry["evidence"]["item_schema"].replace("resolution.mode=observed_disabled", "resolution.mode=unknown")
            )),
            ("missing second legitimate endpoint", lambda entry: entry["evidence"].update(
                item_schema=entry["evidence"]["item_schema"].replace("corelink_prd_container", "container")
            )),
        ):
            with self.subTest(name=name):
                mutated = copy.deepcopy(self.data)
                mutation(next(entry for entry in mutated["items"] if entry["id"] == "B-065"))
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-065")

        stale = copy.deepcopy(self.data)
        stale_item = next(entry for entry in stale["items"] if entry["id"] == "B-065")
        stale_item.update(owner="owner", status="open")
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(stale, "B-065")

    def test_b110_reconciled_closure_matches_backlog(self) -> None:
        self.assertEqual(
            MODULE.check_data(self.data, "B-110"),
            {"items": 29, "population": 29},
        )
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-110")
        self.assertEqual((item["owner"], item["status"]), ("tl", "done"))

        stale = copy.deepcopy(self.data)
        stale_item = next(entry for entry in stale["items"] if entry["id"] == "B-110")
        stale_item.update(owner="owner", status="open")
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(stale, "B-110")

    def test_b110_exact_evidence_binding_rejects_packet_mutations(self) -> None:
        mutations = (
            ("path", "evidence/owner-actions/B-110/missing.json"),
            ("item_schema", "selected_option is anything"),
            ("required_fields", ["schema_version"]),
            ("procedure", ["RUN: noop", "RUN: noop"]),
            ("expected_postcondition", "B-110 is parked"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.data)
                item = next(entry for entry in mutated["items"] if entry["id"] == "B-110")
                if field in {"path", "item_schema", "required_fields"}:
                    item["evidence"][field] = value
                else:
                    item[field] = value
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-110")

    def test_b089_packet_references_resolve_and_fail_on_stale_path(self) -> None:
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-089")
        MODULE._check_b089_surface_contract(item)
        for field in ("references", "procedure"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.data)
                row = next(entry for entry in mutated["items"] if entry["id"] == "B-089")
                if field == "references":
                    row[field][2] = "apps/docs/src/pages/terms.tsx"
                else:
                    row[field][1] = row[field][1].replace(
                        "apps/docs/src/pages/legal/terms.tsx", "apps/docs/src/pages/terms.tsx"
                    )
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-089")

    def test_b089_backlog_verify_is_one_fail_closed_shell_chain(self) -> None:
        backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        section = re.search(r"(?ms)^### B-089\b.*?^```backlog\n(.*?)^```", backlog)
        self.assertIsNotNone(section)
        assert section is not None
        verify_rows = re.findall(r"(?m)^verify: (.+)$", section.group(1))
        command = (
            "python3 scripts/verify_b089_sla_credits.py && "
            "python3 -S scripts/verify_owner_action_packets.py --id B-089"
        )
        self.assertEqual(verify_rows, [command])
        for first, expected in (("false", 1), ("true", 0)):
            with self.subTest(first=first):
                probe = command.replace("python3 scripts/verify_b089_sla_credits.py", first).replace(
                    "python3 -S scripts/verify_owner_action_packets.py --id B-089", "true"
                )
                result = subprocess.run(["/bin/bash", "-o", "pipefail", "-c", probe], check=False)
                self.assertEqual(result.returncode, expected)

    def test_b089_known_cross_document_drift_cannot_change_silently(self) -> None:
        item = next(entry for entry in self.data["items"] if entry["id"] == "B-089")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in MODULE.B089_SURFACES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            for name in (
                "legal/sla/v1.1.0.md", "marketing/sales/FAQ-MASTER.md",
                "apps/docs/src/pages/pricing.tsx",
            ):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            MODULE._check_b089_surface_contract(item, root)

            mutations = (
                (MODULE.B089_SURFACES[0], "| **Free** | ≥ 99.0% |", "| **Free** | ≥ 99.1% |"),
                ("legal/sla/v1.1.0.md", "| Solo | No | No | No | No |", "| Solo | Yes | No | No | No |"),
                ("legal/sla/v1.1.0.md", "| `0 < shortfall < 0.5 pp` | 5% |", "| `0 < shortfall < 0.5 pp` | 6% |"),
                ("legal/sla/v1.1.0.md", "| `0.5 pp ≤ shortfall < 1.0 pp` | 10% |", "| `0.5 pp ≤ shortfall < 1.0 pp` | 11% |"),
                ("legal/sla/v1.1.0.md", "| `1.0 pp ≤ shortfall < 2.5 pp` | 25% |", "| `1.0 pp ≤ shortfall < 2.5 pp` | 26% |"),
                ("legal/sla/v1.1.0.md", "| `2.5 pp ≤ shortfall ≤ 5.0 pp` | 50% |", "| `2.5 pp ≤ shortfall ≤ 5.0 pp` | 51% |"),
                ("legal/sla/v1.1.0.md", "| `shortfall > 5.0 pp` or absolute uptime `< 95%` | 100% plus the §4 termination right |", "| `shortfall > 5.0 pp` or absolute uptime `< 95%` | 99% plus the §4 termination right |"),
                ("legal/sla/v1.1.0.md", "| `0 < excess ≤ 25%` | 5% |", "| `0 < excess ≤ 25%` | 6% |"),
                ("legal/sla/v1.1.0.md", "| `25% < excess ≤ 50%` | 10% |", "| `25% < excess ≤ 50%` | 11% |"),
                ("legal/sla/v1.1.0.md", "| `excess > 50%` | 25% |", "| `excess > 50%` | 26% |"),
                ("legal/sla/v1.1.0.md", "| DSR erasure `30 days ≤ duration < 45 days` | 5% |", "| DSR erasure `30 days ≤ duration < 45 days` | 6% |"),
                ("legal/sla/v1.1.0.md", "| DSR erasure `duration ≥ 45 days` | 25% plus DPO incident review |", "| DSR erasure `duration ≥ 45 days` | 26% plus DPO incident review |"),
                ("legal/sla/v1.1.0.md", "| Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours` | 10% |", "| Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours` | 11% |"),
                ("legal/sla/v1.1.0.md", "| Target met or exceeded | 0% |\n", ""),
                ("legal/sla/v1.1.0.md", "| Target met or exceeded | 0% |\n", "| Target met or exceeded | 0% |\n| Target met or exceeded | 0% |\n"),
                ("legal/sla/v1.1.0.md", "| Target met or exceeded | 0% |\n", "| Target met or exceeded | 0% |\n| Unexpected result | 7% |\n"),
                ("legal/sla/v1.1.0.md", "Credits stack only across distinct SLOs", "Credits stack across any SLOs"),
                ("legal/sla/v1.1.0.md", "aggregate is capped at 100%", "aggregate is capped at 90%"),
                ("legal/sla/v1.1.0.md", "Catastrophic uptime takes priority", "Ordinary uptime takes priority"),
                ("legal/sla/v1.1.0.md", "No separate refund is added for the same\nordinary SLA breach.", "A separate refund is added for the same\nordinary SLA breach."),
                ("legal/sla/v1.1.0.md", "A signed Enterprise Order Form may change only the metrics, rates, or remedies\nthat it expressly identifies.", "A signed Enterprise Order Form may change all metrics, rates, or remedies\nwithout limits."),
                ("legal/sla/v1.1.0.md", "three consecutive months of uptime breach", "two consecutive months of uptime breach"),
                ("legal/sla/v1.1.0.md", "one\ncatastrophic uptime breach", "two\ncatastrophic uptime breaches"),
                ("legal/sla/v1.1.0.md", "repeated DSR erasure breach in two consecutive", "repeated DSR erasure breach in one consecutive"),
                ("legal/sla/v1.1.0.md", "pro-rata refund of prepaid fees applies only after a valid termination", "pro-rata refund of prepaid fees applies after any breach"),
                ("legal/sla/v1.1.0.md", "is not a second recovery for the same SLA breach.", "is a second recovery for the same SLA breach."),
                ("legal/sla/v1.1.0.md", "no promise\nof automatic or manual issuance", "a promise\nof automatic or manual issuance"),
                ("apps/docs/src/pages/legal/terms.tsx", "No SLA service-credit program is currently active", "An SLA service-credit program is currently active"),
                ("marketing/sales/FAQ-MASTER.md", "SLA service credits are not active for any tier today", "SLA service credits are active for every tier today"),
                ("apps/docs/src/pages/pricing.tsx", "const APP_BASE =", "const APP_BASE = \"99.9% SLA + credits\"; // const APP_BASE ="),
                (MODULE.B089_SURFACES[2], '"solo",', '"business",'),
                (MODULE.B089_SURFACES[2], '  solo: {\n    id: "solo",', '  solo: {\n    slaCredits: true,\n    id: "solo",'),
                (MODULE.B089_SURFACES[2], '  starter: {\n    id: "starter",', '  starter: {\n    slaCredits: true,\n    id: "starter",'),
                (MODULE.B089_SURFACES[2], '  pro: {\n    id: "pro",', '  pro: {\n    slaCredits: true,\n    id: "pro",'),
                (MODULE.B089_SURFACES[2], '  max: {\n    id: "max",', '  max: {\n    slaCredits: true,\n    id: "max",'),
            )
            for name, old, new in mutations:
                with self.subTest(source=name, mutation=old):
                    target = root / name
                    original = target.read_text(encoding="utf-8")
                    self.assertIn(old, original)
                    target.write_text(original.replace(old, new, 1), encoding="utf-8")
                    try:
                        with self.assertRaises(MODULE.PacketError):
                            MODULE._check_b089_surface_contract(item, root)
                    finally:
                        target.write_text(original, encoding="utf-8")
            (root / MODULE.B089_SURFACES[1]).unlink()
            with self.assertRaises(MODULE.PacketError):
                MODULE._check_b089_surface_contract(item, root)

    def test_b110_capacity_decision_evidence_mutations_fail_closed(self) -> None:
        for field, value in (
            ("selected_option", "owner_authorized_park"),
            ("runner_labels", ["mac"]),
            ("workflows", []),
        ):
            with self.subTest(field=field):
                record = copy.deepcopy(MODULE._read_b110_evidence())
                record[field] = value
                with mock.patch.object(MODULE, "_read_b110_evidence", return_value=record):
                    with self.assertRaises(MODULE.PacketError):
                        MODULE.check_data(self.data, "B-110")

    def test_identifier_focus_skips_unrelated_owner_receipts(self) -> None:
        mutated = copy.deepcopy(self.data)
        b086 = next(entry for entry in mutated["items"] if entry["id"] == "B-086")
        b086["owner"] = "owner"
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(mutated)
        self.assertEqual(MODULE.check_data(mutated, "B-054"), {"items": 29, "population": 29})

    def test_b054_receipt_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        record = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        record["migration_receipts"]["blocker"] = ""
        def read_b054(path, fields, label):
            return record if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_b054):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        for field, value in (
            ("algorithm_version", "E1/keyed"),
            ("verification", "BLOCKED"),
        ):
            mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
            mutated["legacy_epoch"][field] = value
            def read_mutated(path, fields, label, receipt=mutated):
                return receipt if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
            with self.subTest(field=field), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_mutated):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-054")

        mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        mutated["keyed_epoch"]["status"] = "NOT_EXECUTED"
        def read_keyed(path, fields, label):
            return mutated if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_keyed):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        mutated["two_person_administration"]["status"] = "PASS"
        def read_custody_status(path, fields, label):
            return mutated if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_custody_status):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        mutated["two_person_administration"]["access_review"]["owner"] = "unverified-owner"
        def read_custody_owner(path, fields, label):
            return mutated if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_custody_owner):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        mutated["witness_receipt"]["status"] = "NOT_EXECUTED"
        def read_witness(path, fields, label):
            return mutated if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_witness):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        mutated = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        mutated["repository_checks"][0]["command"] = "backlog B-054 verification shell"
        def read_command(path, fields, label):
            return mutated if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_command):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

        record = copy.deepcopy(original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054"))
        record["witness_receipt"]["reference"] = "forged-reference"
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_b054):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-054")

    def test_b054_custody_scope_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        baseline = original(MODULE.B054_EVIDENCE_PATH, MODULE.B054_EVIDENCE_REQUIRED_FIELDS, "B-054")
        mutations = (
            ("evidence_mode", "EXECUTED_CEREMONY"),
            ("authority_roles", ["SRE executor"]),
            ("non_material_references", []),
            ("revocation_recovery.status", "PASS"),
            ("retention.status", "PASS"),
            ("audit_linkage.reference", "receipt://forged"),
        )
        for field, value in mutations:
            mutated = copy.deepcopy(baseline)
            target = mutated
            leaf = field
            if "." in field:
                parent, leaf = field.split(".", 1)
                target = mutated[parent]
            target[leaf] = value

            def read_mutated(path, fields, label, receipt=mutated):
                return receipt if path == MODULE.B054_EVIDENCE_PATH else original(path, fields, label)

            with self.subTest(field=field), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_mutated):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-054")

    def test_b083_receipt_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        record = copy.deepcopy(original(MODULE.B083_EVIDENCE_PATH, MODULE.B083_EVIDENCE_REQUIRED_FIELDS, "B-083"))
        record["lifecycle"]["wrap_unwrap"]["receipt_reference"] = "audit://forged/receipt"
        def read_b083(path, fields, label):
            return record if path == MODULE.B083_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_b083):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-083")

        for field, value in (("evidence_state", "VERIFIED"), ("tenant_redacted", "tenant-redacted")):
            mutated = copy.deepcopy(original(MODULE.B083_EVIDENCE_PATH, MODULE.B083_EVIDENCE_REQUIRED_FIELDS, "B-083"))
            mutated[field] = value
            def read_mutated(path, fields, label, receipt=mutated):
                return receipt if path == MODULE.B083_EVIDENCE_PATH else original(path, fields, label)
            with self.subTest(field=field), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_mutated):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-083")

        for field, value in (
            ("command", "backlog B-083 verification shell"),
            ("detail", "activation remains fail-closed"),
        ):
            mutated = copy.deepcopy(original(MODULE.B083_EVIDENCE_PATH, MODULE.B083_EVIDENCE_REQUIRED_FIELDS, "B-083"))
            mutated["repository_checks"][1][field] = value
            def read_repository_check(path, fields, label, receipt=mutated):
                return receipt if path == MODULE.B083_EVIDENCE_PATH else original(path, fields, label)
            with self.subTest(repository_check_field=field), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_repository_check):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-083")

    def test_b083_owner_packet_lifecycle_contract_rejects_omissions(self) -> None:
        self.assertEqual(MODULE.check_data(self.data, "B-083"), {"items": 29, "population": 29})
        mutations = (
            ("procedure", 0, "sha256 image digest", "image digest"),
            ("procedure", 1, "distinct isolated test tenant", "one test tenant"),
            ("procedure", 2, "durable audit receipt sink", "audit record"),
            ("procedure", 3, "provider failure with bounded retry", "provider retry"),
            ("procedure", 4, "no more than five minutes", "bounded timing"),
            ("procedure", 5, "ten lifecycle keys", "lifecycle keys"),
            ("procedure", 6, "keep #1653 open", "#1653 complete"),
            ("credentials", None, "repository action never creates, imports, rotates, disables, schedules deletion for, or cleans up a provider resource", "repository action is bounded"),
            ("postcondition", None, "run_loop revoke/restore p99 is at most five minutes", "revoke/restore p99 is bounded"),
            ("retry", None, "provider mutation, rollback, or cleanup is separately authorized", "provider work is authorized"),
        )
        for field, index, before, after in mutations:
            with self.subTest(field=field, index=index, before=before):
                mutated = copy.deepcopy(self.data)
                item = next(entry for entry in mutated["items"] if entry["id"] == "B-083")
                if field == "procedure":
                    item[field][index] = item[field][index].replace(before, after, 1)
                elif field == "credentials":
                    boundary = item["inputs_and_credentials_boundary"]
                    boundary["credentials"] = boundary["credentials"].replace(before, after, 1)
                elif field == "postcondition":
                    item["expected_postcondition"] = item["expected_postcondition"].replace(before, after, 1)
                else:
                    item["retry_and_rollback"] = item["retry_and_rollback"].replace(before, after, 1)
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-083")

    def test_b071_owner_packet_external_evidence_contract_rejects_omissions(self) -> None:
        self.assertEqual(MODULE.check_data(self.data, "B-071"), {"items": 29, "population": 29})
        mutations = (
            ("procedure", 0, "legal and audit holds", "holds"),
            ("procedure", 1, "evidence/staging/readiness.json", "readiness receipt"),
            ("procedure", 2, "K6_STAGING_PAT", "staging secret"),
            ("procedure", 4, "source-backed artifact equivalence", "artifact equivalence"),
            ("procedure", 5, "R2_TDK_HEX", "runtime input"),
            ("procedure", 6, "delete_count=0", "zero deletions"),
            ("procedure", 7, "Keep the observation JSON unchanged at PENDING_OWNER_REVIEW", "review the pending package"),
            ("credentials", None, "GC_LIVE_DELETE=false", "GC_LIVE_DELETE=true"),
            ("credentials", None, "CF_API_TOKEN must be a D1 read-only Cloudflare token", "CF_API_TOKEN must be a D1 token"),
            ("required_fields", None, "deleted_bytes", "deleted_total"),
            ("item_schema", None, "Legal-hold and accounting outcomes are not fields", "holds are reported as fields"),
            ("postcondition", None, "production observation image identity/equivalence", "staging image digest"),
            ("retry", None, "Do not broaden scope", "retry broadly"),
            ("reference", None, "#2167", "#2167-removed"),
        )
        for field, index, before, after in mutations:
            with self.subTest(field=field, index=index, before=before):
                mutated = copy.deepcopy(self.data)
                item = next(entry for entry in mutated["items"] if entry["id"] == "B-071")
                if field == "procedure":
                    item[field][index] = item[field][index].replace(before, after, 1)
                elif field == "credentials":
                    boundary = item["inputs_and_credentials_boundary"]
                    boundary["credentials"] = boundary["credentials"].replace(before, after, 1)
                elif field == "required_fields":
                    item["evidence"][field].remove(before)
                elif field == "item_schema":
                    item["evidence"][field] = item["evidence"][field].replace(before, after, 1)
                elif field == "postcondition":
                    item["expected_postcondition"] = item["expected_postcondition"].replace(before, after, 1)
                elif field == "retry":
                    item["retry_and_rollback"] = item["retry_and_rollback"].replace(before, after, 1)
                else:
                    item["references"].remove(before)
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(mutated, "B-071")

    def test_b097_read_only_capture_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        record = copy.deepcopy(original(MODULE.B097_EVIDENCE_PATH, MODULE.B097_EVIDENCE_REQUIRED_FIELDS, "B-097"))
        record["read_only_capture"]["support_case"] = "submitted"
        def read_b097(path, fields, label):
            return record if path == MODULE.B097_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_b097):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-097")

        mutated = copy.deepcopy(original(MODULE.B097_EVIDENCE_PATH, MODULE.B097_EVIDENCE_REQUIRED_FIELDS, "B-097"))
        mutated["read_only_capture"]["activity_readback"]["interpretation"] = "active tenants confirmed"
        def read_interpretation(path, fields, label):
            return mutated if path == MODULE.B097_EVIDENCE_PATH else original(path, fields, label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_interpretation):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-097")

        record = copy.deepcopy(original(MODULE.B097_EVIDENCE_PATH, MODULE.B097_EVIDENCE_REQUIRED_FIELDS, "B-097"))
        record["read_only_capture"]["active_tenant_metric"] = "available"
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_b097):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-097")

    def test_b097_account_reservation_and_tenant_population_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        baseline = original(MODULE.B097_EVIDENCE_PATH, MODULE.B097_EVIDENCE_REQUIRED_FIELDS, "B-097")
        mutations = {
            "omitted_app": lambda r: r["read_only_capture"]["application_readback"]["applications"].pop(),
            "regional_off_claim": lambda r: r["read_only_capture"]["application_readback"]["applications"][1].update(max_instances=0),
            "old_subtotal_as_total": lambda r: r.update(declared_reservation_vcpu=1250),
            "masked_other_apps": lambda r: r["read_only_capture"]["application_readback"].update(other_applications_reservation_vcpu=0),
            "registered_as_concurrent": lambda r: r.update(active_tenants_concurrent=264),
            "missing_tenant_region": lambda r: r["read_only_capture"]["tenant_population_readback"]["rows"].pop(),
            "d1_write_claim": lambda r: r["read_only_capture"]["tenant_population_readback"].update(rows_written=1),
            "d1_write_bool": lambda r: r["read_only_capture"]["tenant_population_readback"].update(rows_written=False),
        }
        for label, mutate in mutations.items():
            record = copy.deepcopy(baseline)
            mutate(record)
            def read_candidate(path, fields, receipt_label, candidate=record):
                return candidate if path == MODULE.B097_EVIDENCE_PATH else original(path, fields, receipt_label)
            with self.subTest(mutation=label), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_candidate):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-097")

    def test_b097_instance_census_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        baseline = original(MODULE.B097_EVIDENCE_PATH, MODULE.B097_EVIDENCE_REQUIRED_FIELDS, "B-097")
        mutations = {
            "missing_region": lambda c: c["by_region"].pop("prod-syd"),
            "system_as_tenant": lambda c: c["by_region"]["prod"].update(running_tenant_named=1, running_reserved_system=0),
            "wrong_total": lambda c: c.update(listed_named_instances=11),
            "boolean_count": lambda c: c["by_region"]["prod"].update(running_reserved_system=True),
            "wrong_capture_time": lambda c: c.update(captured_at="2026-09-13T00:44:49Z"),
            "peak_claim": lambda c: c.update(interpretation="peak tenant concurrency measured"),
            "simultaneous_claim": lambda c: c.update(interpretation=c["interpretation"].replace("not one simultaneous snapshot", "one simultaneous snapshot")),
            "extra_field": lambda c: c.update(tenant_id="should-not-appear"),
        }
        for label, mutate in mutations.items():
            record = copy.deepcopy(baseline)
            mutate(record["read_only_capture"]["instance_census"])
            def read_candidate(path, fields, receipt_label, candidate=record):
                return candidate if path == MODULE.B097_EVIDENCE_PATH else original(path, fields, receipt_label)
            with self.subTest(mutation=label), mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_candidate):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-097")

        record = copy.deepcopy(baseline)
        record["captured_at"] = "2026-09-13T14:28:56Z"
        def read_wrong_outer_time(path, fields, receipt_label):
            return record if path == MODULE.B097_EVIDENCE_PATH else original(path, fields, receipt_label)
        with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_wrong_outer_time):
            with self.assertRaises(MODULE.PacketError):
                MODULE.check_data(self.data, "B-097")

    def test_b086_shared_d1_owner_and_active_readback_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        baseline = original(MODULE.B086_EVIDENCE_PATH, MODULE.B086_EVIDENCE_REQUIRED_FIELDS, "B-086")
        for mutate in (
            lambda value: value.update(decision="unresolved"),
            lambda value: value["current_owner_decision"].update(closure_status="CLOSED"),
            lambda value: value["deployed_active_readback"]["active_workers"][0].update(CONFIG_DB_database_id="00000000-0000-4000-8000-000000000000"),
        ):
            record = copy.deepcopy(baseline)
            mutate(record)
            def read_candidate(path, fields, label, candidate=record):
                return candidate if path == MODULE.B086_EVIDENCE_PATH else original(path, fields, label)
            with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_candidate):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-086")

    def test_b086_packet_cannot_call_pending_template_executed(self) -> None:
        packet = copy.deepcopy(self.data)
        item = next(row for row in packet["items"] if row["id"] == "B-086")
        item["procedure"][0] = item["procedure"][0].replace(
            "pending legal-review template, not an executed instrument",
            "executed residency instrument",
        )
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(packet, "B-086")

    def test_b154_prelaunch_claim_mutations_fail_closed(self) -> None:
        original = MODULE._read_json_evidence
        baseline = original(MODULE.B154_EVIDENCE_PATH, MODULE.B154_EVIDENCE_REQUIRED_FIELDS, "B-154")
        mutations = (
            lambda value: value["lifecycle"].update(customers="ONE"),
            lambda value: value.update(provider_chains_closed=True),
            lambda value: value["claims"]["object_lock"].update(launch_availability="AVAILABLE"),
            lambda value: value["claims"]["byok_kill_switch"].update(p99_measurement="PASS"),
            lambda value: value["source_sha256"].update({next(iter(value["source_sha256"])): "0" * 64}),
        )
        for mutate in mutations:
            record = copy.deepcopy(baseline)
            mutate(record)
            def read_candidate(path, fields, label, candidate=record):
                return candidate if path == MODULE.B154_EVIDENCE_PATH else original(path, fields, label)
            with mock.patch.object(MODULE, "_read_json_evidence", side_effect=read_candidate):
                with self.assertRaises(MODULE.PacketError):
                    MODULE.check_data(self.data, "B-154")

    def test_base_sha_provenance_disclaimer_is_mandatory(self) -> None:
        missing = copy.deepcopy(self.data)
        missing["non_claim"] = "No claims."
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(missing)

        wrong_reference = copy.deepcopy(self.data)
        wrong_reference["base_sha"] = "0" * 40
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(wrong_reference)

    def test_every_load_bearing_field_mutation_fails(self) -> None:
        self.assertEqual(MODULE.mutation_self_test(self.data), 29 * (len(MODULE.ITEM_FIELDS) + 2) + 2)

    def test_backlog_owner_status_mismatch_fails_closed(self) -> None:
        contracts = MODULE._read_backlog_contracts()
        contracts["B-029"] = ("owner", "open")
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(self.data, backlog_contracts=contracts)

        contracts = MODULE._read_backlog_contracts()
        contracts["B-142"] = ("tl", "closed")
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(self.data, backlog_contracts=contracts)

    def test_missing_item_and_ambiguous_field_fail_closed(self) -> None:
        missing = copy.deepcopy(self.data)
        del missing["items"][0]["evidence"]
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(missing)

        ambiguous = copy.deepcopy(self.data)
        ambiguous["items"][0]["procedure"] = "UI: do the thing"
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(ambiguous)

    def test_unknown_and_duplicate_population_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.data)
        unknown["population"][0] = "B-999"
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(unknown)

        duplicate = copy.deepcopy(self.data)
        duplicate["items"][1]["id"] = duplicate["items"][0]["id"]
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(duplicate)

    def test_b111_semantic_workflow_secret_mutation_fails_closed(self) -> None:
        contracts = MODULE._read_b111_workflow_contracts()
        mutated = copy.deepcopy(contracts)
        path = ".github/workflows/notarize-macos.yml"
        mutated[path]["declared"] = frozenset(
            set(mutated[path]["declared"]) - {"APPLE_NOTARIZATION_API_KEY"}
        )
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(self.data, workflow_contracts=mutated)

    def test_b111_release_chain_mutation_fails_closed(self) -> None:
        contracts = MODULE._read_b111_workflow_contracts()
        mutated = copy.deepcopy(contracts)
        jobs = mutated["release-chain"]["jobs"]
        jobs["notarize-macos"]["needs"] = ["release"]
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(self.data, workflow_contracts=mutated)

    def test_b111_obsolete_secret_name_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.data)
        item = next(entry for entry in mutated["items"] if entry["id"] == "B-111")
        item["procedure"][0] = item["procedure"][0].replace(
            "APPLE_NOTARIZATION_API_KEY", "APPLE_NOTARIZATION_PASSWORD"
        )
        with self.assertRaises(MODULE.PacketError):
            MODULE.check_data(mutated)


if __name__ == "__main__":
    unittest.main()
