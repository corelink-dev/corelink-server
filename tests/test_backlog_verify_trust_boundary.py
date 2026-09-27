"""Adversarial tests for the BASE-owned backlog PR gate."""

from __future__ import annotations

import hashlib
import re
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import datetime as dt
from pathlib import Path
from unittest.mock import patch

from scripts import backlog_verify


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "backlog_verify.py"


class BacklogVerifyTrustBoundaryTests(unittest.TestCase):
    @staticmethod
    def _write(root: Path, relative: str, contents: bytes) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)

    def _c0_fixture(self) -> tuple[Path, Path, dict[str, str], dict[str, str]]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        trusted = Path(directory.name) / "trusted"
        candidate = Path(directory.name) / "candidate"
        trusted.mkdir()
        candidate.mkdir()
        for root in (trusted, candidate):
            self._write(root, ".actionlint.yaml", b"shared actionlint policy\n")
            link = root / ".github" / "actionlint.yaml"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("../.actionlint.yaml")
        preimages = {
            "scripts/verify_b057_sli.py": b"def trusted_verifier_preimage():\n    return True\n",
            "tests/test_b057_sli_contract.py": b"trusted contract preimage\n",
        }
        targets = {
            "scripts/verify_b057_sli.py": b"candidate verifier target\n",
            "tests/test_b057_sli_contract.py": b"candidate contract target\n",
            ".github/workflows/issue-2414-b057-sli.yml": b"candidate workflow target\n",
        }
        for relative, contents in preimages.items():
            self._write(trusted, relative, contents)
            self._write(candidate, relative, targets[relative])
        self._write(candidate, ".github/workflows/issue-2414-b057-sli.yml", targets[
            ".github/workflows/issue-2414-b057-sli.yml"
        ])
        return (
            trusted,
            candidate,
            {relative: hashlib.sha256(contents).hexdigest() for relative, contents in preimages.items()},
            {relative: hashlib.sha256(contents).hexdigest() for relative, contents in targets.items()},
        )

    def _b029_load_gate_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        trusted, candidate = Path(directory.name) / "trusted", Path(directory.name) / "candidate"
        trusted.mkdir()
        candidate.mkdir()
        preimages: dict[str, str | None] = {}
        targets: dict[str, str] = {}
        modes: dict[str, int] = {}
        for relative in backlog_verify.B029_LOAD_GATE_TARGETS:
            old = None if relative in {
                "scripts/staging_load_lifecycle_auth.py",
                "tests/load/k6/lib/staging_load_admission.js",
                "tests/test_staging_load_lifecycle_auth.py",
            } else f"old:{relative}".encode()
            new = f"new:{relative}".encode()
            if old is not None:
                self._write(trusted, relative, old)
                preimages[relative] = hashlib.sha256(old).hexdigest()
            else:
                preimages[relative] = None
            self._write(candidate, relative, new)
            targets[relative] = hashlib.sha256(new).hexdigest()
            modes[relative] = 0o755 if relative == "scripts/verify_b029_load_gate.py" else 0o644
            (candidate / relative).chmod(modes[relative])
            if old is not None:
                (trusted / relative).chmod(modes[relative])
        return trusted, candidate, preimages, targets, modes

    def _staging_transition_fixture(self, *, delivered: bool = False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        trusted, candidate = Path(directory.name) / "trusted", Path(directory.name) / "candidate"
        trusted.mkdir()
        candidate.mkdir()
        preimages = {path: f"old:{path}".encode() for path in backlog_verify.STAGING_CUSTOM_DOMAIN_PREIMAGES}
        targets = {path: f"new:{path}".encode() for path in backlog_verify.STAGING_CUSTOM_DOMAIN_TARGETS}
        for relative in preimages:
            self._write(trusted, relative, targets[relative] if delivered else preimages[relative])
            self._write(candidate, relative, preimages[relative] if delivered else targets[relative])
        for relative in backlog_verify.STAGING_CUSTOM_DOMAIN_DELIVERY_PATHS:
            old_payload, new_payload = b"previous delivery bytes\n", b"new delivery bytes\n"
            self._write(trusted, relative, new_payload if delivered else old_payload)
            self._write(candidate, relative, old_payload if delivered else new_payload)
        target_topology = (
            b'{"deployment_state":"unprovisioned","cloudflare":{"routes":[{"pattern":'
            b'"staging.corelink.humangr.com","worker":"corelink-staging",'
            b'"zone_name":"humangr.com","custom_domain":true}]}}'
        )
        preimages["infra/staging/topology.json"] = b'{"deployment_state":"unprovisioned", "cloudflare":{"routes":[]}}'
        targets["infra/staging/topology.json"] = target_topology
        # Rewrite topology with the compact, semantically exact target fixture.
        self._write(trusted, "infra/staging/topology.json", target_topology if delivered else preimages["infra/staging/topology.json"])
        self._write(candidate, "infra/staging/topology.json", preimages["infra/staging/topology.json"] if delivered else target_topology)
        old_pins = {path: hashlib.sha256(data).hexdigest() for path, data in preimages.items()}
        new_pins = {path: hashlib.sha256(data).hexdigest() for path, data in targets.items()}
        return trusted, candidate, old_pins, new_pins, preimages, targets

    def test_1700_staging_custom_domain_transition_is_exact_and_data_only(self) -> None:
        trusted, candidate, old_pins, new_pins, _, targets = self._staging_transition_fixture()
        # The real delivery changes thirteen separately enumerated paths
        # alongside the four pinned controls.
        delivery_paths = (
            ".github/workflows/issue-1700-staging-custom-domain.yml",
            "docs/campaigns/remediation/wp150-workflow-ownership.md",
            "infra/staging/README.md",
            "scripts/plan_staging_provider.py",
            "scripts/render_staging_wrangler.py",
            "scripts/staging_bootstrap_provider.py",
            "scripts/staging_custom_domain.py",
            "scripts/verify_staging_provider_preflight.py",
            "scripts/verify_staging_target.py",
            "tests/test_render_staging_wrangler.py",
            "tests/test_staging_bootstrap_provider.py",
            "tests/test_staging_custom_domain.py",
            "tests/test_verify_staging_target.py",
        )
        self.assertEqual(set(delivery_paths), backlog_verify.STAGING_CUSTOM_DOMAIN_DELIVERY_PATHS)
        marker = candidate.parent / "executed"
        malicious = f"from pathlib import Path; Path({str(marker)!r}).write_text('bad')".encode()
        targets["scripts/verify_b072_receiver.py"] = malicious
        new_pins["scripts/verify_b072_receiver.py"] = hashlib.sha256(malicious).hexdigest()
        self._write(candidate, "scripts/verify_b072_receiver.py", malicious)
        with patch.object(backlog_verify, "STAGING_CUSTOM_DOMAIN_PREIMAGES", old_pins), patch.object(
            backlog_verify, "STAGING_CUSTOM_DOMAIN_TARGETS", new_pins
        ):
            self.assertTrue(backlog_verify._preauthorized_staging_custom_domain(candidate, trusted))
        self.assertFalse(marker.exists())

    def test_1700_transition_still_rejects_an_additional_trusted_control(self) -> None:
        trusted, candidate, old_pins, new_pins, _, _ = self._staging_transition_fixture()
        control_paths = (
            "scripts/backlog_verify.py",
            "scripts/verify_backlog_wp_ledger.py",
            "scripts/backlog_ledger_successor.py",
            "scripts/backlog_ledger_contracts.py",
            "scripts/extra_trusted.py",
        )
        for relative in control_paths:
            self._write(trusted, relative, b"trusted bytes\n")
            self._write(candidate, relative, b"trusted bytes\n")
        self._write(candidate, "scripts/extra_trusted.py", b"candidate mutation\n")
        items = [self.item("B-001", verify="python3 scripts/extra_trusted.py")]
        with patch.object(backlog_verify, "STAGING_CUSTOM_DOMAIN_PREIMAGES", old_pins), patch.object(
            backlog_verify, "STAGING_CUSTOM_DOMAIN_TARGETS", new_pins
        ):
            with self.assertRaisesRegex(RuntimeError, "scripts/extra_trusted.py"):
                backlog_verify.check_candidate_controls(candidate, trusted, items)

    def test_1700_staging_custom_domain_rejects_partial_mixed_extra_and_wrong_topology(self) -> None:
        for mutation in ("partial", "mixed", "extra", "wrong-topology"):
            with self.subTest(mutation=mutation):
                trusted, candidate, old_pins, new_pins, _, _ = self._staging_transition_fixture()
                if mutation == "partial":
                    self._write(candidate, "tests/test_verify_staging_topology_contract.py", (trusted / "tests/test_verify_staging_topology_contract.py").read_bytes())
                elif mutation == "mixed":
                    self._write(candidate, "scripts/verify_b072_receiver.py", b"mixed preimage")
                elif mutation == "extra":
                    self._write(candidate, "unapproved.txt", b"extra")
                else:
                    self._write(candidate, "infra/staging/topology.json", b'{"deployment_state":"provisioned"}')
                with patch.object(backlog_verify, "STAGING_CUSTOM_DOMAIN_PREIMAGES", old_pins), patch.object(
                    backlog_verify, "STAGING_CUSTOM_DOMAIN_TARGETS", new_pins
                ):
                    self.assertFalse(backlog_verify._preauthorized_staging_custom_domain(candidate, trusted))

    def test_1700_staging_custom_domain_rejects_downgrade_after_delivery(self) -> None:
        trusted, candidate, old_pins, new_pins, _, _ = self._staging_transition_fixture(delivered=True)
        with patch.object(backlog_verify, "STAGING_CUSTOM_DOMAIN_PREIMAGES", old_pins), patch.object(
            backlog_verify, "STAGING_CUSTOM_DOMAIN_TARGETS", new_pins
        ):
            self.assertFalse(backlog_verify._preauthorized_staging_custom_domain(candidate, trusted))

    def test_1700_staging_custom_domain_constants_bind_frozen_hashes(self) -> None:
        self.assertEqual(backlog_verify.STAGING_CUSTOM_DOMAIN_PREIMAGES, {
            "scripts/verify_b072_receiver.py": "8acce3d50dbe4ad9a3df24d33e56828203a51510eab3fcfa3bff2b46c0b27a69",
            "scripts/verify_staging_topology_contract.py": "ba7abe9d5887269a69fcf2a8cfcec6d60d579ecd53f72a3ec6e9cc74250c677b",
            "tests/test_verify_staging_topology_contract.py": "97d1f75eb3608dbf71cc0506922ddd7b88b92f7f8f0812f01d392ee535be8103",
            "infra/staging/topology.json": "5156d6578d662020777a7e98cb1b91a181c6b4536afbd2c4a9498be06f57357e",
        })

    def test_b057_c0_pins_the_fresh_preimage_and_target_bytes(self) -> None:
        self.assertEqual(
            backlog_verify.B057_C0_PREIMAGES,
            {
                "scripts/verify_b057_sli.py": "5db63c2981c9f8278e1df9141f1eb5514712d964210c42cd9e4f451cfb78a82b",
                "tests/test_b057_sli_contract.py": "e50ffb0b8a78d9050656d79527fbb575be646530538a44b4315f4e334aead90c",
            },
        )
        self.assertEqual(
            backlog_verify.B057_C0_TARGETS,
            {
                "scripts/verify_b057_sli.py": "cc19cdd2501c8eddbb99feffcdf7eb6466a5f9fe31bf3fb71d7d7b887918de2e",
                "tests/test_b057_sli_contract.py": "77c2ebfb5842e007ca096e2bcbbccb9fb4e1a8c51a13aa58ecfd2c0622fc7421",
                ".github/workflows/issue-2414-b057-sli.yml": "feed9cf65ce17f8a11427db710ff0dbae26ad185ca38c1effeffdb94bfc09084",
            },
        )

    def test_b057_c0_admission_is_byte_pinned_and_never_executes_candidate_code(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        marker = candidate.parent / "candidate-code-executed"
        payload = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
        ).encode()
        self._write(candidate, "scripts/verify_b057_sli.py", payload)
        targets["scripts/verify_b057_sli.py"] = hashlib.sha256(payload).hexdigest()
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            self.assertTrue(backlog_verify._preauthorized_b057_c0(candidate, trusted))
        self.assertFalse(marker.exists(), "candidate verifier code was executed")

    def test_b029_load_gate_transition_is_full_pinned_and_data_only(self) -> None:
        trusted, candidate, preimages, targets, modes = self._b029_load_gate_fixture()
        verifier = "scripts/verify_b029_load_gate.py"
        marker = candidate.parent / "candidate-code-executed"
        payload = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
        ).encode()
        self._write(candidate, verifier, payload)
        (candidate / verifier).chmod(0o755)
        targets[verifier] = hashlib.sha256(payload).hexdigest()
        with patch.object(backlog_verify, "B029_LOAD_GATE_PREIMAGES", preimages), patch.object(
            backlog_verify, "B029_LOAD_GATE_TARGETS", targets
        ), patch.object(backlog_verify, "B029_LOAD_GATE_TARGET_MODES", modes):
            self.assertTrue(backlog_verify._preauthorized_b029_load_gate(candidate, trusted))
            with patch.object(backlog_verify, "_candidate_control_paths", return_value={verifier}):
                backlog_verify.check_candidate_controls(candidate, trusted, [])
        self.assertFalse(marker.exists(), "candidate verifier code was executed")

    def test_b029_load_gate_rejects_partial_mixed_extra_downgrade_mode_and_symlink(self) -> None:
        for mutation in ("partial", "mixed", "extra", "downgrade", "wrong-mode", "symlink"):
            with self.subTest(mutation=mutation):
                trusted, candidate, preimages, targets, modes = self._b029_load_gate_fixture()
                verifier = "scripts/verify_b029_load_gate.py"
                if mutation == "partial":
                    self._write(candidate, verifier, (trusted / verifier).read_bytes())
                    (candidate / verifier).chmod(0o755)
                elif mutation == "mixed":
                    self._write(candidate, verifier, b"unapproved mixed bytes\n")
                    (candidate / verifier).chmod(0o755)
                elif mutation == "extra":
                    self._write(candidate, "unapproved.txt", b"extra\n")
                elif mutation == "wrong-mode":
                    (candidate / verifier).chmod(0o644)
                elif mutation == "symlink":
                    payload = candidate.parent / "external-pinned-verifier.py"
                    payload.write_bytes((candidate / verifier).read_bytes())
                    (candidate / verifier).unlink()
                    (candidate / verifier).symlink_to(payload)
                else:
                    self._write(trusted, verifier, (candidate / verifier).read_bytes())
                    (trusted / verifier).chmod(0o755)
                with patch.object(backlog_verify, "B029_LOAD_GATE_PREIMAGES", preimages), patch.object(
                    backlog_verify, "B029_LOAD_GATE_TARGETS", targets
                ), patch.object(backlog_verify, "B029_LOAD_GATE_TARGET_MODES", modes):
                    self.assertFalse(backlog_verify._preauthorized_b029_load_gate(candidate, trusted))

    def test_b057_c0_allows_an_unchanged_inherited_symlink_without_following_it(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        outside = candidate.parent / "outside"
        outside.mkdir()
        (outside / "untracked.py").write_text("must not be traversed", encoding="utf-8")
        for root in (trusted, candidate):
            (root / ".github" / "outside-link").symlink_to(outside, target_is_directory=True)
            (root / ".git").symlink_to(outside, target_is_directory=True)

        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            trusted_entries = backlog_verify._candidate_tree_entries(trusted)
            candidate_entries = backlog_verify._candidate_tree_entries(candidate)
            self.assertEqual(trusted_entries[".github/actionlint.yaml"][0], "symlink")
            self.assertEqual(trusted_entries[".github/actionlint.yaml"][2], "../.actionlint.yaml")
            self.assertIn(".github/outside-link", candidate_entries)
            self.assertNotIn(".github/outside-link/untracked.py", candidate_entries)
            self.assertIn(".git", candidate_entries)
            self.assertNotIn(".git/untracked.py", candidate_entries)
            self.assertTrue(backlog_verify._preauthorized_b057_c0(candidate, trusted))

    def test_b057_c0_rejects_added_deleted_and_mutated_symlinks(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        link = ".github/actionlint.yaml"
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            self.assertTrue(backlog_verify._preauthorized_b057_c0(candidate, trusted))
            for mutation in ("mutated", "deleted", "added", "git-directory"):
                with self.subTest(mutation=mutation):
                    mutated = Path(tempfile.mkdtemp())
                    self.addCleanup(shutil.rmtree, mutated)
                    mutated_candidate = mutated / "candidate"
                    shutil.copytree(candidate, mutated_candidate, symlinks=True)
                    if mutation == "mutated":
                        (mutated_candidate / link).unlink()
                        (mutated_candidate / link).symlink_to("../different.yaml")
                    elif mutation == "deleted":
                        (mutated_candidate / link).unlink()
                    elif mutation == "added":
                        (mutated_candidate / ".github" / "extra-link").symlink_to("../.actionlint.yaml")
                    else:
                        git_target = mutated / "git-metadata"
                        git_target.mkdir()
                        (mutated_candidate / ".git").symlink_to(git_target, target_is_directory=True)
                    self.assertFalse(backlog_verify._preauthorized_b057_c0(mutated_candidate, trusted))

    def test_b057_c0_rejects_symlinks_at_every_pinned_target(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            for relative in targets:
                with self.subTest(target=relative):
                    mutated = Path(tempfile.mkdtemp())
                    self.addCleanup(shutil.rmtree, mutated)
                    mutated_candidate = mutated / "candidate"
                    shutil.copytree(candidate, mutated_candidate, symlinks=True)
                    link = mutated_candidate / relative
                    link.unlink()
                    external = mutated / "pinned-bytes"
                    external.write_bytes((candidate / relative).read_bytes())
                    link.symlink_to(external)
                    self.assertFalse(backlog_verify._preauthorized_b057_c0(mutated_candidate, trusted))

    def test_b057_c0_rejects_an_added_symlink_directory_without_traversing_it(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        outside = candidate.parent / "outside"
        outside.mkdir()
        (outside / "unapproved.txt").write_text("unapproved", encoding="utf-8")
        (candidate / ".github" / "unapproved-dir").symlink_to(outside, target_is_directory=True)
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            entries = backlog_verify._candidate_tree_entries(candidate)
            self.assertIn(".github/unapproved-dir", entries)
            self.assertNotIn(".github/unapproved-dir/unapproved.txt", entries)
            self.assertFalse(backlog_verify._preauthorized_b057_c0(candidate, trusted))

    def test_b057_c0_admission_rejects_nearby_mutations_and_policy_mutation(self) -> None:
        trusted, candidate, preimages, targets = self._c0_fixture()
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            self.assertTrue(backlog_verify._preauthorized_b057_c0(candidate, trusted))
            for relative in (*targets, "unapproved.txt"):
                with self.subTest(mutation=relative):
                    mutated = Path(tempfile.mkdtemp())
                    self.addCleanup(shutil.rmtree, mutated)
                    mutated_candidate = mutated / "candidate"
                    shutil.copytree(candidate, mutated_candidate, symlinks=True)
                    self._write(mutated_candidate, relative, b"unauthorized mutation\n")
                    self.assertFalse(backlog_verify._preauthorized_b057_c0(mutated_candidate, trusted))

            mutated = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, mutated)
            mutated_trusted = mutated / "trusted"
            shutil.copytree(trusted, mutated_trusted, symlinks=True)
            self._write(mutated_trusted, "scripts/verify_b057_sli.py", b"wrong preimage\n")
            self.assertFalse(backlog_verify._preauthorized_b057_c0(candidate, mutated_trusted))

            self._write(trusted, "base-only.txt", b"candidate has stale base\n")
            self.assertFalse(backlog_verify._preauthorized_b057_c0(candidate, trusted))
            (trusted / "base-only.txt").unlink()

            missing = candidate / ".github/workflows/issue-2414-b057-sli.yml"
            missing.unlink()
            self.assertFalse(backlog_verify._preauthorized_b057_c0(candidate, trusted))
            self._write(candidate, ".github/workflows/issue-2414-b057-sli.yml", b"candidate workflow target\n")
            verifier = candidate / "scripts/verify_b057_sli.py"
            verifier.unlink()
            verifier.symlink_to("../missing.py")
            self.assertFalse(backlog_verify._preauthorized_b057_c0(candidate, trusted))

        trusted, candidate, preimages, targets = self._c0_fixture()
        for relative in (
            "scripts/backlog_verify.py",
            "scripts/verify_backlog_wp_ledger.py",
            "scripts/backlog_ledger_successor.py",
            "scripts/backlog_ledger_contracts.py",
        ):
            self._write(trusted, relative, b"trusted control\n")
            self._write(candidate, relative, b"trusted control\n")
        self._write(candidate, "scripts/backlog_verify.py", b"candidate policy mutation\n")
        items = [self.item("B-057", verify="python3 scripts/verify_b057_sli.py")]
        with patch.object(backlog_verify, "B057_C0_PREIMAGES", preimages), patch.object(
            backlog_verify, "B057_C0_TARGETS", targets
        ):
            with self.assertRaisesRegex(RuntimeError, "scripts/backlog_verify.py"):
                backlog_verify.check_candidate_controls(candidate, trusted, items)

    def test_workflow_uses_base_control_and_credentialless_data_checkouts(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "backlog-verify.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request_target:", workflow)
        self.assertNotIn("\n  pull_request:\n", workflow)
        self.assertIn("  verify:\n    runs-on: ubuntu-24.04", workflow)
        self.assertIn('    env:\n      PYTHONDONTWRITEBYTECODE: "1"', workflow)
        self.assertIn(
            "  trusted_semantic:\n"
            "    if: github.event_name == 'push' || github.event_name == 'schedule'\n"
            "    runs-on: ubuntu-24.04",
            workflow,
        )
        self.assertGreaterEqual(workflow.count("persist-credentials: false"), 2)
        self.assertIn("github.event.pull_request.head.sha || github.sha", workflow)
        self.assertIn("github.event.pull_request.base.sha || github.sha", workflow)
        self.assertNotIn("github.event.pull_request.head.ref", workflow)
        self.assertNotIn("github.event.pull_request.base.ref", workflow)
        self.assertEqual(workflow.count("GH_TOKEN:"), 1)
        self.assertIn("vulnerability-alerts: read", workflow)
        self.assertIn("--trusted-semantic --auth-only", workflow)
        self.assertIn("--trusted-semantic --exclude-auth-checks", workflow)
        self.assertIn("path: _candidate", workflow)
        self.assertIn("path: _base", workflow)
        self.assertIn("working-directory: _base", workflow)
        self.assertIn("--candidate-file", workflow)
        self.assertIn("--trusted-file", workflow)
        self.assertIn("--trusted-semantic", workflow)
        self.assertIn("if: github.event_name == 'push' || github.event_name == 'schedule'", workflow)

    @staticmethod
    def item(item_id: str, *, status: str = "open", verify: str = '"true"', owner: str = "tl") -> backlog_verify.Item:
        return backlog_verify.Item(
            raw={
                "id": item_id,
                "repo": "corelink-server",
                "owner": owner,
                "status": status,
                "verify": verify,
                "verify-means": "proof",
                "last-verified": "2026-08-23",
            },
            line=1,
            id=item_id,
        )

    def test_new_id_must_be_open_but_open_implementation_id_is_allowed(self) -> None:
        base = [self.item("B-001")]
        self.assertEqual(
            backlog_verify.validate_candidate_transitions(
                [self.item("B-001"), self.item("B-002")], base, dt.date(2026, 8, 23)
            ),
            [],
        )
        errors = backlog_verify.validate_candidate_transitions(
            [self.item("B-001"), self.item("B-002", status="done")],
            base,
            dt.date(2026, 8, 23),
        )
        self.assertTrue(any("new item B-002 must start status: open" in error for error in errors))

    def test_block_scalar_verify_and_field_status_manipulation_are_rejected(self) -> None:
        base = [self.item("B-001", status="open", verify="python3 scripts/verify.py\n")]
        candidate = [self.item("B-001", status="done", verify="python3 scripts/verify.py\n# mutation\n")]
        errors = backlog_verify.validate_candidate_transitions(
            candidate, base, dt.date(2026, 8, 23)
        )
        self.assertTrue(any("immutable field 'verify' changed" in error for error in errors))
        self.assertFalse(any("status transition" in error for error in errors))
        errors = backlog_verify.validate_candidate_transitions(
            [self.item("B-001", status="open", owner="owner")],
            base,
            dt.date(2026, 8, 23),
        )
        self.assertTrue(any("owner may change" in error for error in errors))

    def test_verify_means_can_change_only_with_status_transition(self) -> None:
        base = self.item("B-373", status="open")
        changed = self.item("B-373", status="done")
        changed.raw["verify-means"] = "done — authenticated post-merge live zero"
        self.assertEqual(
            backlog_verify.validate_candidate_transitions([changed], [base], dt.date(2026, 9, 12)),
            [],
        )
        unchanged_status = self.item("B-373", status="open")
        unchanged_status.raw["verify-means"] = changed.raw["verify-means"]
        errors = backlog_verify.validate_candidate_transitions(
            [unchanged_status], [base], dt.date(2026, 9, 12)
        )
        self.assertTrue(any("verify-means may change only with a status transition" in error for error in errors))
        changed.raw["verify"] = "true"
        errors = backlog_verify.validate_candidate_transitions([changed], [base], dt.date(2026, 9, 12))
        self.assertTrue(any("immutable field 'verify' changed" in error for error in errors))

    def test_successor_proof_update_does_not_authorize_verifier_commands(self) -> None:
        base = self.item("B-089", verify="python3 scripts/verify_b089_sla_credits.py\n")
        candidate = self.item("B-089", verify=base.raw["verify"])
        candidate.raw["verify-means"] = "new evidence readback"
        self.assertTrue(
            any("verify-means may change only" in error for error in
                backlog_verify.validate_candidate_transitions(
                    [candidate], [base], dt.date(2026, 9, 12), successor_mode=True,
                ))
        )
        candidate.raw["verify"] += "python3 scripts/evil.py\n"
        errors = backlog_verify.validate_candidate_transitions(
            [candidate], [base], dt.date(2026, 9, 12), successor_mode=True,
        )
        self.assertTrue(any("immutable field 'verify' changed" in error for error in errors))
        candidate.raw["verify"] = (
            "python3 scripts/verify_b089_sla_credits.py && "
            "python3 -S scripts/verify_owner_action_packets.py --id B-089"
        )
        self.assertEqual(
            [error for error in backlog_verify.validate_candidate_transitions(
                [candidate], [base], dt.date(2026, 9, 12), successor_mode=True,
            ) if "verify-means" not in error],
            ["B-089: immutable field 'verify' changed"],
        )
        self.assertEqual(
            backlog_verify.validate_candidate_transitions(
                [candidate], [base], dt.date(2026, 9, 12),
                successor_mode=True, allow_sprint3_rewrite=True,
            ),
            [],
        )
        candidate.raw["verify"] = (
            "python3 scripts/verify_b089_sla_credits.py\n"
            "python3 -S scripts/verify_owner_action_packets.py --id B-089\n"
        )
        errors = backlog_verify.validate_candidate_transitions(
            [candidate], [base], dt.date(2026, 9, 12),
            successor_mode=True, allow_sprint3_rewrite=True,
        )
        self.assertTrue(any("immutable field 'verify' changed" in error for error in errors))

    def test_open_owner_approval_cannot_be_waived_without_exact_exception(self) -> None:
        base = self.item("B-065", verify="manual")
        base.raw["verify-means"] = "owner must approve"
        candidate = self.item("B-065", verify="manual")
        candidate.raw["verify-means"] = "no owner approval needed"
        errors = backlog_verify.validate_candidate_transitions(
            [candidate], [base], dt.date(2026, 9, 12), successor_mode=True,
        )
        self.assertTrue(any("verify-means may change only" in error for error in errors))

    def test_b089_conjunction_preserves_first_command_failure(self) -> None:
        self.assertNotEqual(backlog_verify.run_verify("false && true", mode="trusted")[0], 0)
        self.assertEqual(backlog_verify.run_verify("false\ntrue", mode="trusted")[0], 0)

    def test_b154_exception_requires_reviewed_fail_closed_command(self) -> None:
        base = next(
            item for item in backlog_verify.parse((ROOT / "BACKLOG.md").read_text())
            if item.id == "B-154"
        )
        candidate = backlog_verify.Item(raw=dict(base.raw), line=base.line, id=base.id)
        candidate.raw["verify"] = (
            "python3 -S scripts/verify_owner_action_packets.py --id B-154 &&\n"
            "python3 -S scripts/verify_b154_instrument_claims.py --self-test\n"
        )
        self.assertEqual(backlog_verify.validate_candidate_transitions(
            [candidate], [base], dt.date(2026, 9, 13), allow_b154_reconciliation=True,
        ), [])
        candidate.raw["verify"] = candidate.raw["verify"].replace(" &&\n", "\n")
        errors = backlog_verify.validate_candidate_transitions(
            [candidate], [base], dt.date(2026, 9, 13), allow_b154_reconciliation=True,
        )
        self.assertTrue(any("immutable field 'verify' changed" in error for error in errors))
        self.assertNotEqual(backlog_verify.run_verify("false &&\ntrue", mode="trusted")[0], 0)

    def test_workflow_style_cli_imports_with_clean_pythonpath(self) -> None:
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        result = subprocess.run(
            [
                sys.executable, str(VERIFIER), "--help",
            ],
            cwd=ROOT, env=env, capture_output=True, text=True, check=False,
        )
        self.assertNotIn("ModuleNotFoundError", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_deleting_highest_base_id_is_rejected(self) -> None:
        errors = backlog_verify.validate_candidate_transitions(
            [self.item("B-001")],
            [self.item("B-001"), self.item("B-002")],
            dt.date(2026, 8, 23),
        )
        self.assertTrue(any("deleted BASE item(s): B-002" in error for error in errors))

    def test_dense_primary_ids_preserve_only_v0004_external_issue_identity(self) -> None:
        current = backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))
        self.assertEqual(backlog_verify.validate_dense_id_population(current), [])
        historic = next(item for item in current if item.id == "B-1630")
        self.assertEqual(backlog_verify.HISTORICAL_EXTERNAL_ISSUE_IDS["B-1630"], 1630)
        self.assertIn("PR #1923", historic.raw["verify-means"])
        self.assertIn("35700316381", historic.raw["verify-means"])

        synthetic = [self.item(f"B-{number:03d}") for number in range(1, 374)]
        synthetic.append(self.item("B-1630"))
        self.assertEqual(backlog_verify.validate_dense_id_population(synthetic), [])

        # The exception names one immutable external issue identity, not a sparse range.
        unapproved_outlier = [*synthetic, self.item("B-1631")]
        errors = backlog_verify.validate_dense_id_population(unapproved_outlier)
        self.assertTrue(
            any("B-374..B-1630" in error and "ids must be dense" in error for error in errors)
        )

        missing_middle = [item for item in current if item.id != "B-200"]
        errors = backlog_verify.validate_dense_id_population(missing_middle)
        self.assertTrue(any("B-200" in error and "ids must be dense" in error for error in errors))

        missing_external = [item for item in current if item.id != "B-1630"]
        errors = backlog_verify.validate_dense_id_population(missing_external)
        self.assertTrue(any("external issue identity B-1630" in error for error in errors))

    def test_candidate_cannot_delete_real_middle_id_or_v0004_external_identity(self) -> None:
        base = backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))
        for missing_id in ("B-200", "B-1630"):
            candidate = [item for item in base if item.id != missing_id]
            errors = backlog_verify.validate_candidate_transitions(
                candidate, base, dt.date(2026, 9, 24)
            )
            self.assertTrue(
                any(f"deleted BASE item(s): {missing_id}" in error for error in errors),
                f"deletion of {missing_id} must fail closed",
            )

    def test_mutable_workflow_ref_is_rejected_as_data(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        text = workflow.read_text(encoding="utf-8").replace(
            "github.event.pull_request.head.sha || github.sha",
            "github.event.pull_request.head.ref",
        )
        workflow.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "candidate workflow policy"):
            backlog_verify.validate_candidate_workflow(self.candidate)

    def test_concurrency_group_migration_is_monotonic_and_exact(self) -> None:
        legacy_group = "ci-backlog-verify-${{ github.event_name }}-${{ github.ref }}"
        pr_number_group = (
            "ci-backlog-verify-${{ github.event_name }}-"
            "${{ github.event.pull_request.number || github.ref }}"
        )
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        legacy_count = baseline.count(legacy_group)
        pr_number_count = baseline.count(pr_number_group)
        self.assertEqual(legacy_count + pr_number_count, 1)
        if pr_number_count == 1:
            baseline = baseline.replace(pr_number_group, legacy_group, 1)
        workflow.write_text(baseline, encoding="utf-8")
        trusted = Path(self.temp.name) / "trusted"
        trusted_workflow = trusted / ".github" / "workflows" / "backlog-verify.yml"
        trusted_workflow.parent.mkdir(parents=True)

        def set_group(root: Path, source: str, target: str) -> None:
            root_workflow = root / ".github" / "workflows" / "backlog-verify.yml"
            root_text = root_workflow.read_text(encoding="utf-8")
            self.assertEqual(root_text.count(source), 1)
            root_workflow.write_text(root_text.replace(source, target), encoding="utf-8")

        trusted_workflow.write_text(baseline, encoding="utf-8")
        # An old BASE admits the unchanged group during rollout or the exact PR-keyed group.
        backlog_verify.validate_candidate_workflow(self.candidate, trusted)
        set_group(self.candidate, legacy_group, pr_number_group)
        backlog_verify.validate_candidate_workflow(self.candidate, trusted)

        # Once BASE has the new group, the old value is no longer accepted.
        set_group(trusted, legacy_group, pr_number_group)
        backlog_verify.validate_candidate_workflow(self.candidate, trusted)
        set_group(self.candidate, pr_number_group, legacy_group)
        with self.assertRaisesRegex(RuntimeError, "unexpected concurrency settings"):
            backlog_verify.validate_candidate_workflow(self.candidate, trusted)

        # No third group or relaxed cancellation setting is admitted.
        set_group(self.candidate, legacy_group, "ci-backlog-verify-${{ github.ref }}")
        with self.assertRaisesRegex(RuntimeError, "unexpected concurrency settings"):
            backlog_verify.validate_candidate_workflow(self.candidate, trusted)
        set_group(self.candidate, "ci-backlog-verify-${{ github.ref }}", pr_number_group)
        candidate_text = workflow.read_text(encoding="utf-8")
        self.assertEqual(candidate_text.count("cancel-in-progress: true"), 1)
        workflow.write_text(
            candidate_text.replace("cancel-in-progress: true", "cancel-in-progress: false"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected concurrency settings"):
            backlog_verify.validate_candidate_workflow(self.candidate, trusted)
        workflow.write_text(baseline, encoding="utf-8")

    def test_both_jobs_require_the_approved_hosted_runner(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        backlog_verify.validate_candidate_workflow(self.candidate)

        trusted_start = baseline.index("  trusted_semantic:")
        trusted_job = baseline[trusted_start:]
        for runner in ("corelink", "ubuntu-latest", "self-hosted", "[self-hosted, linux]"):
            with self.subTest(verify_runner=runner):
                mutated = baseline.replace(
                    "  verify:\n    runs-on: ubuntu-24.04",
                    f"  verify:\n    runs-on: {runner}",
                    1,
                )
                workflow.write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "unexpected verify runner"):
                    backlog_verify.validate_candidate_workflow(self.candidate)

            with self.subTest(trusted_semantic_runner=runner):
                mutated_trusted = trusted_job.replace(
                    "    runs-on: ubuntu-24.04", f"    runs-on: {runner}", 1
                )
                self.assertNotEqual(mutated_trusted, trusted_job)
                workflow.write_text(baseline[:trusted_start] + mutated_trusted, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "unexpected trusted semantic runner"):
                    backlog_verify.validate_candidate_workflow(self.candidate)

        workflow.write_text(baseline, encoding="utf-8")

    def test_b314_dependency_and_trusted_step_shape_are_fail_closed(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        backlog_verify.validate_candidate_workflow(self.candidate)
        dependency_marker = "      - name: Install CI Python dependencies for B-314 tests"
        b314_marker = "      - name: Prove BASE B-314 owner-gate mutation teeth"
        semantic_marker = "      - name: Execute trusted main semantic checks"
        start = baseline.index(dependency_marker)
        end = baseline.index(semantic_marker, start)
        prefix, b314_steps, suffix = baseline[:start], baseline[start:end], baseline[end:]
        mutations = {
            "removed-dependency-and-tests": prefix + suffix,
            "wrong-dependency-working-directory": prefix + b314_steps.replace(
                "name: Install CI Python dependencies for B-314 tests\n        working-directory: _base",
                "name: Install CI Python dependencies for B-314 tests\n        working-directory: _candidate",
                1,
            ) + suffix,
            "dependency-from-candidate": prefix + b314_steps.replace(
                "-r requirements-ci.txt", "-r $GITHUB_WORKSPACE/_candidate/requirements-ci.txt", 1
            ) + suffix,
            "unverified-pytest-install": prefix + b314_steps.replace(
                ".venv/bin/python3 -m pytest --version", "true", 1
            ) + suffix,
            "wrong-test-working-directory": prefix + b314_steps.replace(
                b314_marker + "\n        working-directory: _base",
                b314_marker + "\n        working-directory: _candidate",
                1,
            ) + suffix,
            "weakened-self-test": prefix + b314_steps.replace(
                "python3 -S scripts/verify_b314_gdpr_sigstore.py --self-test",
                "python3 -S scripts/verify_b314_gdpr_sigstore.py",
                1,
            ) + suffix,
            "weakened-mutation-test": prefix + b314_steps.replace(
                "python3 -m pytest -q tests/test_verify_b314_gdpr_sigstore.py", "true", 1
            ) + suffix,
            "extra-shell-key": prefix + b314_steps + "        shell: bash\n" + suffix,
            "reordered": prefix + suffix + b314_steps,
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                workflow.write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "candidate workflow policy"):
                    backlog_verify.validate_candidate_workflow(self.candidate)
        workflow.write_text(baseline, encoding="utf-8")

    def test_workflow_rejects_inherited_and_step_environment_execution(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        backlog_verify.validate_candidate_workflow(self.candidate)
        b314_marker = "      - name: Prove BASE B-314 owner-gate mutation teeth"
        mutations = {
            "job-bytecode-env-removed": baseline.replace(
                '      PYTHONDONTWRITEBYTECODE: "1"\n', "", 1,
            ),
            "job-bytecode-env-wrong": baseline.replace(
                'PYTHONDONTWRITEBYTECODE: "1"', 'PYTHONDONTWRITEBYTECODE: "0"', 1,
            ),
            "job-bytecode-env-extra": baseline.replace(
                '      PYTHONDONTWRITEBYTECODE: "1"\n',
                '      PYTHONDONTWRITEBYTECODE: "1"\n      BASH_ENV: ${{ github.workspace }}/_candidate/evil.sh\n', 1,
            ),
            "root-env-bash-env": baseline.replace(
                "name: backlog-verify\n",
                "name: backlog-verify\nenv:\n  BASH_ENV: ${{ github.workspace }}/_candidate/evil.sh\n", 1,
            ),
            "root-default-shell": baseline.replace(
                "name: backlog-verify\n",
                "name: backlog-verify\ndefaults:\n  run:\n    shell: bash\n", 1,
            ),
            "job-env-bash-env": baseline.replace(
                '      PYTHONDONTWRITEBYTECODE: "1"\n',
                '      PYTHONDONTWRITEBYTECODE: "1"\n      BASH_ENV: ${{ github.workspace }}/_candidate/evil.sh\n', 1,
            ),
            "job-defaults": baseline.replace(
                "    timeout-minutes: 10\n",
                "    timeout-minutes: 10\n    defaults:\n      run:\n        working-directory: _candidate\n", 1,
            ),
            "job-container": baseline.replace(
                "    timeout-minutes: 10\n",
                "    timeout-minutes: 10\n    container: attacker-controlled-image\n", 1,
            ),
            "base-gate-env-bash-env": baseline.replace(
                "          TRUSTED_ROOT: ${{ github.workspace }}/_base\n",
                "          TRUSTED_ROOT: ${{ github.workspace }}/_base\n"
                "          BASH_ENV: ${{ github.workspace }}/_candidate/evil.sh\n", 1,
            ),
            "b314-step-env": baseline.replace(
                b314_marker + "\n",
                b314_marker + "\n        env:\n          BASH_ENV: ${{ github.workspace }}/_candidate/evil.sh\n", 1,
            ),
            "extra-pr-trigger": baseline.replace(
                "    paths: [\"**\"]\n  push:\n",
                "    paths: [\"**\"]\n    branches: [main]\n  push:\n", 1,
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(mutated, baseline)
                workflow.write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "candidate workflow policy"):
                    backlog_verify.validate_candidate_workflow(self.candidate)
        workflow.write_text(baseline, encoding="utf-8")

    def test_b046_trusted_step_shape_and_placement_are_fail_closed(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        backlog_verify.validate_candidate_workflow(self.candidate)
        marker = "      - name: Execute B-046 Object-Lock contract and mutation checks"
        b046_start = baseline.index(marker)
        prefix, b046_step = baseline[:b046_start], baseline[b046_start:]
        auth_marker = "      - name: Execute authenticated Dependabot semantic checks"
        auth_start = prefix.index(auth_marker)
        prefix_without_auth = prefix[:auth_start]
        auth_step = prefix[auth_start:]
        mutations = {
            "removed": prefix.rstrip() + "\n",
            "extra-if": prefix + b046_step.replace(
                "        working-directory: _base", "        if: github.event_name == 'workflow_dispatch'\n        working-directory: _base", 1),
            "wrong-working-directory": prefix + b046_step.replace(
                "working-directory: _base", "working-directory: _candidate", 1
            ),
            "reordered": prefix_without_auth + b046_step + auth_step,
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                workflow.write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "candidate workflow policy"):
                    backlog_verify.validate_candidate_workflow(self.candidate)
        workflow.write_text(baseline, encoding="utf-8")

    def test_alert_token_is_confined_to_exact_trusted_verifiers(self) -> None:
        result = subprocess.CompletedProcess([], 0, "ok", "")
        commands = backlog_verify.AUTH_VERIFY_COMMANDS
        with patch.dict(os.environ, {
            "GH_TOKEN": "test-only-alert-token", "GITHUB_TOKEN": "other-token",
            "ACTIONS_RUNTIME_TOKEN": "runtime-token", "BASH_ENV": "/tmp/evil",
        }), patch.object(backlog_verify.subprocess, "run", return_value=result) as run:
            for item_id, command in commands.items():
                backlog_verify.run_verify(command, mode="trusted", item_id=item_id)
                env = run.call_args.kwargs["env"]
                self.assertEqual(env.get("GH_TOKEN"), "test-only-alert-token")
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("ACTIONS_RUNTIME_TOKEN", env)
                self.assertNotIn("BASH_ENV", env)
            for item_id, command in (
                ("B-001", "true"),
                ("B-028", commands["B-028"] + " && env"),
                ("B-373", "true"),
            ):
                backlog_verify.run_verify(command, mode="trusted", item_id=item_id)
                self.assertNotIn("GH_TOKEN", run.call_args.kwargs["env"])
            count = run.call_count
            backlog_verify.run_verify(commands["B-028"], mode="candidate", item_id="B-028")
            self.assertEqual(run.call_count, count)

    def test_split_semantic_modes_reject_single_id_shortcut(self) -> None:
        for mode in ("--auth-only", "--exclude-auth-checks"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, str(VERIFIER), "--trusted-semantic", mode, "--id", "B-028"],
                    cwd=ROOT, capture_output=True, text=True,
                    env={**os.environ, "GITHUB_EVENT_NAME": "push"}, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("full partition", result.stderr)

    def test_workflow_rejects_token_grants_or_candidate_exposure(self) -> None:
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        baseline = workflow.read_text(encoding="utf-8")
        mutations = {
            "workflow-scope-alerts": baseline.replace(
                "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  vulnerability-alerts: read\n", 1),
            "pr-step-token": baseline.replace(
                "          TRUSTED_ROOT: ${{ github.workspace }}/_base\n",
                "          TRUSTED_ROOT: ${{ github.workspace }}/_base\n          GH_TOKEN: ${{ github.token }}\n", 1),
            "trusted-candidate-checkout": baseline.replace(
                "      - name: Execute trusted main semantic checks\n",
                "      - name: Checkout candidate again\n        run: true\n"
                "      - name: Execute trusted main semantic checks\n", 1),
            "extra-token-env": baseline.replace(
                "      - name: Execute trusted main semantic checks\n",
                "      - name: Execute trusted main semantic checks\n        env:\n          GH_TOKEN: ${{ github.token }}\n", 1),
            "wrong-auth-command": baseline.replace(
                "--trusted-semantic --auth-only", "--trusted-semantic", 1),
            "credential-persistence": baseline.replace(
                "          fetch-depth: 0\n          persist-credentials: false",
                "          fetch-depth: 0\n          persist-credentials: true", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(mutated, baseline)
                workflow.write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "candidate workflow policy"):
                    backlog_verify.validate_candidate_workflow(self.candidate)
        workflow.write_text(baseline, encoding="utf-8")

    def test_transitive_control_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trusted = Path(directory) / "trusted"
            candidate = Path(directory) / "candidate"
            (trusted / "scripts").mkdir(parents=True)
            (candidate / "scripts").mkdir(parents=True)
            for control in (
                "backlog_verify.py", "verify_backlog_wp_ledger.py",
                "backlog_ledger_successor.py", "backlog_ledger_contracts.py",
            ):
                shutil.copy2(ROOT / "scripts" / control, trusted / "scripts" / control)
                shutil.copy2(ROOT / "scripts" / control, candidate / "scripts" / control)
            (trusted / "scripts" / "check.py").write_text("from scripts import helper\n", encoding="utf-8")
            (trusted / "scripts" / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            for name in ("check.py", "helper.py"):
                shutil.copy2(trusted / "scripts" / name, candidate / "scripts" / name)
            items = [self.item("B-001", verify="python3 scripts/check.py")]
            candidate.joinpath("scripts/helper.py").write_text("VALUE = 2\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "helper.py"):
                backlog_verify.check_candidate_controls(candidate, trusted, items)

    def test_dynamic_import_control_mutation_is_rejected(self) -> None:
        trusted_items = backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))
        controls = backlog_verify._candidate_control_paths(ROOT, trusted_items)
        self.assertIn("scripts/b155_backlog_grep_parser.py", controls)
        parser = self.candidate / "scripts" / "b155_backlog_grep_parser.py"
        parser.write_text(parser.read_text(encoding="utf-8") + "\n# candidate mutation\n", encoding="utf-8")

        result = self.run_gate()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("b155_backlog_grep_parser.py", result.stdout + result.stderr)

    def test_trusted_semantic_mode_reproduces_stale_b001(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VERIFIER), "--trusted-semantic", "--id", "B-001", "--today", "2026-09-08"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "GITHUB_EVENT_NAME": "push"},
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("STALE", result.stdout + result.stderr)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.candidate = Path(self.temp.name) / "candidate"
        self.candidate.mkdir()
        shutil.copy2(ROOT / "BACKLOG.md", self.candidate / "BACKLOG.md")
        trusted_items = backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))
        controls = backlog_verify._candidate_control_paths(ROOT, trusted_items)
        for relative in controls:
            source = ROOT / relative
            target = self.candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        # The BASE ledger gate also compares the immutable data preimage, even
        # when a test mutates only one BACKLOG declaration.
        ledger_data = [
            "docs/campaigns/remediation/BACKLOG-WP-LEDGER.md",
            "docs/campaigns/remediation/backlog-ledger-snapshot.json",
            "docs/campaigns/remediation/backlog-ledger-snapshot-b373-postmerge.json",
            "docs/campaigns/remediation/work-packages/B001-B045.md",
            "docs/campaigns/remediation/work-packages/B046-B090.md",
            "docs/campaigns/remediation/work-packages/B091-B130.md",
            "docs/campaigns/remediation/work-packages/B131-B167.md",
        ]
        for relative in ledger_data:
            target = self.candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        workflow = self.candidate / ".github" / "workflows" / "backlog-verify.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / ".github" / "workflows" / "backlog-verify.yml", workflow)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--candidate-file",
                str(self.candidate / "BACKLOG.md"),
                "--trusted-file",
                str(ROOT / "BACKLOG.md"),
                "--candidate-root",
                str(self.candidate),
                "--trusted-root",
                str(ROOT),
                "--today",
                "2026-09-08",
                "--id",
                "B-044",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_mutated_candidate_verify_string_cannot_execute_or_green(self) -> None:
        text = (self.candidate / "BACKLOG.md").read_text(encoding="utf-8")
        marker = Path(self.temp.name) / "candidate-verify-executed"
        payload = (
            'python3 -c "from pathlib import Path; '
            f"Path({str(marker)!r}).write_text('pwned')"
            '"'
        )
        mutated, count = re.subn(
            r"(### B-044\b.*?^verify:) .*?$",
            rf"\1 {payload}",
            text,
            count=1,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertEqual(count, 1)
        (self.candidate / "BACKLOG.md").write_text(mutated, encoding="utf-8")

        result = self.run_gate()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), "candidate verify payload was executed")
        self.assertIn("candidate must append exactly one next successor snapshot", result.stdout + result.stderr)

    def test_mutated_candidate_verifier_cannot_green(self) -> None:
        verifier = self.candidate / "scripts" / "verify_b044_orphan_teardown_wp.py"
        self.assertTrue(verifier.is_file())
        verifier.write_text(verifier.read_text(encoding="utf-8") + "\n# candidate mutation\n", encoding="utf-8")

        result = self.run_gate()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("mutated trusted backlog control", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
