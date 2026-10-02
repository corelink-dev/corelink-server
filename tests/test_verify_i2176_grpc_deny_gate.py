"""Adversarial regressions for the protected-base #2176 verifier."""

from __future__ import annotations

import ast
import contextlib
import sys
import unittest
from pathlib import Path
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2176_grpc_deny_gate as verify


class P0WaveClassifierTests(unittest.TestCase):
    def test_two_trusted_checkers_have_identical_i1652_pin_map(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "scripts/backlog_verify.py").read_text(
            encoding="utf-8"
        )
        definitions = [
            node for node in ast.parse(source).body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "I1652_DELIVERY_PINS"
        ]
        self.assertEqual(len(definitions), 1)
        backlog_pins = ast.literal_eval(definitions[0].value)
        self.assertEqual(
            {str(path): pins for path, pins in verify.WAVE_GROUPS["i1652"].items()},
            backlog_pins,
        )

    def test_four_reviewed_groups_are_finite_and_path_disjoint(self) -> None:
        expected = {"i1652": 17, "i1648": 4, "i1700": 17, "i2565": 8}
        self.assertEqual(set(verify.WAVE_GROUPS), set(expected))
        seen: set[Path] = set()
        for name, pins in verify.WAVE_GROUPS.items():
            self.assertEqual(len(pins), expected[name])
            self.assertTrue(seen.isdisjoint(pins), name)
            seen.update(pins)
            for old_pin, new_pin in pins.values():
                for pin in (old_pin, new_pin):
                    if pin is not None:
                        mode, digest = pin
                        self.assertIn(mode, (0o644, 0o755))
                        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(len(seen), 46)
        self.assertEqual(len(verify.WAVE_BASE_CONTROLS), 54)

    def test_p0_matrix_is_pinned_separately_from_checker_controls(self) -> None:
        matrix = Path(__file__).resolve().parents[1] / "docs/internal/secrets-checklist.md"
        self.assertEqual(
            hashlib.sha256(matrix.read_bytes()).hexdigest(), verify.WAVE_MATRIX_SHA256
        )
        text = matrix.read_text(encoding="utf-8")
        self.assertEqual(sum(line.startswith("| 315 |") for line in text.splitlines()), 1)
        for name in (
            "B072_STAGING_CF_WORKERS_TOKEN",
            "B072_STAGING_D1_WRITE_TOKEN",
            "B072_STAGING_CF_ROUTE_READ_TOKEN",
        ):
            self.assertEqual(text.count(f"`{name}`"), 1)

    def _wallet_route_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        trusted, candidate = root / "trusted", root / "candidate"
        source_root = Path(__file__).resolve().parents[1]
        for relative in verify.WALLET_ROUTE_PATHS:
            for target in (trusted, candidate):
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((source_root / relative).read_bytes())
                path.chmod(0o644)
        for target in (trusted, candidate):
            actionlint = target / ".actionlint.yaml"
            actionlint.write_text("protected\n")
            link = target / ".github/actionlint.yaml"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("../.actionlint.yaml")
            self._normalize_old_wallet_route_fixture(target)
        return trusted, candidate

    def _normalize_old_wallet_route_fixture(self, root: Path) -> None:
        """Build the explicit pre-route fixture even when tests run post-merge."""
        def replace_fixture(path: Path, content: bytes) -> None:
            mode = path.lstat().st_mode & 0o777
            path.unlink()
            path.write_bytes(content)
            path.chmod(mode)

        live_path = root / verify.WALLET_ROUTE_LIVE_PATH
        live = live_path.read_bytes()
        base_live_sha = verify.WAVE_GROUPS["i2565"][verify.WALLET_ROUTE_LIVE_PATH][1][1]
        live_sha = hashlib.sha256(live).hexdigest()
        if live_sha == verify.WALLET_ROUTE_TRANSFORMED_LIVE_SHA256:
            module = verify.WALLET_ROUTE_LIVE_MODULE
            end_marker = verify.WALLET_ROUTE_LIVE_END
            start = live.index(module)
            end = live.index(end_marker, start)
            region_end = end + len(end_marker) - len(b"\n\nimpl Drop for HarnessCleanup")
            region = live[start:region_end]
            marker = b'"/stripe-prod-test'
            self.assertEqual(region.count(marker), verify.WALLET_ROUTE_LIVE_LITERAL_COUNT)
            restored = live[:start] + region.replace(marker, b'"/_wallet/proxy/stripe-prod-test') + live[region_end:]
            self.assertEqual(hashlib.sha256(restored).hexdigest(), base_live_sha)
            replace_fixture(live_path, restored)
        else:
            self.assertEqual(live_sha, base_live_sha, "unexpected wallet live source in route fixture")

        verifier_path = root / verify.WALLET_ROUTE_VERIFIER_PATH
        verifier = verifier_path.read_bytes()
        base_verifier_sha = verify.WAVE_GROUPS["i2565"][verify.WALLET_ROUTE_VERIFIER_PATH][1][1]
        successor_sha = verify.WAVE_GROUP_SUCCESSOR_PINS["i2565"][verify.WALLET_ROUTE_VERIFIER_PATH][1]
        verifier_sha = hashlib.sha256(verifier).hexdigest()
        if verifier_sha in (verify.WALLET_ROUTE_TRANSFORMED_VERIFIER_SHA256, successor_sha):
            self.assertEqual(verifier.count(verify.WALLET_ROUTE_VERIFIER_KEY), 1)
            start = verifier.index(verify.WALLET_ROUTE_VERIFIER_KEY) + len(verify.WALLET_ROUTE_VERIFIER_KEY)
            end = start + 64
            target_live_sha = verify.WALLET_ROUTE_TRANSFORMED_LIVE_SHA256.encode("ascii")
            base_live_sha_bytes = base_live_sha.encode("ascii")
            self.assertEqual(verifier[start:end], target_live_sha)
            restored = verifier[:start] + base_live_sha_bytes + verifier[end:]
            if verifier_sha == verify.WALLET_ROUTE_TRANSFORMED_VERIFIER_SHA256:
                self.assertEqual(hashlib.sha256(restored).hexdigest(), base_verifier_sha)
            else:
                self._pin_derived_pre_route_verifier(hashlib.sha256(restored).hexdigest())
            replace_fixture(verifier_path, restored)
        else:
            self.assertEqual(verifier_sha, base_verifier_sha, "unexpected B068 source in route fixture")

    def _pin_derived_pre_route_verifier(self, digest: str) -> None:
        """Stand in for the historical pre-route verifier in fixture tests only.

        The pre-route B068 verifier (the 377bcacb #2565 target) predates the
        #2800/#2811 edits and is not in this tree. The exact inverse of the
        route transform applied to the reviewed successor replaces it, so the
        transform is exercised on today's bytes. Production pins stay
        historical; the patch is undone when the test ends.
        """
        group = verify.WAVE_GROUPS["i2565"]
        old_pin, _new_pin = group[verify.WALLET_ROUTE_VERIFIER_PATH]
        patcher = patch.dict(group, {verify.WALLET_ROUTE_VERIFIER_PATH: (old_pin, (0o644, digest))})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _wallet_route_classifier_patches(self):
        states = {name: "new" for name in ("i1652", "i1648", "i1700", "i2565")}
        return (
            patch.object(verify, "_wave_state", return_value=states),
            patch.object(verify, "_wave_group_state", return_value="new"),
            patch.object(verify, "_wave_common_controls_equal"),
            patch.object(verify, "_wave_pin_matches", return_value=True),
        )

    def test_wallet_route_accepts_consumed_base_self_and_ordinary_client_maintenance(self) -> None:
        trusted, candidate = self._wallet_route_fixture()
        with self._wallet_route_classifier_patches()[0], self._wallet_route_classifier_patches()[1], self._wallet_route_classifier_patches()[2], self._wallet_route_classifier_patches()[3]:
            with patch.object(verify, "_wave_controls_match", return_value=True):
                self.assertTrue(verify.validate_wave(trusted, trusted, set()))
            ordinary = next(iter(verify.WALLET_ROUTE_ORDINARY_PATHS))
            target = candidate / ordinary
            target.write_bytes(target.read_bytes() + b"\n// reviewed ordinary maintenance\n")
            changed = verify.changed_paths(trusted, candidate)
            self.assertEqual(changed, {ordinary})
            with patch.object(verify, "_wave_controls_match", return_value=True):
                self.assertTrue(verify.validate_wave(candidate, trusted, changed))

    def test_wallet_route_real_tree_transformed_base_self_and_second_maintenance(self) -> None:
        # Formerly skipped whenever the tree was not the pinned baseline, which
        # hid that every BASE was refused. A non-baseline tree now fails here.
        source_root = Path(__file__).resolve().parents[1]
        required = set(verify.WALLET_ROUTE_PATHS) | {Path("docs/internal/secrets-checklist.md")}
        required.update(path for path, pin in verify.WAVE_BASE_CONTROLS.items() if pin is not None)
        missing = sorted(str(relative) for relative in required if not (source_root / relative).exists())
        self.assertEqual(missing, [], "complete protected-base source tree is unavailable")
        self.assertTrue(verify._wave_controls_match(source_root), "source tree is not the reviewed baseline")
        verify._wallet_route_base_states(source_root)

        def hardlink_tree(source: Path, destination: Path) -> None:
            ignored = shutil.ignore_patterns(".git", "target", "node_modules", ".venv", "__pycache__")
            shutil.copytree(source, destination, symlinks=True, copy_function=os.link, ignore=ignored)

        def replace_bytes(root: Path, relative: Path, content: bytes) -> None:
            target = root / relative
            mode = target.lstat().st_mode & 0o777
            target.unlink()
            target.write_bytes(content)
            target.chmod(mode)

        with tempfile.TemporaryDirectory() as directory:
            trusted = Path(directory) / "trusted"
            hardlink_tree(source_root, trusted)
            self._normalize_old_wallet_route_fixture(trusted)
            base_live, transformed_live = verify._wallet_route_expected_live(trusted)
            self.assertNotEqual(base_live, transformed_live)
            transformed_verifier = verify._wallet_route_expected_verifier(trusted, transformed_live)
            replace_bytes(trusted, verify.WALLET_ROUTE_LIVE_PATH, transformed_live)
            replace_bytes(trusted, verify.WALLET_ROUTE_VERIFIER_PATH, transformed_verifier)
            for relative in verify.WALLET_ROUTE_ORDINARY_PATHS:
                path = trusted / relative
                replace_bytes(trusted, relative, path.read_bytes() + b"\n// trusted wallet-route maintenance\n")

            self.assertTrue(verify.validate_wave(trusted, trusted, set()))
            candidate = Path(directory) / "candidate"
            hardlink_tree(trusted, candidate)
            client = candidate / "crates/corelink-stripe-real/src/client.rs"
            replace_bytes(
                candidate,
                Path("crates/corelink-stripe-real/src/client.rs"),
                client.read_bytes() + b"\n// second ordinary maintenance change\n",
            )
            changes = verify.changed_paths(trusted, candidate)
            self.assertEqual(changes, {Path("crates/corelink-stripe-real/src/client.rs")})
            self.assertTrue(verify.validate_wave(candidate, trusted, changes))

    def test_wallet_route_accepts_exact_privileged_pair_only_with_all_three_ordinary_paths(self) -> None:
        trusted, candidate = self._wallet_route_fixture()
        base_live, transformed_live = verify._wallet_route_expected_live(trusted)
        self.assertEqual(base_live.count(verify.WALLET_ROUTE_LITERAL), 11)
        (candidate / verify.WALLET_ROUTE_LIVE_PATH).write_bytes(transformed_live)
        (candidate / verify.WALLET_ROUTE_VERIFIER_PATH).write_bytes(
            verify._wallet_route_expected_verifier(trusted, transformed_live)
        )
        for relative in verify.WALLET_ROUTE_ORDINARY_PATHS:
            target = candidate / relative
            original = target.read_bytes()
            target.write_bytes(original + b"\n// ordinary wallet-route source update\n")
        with self._wallet_route_classifier_patches()[0], self._wallet_route_classifier_patches()[1], self._wallet_route_classifier_patches()[2], self._wallet_route_classifier_patches()[3]:
            changed = verify.changed_paths(trusted, candidate)
            self.assertEqual(changed, set(verify.WALLET_ROUTE_PATHS))
            with patch.object(verify, "_wave_controls_match", return_value=True):
                self.assertTrue(verify.validate_wave(candidate, trusted, changed))

    def test_wallet_route_rejects_partial_live_transform_or_unpaired_verifier(self) -> None:
        for case in ("partial", "unpaired", "altered-live", "verifier-drift", "wrong-digest"):
            trusted, candidate = self._wallet_route_fixture()
            base_live, transformed_live = verify._wallet_route_expected_live(trusted)
            if case == "partial":
                actual_live = base_live.replace(verify.WALLET_ROUTE_LITERAL, b"", 1)
                (candidate / verify.WALLET_ROUTE_LIVE_PATH).write_bytes(actual_live)
            elif case == "unpaired":
                (candidate / verify.WALLET_ROUTE_LIVE_PATH).write_bytes(transformed_live)
                for relative in verify.WALLET_ROUTE_ORDINARY_PATHS:
                    target = candidate / relative
                    target.write_bytes(target.read_bytes() + b"\n")
            elif case == "altered-live":
                actual_live = transformed_live.replace(b"customer_id", b"session_id", 1)
                (candidate / verify.WALLET_ROUTE_LIVE_PATH).write_bytes(actual_live)
                for relative in verify.WALLET_ROUTE_ORDINARY_PATHS:
                    target = candidate / relative
                    target.write_bytes(target.read_bytes() + b"\n")
            elif case == "verifier-drift":
                verifier = candidate / verify.WALLET_ROUTE_VERIFIER_PATH
                verifier.write_bytes(verifier.read_bytes() + b"\n# candidate verifier change\n")
            else:
                (candidate / verify.WALLET_ROUTE_LIVE_PATH).write_bytes(transformed_live)
                for relative in verify.WALLET_ROUTE_ORDINARY_PATHS:
                    target = candidate / relative
                    target.write_bytes(target.read_bytes() + b"\n")
                verifier = verify._wallet_route_expected_verifier(trusted, transformed_live)
                start = verifier.index(verify.WALLET_ROUTE_VERIFIER_KEY) + len(verify.WALLET_ROUTE_VERIFIER_KEY)
                verifier = verifier[:start] + b"0" * 64 + verifier[start + 64:]
                (candidate / verify.WALLET_ROUTE_VERIFIER_PATH).write_bytes(verifier)
            with self._wallet_route_classifier_patches()[0], self._wallet_route_classifier_patches()[1], self._wallet_route_classifier_patches()[2], self._wallet_route_classifier_patches()[3]:
                with patch.object(verify, "_wave_controls_match", return_value=True):
                    with self.assertRaises(verify.ContractError, msg=case):
                        verify.validate_wave(candidate, trusted, verify.changed_paths(trusted, candidate))

    def test_wallet_route_triggers_both_protected_entrypoints_and_manual_proof(self) -> None:
        root = Path(__file__).resolve().parents[1]
        paths = (
            "crates/corelink-stripe-real/src/client.rs",
            "crates/corelink-stripe-real/src/client/tests_part_01.rs",
            "crates/corelink-stripe-real/tests/live_integration.rs",
            "crates/corelink-stripe-real/tests/wallet_broker_proxy.rs",
            "scripts/verify_real_ignored_harnesses.py",
        )
        protected = (root / ".github/workflows/issue-2176-grpc-deny-gate.yml").read_text()
        supplemental = (root / ".github/workflows/issue-2574-staging-grpc-diagnostic.yml").read_text()
        for workflow in (protected, supplemental):
            for relative in paths:
                self.assertIn(f'"{relative}"', workflow)
        self.assertIn("pull_request_target:", protected)
        self.assertNotIn("workflow_dispatch:", protected)
        self.assertIn('ref: ${{ github.event.pull_request.base.sha }}', protected)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha }}', protected)
        self.assertIn("trusted-base/scripts/verify_i2176_grpc_deny_gate.py", protected)
        self.assertIn("trusted-base/scripts/verify_i2574_grpc_diagnostic_policy.py", protected)
        self.assertIn("python3 -B -S trusted-base/scripts/verify_i2176_grpc_deny_gate.py", protected)
        self.assertIn("python3 -B -S trusted-base/scripts/verify_i2574_grpc_diagnostic_policy.py", protected)
        self.assertIn("python3 -B -S -m unittest", protected)
        self.assertIn("python3 -B -S -m unittest", supplemental)

    def test_wallet_route_rejects_other_delivery_wave_or_unconsumed_2565_base(self) -> None:
        trusted, candidate = self._wallet_route_fixture()
        ordinary = next(iter(verify.WALLET_ROUTE_ORDINARY_PATHS))
        target = candidate / ordinary
        target.write_bytes(target.read_bytes() + b"\n")
        with self._wallet_route_classifier_patches()[0], self._wallet_route_classifier_patches()[1], self._wallet_route_classifier_patches()[2], self._wallet_route_classifier_patches()[3]:
            with patch.object(verify, "_wave_group_state", side_effect=lambda root, group: "old" if root == candidate and group == "i1700" else "new"):
                with self.assertRaises(verify.ContractError):
                    verify.validate_wallet_route_candidate(trusted, candidate)
            def unconsumed_pin(root: Path, relative: Path, pin: tuple[int, str] | None) -> bool:
                if relative == Path(".github/workflows/issue-1650-real-integration-contract.yml"):
                    return False
                return verify.matches_pinned_file(root, relative, pin)
            with patch.object(verify, "_wave_pin_matches", side_effect=unconsumed_pin):
                with self.assertRaises(verify.ContractError):
                    verify.validate_wallet_route_candidate(trusted, candidate)

    def test_wallet_route_rejects_foreign_path_mode_and_symlink(self) -> None:
        for mutation in ("foreign", "mode", "symlink"):
            trusted, candidate = self._wallet_route_fixture()
            ordinary = next(iter(verify.WALLET_ROUTE_ORDINARY_PATHS))
            target = candidate / ordinary
            if mutation == "foreign":
                extra = candidate / "unexpected.txt"
                extra.write_text("extra")
                target.write_bytes(target.read_bytes() + b"\n")
            elif mutation == "mode":
                target.chmod(0o755)
            else:
                target.unlink()
                target.symlink_to(trusted / ordinary)
            with self._wallet_route_classifier_patches()[0], self._wallet_route_classifier_patches()[1], self._wallet_route_classifier_patches()[2], self._wallet_route_classifier_patches()[3]:
                with self.assertRaises(verify.ContractError, msg=mutation):
                    verify.validate_wallet_route_candidate(trusted, candidate)

    def test_i1652_full_guard_transition_is_atomic_and_monotonic(self) -> None:
        paths = verify.WAVE_GROUPS["i1652"]
        self.assertEqual(len(paths), 17)
        self.assertIn(Path("scripts/verify_b072_receiver.py"), paths)
        self.assertIn(Path("scripts/test_b072_receiver_mutations.py"), paths)
        with tempfile.TemporaryDirectory() as directory:
            trusted, candidate = Path(directory) / "trusted", Path(directory) / "candidate"
            trusted.mkdir()
            candidate.mkdir()
            fake_pins = {}
            for relative, (old_pin, _new_pin) in paths.items():
                old = None if old_pin is None else f"old:{relative}\n".encode()
                new = f"new:{relative}\n".encode()
                if old is not None:
                    target = trusted / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(old)
                target = candidate / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(new)
                fake_pins[relative] = (
                    None if old is None else (0o644, hashlib.sha256(old).hexdigest()),
                    (0o644, hashlib.sha256(new).hexdigest()),
                )
            changed = set(paths)
            with patch.object(verify, "WAVE_GROUPS", {"i1652": fake_pins}), patch.object(
                verify, "_wave_common_controls_equal"
            ), patch.object(verify, "_wave_controls_match", return_value=True):
                self.assertTrue(verify.validate_wave(trusted, trusted, set()))
                self.assertTrue(verify.validate_wave(candidate, trusted, changed))
                with self.assertRaises(verify.ContractError):
                    verify.validate_wave(trusted, candidate, changed)
                with self.assertRaises(verify.ContractError):
                    verify.validate_wave(candidate, trusted, changed - {Path("scripts/verify_b072_receiver.py")})
                with self.assertRaises(verify.ContractError):
                    verify.validate_wave(candidate, trusted, changed | {Path("unapproved.txt")})
                guard = candidate / "scripts/verify_b072_receiver.py"
                original = guard.read_bytes()
                guard.write_bytes(b"arbitrary verifier\n")
                with self.assertRaises(verify.ContractError):
                    verify.validate_wave(candidate, trusted, changed)
                guard.write_bytes(original)
                guard.chmod(0o755)
                with self.assertRaises(verify.ContractError):
                    verify.validate_wave(candidate, trusted, changed)


# WAVE_BASE_CONTROLS and the P0 matrix pin as they stood on main da2d3f8db,
# before the #2868 re-baseline. History for the ledger check only.
PRE_REBASELINE_CONTROLS = {
    '.github/workflows/container-build-push-prod.yml': (0o0644, "8ee0d29eff20ef5d473e4a712279a727fcdc6c881ba2bb46433f7659802f598f"),
    '.github/workflows/issue-2183-reapi-composition.yml': (0o0644, "bb382d6898ce95fb690c62bfc50334e94889dbf371fa7a0871dd7bac5e24b431"),
    '.github/workflows/issue-2568-sla-credit-real.yml': (0o0644, "1376e1b9eb4136ef1faba62abbe3e051bcf9c9df837351697e0b3048bac55390"),
    '.github/workflows/issue-2730-dsr-alert-receiver.yml': (0o0644, "00ed5dab40391114b3a3a5bc299f98568e78c2dfcd14a05ccf5bac4276a6a235"),
    '.github/workflows/staging-quarantine-apply.yml': (0o0644, "24d901a61e2b45af71fc5ec0632455956690725f8f05f9959c0baf213deb1594"),
    'Cargo.lock': (0o0644, "e161aa27d6994badb497a9c881b99d9ee0255a4c2796b7f345e8a81c1bb9e707"),
    'Cargo.toml': (0o0644, "6012612bdd15b83e906f9a870049e137a9f2b947af1dd1105ee9aa6a460bfb0a"),
    'Dockerfile': (0o0644, "884f577834cfb8ef3c357afee884ac02f27c9c6031a139db04a0523fc07d5472"),
    'crates/corelink-container/build.rs': (0o0644, "b7d1b11510f0bf00a21f2f83a97a43389b0d288167f6b9c5516da57ffda9ce4d"),
    'crates/corelink-container/proto/staging_transport_probe.proto': (0o0644, "b243732e58ba3ced040e9181befd4f3c2bd995e0b23eb750889c93629245970c"),
    'crates/corelink-container/src/grpc_staging_probe.rs': (0o0644, "bab9a3dd5fea718e4e384e2fabe9145fadf9233bd9b41522c267ea02019d8e3d"),
    'crates/corelink-container/src/lib.rs': (0o0644, "01ad3ff6280beabd6dd0dea5e701315e41f7a1aba85a9dd3c7706bde0d3d7ef0"),
    'crates/corelink-container/src/main.rs': (0o0644, "44c28a9a8387212b156ce05aa65918b0c34454453d7fcd85e79fd29f9a5518db"),
    'crates/corelink-container/src/reapi_composition.rs': (0o0644, "57b3e2c730cf2f326b7f8bdb99df04b9423179524dc830805c3dbb8e62a5f337"),
    'crates/corelink-container/src/routes.rs': (0o0644, "04a84d7be655fd25ee6d05d1b5c598c169be1aae381a255533ffeda0aad1ec2f"),
    'crates/corelink-container/src/storage.rs': (0o0644, "ee16e0155fae72ddfe01fedb4b7d29bff087467b2a23c42c830a42f3aeb9b78e"),
    'crates/corelink-container/src/storage/d1_http.rs': (0o0644, "258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5"),
    'infra/staging/README.md': (0o0644, "5f3daac1edba6320bcfc6663d57bece16a9c63b7977156c0fc3a3b562276a435"),
    'infra/staging/topology.json': (0o0644, "a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14"),
    'scripts/staging_bootstrap_provider.py': (0o0644, "8a77837893f2bd094f1fd834042361e69375e1453ec1d4dde9c20c605d00ccdb"),
    'scripts/verify_i2183_reapi_composition.py': (0o0644, "532408187817e4ff508e9b2f5776e1646f7f304235ab697cf2e28fbab49a1b6c"),
    'scripts/verify_i2574_grpc_diagnostic_policy.py': (0o0644, "28023901b65dd1046af666fb26c8d862a389b94cafc11e3870a2794d869a6743"),
    'scripts/verify_staging_provider_preflight.py': (0o0644, "ddc9d57aa31cbee273dabc923b23a3ef33fb11b40bbd3b746ad7dcaca0633b62"),
    'scripts/verify_staging_topology_contract.py': (0o0644, "48b69bc6c4852ef8218058d53105fb82c4a60d22af25739b111dc4a0def79bf9"),
    'specs/03_architecture/issue-2176-grpc-transport-contract.md': (0o0644, "351aa666c129c7dbc87db4f69f476f8bcdf522d0ba35223dca7eb507c8a926b3"),
    'tests/test_issue_1700_route_inventory.py': (0o0644, "a371d50bc84eafad075c9ad943cbe9ab5b90a53a4e1501d19a428d38873a5d4a"),
    'tests/test_staging_bootstrap_provider.py': (0o0644, "ec4633c038fd4ae1553464e00ba2ce6dfe79e10562f79243e0fb629d1d93e219"),
    'tests/test_staging_custom_domain.py': (0o0644, "cfc063496302c06c8bc879c380c7f24e13088fdf8f2a5412def3e6e60b115afc"),
    'tests/test_staging_quarantine_apply_contract.py': (0o0644, "b90d143271b96038ce2f51a23bc62b3be3fee546a231f003b9bcfbfb79a497bf"),
    'worker/package.json': (0o0644, "96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34"),
    'worker/src/durable_object_probes.ts': (0o0644, "3b1a67b3c6883d23dfd29bd0a8cf18de9e9c3848b4e79e1d3d04539944081f78"),
    'worker/src/durable_object_start.ts': (0o0644, "7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c"),
    'worker/src/grpc_staging_authorization.ts': (0o0644, "6b8e2f6eb6cc42d0b0d7404950d068bab9da47c4bb1bb4c4fa0a0073c3f48400"),
    'worker/src/grpc_staging_transport.ts': (0o0644, "b3c0b471790ed7fd64138d99c0976b63c4fb620b0ce588f8c9852ea2de900f72"),
    'worker/src/grpc_transport_gate.ts': (0o0644, "68b14c5537100733ff467d8beb80f3cadce07f9b3b5f43339ab323e8ca1cfcfd"),
    'worker/src/index.ts': (0o0644, "18b960a74833284f953bd28818cd7260798d9570c17bce459502f7b7ca50f3cd"),
    'worker/src/index_common.ts': (0o0644, "dadbd05f00c855febed2266eb0ef308e2aaa80a909c4c8e463c400ed2d6bb4de"),
    'worker/src/index_env.ts': (0o0644, "ae733fad5467d839b0983f5b0df306fe8ad4c7bee68822e66e1d5b4f028886cf"),
    'worker/src/index_env_contract.ts': (0o0644, "ec259cf4d4f4c6bab582375b88a449c3d5a3d8d53c7680afdcb8e7728710eb9d"),
    'worker/src/index_fetch.ts': (0o0644, "d8619985ea28485792198c8f0e8607c108d82af66a76c0fbfc5253f2e2c3ab07"),
    'worker/src/lib/devenv_cleanup_route.ts': (0o0644, "e279cb99a585388fbf4483313a80c042df3c14bf1ca5ef52c31dc451e329907c"),
    'worker/src/lib/internal_auth.ts': (0o0644, "e773fa80db1ffd97ccdd20ae08e60e662482eea7e55bef6f19a3d61644b43acf"),
    'worker/src/lib/runner_credential_routes.ts': (0o0644, "6cd7af8c032dd8315c619f6830c3ef63df1a459152f197ca6a7faedf847b5731"),
    'worker/src/pat_issue_rate_limit.ts': (0o0644, "ff4ca0814c40f128fed4650b2041660670bcc985037b975cb6f29b177d3c1afb"),
    'worker/src/staging_d1_binding_proxy.ts': (0o0644, "1e5d940b240a4bef9daba0e360758793ab7b11a165f5b1bc8ccb7eae658a348d"),
    'worker/src/staging_d1_binding_proxy_entrypoint.ts': (0o0644, "af759d84e63a2016737c899cfba045f52c1fcf20061678a3612ddeec6c18bdab"),
    'worker/tests/cloudflare_workers_node_stub.ts': (0o0644, "0237103e747517298fea07261598d250e25edff6f412cd1df33695c1585cfcf7"),
    'worker/tests/grpc_staging_transport.test.ts': (0o0644, "ab3748063dda62d241c4c0cfdd482261514a2b8fd8a6f427d5ef4023c7fe4f96"),
    'worker/tests/staging_d1_binding_proxy.test.ts': (0o0644, "5710f974898de4c88a1ddca3f9815589d7c805faa4481f44d9005054d10796cc"),
    'worker/tests/staging_d1_binding_start_gate.test.ts': (0o0644, "2377e10e46528888f60f711820a931f8358d214ac53b8c822bfac9c2d9f2da66"),
    'worker/tsconfig.json': (0o0644, "98bfdb3e20a22fe1433a82c1cb04bd3522fa74445a61524a4f2a7263f01a93b3"),
    'worker/tsconfig.test.json': (0o0644, "7dded910aa967755433a54655f915ba7cf35e271afce2d9f47dffa32ad6f3f79"),
    'worker/vitest.config.mts': (0o0644, "e2c2f0e46d4a45d5e789f920f95b73ffd44e6a14a9450e11817426995feda506"),
    'worker/vitest.miniflare.config.mts': (0o0644, "da43009c6edc93f9ca3b626e29371b84d5125de0645c10ba7f3b6bbf3751a12a"),
}
PRE_REBASELINE_MATRIX_SHA256 = "323917e9f4cb3c67ace170b59cd548034a7af1d17759f81ab5ccd9e300f9b8aa"
MATRIX = Path("docs/internal/secrets-checklist.md")


class ReviewedBaselineTests(unittest.TestCase):
    """The committed tree is the #2868 reviewed baseline; real bytes, no patches.

    One hardlinked BASE copy and one candidate copy of the tracked tree are
    shared by the class; every test restores the bytes it moves.
    """

    root = Path(__file__).resolve().parents[1]

    @classmethod
    def setUpClass(cls) -> None:
        listed = subprocess.run(
            ["git", "-C", str(cls.root), "ls-files", "-z"], check=True, capture_output=True
        ).stdout.decode("utf-8")
        tracked = [Path(name) for name in listed.split("\0") if name]
        if len(tracked) < 1000:
            raise AssertionError(f"tracked inventory is implausibly small: {len(tracked)}")
        cls.policy = verify.load_trusted_delivery_policy()
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = Path(cls.directory.name) / "base"
        cls.candidate = Path(cls.directory.name) / "candidate"
        for destination in (cls.base, cls.candidate):
            # Exactly the tracked tree: ignored build output never enters it.
            for relative in tracked:
                source, target = cls.root / relative, destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink():
                    os.symlink(os.readlink(source), target)
                    continue
                try:
                    os.link(source, target)
                except OSError:
                    shutil.copy2(source, target)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def setUp(self) -> None:
        # The #2574 wallet-route delegation imports the BASE #2176 checker; a
        # bytecode cache written into a BASE copy would be a foreign path.
        original = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        self.addCleanup(setattr, sys, "dont_write_bytecode", original)

    @contextlib.contextmanager
    def _moved(self, root: Path, relative: Path, content: bytes):
        """Replace one path, never writing through the shared hardlink."""
        target = root / relative
        original = target.read_bytes() if target.exists() else None
        mode = target.lstat().st_mode & 0o777 if target.exists() else 0o644

        def write(value: bytes | None) -> None:
            if target.exists():
                target.unlink()
            if value is not None:
                target.write_bytes(value)
                target.chmod(mode)

        write(content)
        try:
            yield
        finally:
            write(original)

    def test_real_tree_is_the_reviewed_baseline(self) -> None:
        drift = sorted(
            str(path) for path, pin in verify.WAVE_BASE_CONTROLS.items()
            if not verify._wave_pin_matches(self.root, path, pin)
        )
        self.assertEqual(drift, [], "controls moved after #2868; review them into REBASELINE_LEDGER")
        self.assertTrue(verify._wave_pin_matches(self.root, MATRIX, (0o644, verify.WAVE_MATRIX_SHA256)))
        for group in verify.WAVE_GROUPS:
            self.assertEqual(verify._wave_group_state(self.root, group), "successor", group)
        self.assertTrue(self.policy.at_reviewed_surface(self.root))

    def test_reviewed_baseline_accepts_itself_and_ordinary_wallet_maintenance(self) -> None:
        base, candidate = self.base, self.candidate
        verify.validate(candidate, base)
        self.policy.validate(base, candidate)

        client = Path("crates/corelink-stripe-real/src/client.rs")
        with self._moved(candidate, client, (base / client).read_bytes() + b"\n// ordinary maintenance\n"):
            changes = verify.changed_paths(base, candidate)
            self.assertEqual(changes, {client})
            self.assertTrue(verify.validate_wave(candidate, base, changes))
            self.policy.validate(base, candidate)
        self.assertFalse((base / "scripts/__pycache__").exists())

    def test_reviewed_baseline_rejects_unreviewed_candidates(self) -> None:
        cases = (
            # (path, also run the full-tree #2574 policy: one per refusal branch)
            (Path("worker/src/index_fetch.ts"), True),  # control and #2574 surface: unexpected bytes
            (Path("worker/src/durable_object.ts"), False),  # i1700 successor, same #2574 branch
            (Path("Dockerfile"), True),  # control outside the surface: closed world
            (MATRIX, True),  # P0 secrets matrix: policy self-alteration
            (Path("scripts/verify_real_ignored_harnesses.py"), True),  # B068 verifier: wallet route
            (Path("crates/corelink-container/src/unreviewed_route.rs"), False),  # new path: closed world
        )
        for relative, full_policy in cases:
            with self.subTest(str(relative)):
                original = (self.base / relative).read_bytes() if (self.base / relative).exists() else b""
                with self._moved(self.candidate, relative, original + b"\n// unreviewed\n"):
                    with self.assertRaises(verify.ContractError):
                        verify.validate_wave(self.candidate, self.base, {relative})
                    if full_policy:
                        with self.assertRaises(self.policy.ContractError):
                            self.policy.validate(self.base, self.candidate)
        self.assertTrue(verify.validate_wave(self.candidate, self.base, set()))

    def test_reviewed_baseline_recognition_is_exact(self) -> None:
        cases = (
            (Path("worker/src/index_fetch.ts"), "do not match the reviewed snapshot"),
            (MATRIX, "do not match the reviewed snapshot"),
            (Path("worker/src/index_schedule.ts"), "delivery state: i1652"),
            (Path("worker/src/durable_object.ts"), "delivery state: i1700"),
            (Path("scripts/issue_1648_image_only.py"), "delivery state: i1648"),
            (Path("scripts/run-real-ignored-harnesses.sh"), "i2565"),
        )
        self.assertTrue(verify.validate_wave(self.base, self.base, set()))
        for relative, message in cases:
            with self.subTest(str(relative)):
                moved = (self.base / relative).read_bytes() + b"\n# moved without review\n"
                with self._moved(self.base, relative, moved):
                    with self.assertRaisesRegex(verify.ContractError, message):
                        verify.validate_wave(self.base, self.base, set())
        self.assertTrue(verify.validate_wave(self.base, self.base, set()))


class ReviewedBaselineLedgerTests(unittest.TestCase):
    def test_ledger_names_exactly_the_moved_pins(self) -> None:
        policy = verify.load_trusted_delivery_policy()
        self.assertEqual(list(PRE_REBASELINE_CONTROLS), [str(path) for path in verify.WAVE_BASE_CONTROLS])
        # Every pin map whose pin moved, per path, in a fixed map order.
        moved: dict[Path, list[str]] = {}
        for path, pin in PRE_REBASELINE_CONTROLS.items():
            if verify.WAVE_BASE_CONTROLS[Path(path)] != pin:
                moved.setdefault(Path(path), []).append("WAVE_BASE_CONTROLS")
        if verify.WAVE_MATRIX_SHA256 != PRE_REBASELINE_MATRIX_SHA256:
            moved.setdefault(MATRIX, []).append("WAVE_MATRIX_SHA256")
        for group, successors in verify.WAVE_GROUP_SUCCESSOR_PINS.items():
            for path in successors:
                moved.setdefault(path, []).append(f"WAVE_GROUP_SUCCESSOR_PINS[{group}]")
        for name, (_mode, digest) in policy.REVIEWED_SURFACE.items():
            if digest != policy.EXPECTED[name]:
                moved.setdefault(Path(name), []).append("REVIEWED_SURFACE")
        self.assertEqual(sorted(map(str, verify.REBASELINE_LEDGER)), sorted(map(str, moved)))
        for path, (prs, kind, disposition, reason) in verify.REBASELINE_LEDGER.items():
            with self.subTest(str(path)):
                self.assertRegex(prs, r"^#\d{4}(, #\d{4})*$")
                numbers = [int(number) for number in re.findall(r"\d{4}", prs)]
                self.assertEqual(numbers, sorted(set(numbers)))
                self.assertIn(kind, {"transport-reviewed", "not-transport"})
                # The disposition names exactly the maps re-pinned for this
                # path: a stale, missing or invented map entry fails here.
                self.assertEqual(disposition, tuple(moved[path]))
                self.assertTrue(reason.strip())

    def test_successor_pins_extend_history_without_rewriting_it(self) -> None:
        self.assertEqual(set(verify.WAVE_GROUP_SUCCESSOR_PINS), set(verify.WAVE_GROUPS))
        for group, successors in verify.WAVE_GROUP_SUCCESSOR_PINS.items():
            with self.subTest(group):
                self.assertTrue(successors)
                self.assertLessEqual(set(successors), set(verify.WAVE_GROUPS[group]))
                for path, (mode, digest) in successors.items():
                    self.assertNotEqual(verify.WAVE_GROUPS[group][path][1], (mode, digest), str(path))
                    self.assertIn(mode, (0o644, 0o755))
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")
        # The historical #2565/#2792 B068 pair is still the recorded transition.
        verifier = verify.WAVE_GROUPS["i2565"][verify.WALLET_ROUTE_VERIFIER_PATH]
        self.assertEqual(verifier[1][1], "377bcacb98e7e936bc812babc781a1fc50e68c4da8760c0bf25910f1e16e283a")
        self.assertEqual(
            verify.WALLET_ROUTE_TRANSFORMED_VERIFIER_SHA256,
            "294ea6c178b6713f75e3b85f4db9e4ee28c79576c20a47aeb071069f175333fa",
        )

    def test_two_trusted_checkers_agree_on_the_reviewed_surface(self) -> None:
        policy = verify.load_trusted_delivery_policy()
        for name, pin in policy.REVIEWED_SURFACE.items():
            path = Path(name)
            pins = []
            if path in verify.WAVE_BASE_CONTROLS:
                pins.append(verify.WAVE_BASE_CONTROLS[path])
            for group in verify.WAVE_GROUPS:
                successor = verify._wave_group_successor_pins(group)
                if successor is not None and path in successor:
                    pins.append(successor[path])
            with self.subTest(name):
                self.assertTrue(pins, "#2574 surface path is not pinned by the #2176 BASE")
                for other in pins:
                    self.assertEqual(other, pin)

    def test_successor_state_is_a_base_state_and_never_a_transition(self) -> None:
        a, b, added = Path("group/a.txt"), Path("group/b.txt"), Path("group/added.txt")
        content = {
            "old": {a: b"a0\n", b: b"b0\n"},
            "new": {a: b"a1\n", b: b"b1\n", added: b"c1\n"},
            "successor": {a: b"a1\n", b: b"b2\n", added: b"c1\n"},
        }
        digest = lambda value: (0o644, hashlib.sha256(value).hexdigest())  # noqa: E731
        groups = {"gx": {
            a: (digest(b"a0\n"), digest(b"a1\n")),
            b: (digest(b"b0\n"), digest(b"b1\n")),
            added: (None, digest(b"c1\n")),
        }}
        with tempfile.TemporaryDirectory() as directory:
            trees = {}
            for state, files in content.items():
                tree = Path(directory) / state
                for relative, value in files.items():
                    verify.write(tree, relative, value.decode())
                trees[state] = tree
            with patch.object(verify, "WAVE_GROUPS", groups), patch.object(
                verify, "WAVE_GROUP_SUCCESSOR_PINS", {"gx": {b: digest(b"b2\n")}}
            ), patch.object(verify, "_wave_common_controls_equal"), patch.object(
                verify, "_wave_controls_match", return_value=True
            ):
                for state, tree in trees.items():
                    self.assertEqual(verify._wave_group_state(tree, "gx"), state)
                self.assertTrue(verify.validate_wave(trees["successor"], trees["successor"], set()))
                self.assertTrue(verify.validate_wave(trees["new"], trees["old"], {a, b, added}))
                for candidate, base, changes in (
                    ("new", "successor", {b}),
                    ("successor", "new", {b}),
                    ("successor", "old", {a, b, added}),
                    ("old", "successor", {a, b, added}),
                ):
                    with self.subTest(f"{base} -> {candidate}"):
                        with self.assertRaisesRegex(verify.ContractError, "downgrades delivery group"):
                            verify.validate_wave(trees[candidate], trees[base], changes)
                verify.write(trees["successor"], b, "b3\n")
                with self.assertRaisesRegex(verify.ContractError, "partial trusted BASE delivery state"):
                    verify.validate_wave(trees["successor"], trees["successor"], set())
            for successors, message in (
                ({b: digest(b"b1\n")}, "repeats the delivered pin"),
                ({Path("elsewhere.txt"): digest(b"x\n")}, "outside delivery group"),
                ({}, "empty"),
            ):
                with patch.object(verify, "WAVE_GROUPS", groups), patch.object(
                    verify, "WAVE_GROUP_SUCCESSOR_PINS", {"gx": successors}
                ):
                    with self.assertRaisesRegex(verify.ContractError, message):
                        verify._wave_group_state(trees["new"], "gx")


class TrustedGrpcDenyGateTests(unittest.TestCase):
    def _i2575_fixture(self, delivered: bool = False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        trusted, candidate = root / "trusted", root / "candidate"
        verify.write_fixture_base(trusted)
        paths = verify.I2575_DELIVERY_PATHS
        preimages = {
            path: (0o644, hashlib.sha256((trusted / path).read_bytes()).hexdigest())
            if path == Path(".actionlint.yaml") else None
            for path in paths
        }
        targets = {
            path: (0o755 if path == Path("scripts/i2575_grpc_probe_client.py") else 0o644,
                   hashlib.sha256(f"reviewed #2575 {path}\n".encode()).hexdigest())
            for path in paths
        }
        for name, value in (("I2575_PREIMAGES", preimages), ("I2575_TARGETS", targets),
                            ("I2575_DELIVERY_PATHS", frozenset(paths))):
            patcher = patch.object(verify, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        shutil.copytree(trusted, candidate, dirs_exist_ok=True, symlinks=True)
        if delivered:
            for root_path in (candidate, trusted):
                for path, (mode, _digest) in targets.items():
                    target = root_path / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(f"reviewed #2575 {path}\n".encode())
                    target.chmod(mode)
        return trusted, candidate, targets

    def test_i2575_transition_pins_exact_seven_path_delivery(self) -> None:
        expected = {
            Path(".actionlint.yaml"): (0o644, "fac3a8d8271a9d2b4763ecaa966890f693cf025167f5b3f1f6cd945f706282df"),
            Path(".github/workflows/issue-2575-staging-grpc-probe.yml"): (0o644, "6055fd324f55df7549d47944e239f6e70849548c47026302e85d98b89ebc988c"),
            Path("docs/internal/issue-2575-postflight-handoff.md"): (0o644, "44f912211ef866e9d6d0ec20a1d7ca7f4280aaddd60ffa430aad604b551b2bd9"),
            Path("scripts/i2575_grpc_probe_client.py"): (0o755, "7e2eb08c70a29089afc084ed499fd60176bca96c41f363aca802ec3989461611"),
            Path("scripts/verify_i2575_readiness.py"): (0o644, "931ead0889c3cafc223141b97d933d0b1f571439a16bc57fda41e7440f238239"),
            Path("tests/test_i2575_grpc_probe_client.py"): (0o644, "88041922a3c27e82288daf1c5d379b900338937438eedd312fd880fee0f7b7e8"),
            Path("tests/test_verify_i2575_readiness.py"): (0o644, "77f6d855686a3aced792eeaa166758e19b31e5fb13f6a5e4c4dae1d0703c67cf"),
        }
        self.assertEqual(verify.I2575_TARGETS, expected)
        self.assertEqual(len(verify.I2575_DELIVERY_PATHS), 7)
        self.assertEqual(set(verify.I2575_PREIMAGES), verify.I2575_DELIVERY_PATHS)
        self.assertEqual(set(verify.I2575_TARGETS), verify.I2575_DELIVERY_PATHS)
        trusted, candidate, targets = self._i2575_fixture()
        for path, (mode, _digest) in targets.items():
            target = candidate / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(f"reviewed #2575 {path}\n".encode())
            target.chmod(mode)
        verify._validate_legacy_fixture(candidate, trusted)

    def test_fixture_keeps_pinned_actionlint_preimage_after_repository_advances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "trusted"
            verify.write_fixture_base(fixture)
            pin = verify.I2575_PREIMAGES[Path(".actionlint.yaml")]
            self.assertIsNotNone(pin)
            self.assertTrue(verify.matches_pinned_file(fixture, Path(".actionlint.yaml"), pin))

    def test_i2575_transition_rejects_partial_digest_mode_and_policy_changes(self) -> None:
        for mutation in ("partial", "digest", "mode", "policy", "old_actionlint"):
            with self.subTest(mutation=mutation):
                trusted, candidate, targets = self._i2575_fixture()
                for path, (mode, _digest) in targets.items():
                    target = candidate / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(f"reviewed #2575 {path}\n".encode())
                    target.chmod(mode)
                if mutation == "partial":
                    (candidate / Path("tests/test_verify_i2575_readiness.py")).unlink()
                elif mutation == "digest":
                    (candidate / Path("scripts/verify_i2575_readiness.py")).write_text("altered\n")
                elif mutation == "mode":
                    (candidate / Path("scripts/i2575_grpc_probe_client.py")).chmod(0o644)
                elif mutation == "policy":
                    verify.write(candidate, "scripts/verify_i2176_grpc_deny_gate.py", "self-authorize\n")
                else:
                    (candidate / Path(".actionlint.yaml")).write_text("old actionlint\n")
                with self.assertRaises(verify.ContractError):
                    verify._validate_legacy_fixture(candidate, trusted)

    def test_i2575_delivered_tree_rejects_downgrade_or_alteration(self) -> None:
        trusted, candidate, _targets = self._i2575_fixture(delivered=True)
        verify._validate_legacy_fixture(candidate, trusted)
        (candidate / Path("scripts/i2575_grpc_probe_client.py")).write_text("downgrade\n")
        with self.assertRaisesRegex(verify.ContractError, "downgraded or altered"):
            verify._validate_legacy_fixture(candidate, trusted)

    def _staging_d1_proxy_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        trusted = root / "trusted"
        candidate = root / "candidate"
        package = Path("worker/package.json")
        lock = Path("pnpm-lock.yaml")
        paths = frozenset({package, lock} | {
            Path(f"tests/fixture/staging-proxy-{index:02}.txt")
            for index in range(35)
        })
        originals = {path: f"trusted preimage {path}\n".encode() for path in paths}
        targets = {path: f"reviewed target {path}\n".encode() for path in paths}
        verify.write_fixture_base(trusted)
        verify.write(trusted, verify.INDEX, verify.expected_index(trusted))
        verify.write(trusted, verify.GATE, verify.GATE_SOURCE)
        verify.write(trusted, verify.CONTRACT, verify.CONTRACT_SOURCE)
        for path, content in originals.items():
            verify.write(trusted, path, content.decode())
        shutil.copytree(trusted, candidate, dirs_exist_ok=True, symlinks=True)
        for path, content in targets.items():
            verify.write(candidate, path, content.decode())

        package_lock_preimages = {
            path: hashlib.sha256(originals[path]).hexdigest()
            for path in (package, lock)
        }
        package_lock_targets = {
            path: hashlib.sha256(targets[path]).hexdigest()
            for path in (package, lock)
        }
        frozen_preimages = {
            path: (0o644, hashlib.sha256(content).hexdigest())
            for path, content in originals.items()
        }
        rows = []
        for path in sorted(paths, key=str):
            rows.append(
                f"100644 {hashlib.sha256(targets[path]).hexdigest()} {path}\n"
            )
        tree_digest = hashlib.sha256("".join(rows).encode()).hexdigest()
        patches = (
            patch.object(verify, "STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES", package_lock_preimages),
            patch.object(verify, "STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS", package_lock_targets),
            patch.object(verify, "STAGING_D1_PROXY_DELIVERY_PATHS", paths),
            patch.object(verify, "STAGING_D1_PROXY_PREIMAGES", frozen_preimages),
            patch.object(verify, "STAGING_D1_PROXY_DELIVERY_TREE_SHA256", tree_digest),
        )
        for item in patches:
            item.__enter__()
        self.addCleanup(lambda: [item.__exit__(None, None, None) for item in reversed(patches)])
        return trusted, candidate, paths, originals, targets

    def test_1700_package_lock_exception_requires_exact_frozen_delivery_tree(self) -> None:
        trusted, candidate, _paths, _originals, _targets = self._staging_d1_proxy_fixture()
        verify._validate_legacy_fixture(candidate, trusted)

    def test_1700_package_lock_exception_constants_bind_exact_37_path_tree(self) -> None:
        self.assertEqual(len(verify.STAGING_D1_PROXY_DELIVERY_PATHS), 37)
        self.assertEqual(
            verify.STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES,
            {
                Path("worker/package.json"): "7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348",
                Path("pnpm-lock.yaml"): "b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278",
            },
        )
        self.assertEqual(
            verify.STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS,
            {
                Path("worker/package.json"): "96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34",
                Path("pnpm-lock.yaml"): "7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc",
            },
        )
        self.assertEqual(
            verify.STAGING_D1_PROXY_DELIVERY_TREE_SHA256,
            "05e9e3c71a7073146ced7fbcf52afaf8acae88ee6ffc621710921a0eb1f6ec0e",
        )
        self.assertEqual(
            verify.STAGING_D1_PROXY_TARGETS[
                Path("tests/test_issue_1700_route_inventory.py")
            ],
            (0o644, "d9dc1e4012f590ef6b3e76eb1e342ac43d513a14ef16f3ee8db8cffb9ef2b734"),
        )
        self.assertEqual(
            verify.STAGING_D1_PROXY_PREIMAGES[
                Path("tests/test_issue_1700_route_inventory.py")
            ],
            (0o644, "216a00df6c5b67d78c90d5a9d1c78043a56985c230d7ede72e0270186eb6ef56"),
        )

    def test_follow_on_maps_are_ordered_and_package_paths_keep_predecessor_pins(self) -> None:
        self.assertEqual(len(verify.I1648_PATHS), 5)
        self.assertEqual(len(verify.B216_PATHS), 4)
        self.assertEqual(len(verify.I2568_PATHS), 8)
        self.assertEqual(
            verify.I2568_TARGETS[Path("docs/campaigns/remediation/wp150-workflow-ownership.md")],
            (0o644, "cb9bb10177faf2fd578e1cc23163015f8c2913e360e8f2880dcd2afc71904e15"),
        )
        self.assertEqual(
            verify.I2568_TARGETS[Path("scripts/verify_issue_2568_sla_credit_real.py")][1],
            "bca4fc394e00694eb2bf95e2418a5f90005cace3c426133e862eae868d20bab4",
        )

    def test_follow_on_base_pins_compose_in_frozen_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "base"
            candidate = Path(temporary) / "candidate"
            base.mkdir(); candidate.mkdir()
            relative = Path("stage/path.txt")
            shared = Path("docs/internal/secrets-checklist.md")
            old, new = b"before\n", b"after\n"
            superseded, final = b"native checklist\n", b"B216 checklist\n"
            verify.write(base, relative, old.decode())
            verify.write(candidate, relative, new.decode())
            verify.write(base, shared, final.decode())
            verify.write(candidate, shared, final.decode())
            preimages = {relative: (0o644, hashlib.sha256(old).hexdigest())}
            targets = {relative: (0o644, hashlib.sha256(new).hexdigest())}
            ordered = (
                {shared: (0o644, hashlib.sha256(superseded).hexdigest())},
                {shared: (0o644, hashlib.sha256(final).hexdigest())},
            )
            self.assertTrue(verify.preauthorized_exact_transition(
                candidate, base, {relative}, frozenset({relative}), preimages, targets, ordered
            ))
            self.assertFalse(verify.preauthorized_exact_transition(
                candidate, base, {relative}, frozenset({relative}), preimages, targets, tuple(reversed(ordered))
            ))

    def test_exact_follow_on_transition_requires_complete_predecessor_and_rejects_mixed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "base"
            candidate = Path(temporary) / "candidate"
            base.mkdir(); candidate.mkdir()
            rel = Path("follow/on.txt")
            prior = Path("prior/stage.txt")
            old, new, prior_bytes = b"old\n", b"target\n", b"prior target\n"
            verify.write(base, rel, old.decode())
            verify.write(candidate, rel, new.decode())
            verify.write(base, prior, prior_bytes.decode())
            verify.write(candidate, prior, prior_bytes.decode())
            preimages = {rel: (0o644, hashlib.sha256(old).hexdigest())}
            targets = {rel: (0o644, hashlib.sha256(new).hexdigest())}
            predecessor = {prior: (0o644, hashlib.sha256(prior_bytes).hexdigest())}
            self.assertTrue(verify.preauthorized_exact_transition(
                candidate, base, {rel}, frozenset({rel}), preimages, targets, (predecessor,)
            ))
            verify.write(candidate, Path("foreign.txt"), "foreign\n")
            self.assertFalse(verify.preauthorized_exact_transition(
                candidate, base, {rel, Path("foreign.txt")}, frozenset({rel}), preimages, targets, (predecessor,)
            ))
            (candidate / "foreign.txt").unlink()
            verify.write(base, prior, "stale predecessor\n")
            self.assertFalse(verify.preauthorized_exact_transition(
                candidate, base, {rel}, frozenset({rel}), preimages, targets, (predecessor,)
            ))

    def test_1700_package_lock_exception_rejects_partial_foreign_mixed_and_downgrade(self) -> None:
        for mutation in ("partial", "foreign", "mixed", "downgrade", "grpc"):
            with self.subTest(mutation=mutation):
                trusted, candidate, paths, originals, targets = self._staging_d1_proxy_fixture()
                package = Path("worker/package.json")
                lock = Path("pnpm-lock.yaml")
                if mutation == "partial":
                    (candidate / lock).write_bytes(originals[lock])
                elif mutation == "foreign":
                    verify.write(candidate, "tests/foreign-staging-path.txt", "foreign\n")
                elif mutation == "mixed":
                    (candidate / lock).write_bytes(b"unreviewed lock state\n")
                elif mutation == "downgrade":
                    for path in paths:
                        (trusted / path).write_bytes(targets[path])
                        (candidate / path).write_bytes(originals[path])
                else:
                    content = verify.read(candidate, verify.INDEX)
                    verify.write(candidate, verify.INDEX, content.replace(
                        "if (grpcTransportGate !== null) return grpcTransportGate;",
                        "",
                        1,
                    ))
                with self.assertRaises(verify.ContractError):
                    verify._validate_legacy_fixture(candidate, trusted)

    def test_future_i2568_workflow_is_optional_only_when_absent_on_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            candidate = root / "candidate"
            verify.write_fixture_base(trusted)
            shutil.copytree(trusted, candidate, dirs_exist_ok=True, symlinks=True)
            relative = verify.FUTURE_I2568_WORKFLOW

            (trusted / relative).unlink()
            (candidate / relative).unlink()
            verify._validate_legacy_fixture(candidate, trusted)

            verify.write(candidate, relative, "future workflow\n")
            with self.assertRaisesRegex(verify.ContractError, "one-sided presence"):
                verify._validate_legacy_fixture(candidate, trusted)
            (candidate / relative).unlink()

            verify.write(trusted, relative, "future workflow\n")
            with self.assertRaisesRegex(verify.ContractError, "one-sided presence"):
                verify._validate_legacy_fixture(candidate, trusted)
            verify.write(candidate, relative, "future workflow\n")
            verify._validate_legacy_fixture(candidate, trusted)

            (candidate / relative).chmod(0o755)
            with self.assertRaisesRegex(verify.ContractError, "protected bytes or mode drift"):
                verify._validate_legacy_fixture(candidate, trusted)
            (candidate / relative).chmod(0o644)
            (candidate / relative).unlink()
            target = candidate / "future-target"
            target.write_text("future workflow\n", encoding="utf-8")
            (candidate / relative).symlink_to(target)
            with self.assertRaisesRegex(verify.ContractError, "symlink"):
                verify._validate_legacy_fixture(candidate, trusted)

    def test_2578_mount_is_exactly_the_reviewed_ten_path_transition(self) -> None:
        expected = {
            ".github/workflows/issue-2183-reapi-composition.yml": ("e7120a3bf5978cb83c1a5efea8c5388edf4dffa925d53a1b4b83696f8e35bc48", "bb382d6898ce95fb690c62bfc50334e94889dbf371fa7a0871dd7bac5e24b431"),
            "Cargo.toml": ("ea29a8e09c640ee07f33bce567b00d00c35b666e0843cdcd8c9c46317d110695", "6012612bdd15b83e906f9a870049e137a9f2b947af1dd1105ee9aa6a460bfb0a"),
            "crates/corelink-container/build.rs": ("11000cad599f6b9afea46c379c9f1dff73bd56d30a99aba68ddc9bc7ccfc8bd1", "b7d1b11510f0bf00a21f2f83a97a43389b0d288167f6b9c5516da57ffda9ce4d"),
            "crates/corelink-container/proto/staging_transport_probe.proto": (None, "b243732e58ba3ced040e9181befd4f3c2bd995e0b23eb750889c93629245970c"),
            "crates/corelink-container/src/grpc_staging_probe.rs": (None, "bab9a3dd5fea718e4e384e2fabe9145fadf9233bd9b41522c267ea02019d8e3d"),
            "crates/corelink-container/src/lib.rs": ("b47f78891864678310d0d3ff6395f00cf5a3fa074a8733cd656c49f09d07baa9", "01ad3ff6280beabd6dd0dea5e701315e41f7a1aba85a9dd3c7706bde0d3d7ef0"),
            "crates/corelink-container/src/main.rs": ("cd08712cf96d988246665314a29a02f7ecf7072def91b75dddc285513eeb4d16", "f1150ff53657179a26373bea5d009a732d1a9bccea8c820936858c460ae4b46c"),
            "crates/corelink-container/src/reapi_composition.rs": ("a7b0fcbe499f7db437da745e74091675e62c5917675a230d08a4cd35ea5f35c6", "57b3e2c730cf2f326b7f8bdb99df04b9423179524dc830805c3dbb8e62a5f337"),
            "examples/buck2-starter/.buckconfig": ("24ffdf356bff1238e4397392048f7f20702b75ef408ac03307adddca75be2905", "47f6c78d1b20449bf429537b0ba06f1453c2fbc3ec2e0e2b9e828b1f38281899"),
            "scripts/verify_i2183_reapi_composition.py": ("99550ecedb1d700945b5b214323923db2e6bbf9b17067e9f6758491cffe17f6d", "532408187817e4ff508e9b2f5776e1646f7f304235ab697cf2e28fbab49a1b6c"),
        }
        self.assertEqual(verify.MOUNT, expected)

    def test_2578_mount_rejects_the_predecessor_or_partial_delivery(self) -> None:
        predecessor_probe = "797aff699ce4b64e1112daf5634575ac2da0d2f30e72647f7729669a1cf66867"
        predecessor_lib = "9148917bfa87f2d46b502d1c3ed4ed639e6ded55f0afab4c70c054d42f2cd1e5"
        predecessor_main = "551c05c037b9c65120b08fd71035eb1e8405ceca48dadd338674ff0c72c03f8a"
        self.assertEqual(len(verify.MOUNT), 10)
        self.assertIn("Cargo.toml", verify.MOUNT)
        self.assertIn(".github/workflows/issue-2183-reapi-composition.yml", verify.MOUNT)
        self.assertNotIn(predecessor_probe, verify.MOUNT["crates/corelink-container/src/grpc_staging_probe.rs"])
        self.assertNotIn(predecessor_lib, verify.MOUNT["crates/corelink-container/src/lib.rs"])
        self.assertNotIn(predecessor_main, verify.MOUNT["crates/corelink-container/src/main.rs"])

    def test_adversarial_fixture_mutations_fail_closed(self) -> None:
        verify.self_test()

    def test_wp150_only_skips_but_mixed_grpc_change_hits_pull_request_target_filter(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/issue-2176-grpc-deny-gate.yml").read_text()
        trigger = workflow.split("  pull_request_target:", 1)[1].split("\npermissions:", 1)[0]
        paths_block = trigger.split("    paths:\n", 1)[1]
        patterns = [
            line.strip()[3:-1]
            for line in paths_block.splitlines()
            if line.strip().startswith('- "') and line.strip().endswith('"')
        ]

        manifest = "docs/campaigns/remediation/wp150-workflow-ownership.md"
        def triggers(changed_paths: list[str]) -> bool:
            return any(
                fnmatch.fnmatchcase(path, pattern)
                for path in changed_paths
                for pattern in patterns
            )

        grpc_path = "worker/src/index_fetch.ts"
        self.assertFalse(triggers([manifest]))
        self.assertTrue(triggers([grpc_path]))
        self.assertTrue(triggers([manifest, grpc_path]))


if __name__ == "__main__":
    unittest.main()
