"""Adversarial regressions for the protected-base #2176 verifier."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path
import fnmatch
import hashlib
import shutil
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
