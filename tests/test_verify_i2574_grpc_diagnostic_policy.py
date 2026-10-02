"""Adversarial regressions for the protected #2574 delivery predicate."""
import re
import subprocess
import sys
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2574_grpc_diagnostic_policy as policy


class PolicyTests(unittest.TestCase):
    def test_1700_final_runtime_pins_are_exact_and_complete(self) -> None:
        self.assertEqual(len(policy.STAGING_D1_PROXY_TARGETS), 37)
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object.ts"][1],
            "c4046c2008acedecc7d1404bfad2fecbda58131e66927b58c5d56d82ca9febb9",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object_start.ts"][1],
            "7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_MANIFEST_SHA256,
            "05e9e3c71a7073146ced7fbcf52afaf8acae88ee6ffc621710921a0eb1f6ec0e",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS[
                "tests/test_issue_1700_route_inventory.py"
            ][1],
            "d9dc1e4012f590ef6b3e76eb1e342ac43d513a14ef16f3ee8db8cffb9ef2b734",
        )

    def test_follow_on_successor_maps_are_frozen_and_ordered(self) -> None:
        self.assertEqual(len(policy.STAGING_I1648_TARGETS), 5)
        self.assertEqual(len(policy.STAGING_B216_TARGETS), 4)
        self.assertEqual(len(policy.STAGING_I2568_TARGETS), 8)
        self.assertEqual(
            policy.STAGING_B216_TARGETS["docs/internal/secrets-checklist.md"],
            (0o644, "acc1debc7f96d7b38b03743f6c905e882655dc0a370ab4b7c97d7b37b5e00196"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            base, candidate = Path(temporary) / "base", Path(temporary) / "candidate"
            base.mkdir(); candidate.mkdir()
            source = "future/file.txt"
            shared = "docs/internal/secrets-checklist.md"
            old, target = b"old successor\n", b"exact successor\n"
            native, b216 = b"native checklist\n", b"B216 checklist\n"
            (base / source).parent.mkdir(parents=True)
            (candidate / source).parent.mkdir(parents=True)
            (base / source).write_bytes(old)
            (candidate / source).write_bytes(target)
            (base / shared).parent.mkdir(parents=True)
            (candidate / shared).parent.mkdir(parents=True)
            (base / shared).write_bytes(b216)
            (candidate / shared).write_bytes(b216)
            pre = {source: (0o644, hashlib.sha256(old).hexdigest())}
            targets = {source: (0o644, hashlib.sha256(target).hexdigest())}
            predecessor = (
                {shared: (0o644, hashlib.sha256(native).hexdigest())},
                {shared: (0o644, hashlib.sha256(b216).hexdigest())},
            )
            self.assertTrue(policy.exact_staging_successor(base, candidate, pre, targets, predecessor))
            self.assertFalse(policy.exact_staging_successor(base, candidate, pre, targets, tuple(reversed(predecessor))))
            (candidate / "foreign.txt").write_text("unapproved\n")
            self.assertFalse(policy.exact_staging_successor(base, candidate, pre, targets, predecessor))
            (candidate / "foreign.txt").unlink()
            (candidate / source).chmod(0o755)
            self.assertFalse(policy.exact_staging_successor(base, candidate, pre, targets, predecessor))
            (candidate / source).chmod(0o644)
            (candidate / shared).write_bytes(native)
            self.assertFalse(policy.exact_staging_successor(base, candidate, pre, targets, predecessor))
            (candidate / shared).write_bytes(b216)
            (candidate / source).write_bytes(old)
            self.assertFalse(policy.exact_staging_successor(base, candidate, pre, targets, predecessor))

    def test_closed_world_and_self_alteration_fail(self) -> None:
        policy.self_test()

    def test_reviewed_surface_is_a_base_state_not_a_transition(self) -> None:
        # EXPECTED stays the historical delivery target the fixtures prove.
        fixtures = Path(__file__).resolve().parents[1] / "tests/fixtures"
        for name, pinned in policy.EXPECTED.items():
            fixture = fixtures / "i2574_delivery_bytes" / name
            if not fixture.exists():
                fixture = fixtures / "i2574_old_base_bytes" / name
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), pinned, name)
        self.assertEqual(set(policy.REVIEWED_SURFACE), set(policy.EXPECTED))

        delivered = {name: f"delivered {name}\n".encode() for name in policy.EXPECTED}
        reviewed = {name: f"reviewed {name}\n".encode() for name in policy.EXPECTED}
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in delivered.items()}
        surface = {name: (0o644, hashlib.sha256(value).hexdigest()) for name, value in reviewed.items()}

        def tree(root: Path, surface_bytes: dict[str, bytes]) -> None:
            for name in policy.POLICY | policy.POLICY_FIXTURES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("protected")
            for name, value in surface_bytes.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
            (root / ".github").mkdir(exist_ok=True)
            (root / ".github/actionlint.yaml").symlink_to("../.actionlint.yaml")

        moved = "worker/src/index_fetch.ts"
        with patch.object(policy, "EXPECTED", expected), patch.object(policy, "REVIEWED_SURFACE", surface):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for name, base_bytes, candidate_bytes, admitted in (
                    ("reviewed base accepts itself", reviewed, reviewed, True),
                    ("reviewed base refuses a downgrade to the delivery bytes",
                     reviewed, {**reviewed, moved: delivered[moved]}, False),
                    ("reviewed base refuses an unreviewed edit",
                     reviewed, {**reviewed, moved: reviewed[moved] + b"edit\n"}, False),
                    ("delivery base keeps its historical self-acceptance", delivered, delivered, True),
                    ("delivery base cannot jump to the reviewed bytes",
                     delivered, {**delivered, moved: reviewed[moved]}, False),
                    ("partial reviewed base holds the historical bytes",
                     {**reviewed, moved: delivered[moved]}, reviewed, False),
                ):
                    with self.subTest(name):
                        base, candidate = root / name / "base", root / name / "candidate"
                        tree(base, base_bytes)
                        tree(candidate, candidate_bytes)
                        if admitted:
                            policy.validate(base, candidate)
                        else:
                            with self.assertRaisesRegex(policy.ContractError, "unexpected bytes"):
                                policy.validate(base, candidate)
            with patch.object(policy, "REVIEWED_SURFACE", {**surface, "worker/src/extra.ts": surface[moved]}):
                with self.assertRaisesRegex(policy.ContractError, "reviewed #2574 surface"):
                    policy.at_reviewed_surface(Path("/nonexistent"))

    def test_wallet_route_dispatch_loads_trusted_base_checker_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_script = root / "base/scripts/verify_i2176_grpc_deny_gate.py"
            candidate_script = root / "candidate/scripts/verify_i2176_grpc_deny_gate.py"
            base_script.parent.mkdir(parents=True)
            candidate_script.parent.mkdir(parents=True)
            base_script.write_text(
                "def validate_wallet_route_candidate(base, candidate):\n    return 'trusted-base'\n"
            )
            marker = root / "candidate-executed"
            candidate_script.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
                "def validate_wallet_route_candidate(base, candidate):\n    return 'candidate'\n"
            )
            self.assertEqual(policy.validate_wallet_route_transition(root / "base", root / "candidate"), "trusted-base")
            self.assertFalse(marker.exists())

    def test_receiver_boundary_scopes_path_allowlist_but_keeps_privacy_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "apps/dsr-alert-receiver/src"
            source.mkdir(parents=True)
            entry = source / "handler.ts"
            entry.write_text("export const safe = true;\n")
            policy.validate_receiver_path_boundary(
                {"infra/staging/topology.json", "docs/internal/secrets-checklist.md"}, root
            )
            policy.validate_receiver_path_boundary(
                {"apps/dsr-alert-receiver/src/handler.ts"}, root
            )
            with self.assertRaises(policy.ContractError):
                policy.validate_receiver_path_boundary(
                    {"apps/dsr-alert-receiver/src/handler.ts", "infra/staging/topology.json"}, root
                )
            entry.write_text("console.log('raw body');\n")
            with self.assertRaises(policy.ContractError):
                policy.validate_receiver_path_boundary({"infra/staging/topology.json"}, root)

    def test_receiver_boundary_admits_only_an_added_flat_changelog_fragment(self) -> None:
        receiver = "apps/dsr-alert-receiver/src/handler.ts"
        fragment = "changelog.d/i1678-token-verify-error-class.md"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy.validate_receiver_path_boundary({receiver, fragment}, root, {fragment})
            # Modified: changed but not added. The two-argument caller has no
            # added-path evidence, so it must keep refusing the fragment too.
            for added in ({receiver}, frozenset()):
                with self.assertRaisesRegex(policy.ContractError, "i1678-token-verify-error-class"):
                    policy.validate_receiver_path_boundary({receiver, fragment}, root, added)
            with self.assertRaisesRegex(policy.ContractError, "i1678-token-verify-error-class"):
                policy.validate_receiver_path_boundary({receiver, fragment}, root)
            for foreign in (
                "changelog.d/README.md",
                "changelog.d/../x.md",
                "changelog.d/sub/x.md",
                "changelog.d/.hidden.md",
                "changelog.d/x.md.txt",
                "changelog.d/x.md\n",
                "CHANGELOG.md",
                "scripts/verify_i2574_grpc_diagnostic_policy.py",
            ):
                with self.subTest(foreign=foreign):
                    with self.assertRaises(policy.ContractError) as raised:
                        policy.validate_receiver_path_boundary({receiver, foreign}, root, {foreign})
                    self.assertIn(repr(foreign), str(raised.exception))

    def test_receiver_boundary_reads_added_status_from_git(self) -> None:
        def git(root: Path, *args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(root), "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *args],
                check=True, capture_output=True, text=True,
            ).stdout.strip()

        receiver = Path("apps/dsr-alert-receiver/src/handler.ts")
        existing = Path("changelog.d/existing-fragment.md")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, "init", "-q")
            for relative in (receiver, existing, Path("changelog.d/README.md")):
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_text("base\n")
            git(root, "add", "-A")
            git(root, "commit", "-q", "-m", "base")
            base = git(root, "rev-parse", "HEAD")

            def candidate(*edits: Path) -> None:
                git(root, "checkout", "-q", "--detach", base)
                for relative in (receiver, *edits):
                    (root / relative).parent.mkdir(parents=True, exist_ok=True)
                    (root / relative).write_text("candidate\n")
                git(root, "add", "-A")
                git(root, "commit", "-q", "-m", "candidate")

            candidate(Path("changelog.d/i1678-new-entry.md"))
            policy.check_receiver_path_boundary(root, base)
            for edit in (existing, Path("changelog.d/README.md"), Path("CHANGELOG.md")):
                with self.subTest(edit=str(edit)):
                    candidate(edit)
                    with self.assertRaisesRegex(policy.ContractError, re.escape(str(edit))):
                        policy.check_receiver_path_boundary(root, base)
            git(root, "checkout", "-q", "--detach", base)
            git(root, "rm", "-q", str(existing))
            (root / receiver).write_text("candidate\n")
            git(root, "add", "-A")
            git(root, "commit", "-q", "-m", "delete fragment")
            with self.assertRaisesRegex(policy.ContractError, re.escape(str(existing))):
                policy.check_receiver_path_boundary(root, base)


if __name__ == "__main__":
    unittest.main()
