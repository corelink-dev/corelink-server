"""Adversarial regressions for the protected #2574 delivery predicate."""
import sys
import hashlib
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2574_grpc_diagnostic_policy as policy


class PolicyTests(unittest.TestCase):
    def test_1700_final_runtime_pins_are_exact_and_complete(self) -> None:
        self.assertEqual(len(policy.STAGING_D1_PROXY_TARGETS), 37)
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object.ts"][1],
            "5c9af7c31ce1ef00a9123819f81d5053705ee01423bfebef20ee94186baf92a2",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object_start.ts"][1],
            "7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_MANIFEST_SHA256,
            "d4113f29103530aaf660a54e593599115296671dffb05de206e6f220b660fc74",
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


if __name__ == "__main__":
    unittest.main()
