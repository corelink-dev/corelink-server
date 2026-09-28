"""Adversarial regressions for the protected #2574 delivery predicate."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2574_grpc_diagnostic_policy as policy


class PolicyTests(unittest.TestCase):
    def test_1700_final_runtime_pins_are_exact_and_complete(self) -> None:
        self.assertEqual(len(policy.STAGING_D1_PROXY_TARGETS), 33)
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object.ts"][1],
            "f2185d824862738ed428b92fb914b1a47e79c2b1ee3a0cc679d0d90d14214105",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_TARGETS["worker/src/durable_object_start.ts"][1],
            "7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c",
        )
        self.assertEqual(
            policy.STAGING_D1_PROXY_MANIFEST_SHA256,
            "4c29964fb1b46800a4dd281aebd97670d664e5bced4cf68c5ac5e9887cbae43c",
        )

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
