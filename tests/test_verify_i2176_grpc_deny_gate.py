"""Adversarial regressions for the protected-base #2176 verifier."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
import fnmatch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2176_grpc_deny_gate as verify


class TrustedGrpcDenyGateTests(unittest.TestCase):
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
