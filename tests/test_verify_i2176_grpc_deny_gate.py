"""Adversarial regressions for the protected-base #2176 verifier."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
import fnmatch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2176_grpc_deny_gate as verify


class TrustedGrpcDenyGateTests(unittest.TestCase):
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
