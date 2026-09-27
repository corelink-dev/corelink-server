"""Adversarial regressions for the protected #2574 delivery predicate."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2574_grpc_diagnostic_policy as policy


class PolicyTests(unittest.TestCase):
    def test_closed_world_and_self_alteration_fail(self) -> None:
        policy.self_test()


if __name__ == "__main__":
    unittest.main()
