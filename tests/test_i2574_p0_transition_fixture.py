"""Real-tree regression for the root-only #2574 policy transition."""
from __future__ import annotations

import shutil
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
sys.path.insert(0, str(ROOT / "scripts"))
import verify_i2574_grpc_diagnostic_policy as policy


OLD_POLICY = (
    "worker/src/grpc_transport_gate.ts",
    "specs/03_architecture/issue-2176-grpc-transport-contract.md",
    "scripts/verify_i2176_grpc_deny_gate.py",
    ".github/workflows/issue-2176-grpc-deny-gate.yml",
)


def copy_current(tree: Path, names: set[str]) -> None:
    for name in names:
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def materialize_old(tree: Path) -> None:
    shutil.copytree(FIXTURES / "i2574_old_base_bytes", tree, dirs_exist_ok=True)


def overlay_delivery_fixture(tree: Path) -> None:
    shutil.copytree(FIXTURES / "i2574_delivery_bytes", tree, dirs_exist_ok=True)


class P0TransitionFixtureTests(unittest.TestCase):
    def test_old_to_root_only_p0_to_exact_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            old, p0, delivery = (Path(directory) / name for name in ("old", "p0", "delivery"))
            old.mkdir(); p0.mkdir(); delivery.mkdir()
            materialize_old(old)
            materialize_old(p0)
            # Root-only P0 supplies policy, but deliberately retains the old
            # Worker/contract bytes until the separately checked delivery.
            copy_current(p0, set(policy.POLICY) | set(policy.POLICY_FIXTURES))
            shutil.copytree(p0, delivery, dirs_exist_ok=True)
            overlay_delivery_fixture(delivery)
            (p0 / ".github").mkdir(exist_ok=True); (delivery / ".github").mkdir(exist_ok=True)
            os.symlink("../.actionlint.yaml", p0 / ".github/actionlint.yaml")
            os.symlink("../.actionlint.yaml", delivery / ".github/actionlint.yaml")

            self.assertFalse((old / "scripts/verify_i2574_grpc_diagnostic_policy.py").exists())
            self.assertNotEqual(
                (old / ".github/workflows/issue-2176-grpc-deny-gate.yml").read_bytes(),
                (p0 / ".github/workflows/issue-2176-grpc-deny-gate.yml").read_bytes(),
            )
            self.assertEqual(
                (old / "worker/src/grpc_transport_gate.ts").read_bytes(),
                (p0 / "worker/src/grpc_transport_gate.ts").read_bytes(),
            )
            self.assertNotEqual(
                (p0 / "worker/src/grpc_transport_gate.ts").read_bytes(),
                (delivery / "worker/src/grpc_transport_gate.ts").read_bytes(),
            )
            required = set(policy.EXPECTED) - {"worker/src/lib/internal_auth.ts"}
            self.assertEqual(policy.changed(p0, delivery), required)
            policy.validate(p0, delivery)

            for name in policy.EXPECTED:
                target = delivery / name
                original = target.read_bytes(); target.write_bytes(original + b"\nmutation\n")
                with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)
                target.write_bytes(original)

            pinned = delivery / "worker/src/grpc_transport_gate.ts"
            pinned_bytes = pinned.read_bytes()
            external = Path(directory) / "same-bytes.ts"; external.write_bytes(pinned_bytes)
            pinned.unlink(); os.symlink(external, pinned)
            with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)
            pinned.unlink(); pinned.write_bytes(pinned_bytes)
            pinned.chmod(0o755)
            with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)
            pinned.chmod(0o644)
            dangling = delivery / "worker/src/dangling.ts"
            os.symlink(Path(directory) / "missing.ts", dangling)
            with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)

            ordinary = Path(directory) / "ordinary"
            ordinary.mkdir()
            executable = ordinary / "tests/test_classify_runner_failure.sh"
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            policy.require_regular_tree(ordinary)

            canonical_base, canonical_candidate = Path(directory) / "canonical-base", Path(directory) / "canonical-candidate"
            canonical_base.mkdir(); canonical_candidate.mkdir()
            (canonical_base / ".github").mkdir(); (canonical_candidate / ".github").mkdir()
            os.symlink("../.actionlint.yaml", canonical_base / ".github/actionlint.yaml")
            os.symlink("../.actionlint.yaml", canonical_candidate / ".github/actionlint.yaml")
            policy.require_regular_tree(canonical_candidate, canonical_base)
            policy.require_tree_union(canonical_base, canonical_candidate)
            (canonical_candidate / ".github/actionlint.yaml").unlink()
            os.symlink("../retargeted", canonical_candidate / ".github/actionlint.yaml")
            with self.assertRaises(policy.ContractError): policy.require_regular_tree(canonical_candidate, canonical_base)
            with self.assertRaises(policy.ContractError): policy.require_tree_union(canonical_base, canonical_candidate)
            for name in policy.POLICY:
                target = delivery / name
                original = target.read_bytes(); target.write_bytes(original + b"\nmutation\n")
                with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)
                target.write_bytes(original)

            # These cover path-filter removal, target-trigger substitution and
            # candidate execution by mutating the protected BASE workflow bytes.
            workflow = delivery / ".github/workflows/issue-2176-grpc-deny-gate.yml"
            original = workflow.read_bytes()
            for old_bytes, new_bytes in ((b'"worker/src/grpc_transport_gate.ts"', b'"worker/src/removed.ts"'), (b"pull_request_target:", b"pull_request:"), (b"trusted-base/scripts/verify_i2574", b"candidate/scripts/verify_i2574")):
                workflow.write_bytes(original.replace(old_bytes, new_bytes, 1))
                with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)
            workflow.write_bytes(original)

            extra = delivery / "worker/src/candidate_execution.ts"
            extra.parent.mkdir(parents=True, exist_ok=True); extra.write_text("export {}\n")
            with self.assertRaises(policy.ContractError): policy.validate(p0, delivery)


if __name__ == "__main__":
    unittest.main()
