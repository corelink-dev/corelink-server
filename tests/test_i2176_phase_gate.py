"""Synthetic public validate() vectors for the #2176 phase classifier."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_i2176_grpc_deny_gate as gate

ROOT = Path(__file__).resolve().parents[1]


class PhaseGateTests(unittest.TestCase):
    def test_public_mount_phases_and_negatives(self) -> None:
        original = gate.MOUNT
        try:
            h = lambda value: hashlib.sha256(value.encode()).hexdigest()
            gate.MOUNT = {
                **{f"tests/phase_mount/present-{n}.txt": (h(f"old-{n}"), h(f"new-{n}")) for n in range(6)},
                "tests/phase_mount/absent-a.txt": (None, h("new-absent-a")),
                "tests/phase_mount/absent-b.txt": (None, h("new-absent-b")),
            }
            mount_bytes = {
                **{f"tests/phase_mount/present-{n}.txt": f"new-{n}".encode() for n in range(6)},
                "tests/phase_mount/absent-a.txt": b"new-absent-a",
                "tests/phase_mount/absent-b.txt": b"new-absent-b",
            }
            with tempfile.TemporaryDirectory() as directory:
                base, candidate = Path(directory) / "base", Path(directory) / "candidate"
                ignore = shutil.ignore_patterns(".git", "node_modules", ".pnpm-store")
                shutil.copytree(ROOT, base, ignore=ignore, symlinks=True); shutil.copytree(ROOT, candidate, ignore=ignore, symlinks=True)
                for tree in (base, candidate):
                    shutil.copytree(ROOT / "tests/fixtures/i2574_delivery_bytes", tree, dirs_exist_ok=True)
                    for n in range(6):
                        p = tree / f"tests/phase_mount/present-{n}.txt"; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(f"old-{n}")
                for name, value in mount_bytes.items():
                    p = candidate / name; p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(value)
                gate.validate(candidate, base)
                (candidate/"crates/corelink-container/alternate.rs").write_text("ninth")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                (candidate/"crates/corelink-container/alternate.rs").unlink()
                # Mounted base permits the existing CI-only path, but not Worker drift.
                shutil.rmtree(base)
                shutil.copytree(candidate, base, symlinks=True)
                (candidate/".github/workflows/corelink-worker.yml").write_text("ci-only")
                gate.validate(candidate, base)
                (candidate/"worker/src/index_fetch.ts").write_text("drift")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                shutil.copy2(base / "worker/src/index_fetch.ts", candidate / "worker/src/index_fetch.ts")
                authorization = candidate / "worker/src/grpc_staging_authorization.ts"
                authorization.write_bytes(authorization.read_bytes() + b"// drift\n")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                shutil.copy2(base / "worker/src/grpc_staging_authorization.ts", authorization)

                # Every mount file is regular 0644 in both trusted states.
                mounted = candidate / "tests/phase_mount/present-0.txt"
                mounted.chmod(0o755)
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                mounted.chmod(0o644)

                # The only retained link is the exact canonical actionlint link.
                dangling = candidate / "worker/src/escape-link"
                os.symlink("missing-target", dangling)
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                dangling.unlink()
                directory_link = candidate / "worker/src/directory-link"
                os.symlink(".", directory_link)
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                directory_link.unlink()
                for tree in (base, candidate):
                    (tree / ".github/actionlint.yaml").unlink()
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                for tree in (base, candidate):
                    os.symlink("../.actionlint.yaml", tree / ".github/actionlint.yaml")
                (candidate / ".github/actionlint.yaml").unlink()
                os.symlink("../wrong-actionlint.yaml", candidate / ".github/actionlint.yaml")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                (candidate / ".github/actionlint.yaml").unlink()
                os.symlink("../.actionlint.yaml", candidate / ".github/actionlint.yaml")

                # The B141 sentinel and trusted policy remain byte and mode pinned.
                sentinel = candidate / "tests/test_pull_request_target_spawn_boundary.py"
                sentinel.write_bytes(sentinel.read_bytes() + b"# tamper\n")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                shutil.copy2(base / "tests/test_pull_request_target_spawn_boundary.py", sentinel)
                sentinel.chmod(0o755)
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                sentinel.chmod(0o644)
                policy = candidate / "scripts/verify_i2574_grpc_diagnostic_policy.py"
                policy.chmod(0o755)
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                policy.chmod(0o644)
                policy.write_bytes(policy.read_bytes() + b"# tamper\n")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
                shutil.copy2(base / "scripts/verify_i2574_grpc_diagnostic_policy.py", policy)

                # A partial trusted mount is never an admission state.
                (base / "tests/phase_mount/present-0.txt").write_text("old-0")
                with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
        finally:
            gate.MOUNT = original

    def test_public_deny_to_delivery_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base, candidate = Path(directory) / "base", Path(directory) / "candidate"
            ignore = shutil.ignore_patterns(".git", "node_modules", ".pnpm-store")
            shutil.copytree(ROOT, base, ignore=ignore, symlinks=True)
            shutil.copytree(ROOT, candidate, ignore=ignore, symlinks=True)
            # Known DENY admits only no change or the explicitly inert CI paths.
            gate.validate(candidate, base)
            (candidate / ".github/workflows/corelink-worker.yml").write_text("ci-only")
            gate.validate(candidate, base)
            shutil.copy2(base / ".github/workflows/corelink-worker.yml", candidate / ".github/workflows/corelink-worker.yml")
            added_worker = candidate / "worker/src/grpc_staging_authorization.ts"
            added_worker.write_text("partial delivery")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            added_worker.unlink()
            added_container = candidate / "crates/corelink-container/src/alternate.rs"
            added_container.parent.mkdir(parents=True, exist_ok=True)
            added_container.write_text("unexpected container")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            added_container.unlink()
            sentinel = candidate / "tests/test_pull_request_target_spawn_boundary.py"
            sentinel.write_bytes(sentinel.read_bytes() + b"# tamper\n")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            shutil.copy2(base / "tests/test_pull_request_target_spawn_boundary.py", sentinel)
            verifier = candidate / "scripts/verify_i2574_grpc_diagnostic_policy.py"
            verifier.write_bytes(verifier.read_bytes() + b"# tamper\n")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            shutil.copy2(base / "scripts/verify_i2574_grpc_diagnostic_policy.py", verifier)
            old_verifier = candidate / "scripts/verify_i2176_grpc_deny_gate.py"
            old_verifier.write_bytes(old_verifier.read_bytes() + b"# tamper\n")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            shutil.copy2(base / "scripts/verify_i2176_grpc_deny_gate.py", old_verifier)
            shutil.copytree(ROOT / "tests/fixtures/i2574_delivery_bytes", candidate, dirs_exist_ok=True)
            gate.validate(candidate, base)
            added_container.write_text("delivery plus extra")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)
            added_container.unlink()
            (base / "worker/src/index_fetch.ts").write_text("partial-delivery")
            with self.assertRaises(gate.ContractError): gate.validate(candidate, base)

    def test_phase_classifier_rejects_partial_mount(self) -> None:
        original = gate.MOUNT
        original_policy = gate.load_trusted_delivery_policy
        try:
            h = lambda value: hashlib.sha256(value.encode()).hexdigest()
            gate.MOUNT = {"a": (h("aa"), h("bb")), "b": (h("cc"), h("dd"))}
            gate.load_trusted_delivery_policy = lambda: SimpleNamespace(EXPECTED={})
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, text in (("a", "aa"), ("b", "dd")):
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
                self.assertRaises(gate.ContractError, gate.classify_phase, root)
        finally:
            gate.MOUNT = original
            gate.load_trusted_delivery_policy = original_policy


if __name__ == "__main__":
    unittest.main()
