#!/usr/bin/env python3
"""Trusted-base, data-only delivery predicate for #2574.

The pull_request_target gate runs this file from protected base.  The candidate
tree is only read, never imported or executed.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import tempfile
from pathlib import Path


class ContractError(RuntimeError):
    pass


EXPECTED = {
    "specs/03_architecture/issue-2176-grpc-transport-contract.md": "a9d66d36a0bb4cf33a3a3d271b1744513a72ff244920125a392b9f45de74552f",
    "worker/src/grpc_transport_gate.ts": "68b14c5537100733ff467d8beb80f3cadce07f9b3b5f43339ab323e8ca1cfcfd",
    "worker/src/grpc_staging_authorization.ts": "d9ed7b48ba291aadd66cf9bcef65a4481926c1cceae80884c3abafea5039835c",
    "worker/src/grpc_staging_transport.ts": "d94bdd39789794c2b25d2bc12e371497030d1ce1677bfaf5c26da638137ecdeb",
    "worker/src/index_fetch.ts": "d8619985ea28485792198c8f0e8607c108d82af66a76c0fbfc5253f2e2c3ab07",
    "worker/src/index_env.ts": "ae733fad5467d839b0983f5b0df306fe8ad4c7bee68822e66e1d5b4f028886cf",
    "worker/src/index_env_contract.ts": "ec259cf4d4f4c6bab582375b88a449c3d5a3d8d53c7680afdcb8e7728710eb9d",
    "worker/src/durable_object.ts": "96f3f6e395d9f09feda2cc7d4e8616b27ff0b5afdbded5e0344085063146f410",
    "worker/src/durable_object_probes.ts": "3b1a67b3c6883d23dfd29bd0a8cf18de9e9c3848b4e79e1d3d04539944081f78",
    "worker/src/durable_object_start.ts": "26d78fadfb89ca7327f698696ec15c53c455823f3f2c1ae3c282af16b4cab244",
    "worker/tests/grpc_staging_transport.test.ts": "316b538eb01676e71db8b023550c314b1e37fadd6b1c3974acdb28565e312b8d",
    "worker/src/lib/internal_auth.ts": "e773fa80db1ffd97ccdd20ae08e60e662482eea7e55bef6f19a3d61644b43acf",
}
POLICY = {
    "scripts/verify_i2176_grpc_deny_gate.py",
    "tests/test_verify_i2176_grpc_deny_gate.py",
    "scripts/verify_i2574_grpc_diagnostic_policy.py",
    "tests/test_verify_i2574_grpc_diagnostic_policy.py",
    "tests/test_i2574_p0_transition_fixture.py",
    ".github/workflows/issue-2176-grpc-deny-gate.yml",
    ".github/workflows/issue-2574-staging-grpc-diagnostic.yml",
}
POLICY_FIXTURES = {
    "tests/fixtures/i2574_old_base_bytes/specs/03_architecture/issue-2176-grpc-transport-contract.md",
    "tests/fixtures/i2574_old_base_bytes/worker/src/grpc_transport_gate.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_fetch.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_env.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_env_contract.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object_probes.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object_start.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/lib/internal_auth.ts",
    "tests/fixtures/i2574_old_base_bytes/scripts/verify_i2176_grpc_deny_gate.py",
    "tests/fixtures/i2574_old_base_bytes/.github/workflows/issue-2176-grpc-deny-gate.yml",
    "tests/fixtures/i2574_delivery_bytes/specs/03_architecture/issue-2176-grpc-transport-contract.md",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_transport_gate.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_staging_authorization.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_staging_transport.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_fetch.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_env.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_env_contract.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object_probes.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object_start.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/tests/grpc_staging_transport.test.ts",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(root: Path) -> set[str]:
    return {
        str(p.relative_to(root)) for p in root.rglob("*")
        if stat.S_ISREG(p.lstat().st_mode) and ".git" not in p.parts
    }


def require_regular_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if ".git" in path.parts:
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ContractError(f"symlink forbidden: {path.relative_to(root)}")
        if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
            raise ContractError(f"non-regular path forbidden: {path.relative_to(root)}")


def require_pinned_modes(root: Path, paths: set[str]) -> None:
    for name in paths:
        path = root / name
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o644:
            raise ContractError(f"unexpected pinned mode: {name}")


def changed(base: Path, candidate: Path) -> set[str]:
    names = files(base) | files(candidate)
    return {name for name in names if not (base / name).exists() or not (candidate / name).exists() or digest(base / name) != digest(candidate / name)}


def validate(base: Path, candidate: Path) -> None:
    require_regular_tree(base)
    require_regular_tree(candidate)
    require_pinned_modes(base, POLICY | POLICY_FIXTURES)
    require_pinned_modes(candidate, set(EXPECTED) | POLICY | POLICY_FIXTURES)
    differences = changed(base, candidate)
    allowed = set(EXPECTED) - {"worker/src/lib/internal_auth.ts"}
    if differences - allowed:
        raise ContractError(f"closed-world violation: {sorted(differences - allowed)}")
    for name in POLICY | POLICY_FIXTURES:
        if (base / name).read_bytes() != (candidate / name).read_bytes():
            raise ContractError(f"policy self-alteration: {name}")
    for name, expected in EXPECTED.items():
        target = candidate / name
        if not target.is_file() or digest(target) != expected:
            raise ContractError(f"unexpected bytes: {name}")


def self_test() -> None:
    global EXPECTED
    with tempfile.TemporaryDirectory() as tmp:
        base, candidate = Path(tmp) / "base", Path(tmp) / "candidate"
        for name, value in EXPECTED.items():
            p = base / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"base")
            p = candidate / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"base")
        for name in POLICY | POLICY_FIXTURES:
            p = base / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("protected")
            p = candidate / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("protected")
        # Install exact expected bytes by replacing the predicate for this fixture.
        original = EXPECTED
        EXPECTED = {name: digest(candidate / name) for name in original}
        validate(base, candidate)
        for name in ("worker/src/grpc_transport_gate.ts", "scripts/verify_i2574_grpc_diagnostic_policy.py", ".github/workflows/issue-2574-staging-grpc-diagnostic.yml"):
            p = candidate / name; p.write_bytes(p.read_bytes() + b"x")
            try: validate(base, candidate)
            except ContractError: pass
            else: raise ContractError(f"mutation escaped: {name}")
            p.write_bytes(p.read_bytes()[:-1])
        unexpected = candidate / "worker/src/alternate.ts"; unexpected.write_text("escape")
        try: validate(base, candidate)
        except ContractError: pass
        else: raise ContractError("added path escaped")
        EXPECTED = original


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--trusted-base", type=Path); parser.add_argument("--candidate", type=Path); parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test: self_test()
        elif args.trusted_base and args.candidate: validate(args.trusted_base, args.candidate)
        else: raise ContractError("pass --self-test or both trees")
    except ContractError as exc:
        print(f"issue-2574 trusted policy: FAIL: {exc}"); return 1
    print("issue-2574 trusted policy: PASS"); return 0


if __name__ == "__main__": raise SystemExit(main())
