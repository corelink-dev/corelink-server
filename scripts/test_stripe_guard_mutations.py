#!/usr/bin/env python3
"""Hosted-only behavioral guard mutations, always in a temporary workspace."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_real_ignored_harnesses import (
    ROOT,
    STRIPE_GUARDED_METHODS,
    STRIPE_REFUSAL_TEST,
    rust_function_body,
)


TEST = f"cleanup_fault_injection::{STRIPE_REFUSAL_TEST}"


def check_result(result: subprocess.CompletedProcess[str], method: str | None) -> None:
    """Require the exact behavioral result; compilation failures are not kills."""
    output = result.stdout
    if method is None:
        if result.returncode != 0 or f"test {TEST} ... ok" not in output:
            raise AssertionError("unmutated refusal behavioral control did not pass")
    elif (
        result.returncode == 0
        or f"test {TEST} ... FAILED" not in output
        or f"request before key refusal: {method}\n" not in output
    ):
        raise AssertionError(f"guard removal did not fail the zero-request assertion: {method}")


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Rust guard mutations run only in the hosted PR lane")
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="stripe-guard-mutations-") as temp:
        root = Path(temp)
        for relative in filter(None, tracked):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target, follow_symlinks=False)
        client_path = root / "crates/corelink-stripe-real/src/client.rs"
        original = client_path.read_text(encoding="utf-8")
        # Reuse dependency artifacts from the preceding unmutated hosted test.
        target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
        env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir))
        command = [
            "cargo", "test", "--locked", "--offline", "-p", "corelink-stripe-real",
            "--features", "live-integration", "--test", "live_integration",
            TEST, "--", "--exact", "--nocapture",
        ]

        def run(method: str | None) -> None:
            result = subprocess.run(
                command, cwd=root, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600,
            )
            try:
                check_result(result, method)
            except AssertionError:
                print(result.stdout, flush=True)
                raise
            print(f"Stripe behavioral guard mutation: {method or 'unmutated control'} PASS", flush=True)

        run(None)
        for method in STRIPE_GUARDED_METHODS:
            body = rust_function_body(original, method)
            guard = "self.require_direct_test_key()?;"
            if body.count(guard) != 1 or original.count(body) != 1:
                raise AssertionError(f"guard mutation preimage is not unique: {method}")
            client_path.write_text(original.replace(body, body.replace(guard, "", 1), 1), encoding="utf-8")
            try:
                run(method)
            finally:
                client_path.write_text(original, encoding="utf-8")
        run(None)


if __name__ == "__main__":
    main()
