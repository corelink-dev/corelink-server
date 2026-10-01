#!/usr/bin/env python3
"""Focused positive and fail-closed mutation tests for #1648 build-only mode."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import yaml

from verify_i1648_verifier_build_only_workflow import WORKFLOW, verify


ROOT = Path(__file__).resolve().parents[1]


class BuildOnlyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / WORKFLOW).read_text()

    def test_current_workflow_satisfies_guard(self) -> None:
        verify(self.source)

    def test_rejects_open_ended_mode(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace("options: [full, build_only]", "options: [full, build_only, production]", 1))

    def test_rejects_unpinned_main_sha(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"$EXPECTED_SHA" == "$GITHUB_SHA"', '"$EXPECTED_SHA" != "$GITHUB_SHA"', 1))

    def test_rejects_non_main_ref(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"$GITHUB_REF" == "refs/heads/main"', '"$GITHUB_REF" == "refs/heads/release"', 1))

    def test_rejects_pipefail_sensitive_rust_host_probe(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace(
                'RUSTC_DETAILS="$(rustc -vV)"\n          grep -q \'^host: x86_64-apple-darwin$\' <<<"$RUSTC_DETAILS"',
                "rustc -vV | grep -q '^host: x86_64-apple-darwin$'",
                1,
            ))

    def test_rejects_build_without_locked_dependencies(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace(
                "cargo build --locked -p corelink-audit-chain --bin verifier --release",
                "cargo build -p corelink-audit-chain --bin verifier --release",
                1,
            ))

    def test_native_host_probe_matches_and_rejects_under_pipefail(self) -> None:
        workflow = yaml.load(self.source, Loader=yaml.BaseLoader)
        native = next(
            step["run"]
            for step in workflow["jobs"]["build-only-verifier"]["steps"]
            if step.get("name") == "Assert native macOS x86_64 Rust target"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            tools = Path(temp_dir)
            uname = tools / "uname"
            uname.write_text("#!/bin/sh\nprintf 'x86_64\\n'\n")
            uname.chmod(0o755)
            rustc = tools / "rustc"
            script = "#!/bin/sh\nprintf 'host: %s\\n' \"${RUST_HOST_TEST:-x86_64-apple-darwin}\"\n"
            script += "i=0; while [ $i -lt 10000 ]; do printf 'build detail\\n'; i=$((i + 1)); done\n"
            rustc.write_text(script)
            rustc.chmod(0o755)
            env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}

            matching = subprocess.run(["bash", "-c", native], env=env, capture_output=True, text=True)
            self.assertEqual(matching.returncode, 0, matching.stderr)

            mismatch_env = {**env, "RUST_HOST_TEST": "aarch64-apple-darwin"}
            mismatching = subprocess.run(["bash", "-c", native], env=mismatch_env, capture_output=True, text=True)
            self.assertNotEqual(mismatching.returncode, 0)

    def test_rejects_production_job_in_build_only(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace("inputs.mode != 'build_only'", "inputs.mode == 'full'", 1))

    def test_rejects_secret_in_provenance(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"workflow": os.environ["GITHUB_WORKFLOW"],', '"token": os.environ["CF_API_TOKEN"],', 1))

    def test_rejects_gha_expression_inside_long_shell_body(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace(
                '          BUCKET="${R2_BUCKET:-${AUDIT_R2_BUCKET_DEFAULT}}"',
                '          DATES="${{ steps.window.outputs.dates }}"\n'
                '          BUCKET="${R2_BUCKET:-${AUDIT_R2_BUCKET_DEFAULT}}"',
                1,
            ))


if __name__ == "__main__":
    unittest.main()
