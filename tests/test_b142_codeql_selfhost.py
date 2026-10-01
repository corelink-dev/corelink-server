"""Focused CodeQL hosted runner/evidence contract and mutation tests."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / ".github" / "workflows" / "codeql.yml"
SEMGREP = ROOT / ".github" / "workflows" / "semgrep.yml"
WATCHDOG = ROOT / ".github" / "workflows" / "codeql-evidence-watchdog.yml"
EVIDENCE = ROOT / "scripts" / "check_codeql_evidence.py"
RUNBOOK = ROOT / "specs" / "_runbooks" / "RB-STATIC-ANALYSIS-TRIAGE.md"
I2374_VERIFIER = ROOT / "scripts" / "verify_issue_2374_hosted_proof.py"
CODEQL_ACTION_SHA = "7188fc363630916deb702c7fdcf4e481b751f97a"
CODEQL_ACTION_VERSION = "v4.37.1"


def _assert_scanner_contract(text: str) -> None:
    """Small lexical contract used by the mutation probes below."""
    assert "runs-on: ubuntu-latest" in text
    assert "runs-on: corelink" not in text
    assert "max-parallel: 3" in text
    assert "dependency-caching: true" in text
    assert "name: Require CodeQL SARIF evidence" in text
    assert "CodeQL emitted no SARIF" in text
    assert "evidence_status=missing" in text
    assert "exit 1" in text
    assert "name: codeql-sarif-${{ matrix.language }}" in text
    assert "pull_request:" in text
    assert "cancel-in-progress:" in text
    assert "continue-on-error:" not in text


def _assert_pin_contract(scanner: str, semgrep: str, runbook: str) -> None:
    assert f'CODEQL_ACTION_VERSION: "{CODEQL_ACTION_VERSION}"' in scanner
    for action in ("init", "analyze", "upload-sarif"):
        assert f"github/codeql-action/{action}@{CODEQL_ACTION_SHA}" in scanner
        assert f"github/codeql-action/{action}@{CODEQL_ACTION_VERSION}" in scanner
    assert scanner.count(CODEQL_ACTION_SHA) == 3  # init, analyze, and upload
    assert "v3.27.0" not in scanner
    assert "TBD" not in scanner
    assert f"github/codeql-action/upload-sarif@{CODEQL_ACTION_VERSION}" in semgrep
    assert CODEQL_ACTION_VERSION in runbook
    assert CODEQL_ACTION_SHA in runbook
    assert "ADR + Security review" in runbook
    assert "TBD-SHA replace post-baseline" not in runbook
    assert "actions/checkout@v7.0.0" in scanner
    assert "actions/upload-artifact@v7.0.1" in scanner
    assert "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8" in scanner


def _load_module():
    spec = importlib.util.spec_from_file_location("check_codeql_evidence", EVIDENCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_i2374_verifier():
    sys.path.insert(0, str(I2374_VERIFIER.parent))
    spec = importlib.util.spec_from_file_location("verify_issue_2374_hosted_proof", I2374_VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class B142WorkflowContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SCANNER.read_text(encoding="utf-8")
        self.semgrep = SEMGREP.read_text(encoding="utf-8")
        self.watchdog = WATCHDOG.read_text(encoding="utf-8")
        self.runbook = RUNBOOK.read_text(encoding="utf-8")

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for the socket egress controls")
    def test_i2374_socket_guard_allows_only_the_local_mock(self) -> None:
        _load_i2374_verifier().verify_socket_guard_controls()

    def test_scanner_is_hosted_with_bounded_matrix(self) -> None:
        self.assertIn("runs-on: ubuntu-latest", self.scanner)
        self.assertNotIn("runs-on: corelink", self.scanner)
        self.assertIn("max-parallel: 3", self.scanner)
        self.assertIn("group: codeql-${{ github.workflow }}", self.scanner)
        self.assertIn("cancel-in-progress: true", self.scanner)
        self.assertIn("pull_request:", self.scanner)
        self.assertIn("paths:", self.scanner)
        self.assertIn("**/*.rs", self.scanner)
        self.assertIn("permissions:\n  contents: read\n  security-events: write", self.scanner)
        self.assertNotIn("actions: read", self.scanner)
        self.assertIn('CARGO_BUILD_JOBS: "2"', self.scanner)
        self.assertIn('CODEQL_THREADS: "2"', self.scanner)
        self.assertIn('CODEQL_RAM_MB: "4096"', self.scanner)

    def test_security_semantics_and_exact_matrix_are_preserved(self) -> None:
        for language in ("rust", "javascript-typescript", "python"):
            self.assertIn(f"- language: {language}", self.scanner)
            self.assertIn(f'category: "/language:${{{{ matrix.language }}}}"', self.scanner)
        self.assertIn("queries: ${{ matrix.queries }}", self.scanner)
        self.assertIn("security-extended,security-and-quality", self.scanner)
        self.assertIn("build-mode: none", self.scanner)
        self.assertIn("dependency-caching: true", self.scanner)
        self.assertIn("upload: never", self.scanner)
        self.assertIn("github/codeql-action/upload-sarif@", self.scanner)
        self.assertIn("security-events: write", self.scanner)

    def test_codeql_pin_identity_and_approval_guard_are_consistent(self) -> None:
        _assert_pin_contract(self.scanner, self.semgrep, self.runbook)

    def test_scan_cannot_become_a_green_zero_scan(self) -> None:
        self.assertNotIn("steps.preflight.outputs.enabled == 'true'", self.scanner)
        self.assertIn("name: Require CodeQL SARIF evidence", self.scanner)
        self.assertIn("if: always()", self.scanner)
        self.assertIn("CodeQL emitted no SARIF", self.scanner)
        self.assertIn("exit 1", self.scanner)
        self.assertIn("if-no-files-found: error", self.scanner)
        self.assertIn("retention-days: 90", self.scanner)
        self.assertIn("name: codeql-sarif-${{ matrix.language }}", self.scanner)

    def test_watchdog_has_closed_population_and_fail_closed_alarm(self) -> None:
        self.assertIn("runs-on: ubuntu-latest", self.watchdog)
        self.assertIn("check_codeql_evidence.py", self.watchdog)
        for language in ("rust", "javascript-typescript", "python"):
            self.assertIn(f"CodeQL {language}", self.watchdog)
            self.assertIn(f"codeql-sarif-{{language}}", self.watchdog)
        self.assertIn("<!-- codeql-evidence-gap -->", self.watchdog)
        self.assertIn("issues: write", self.watchdog)
        self.assertIn("Fail closed on CodeQL evidence gap", self.watchdog)
        self.assertIn("if-no-files-found: error", self.watchdog)

    def test_mutations_remove_load_bearing_controls(self) -> None:
        _assert_scanner_contract(self.scanner)
        runner_mutant = self.scanner.replace("runs-on: ubuntu-latest", "runs-on: self-hosted")
        with self.assertRaises(AssertionError):
            _assert_scanner_contract(runner_mutant)
        matrix_mutant = self.scanner.replace("max-parallel: 3", "max-parallel: 1")
        with self.assertRaises(AssertionError):
            _assert_scanner_contract(matrix_mutant)
        language_mutant = self.scanner.replace("- language: python", "- language: ruby")
        self.assertNotIn("- language: python", language_mutant)
        evidence_mutant = self.scanner.replace("evidence_status=missing", "evidence_status=present", 1)
        with self.assertRaises(AssertionError):
            _assert_scanner_contract(evidence_mutant)
        pin_mutant = self.scanner.replace(CODEQL_ACTION_VERSION, "v3.27.0", 1)
        with self.assertRaises(AssertionError):
            _assert_pin_contract(pin_mutant, self.semgrep, self.runbook)
        sha_mutant = self.scanner.replace(
            f"github/codeql-action/init@{CODEQL_ACTION_SHA}",
            f"github/codeql-action/init@{'0' * 40}",
            1,
        )
        with self.assertRaises(AssertionError):
            _assert_pin_contract(sha_mutant, self.semgrep, self.runbook)
        alarm_mutant = self.watchdog.replace("<!-- codeql-evidence-gap -->", "")
        self.assertNotIn("<!-- codeql-evidence-gap -->", alarm_mutant)


class B142EvidenceInspectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()
        cls.now = datetime(2026, 9, 5, 8, tzinfo=timezone.utc)
        cls.run_payload = {
            "id": 42,
            "run_number": 7,
            "event": "schedule",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-09-05T05:30:00Z",
            "html_url": "https://github.example/actions/runs/42",
        }
        cls.jobs = {
            "jobs": [
                {"name": "CodeQL rust", "status": "completed", "conclusion": "success"},
                {"name": "CodeQL javascript-typescript", "status": "completed", "conclusion": "success"},
                {"name": "CodeQL python", "status": "completed", "conclusion": "success"},
            ]
        }
        cls.artifacts = {
            "artifacts": [
                {"name": "codeql-sarif-rust", "expired": False},
                {"name": "codeql-sarif-javascript-typescript", "expired": False},
                {"name": "codeql-sarif-python", "expired": False},
            ]
        }

    def inspect(self, run=None, jobs=None, artifacts=None, now=None):
        return self.module.inspect_evidence(
            {"workflow_runs": [run or self.run_payload]},
            jobs or self.jobs,
            artifacts or self.artifacts,
            now=now or self.now,
            max_age=timedelta(hours=26),
        )

    def test_success_requires_exact_jobs_and_artifacts(self) -> None:
        healthy, reason, metadata = self.inspect()
        self.assertTrue(healthy)
        self.assertIn("every SARIF artifact", reason)
        self.assertEqual(len(metadata["jobs"]), 3)
        self.assertEqual(len(metadata["artifacts"]), 3)

    def test_missing_or_unexpected_population_is_a_gap(self) -> None:
        missing_job = {"jobs": self.jobs["jobs"][:-1]}
        self.assertFalse(self.inspect(jobs=missing_job)[0])
        extra_job = {"jobs": self.jobs["jobs"] + [{"name": "CodeQL go"}]}
        self.assertFalse(self.inspect(jobs=extra_job)[0])
        duplicate_job = {"jobs": self.jobs["jobs"] + [self.jobs["jobs"][0]]}
        self.assertFalse(self.inspect(jobs=duplicate_job)[0])
        missing_artifact = {"artifacts": self.artifacts["artifacts"][:-1]}
        self.assertFalse(self.inspect(artifacts=missing_artifact)[0])
        duplicate_artifact = {"artifacts": self.artifacts["artifacts"] + [self.artifacts["artifacts"][0]]}
        self.assertFalse(self.inspect(artifacts=duplicate_artifact)[0])

    def test_failed_stale_running_and_expired_evidence_are_gaps(self) -> None:
        self.assertFalse(self.inspect(run={**self.run_payload, "conclusion": "failure"})[0])
        self.assertFalse(self.inspect(run={**self.run_payload, "status": "in_progress"})[0])
        stale = {**self.run_payload, "created_at": "2026-09-03T00:00:00Z"}
        self.assertFalse(self.inspect(run=stale)[0])
        expired = {"artifacts": [{**artifact, "expired": True} for artifact in self.artifacts["artifacts"]]}
        self.assertFalse(self.inspect(artifacts=expired)[0])

    def test_latest_failed_run_cannot_be_hidden_by_older_green_run(self) -> None:
        latest_failed = {**self.run_payload, "id": 43, "created_at": "2026-09-05T05:31:00Z", "conclusion": "failure"}
        healthy, _, _ = self.module.inspect_evidence(
            {"workflow_runs": [self.run_payload, latest_failed]},
            self.jobs,
            self.artifacts,
            now=self.now,
            max_age=timedelta(hours=26),
        )
        self.assertFalse(healthy)

    def test_api_unknown_is_not_reported_as_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "watchdog.json"
            rc = self.module.main(["--repo", "HuGR-Labs/corelink-server", "--report", str(report)])
            self.assertEqual(rc, 2)
            self.assertIn('"status": "watchdog_error"', report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
