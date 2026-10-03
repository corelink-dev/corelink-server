"""Execute the protected readiness admission and check credential boundaries."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/issue-1700-staging-readiness.yml"


class ReadinessWorkflowTests(unittest.TestCase):
    def test_only_the_manual_protected_job_can_receive_credentials(self) -> None:
        source = WORKFLOW.read_text()
        contract, provider = source.split("  readiness:\n", 1)
        self.assertNotIn("secrets.", contract)
        self.assertNotIn("environment:", contract)
        for guard in (
            "github.repository_id == '",
            "github.event_name == 'workflow_dispatch'",
            "github.ref == 'refs/heads/main' && github.ref_protected",
            "environment: staging",
            "needs: contract",
            "ref: ${{ github.sha }}",
        ):
            self.assertIn(guard, provider)
        self.assertEqual(source.count("runs-on: ubuntu-24.04"), 2)
        self.assertEqual(source.count("timeout-minutes: 5"), 2)
        self.assertNotIn("schedule:", source)
        self.assertNotIn("pull_request_target:", source)
        self.assertNotIn("write", re.search(r"(?m)^permissions:\n((?:  .+\n)+)", source)[1])
        secrets = set(re.findall(r"secrets\.([A-Z0-9_]+)", source))
        self.assertEqual(secrets, {"K6_TARGET_HOST", "K6_TARGET_IDENTITY_RECEIPT", "K6_STAGING_PAT", "K6_STAGING_PREVIOUS_PAT"})
        self.assertNotIn("CF_API_TOKEN", source)
        self.assertNotIn("ADMIN_AUTH", source)

    def test_admission_executes_before_checkout_and_rejects_each_wrong_input(self) -> None:
        provider = WORKFLOW.read_text().split("  readiness:\n", 1)[1]
        guard = provider.split("      - name: Checkout", 1)[0]
        command = textwrap.dedent(guard.split("        run: |\n", 1)[1])
        good = {
            "MODE": "readiness", "EXPECTED_SHA": "a" * 40,
            "EXPECTED_RELEASE": "b" * 40, "GITHUB_SHA": "a" * 40,
            "CONFIRM": "verify-scoped-staging-1700",
            "K6_TARGET_HOST": "https://staging.corelink.humangr.com",
        }
        cases = [(dict(good, MODE=mode), True) for mode in ("readiness", "rotation", "teardown")]
        for key, value in (
            ("MODE", "publish"), ("EXPECTED_SHA", "b" * 40),
            ("EXPECTED_SHA", "main"), ("EXPECTED_RELEASE", "HEAD"),
            ("EXPECTED_RELEASE", ""), ("CONFIRM", ""),
            ("K6_TARGET_HOST", "https://corelink-api.humangr.com"),
            ("K6_TARGET_HOST", "https://staging.corelink.humangr.com/?x=1"),
        ):
            cases.append((dict(good, **{key: value}), False))
        for environment, accepted in cases:
            with self.subTest(environment=environment):
                result = subprocess.run(["bash", "-c", command], env={**os.environ, **environment}, capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, accepted)

    def test_pr_queue_has_no_provider_lock_and_requires_an_actual_number(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn("github.event_name == 'pull_request' && format('issue-1700-readiness-contract-pr-{0}', github.event.pull_request.number) || 'issue-1700-staging-custom-domain'", source)
        self.assertIn("cancel-in-progress: false", source)
        guard = source.split("  contract:\n", 1)[1].split("      - uses:", 1)[0]
        command = textwrap.dedent(guard.split("        run: |\n", 1)[1])
        for number in ("2848", "2849", "", "0", "-1", "2848x"):
            result = subprocess.run(["bash", "-c", command], env={**os.environ, "PR_NUMBER": number}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode == 0, number in {"2848", "2849"})

    def test_actual_client_receives_separate_source_and_release_and_only_redacted_output_is_uploaded(self) -> None:
        source = WORKFLOW.read_text()
        for value in (
            'scripts/issue_1700_staging_readiness.py',
            '--mode "$MODE" --expected-release "$EXPECTED_RELEASE"',
            '--source-sha "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" --job-id "$JOB_ID"',
            'if length == 1 then .[0] else error("job cardinality") end',
            'path: ${{ runner.temp }}/i1700-readiness/receipt.json',
            'if: always()', 'umask 077',
        ):
            self.assertIn(value, source)
        self.assertEqual(source.count("actions/upload-artifact@"), 1)
        self.assertNotIn("--location", source)
        self.assertNotIn("/_health", source)
        self.assertNotIn("/_internal/i1675", source)
        self.assertNotIn("POST", source)


if __name__ == "__main__":
    unittest.main()
