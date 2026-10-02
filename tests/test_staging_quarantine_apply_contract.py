"""Static safety checks for the #1700 quarantined staging apply workflow."""

from __future__ import annotations

import unittest
import os
import re
import subprocess
import textwrap
from pathlib import Path


WORKFLOW = Path(".github/workflows/staging-quarantine-apply.yml")
CUSTOM_DOMAIN = Path(".github/workflows/issue-1700-staging-custom-domain.yml")
PROVIDER_GROUP = "issue-1700-staging-custom-domain"
PR_GROUP_EXPRESSION = "${{ github.event_name == 'pull_request' && format('issue-1700-staging-contract-pr-{0}', github.event.pull_request.number) || 'issue-1700-staging-custom-domain' }}"


def contract_group(workflow: str, event: str, pr_number: str = "") -> str:
    """Interpret only the frozen literal or event-conditional queue contract."""
    matches = re.findall(
        r"(?m)^concurrency:\n  group: ([^\n]+)\n  cancel-in-progress: false$", workflow,
    )
    if len(matches) != 1:
        raise AssertionError("missing or ambiguous concurrency boundary")
    expression = matches[0]
    if expression == PROVIDER_GROUP:
        return PROVIDER_GROUP
    if expression != PR_GROUP_EXPRESSION:
        raise AssertionError("unapproved concurrency expression")
    if event != "pull_request":
        return PROVIDER_GROUP
    if not re.fullmatch(r"[1-9][0-9]*", pr_number):
        raise AssertionError("PR identity is absent or malformed")
    return f"issue-1700-staging-contract-pr-{pr_number}"


class StagingQuarantineApplyContractTests(unittest.TestCase):
    def test_workflow_never_publishes_dns_or_routes(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertFalse(Path(".github/workflows/staging-bootstrap.yml").exists())
        self.assertIn("quarantine-apply-staging-1700", workflow)
        self.assertIn("--phase preflight", workflow)
        self.assertGreaterEqual(workflow.count("--phase quarantine"), 2)
        self.assertNotIn("--phase final", workflow)
        self.assertNotIn("--phase postflight", workflow)
        self.assertNotIn("wrangler route", workflow)
        self.assertNotIn("wrangler dns", workflow)

    def test_create_gate_preflight_never_accepts_existing_workers(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        # The quarantine create path deploys code and puts secrets; its gate
        # must keep refusing existing Worker names instead of planning around them.
        self.assertNotIn("--existing-worker-plan", workflow)
        self.assertIn(
            "python3 scripts/staging_bootstrap_provider.py --phase preflight\n", workflow
        )
        read_only = Path(".github/workflows/staging-provider-preflight.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/staging_bootstrap_provider.py --phase preflight --existing-worker-plan",
            read_only,
        )

    def test_workflow_requires_protected_main_and_staging_environment(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "github.ref == 'refs/heads/main' && github.ref_protected", workflow
        )
        self.assertIn("environment: staging", workflow)
        self.assertIn("STAGING_CF_API_TOKEN", workflow)
        self.assertIn("STAGING_CF_WORKER_API_TOKEN", workflow)
        self.assertNotIn("STAGING_CF_D1_RUNTIME_TOKEN", workflow)
        self.assertNotIn('bind_env_secret "$root" CF_API_TOKEN', workflow)
        self.assertNotIn('bind_env_secret "$root" CF_API_TOKEN STAGING_CF_WORKER_API_TOKEN', workflow)
        self.assertIn("scope-probe-staging-1700", workflow)
        self.assertIn("inputs.mode == 'scope-probe'", workflow)
        self.assertIn('f"https://api.cloudflare.com/client/v4/{path}"', workflow)
        self.assertIn("cf_api_tokens_write_endpoint_authorized", workflow)
        self.assertNotIn("K6_STAGING_", workflow)
        self.assertIn("enable_b216_dsr_alert:", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("inputs.enable_b216_dsr_alert == true && secrets.STAGING_DSR_DLQ_ALERT_ENDPOINT", workflow)
        self.assertIn("inputs.enable_b216_dsr_alert == true && secrets.STAGING_DSR_DLQ_ALERT_AUTH_TOKEN", workflow)
        self.assertIn("update-existing-secrets-staging-1700-b216-alert", workflow)
        self.assertIn("STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST: ${{ vars.STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST }}", workflow)
        self.assertIn("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", workflow)

    def test_provider_writers_share_staging_lock_with_route_free_rollout(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        route_free = Path(
            ".github/workflows/issue-1700-container-staging-deploy.yml"
        ).read_text(encoding="utf-8")
        custom_domain = CUSTOM_DOMAIN.read_text(encoding="utf-8")
        for source in (workflow, route_free, custom_domain):
            for event in ("workflow_dispatch", "push", "pull_request_target"):
                with self.subTest(event=event):
                    self.assertEqual(contract_group(source, event, "2846"), PROVIDER_GROUP)

    def test_custom_domain_pr_contract_queues_are_distinct_from_provider_writes(self) -> None:
        workflow = CUSTOM_DOMAIN.read_text(encoding="utf-8")
        first = contract_group(workflow, "pull_request", "2846")
        second = contract_group(workflow, "pull_request", "2847")
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, PROVIDER_GROUP)
        self.assertNotEqual(second, PROVIDER_GROUP)
        for number in ("", "0", "-1", "2846x"):
            with self.subTest(number=number):
                with self.assertRaisesRegex(AssertionError, "PR identity"):
                    contract_group(workflow, "pull_request", number)
        for old, new in (
            ("github.event_name == 'pull_request'", "github.event_name != 'workflow_dispatch'"),
            ("github.event.pull_request.number)", "github.run_id)"),
            (" || 'issue-1700-staging-custom-domain'", " || 'issue-1700-staging-contract-pr-0'"),
            ("cancel-in-progress: false", "cancel-in-progress: true"),
        ):
            with self.subTest(mutation=old):
                self.assertIn(old, workflow)
                with self.assertRaises(AssertionError):
                    contract_group(workflow.replace(old, new, 1), "workflow_dispatch", "2846")

    def test_pr_identity_guard_executes_before_candidate_checkout_without_credentials(self) -> None:
        workflow = CUSTOM_DOMAIN.read_text(encoding="utf-8")
        contract, provider = workflow.split("  provider:\n", 1)
        contract = contract.split("  contract:\n", 1)[1]
        self.assertNotIn("secrets.", contract)
        self.assertNotIn("environment:", contract)
        self.assertIn("github.event_name == 'workflow_dispatch'", provider)
        guard, checkout = contract.split("      - uses: actions/checkout@", 1)
        self.assertIn("if: github.event_name == 'pull_request'", guard)
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", guard)
        self.assertIn("persist-credentials: false", checkout)
        command = textwrap.dedent(guard.split("        run: |\n", 1)[1])
        for number, expected in (("2846", 0), ("2847", 0), ("", 1), ("0", 1), ("-1", 1), ("2846x", 1)):
            with self.subTest(number=number):
                result = subprocess.run(
                    ["bash", "-c", command], env={**os.environ, "PR_NUMBER": number},
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_update_existing_uses_split_scoped_tokens_and_never_redeploys_code(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("- update-existing-secrets", workflow)
        self.assertIn("inputs.mode == 'update-existing-secrets'", workflow)
        self.assertIn("environment: staging", workflow)
        self.assertIn("STAGING_CF_WORKER_API_TOKEN: ${{ secrets.STAGING_CF_WORKER_API_TOKEN }}", workflow)
        self.assertIn("STAGING_CF_ROUTE_READ_TOKEN: ${{ secrets.STAGING_CF_ROUTE_READ_TOKEN }}", workflow)
        self.assertNotIn("STAGING_CF_D1_RUNTIME_TOKEN", workflow)
        self.assertIn("STAGING_CF_API_TOKEN: ${{ secrets.STAGING_CF_API_TOKEN }}", workflow)
        self.assertIn("update-existing-secrets-staging-1700", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("inputs.enable_b216_dsr_alert == true && secrets.STAGING_DSR_DLQ_ALERT_ENDPOINT || ''", workflow)
        self.assertIn("inputs.enable_b216_dsr_alert == true && secrets.STAGING_DSR_DLQ_ALERT_AUTH_TOKEN || ''", workflow)
        self.assertIn('row.get("author_association") != "OWNER"', workflow)
        self.assertIn("b216-receiver-readback-${{ inputs.b216_authority_run_id }}", workflow)
        operation = workflow.split("  update-existing-secrets:", 1)[1]
        self.assertNotIn("CF_API_TOKEN", operation)
        self.assertNotIn("secrets.STAGING_CF_API_TOKEN", operation)
        self.assertNotIn("wrangler deploy", operation)
        self.assertIn("--phase update-existing-apply", operation)
        self.assertIn("--enable-b216-dsr-alert", operation)
        self.assertIn("--b216-authority-receipt", operation)
        self.assertIn("--b216-authority-sha256", operation)
        self.assertIn("--b216-owner-ack-ref", operation)
        self.assertIn("permissions:", operation)
        self.assertIn("persist-credentials: false", workflow)
        provider = Path("scripts/staging_bootstrap_provider.py").read_text(encoding="utf-8")
        self.assertIn("versions", provider)
        self.assertIn('f"{version}@100%"', provider)
        self.assertIn("issue-1700-secrets-rollback-", provider)
        self.assertIn("if _active_exact_marker", provider)
        self.assertIn("validate_b216_alert_authority", provider)
        self.assertIn("corelink-dsr-b216-alert-receiver-20260927", provider)
        self.assertIn("51284495e71acdb5a7677e7383ab026b", provider)
        production = Path(".github/workflows/signup-worker-deploy.yml").read_text(encoding="utf-8")
        self.assertNotIn("STAGING_DSR_DLQ_ALERT_ENDPOINT", production)
        self.assertNotIn("STAGING_DSR_DLQ_ALERT_AUTH_TOKEN", production)


if __name__ == "__main__":
    unittest.main()
