"""Static safety checks for the #1700 quarantined staging apply workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = Path(".github/workflows/staging-quarantine-apply.yml")


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
        self.assertNotIn("DSR_DLQ_ALERT_ENDPOINT", workflow)
        self.assertNotIn("DSR_DLQ_ALERT_AUTH_TOKEN", workflow)

    def test_provider_writers_share_staging_lock_with_route_free_rollout(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        route_free = Path(
            ".github/workflows/issue-1700-container-staging-deploy.yml"
        ).read_text(encoding="utf-8")
        custom_domain = Path(
            ".github/workflows/issue-1700-staging-custom-domain.yml"
        ).read_text(encoding="utf-8")
        group = "group: issue-1700-staging-custom-domain"
        self.assertIn(group, workflow)
        self.assertIn(group, route_free)
        self.assertIn(group, custom_domain)

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
        operation = workflow.split("  update-existing-secrets:", 1)[1]
        self.assertNotIn("CF_API_TOKEN", operation)
        self.assertNotIn("secrets.STAGING_CF_API_TOKEN", operation)
        self.assertNotIn("wrangler deploy", operation)
        self.assertIn("--phase update-existing-apply", operation)
        self.assertIn("persist-credentials: false", workflow)
        provider = Path("scripts/staging_bootstrap_provider.py").read_text(encoding="utf-8")
        self.assertIn("versions", provider)
        self.assertIn('f"{version}@100%"', provider)
        self.assertIn("issue-1700-secrets-rollback-", provider)
        self.assertIn("if _active_exact_marker", provider)


if __name__ == "__main__":
    unittest.main()
