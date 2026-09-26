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
        self.assertIn("github.ref == 'refs/heads/main' && github.ref_protected", workflow)
        self.assertIn("environment: staging", workflow)
        self.assertIn("STAGING_CF_API_TOKEN", workflow)
        self.assertIn("STAGING_CF_WORKER_API_TOKEN", workflow)
        self.assertNotIn("K6_STAGING_", workflow)
        self.assertNotIn("DSR_DLQ_ALERT_ENDPOINT", workflow)
        self.assertNotIn("DSR_DLQ_ALERT_AUTH_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
