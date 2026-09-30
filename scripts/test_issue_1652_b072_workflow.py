#!/usr/bin/env python3
"""Static policy checks for B-072 workflow isolation and redaction."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / ".github/workflows/issue-1652-b072-evidence.yml"
LEGACY = ROOT / ".github/workflows/synthetic-pager-worker-deploy.yml"
SCRIPT = ROOT / "scripts/issue_1652_b072_operator.py"


class WorkflowIsolationTests(unittest.TestCase):
    def test_pr_pack_is_exact_head_and_has_no_provider_credentials(self) -> None:
        workflow = OPERATOR.read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertNotIn("runs-on: corelink", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("B072_STAGING_CF_WORKERS_TOKEN", workflow.split("exact-head-evidence:", 1)[1].split("protected-staging-operator:", 1)[0])
        self.assertNotIn("PAGERDUTY", workflow.upper())
        self.assertNotIn("CF_API_TOKEN", workflow)
        self.assertIn("issue-1652-b072-execution-${{ github.run_id }}", workflow)

    def test_operator_is_main_only_protected_staging_with_explicit_scoped_secrets(self) -> None:
        workflow = OPERATOR.read_text(encoding="utf-8")
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.ref_protected", workflow)
        self.assertIn("environment: staging", workflow)
        for name in ("B072_STAGING_CF_WORKERS_TOKEN", "B072_STAGING_D1_WRITE_TOKEN",
                     "B072_STAGING_CF_ROUTE_READ_TOKEN"):
            self.assertIn(name, workflow)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("production", workflow.lower())
        self.assertIn("issue-1652-b072-protected-operator", workflow)
        self.assertNotIn("|| inputs.operation", workflow)

    def test_legacy_receiver_deploy_has_no_secret_or_mutation_bypass(self) -> None:
        workflow = LEGACY.read_text(encoding="utf-8")
        self.assertIn("fail-closed", workflow)
        self.assertNotIn("wrangler deploy", workflow)
        self.assertNotIn("CF_API_TOKEN", workflow)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_operator_receipts_do_not_serialize_raw_version_bindings(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('"receiver_bindings": preimage', script)
        self.assertNotIn('"root_settings": preimage', script)
        self.assertNotIn('output["authorization"] =', script)
        self.assertNotIn('output["receiver_routes"] = routes', script)
        self.assertIn('database_window_expired = now_ms() >= rows[0].get("ends_at_ms"', script)
        self.assertNotIn('now_ms() >= auth.get("window_end_ms"', script)
        self.assertIn('"root_d1_binding": {"name": "CONFIG_DB", "id": STAGING_D1_ID}', script)
        self.assertIn("provider details were suppressed", script)
        self.assertIn("at most one provider_deferred service-binding POST", script)
        self.assertIn('"PATH", "HOME", "CI", "RUNNER_TEMP", "TMPDIR", "TMP", "TEMP", "NODE_OPTIONS"', script)
        self.assertIn('local_env["CLOUDFLARE_API_TOKEN"] = env["B072_STAGING_CF_WORKERS_TOKEN"]', script)
        self.assertIn('"--var", f"B072_OPERATOR_RUN_ID:{run_id}"', script)
        self.assertIn('vars_.get("B072_OPERATOR_RUN_ID") != marker', script)
        self.assertNotIn("marker_seen", script)
        self.assertNotIn('local_env = {key: value for key, value in env.items()', script)
        self.assertLess(script.index('put_schedules(cf, [ONE_SHOT_CRON])'),
                        script.index('arm_at = now_ms()', script.index('put_schedules(cf, [ONE_SHOT_CRON])')))


if __name__ == "__main__":
    unittest.main()
