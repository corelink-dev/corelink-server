"""Credentialless route inventory tests for the #1700 staging bootstrap."""

from __future__ import annotations

import unittest
import json
import hashlib
import subprocess
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from scripts import render_staging_wrangler as renderer
from scripts import staging_bootstrap_provider as provider
from scripts import staging_custom_domain as custom_domain
from scripts import verify_staging_provider_preflight as preflight


class StagingBootstrapProviderTests(unittest.TestCase):
    def test_wrangler_child_process_receives_no_runtime_source_secrets(self) -> None:
        with patch.dict(os.environ, {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp/home",
            "CI": "true",
            "COREPACK_HOME": "/tmp/corepack",
            "STAGING_CLERK_SECRET_KEY": "must-not-escape",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "must-not-escape-either",
            "GITHUB_TOKEN": "must-not-escape",
        }, clear=True):
            child_env = provider._wrangler_environment("worker-scoped-token")
        self.assertEqual(
            child_env,
            {
                "PATH": "/usr/bin:/bin",
                "HOME": "/tmp/home",
                "CI": "true",
                "COREPACK_HOME": "/tmp/corepack",
                "CLOUDFLARE_API_TOKEN": "worker-scoped-token",
            },
        )

    def test_existing_secret_activation_requires_exact_marker_and_version(self) -> None:
        row = {
            "id": "11111111-2222-4333-8444-555555555555",
            "annotations": {"workers/message": "issue-1700-secrets-12-" + "a" * 40 + "-corelink-staging"},
        }
        marker = row["annotations"]["workers/message"]
        with patch.object(provider, "_deployment_state", return_value=(row, "22222222-2222-4333-8444-555555555555")):
            self.assertEqual(
                provider._active_exact_marker(
                    "worker-token", "account", "corelink-staging", marker,
                    "22222222-2222-4333-8444-555555555555",
                ),
                (row["id"], "22222222-2222-4333-8444-555555555555"),
            )
            self.assertIsNone(
                provider._active_exact_marker(
                    "worker-token", "account", "corelink-staging", marker + "-wrong",
                    "22222222-2222-4333-8444-555555555555",
                )
            )
            self.assertIsNone(
                provider._active_exact_marker(
                    "worker-token", "account", "corelink-staging", marker,
                    "33333333-2222-4333-8444-555555555555",
                )
            )

    def test_existing_secret_update_checks_all_sources_before_any_provider_write(self) -> None:
        environment = {
            "STAGING_CF_WORKER_API_TOKEN": "worker-token",
            "STAGING_CF_ROUTE_READ_TOKEN": "route-token",
            "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
            "CF_ZONE_ID": custom_domain.ZONE_ID,
            "STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
            "STAGING_CLERK_SECRET_KEY": "clerk-secret",
            "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-secret",
            "STAGING_ERASURE_SALT_KEY": "salt-secret",
            "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
            # STAGING_CLERK_WEBHOOK_SECRET intentionally absent.
        }
        zone_response = {
            "result": {
                "id": custom_domain.ZONE_ID,
                "name": "humangr.com",
                "account": {"id": custom_domain.ACCOUNT_ID},
            }
        }
        with patch.dict(os.environ, environment, clear=True), patch.object(
            provider, "get", side_effect=[zone_response, {"result": []}]
        ), patch.object(provider, "validate_existing_worker_inventory"), patch.object(
            provider, "_secret_names", return_value=set()
        ), patch.object(provider.subprocess, "run") as run:
            with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
                RuntimeError, "STAGING_CLERK_WEBHOOK_SECRET"
            ):
                provider.apply_existing_secret_updates(
                    Path(temporary), Path(temporary) / "receipt.json", "12", "a" * 40
                )
            run.assert_not_called()

    def test_existing_secret_update_preserves_unknown_active_state_after_readback_error(self) -> None:
        env = {
            "STAGING_CF_WORKER_API_TOKEN": "worker-token",
            "STAGING_CF_ROUTE_READ_TOKEN": "route-token",
            "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
            "CF_ZONE_ID": custom_domain.ZONE_ID,
            "STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
            "STAGING_CLERK_SECRET_KEY": "clerk-secret",
            "STAGING_CLERK_WEBHOOK_SECRET": "webhook-secret",
            "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-secret",
            "STAGING_ERASURE_SALT_KEY": "salt-secret",
            "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
        }
        zone = {"result": {"name": "humangr.com", "account": {"id": custom_domain.ACCOUNT_ID}}}
        calls: dict[str, int] = {}
        old_deployment = "11111111-2222-4333-8444-555555555555"
        old_version = "22222222-2222-4333-8444-555555555555"

        def deployment_state(_token: str, _account: str, worker: str) -> tuple[dict, str]:
            calls[worker] = calls.get(worker, 0) + 1
            if worker == "corelink-staging" and calls[worker] >= 3:
                raise RuntimeError("provider readback unavailable")
            return (
                {
                    "id": old_deployment,
                    "created_on": "2026-09-27T00:00:00Z",
                    "versions": [{"version_id": old_version, "percentage": 100}],
                },
                old_version,
            )

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, env, clear=True
        ), patch.object(provider, "get", side_effect=[zone, {"result": []}]), patch.object(
            provider, "validate_existing_worker_inventory"
        ), patch.object(provider, "_secret_names", return_value=set()), patch.object(
            provider, "_deployment_state", side_effect=deployment_state
        ), patch.object(
            provider, "_version_for_marker", return_value="33333333-2222-4333-8444-555555555555"
        ), patch.object(
            provider.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0),
            ],
        ) as run:
            config_dir = Path(temporary)
            for worker in renderer.StagingTopologyAdapter.from_file().workers:
                (config_dir / f"{worker}.toml").write_text("name = 'test'\n", encoding="utf-8")
            receipt_path = config_dir / "receipt.json"
            with self.assertRaisesRegex(RuntimeError, "inspect redacted receipt"):
                provider.apply_existing_secret_updates(
                    config_dir, receipt_path, "12", "a" * 40
                )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["postflight"], "failed-unknown-active-state")
            self.assertTrue(receipt["provider_mutation_performed"])
            self.assertEqual(receipt["rollback"]["unknown_active_workers"], ["corelink-staging"])
            self.assertTrue(receipt["rollback"]["attempted"])
            self.assertEqual(receipt["rollback"]["status"], "failed-rollback-unverified")
            self.assertTrue(receipt["rollback"]["requires_operator_intervention"])
            self.assertEqual(run.call_count, 3)

    def test_existing_secret_update_marks_ambiguous_bulk_result_for_operator_inspection(self) -> None:
        env = {
            "STAGING_CF_WORKER_API_TOKEN": "worker-token",
            "STAGING_CF_ROUTE_READ_TOKEN": "route-token",
            "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
            "CF_ZONE_ID": custom_domain.ZONE_ID,
            "STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
            "STAGING_CLERK_SECRET_KEY": "clerk-secret",
            "STAGING_CLERK_WEBHOOK_SECRET": "webhook-secret",
            "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-secret",
            "STAGING_ERASURE_SALT_KEY": "salt-secret",
            "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
        }
        zone = {"result": {"name": "humangr.com", "account": {"id": custom_domain.ACCOUNT_ID}}}
        deployment_id = "11111111-2222-4333-8444-555555555555"
        version_id = "22222222-2222-4333-8444-555555555555"
        deployment = {
            "id": deployment_id,
            "created_on": "2026-09-27T00:00:00Z",
            "versions": [{"version_id": version_id, "percentage": 100}],
        }
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, env, clear=True
        ), patch.object(provider, "get", side_effect=[zone, {"result": []}]), patch.object(
            provider, "validate_existing_worker_inventory"
        ), patch.object(provider, "_secret_names", return_value=set()), patch.object(
            provider, "_deployment_state", return_value=(deployment, version_id)
        ), patch.object(
            provider.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)
        ) as run:
            config_dir = Path(temporary)
            for worker in renderer.StagingTopologyAdapter.from_file().workers:
                (config_dir / f"{worker}.toml").write_text("name = 'test'\n", encoding="utf-8")
            receipt_path = config_dir / "receipt.json"
            with self.assertRaisesRegex(RuntimeError, "inspect redacted receipt"):
                provider.apply_existing_secret_updates(
                    config_dir, receipt_path, "12", "a" * 40
                )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["postflight"], "failed-staged-version-unknown")
            self.assertEqual(receipt["provider_mutation_performed"], "unknown")
            self.assertEqual(receipt["staging"]["unknown_workers"], ["corelink-staging"])
            self.assertEqual(
                receipt["workers"]["corelink-staging"]["status"],
                "secret-upload-outcome-unknown",
            )
            self.assertTrue(receipt["rollback"]["requires_operator_intervention"])
            self.assertFalse(receipt["rollback"]["attempted"])
            self.assertEqual(run.call_count, 1)

    def test_existing_secret_plan_adds_only_missing_secrets(self) -> None:
        workers = {
            "corelink-staging": set(),
            "corelink-signup-staging": set(),
            "corelink-synthetic-pager-staging": set(),
        }
        environment = {
            "STAGING_CF_ACCOUNT_ID": "6a1fc1c626fc2628823e60b9db01f5cd",
            "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
            "STAGING_CLERK_SECRET_KEY": "clerk-test-secret",
            "STAGING_CLERK_WEBHOOK_SECRET": "webhook-test-secret",
            "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-test-secret",
            "STAGING_ERASURE_SALT_KEY": "salt-test-secret",
            "STAGING_R2_S3_ACCESS_KEY_ID": "r2-test-id",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-test-secret",
        }
        plan = provider.plan_missing_secret_values(workers, environment)
        self.assertEqual(
            set(plan["corelink-staging"]),
            {
                "CLERK_ISSUER_URL", "CLERK_SECRET_KEY",
                "CLOUDFLARE_ACCOUNT_ID", "CORELINK_ADMIN_AUTH_KEY",
                "CORELINK_ERASE_AUTH_KEY", "CORELINK_INTERNAL_AUTH_KEY",
                "PAT_SIGNING_KEY", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
            },
        )
        self.assertEqual(
            set(plan["corelink-signup-staging"]),
            {
                "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
                "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
            },
        )
        self.assertEqual(plan["corelink-staging"]["CORELINK_INTERNAL_AUTH_KEY"], plan["corelink-signup-staging"]["CORELINK_INTERNAL_AUTH_KEY"])
        self.assertEqual(plan["corelink-staging"]["CORELINK_ERASE_AUTH_KEY"], plan["corelink-signup-staging"]["CORELINK_ERASE_AUTH_KEY"])
        self.assertNotIn("CF_API_TOKEN", plan["corelink-staging"])
        self.assertEqual(plan["corelink-staging"]["CLOUDFLARE_ACCOUNT_ID"], environment["STAGING_CF_ACCOUNT_ID"])
        self.assertEqual(plan["corelink-synthetic-pager-staging"], {})

    def test_existing_secret_plan_never_overwrites_or_accepts_partial_shared_secret(self) -> None:
        complete = {
            "corelink-staging": {
                "CLERK_ISSUER_URL", "CLERK_SECRET_KEY",
                "CLOUDFLARE_ACCOUNT_ID", "CORELINK_ADMIN_AUTH_KEY",
                "CORELINK_ERASE_AUTH_KEY", "CORELINK_INTERNAL_AUTH_KEY",
                "PAT_SIGNING_KEY", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
            },
            "corelink-signup-staging": {
                "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
                "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
            },
            "corelink-synthetic-pager-staging": set(),
        }
        self.assertEqual(provider.plan_missing_secret_values(complete, {}), {worker: {} for worker in complete})
        partial = {worker: set(names) for worker, names in complete.items()}
        partial["corelink-signup-staging"].remove("CORELINK_INTERNAL_AUTH_KEY")
        with self.assertRaisesRegex(RuntimeError, "shared staging secret"):
            provider.plan_missing_secret_values(partial, {})

    def test_existing_secret_plan_fails_before_writes_when_any_source_is_missing(self) -> None:
        workers = {
            "corelink-staging": set(),
            "corelink-signup-staging": set(),
            "corelink-synthetic-pager-staging": set(),
        }
        with self.assertRaisesRegex(RuntimeError, "STAGING_CLERK_WEBHOOK_SECRET"):
            provider.plan_missing_secret_values(workers, {
                "STAGING_CF_ACCOUNT_ID": "account",
                "STAGING_CLERK_ISSUER_URL": "issuer",
                "STAGING_CLERK_SECRET_KEY": "clerk-secret",
                "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr",
                "STAGING_ERASURE_SALT_KEY": "salt",
                "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
                "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
            })

    def test_existing_secret_plan_never_binds_provider_token_as_runtime_d1_token(self) -> None:
        plan = provider.plan_missing_secret_values(
            {
                "corelink-staging": set(),
                "corelink-signup-staging": set(),
                "corelink-synthetic-pager-staging": set(),
            },
            {
                "STAGING_CF_API_TOKEN": "provider-management-token",
                "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
                "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
                "STAGING_CLERK_SECRET_KEY": "clerk-secret",
                "STAGING_CLERK_WEBHOOK_SECRET": "webhook-secret",
                "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-secret",
                "STAGING_ERASURE_SALT_KEY": "salt-secret",
                "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
                "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
            },
        )
        self.assertNotIn("CF_API_TOKEN", plan["corelink-staging"])

    def test_provider_preflight_pins_reject_provider_and_renderer_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / "workflow.yml"
            provider = root / "provider.py"
            renderer_path = root / "renderer.py"
            workflow.write_text("", encoding="utf-8")
            baselines = {
                provider: b"reviewed provider bytes\n",
                renderer_path: b"reviewed renderer bytes\n",
            }
            for mutated_path in baselines:
                with self.subTest(mutated=str(mutated_path)):
                    for path, contents in baselines.items():
                        path.write_bytes(b"changed source bytes\n" if path == mutated_path else contents)
                    provider_pin = hashlib.sha256(baselines[provider]).hexdigest()
                    renderer_pin = hashlib.sha256(baselines[renderer_path]).hexdigest()
                    with patch.object(preflight, "WORKFLOW", workflow), patch.object(
                        preflight, "PROVIDER", provider
                    ), patch.object(preflight, "RENDERER", renderer_path), patch.object(
                        preflight, "CANONICAL_PROVIDER_SOURCE_SHA256", provider_pin
                    ), patch.object(
                        preflight, "CANONICAL_RENDERER_SOURCE_SHA256", renderer_pin
                    ), self.assertRaisesRegex(SystemExit, str(mutated_path.name)):
                        preflight.main()

    def test_route_pairs_include_any_canonical_matching_pattern(self) -> None:
        routes = [
            {
                "id": "route-1",
                "pattern": "staging.corelink.humangr.com/api/*",
                "script": "corelink-staging",
            },
            {"id": "route-2", "pattern": "other.humangr.com/*", "script": "other-worker"},
        ]
        self.assertEqual(
            provider.route_pairs(routes),
            {
                ("staging.corelink.humangr.com/api/*", "corelink-staging"),
            },
        )

    def test_route_pairs_reject_unsafe_staging_targets(self) -> None:
        for script in ("corelink-production", "corelink-prod", None):
            with self.subTest(script=script), self.assertRaises(RuntimeError):
                provider.route_pairs(
                    [{
                        "id": "route-1",
                        "pattern": f"{renderer.CANONICAL_HOST}/*",
                        "script": script,
                    }]
                )

    def test_typed_renderer_owns_exact_route_contract(self) -> None:
        topology = renderer.StagingTopologyAdapter.from_file()
        expected = {
            (renderer.CANONICAL_HOST, topology.workers[0]),
        }
        configured = {
            (route["pattern"], route["worker"])
            for route in topology.cloudflare["routes"]
        }
        self.assertEqual(configured, expected)
        self.assertTrue(topology.cloudflare["routes"][0]["custom_domain"])

    def test_postflight_requires_exact_readback_flags_and_domain(self) -> None:
        required = json.loads(
            Path("infra/staging/topology.json").read_text(encoding="utf-8")
        )["required_secret_names"]
        def settings(flags: list[str], worker: str) -> dict:
            return {
                "success": True,
                "errors": [],
                "messages": [],
                "result": {
                    "compatibility_flags": flags,
                    "bindings": [
                        {"name": name, "type": "secret_text"}
                        for name in required[worker]
                    ],
                },
            }
        root_settings = settings(
            ["nodejs_compat", "enable_request_signal", "request_signal_passthrough"],
            "corelink-staging",
        )
        signup_settings = settings([], "corelink-signup-staging")
        domain_id = "a" * 32
        cert_id = "11111111-2222-4333-8444-555555555555"
        inventory = (
            {
                "success": True,
                "errors": [],
                "messages": [],
                "result": {
                    "id": custom_domain.ZONE_ID,
                    "name": custom_domain.ZONE_NAME,
                    "account": {"id": custom_domain.ACCOUNT_ID},
                },
            },
            {"success": True, "errors": [], "messages": [], "result": []},
            {
                "success": True,
                "errors": [],
                "messages": [],
                "result": [
                    {
                        "id": domain_id,
                        "cert_id": cert_id,
                        "hostname": custom_domain.HOSTNAME,
                        "service": custom_domain.WORKER,
                        "zone_id": custom_domain.ZONE_ID,
                        "zone_name": custom_domain.ZONE_NAME,
                    }
                ],
                "result_info": {
                    "count": 1,
                    "page": 1,
                    "per_page": custom_domain.DOMAIN_PAGE_SIZE,
                    "total_count": 2,
                    "total_pages": 1,
                },
            },
            {
                "success": True,
                "errors": [],
                "messages": [],
                "result": [
                    {
                        "id": "b" * 32,
                        "name": custom_domain.HOSTNAME,
                        "type": "CNAME",
                        "content": "worker-managed.invalid",
                        "proxied": True,
                    }
                ],
                "result_info": {
                    "count": 1,
                    "page": 1,
                    "per_page": custom_domain.DNS_PAGE_SIZE,
                    "total_count": 2,
                    "total_pages": 1,
                },
            },
            {
                "success": True,
                "errors": [],
                "messages": [],
                "result": {"enabled": False, "previews_enabled": False},
            },
            root_settings,
            signup_settings,
        )
        self.assertEqual(
            provider.validate_postflight_custom_domain(
                inventory, custom_domain.ACCOUNT_ID, custom_domain.ZONE_ID
            )["action"],
            "already-exact",
        )

        bad_flag_sets = (
            [],
            ["nodejs_compat", "request_signal_passthrough"],
            ["nodejs_compat", "enable_request_signal", "wrong_flag"],
            [
                "nodejs_compat",
                "enable_request_signal",
                "request_signal_passthrough",
                "extra_flag",
            ],
        )
        for flags in bad_flag_sets:
            with self.subTest(flags=flags):
                invalid_inventory = (*inventory[:5], settings(flags, "corelink-staging"), signup_settings)
                with self.assertRaisesRegex(ValueError, "request-signal"):
                    provider.validate_postflight_custom_domain(
                        invalid_inventory,
                        custom_domain.ACCOUNT_ID,
                        custom_domain.ZONE_ID,
                    )


if __name__ == "__main__":
    unittest.main()
