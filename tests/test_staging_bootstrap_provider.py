"""Credentialless route inventory tests for the #1700 staging bootstrap."""

from __future__ import annotations

import contextlib
import io
import unittest
import json
import hashlib
import subprocess
import tempfile
import os
from datetime import datetime, timezone
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

    @staticmethod
    def _b216_environment() -> dict[str, str]:
        return {
            "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
            "STAGING_CLERK_ISSUER_URL": "https://staging-clerk.invalid",
            "STAGING_CLERK_SECRET_KEY": "clerk-secret",
            "STAGING_CLERK_WEBHOOK_SECRET": "webhook-secret",
            "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY": "dsr-secret",
            "STAGING_ERASURE_SALT_KEY": "salt-secret",
            "STAGING_R2_S3_ACCESS_KEY_ID": "r2-id",
            "STAGING_R2_S3_SECRET_ACCESS_KEY": "r2-secret",
            "STAGING_DSR_DLQ_ALERT_ENDPOINT": "https://alerts.example.invalid/",
            "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN": "dedicated-receiver-bearer",
            "STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST": "alerts.example.invalid",
        }

    @staticmethod
    def _empty_worker_secret_names() -> dict[str, set[str]]:
        return {
            "corelink-staging": set(),
            "corelink-signup-staging": set(),
            "corelink-synthetic-pager-staging": set(),
        }

    def test_b216_alert_secret_pair_is_explicit_and_signup_only(self) -> None:
        environment = self._b216_environment()
        names = self._empty_worker_secret_names()
        with self.assertRaisesRegex(RuntimeError, "explicit protected opt-in"):
            provider.plan_missing_secret_values(names, environment)

        plan = provider.plan_missing_secret_values(
            names, environment, enable_b216_alert=True
        )
        self.assertEqual(
            set(plan["corelink-signup-staging"]) & {
                "DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"
            },
            {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"},
        )
        self.assertEqual(
            plan["corelink-signup-staging"]["DSR_DLQ_ALERT_ENDPOINT"],
            environment["STAGING_DSR_DLQ_ALERT_ENDPOINT"],
        )
        self.assertEqual(
            plan["corelink-signup-staging"]["DSR_DLQ_ALERT_AUTH_TOKEN"],
            environment["STAGING_DSR_DLQ_ALERT_AUTH_TOKEN"],
        )
        for worker in ("corelink-staging", "corelink-synthetic-pager-staging"):
            self.assertFalse(set(plan[worker]) & {
                "DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"
            })

    def test_b216_alert_plan_rejects_partial_pair_and_wrong_worker(self) -> None:
        environment = self._b216_environment()
        partial = self._empty_worker_secret_names()
        partial["corelink-signup-staging"].add("DSR_DLQ_ALERT_ENDPOINT")
        with self.assertRaisesRegex(RuntimeError, "pair is incomplete"):
            provider.plan_missing_secret_values(
                partial, environment, enable_b216_alert=True
            )
        wrong_worker = self._empty_worker_secret_names()
        wrong_worker["corelink-staging"].add("DSR_DLQ_ALERT_ENDPOINT")
        with self.assertRaisesRegex(RuntimeError, "unexpected names"):
            provider.plan_missing_secret_values(
                wrong_worker, environment, enable_b216_alert=True
            )

    def test_b216_alert_plan_rejects_mismatched_endpoint_and_invalid_authority_host(self) -> None:
        environment = self._b216_environment()
        for endpoint, host in (
            ("http://alerts.example.invalid/", "alerts.example.invalid"),
            ("https://other.example.invalid/", "alerts.example.invalid"),
            ("https://alerts.example.invalid/events", "alerts.example.invalid"),
            ("https://user@alerts.example.invalid/", "alerts.example.invalid"),
            ("https://alerts.example.invalid/", "alerts.example.invalid:443"),
            ("https://alerts.example.invalid/", "alerts.example.invalid.workers.dev"),
        ):
            invalid = {
                **environment,
                "STAGING_DSR_DLQ_ALERT_ENDPOINT": endpoint,
                "STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST": host,
            }
            with self.subTest(endpoint=endpoint, host=host), self.assertRaisesRegex(
                RuntimeError, "owner-authorized HTTPS receiver root"
            ):
                provider.plan_missing_secret_values(
                    self._empty_worker_secret_names(), invalid, enable_b216_alert=True
                )
        for token in ("", " dedicated-receiver-bearer"):
            invalid = {**environment, "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN": token}
            with self.subTest(token=repr(token)), self.assertRaisesRegex(
                RuntimeError, "both B-216 staging alert secret sources are required"
            ):
                provider.plan_missing_secret_values(
                    self._empty_worker_secret_names(), invalid, enable_b216_alert=True
                )
        invalid = {
            **environment,
            "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN": "dedicated-receiver-bearer\nforged",
        }
        with self.assertRaisesRegex(RuntimeError, "bearer token is malformed"):
            provider.plan_missing_secret_values(
                self._empty_worker_secret_names(), invalid, enable_b216_alert=True
            )

    def test_b216_existing_exact_pair_is_idempotent_and_default_maintenance_tolerates_it(self) -> None:
        names = {
            "corelink-staging": {
                "CLERK_ISSUER_URL", "CLERK_SECRET_KEY", "CLOUDFLARE_ACCOUNT_ID",
                "CORELINK_ADMIN_AUTH_KEY", "CORELINK_ERASE_AUTH_KEY",
                "CORELINK_INTERNAL_AUTH_KEY", "PAT_SIGNING_KEY",
                "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
            },
            "corelink-signup-staging": {
                "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
                "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
                "DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN",
            },
            "corelink-synthetic-pager-staging": set(),
        }
        self.assertNotIn(
            "DSR_DLQ_ALERT_ENDPOINT",
            provider.plan_missing_secret_values(names, {})["corelink-signup-staging"],
        )
        with self.assertRaisesRegex(RuntimeError, "explicit protected opt-in"):
            provider.plan_missing_secret_values(
                names, self._b216_environment()
            )
        repeat = provider.plan_missing_secret_values(
            names, self._b216_environment(), enable_b216_alert=True
        )
        self.assertNotIn("DSR_DLQ_ALERT_ENDPOINT", repeat["corelink-signup-staging"])
        self.assertNotIn("DSR_DLQ_ALERT_AUTH_TOKEN", repeat["corelink-signup-staging"])

    def test_b216_readback_tolerates_only_the_complete_signup_pair(self) -> None:
        topology = renderer.StagingTopologyAdapter.from_file()
        required = provider.expected_worker_bindings(topology, "corelink-signup-staging")
        pair = {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}

        def read(names: set[str]) -> None:
            payload = {
                "result": {
                    "bindings": [
                        {
                            "name": name,
                            **({"text": "staging"} if name == "ENVIRONMENT" else {}),
                            **(
                                {"text": "https://" + "a" * 32 + ".r2.cloudflarestorage.com"}
                                if name == "R2_S3_ENDPOINT"
                                else {}
                            ),
                        }
                        for name in names
                    ]
                }
            }
            with patch.dict(
                os.environ,
                {"STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com"},
            ), patch.object(provider, "get", return_value=payload):
                provider.read_worker_bindings(
                    topology, "token", custom_domain.ACCOUNT_ID,
                    "corelink-signup-staging",
                )

        read(required | pair)
        with self.assertRaisesRegex(RuntimeError, "outside the explicit signup-only scope"):
            read(required | {"DSR_DLQ_ALERT_ENDPOINT"})
        with self.assertRaisesRegex(RuntimeError, "do not match the typed topology"):
            read(required | pair | {"ENVIRONMENT_EXTRA"})

    def test_b216_readback_receipt_requires_exact_fresh_route_and_owner_ack(self) -> None:
        host = "alerts.example.invalid"
        sha = "a" * 40
        receipt = {
            "schema_version": 1,
            "repository": "HuGR-dev/corelink-server",
            "ref": "refs/heads/main",
            "sha": sha,
            "account_id": "51284495e71acdb5a7677e7383ab026b",
            "worker_name": "corelink-dsr-b216-alert-receiver-20260927",
            "captured_at": "2026-09-30T12:00:00.000Z",
            "status": "complete",
            "worker": {"exists": True, "inventory_count": 1},
            "routes": {
                "status": "known",
                "count": 1,
                "pattern_sha256": [hashlib.sha256(f"{host}/*".encode()).hexdigest()],
            },
            "subdomain": {"status": "known", "enabled": False, "previews_enabled": False},
        }
        owner_ack = "https://github.com/HuGR-dev/corelink-server/issues/1678#issuecomment-123"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            raw = json.dumps(receipt, sort_keys=True).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            now = datetime(2026, 9, 30, 12, 10, tzinfo=timezone.utc)
            evidence = provider.validate_b216_alert_authority(
                path, digest, owner_ack, f"https://{host}/", sha, now=now
            )
            self.assertEqual(evidence["receipt_sha256"], digest)
            for mutation in (
                {"account_id": "6a1fc1c626fc2628823e60b9db01f5cd"},
                {"sha": "b" * 40},
                {"subdomain": {"status": "known", "enabled": True, "previews_enabled": False}},
                {"routes": {"status": "known", "count": 0, "pattern_sha256": []}},
                {"captured_at": "2026-09-30T11:29:00.000Z"},
            ):
                changed = {**receipt, **mutation}
                path.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    provider.validate_b216_alert_authority(
                        path, hashlib.sha256(path.read_bytes()).hexdigest(),
                        owner_ack, f"https://{host}/", sha, now=now,
                    )
            path.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, "owner acknowledgement"):
                provider.validate_b216_alert_authority(
                    path, digest, "not-an-issue-reference", f"https://{host}/", sha, now=now
                )

    def test_b216_opt_in_without_authority_stops_before_provider_reads(self) -> None:
        environment = {
            "STAGING_CF_WORKER_API_TOKEN": "worker-token",
            "STAGING_CF_ROUTE_READ_TOKEN": "route-token",
            "STAGING_CF_ACCOUNT_ID": custom_domain.ACCOUNT_ID,
            "CF_ZONE_ID": custom_domain.ZONE_ID,
            "STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            **self._b216_environment(),
        }
        with patch.dict(os.environ, environment, clear=True), patch.object(
            provider, "get"
        ) as get, patch.object(provider.subprocess, "run") as run:
            with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
                RuntimeError, "authority readback is required"
            ):
                provider.apply_existing_secret_updates(
                    Path(temporary), Path(temporary) / "receipt.json", "12", "a" * 40,
                    enable_b216_alert=True,
                )
        get.assert_not_called()
        run.assert_not_called()

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

    # Existing-Worker read-only preflight (#2167 / #1700). Every provider read
    # is a mocked GET response; no request leaves the process.
    _ROOT_NAMES = {
        "CLERK_ISSUER_URL", "CLERK_SECRET_KEY", "CLOUDFLARE_ACCOUNT_ID",
        "CORELINK_ADMIN_AUTH_KEY", "CORELINK_ERASE_AUTH_KEY",
        "CORELINK_INTERNAL_AUTH_KEY", "PAT_SIGNING_KEY",
        "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
    }
    _SIGNUP_NAMES = {
        "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
        "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
    }
    _SOURCE_VALUE = "source-secret-value-must-never-be-read"

    def _run_preflight(
        self,
        scripts: object,
        secrets_by_worker: dict[str, object] | None = None,
        *flags: str,
    ) -> tuple[int, str, str, list[str]]:
        account, zone = custom_domain.ACCOUNT_ID, custom_domain.ZONE_ID
        responses: dict[str, dict] = {
            f"zones/{zone}": {
                "success": True,
                "result": {"name": "humangr.com", "account": {"id": account}},
            },
            f"zones/{zone}/workers/routes": {"success": True, "result": []},
            f"accounts/{account}/workers/scripts": {"success": True, "result": scripts},
        }
        for worker, rows in (secrets_by_worker or {}).items():
            responses[f"accounts/{account}/workers/scripts/{worker}/secrets"] = {
                "success": True,
                "result": rows,
            }
        paths: list[str] = []

        def fake_get(_token: str, path: str) -> dict:
            paths.append(path)
            if path not in responses:
                raise RuntimeError("Cloudflare staging readback failed")
            return responses[path]

        environment = {
            "STAGING_CF_API_TOKEN": "read-only-token",
            "STAGING_CF_ACCOUNT_ID": account,
            "CF_ZONE_ID": zone,
            "STAGING_R2_S3_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "STAGING_CLERK_SECRET_KEY": self._SOURCE_VALUE,
            "STAGING_R2_S3_SECRET_ACCESS_KEY": self._SOURCE_VALUE,
        }
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment, clear=True), patch.object(
            provider, "get", side_effect=fake_get
        ), patch.object(provider.subprocess, "run") as run, patch.object(
            provider.secrets, "token_hex"
        ) as token_hex, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = provider.main(["--phase", "preflight", *flags])
        run.assert_not_called()
        token_hex.assert_not_called()
        return code, stdout.getvalue(), stderr.getvalue(), paths

    @staticmethod
    def _secret_rows(names: set[str]) -> list[dict[str, str]]:
        return [{"name": name, "type": "secret_text"} for name in sorted(names)]

    def _all_workers(self) -> list[dict[str, str]]:
        workers = renderer.StagingTopologyAdapter.from_file().workers
        return [{"id": "unrelated-worker"}, *({"id": worker} for worker in workers)]

    def test_create_gate_preflight_still_refuses_existing_workers(self) -> None:
        code, stdout, stderr, paths = self._run_preflight(self._all_workers())
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("already exist; refusing to overwrite them", stderr)
        self.assertFalse(any(path.endswith("/secrets") for path in paths))

    def test_existing_worker_plan_is_a_name_only_delta(self) -> None:
        root_present = self._ROOT_NAMES - {"PAT_SIGNING_KEY", "R2_S3_SECRET_ACCESS_KEY"}
        signup_present = self._SIGNUP_NAMES - {"CLERK_WEBHOOK_SECRET"}
        code, stdout, stderr, paths = self._run_preflight(
            self._all_workers(),
            {
                "corelink-staging": self._secret_rows(root_present),
                "corelink-signup-staging": self._secret_rows(signup_present),
                "corelink-synthetic-pager-staging": [],
            },
            "--existing-worker-plan",
        )
        self.assertEqual(code, 0, stderr)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["existing_workers"], "all-present")
        self.assertEqual(receipt["next_operation"], "update-existing-secrets")
        self.assertIs(receipt["provider_mutation_performed"], False)
        self.assertIs(receipt["secret_values_read"], False)
        self.assertEqual(receipt["worker_count"], 3)
        self.assertEqual(
            receipt["update_existing_secrets_plan"],
            {
                "corelink-staging": {
                    "secret_names": sorted(root_present),
                    "missing_secret_names": ["PAT_SIGNING_KEY", "R2_S3_SECRET_ACCESS_KEY"],
                },
                "corelink-signup-staging": {
                    "secret_names": sorted(signup_present),
                    "missing_secret_names": ["CLERK_WEBHOOK_SECRET"],
                },
                "corelink-synthetic-pager-staging": {
                    "secret_names": [],
                    "missing_secret_names": [],
                },
            },
        )
        self.assertNotIn(self._SOURCE_VALUE, stdout + stderr)
        self.assertNotIn("read-only-token", stdout + stderr)
        account = custom_domain.ACCOUNT_ID
        self.assertEqual(
            sorted(path for path in paths if path.endswith("/secrets")),
            sorted(
                f"accounts/{account}/workers/scripts/{worker}/secrets"
                for worker in renderer.StagingTopologyAdapter.from_file().workers
            ),
        )

    def test_existing_worker_plan_accepts_complete_names_and_exact_b216_pair(self) -> None:
        code, stdout, stderr, _ = self._run_preflight(
            self._all_workers(),
            {
                "corelink-staging": self._secret_rows(self._ROOT_NAMES),
                "corelink-signup-staging": self._secret_rows(
                    self._SIGNUP_NAMES | {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
                ),
                "corelink-synthetic-pager-staging": [],
            },
            "--existing-worker-plan",
        )
        self.assertEqual(code, 0, stderr)
        plan = json.loads(stdout)["update_existing_secrets_plan"]
        self.assertEqual(
            {worker: entry["missing_secret_names"] for worker, entry in plan.items()},
            {
                "corelink-staging": [],
                "corelink-signup-staging": [],
                "corelink-synthetic-pager-staging": [],
            },
        )

    def test_existing_worker_plan_fails_closed_on_ambiguous_state(self) -> None:
        workers = renderer.StagingTopologyAdapter.from_file().workers
        complete = {
            "corelink-staging": self._secret_rows(self._ROOT_NAMES),
            "corelink-signup-staging": self._secret_rows(self._SIGNUP_NAMES),
            "corelink-synthetic-pager-staging": [],
        }
        cases = {
            "partial Worker set": (
                [{"id": workers[0]}, {"id": workers[1]}],
                complete,
                "only partially present",
            ),
            "unapproved secret name": (
                self._all_workers(),
                {**complete, "corelink-staging": self._secret_rows(self._ROOT_NAMES | {"CF_API_TOKEN"})},
                "unapproved staging secret name",
            ),
            "B-216 pair on the wrong Worker": (
                self._all_workers(),
                {
                    **complete,
                    "corelink-staging": self._secret_rows(
                        self._ROOT_NAMES | {"DSR_DLQ_ALERT_ENDPOINT", "DSR_DLQ_ALERT_AUTH_TOKEN"}
                    ),
                },
                "unapproved staging secret name",
            ),
            "partial B-216 pair": (
                self._all_workers(),
                {
                    **complete,
                    "corelink-signup-staging": self._secret_rows(
                        self._SIGNUP_NAMES | {"DSR_DLQ_ALERT_ENDPOINT"}
                    ),
                },
                "pair is incomplete",
            ),
            "shared secret on one Worker": (
                self._all_workers(),
                {
                    **complete,
                    "corelink-signup-staging": self._secret_rows(
                        self._SIGNUP_NAMES - {"CORELINK_INTERNAL_AUTH_KEY"}
                    ),
                },
                "present on only one Worker",
            ),
            "malformed secret inventory": (
                self._all_workers(),
                {**complete, "corelink-signup-staging": {"names": ["CLERK_SECRET_KEY"]}},
                "incomplete or unbounded",
            ),
            "duplicate secret name": (
                self._all_workers(),
                {
                    **complete,
                    "corelink-staging": [
                        *self._secret_rows(self._ROOT_NAMES),
                        {"name": "PAT_SIGNING_KEY", "type": "secret_text"},
                    ],
                },
                "contains duplicates",
            ),
            "unreadable secret inventory": (
                self._all_workers(),
                {key: value for key, value in complete.items() if key != "corelink-synthetic-pager-staging"},
                "readback failed",
            ),
        }
        for label, (scripts, secrets_by_worker, message) in cases.items():
            with self.subTest(case=label):
                code, stdout, stderr, _ = self._run_preflight(
                    scripts, secrets_by_worker, "--existing-worker-plan"
                )
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn(message, stderr)

    def test_preflight_refuses_a_malformed_worker_listing(self) -> None:
        for flags in ((), ("--existing-worker-plan",)):
            for scripts in ({"items": []}, ["corelink-staging"], [{"id": None}]):
                with self.subTest(flags=flags, scripts=scripts):
                    code, stdout, stderr, _ = self._run_preflight(scripts, None, *flags)
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout, "")
                    self.assertIn("Worker script inventory is malformed", stderr)

    def test_existing_worker_plan_without_workers_points_to_the_create_path(self) -> None:
        code, stdout, stderr, paths = self._run_preflight(
            [{"id": "unrelated-worker"}], None, "--existing-worker-plan"
        )
        self.assertEqual(code, 0, stderr)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["existing_workers"], "absent")
        self.assertEqual(receipt["next_operation"], "quarantine-apply")
        self.assertEqual(receipt["worker_count"], 0)
        self.assertNotIn("update_existing_secrets_plan", receipt)
        self.assertFalse(any(path.endswith("/secrets") for path in paths))

    def test_existing_worker_plan_flag_is_preflight_only(self) -> None:
        for phase in ("quarantine", "postflight", "update-existing-preflight", "update-existing-apply"):
            with self.subTest(phase=phase), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit
            ) as raised:
                provider.main(["--phase", phase, "--existing-worker-plan"])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
