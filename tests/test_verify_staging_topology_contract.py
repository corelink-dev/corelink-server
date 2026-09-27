from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_staging_topology_contract.py"
spec = importlib.util.spec_from_file_location("staging_topology", SCRIPT)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


class StagingTopologyContractTests(unittest.TestCase):
    def fixture(self) -> tempfile.TemporaryDirectory[str]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for relative in (
            verifier.CONTRACT,
            verifier.RECEIPT,
            verifier.ROOT_WRANGLER,
            verifier.LOAD_WORKFLOW,
            verifier.ENDURANCE_WORKFLOW,
            verifier.SYNTHETIC_RECEIVER_WRANGLER,
            verifier.SIGNUP_WRANGLER,
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temp

    def mutate_contract(self, callback) -> list[str]:
        temp = self.fixture()
        with temp:
            root = Path(temp.name)
            path = root / verifier.CONTRACT
            data = json.loads(path.read_text())
            callback(data)
            path.write_text(json.dumps(data), encoding="utf-8")
            return verifier.assess(root)

    def mutate_receipt(self, callback) -> list[str]:
        temp = self.fixture()
        with temp:
            root = Path(temp.name)
            path = root / verifier.RECEIPT
            data = json.loads(path.read_text())
            callback(data)
            path.write_text(json.dumps(data), encoding="utf-8")
            return verifier.assess(root)

    def test_repository_contract_is_ready_to_provision(self) -> None:
        self.assertEqual(verifier.assess(ROOT), [])

    def test_each_resource_family_is_closed(self) -> None:
        mutations = {
            "worker:root_worker": lambda d: d["cloudflare"].__setitem__("root_worker", "corelink-prod"),
            "container": lambda d: d["cloudflare"]["container"].__setitem__("max_instances", 200),
            "root-worker-settings": lambda d: d["cloudflare"]["root_worker_settings"].__setitem__("workers_dev", True),
            "canonical-custom-domain": lambda d: d["cloudflare"]["routes"][0].__setitem__("custom_domain", False),
            "binding-family:d1": lambda d: d["cloudflare"]["d1"][0]["bindings"].pop(),
            "binding-family:r2": lambda d: d["cloudflare"]["r2"].pop(),
            "binding-family:kv": lambda d: d["cloudflare"]["kv"].pop(),
            "binding-family:do": lambda d: d["cloudflare"]["durable_objects"].pop(),
            "binding-family:queues": lambda d: d["cloudflare"]["queues"].clear(),
            "binding-family:services": lambda d: d["cloudflare"]["service_bindings"].clear(),
        }
        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.mutate_contract(mutation))

    def test_resource_reuse_and_secret_values_fail_closed(self) -> None:
        self.assertIn(
            "resource-reuses-non-staging-name",
            self.mutate_contract(lambda d: d["cloudflare"]["r2"][0].__setitem__("bucket_name", "corelink-cas-prod")),
        )
        self.assertIn(
            "embedded-secret-value-field",
            self.mutate_contract(lambda d: d.__setitem__("token_value", "must-never-be-here")),
        )
        self.assertIn(
            "provider-resource-ids:d1",
            self.mutate_contract(lambda d: d["cloudflare"]["d1"][0].__setitem__("database_id", "invented")),
        )

    def test_partial_root_environment_is_rejected(self) -> None:
        temp = self.fixture()
        with temp:
            root = Path(temp.name)
            path = root / verifier.ROOT_WRANGLER
            path.write_text(path.read_text() + '\n[env.staging]\nname = "corelink-staging"\n')
            self.assertIn("partial-or-unrendered-root-staging-env", verifier.assess(root))

    def test_receiver_database_id_and_deployment_state_fail_closed(self) -> None:
        temp = self.fixture()
        with temp:
            root = Path(temp.name)
            path = root / verifier.SYNTHETIC_RECEIVER_WRANGLER
            path.write_text(
                path.read_text().replace(
                    verifier.CONFIG_DB_ID,
                    "11111111-1111-1111-1111-111111111111",
                )
            )
            gaps = verifier.assess(root)
            self.assertIn("synthetic-receiver-staging-d1", gaps)

        self.assertIn(
            "deployment-state-must-remain-unprovisioned",
            self.mutate_contract(lambda d: d.__setitem__("deployment_state", "provisioned")),
        )

    def test_provider_readback_and_each_real_id_fail_closed(self) -> None:
        mutations = {
            "provider-resource-state": lambda d: d.__setitem__("provider_resource_state", "unprovisioned"),
            "provider-resource-ids:d1": lambda d: d["cloudflare"]["d1"][0].__setitem__("location", "WEUR"),
            "provider-resource-ids:kv": lambda d: d["cloudflare"]["kv"][0].__setitem__("namespace_id", "invented"),
            "provider-resource-ids:queues": lambda d: d["cloudflare"]["queues"][0].__setitem__("queue_id", "invented"),
            "provider-resource-location:r2": lambda d: d["cloudflare"]["r2"][0].__setitem__("location", "WEUR"),
            "provider-readback": lambda d: d["provider_readback"]["dns"].__setitem__("state", "ready"),
        }
        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.mutate_contract(mutation))

    def test_provider_receipt_is_bound_and_empty_readbacks_fail_closed(self) -> None:
        self.assertIn(
            "provider-receipt-binding",
            self.mutate_contract(lambda d: d.__setitem__("provider_receipt", "evidence/elsewhere.json")),
        )
        mutations = {
            "provider-receipt-d1": lambda d: d["resources"]["d1"][0].__setitem__("user_table_count", 1),
            "provider-receipt-r2": lambda d: d["resources"]["r2"][0].__setitem__("object_count", 1),
            "provider-receipt-kv": lambda d: d["resources"]["kv"][0].__setitem__("key_count", 1),
            "provider-receipt-queues": lambda d: d["resources"]["queues"][0].__setitem__("consumer_count", 1),
            "provider-receipt-workers": lambda d: d["workers"].__setitem__("corelink-staging", "deployed"),
            "provider-receipt-dns": lambda d: d["dns"].__setitem__("public_dns_result", "resolved"),
            "provider-receipt-secrets": lambda d: d["secrets"].__setitem__("bindings_claimed", True),
            "provider-receipt-claims": lambda d: d["readback"].__setitem__("workers_deployed", True),
        }
        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.mutate_receipt(mutation))

    def test_every_root_non_inherited_var_is_required(self) -> None:
        for key in verifier.EXPECTED_ROOT_SETTINGS["vars"]:
            with self.subTest(key=key):
                self.assertIn(
                    "root-worker-settings",
                    self.mutate_contract(
                        lambda d, key=key: d["cloudflare"]["root_worker_settings"]["vars"].pop(key)
                    ),
                )

    def test_signup_vars_and_hourly_trigger_are_required(self) -> None:
        for key in (
            "ENVIRONMENT",
            "CORELINK_API_BASE",
            "SLA_CREDITS_ENABLED",
            "SLA_OBSERVATIONS_ENABLED",
        ):
            with self.subTest(key=key):
                self.assertIn(
                    "signup-worker-settings",
                    self.mutate_contract(
                        lambda d, key=key: d["cloudflare"]["signup_worker_settings"]["vars"].pop(key)
                    ),
                )
                self.assertIn(
                    "signup-worker-settings",
                    self.mutate_contract(
                        lambda d, key=key: d["cloudflare"]["signup_worker_settings"]["vars"].__setitem__(key, "mutated")
                    ),
                )
        self.assertIn(
            "signup-worker-settings",
            self.mutate_contract(
                lambda d: d["cloudflare"]["signup_worker_settings"].__setitem__("crons", [])
            ),
        )

    def test_receiver_real_config_settings_vars_and_cron_are_pinned(self) -> None:
        mutations = {
            "synthetic-receiver-source-settings": ("workers_dev = false", "workers_dev = true"),
            "synthetic-receiver-source-settings-compat": (
                'compatibility_date = "2026-04-01"',
                'compatibility_date = "2025-01-01"',
            ),
            "synthetic-receiver-staging-vars": (
                'SYNTHETIC_DRILL_ENABLED = "false"',
                'SYNTHETIC_DRILL_ENABLED = "true"',
            ),
            "synthetic-receiver-staging-vars-environment": (
                'ENVIRONMENT = "staging"',
                'ENVIRONMENT = "prod"',
            ),
            "synthetic-receiver-staging-vars-provider-mode": (
                'SYNTHETIC_DRILL_PROVIDER_MODE = "provider_deferred"',
                'SYNTHETIC_DRILL_PROVIDER_MODE = "pagerduty"',
            ),
            "synthetic-receiver-staging-crons": (
                'crons = ["59 23 * * 1"]',
                'crons = []',
            ),
        }
        for case, (old, new) in mutations.items():
            with self.subTest(case=case):
                temp = self.fixture()
                with temp:
                    root = Path(temp.name)
                    path = root / verifier.SYNTHETIC_RECEIVER_WRANGLER
                    text = path.read_text()
                    self.assertIn(old, text)
                    path.write_text(text.replace(old, new))
                    gaps = verifier.assess(root)
                    expected = case.removesuffix("-compat")
                    for suffix in ("-environment", "-provider-mode"):
                        expected = expected.removesuffix(suffix)
                    self.assertIn(expected, gaps)

    def test_every_resource_family_pins_worker_ownership(self) -> None:
        mutations = {
            "container": lambda d: d["cloudflare"]["container"].__setitem__("worker", "corelink-prod"),
            "canonical-custom-domain": lambda d: d["cloudflare"]["routes"][0].__setitem__("worker", "corelink-prod"),
            "binding-family:d1": lambda d: d["cloudflare"]["d1"][0]["bindings"][0].__setitem__("worker", "corelink-prod"),
            "binding-family:r2": lambda d: d["cloudflare"]["r2"][0].__setitem__("worker", "corelink-prod"),
            "binding-family:kv": lambda d: d["cloudflare"]["kv"][0].__setitem__("worker", "corelink-prod"),
            "binding-family:do": lambda d: d["cloudflare"]["durable_objects"][0].__setitem__("worker", "corelink-prod"),
            "binding-family:queues": lambda d: d["cloudflare"]["queues"][0].__setitem__("consumer_worker", "corelink-prod"),
            "binding-family:services": lambda d: d["cloudflare"]["service_bindings"][0].__setitem__("worker", "corelink-prod"),
        }
        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.mutate_contract(mutation))

    def test_both_load_workflows_pin_exact_origin(self) -> None:
        for relative in (verifier.LOAD_WORKFLOW, verifier.ENDURANCE_WORKFLOW):
            with self.subTest(relative=relative):
                temp = self.fixture()
                with temp:
                    root = Path(temp.name)
                    path = root / relative
                    path.write_text(path.read_text().replace(verifier.CANONICAL_ORIGIN, "https://api-staging.corelink.humangr.com"))
                    gaps = verifier.assess(root)
                    self.assertIn(f"workflow-canonical-target:{relative.name}", gaps)


if __name__ == "__main__":
    unittest.main()
