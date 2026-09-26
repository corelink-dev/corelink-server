"""Hosted contract and mutation coverage for the staging topology renderer."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts import render_staging_wrangler as renderer


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"


class StagingTopologyAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = json.loads(renderer.TOPOLOGY.read_text(encoding="utf-8"))

    def assert_rejected(self, mutated: dict) -> None:
        with self.assertRaises(renderer.ContractError):
            renderer.StagingTopologyAdapter.from_mapping(mutated)

    def test_accepts_only_top_level_canonical_origin(self) -> None:
        adapter = renderer.StagingTopologyAdapter.from_mapping(self.raw)
        self.assertEqual(adapter.canonical_origin, "https://staging.corelink.humangr.com")

        nested_only = copy.deepcopy(self.raw)
        nested_only.pop("canonical_origin")
        nested_only["cloudflare"]["canonical_origin"] = "https://staging.corelink.humangr.com"
        self.assert_rejected(nested_only)

        stale_nested = copy.deepcopy(self.raw)
        stale_nested["cloudflare"]["canonical_origin"] = "https://old-staging.corelink.humangr.com"
        self.assert_rejected(stale_nested)

    def test_rejects_missing_conflicting_and_unsafe_origins(self) -> None:
        mutations = {
            "missing": lambda value: value.pop("canonical_origin"),
            "stale_output": lambda value: value["outputs"].update(
                {"target_host": "https://old-staging.corelink.humangr.com"}
            ),
            "http": lambda value: value.update({"canonical_origin": "http://staging.corelink.humangr.com"}),
            "non_staging": lambda value: value.update({"canonical_origin": "https://preview.corelink.humangr.com"}),
            "production": lambda value: value.update({"canonical_origin": "https://api.production.humangr.com"}),
            "path": lambda value: value.update({"canonical_origin": "https://staging.corelink.humangr.com/private"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(origin_mutation=name):
                mutated = copy.deepcopy(self.raw)
                mutate(mutated)
                self.assert_rejected(mutated)


class StagingWranglerRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.topology = renderer.StagingTopologyAdapter.from_file(renderer.TOPOLOGY)

    def test_renders_three_isolated_configs_from_validated_topology(self) -> None:
        configs = {}
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "root.wrangler.toml"
            prior = os.environ.get("GITHUB_SHA")
            os.environ["GITHUB_SHA"] = "0123456789abcdef0123456789abcdef01234567"
            try:
                for worker in self.topology.workers:
                    configs[worker] = tomllib.loads(
                        renderer.render_worker(self.topology, worker, ENDPOINT, "final", output_path)
                    )
            finally:
                if prior is None:
                    del os.environ["GITHUB_SHA"]
                else:
                    os.environ["GITHUB_SHA"] = prior

        self.assertEqual(set(configs), set(self.topology.workers))
        for worker, config in configs.items():
            self.assertEqual(config["name"], worker)
            self.assertFalse(config["workers_dev"])
            self.assertNotIn("env", config)
            rendered = json.dumps(config).lower()
            self.assertNotIn("production", rendered)
            self.assertNotIn("prod.corelink", rendered)

        root = configs[self.topology.workers[0]]
        self.assertEqual(root["vars"]["R2_S3_ENDPOINT"], ENDPOINT)
        self.assertEqual(root["vars"]["SENTRY_RELEASE"], "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(len(root["routes"]), 1)
        self.assertNotIn("routes", configs[self.topology.workers[2]])
        self.assertEqual(configs[self.topology.workers[2]]["version_metadata"], {"binding": "CF_VERSION_METADATA"})
        self.assertNotIn("routes", configs[self.topology.workers[1]])
        self.assertEqual(
            {
                (route["pattern"], route["zone_name"])
                for config in configs.values()
                for route in config.get("routes", [])
            },
            {
                ("staging.corelink.humangr.com/*", "humangr.com"),
            },
        )
        self.assertEqual(
            {binding["binding"] for binding in configs[self.topology.workers[1]]["d1_databases"]},
            {"CONFIG_DB", "BILLING_DB"},
        )

    def test_bootstrap_render_has_no_routes_or_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "bootstrap.wrangler.toml"
            prior = os.environ.get("GITHUB_SHA")
            os.environ["GITHUB_SHA"] = "0123456789abcdef0123456789abcdef01234567"
            try:
                for worker in self.topology.workers:
                    rendered = renderer.render_worker(
                        self.topology, worker, ENDPOINT, "bootstrap", output_path
                    )
                    config = tomllib.loads(rendered)
                    self.assertNotIn("routes", config)
                    self.assertNotIn("[env.staging]", rendered)
                    self.assertNotIn("secret", rendered.lower())
                    for names in self.topology.required_secret_names.values():
                        for name in names:
                            self.assertNotIn(name, rendered)
            finally:
                if prior is None:
                    del os.environ["GITHUB_SHA"]
                else:
                    os.environ["GITHUB_SHA"] = prior

    def test_root_release_requires_exact_dispatch_sha(self) -> None:
        prior = os.environ.get("GITHUB_SHA")
        try:
            for value in ("", "unknown", "0123456789abcdef"):
                os.environ["GITHUB_SHA"] = value
                with self.subTest(value=value), self.assertRaises(renderer.ContractError):
                    renderer.render_worker(self.topology, self.topology.workers[0], ENDPOINT, "bootstrap", Path("/tmp/corelink-rendered.toml"))
        finally:
            if prior is None:
                os.environ.pop("GITHUB_SHA", None)
            else:
                os.environ["GITHUB_SHA"] = prior

    def test_rejects_missing_or_production_provider_endpoint(self) -> None:
        for endpoint in (
            "",
            "https://api.r2.cloudflarestorage.com",
            "https://production.r2.cloudflarestorage.com",
            "https://abc.r2.cloudflarestorage.com",
            "https://0123456789abcdef0123456789abcdef.extra.r2.cloudflarestorage.com",
            "http://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/path",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(renderer.ContractError):
                renderer.render_worker(
                    self.topology,
                    self.topology.workers[0],
                    endpoint,
                    "bootstrap",
                    Path("/tmp/corelink-rendered.toml"),
                )

    def test_rejects_route_set_mutations(self) -> None:
        for mutate in (
            lambda value: value["cloudflare"]["routes"].append(
                {
                    "worker": "corelink-staging",
                    "pattern": "staging.corelink.humangr.com/extra/*",
                    "zone_name": "humangr.com",
                }
            ),
            lambda value: value["cloudflare"]["routes"].pop(),
        ):
            mutated = copy.deepcopy(json.loads(renderer.TOPOLOGY.read_text(encoding="utf-8")))
            mutate(mutated)
            with self.subTest(routes=mutated["cloudflare"]["routes"]):
                with self.assertRaises(renderer.ContractError):
                    renderer.StagingTopologyAdapter.from_mapping(mutated)

    def test_cli_rejects_in_repository_output(self) -> None:
        result = renderer.main(
            [
                "--phase",
                "bootstrap",
                "--worker",
                "root",
                "--output",
                str(ROOT / "infra/staging/.rendered/root.toml"),
            ]
        )
        self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
