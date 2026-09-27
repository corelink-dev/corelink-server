"""Credentialless route inventory tests for the #1700 staging bootstrap."""

from __future__ import annotations

import unittest
import json
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts import render_staging_wrangler as renderer
from scripts import staging_bootstrap_provider as provider
from scripts import staging_custom_domain as custom_domain
from scripts import verify_staging_provider_preflight as preflight


class StagingBootstrapProviderTests(unittest.TestCase):
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
