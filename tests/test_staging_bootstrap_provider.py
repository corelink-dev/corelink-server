"""Credentialless route inventory tests for the #1700 staging bootstrap."""

from __future__ import annotations

import unittest

from scripts import render_staging_wrangler as renderer
from scripts import staging_bootstrap_provider as provider


class StagingBootstrapProviderTests(unittest.TestCase):
    def test_route_pairs_include_only_the_canonical_host(self) -> None:
        routes = [
            {
                "pattern": "staging.corelink.humangr.com/*",
                "script": "corelink-staging",
            },
            {"pattern": "other.humangr.com/*", "script": "other-worker"},
        ]
        self.assertEqual(
            provider.route_pairs(routes),
            {
                ("staging.corelink.humangr.com/*", "corelink-staging"),
            },
        )

    def test_route_pairs_reject_unsafe_staging_targets(self) -> None:
        for script in ("corelink-production", "corelink-prod", None):
            with self.subTest(script=script), self.assertRaises(RuntimeError):
                provider.route_pairs(
                    [{
                        "pattern": f"{renderer.CANONICAL_HOST}/*",
                        "script": script,
                    }]
                )

    def test_typed_renderer_owns_exact_route_contract(self) -> None:
        topology = renderer.StagingTopologyAdapter.from_file()
        expected = {
            (f"{renderer.CANONICAL_HOST}/*", topology.workers[0]),
        }
        configured = {
            (route["pattern"], route["worker"])
            for route in topology.cloudflare["routes"]
        }
        self.assertEqual(configured, expected)


if __name__ == "__main__":
    unittest.main()
