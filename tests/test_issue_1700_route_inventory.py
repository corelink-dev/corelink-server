"""Acceptance cases for the shared, fail-closed #1700 route inventory gate."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from scripts import verify_issue_1700_route_inventory as routes


def envelope(
    result: Any, *, total_pages: int = 1, total_count: int | None = None
) -> dict[str, Any]:
    count = len(result) if isinstance(result, list) else 0
    return {
        "success": True,
        "result": result,
        "result_info": {
            "page": 1,
            "per_page": 1000,
            "count": count,
            "total_count": count if total_count is None else total_count,
            "total_pages": total_pages,
        },
    }


def zone(
    name: str = routes.ZONE_NAME, account_id: str = routes.ACCOUNT_ID
) -> dict[str, Any]:
    return {
        "id": "a" * 32,
        "name": name,
        "account": {"id": account_id},
    }


class Issue1700RouteGrammarTests(unittest.TestCase):
    def test_every_frozen_canonical_pattern_rejects(self) -> None:
        patterns = (
            "staging.corelink.humangr.com",
            "staging.corelink.humangr.com/",
            "staging.corelink.humangr.com/*",
            "staging.corelink.humangr.com/api/v2",
            "http://staging.corelink.humangr.com/*",
            "https://staging.corelink.humangr.com/api/*",
            "StAgInG.CoReLiNk.HuMaNgR.CoM/private/*",
            "*.corelink.humangr.com/*",
            "*corelink.humangr.com/*",
            "*.humangr.com/*",
            "*humangr.com/*",
            "*staging.corelink.humangr.com/*",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertTrue(routes.route_matches_canonical(pattern))

    def test_clear_unrelated_zone_patterns_pass(self) -> None:
        patterns = (
            "api.humangr.com/*",
            "*.api.humangr.com/*",
            "humangr.com/*",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertFalse(routes.route_matches_canonical(pattern))

    def test_malformed_or_unsupported_patterns_reject(self) -> None:
        patterns = (
            "",
            "ftp://api.humangr.com/*",
            "api.*.humangr.com/*",
            "api.**.humangr.com/*",
            "api.humangr.com/a*b",
            "api.humangr.com/a**",
            " api.humangr.com/*",
            "api.humangr.com/* ",
            "user@api.humangr.com/*",
            "api.humangr.com:443/*",
            "api.humangr.com/*?x=1",
            "api.humangr.com/*#fragment",
            "api.humangr.com\\*",
            "unicode-☃.humangr.com/*",
            "evil.example/*",
        )
        for pattern in patterns:
            with (
                self.subTest(pattern=pattern),
                self.assertRaises(routes.InventoryError),
            ):
                routes.route_matches_canonical(pattern)
        for pattern in (None, 1, {}):
            with (
                self.subTest(pattern=pattern),
                self.assertRaises(routes.InventoryError),
            ):
                routes.route_matches_canonical(pattern)

    def test_route_inventory_checks_all_routes_and_allows_null_worker(self) -> None:
        inventory = envelope(
            [
                {"id": "route-1", "pattern": "api.humangr.com/*", "script": "other"},
                {
                    "id": "route-2",
                    "pattern": "staging.corelink.humangr.com/api",
                    "script": None,
                },
            ]
        )
        with self.assertRaises(routes.InventoryError):
            routes.verify_route_free_from_payloads(envelope([zone()]), inventory)

    def test_empty_inventory_and_unrelated_routes_are_route_free(self) -> None:
        result = routes.verify_route_free_from_payloads(
            envelope([zone()]),
            envelope(
                [
                    {
                        "id": "route-1",
                        "pattern": "api.humangr.com/*",
                        "script": "other",
                    },
                ]
            ),
        )
        self.assertEqual(result, {"route_count": 1, "canonical_staging_route_count": 0})
        self.assertEqual(
            routes.verify_route_free_from_payloads(envelope([zone()]), envelope([])),
            {"route_count": 0, "canonical_staging_route_count": 0},
        )

    def test_malformed_route_entries_and_incomplete_pagination_reject(self) -> None:
        for item in (
            None,
            {},
            {"pattern": "api.humangr.com/*"},
            {"pattern": "api.humangr.com/*", "script": 42},
        ):
            with self.subTest(item=item), self.assertRaises(routes.InventoryError):
                routes.validate_route_inventory(envelope([item]))
        for bad in (
            {"success": False, "result": [], "result_info": {}},
            {"success": True, "result": None, "result_info": {}},
            {"success": True, "result": [], "result_info": {"page": 1}},
            envelope([], total_pages=2, total_count=1001),
        ):
            with self.subTest(bad=bad), self.assertRaises(routes.InventoryError):
                routes.validate_route_inventory(bad)

    def test_zone_identity_and_completeness_reject_ambiguous_inputs(self) -> None:
        bad_payloads = (
            envelope([]),
            envelope([zone(), zone()]),
            envelope([zone(account_id="b" * 32)]),
            envelope([zone(name="other.humangr.com")]),
            {"success": False, "result": [zone()], "result_info": {}},
            {"success": True, "result": [zone()], "result_info": {"page": 1}},
            envelope([zone()], total_pages=2, total_count=2),
        )
        for payload in bad_payloads:
            with (
                self.subTest(payload=payload),
                self.assertRaises(routes.InventoryError),
            ):
                routes.validate_zone_inventory(payload)

    def test_both_workflow_phases_call_the_shared_helper(self) -> None:
        workflow = Path(
            ".github/workflows/issue-1700-container-staging-deploy.yml"
        ).read_text()
        self.assertEqual(
            workflow.count("python3 scripts/verify_issue_1700_route_inventory.py"), 2
        )
        self.assertNotIn("def canonical(route)", workflow)


if __name__ == "__main__":
    unittest.main()
