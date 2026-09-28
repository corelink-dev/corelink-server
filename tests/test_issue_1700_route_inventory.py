"""Acceptance cases for the shared, fail-closed #1700 route inventory gate."""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from scripts import verify_issue_1700_route_inventory as routes


def zone_envelope(
    result: Any, *, total_pages: int = 1, total_count: int | None = None
) -> dict[str, Any]:
    count = len(result) if isinstance(result, list) else 0
    # Cloudflare's filtered zone endpoint reports an unfiltered total_count.
    return {
        "success": True,
        "result": result,
        "result_info": {
            "page": 1,
            "per_page": routes.ZONE_PAGE_SIZE,
            "count": count,
            "total_count": count if total_count is None else total_count,
            "total_pages": total_pages,
        },
    }


def route_envelope(result: Any, *, metadata: bool = False) -> dict[str, Any]:
    payload = {"success": True, "result": result}
    if metadata:
        count = len(result) if isinstance(result, list) else 0
        payload["result_info"] = {
            "page": 1,
            "per_page": routes.MAX_ITEMS,
            "count": count,
            "total_count": count,
            "total_pages": 1,
        }
    return payload


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
        inventory = route_envelope(
            [
                {"id": "a" * 32, "pattern": "api.humangr.com/*", "script": "other"},
                {
                    "id": "b" * 32,
                    "pattern": "staging.corelink.humangr.com/api",
                    "script": None,
                },
            ]
        )
        with self.assertRaises(routes.InventoryError):
            routes.verify_route_free_from_payloads(zone_envelope([zone()]), inventory)

    def test_empty_inventory_and_unrelated_routes_are_route_free(self) -> None:
        result = routes.verify_route_free_from_payloads(
            zone_envelope([zone()]),
            route_envelope(
                [
                    {
                        "id": "a" * 32,
                        "pattern": "api.humangr.com/*",
                        "script": "other",
                    },
                    {"id": "b" * 32, "pattern": "cdn.humangr.com/*"},
                ]
            ),
        )
        self.assertEqual(result, {"route_count": 2, "canonical_staging_route_count": 0})
        self.assertEqual(
            routes.verify_route_free_from_payloads(
                zone_envelope([zone()]), route_envelope([])
            ),
            {"route_count": 0, "canonical_staging_route_count": 0},
        )
        self.assertEqual(
            routes.verify_route_free_from_payloads(
                zone_envelope([zone()]),
                route_envelope(
                    [{"id": "c" * 32, "pattern": "api.humangr.com/*"}],
                    metadata=True,
                ),
            )["canonical_staging_route_count"],
            0,
        )

    def test_malformed_route_entries_and_metadata_reject(self) -> None:
        for item in (
            None,
            {},
            {"id": "a" * 32, "script": "api"},
            {"id": "a" * 32, "pattern": "api.humangr.com/*", "script": []},
            {"id": "a" * 32, "pattern": "api.humangr.com/*", "script": 42},
            {"id": "", "pattern": "api.humangr.com/*", "script": None},
        ):
            with self.subTest(item=item), self.assertRaises(routes.InventoryError):
                routes.validate_route_inventory(route_envelope([item]))
        incomplete_metadata = route_envelope([], metadata=True)
        incomplete_metadata["result_info"] = {"page": 1}
        null_metadata = route_envelope([])
        null_metadata["result_info"] = None
        for bad in (
            {"success": False, "result": []},
            {"success": True, "result": None},
            incomplete_metadata,
            null_metadata,
        ):
            with self.subTest(bad=bad), self.assertRaises(routes.InventoryError):
                routes.validate_route_inventory(bad)

    def test_zone_identity_and_completeness_reject_ambiguous_inputs(self) -> None:
        bad_payloads = (
            zone_envelope([]),
            zone_envelope([zone(), zone()]),
            zone_envelope([zone(account_id="b" * 32)]),
            zone_envelope([zone(name="other.humangr.com")]),
            {"success": False, "result": [zone()], "result_info": {}},
            {"success": True, "result": [zone()]},
            zone_envelope([zone()], total_pages=2),
            zone_envelope([zone()], total_count=0),
        )
        for payload in bad_payloads:
            with (
                self.subTest(payload=payload),
                self.assertRaises(routes.InventoryError),
            ):
                routes.validate_zone_inventory(payload)

    def test_filtered_zone_count_may_be_below_unfiltered_total_count(self) -> None:
        self.assertEqual(
            routes.validate_zone_inventory(zone_envelope([zone()], total_count=2)),
            "a" * 32,
        )

    def test_provider_request_uses_zone_limit_and_unpaginated_route_schema(
        self,
    ) -> None:
        responses = [
            zone_envelope([zone()]),
            route_envelope(
                [{"id": "b" * 32, "pattern": "api.humangr.com/*", "script": "api"}]
            ),
        ]
        requested: list[str] = []

        def fake_urlopen(request: Any, timeout: int) -> io.BytesIO:
            requested.append(request.full_url)
            return io.BytesIO(json.dumps(responses.pop(0)).encode())

        with patch.object(routes.urllib.request, "urlopen", side_effect=fake_urlopen):
            receipt = routes.verify_route_free("test-only-placeholder")

        self.assertEqual(receipt["canonical_staging_route_count"], 0)
        zone_request, route_request = map(urlsplit, requested)
        self.assertEqual(parse_qs(zone_request.query)["per_page"], ["50"])
        self.assertEqual(parse_qs(zone_request.query)["name"], [routes.ZONE_NAME])
        self.assertEqual(
            route_request.path,
            "/client/v4/zones/" + "a" * 32 + "/workers/routes",
        )
        self.assertEqual(route_request.query, "")

    def test_both_workflow_phases_call_the_shared_helper(self) -> None:
        workflow = Path(
            ".github/workflows/issue-1700-container-staging-deploy.yml"
        ).read_text()
        self.assertEqual(
            workflow.count("python3 scripts/verify_issue_1700_route_inventory.py"), 5
        )
        for receipt in (
            "staging-route-inventory-before.json",
            "staging-route-inventory-after.json",
            "staging-route-inventory-after-rollback.json",
            "staging-route-inventory-after-runtime-probe.json",
            "staging-runtime-routes-after-rollback.json",
        ):
            self.assertIn(receipt, workflow)
        self.assertNotIn("def canonical(route)", workflow)


if __name__ == "__main__":
    unittest.main()
