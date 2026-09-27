"""Credentialless tests for the closed #1700 Custom Domain publisher."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import staging_custom_domain as domain


def envelope(rows: list[dict], *, total: int | None = None) -> dict:
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": rows,
        "result_info": {
            "count": len(rows),
            "page": 1,
            "per_page": domain.DNS_PAGE_SIZE
            if total is None
            else domain.DOMAIN_PAGE_SIZE,
            "total_count": max(len(rows), total or len(rows)),
            "total_pages": 1,
        },
    }


def zone() -> dict:
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": {
            "id": domain.ZONE_ID,
            "name": domain.ZONE_NAME,
            "account": {"id": domain.ACCOUNT_ID},
        },
    }


def routes(rows: list[dict] | None = None) -> dict:
    return {"success": True, "errors": [], "messages": [], "result": rows or []}


def domain_rows(rows: list[dict] | None = None) -> dict:
    return envelope(rows or [], total=len(rows or []))


def dns_rows(rows: list[dict] | None = None) -> dict:
    result = rows or []
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {
            "count": len(result),
            "page": 1,
            "per_page": domain.DNS_PAGE_SIZE,
            "total_count": max(len(result), 12),
            "total_pages": 1,
        },
    }


def exact_domain(*, service: str = domain.WORKER) -> dict:
    return {
        "id": "a" * 32,
        "cert_id": "11111111-2222-4333-8444-555555555555",
        "hostname": domain.HOSTNAME,
        "service": service,
        "zone_id": domain.ZONE_ID,
        "zone_name": domain.ZONE_NAME,
    }


def exact_dns(*, proxied: bool = True) -> dict:
    return {
        "id": "b" * 32,
        "name": domain.HOSTNAME,
        "type": "CNAME",
        "content": "worker-managed.invalid",
        "proxied": proxied,
    }


def require_provider_guard_bindings(workflow: str) -> None:
    start = workflow.index("      - name: Confirm exact protected target and operation")
    end = workflow.find("\n      - name:", start + 1)
    step = workflow[start:] if end == -1 else workflow[start:end]
    env = step.split("\n        run:", 1)[0]
    expected = (
        "          STAGING_CF_ACCOUNT_ID: ${{ secrets.STAGING_CF_ACCOUNT_ID }}",
        "          CF_ZONE_ID: ${{ vars.CF_ZONE_ID }}",
    )
    missing = [binding for binding in expected if binding not in env]
    if missing:
        raise AssertionError(
            f"protected provider guard lacks exact bindings: {missing}"
        )


def subdomain(enabled: bool = False) -> dict:
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": {"enabled": enabled, "previews_enabled": False},
    }


def assess(
    domain_list: dict | None = None,
    dns_list: dict | None = None,
    route_list: dict | None = None,
    worker_domain_list: dict | None = None,
) -> dict:
    return domain.assess_state(
        zone(),
        route_list or routes(),
        domain_list or domain_rows(),
        dns_list or dns_rows(),
        worker_domain_list or subdomain(),
    )


class StagingCustomDomainTests(unittest.TestCase):
    def test_empty_state_is_a_preview_only_exact_attach_candidate(self) -> None:
        plan = assess()
        self.assertEqual(plan["action"], "attach-custom-domain")
        self.assertEqual(plan["hostname"], "staging.corelink.humangr.com")
        self.assertEqual(plan["worker"], "corelink-staging")
        self.assertEqual(plan["zone_id"], domain.ZONE_ID)
        self.assertEqual(plan["canonical_route_count"], 0)

    def test_exact_custom_domain_and_filtered_dns_are_idempotent(self) -> None:
        plan = assess(
            domain_rows([exact_domain()]),
            dns_rows([exact_dns()]),
        )
        self.assertEqual(plan["action"], "already-exact")
        self.assertEqual(plan["custom_domain_id"], "a" * 32)
        self.assertEqual(plan["dns_record_count"], 1)

    def test_worker_domain_filtered_response_allows_optional_total_pages(self) -> None:
        empty = domain_rows()
        del empty["result_info"]["total_pages"]
        self.assertEqual(domain.validate_domains(empty), [])

        one_filtered_result = domain_rows([exact_domain()])
        del one_filtered_result["result_info"]["total_pages"]
        one_filtered_result["result_info"]["total_count"] = 29
        self.assertEqual(domain.validate_domains(one_filtered_result), [exact_domain()])

    def test_worker_domain_optional_page_count_still_fails_closed_on_bad_bounds(
        self,
    ) -> None:
        missing_count = domain_rows()
        del missing_count["result_info"]["count"]
        with self.assertRaisesRegex(domain.DomainError, "incomplete"):
            domain.validate_domains(missing_count)

        multipage = domain_rows()
        multipage["result_info"]["total_pages"] = 2
        with self.assertRaisesRegex(domain.DomainError, "incomplete"):
            domain.validate_domains(multipage)

        count_mismatch = domain_rows([exact_domain()])
        del count_mismatch["result_info"]["total_pages"]
        count_mismatch["result_info"]["count"] = 0
        with self.assertRaisesRegex(domain.DomainError, "incomplete"):
            domain.validate_domains(count_mismatch)

    def test_dns_and_worker_domain_filtered_responses_allow_optional_total_pages(
        self,
    ) -> None:
        domain_payload = domain_rows()
        del domain_payload["result_info"]["total_pages"]
        self.assertEqual(domain.validate_domains(domain_payload), [])

        matching_domain = domain_rows([exact_domain()])
        del matching_domain["result_info"]["total_pages"]
        matching_domain["result_info"]["total_count"] = 29
        self.assertEqual(domain.validate_domains(matching_domain), [exact_domain()])

        dns_payload = dns_rows([exact_dns()])
        del dns_payload["result_info"]["total_pages"]
        self.assertEqual(domain.validate_dns(dns_payload), [exact_dns()])

        empty_dns = dns_rows()
        del empty_dns["result_info"]["total_pages"]
        self.assertEqual(domain.validate_dns(empty_dns), [])

    def test_optional_total_pages_still_fails_closed_for_incomplete_or_full_pages(
        self,
    ) -> None:
        for validator, payload in (
            (domain.validate_domains, domain_rows()),
            (domain.validate_dns, dns_rows()),
        ):
            with self.subTest(case="missing count"):
                broken = copy.deepcopy(payload)
                del broken["result_info"]["total_pages"]
                del broken["result_info"]["count"]
                with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                    validator(broken)

            with self.subTest(case="multipage"):
                broken = copy.deepcopy(payload)
                broken["result_info"]["total_pages"] = 2
                with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                    validator(broken)

            with self.subTest(case="null total_pages"):
                broken = copy.deepcopy(payload)
                broken["result_info"]["total_pages"] = None
                with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                    validator(broken)

            with self.subTest(case="count mismatch"):
                broken = copy.deepcopy(payload)
                broken["result_info"].pop("total_pages", None)
                broken["result"].append({})
                with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                    validator(broken)

            with self.subTest(case="total below filtered count"):
                broken = copy.deepcopy(payload)
                broken["result_info"].update({"count": 1, "total_count": 0})
                broken["result"].append({})
                with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                    validator(broken)

        for validator, payload, per_page in (
            (domain.validate_domains, domain_rows(), domain.DOMAIN_PAGE_SIZE),
            (domain.validate_dns, dns_rows(), domain.DNS_PAGE_SIZE),
        ):
            full_page = copy.deepcopy(payload)
            full_page["result"] = [object() for _ in range(per_page)]
            full_page["result_info"].update(
                {"count": per_page, "total_count": per_page}
            )
            full_page["result_info"].pop("total_pages", None)
            with self.assertRaisesRegex(domain.DomainError, "incomplete"):
                validator(full_page)

    def test_filtered_total_count_can_exceed_filtered_count(self) -> None:
        payload = dns_rows([exact_dns()])
        payload["result_info"]["total_count"] = 29
        self.assertEqual(len(domain.validate_dns(payload)), 1)

    def test_domain_without_dns_waits_without_reattach(self) -> None:
        plan = assess(domain_rows([exact_domain()]), dns_rows())
        self.assertEqual(plan["action"], "await-provider-dns")
        self.assertEqual(plan["custom_domain_id"], "a" * 32)

    def test_dns_without_exact_domain_is_a_conflict(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "already occupies"):
            assess(dns_list=dns_rows([exact_dns()]))

    def test_exact_host_mapping_to_another_worker_is_rejected(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "another Worker"):
            assess(
                domain_rows([exact_domain(service="corelink-prod")]),
                dns_rows([exact_dns()]),
            )

    def test_unproxied_existing_dns_is_rejected(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "unproxied"):
            assess(domain_rows([exact_domain()]), dns_rows([exact_dns(proxied=False)]))

    def test_multiple_dns_records_are_rejected_as_ambiguous(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "multiple DNS records"):
            assess(
                domain_rows([exact_domain()]),
                dns_rows([exact_dns(), {**exact_dns(), "id": "c" * 32}]),
            )

    def test_any_matching_route_blocks_custom_domain_attach(self) -> None:
        conflict = routes(
            [
                {
                    "id": "route-1",
                    "pattern": "https://*.corelink.humangr.com/api/*",
                    "script": "other-staging-worker",
                }
            ]
        )
        with self.assertRaisesRegex(domain.DomainError, "Worker Route exists"):
            assess(route_list=conflict)

    def test_malformed_route_and_incomplete_inventory_fail_closed(self) -> None:
        with self.assertRaises(domain.DomainError):
            assess(
                route_list=routes([{"id": "route-1", "pattern": "https://bad host/"}])
            )
        broken = copy.deepcopy(dns_rows([exact_dns()]))
        del broken["result_info"]["count"]
        with self.assertRaisesRegex(domain.DomainError, "incomplete"):
            domain.validate_dns(broken)

    def test_account_zone_or_workers_dev_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "pinned staging target"):
            domain.validate_zone(zone(), domain.ZONE_ID, "f" * 32)
        with self.assertRaisesRegex(domain.DomainError, "workers.dev or preview"):
            assess(worker_domain_list=subdomain(enabled=True))

    def test_request_signal_flags_must_be_read_back_on_root_worker(self) -> None:
        expected = {
            "success": True,
            "errors": [],
            "messages": [],
            "result": {
                "compatibility_flags": [
                    "nodejs_compat",
                    "enable_request_signal",
                    "request_signal_passthrough",
                ]
            },
        }
        domain.validate_request_signal_settings(expected)
        expected["result"]["compatibility_flags"].pop()
        with self.assertRaisesRegex(domain.DomainError, "request-signal"):
            domain.validate_request_signal_settings(expected)

    def test_rollback_detaches_only_verified_domain_created_id(self) -> None:
        owned = {
            "success": True,
            "errors": [],
            "messages": [],
            "result": exact_domain(),
        }
        with (
            patch.object(domain, "_read_json", return_value=owned),
            patch.object(
                domain, "_request_json", return_value={"success": True}
            ) as delete,
            patch.object(
                domain,
                "_inventory",
                return_value=(
                    zone(),
                    routes(),
                    domain_rows(),
                    dns_rows(),
                    subdomain(),
                    {},
                    {},
                ),
            ),
        ):
            self.assertTrue(
                domain._detach_created("unused", "a" * 32, exact_domain()["cert_id"])
            )
        self.assertEqual(
            delete.call_args.args[1],
            f"accounts/{domain.ACCOUNT_ID}/workers/domains/{'a' * 32}",
        )
        self.assertEqual(delete.call_args.args[2], "DELETE")

    def test_rollback_refuses_a_domain_id_whose_mapping_changed(self) -> None:
        changed = {"success": True, "result": exact_domain(service="other-worker")}
        with (
            patch.object(domain, "_read_json", return_value=changed),
            patch.object(domain, "_request_json") as delete,
        ):
            self.assertFalse(
                domain._detach_created("unused", "a" * 32, exact_domain()["cert_id"])
            )
        delete.assert_not_called()

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            json.loads(
                '{"success":true,"success":false}',
                object_pairs_hook=domain._unique_object,
            )

    def test_publish_rechecks_full_inventory_before_attach(self) -> None:
        root_settings = {
            "success": True,
            "result": {
                "compatibility_flags": [
                    "nodejs_compat",
                    "enable_request_signal",
                    "request_signal_passthrough",
                ]
            },
        }
        candidate = (
            zone(),
            routes(),
            domain_rows(),
            dns_rows(),
            subdomain(),
            root_settings,
            {},
        )
        conflict = (
            zone(),
            routes([{"id": "r1", "pattern": "staging.corelink.humangr.com/*"}]),
            domain_rows(),
            dns_rows(),
            subdomain(),
            root_settings,
            {},
        )
        with (
            patch.object(domain, "_inventory", side_effect=[candidate, conflict]),
            patch.object(domain, "runtime_binding_gaps", return_value=[]),
            patch.object(domain, "_request_json") as mutate,
            patch.object(domain, "_write_receipt"),
        ):
            with self.assertRaisesRegex(
                domain.DomainError, "host-matching Worker Route"
            ):
                domain.run(
                    "publish",
                    "token",
                    domain.ACCOUNT_ID,
                    domain.ZONE_ID,
                    Path("unused"),
                )
        mutate.assert_not_called()

    def test_mutation_response_errors_are_rejected(self) -> None:
        with self.assertRaisesRegex(domain.DomainError, "provider errors"):
            domain._validate_mutation_envelope(
                {"success": True, "errors": [{"code": 1}], "result": {}},
                "Custom Domain attach",
            )

    def test_runtime_secrets_are_checked_by_name_and_type_only(self) -> None:
        missing = domain.runtime_binding_gaps(
            {"success": True, "result": {"bindings": []}},
            {"success": True, "result": {"bindings": []}},
        )
        self.assertIn("corelink-staging:CF_API_TOKEN", missing)
        self.assertIn("corelink-signup-staging:CLERK_WEBHOOK_SECRET", missing)
        complete_root = {
            "success": True,
            "result": {
                "bindings": [
                    {"name": name, "type": "secret_text"}
                    for name in (
                        "CF_API_TOKEN",
                        "CLERK_ISSUER_URL",
                        "CLERK_SECRET_KEY",
                        "CLOUDFLARE_ACCOUNT_ID",
                        "CORELINK_ADMIN_AUTH_KEY",
                        "CORELINK_ERASE_AUTH_KEY",
                        "CORELINK_INTERNAL_AUTH_KEY",
                        "PAT_SIGNING_KEY",
                        "R2_S3_ACCESS_KEY_ID",
                        "R2_S3_SECRET_ACCESS_KEY",
                    )
                ]
            },
        }
        complete_signup = {
            "success": True,
            "result": {
                "bindings": [
                    {"name": name, "type": "secret_text"}
                    for name in (
                        "CLERK_SECRET_KEY",
                        "CLERK_WEBHOOK_SECRET",
                        "CORELINK_ERASE_AUTH_KEY",
                        "CORELINK_INTERNAL_AUTH_KEY",
                        "DSR_DLQ_REDRIVE_AUTH_KEY",
                        "ERASURE_SALT_KEY",
                    )
                ]
            },
        }
        self.assertEqual(
            domain.runtime_binding_gaps(complete_root, complete_signup), []
        )

    def test_workflow_has_only_protected_provider_dispatch_and_credentialless_pr_gate(
        self,
    ) -> None:
        workflow = Path(
            ".github/workflows/issue-1700-staging-custom-domain.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn(
            "github.ref == 'refs/heads/main' && github.ref_protected", workflow
        )
        self.assertIn("environment: staging", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("secrets.CF_API_TOKEN", workflow)
        self.assertIn("secrets.STAGING_CF_ACCOUNT_ID", workflow)
        self.assertIn("vars.CF_ZONE_ID", workflow)
        self.assertIn("secrets.K6_TARGET_IDENTITY_RECEIPT", workflow)
        self.assertIn('test -n "${!name:-}"', workflow)
        self.assertIn("publish-custom-domain-staging-1700", workflow)
        require_provider_guard_bindings(workflow)
        for binding, replacement in (
            (
                "          STAGING_CF_ACCOUNT_ID: ${{ secrets.STAGING_CF_ACCOUNT_ID }}",
                "          STAGING_CF_ACCOUNT_ID: ${{ secrets.OTHER_ACCOUNT_ID }}",
            ),
            (
                "          CF_ZONE_ID: ${{ vars.CF_ZONE_ID }}",
                "          CF_ZONE_ID: ${{ vars.OTHER_ZONE_ID }}",
            ),
        ):
            with self.subTest(binding=binding):
                missing = workflow.replace(binding, replacement, 1)
                with self.assertRaisesRegex(AssertionError, "lacks exact bindings"):
                    require_provider_guard_bindings(missing)
        pull_request = workflow.split("  workflow_dispatch:", 1)[0]
        self.assertNotIn("CF_API_TOKEN", pull_request)
        self.assertNotIn("STAGING_CF_ACCOUNT_ID", pull_request)
        self.assertNotIn("run: npx wrangler deploy", workflow)
        self.assertIn(
            "authenticated_readiness",
            Path("scripts/staging_custom_domain.py").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
