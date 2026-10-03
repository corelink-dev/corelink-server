"""Meaningful fail-closed negatives for the #2568 provider operator."""
from __future__ import annotations

import json
import tempfile
import types
import unittest
import sys
from hashlib import sha256
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.issue_2568_sla_credit_real import (
    BRANCH,
    CF_ACCOUNT,
    CONFIRMATION,
    D1_NAME,
    PROTECTED_D1_UUIDS,
    WORKER_NAME,
    Cloudflare,
    OperatorError,
    OwnedStripeObjects,
    _ensure_absent_target,
    _create_wp2_customer,
    _fresh_main_acceptance,
    _prepare_worker_tree,
    _with_fresh_main,
    assert_checkout,
    assert_cloudflare_request,
    assert_pinned_targets,
    cloudflare_from_env,
    invoice_item_from_line,
    run_all,
    validate_account_binding,
    validate_disposable_database_id,
    validate_restricted_key,
    validate_target_name,
    verify_source_checkout,
)
from scripts.verify_issue_2568_sla_credit_real import (
    VerificationError,
    CF_ACCOUNT_PIN,
    DISPOSABLE_TARGET_NAME,
    LEAF_PATHS,
    CORRECTION_PATHS,
    RETIRED_CF_ACCOUNT,
    WP150_OWNERSHIP_ROW,
    WP150_PATH,
    SECRET_REGISTRY_PATH,
    PROVIDER_CREDENTIAL_BINDINGS,
    SOURCE_DIGESTS,
    SOURCE_SHA,
    validate_account_pin,
    validate_receipt,
    validate_provider_receipt,
    validate_candidate_paths,
    validate_registered_credentials,
    validate_wp150_manifest,
    validate_wp150_ownership,
    validate_secret_registry,
    validate_provider_credential_bindings,
    validate_source_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_PATH = ROOT / "scripts/issue_2568_sla_credit_real.py"
WORKFLOW_PATH = ROOT / ".github/workflows/issue-2568-sla-credit-real.yml"
OPERATOR_MODULE = "scripts.issue_2568_sla_credit_real"
VERIFIER_MODULE = "scripts.verify_issue_2568_sla_credit_real"
PRODUCTION_D1_UUID = "d64742ea-e102-40b2-a844-ff02e3f94562"
BOUND_D1_UUID = "11111111-2222-4333-8444-555555555555"


class FakeStripe:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, form=None, *, idem=None):
        self.calls.append((method, path))
        if path.startswith("/v1/invoiceitems?") or path.startswith("/v1/invoices?"):
            return {"data": [], "has_more": False}
        if path.startswith("/v1/customers/cus_foreign"):
            return {"id": "cus_foreign_123", "livemode": False, "metadata": {"corelink_run": "other-run"}}
        if path == "/v1/account":
            return {"object": "account", "id": "acct_foreign"}
        raise AssertionError(f"unexpected request in unit test: {method} {path}")


class FakeCloudflare:
    def __init__(self, subdomain_status=200, worker_status=404, d1_status=200):
        self.subdomain_status = subdomain_status
        self.worker_status = worker_status
        self.d1_status = d1_status
        self.calls: list[tuple[str, str]] = []

    def verify_subdomain(self):
        status, payload = self.request("GET", f"/accounts/{CF_ACCOUNT}/workers/subdomain")
        if status != 200:
            raise OperatorError("existing account Workers subdomain/topology could not be verified")
        return payload["result"]

    def request(self, method, path, data=None):
        self.calls.append((method, path))
        if path.endswith("/workers/subdomain"):
            return self.subdomain_status, {"result": {"subdomain": "private-test"}} if self.subdomain_status == 200 else None
        if path.endswith("/workers/scripts/corelink-i2568-sla-credit-6a"):
            return self.worker_status, {"result": {}} if self.worker_status == 200 else None
        if "/d1/database?name=" in path:
            return self.d1_status, {"result": []} if self.d1_status == 200 else None
        raise AssertionError((method, path))


class Issue2568OperatorTests(unittest.TestCase):
    def test_canonical_source_requires_exact_candidate_sha_and_file_digests(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(verify_source_checkout(root, SOURCE_SHA), SOURCE_DIGESTS)
        with self.assertRaisesRegex(OperatorError, "exact protected-main candidate"):
            verify_source_checkout(root, "0" * 40)
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output", return_value="0" * 40):
            with self.assertRaisesRegex(OperatorError, "exact protected-main candidate"):
                verify_source_checkout(root, SOURCE_SHA)

    def test_wrong_account_rejected_before_provider_request(self) -> None:
        with self.assertRaisesRegex(OperatorError, "does not match"):
            validate_account_binding("acct_wrong")

    def test_live_or_unrestricted_key_rejected_before_provider_request(self) -> None:
        for value in ("sk_live_private", "sk_test_unrestricted", "rk_live_restricted"):
            with self.subTest(prefix=value[:8]):
                with self.assertRaisesRegex(OperatorError, "restricted test key"):
                    validate_restricted_key(value)

    def test_exact_binding_hash_and_restricted_test_key_pass(self) -> None:
        # The protected value itself is deliberately not embedded in tests.
        self.assertRegex(BRANCH, r"^refs/heads/main$")
        validate_restricted_key("rk_test_abcdefgh")

    def test_short_restricted_key_rejected(self) -> None:
        with self.assertRaisesRegex(OperatorError, "restricted test key"):
            validate_restricted_key("rk_test_")

    def test_detached_candidate_uses_immutable_sha_and_github_ref(self) -> None:
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.side_effect = ["a" * 40 + "\n", "a" * 40 + "\trefs/heads/main\n"]
            env = {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REF": BRANCH, "GITHUB_SHA": "a" * 40}
            with patch.dict("os.environ", env):
                self.assertEqual(assert_checkout("a" * 40), "a" * 40)
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.return_value = "a" * 40 + "\n"
            env = {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REF": "refs/heads/codex/support03-issue-2568", "GITHUB_SHA": "a" * 40}
            with patch.dict("os.environ", env):
                with self.assertRaisesRegex(OperatorError, "protected main ref"):
                    assert_checkout("a" * 40)
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.return_value = "b" * 40 + "\n"
            env = {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REF": BRANCH, "GITHUB_SHA": "b" * 40}
            with patch.dict("os.environ", env):
                with self.assertRaisesRegex(OperatorError, "differs from expected_sha"):
                    assert_checkout("a" * 40)

    def test_stale_protected_main_fails_before_provider_write(self) -> None:
        current_sha = "a" * 40
        stale_sha = "b" * 40
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.side_effect = [
                current_sha + "\n",
                stale_sha + "\trefs/heads/main\n",
            ]
            env = {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REF": BRANCH, "GITHUB_SHA": current_sha}
            with patch.dict("os.environ", env):
                with self.assertRaisesRegex(OperatorError, "not the fresh protected-main commit"):
                    assert_checkout(current_sha)
            self.assertEqual(command.call_count, 2)

    def test_main_advance_before_wp2_customer_prevents_stripe_write(self) -> None:
        stripe = FakeStripe()
        owned = OwnedStripeObjects(stripe, "this-run")
        with patch("scripts.issue_2568_sla_credit_real.assert_checkout",
                   side_effect=OperatorError("expected_sha is not the fresh protected-main commit")):
            with self.assertRaisesRegex(OperatorError, "not the fresh protected-main commit"):
                _create_wp2_customer("a" * 40, stripe, owned)
        self.assertEqual(stripe.calls, [])

    def test_main_advance_before_final_acceptance_denies_closure(self) -> None:
        receipt = {"status": "provider_proof_pass_cleanup_pending", "cleanup": {"succeeded": True}}
        with patch("scripts.issue_2568_sla_credit_real.assert_checkout",
                   side_effect=OperatorError("expected_sha is not the fresh protected-main commit")):
            self.assertFalse(_fresh_main_acceptance(receipt, "a" * 40))
        self.assertEqual(receipt["status"], "stale_or_unverifiable_main")
        self.assertEqual(receipt["closure_acceptance"], "denied_fresh_main_check_failed")
        self.assertNotEqual(receipt["status"], "closure_ready_pending_root_credential_revocation")

    def test_main_advance_before_replay_prevents_invocation(self) -> None:
        effects: list[str] = []
        with patch("scripts.issue_2568_sla_credit_real.assert_checkout",
                   side_effect=OperatorError("expected_sha is not the fresh protected-main commit")):
            with self.assertRaisesRegex(OperatorError, "not the fresh protected-main commit"):
                _with_fresh_main("a" * 40, lambda: effects.append("scheduled-replay"))
        self.assertEqual(effects, [])

    def test_main_advance_before_draft_invoice_prevents_stripe_write(self) -> None:
        stripe = FakeStripe()
        form = {"customer": "cus_owned"}
        with patch("scripts.issue_2568_sla_credit_real.assert_checkout",
                   side_effect=OperatorError("expected_sha is not the fresh protected-main commit")):
            with self.assertRaisesRegex(OperatorError, "not the fresh protected-main commit"):
                _with_fresh_main("a" * 40, stripe.request, "POST", "/v1/invoices", form,
                                 idem="run-draft-invoice")
        self.assertEqual(stripe.calls, [])

    def test_foreign_customer_cleanup_refused_without_delete(self) -> None:
        stripe = FakeStripe()
        objects = OwnedStripeObjects(stripe, "this-run")
        objects.customer_id = "cus_foreign_123"
        self.assertFalse(objects.cleanup())
        self.assertIn("ownership/mode mismatch", objects.cleanup_errors[0])
        self.assertNotIn(("DELETE", "/v1/customers/cus_foreign_123"), stripe.calls)

    def test_cloudflare_preexisting_worker_target_fails_without_delete(self) -> None:
        cf = FakeCloudflare(worker_status=200)
        with self.assertRaisesRegex(OperatorError, "already exists"):
            _ensure_absent_target(cf)
        self.assertFalse(any(method == "DELETE" for method, _ in cf.calls))

    def test_cloudflare_auth_failure_fails_without_delete(self) -> None:
        cf = FakeCloudflare(subdomain_status=401)
        with self.assertRaisesRegex(OperatorError, "subdomain/topology"):
            _ensure_absent_target(cf)
        self.assertFalse(any(method == "DELETE" for method, _ in cf.calls))

    def test_stripe_invoice_line_shapes_are_mutually_consistent(self) -> None:
        self.assertEqual(invoice_item_from_line({"invoice_item": "ii_123"}), ("ii_123", "invoice_item"))
        self.assertEqual(invoice_item_from_line({
            "invoice_item": "ii_123", "parent": {
                "type": "invoice_item_details", "invoice_item_details": {"invoice_item": "ii_123"},
            },
        }), ("ii_123", "parent.invoice_item_details.invoice_item"))
        with self.assertRaisesRegex(OperatorError, "conflicting"):
            invoice_item_from_line({
                "invoice_item": "ii_other", "parent": {
                    "type": "invoice_item_details", "invoice_item_details": {"invoice_item": "ii_123"},
                },
            })

    def test_source_drift_refused(self) -> None:
        good = {
            "apps/signup-worker/src/webhooks/sla_credit_cron.ts": "a" * 64,
        }
        with self.assertRaisesRegex(VerificationError, "frozen canonical source SHA"):
            validate_source_manifest({"source_sha": "0" * 40}, good)

    def test_receipt_rejects_raw_provider_payload_and_secret(self) -> None:
        good = {"issue": 2568, "mode": "test", "redacted": True}
        validate_receipt(good)
        for bad in (
            {**good, "raw_response": {"customer": "private"}},
            {**good, "token": "not-for-receipt"},
            {**good, "customer": "cus_123", "debug": "rk_test_1234567890"},
        ):
            with self.subTest(bad=tuple(bad)):
                with self.assertRaises(VerificationError):
                    validate_receipt(bad)

    def test_partial_receipt_cannot_claim_full_provider_pass(self) -> None:
        partial = {"issue": 2568, "mode": "test", "redacted": True}
        with self.assertRaisesRegex(VerificationError, "schema"):
            validate_provider_receipt(partial)

    def test_candidate_gate_accepts_exact_eight_and_rejects_missing_or_foreign(self) -> None:
        validate_candidate_paths(list(LEAF_PATHS))
        correction_branch = "refs/heads/codex/support03-enterprise-credit-correction"
        validate_candidate_paths(list(CORRECTION_PATHS), correction_branch)
        with self.subTest(case="missing registry"):
            with self.assertRaisesRegex(VerificationError, "exact owned leaf paths"):
                validate_candidate_paths(set(LEAF_PATHS) - {SECRET_REGISTRY_PATH})
        with self.subTest(case="foreign path"):
            with self.assertRaisesRegex(VerificationError, "exact owned leaf paths"):
                validate_candidate_paths(set(LEAF_PATHS) | {".github/workflows/foreign.yml"})
        with self.subTest(case="correction branch cannot use original paths"):
            with self.assertRaisesRegex(VerificationError, "exact owned leaf paths"):
                validate_candidate_paths(set(LEAF_PATHS), correction_branch)

    def test_wp150_manifest_gate_rejects_arbitrary_content_or_mode(self) -> None:
        # Pre-merge candidate gate: exact bytes and mode. The shared manifest has
        # moved on since delivery, so its teeth are proven on pinned sample bytes.
        valid = b"| workflow | owner |\n" + WP150_OWNERSHIP_ROW.encode() + b"\n"
        with patch(f"{VERIFIER_MODULE}.WP150_SHA256", sha256(valid).hexdigest()):
            validate_wp150_manifest(valid, 0o100644)
            with self.assertRaisesRegex(VerificationError, "root-authorized"):
                validate_wp150_manifest(valid + b"\nforeign append\n", 0o100644)
            with self.assertRaisesRegex(VerificationError, "root-authorized"):
                validate_wp150_manifest(valid, 0o100755)
        # Post-merge: the current shared manifest still records #2568 ownership once.
        current = (ROOT / WP150_PATH).read_text(encoding="utf-8")
        validate_wp150_ownership(current)
        for drifted in (
            current.replace(WP150_OWNERSHIP_ROW + "\n", ""),
            current.replace(WP150_OWNERSHIP_ROW, ".github/workflows/issue-2568-sla-credit-real.yml | LEAD-BLOCKED | blocked"),
            current + WP150_OWNERSHIP_ROW + "\n",
        ):
            with self.assertRaisesRegex(VerificationError, "#2568 ownership row"):
                validate_wp150_ownership(drifted)

    def test_secret_registry_registers_i2568_and_denies_unknown_credential(self) -> None:
        sample = b"| 314 | token | `CF_I2568_API_TOKEN` | operator |\n"
        with patch(f"{VERIFIER_MODULE}.SECRET_REGISTRY_SHA256", sha256(sample).hexdigest()):
            validate_secret_registry(sample, 0o100644)
            with self.assertRaisesRegex(VerificationError, "root-authorized"):
                validate_secret_registry(sample + b"\nforeign append\n", 0o100644)
            with self.assertRaisesRegex(VerificationError, "root-authorized"):
                validate_secret_registry(sample, 0o100755)
        unregistered = b"| 314 | token | `OTHER_TOKEN` | operator |\n"
        with patch(f"{VERIFIER_MODULE}.SECRET_REGISTRY_SHA256", sha256(unregistered).hexdigest()):
            with self.assertRaisesRegex(VerificationError, "does not register"):
                validate_secret_registry(unregistered, 0o100644)
        # Post-merge: every credential name the provider path handles is registered,
        # including the repository deploy token the owner decision binds.
        registry = (ROOT / SECRET_REGISTRY_PATH).read_text(encoding="utf-8")
        validate_registered_credentials(registry)
        for name in ("CF_API_TOKEN", "CF_I2568_API_TOKEN", "STRIPE_SECRET_KEY"):
            with self.subTest(dropped=name):
                drifted = "\n".join(line for line in registry.splitlines()
                                    if f"| `{name}`" not in line)
                with self.assertRaisesRegex(VerificationError, name):
                    validate_registered_credentials(drifted)
        validate_provider_credential_bindings(PROVIDER_CREDENTIAL_BINDINGS.copy())
        self.assertEqual(PROVIDER_CREDENTIAL_BINDINGS["CF_I2568_API_TOKEN"], "secrets.CF_API_TOKEN")
        with self.assertRaisesRegex(VerificationError, "unregistered or missing credential"):
            validate_provider_credential_bindings(
                {**PROVIDER_CREDENTIAL_BINDINGS, "CF_I2568_API_TOKEN": "secrets.CF_I2568_API_TOKEN"})
        unknown = {**PROVIDER_CREDENTIAL_BINDINGS, "UNREGISTERED_TOKEN": "secrets.UNREGISTERED_TOKEN"}
        with self.assertRaisesRegex(VerificationError, "unregistered or missing credential"):
            validate_provider_credential_bindings(unknown)
        with self.assertRaisesRegex(VerificationError, "unregistered or duplicate credential"):
            validate_provider_credential_bindings(
                PROVIDER_CREDENTIAL_BINDINGS.copy(),
                [*PROVIDER_CREDENTIAL_BINDINGS.values(), "secrets.UNREGISTERED_TOKEN"],
            )

    # --- Owner decision 2026-10-02: main account 6a, dedicated disposable pair ---

    def test_account_pin_is_the_main_account(self) -> None:
        self.assertEqual(CF_ACCOUNT, "6a1fc1c626fc2628823e60b9db01f5cd")
        self.assertEqual(CF_ACCOUNT_PIN, CF_ACCOUNT)
        self.assertNotEqual(RETIRED_CF_ACCOUNT, CF_ACCOUNT)
        self.assertEqual((WORKER_NAME, D1_NAME), (DISPOSABLE_TARGET_NAME, DISPOSABLE_TARGET_NAME))
        assert_pinned_targets(CF_ACCOUNT, WORKER_NAME, D1_NAME)
        with self.assertRaisesRegex(OperatorError, "account identifier is malformed"):
            assert_pinned_targets("6a1fc1c6", WORKER_NAME, D1_NAME)

    def test_workflow_and_operator_pin_the_same_account(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        operator = OPERATOR_PATH.read_text(encoding="utf-8")
        validate_account_pin(workflow, operator)
        self.assertNotIn(RETIRED_CF_ACCOUNT, workflow + operator)
        pinned = f'CLOUDFLARE_ACCOUNT_ID: "{CF_ACCOUNT}"'
        self.assertEqual(workflow.count(pinned), 1)
        with self.assertRaisesRegex(VerificationError, "account literals"):
            validate_account_pin(workflow.replace(pinned, f'CLOUDFLARE_ACCOUNT_ID: "{RETIRED_CF_ACCOUNT}"'), operator)
        with self.assertRaisesRegex(VerificationError, "account literals"):
            validate_account_pin(workflow, operator + f'\nOTHER = "{RETIRED_CF_ACCOUNT}"\n')
        with self.assertRaisesRegex(VerificationError, "CLOUDFLARE_ACCOUNT_ID"):
            validate_account_pin(workflow.replace(pinned, f'CF_ACCOUNT_LITERAL: "{CF_ACCOUNT}"'), operator)
        for marker in ("assert_cloudflare_request(method, path, data, self.database_id)",
                       "cf = cloudflare_from_env(os.environ)"):
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(VerificationError, "fence marker"):
                    validate_account_pin(workflow, operator.replace(marker, "pass"))

    def test_receipt_binds_the_main_account_disposable_d1(self) -> None:
        sha, h = "a" * 40, "sha256:" + "b" * 64
        invocation = {"result": "scheduled_http_200", "process_terminated": True, "canonical_source_sha": sha,
                      "operator_sha": sha, "persistent_worker_version_sha256": h}
        receipt = {
            "schema": "corelink.issue-2568.sla-credit-real.v1", "issue": 2568, "mode": "test", "redacted": True,
            "status": "closure_ready_pending_root_credential_revocation", "candidate_sha": sha,
            "operator": {"branch": "main", "head_sha": sha, "operator_file_sha256": "c" * 64},
            "canonical_source_sha": sha, "canonical_source_digests": dict(SOURCE_DIGESTS),
            "stripe_test_account_id_sha256": "e9678dceccdaa37a7259379096e82875f6ae0c694f9a461a28691c79eceb33ad",
            "checks": {key: "pass" for key in ("gate_false_no_provider_effect", "canonical_credit_applied",
                                               "replay_singular", "next_invoice_reconciled")},
            "capability_probe": {
                "cleanup_succeeded": True,
                "checks": {key: "pass" for key in ("stripe_account_binding", "restricted_test_key_prefix",
                                                   "owned_pending_item_included_once")},
                "provider_effects": ["owned_test_customer_created",
                                     "owned_negative_one_usd_minor_invoice_item_created",
                                     "owned_nonadvancing_draft_invoice_created"],
                "cleanup": {"attempted": True, "succeeded": True, "absence_verified": True},
                "customer_sha256": h, "invoice_item_sha256": h, "draft_invoice_sha256": h,
            },
            "persistent_worker": {"workers_dev": False, "preview_urls": False, "gate": False, "routes": [],
                                  "crons": [], "source_sha": sha, "operator_sha": sha,
                                  "operator_file_sha256": "c" * 64, "bindings_verified": True,
                                  "route_configuration": "wrangler_config_has_no_routes_or_services",
                                  "version_id_sha256": h},
            "private_invocations": [
                {**invocation, "gate": False, "session_sha256": "1" * 64},
                {**invocation, "gate": True, "session_sha256": "2" * 64},
                {**invocation, "gate": True, "replay": True, "session_sha256": "3" * 64},
            ],
            "credit": {"service_period": "2026-08", "tier": "enterprise", "monthly_fee_minor": 10000,
                       "availability_percent": 99.49, "credit_percent": 5, "amount_minor": 500,
                       "currency": "USD", "gate_false_provider_effects": 0},
            "replay": {"same_observation": True, "same_canonical_sweep": True, "provider_objects": 1,
                       "d1_counts_before": {"n": 1}, "d1_counts_after": {"n": 1}},
            "invoice": {"status": "draft", "auto_advance": False, "credit_line_count": 1,
                        "credit_line_amount_minor": -500},
            "d1": {"name": DISPOSABLE_TARGET_NAME, "account": CF_ACCOUNT_PIN, "uuid_sha256": h,
                   "row_counts": {"sla_monthly_observations": 1, "sla_monthly_measurements": 1,
                                  "sla_credit_ledger": 1, "sla_credit_outbox": 1,
                                  "sla_credit_reconciliation": 1, "sla_credit_audit_events": 2},
                   "migration_history": ["0055_tenant_billing", "0117_sla_credit_ledger"],
                   "migration_sha256": {
                       "0055_tenant_billing.sql": SOURCE_DIGESTS["migrations/d1/0055_tenant_billing.sql"],
                       "0117_sla_credit_ledger.sql": SOURCE_DIGESTS["migrations/d1/0117_sla_credit_ledger.sql"]}},
            "cleanup": {"succeeded": True, "gate_final": False, "private_preview_sessions_terminated": True,
                        "pre_cleanup_receipt_written": True, "credential_revocation": "root_action_required",
                        "private_runtime_files_removed": True,
                        "stripe_objects": {"attempted": True, "succeeded": True, "absence_verified": True},
                        "cloudflare_targets": {"worker_deleted": True, "database_deleted": True,
                                               "worker_absent": True, "database_absent": True}},
            "timestamps_utc": {"started": "t0", "provider_proof_complete": "t1", "finished": "t2"},
        }
        with patch(f"{VERIFIER_MODULE}.SOURCE_SHA", sha):
            validate_provider_receipt(receipt)  # control
            for field, value in (("account", RETIRED_CF_ACCOUNT), ("name", "corelink-i2568-sla-credit-test-20260928"),
                                 ("name", "corelink-prod-d1")):
                with self.subTest(**{field: value}):
                    with self.assertRaisesRegex(VerificationError, "D1 migration and row-count"):
                        validate_provider_receipt({**receipt, "d1": {**receipt["d1"], field: value}})

    def test_cloudflare_account_mismatch_refused_before_any_cloudflare_call(self) -> None:
        with self.assertRaisesRegex(OperatorError, "pinned #2568 main account"):
            cloudflare_from_env({"CF_I2568_API_TOKEN": "t", "CLOUDFLARE_ACCOUNT_ID": RETIRED_CF_ACCOUNT})
        with self.assertRaisesRegex(OperatorError, "pinned #2568 main account"):
            cloudflare_from_env({"CF_I2568_API_TOKEN": "t"})
        with self.assertRaisesRegex(OperatorError, "token for the #2568 main-account target is missing"):
            cloudflare_from_env({"CLOUDFLARE_ACCOUNT_ID": CF_ACCOUNT})
        self.assertEqual(cloudflare_from_env({"CF_I2568_API_TOKEN": "t", "CLOUDFLARE_ACCOUNT_ID": CF_ACCOUNT}).token, "t")
        with patch(f"{OPERATOR_MODULE}.urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(OperatorError, "outside the pinned #2568 account"):
                Cloudflare("t").request("GET", f"/accounts/{RETIRED_CF_ACCOUNT}/workers/subdomain")
            urlopen.assert_not_called()

    def _run_all_with(self, environ: dict[str, str], *, stripe_account: dict | None = None):
        """Run the real run_all with checkout identity stubbed and every network call trapped."""
        stripe_calls: list[tuple[str, str]] = []

        def fake_stripe_request(_self, method, path, form=None, *, idem=None):
            stripe_calls.append((method, path))
            if (method, path) == ("GET", "/v1/account") and stripe_account is not None:
                return stripe_account
            raise AssertionError(f"unexpected Stripe call {method} {path}")

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict("os.environ", environ, clear=True), \
                patch(f"{OPERATOR_MODULE}.SOURCE_SHA", "a" * 40), \
                patch(f"{OPERATOR_MODULE}.assert_checkout", return_value="a" * 40), \
                patch(f"{OPERATOR_MODULE}.verify_source_checkout", return_value={}), \
                patch(f"{OPERATOR_MODULE}.subprocess.check_output", return_value="a" * 40 + "\n"), \
                patch(f"{OPERATOR_MODULE}.validate_account_binding", return_value=None), \
                patch(f"{OPERATOR_MODULE}.Stripe.request", fake_stripe_request), \
                patch(f"{OPERATOR_MODULE}.urllib.request.urlopen") as urlopen:
            output = Path(tmp) / "receipt.json"
            code = run_all(expected_sha="a" * 40, run_id="1-1", confirmation=CONFIRMATION,
                           source_root=ROOT, output=output)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            return code, receipt, stripe_calls, urlopen

    def test_run_all_refuses_retired_account_before_any_provider_write(self) -> None:
        environ = {
            "I2568_PROVIDER_APPROVED": "true", "STRIPE_SECRET_KEY": "rk_test_abcdefgh",
            "STRIPE_TEST_ACCOUNT_ID": "acct_bound", "CF_I2568_API_TOKEN": "t",
            "CLOUDFLARE_ACCOUNT_ID": RETIRED_CF_ACCOUNT,
        }
        code, receipt, stripe_calls, urlopen = self._run_all_with(
            environ, stripe_account={"object": "account", "id": "acct_bound"})
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "provider_operation_failed")
        self.assertIn("pinned #2568 main account", receipt["required_act"])
        self.assertEqual(stripe_calls, [("GET", "/v1/account")])
        urlopen.assert_not_called()
        self.assertEqual(receipt["cleanup"]["cloudflare_targets"]["errors"], [])
        self.assertIs(receipt["cleanup"]["stripe_objects"]["attempted"], False)

    def test_live_key_refused_by_run_all_before_any_network_call(self) -> None:
        for key in ("sk_live_abcdef", "rk_live_abcdef", "sk_test_abcdef"):
            with self.subTest(prefix=key[:8]):
                environ = {
                    "I2568_PROVIDER_APPROVED": "true", "STRIPE_SECRET_KEY": key,
                    "STRIPE_TEST_ACCOUNT_ID": "acct_bound", "CF_I2568_API_TOKEN": "t",
                    "CLOUDFLARE_ACCOUNT_ID": CF_ACCOUNT,
                }
                code, receipt, stripe_calls, urlopen = self._run_all_with(environ)
                self.assertEqual(code, 1)
                self.assertIn("restricted test key", receipt["required_act"])
                self.assertEqual(stripe_calls, [])
                urlopen.assert_not_called()
                self.assertNotIn(key, json.dumps(receipt))

    def test_production_and_staging_names_refused(self) -> None:
        self.assertEqual(validate_target_name(D1_NAME, D1_NAME), "corelink-i2568-sla-credit-6a")
        # A drifted pin onto a production or staging name is refused by name, not
        # only because it differs from the pin.
        for name in ("corelink-prod-d1", "corelink-config-prod", "corelink-config-staging",
                     "corelink-analytics-prod", "corelink-staging", "corelink-prod",
                     "corelink-signup-worker", "corelink-dsr-b216-alert-receipts-6a",
                     "corelink-i2568-sla-credit-staging", "corelink-i2568-sla-credit-prod",
                     "corelink-i2568-sla-credit-live"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(OperatorError, "production or staging resource"):
                    validate_target_name(name, name)
        with self.assertRaisesRegex(OperatorError, "outside the dedicated #2568 namespace"):
            validate_target_name("corelink-other-sla-credit-6a", "corelink-other-sla-credit-6a")
        with self.assertRaisesRegex(OperatorError, "not the exact pinned"):
            validate_target_name("corelink-i2568-sla-credit-7b", D1_NAME)
        for identifier in sorted(PROTECTED_D1_UUIDS):
            with self.subTest(uuid=identifier):
                with self.assertRaisesRegex(OperatorError, "production or staging database"):
                    validate_disposable_database_id(identifier)
                cf = Cloudflare("t")
                with self.assertRaisesRegex(OperatorError, "production or staging database"):
                    cf.bind_database(identifier)
                self.assertIsNone(cf.database_id)
        cf = Cloudflare("t")
        cf.bind_database(BOUND_D1_UUID)
        with self.assertRaisesRegex(OperatorError, "cannot change"):
            cf.bind_database("22222222-2222-4333-8444-555555555555")

    def test_generated_wrangler_config_names_only_the_disposable_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            _prepare_worker_tree(runtime, ROOT, ROOT, BOUND_D1_UUID)
            config = (runtime / "wrangler.toml").read_text(encoding="utf-8")
            for line in (f'name = "{WORKER_NAME}"', f'account_id = "{CF_ACCOUNT}"',
                         f'database_name = "{D1_NAME}"', f'database_id = "{BOUND_D1_UUID}"',
                         "workers_dev = false", "preview_urls = false", 'SLA_CREDITS_ENABLED = "false"'):
                self.assertIn(line + "\n", config)
            self.assertNotIn(RETIRED_CF_ACCOUNT, config)
            refused = Path(tmp) / "refused"
            with self.assertRaisesRegex(OperatorError, "production or staging database"):
                _prepare_worker_tree(refused, ROOT, ROOT, PRODUCTION_D1_UUID)
            self.assertFalse(refused.exists())

    def test_drifted_pinned_target_refuses_to_load(self) -> None:
        source = OPERATOR_PATH.read_text(encoding="utf-8")

        def load(text: str) -> None:
            module = types.ModuleType("i2568_operator_copy")
            module.__file__ = str(OPERATOR_PATH)
            sys.modules[module.__name__] = module
            try:
                exec(compile(text, str(OPERATOR_PATH), "exec"), module.__dict__)
            finally:
                sys.modules.pop(module.__name__, None)

        load(source)  # control: the pinned constants load
        for constant, drifted, reason in (
            (f'D1_NAME = "{D1_NAME}"', 'D1_NAME = "corelink-prod-d1"', "production or staging resource"),
            (f'D1_NAME = "{D1_NAME}"', 'D1_NAME = "corelink-config-staging"', "production or staging resource"),
            (f'WORKER_NAME = "{WORKER_NAME}"', 'WORKER_NAME = "corelink-staging"', "production or staging resource"),
            (f'WORKER_NAME = "{WORKER_NAME}"', 'WORKER_NAME = "corelink-other-6a"', "outside the dedicated"),
            (f'CF_ACCOUNT = "{CF_ACCOUNT}"', 'CF_ACCOUNT = "not-an-account"', "malformed"),
        ):
            with self.subTest(drifted=drifted):
                self.assertEqual(source.count(constant), 1)
                with self.assertRaisesRegex(Exception, reason) as raised:
                    load(source.replace(constant, drifted))
                self.assertEqual(type(raised.exception).__name__, "OperatorError")

    def test_cloudflare_request_fence_refuses_everything_but_the_disposable_pair(self) -> None:
        base = f"/accounts/{CF_ACCOUNT}"
        allowed = [
            ("GET", f"{base}/workers/subdomain", None, None),
            ("GET", f"{base}/workers/scripts/{WORKER_NAME}", None, None),
            ("GET", f"{base}/workers/scripts/{WORKER_NAME}/settings", None, None),
            ("GET", f"{base}/workers/scripts/{WORKER_NAME}/subdomain", None, None),
            ("GET", f"{base}/workers/scripts/{WORKER_NAME}/schedules", None, None),
            ("GET", f"{base}/workers/scripts/{WORKER_NAME}/versions", None, None),
            ("DELETE", f"{base}/workers/scripts/{WORKER_NAME}", None, None),
            ("GET", f"{base}/d1/database?name={D1_NAME}", None, None),
            ("POST", f"{base}/d1/database", {"name": D1_NAME}, None),
            ("GET", f"{base}/d1/database/{BOUND_D1_UUID}", None, BOUND_D1_UUID),
            ("POST", f"{base}/d1/database/{BOUND_D1_UUID}/query", {"sql": "SELECT 1", "params": []}, BOUND_D1_UUID),
            ("DELETE", f"{base}/d1/database/{BOUND_D1_UUID}", None, BOUND_D1_UUID),
        ]
        for method, path, data, bound in allowed:
            with self.subTest(allowed=(method, path)):
                assert_cloudflare_request(method, path, data, bound)
        refused = [
            ("GET", f"/accounts/{RETIRED_CF_ACCOUNT}/workers/subdomain", None, None, "pinned #2568 account"),
            ("GET", "/zones?account.id=" + CF_ACCOUNT, None, None, "pinned #2568 account"),
            ("DELETE", f"{base}/workers/scripts/corelink-prod", None, None, "allowlist"),
            ("GET", f"{base}/workers/scripts/corelink-staging/settings", None, None, "allowlist"),
            ("PUT", f"{base}/workers/scripts/{WORKER_NAME}", None, None, "allowlist"),
            ("PATCH", f"{base}/workers/subdomain", None, None, "allowlist"),
            ("GET", f"{base}/d1/database", None, None, "allowlist"),
            ("GET", f"{base}/d1/database?name=corelink-prod-d1", None, None, "allowlist"),
            ("POST", f"{base}/d1/database", {"name": "corelink-prod-d1"}, None, "D1 create"),
            ("POST", f"{base}/d1/database", {"name": D1_NAME, "primary_location_hint": "weur"}, None, "D1 create"),
            ("POST", f"{base}/d1/database/{BOUND_D1_UUID}/query", {"sql": "SELECT 1"}, None, "did not create"),
            ("POST", f"{base}/d1/database/{PRODUCTION_D1_UUID}/query", {"sql": "SELECT 1"}, PRODUCTION_D1_UUID,
             "production or staging database"),
            ("DELETE", f"{base}/d1/database/{PRODUCTION_D1_UUID}", None, PRODUCTION_D1_UUID,
             "production or staging database"),
            ("DELETE", f"{base}/d1/database/{BOUND_D1_UUID}/query", None, BOUND_D1_UUID, "allowlist"),
            ("GET", f"{base}/d1/database/not-a-uuid", None, BOUND_D1_UUID, "canonical UUID"),
        ]
        for method, path, data, bound, reason in refused:
            with self.subTest(refused=(method, path)):
                with self.assertRaisesRegex(OperatorError, reason):
                    assert_cloudflare_request(method, path, data, bound)
        cf = Cloudflare("t")
        with patch(f"{OPERATOR_MODULE}.urllib.request.urlopen") as urlopen:
            for method, path, data in (
                ("DELETE", f"{base}/d1/database/{PRODUCTION_D1_UUID}", None),
                ("POST", f"{base}/d1/database/{BOUND_D1_UUID}/query", {"sql": "DROP TABLE x"}),
                ("DELETE", f"{base}/workers/scripts/corelink-signup-worker", None),
            ):
                with self.subTest(client=(method, path)):
                    with self.assertRaises(OperatorError):
                        cf.request(method, path, data)
            urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
