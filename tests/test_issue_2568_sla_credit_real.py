"""Meaningful fail-closed negatives for the #2568 provider operator."""
from __future__ import annotations

import copy
import unittest
import sys
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.issue_2568_sla_credit_real import IDENTITY as RESOLVER
from scripts.issue_2568_sla_credit_real import (
    BRANCH,
    OperatorError,
    OwnedStripeObjects,
    _ensure_absent_target,
    _create_wp2_customer,
    _fresh_main_acceptance,
    _with_fresh_main,
    assert_checkout,
    invoice_item_from_line,
    validate_account_binding,
    validate_restricted_key,
    verify_source_checkout,
)
from scripts.verify_issue_2568_sla_credit_real import (
    VerificationError,
    LEAF_PATHS,
    CORRECTION_PATHS,
    WP150_PATH,
    WP150_SHA256,
    SECRET_REGISTRY_PATH,
    SECRET_REGISTRY_SHA256,
    PROVIDER_CREDENTIAL_BINDINGS,
    SOURCE_DIGESTS,
    SOURCE_SHA,
    validate_receipt,
    validate_provider_receipt,
    validate_candidate_paths,
    validate_wp150_manifest,
    validate_secret_registry,
    validate_provider_credential_bindings,
    validate_source_manifest,
)


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
        status, payload = self.request("GET", "/accounts/51284495e71acdb5a7677e7383ab026b/workers/subdomain")
        if status != 200:
            raise OperatorError("existing account Workers subdomain/topology could not be verified")
        return payload["result"]

    def request(self, method, path, data=None):
        self.calls.append((method, path))
        if path.endswith("/workers/subdomain"):
            return self.subdomain_status, {"result": {"subdomain": "private-test"}} if self.subdomain_status == 200 else None
        if path.endswith("/workers/scripts/corelink-i2568-sla-credit-test-20260928"):
            return self.worker_status, {"result": {}} if self.worker_status == 200 else None
        if "/d1/database?name=" in path:
            return self.d1_status, {"result": []} if self.d1_status == 200 else None
        raise AssertionError((method, path))


def _read_back_fixture_identity():
    # The operator authorizes through scripts/server_repository.py, whose
    # committed config may still hold the unread ID 0. Keep the configured
    # owner and names; fill synthetic IDs only.
    document = copy.deepcopy(RESOLVER.read_identity_document())
    document["current"]["owner_id"] = 987650000
    for offset, key in enumerate(RESOLVER.REPOSITORY_KEYS, start=1):
        document["current"]["repos"][key]["id"] = 987650000 + offset
    return RESOLVER.parse_identity(document).require_read_back()


FIXTURE_IDENTITY = _read_back_fixture_identity()
FIXTURE_SERVER = FIXTURE_IDENTITY.repository("server")


def context_env(**overrides: str) -> dict[str, str]:
    env = {
        "GITHUB_REPOSITORY": FIXTURE_SERVER.full_name,
        "GITHUB_REPOSITORY_ID": str(FIXTURE_SERVER.id),
        "GITHUB_REF": BRANCH,
        "GITHUB_SHA": "a" * 40,
    }
    env.update(overrides)
    return env


class Issue2568OperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        identity = patch.object(RESOLVER, "load_identity", return_value=FIXTURE_IDENTITY)
        identity.start()
        self.addCleanup(identity.stop)

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
            env = context_env()
            with patch.dict("os.environ", env):
                self.assertEqual(assert_checkout("a" * 40), "a" * 40)
            self.assertEqual(
                command.call_args_list[1].args[0][3],
                f"https://github.com/{FIXTURE_SERVER.full_name}.git",
            )
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.return_value = "a" * 40 + "\n"
            env = context_env(GITHUB_REF="refs/heads/codex/support03-issue-2568")
            with patch.dict("os.environ", env):
                with self.assertRaisesRegex(OperatorError, "protected main ref"):
                    assert_checkout("a" * 40)
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.return_value = "b" * 40 + "\n"
            env = context_env(GITHUB_SHA="b" * 40)
            with patch.dict("os.environ", env):
                with self.assertRaisesRegex(OperatorError, "differs from expected_sha"):
                    assert_checkout("a" * 40)

    def test_retired_or_mismatched_repository_context_is_refused_before_remote_read(self) -> None:
        retired_id = str(min(FIXTURE_IDENTITY.retired_repository_ids))
        runners = FIXTURE_IDENTITY.repository("runners")
        for label, overrides in (
            ("retired destination owner and ID", {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REPOSITORY_ID": retired_id}),
            ("retired destination owner, current ID", {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server"}),
            ("retired source owner", {"GITHUB_REPOSITORY": "HuGR-Labs/corelink-server"}),
            ("current name, retired ID", {"GITHUB_REPOSITORY_ID": retired_id}),
            ("peer repository", {"GITHUB_REPOSITORY": runners.full_name, "GITHUB_REPOSITORY_ID": str(runners.id)}),
            ("missing repository ID", {"GITHUB_REPOSITORY_ID": ""}),
        ):
            with self.subTest(label=label):
                with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
                    command.return_value = "a" * 40 + "\n"
                    with patch.dict("os.environ", context_env(**overrides)):
                        with self.assertRaisesRegex(OperatorError, "canonical repository"):
                            assert_checkout("a" * 40)
                    # Only `git rev-parse HEAD` ran; no remote was contacted.
                    self.assertEqual(command.call_count, 1)

    def test_stale_protected_main_fails_before_provider_write(self) -> None:
        current_sha = "a" * 40
        stale_sha = "b" * 40
        with patch("scripts.issue_2568_sla_credit_real.subprocess.check_output") as command:
            command.side_effect = [
                current_sha + "\n",
                stale_sha + "\trefs/heads/main\n",
            ]
            env = context_env(GITHUB_SHA=current_sha)
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
        valid = (Path(__file__).resolve().parents[1] / WP150_PATH).read_bytes()
        self.assertEqual(sha256(valid).hexdigest(), WP150_SHA256)
        validate_wp150_manifest(valid, 0o100644)
        arbitrary_content = valid + b"\nforeign append\n"
        with self.assertRaisesRegex(VerificationError, "root-authorized"):
            validate_wp150_manifest(arbitrary_content, 0o100644)
        with self.assertRaisesRegex(VerificationError, "root-authorized"):
            validate_wp150_manifest(bytes.fromhex(WP150_SHA256), 0o100644)
        with self.assertRaisesRegex(VerificationError, "root-authorized"):
            validate_wp150_manifest(valid, 0o100755)

    def test_secret_registry_registers_i2568_and_denies_unknown_credential(self) -> None:
        registry = (Path(__file__).resolve().parents[1] / SECRET_REGISTRY_PATH).read_bytes()
        self.assertEqual(sha256(registry).hexdigest(), SECRET_REGISTRY_SHA256)
        validate_secret_registry(registry, 0o100644)
        with self.assertRaisesRegex(VerificationError, "root-authorized"):
            validate_secret_registry(registry + b"\nforeign append\n", 0o100644)
        with self.assertRaisesRegex(VerificationError, "root-authorized"):
            validate_secret_registry(registry, 0o100755)
        validate_provider_credential_bindings(PROVIDER_CREDENTIAL_BINDINGS.copy())
        unknown = {**PROVIDER_CREDENTIAL_BINDINGS, "UNREGISTERED_TOKEN": "secrets.UNREGISTERED_TOKEN"}
        with self.assertRaisesRegex(VerificationError, "unregistered or missing credential"):
            validate_provider_credential_bindings(unknown)
        with self.assertRaisesRegex(VerificationError, "unregistered or duplicate credential"):
            validate_provider_credential_bindings(
                PROVIDER_CREDENTIAL_BINDINGS.copy(),
                [*PROVIDER_CREDENTIAL_BINDINGS.values(), "secrets.UNREGISTERED_TOKEN"],
            )


if __name__ == "__main__":
    unittest.main()
