import copy
import unittest

from scripts import verify_i2575_readiness as readiness

SHA = "a" * 40
VERSION = "12345678-1234-1234-1234-123456789abc"
IMAGE = "sha256:" + "b" * 64


def deployment_run(path):
    return {"path": path, "event": "workflow_dispatch", "head_branch": "main",
            "head_sha": SHA, "status": "completed", "conclusion": "success"}


def deployment_receipts():
    return (
        {"candidate_version_id": VERSION, "rollout_state": "candidate",
         "provider_postflight": {"verified": True}},
        {"contract": "corelink-staging-runtime-deployment-proof-v1",
         "account_id": readiness.ACCOUNT_ID, "worker_name": readiness.WORKER,
         "workflow_sha": SHA, "worker_release": SHA, "container_image_digest": IMAGE,
         "schedule_restored_empty": True, "tail_deleted": True},
    )


def endpoint_receipt():
    return {"mode": "publish", "action": "published-and-health-verified",
            "hostname": readiness.HOST, "worker": readiness.WORKER,
            "health_result": "healthy",
            "runtime_secret_bindings_ready": True, "canonical_route_count": 0,
            "custom_domain_count": 1, "custom_domain_id": "c" * 32,
            "certificate_id": "12345678-1234-1234-1234-123456789abc",
            "dns_record_count": 1, "dns_record_ids": ["d" * 32]}


def http_deployment_receipts():
    deployment, runtime = deployment_receipts()
    del runtime["schedule_restored_empty"], runtime["tail_deleted"]
    native = {
        "contract": "corelink-staging-d1-binding-runtime-v1", "outcome": "pass",
        "probe_nonce": "issue-1700-recovery-20261001-v11", "worker_release": SHA,
        "scheduled_time_ms": 1790884800000,
        "parameterized_select": True, "failed_batch_observed": True,
        "rollback_absence_verified": True, "probe_table_dropped": True,
        "d1_binding_intercepted": True, "authorization_absent": True, "cf_api_token_absent": True,
        "old_probe_release": "0f785fb9b096afe01247f1057d46377b9f604f13",
        "old_probe_retired": True, "old_probe_tables_absent": True,
        "v5_probe_release": "cc32b3d819181bf9175e795868f66212aa5456c1",
        "v5_probe_retired": True, "v5_probe_tables_absent": True,
        "v5_prior_execution": "unknown", "v4_probe_catalog_absent": True,
    }
    proof = {
        "contract": "corelink-staging-d1-http-proof-v1", "carrier": "authenticated_http",
        "worker_release": SHA, "probe_nonce": native["probe_nonce"],
        "status": "complete", "rollback_safe": True, "native_receipt": copy.deepcopy(native),
    }
    for version, old_release in (
        ("v8", "7d18bcfc450db97b1b987923050b92971da530a8"),
        ("v9", "5da497051f0b11dbfc8b87d1dfa8e753304e2719"),
    ):
        proof[version + "_cleanup"] = {
            "contract": f"corelink-staging-{version}-cleanup-v1", "old_release": old_release,
            "old_nonce": "issue-1700-recovery-20261001-" + version, "worker_release": SHA,
            "prior_execution": "unknown", "prior_admission_present": False,
            "container_stopped": True, "alarm_absent": True, "tables_absent": True,
            "completed_at_ms": 1790884801000,
        }
    runtime.update(carrier="authenticated_http", probe_nonce=native["probe_nonce"],
                   origin="https://corelink-staging.gmhelmold.workers.dev", http_proof=proof,
                   receipt=native, schedules_empty=True, tails_empty=True)
    return deployment, runtime


class HttpReadinessEvidenceTests(unittest.TestCase):
    def assert_rejected(self, runtime):
        with self.assertRaises(readiness.ReadinessError):
            readiness.validate_deployment_receipts(http_deployment_receipts()[0], runtime, expected_sha=SHA)

    def test_accepts_separate_http_carrier_without_scheduled_or_tail_execution_claims(self):
        deployment, runtime = http_deployment_receipts()
        self.assertEqual(len(runtime), 13)
        self.assertEqual(len(runtime["http_proof"]), 9)
        self.assertEqual(len(runtime["receipt"]), 20)
        self.assertEqual(len(runtime["http_proof"]["v8_cleanup"]), 10)
        self.assertEqual(len(runtime["http_proof"]["v9_cleanup"]), 10)
        self.assertNotIn("schedule_restored_empty", runtime)
        self.assertNotIn("tail_deleted", runtime)
        self.assertEqual(readiness.validate_deployment_receipts(deployment, runtime, expected_sha=SHA),
                         {"worker_version_id": VERSION, "image_digest": IMAGE})

    def test_rejects_missing_or_extra_keys_at_every_http_layer(self):
        for path in ((), ("http_proof",), ("receipt",), ("http_proof", "native_receipt"),
                     ("http_proof", "v8_cleanup"), ("http_proof", "v9_cleanup")):
            for extra in (False, True):
                with self.subTest(path=path, extra=extra):
                    runtime = http_deployment_receipts()[1]
                    value = runtime
                    for key in path:
                        value = value[key]
                    if extra:
                        value["unexpected"] = "private-sentinel"
                    else:
                        value.pop(next(iter(value)))
                    self.assert_rejected(runtime)

    def test_rejects_wrong_identity_origin_quiescence_and_mixed_carriers(self):
        for key, value in (
            ("carrier", "scheduled"), ("worker_release", "c" * 40), ("workflow_sha", "c" * 40),
            ("account_id", "other"), ("worker_name", "production"),
            ("origin", "https://corelink-staging.other.workers.dev"),
            ("probe_nonce", "issue-1700-recovery-20261001-v9"),
            ("schedules_empty", False), ("tails_empty", False), ("tails_empty", 1),
            ("http_proof", None), ("schedule_restored_empty", True), ("tail_deleted", True),
        ):
            with self.subTest(key=key, value=value):
                runtime = http_deployment_receipts()[1]
                runtime[key] = value
                self.assert_rejected(runtime)
        runtime = http_deployment_receipts()[1]
        del runtime["carrier"]
        runtime.update(schedule_restored_empty=True, tail_deleted=True)
        self.assert_rejected(runtime)

    def test_rejects_noncomplete_unsafe_or_wrong_release_http_proof(self):
        for key, value in (("status", "unknown"), ("status", "running"), ("status", "not_started"),
                           ("rollback_safe", False), ("rollback_safe", 1),
                           ("worker_release", "c" * 40), ("carrier", "scheduled"),
                           ("probe_nonce", "issue-1700-recovery-20261001-v9")):
            with self.subTest(key=key, value=value):
                runtime = http_deployment_receipts()[1]
                runtime["http_proof"][key] = value
                self.assert_rejected(runtime)

    def test_native_proof_requires_every_boolean_identity_and_aligned_window(self):
        native = http_deployment_receipts()[1]["receipt"]
        mutations = [(key, False) for key, value in native.items() if value is True] + [
            ("worker_release", "c" * 40), ("probe_nonce", "issue-1700-recovery-20261001-v9"),
            ("old_probe_release", "c" * 40), ("v5_probe_release", "c" * 40),
            ("v5_prior_execution", "complete"), ("outcome", "fail"),
            ("scheduled_time_ms", 1790884680000), ("scheduled_time_ms", 1790892120000),
            ("scheduled_time_ms", 1790884800001), ("scheduled_time_ms", True),
            ("scheduled_time_ms", 1790884800000.0), ("parameterized_select", 1),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                runtime = http_deployment_receipts()[1]
                runtime["receipt"][key] = value
                runtime["http_proof"]["native_receipt"][key] = value
                self.assert_rejected(runtime)

    def test_wrapper_native_receipt_must_match_and_cannot_alias_integer_true(self):
        runtime = http_deployment_receipts()[1]
        runtime["receipt"]["scheduled_time_ms"] = 1790884920000
        self.assert_rejected(runtime)
        runtime = http_deployment_receipts()[1]
        runtime["receipt"]["parameterized_select"] = 1
        self.assert_rejected(runtime)

    def test_requires_both_exact_old_cleanup_proofs(self):
        for version in ("v8", "v9"):
            for key, value in (
                ("old_release", SHA), ("old_nonce", "issue-1700-recovery-20261001-v11"),
                ("worker_release", "c" * 40), ("prior_execution", "complete"),
                ("prior_admission_present", 1), ("container_stopped", False),
                ("alarm_absent", False), ("tables_absent", False),
                ("completed_at_ms", 1790884799999), ("completed_at_ms", 1790896500000),
                ("completed_at_ms", True), ("completed_at_ms", 1790884801000.0),
            ):
                with self.subTest(version=version, key=key, value=value):
                    runtime = http_deployment_receipts()[1]
                    runtime["http_proof"][version + "_cleanup"][key] = value
                    self.assert_rejected(runtime)
            runtime = http_deployment_receipts()[1]
            runtime["http_proof"][version + "_cleanup"] = None
            self.assert_rejected(runtime)


class ReadinessEvidenceTests(unittest.TestCase):
    def test_preserves_historical_v5_v8_v9_scheduled_receipts(self):
        for nonce in ("issue-1700-recovery-20260930-v5", "issue-1700-recovery-20261001-v8",
                      "issue-1700-recovery-20261001-v9"):
            with self.subTest(nonce=nonce):
                deployment, runtime = deployment_receipts()
                runtime["probe_nonce"] = nonce
                self.assertEqual(readiness.validate_deployment_receipts(deployment, runtime, expected_sha=SHA),
                                 {"worker_version_id": VERSION, "image_digest": IMAGE})

    def test_accepts_exact_successful_run_and_active_runtime_readbacks(self):
        run = deployment_run(".github/workflows/issue-1700-container-staging-deploy.yml")
        endpoint_run = deployment_run(".github/workflows/issue-1700-staging-custom-domain.yml")
        readiness.validate_run(run, expected_sha=SHA, workflow_path=run["path"])
        readiness.validate_run(endpoint_run, expected_sha=SHA, workflow_path=endpoint_run["path"])
        self.assertEqual(readiness.validate_deployment_receipts(*deployment_receipts(), expected_sha=SHA),
                         {"worker_version_id": VERSION, "image_digest": IMAGE})
        readiness.validate_endpoint_receipt(endpoint_receipt())
        readiness.validate_protected_binding({"worker_version_id": VERSION, "image_digest": IMAGE},
                                             worker_version=VERSION, image_digest=IMAGE)

    def test_rejects_protected_worker_or_image_binding_mismatch(self):
        binding = {"worker_version_id": VERSION, "image_digest": IMAGE}
        for field, value in (("worker_version_id", "87654321-1234-1234-1234-123456789abc"),
                             ("image_digest", "sha256:" + "c" * 64)):
            with self.subTest(field=field):
                changed = dict(binding)
                changed[field] = value
                with self.assertRaises(readiness.ReadinessError):
                    readiness.validate_protected_binding(changed, worker_version=VERSION, image_digest=IMAGE)

    def test_rejects_wrong_workflow_sha_branch_event_or_conclusion(self):
        base = deployment_run(".github/workflows/issue-1700-container-staging-deploy.yml")
        for key, value in (("path", ".github/workflows/other.yml"), ("head_sha", "d" * 40),
                           ("head_branch", "feature"), ("event", "push"), ("conclusion", "failure")):
            with self.subTest(key=key):
                run = copy.deepcopy(base)
                run[key] = value
                with self.assertRaises(readiness.ReadinessError):
                    readiness.validate_run(run, expected_sha=SHA, workflow_path=base["path"])

    def test_rejects_missing_or_unattributed_worker_and_image_readback(self):
        for which, key, value in ((0, "provider_postflight", {}), (0, "rollout_state", "unchanged"),
                                  (1, "worker_release", "d" * 40), (1, "container_image_digest", "sha256:bad"),
                                  (1, "tail_deleted", False)):
            with self.subTest(which=which, key=key):
                values = list(deployment_receipts())
                values[which] = copy.deepcopy(values[which])
                values[which][key] = value
                with self.assertRaises(readiness.ReadinessError):
                    readiness.validate_deployment_receipts(*values, expected_sha=SHA)

    def test_rejects_endpoint_receipt_mutations(self):
        base = endpoint_receipt()
        for key, value in (("hostname", "other.example"), ("mode", "preview"),
                           ("health_result", "http-503"), ("runtime_secret_bindings_ready", False),
                           ("canonical_route_count", 1), ("custom_domain_count", 0),
                           ("dns_record_count", 0), ("action", "publication-failed"),
                           ("custom_domain_id", "bad")):
            with self.subTest(key=key):
                receipt = copy.deepcopy(base)
                receipt[key] = value
                with self.assertRaises(readiness.ReadinessError):
                    readiness.validate_endpoint_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
