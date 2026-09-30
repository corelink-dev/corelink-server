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


class ReadinessEvidenceTests(unittest.TestCase):
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
