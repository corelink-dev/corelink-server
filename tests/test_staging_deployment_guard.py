from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import staging_deployment_guard as guard


def deployment(
    deployment_id: str,
    version_id: str,
    created_on: str,
    *,
    message: str = "old deployment",
    percentage: int = 100,
) -> dict:
    return {
        "id": deployment_id,
        "created_on": created_on,
        "versions": [{"version_id": version_id, "percentage": percentage}],
        "annotations": {"workers/message": message},
    }


PREVIOUS_DEPLOYMENT = "11111111-1111-4111-8111-111111111111"
PREVIOUS_VERSION = "22222222-2222-4222-8222-222222222222"
CANDIDATE_DEPLOYMENT = "33333333-3333-4333-8333-333333333333"
CANDIDATE_VERSION = "44444444-4444-4444-8444-444444444444"
ROLLBACK_DEPLOYMENT = "55555555-5555-4555-8555-555555555555"
MARKER = "issue-1700-route-free-123456"
ROLLBACK_MARKER = "issue-1700-route-free-rollback-123456"


class StagingDeploymentGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.preimage = {
            "deployment_id": PREVIOUS_DEPLOYMENT,
            "version_id": PREVIOUS_VERSION,
            "created_on": "2026-09-26T23:49:00Z",
        }

    def test_capture_chooses_latest_and_requires_single_full_traffic_version(
        self,
    ) -> None:
        state = [
            deployment(
                CANDIDATE_DEPLOYMENT,
                CANDIDATE_VERSION,
                "2026-09-27T03:49:00Z",
            ),
            deployment(
                PREVIOUS_DEPLOYMENT,
                PREVIOUS_VERSION,
                "2026-09-26T23:49:00Z",
            ),
        ]
        self.assertEqual(
            guard.capture_preimage(state),
            {
                "deployment_id": CANDIDATE_DEPLOYMENT,
                "version_id": CANDIDATE_VERSION,
                "created_on": "2026-09-27T03:49:00Z",
            },
        )
        state[0]["versions"][0]["percentage"] = 50
        with self.assertRaises(guard.DeploymentError):
            guard.capture_preimage(state)

    def test_capture_rejects_ambiguous_or_incomplete_current_state(self) -> None:
        row = deployment(
            PREVIOUS_DEPLOYMENT,
            PREVIOUS_VERSION,
            "2026-09-26T23:49:00Z",
        )
        with self.assertRaises(guard.DeploymentError):
            guard.capture_preimage([row, {**row, "id": CANDIDATE_DEPLOYMENT}])
        with self.assertRaises(guard.DeploymentError):
            guard.capture_preimage([{"id": "bad", "created_on": row["created_on"]}])

    def test_after_deploy_distinguishes_preimage_candidate_and_unrelated_change(
        self,
    ) -> None:
        before = deployment(
            PREVIOUS_DEPLOYMENT,
            PREVIOUS_VERSION,
            "2026-09-26T23:49:00Z",
        )
        self.assertEqual(
            guard.classify_after_deploy([before], self.preimage, MARKER),
            ("unchanged", None),
        )
        current = deployment(
            CANDIDATE_DEPLOYMENT,
            CANDIDATE_VERSION,
            "2026-09-27T03:50:00Z",
            message=MARKER,
        )
        self.assertEqual(
            guard.classify_after_deploy([current], self.preimage, MARKER),
            ("candidate", CANDIDATE_VERSION),
        )
        current["annotations"]["workers/message"] = "another operator's deploy"
        with self.assertRaises(guard.DeploymentError):
            guard.classify_after_deploy([current], self.preimage, MARKER)

    def test_rollback_requires_this_candidates_full_current_traffic(self) -> None:
        current = deployment(
            CANDIDATE_DEPLOYMENT,
            CANDIDATE_VERSION,
            "2026-09-27T03:50:00Z",
            message=MARKER,
        )
        guard.require_candidate_current([current], CANDIDATE_VERSION, MARKER)
        current["versions"][0]["percentage"] = 50
        with self.assertRaises(guard.DeploymentError):
            guard.require_candidate_current([current], CANDIDATE_VERSION, MARKER)
        current["versions"][0]["percentage"] = 100
        with self.assertRaises(guard.DeploymentError):
            guard.require_candidate_current(
                [current], CANDIDATE_VERSION, "wrong marker"
            )

    def test_rollback_readback_requires_exact_preimage_and_rollback_marker(
        self,
    ) -> None:
        current = deployment(
            ROLLBACK_DEPLOYMENT,
            PREVIOUS_VERSION,
            "2026-09-27T03:51:00Z",
            message=ROLLBACK_MARKER,
        )
        guard.require_rollback_current(
            current_list := [current], self.preimage, ROLLBACK_MARKER
        )
        self.assertEqual(len(current_list), 1)
        with self.assertRaises(guard.DeploymentError):
            guard.require_rollback_current([current], self.preimage, "wrong")

    def test_cli_receipt_records_candidate_and_exact_rollback(self) -> None:
        before = [
            deployment(
                PREVIOUS_DEPLOYMENT,
                PREVIOUS_VERSION,
                "2026-09-26T23:49:00Z",
            )
        ]
        candidate = [
            deployment(
                CANDIDATE_DEPLOYMENT,
                CANDIDATE_VERSION,
                "2026-09-27T03:50:00Z",
                message=MARKER,
            )
        ]
        rolled_back = [
            deployment(
                ROLLBACK_DEPLOYMENT,
                PREVIOUS_VERSION,
                "2026-09-27T03:51:00Z",
                message=ROLLBACK_MARKER,
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "receipt.json"
            output = root / "github-output"
            current = root / "deployments.json"
            routes = root / "routes.json"
            routes.write_text(
                json.dumps({"route_count": 0, "canonical_staging_route_count": 0}),
                encoding="utf-8",
            )
            current.write_text(json.dumps(before), encoding="utf-8")
            self.assertEqual(
                guard.main(
                    [
                        "capture",
                        "--deployments",
                        str(current),
                        "--output",
                        str(output),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
            current.write_text(json.dumps(candidate), encoding="utf-8")
            self.assertEqual(
                guard.main(
                    [
                        "candidate",
                        "--deployments",
                        str(current),
                        "--preimage",
                        str(receipt),
                        "--marker",
                        MARKER,
                        "--output",
                        str(output),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
            self.assertEqual(
                guard.main(
                    [
                        "rollback",
                        "--deployments",
                        str(current),
                        "--preimage",
                        str(receipt),
                        "--candidate-version-id",
                        CANDIDATE_VERSION,
                        "--candidate-marker",
                        MARKER,
                        "--rollback-marker",
                        ROLLBACK_MARKER,
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
            current.write_text(json.dumps(rolled_back), encoding="utf-8")
            self.assertEqual(
                guard.main(
                    [
                        "verify-rollback",
                        "--deployments",
                        str(current),
                        "--preimage",
                        str(receipt),
                        "--marker",
                        ROLLBACK_MARKER,
                        "--routes",
                        str(routes),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
            final_receipt = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertTrue(final_receipt["rollback"]["confirmed"])
            self.assertEqual(
                final_receipt["rollback"]["route_inventory"][
                    "canonical_staging_route_count"
                ],
                0,
            )

    def test_settings_requires_exact_frozen_compatibility_contract(self) -> None:
        topology = {
            "cloudflare": {
                "root_worker_settings": {
                    "compatibility_date": "2026-04-01",
                    "compatibility_flags": [
                        "nodejs_compat",
                        "enable_request_signal",
                        "request_signal_passthrough",
                    ],
                }
            }
        }
        flags = topology["cloudflare"]["root_worker_settings"]["compatibility_flags"]
        payload = {
            "success": True,
            "errors": [],
            "messages": [],
            "result": {
                "compatibility_date": "2026-04-01",
                "compatibility_flags": flags.copy(),
            },
        }
        self.assertEqual(
            guard.validate_worker_settings(payload, topology),
            {
                "compatibility_date": "2026-04-01",
                "compatibility_flags": sorted(flags),
            },
        )
        for bad_flags, bad_date in (
            (["nodejs_compat"], "2026-04-01"),
            ([*flags, "unexpected"], "2026-04-01"),
            (flags, "2026-05-01"),
        ):
            payload["result"]["compatibility_flags"] = bad_flags
            payload["result"]["compatibility_date"] = bad_date
            with (
                self.subTest(flags=bad_flags, date=bad_date),
                self.assertRaises(guard.DeploymentError),
            ):
                guard.validate_worker_settings(payload, topology)

    def test_route_receipt_rejects_any_canonical_host_match(self) -> None:
        self.assertEqual(
            guard.validate_route_receipt(
                {"route_count": 5, "canonical_staging_route_count": 0}
            ),
            {"route_count": 5, "canonical_staging_route_count": 0},
        )
        for payload in (
            {"route_count": 0, "canonical_staging_route_count": 1},
            {"route_count": 0, "canonical_staging_route_count": False},
            {"route_count": True, "canonical_staging_route_count": 0},
            {"route_count": -1, "canonical_staging_route_count": 0},
        ):
            with (
                self.subTest(payload=payload),
                self.assertRaises(guard.DeploymentError),
            ):
                guard.validate_route_receipt(payload)

    def test_workflow_has_exact_target_preimage_postflight_and_bounded_rollback(
        self,
    ) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/issue-1700-container-staging-deploy.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "github.event_name == 'workflow_dispatch'",
            "github.ref == 'refs/heads/main' && github.ref_protected",
            "config['account_id']='6a1fc1c626fc2628823e60b9db01f5cd'",
            "--name corelink-staging --json",
            '--message "$DEPLOYMENT_MARKER"',
            "assert-candidate",
            "scripts/verify_issue_1700_route_inventory.py",
            "scripts/staging_deployment_guard.py settings",
            "scripts/staging_deployment_guard.py record-success",
            'wrangler versions deploy "${PREIMAGE_VERSION_ID}@100%"',
            "if: failure() && steps.candidate.outputs.candidate_version_id != ''",
            '--message "$ROLLBACK_MARKER"',
            "if: always()",
            "upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        deploy_step = workflow.split(
            "- name: Deploy root with container rollout and no route", 1
        )[1].split("- name: Identify only this run's exact rollout", 1)[0]
        self.assertNotIn("--routes", deploy_step)
        self.assertNotIn("--domains", deploy_step)
        names = [
            "Install pinned Wrangler and capture exact active preimage",
            "Deploy root with container rollout and no route",
            "Identify only this run's exact rollout",
            "Require the new deployment to be attributable before validation",
            "Verify deployed compatibility flags and empty route inventory",
            "Roll back only this run to the recorded exact preimage",
            "Upload redacted route-free deployment receipt",
        ]
        positions = [workflow.index(name) for name in names]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
