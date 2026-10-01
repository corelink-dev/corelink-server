from __future__ import annotations

import sys
import unittest
import datetime as dt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from issue_2165_image_budget import BudgetError, validate_budget, validate_cleanup_deadline  # noqa: E402
from issue_2165_cleanup_tasks import TASK_DESIRED_STATUSES, TaskSnapshotError, validate_task_snapshots  # noqa: E402
from verify_issue_2165_ecr_image_build import ContractError, validate  # noqa: E402


class ImageBuildContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (ROOT / ".github/workflows/issue-2165-ecr-image-build.yml").read_text()
        self.runtime = (ROOT / "scripts/issue_2165_kms_runtime.py").read_text()
        self.cleanup_tasks = (ROOT / "scripts/issue_2165_cleanup_tasks.py").read_text()

    def test_current_image_and_runtime_contract(self) -> None:
        validate(self.workflow, self.runtime, self.cleanup_tasks)

    def test_rejects_missing_cap_or_cleanup_role(self) -> None:
        for marker in ("cap_bytes=$((20 * 1000 * 1000 * 1000))", "IMAGE_CLEANUP_ROLE_ARN: ${{ vars.B083_AWS_IMAGE_CLEANUP_ROLE_ARN }}", '"countNumber":1'):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime, self.cleanup_tasks)

    def test_rejects_broad_delete_or_cleanup_of_under_cap_success(self) -> None:
        with self.assertRaisesRegex(ContractError, "each have one exact-tag"):
            validate(self.workflow.replace('aws ecr batch-delete-image', 'aws ecr batch-delete-image\n          aws ecr batch-delete-image'), self.runtime, self.cleanup_tasks)
        condition = " || steps.image-size.outputs.within_cap == 'false'"
        with self.assertRaises(ContractError):
            validate(self.workflow.replace(condition, ""), self.runtime, self.cleanup_tasks)

    def test_rejects_single_task_policy_or_foreign_tasks(self) -> None:
        for marker in ("MAX_CONCURRENT_TASKS = 2", "active.difference(allowed_existing)"):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow, self.runtime.replace(marker, ""), self.cleanup_tasks)

    def test_budget_requires_finite_exact_remaining_and_five_dollar_reserve(self) -> None:
        self.assertEqual(validate_budget("10", "10", "5", "0"), (10, 10, 5, 0))
        for values in (
            ("15", "5", "0.01", "0"),
            ("14", "6", "1.01", "0"),
            ("14", "6", "0.5", "0.6"),
            ("21", "-1", "1", "0"),
            ("1", "18", "1", "0"),
            ("-1", "21", "1", "0"),
            ("NaN", "NaN", "1", "0"),
            ("Infinity", "-Infinity", "1", "0"),
            ("bad", "19", "1", "0"),
            (True, "19", "1", "0"),
            ("10", "10", "5", "NaN"),
        ):
            with self.subTest(values=values), self.assertRaises(BudgetError):
                validate_budget(*values)

    def test_cleanup_deadline_covers_full_build_timeout_but_stays_within_24_hours(self) -> None:
        now = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
        self.assertEqual(validate_cleanup_deadline("2026-10-01T02:00:00Z", now), now + dt.timedelta(hours=2))
        for deadline in ("2026-10-01T01:50:00Z", "2026-10-02T01:00:00Z", "2026-09-30T23:00:00Z", "2026-10-01T02:00:00", "invalid"):
            with self.subTest(deadline=deadline), self.assertRaises(BudgetError):
                validate_cleanup_deadline(deadline, now)

    def test_cleanup_mode_requires_exact_manifest_preimage_and_idle_task_gates(self) -> None:
        for marker in (
            'lease["app_digest"] == os.environ["APP_DIGEST"]',
            'lease["operator_digest"] == os.environ["OPERATOR_DIGEST"]',
            'lease["owner"] == os.environ["GITHUB_ACTOR"]',
            "imageTag=\"$SOURCE_SHA\"",
            "python3 scripts/issue_2165_cleanup_tasks.py \"$cluster\"",
            "postread:$postread_at",
            'lease["cleanup_operation_ref"] == "cleanup-successful-images"',
            'lease["cleanup_deadline_at"]',
            "if: always()\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime, self.cleanup_tasks)


class CleanupTaskSnapshotTests(unittest.TestCase):
    cluster = "arn:aws:ecs:us-east-1:046797548582:cluster/i2165-b083-20260930-fab9cc09-cluster"
    task = "arn:aws:ecs:us-east-1:046797548582:task/i2165-b083-20260930-fab9cc09-cluster/0123456789abcdef"

    def test_pending_filter_is_excluded_because_it_is_a_last_status(self) -> None:
        self.assertEqual(TASK_DESIRED_STATUSES, ("RUNNING", "STOPPED"))

    def test_empty_running_and_stopped_lists_are_idle(self) -> None:
        validate_task_snapshots({"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": []}}, [], self.cluster)

    def test_stopped_desired_but_running_last_status_blocks_deletion(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        described = [{"taskArn": self.task, "clusterArn": self.cluster, "desiredStatus": "STOPPED", "lastStatus": "RUNNING"}]
        with self.assertRaisesRegex(TaskSnapshotError, "not terminal"):
            validate_task_snapshots(listed, described, self.cluster)

    def test_stopped_desired_and_stopped_last_status_is_terminal(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        described = [{"taskArn": self.task, "clusterArn": self.cluster, "desiredStatus": "STOPPED", "lastStatus": "STOPPED"}]
        validate_task_snapshots(listed, described, self.cluster)

    def test_incomplete_or_cross_cluster_describe_fails_closed(self) -> None:
        listed = {"RUNNING": {"taskArns": []}, "STOPPED": {"taskArns": [self.task]}}
        with self.assertRaisesRegex(TaskSnapshotError, "incomplete"):
            validate_task_snapshots(listed, [], self.cluster)
        described = [{"taskArn": self.task, "clusterArn": "arn:aws:ecs:us-east-1:046797548582:cluster/other", "lastStatus": "STOPPED"}]
        with self.assertRaisesRegex(TaskSnapshotError, "outside"):
            validate_task_snapshots(listed, described, self.cluster)


if __name__ == "__main__":
    unittest.main()
