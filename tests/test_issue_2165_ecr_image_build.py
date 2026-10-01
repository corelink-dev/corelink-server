from __future__ import annotations

import sys
import unittest
import datetime as dt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from issue_2165_image_budget import BudgetError, validate_budget, validate_cleanup_deadline  # noqa: E402
from verify_issue_2165_ecr_image_build import ContractError, validate  # noqa: E402


class ImageBuildContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (ROOT / ".github/workflows/issue-2165-ecr-image-build.yml").read_text()
        self.runtime = (ROOT / "scripts/issue_2165_kms_runtime.py").read_text()

    def test_current_image_and_runtime_contract(self) -> None:
        validate(self.workflow, self.runtime)

    def test_rejects_missing_cap_or_cleanup_role(self) -> None:
        for marker in ("cap_bytes=$((20 * 1000 * 1000 * 1000))", "IMAGE_CLEANUP_ROLE_ARN: ${{ vars.B083_AWS_IMAGE_CLEANUP_ROLE_ARN }}", '"countNumber":1'):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime)

    def test_rejects_broad_delete_or_cleanup_of_under_cap_success(self) -> None:
        with self.assertRaisesRegex(ContractError, "each have one exact-tag"):
            validate(self.workflow.replace('aws ecr batch-delete-image', 'aws ecr batch-delete-image\n          aws ecr batch-delete-image'), self.runtime)
        condition = " || steps.image-size.outputs.within_cap == 'false'"
        with self.assertRaises(ContractError):
            validate(self.workflow.replace(condition, ""), self.runtime)

    def test_rejects_single_task_policy_or_foreign_tasks(self) -> None:
        for marker in ("MAX_CONCURRENT_TASKS = 2", "active.difference(allowed_existing)"):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow, self.runtime.replace(marker, ""))

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
            "aws ecs list-tasks --cluster \"$cluster\" --desired-status \"$status\"",
            "postread:$postread_at",
            'lease["cleanup_operation_ref"] == "cleanup-successful-images"',
            'lease["cleanup_deadline_at"]',
            "if: always()\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow.replace(marker, ""), self.runtime)


if __name__ == "__main__":
    unittest.main()
