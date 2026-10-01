from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
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
        with self.assertRaisesRegex(ContractError, "narrowly scoped"):
            validate(self.workflow.replace('aws ecr batch-delete-image', 'aws ecr batch-delete-image\n          aws ecr batch-delete-image'), self.runtime)
        condition = " || steps.image-size.outputs.within_cap == 'false'"
        with self.assertRaises(ContractError):
            validate(self.workflow.replace(condition, ""), self.runtime)

    def test_rejects_single_task_policy_or_foreign_tasks(self) -> None:
        for marker in ("MAX_CONCURRENT_TASKS = 2", "active.difference(allowed_existing)"):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate(self.workflow, self.runtime.replace(marker, ""))


if __name__ == "__main__":
    unittest.main()
