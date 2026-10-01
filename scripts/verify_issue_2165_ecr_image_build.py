#!/usr/bin/env python3
"""Credentialless contract checks for the bounded #2165 ECR build lane."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


class ContractError(ValueError):
    pass


def validate(workflow: str, runtime: str) -> None:
    required_workflow = (
        "workflow_dispatch:",
        "environment: b083-kms-lifecycle",
        "IMAGE_CLEANUP_ROLE_ARN: ${{ vars.B083_AWS_IMAGE_CLEANUP_ROLE_ARN }}",
        'test \"$IMAGE_CLEANUP_ROLE_ARN\" != \"$IMAGE_BUILD_ROLE_ARN\"',
        "aws ecr describe-images",
        "imageDetails[0].imageSizeInBytes",
        "jq -r '.manifests[].digest'",
        "cap_bytes=$((20 * 1000 * 1000 * 1000))",
        "total_bytes=$((total_bytes + bytes))",
        "aws ecr get-lifecycle-policy",
        '"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":1',
        "Existing ECR retention policy differs; refusing to replace it.",
        "aws ecr put-lifecycle-policy",
        "steps.image-size.outputs.within_cap == 'false'",
        "aws ecr batch-delete-image",
        '--image-ids imageTag=\"$SOURCE_SHA\"',
        "cleanup_deleted_exact_run_tags",
        'retention:\"successful-under-cap-tags-retained-for-authorized-lifecycle\"',
        "Fail the build after cleanup when aggregate image size exceeds 20 GB",
    )
    if any(marker not in workflow for marker in required_workflow):
        raise ContractError("image build workflow is missing a bounded cap, isolated cleanup role, exact-tag cleanup, or retention receipt control")
    if workflow.count("aws ecr batch-delete-image") != 1:
        raise ContractError("image cleanup must have exactly one narrowly scoped delete command")
    if workflow.index("aws ecr get-lifecycle-policy") > workflow.index("aws ecr put-lifecycle-policy"):
        raise ContractError("retention policy must be read before creation")
    if workflow.index("Delete only this run's image tags") > workflow.index("Fail the build after cleanup when aggregate image size exceeds 20 GB"):
        raise ContractError("oversize failure must be reported after cleanup")
    cleanup_condition = "steps.app.outcome != 'success' || steps.operator.outcome != 'success' || steps.readback.outcome != 'success' || steps.image-size.outcome != 'success' || steps.image-size.outputs.within_cap == 'false'"
    if cleanup_condition not in workflow or "(steps.app.outcome != 'skipped' || steps.operator.outcome != 'skipped')" not in workflow:
        raise ContractError("cleanup must run for partial builds, failed readback, or aggregate size above the cap")

    required_runtime = (
        "MAX_CONCURRENT_TASKS = 2",
        '"ecs", "list-tasks"',
        '"--desired-status", status',
        '("RUNNING", "PENDING", "STOPPED")',
        '"ecs", "describe-tasks"',
        'if status != "STOPPED"',
        "active.difference(allowed_existing)",
        "set(allowed_existing).issubset(active)",
        "len(active) >= MAX_CONCURRENT_TASKS",
        "allowed_existing_task_arns=(app_task,)",
    )
    if any(marker not in runtime for marker in required_runtime):
        raise ContractError("runtime task launcher does not fail closed at the dedicated two-task ceiling")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(args.workflow.read_text(encoding="utf-8"), args.runtime.read_text(encoding="utf-8"))
    except (OSError, ContractError) as exc:
        print(f"Issue #2165 ECR/runtime contract failed: {exc}", file=sys.stderr)
        return 1
    print("Issue #2165 ECR image cap, cleanup, retention, and task concurrency contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
