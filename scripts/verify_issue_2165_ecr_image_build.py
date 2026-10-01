#!/usr/bin/env python3
"""Credentialless contract checks for the bounded #2165 ECR build lane."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


class ContractError(ValueError):
    pass


def validate(workflow: str, runtime: str, cleanup_tasks: str = "") -> None:
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
        "inputs.operation == 'build-both-images'",
        "inputs.operation == 'cleanup-successful-images'",
        "from issue_2165_image_budget import validate_budget, validate_cleanup_deadline",
        'lease["cleanup_operation_ref"] == "cleanup-successful-images"',
        'lease["cleanup_deadline_at"]',
        '"cleanup_deadline_at"], now)',
        'dt.timedelta(hours=2)',
        'dt.timedelta(hours=24)',
        'lease["commitments_receipt_ref"]',
        'lease["campaign_commitments_usd"]',
        'git merge-base --is-ancestor "$SOURCE_SHA" "$GITHUB_SHA"',
        'lease["operation"] == "cleanup-successful-images"',
        'lease["owner"] == os.environ["GITHUB_ACTOR"]',
        'lease["app_repository"] == os.environ["APP_REPOSITORY"]',
        'lease["operator_repository"] == os.environ["OPERATOR_REPOSITORY"]',
        'lease["app_digest"] == os.environ["APP_DIGEST"]',
        'lease["operator_digest"] == os.environ["OPERATOR_DIGEST"]',
        "Final read-only task check, assume cleanup role, and delete exact SHA tags",
        'python3 scripts/issue_2165_cleanup_tasks.py "$cluster"',
        "aws sts assume-role-with-web-identity",
        "readback_times_utc",
        "postread:$postread_at",
        "role_arns",
    )
    if any(marker not in workflow for marker in required_workflow):
        raise ContractError("image build workflow is missing a bounded cap, isolated cleanup role, exact-tag cleanup, or retention receipt control")
    if workflow.count('python3 scripts/issue_2165_cleanup_tasks.py "$cluster"') != 2:
        raise ContractError("both pre-delete checks must validate RUNNING and STOPPED task lifecycle states")
    required_cleanup_tasks = (
        'TASK_DESIRED_STATUSES = ("RUNNING", "STOPPED")',
        'PENDING is a lastStatus',
        '"ecs", "list-tasks", "--cluster", cluster_arn, "--desired-status", status',
        '"ecs", "describe-tasks"',
        'task.get("lastStatus") != "STOPPED"',
        'response.get("failures", [])',
        'not isinstance(failures, list) or failures',
    )
    if any(marker not in cleanup_tasks for marker in required_cleanup_tasks):
        raise ContractError("cleanup task check must describe RUNNING and STOPPED desired-state results and fail closed before deletion")
    if workflow.count("aws ecr batch-delete-image") != 2:
        raise ContractError("failed-build and successful-image cleanup must each have one exact-tag delete command")
    if workflow.index("aws ecr get-lifecycle-policy") > workflow.index("aws ecr put-lifecycle-policy"):
        raise ContractError("retention policy must be read before creation")
    if workflow.index("Delete only this run's image tags") > workflow.index("Fail the build after cleanup when aggregate image size exceeds 20 GB"):
        raise ContractError("oversize failure must be reported after cleanup")
    cleanup_condition = "steps.app.outcome != 'success' || steps.operator.outcome != 'success' || steps.readback.outcome != 'success' || steps.image-size.outcome != 'success' || steps.image-size.outputs.within_cap == 'false'"
    if cleanup_condition not in workflow or "(steps.app.outcome != 'skipped' || steps.operator.outcome != 'skipped')" not in workflow:
        raise ContractError("cleanup must run for partial builds, failed readback, or aggregate size above the cap")
    if workflow.index("validate_budget(lease[") > workflow.index("Build and push the exact-main application image"):
        raise ContractError("protected reserve admission must complete before either image build dispatch")
    cleanup_job = workflow.split("  cleanup-successful-images:\n", 1)[1]
    if "docker build" in cleanup_job or "docker push" in cleanup_job:
        raise ContractError("successful-image cleanup mode must not build or push images")
    delete_step = cleanup_job.split("- name: Final read-only task check, assume cleanup role, and delete exact SHA tags\n", 1)[1]
    if cleanup_job.index("Read back both exact SHA tags") > cleanup_job.index("aws sts assume-role-with-web-identity"):
        raise ContractError("exact digest preimage must pass before cleanup credentials are assumed")
    if not (
        delete_step.index('python3 scripts/issue_2165_cleanup_tasks.py "$cluster"')
        < delete_step.index("aws sts assume-role-with-web-identity")
        < delete_step.index("cleanup_aws ecr batch-delete-image")
    ):
        raise ContractError("final task reread must use the read-only role immediately before cleanup-role assumption and deletion in one step")
    receipt_step = cleanup_job.split("- name: Publish cleanup receipt\n", 1)[1]
    if "if: always()" not in receipt_step or "if-no-files-found: error" not in receipt_step:
        raise ContractError("cleanup receipt upload must be reached after failed, partial, or successful cleanup")

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
    parser.add_argument("--cleanup-tasks", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(
            args.workflow.read_text(encoding="utf-8"),
            args.runtime.read_text(encoding="utf-8"),
            args.cleanup_tasks.read_text(encoding="utf-8"),
        )
    except (OSError, ContractError) as exc:
        print(f"Issue #2165 ECR/runtime contract failed: {exc}", file=sys.stderr)
        return 1
    print("Issue #2165 ECR image cap, cleanup, retention, and task concurrency contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
