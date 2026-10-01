#!/usr/bin/env python3
"""Fail closed unless every task returned for the target cluster is terminal."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterable, Mapping


class TaskSnapshotError(ValueError):
    """The ECS task snapshot is incomplete, inconsistent, or not idle."""


# ECS accepts PENDING as a desiredStatus filter but always returns no results:
# PENDING is a lastStatus, so an empty PENDING query cannot prove idleness.
TASK_DESIRED_STATUSES = ("RUNNING", "STOPPED")


def validate_task_snapshots(
    listed: Mapping[str, Mapping[str, object]],
    described: Iterable[Mapping[str, object]],
    cluster_arn: str,
) -> None:
    task_arns: list[str] = []
    for desired_status in TASK_DESIRED_STATUSES:
        response = listed.get(desired_status)
        if not isinstance(response, Mapping):
            raise TaskSnapshotError(f"missing {desired_status} list response")
        arns = response.get("taskArns")
        if not isinstance(arns, list) or any(not isinstance(arn, str) or not arn for arn in arns):
            raise TaskSnapshotError(f"invalid {desired_status} task list")
        task_arns.extend(arns)
    if len(task_arns) != len(set(task_arns)):
        raise TaskSnapshotError("task ARN appeared in more than one desired-status list")

    tasks = list(described)
    described_arns = [task.get("taskArn") for task in tasks]
    if any(not isinstance(arn, str) or not arn for arn in described_arns):
        raise TaskSnapshotError("DescribeTasks returned an invalid task ARN")
    if len(described_arns) != len(set(described_arns)) or set(described_arns) != set(task_arns):
        raise TaskSnapshotError("DescribeTasks response was incomplete or inconsistent")
    for task in tasks:
        if task.get("clusterArn") != cluster_arn:
            raise TaskSnapshotError("DescribeTasks returned a task outside the target cluster")
        if task.get("lastStatus") != "STOPPED":
            raise TaskSnapshotError("target cluster still has a task that is not terminal")


def _aws_json(*args: str) -> Mapping[str, object]:
    result = subprocess.run(
        ["aws", *args, "--output", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, Mapping):
        raise TaskSnapshotError("AWS CLI returned a non-object response")
    return value


def assert_cluster_idle(cluster_arn: str) -> None:
    listed: dict[str, Mapping[str, object]] = {}
    arns: list[str] = []
    for status in TASK_DESIRED_STATUSES:
        response = _aws_json("ecs", "list-tasks", "--cluster", cluster_arn, "--desired-status", status)
        listed[status] = response
        status_arns = response.get("taskArns")
        if not isinstance(status_arns, list) or any(not isinstance(arn, str) for arn in status_arns):
            raise TaskSnapshotError(f"invalid {status} task list")
        arns.extend(status_arns)

    described: list[Mapping[str, object]] = []
    for start in range(0, len(arns), 100):
        response = _aws_json(
            "ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks", *arns[start : start + 100]
        )
        failures = response.get("failures")
        tasks = response.get("tasks")
        if failures != [] or not isinstance(tasks, list):
            raise TaskSnapshotError("DescribeTasks reported failures or an invalid task list")
        described.extend(task for task in tasks if isinstance(task, Mapping))

    validate_task_snapshots(listed, described, cluster_arn)
    print(f"ECS cluster task snapshot is terminal ({len(arns)} tasks checked)")


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("arn:aws:ecs:"):
        print("usage: issue_2165_cleanup_tasks.py <exact-cluster-arn>", file=sys.stderr)
        return 2
    try:
        assert_cluster_idle(sys.argv[1])
    except (TaskSnapshotError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"ECS cleanup safety check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
