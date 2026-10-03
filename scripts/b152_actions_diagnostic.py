#!/usr/bin/env python3
"""Read-only GitHub Actions evidence collector for backlog item B-152.

The collector deliberately does not mutate GitHub state.  It walks the complete
run set in a UTC time window (splitting intervals when GitHub's 1,000-result
search cap would otherwise make pagination incomplete), then walks every jobs
page for failed runs.  Job logs are fetched only when requested and a missing
or expired log is reported as indeterminate rather than treated as clean.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode


UTC = dt.timezone.utc
SCHEMA = "b152-actions-diagnostic/v2"
MAX_SEARCH_RESULTS = 1_000
PAGE_SIZE = 100
# GitHub's documented step states are queued/in_progress/completed.  Historical
# job objects can also retain ``pending`` after a runner/startup failure; it is
# an unevaluated step, not a successful completion.  Keep the set explicit so
# a newly invented/non-string state still fails closed.
STEP_STATUSES = frozenset({"queued", "in_progress", "pending", "completed"})
ACTIVE_STEP_STATUSES = frozenset({"queued", "in_progress", "pending"})
# These are the conclusion values documented by the Actions API.  ``None`` is
# valid while a run/job is still in progress; unknown values are evidence
# corruption, not a reason to silently drop a failed object.
RUN_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "startup_failure", "stale",
})
JOB_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale",
})
STEP_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale",
})
NON_SUCCESS_RUN_CONCLUSIONS = frozenset(RUN_CONCLUSIONS - {"success"})
RUN_CLASSIFICATIONS = {
    "failure": "job_or_test_failure",
    "cancelled": "cancelled_before_cause_established",
    "timed_out": "actions_timeout",
    "action_required": "action_required",
    "startup_failure": "runner_startup_failure",
    "stale": "stale_run",
    "neutral": "neutral_outcome",
    "skipped": "skipped_outcome",
}
# B-250 is the deleted workflow whose backend identity still appears in fresh
# startup_failure runs. Name alone is unsafe: an active classification workflow
# contains "BuildFailed" in its name but has a different workflow path/ID.
B250_WORKFLOW_ID = 303501160
B250_WORKFLOW_PATH = "BuildFailed"
B250_RUN_CLASSIFICATION = "buildfailed_workflow_startup_failure"
FRACTIONAL_COMPONENTS = re.compile(r"[.,](\d+)")
HTTP_STATUS = re.compile(r"\bHTTP(?:/\d(?:\.\d)?)?\s+([1-5]\d\d)\b", re.IGNORECASE)
# Keep every external API invocation bounded.  The retry delays are constants so
# the tests can replace ``time.sleep`` and prove both the bound and the retry
# path without waiting for a wall-clock timeout.
GH_API_TIMEOUT_SECONDS = 30
GH_RETRY_DELAYS_SECONDS = (1, 2)
GH_MAX_ATTEMPTS = len(GH_RETRY_DELAYS_SECONDS) + 1


class EvidenceUnavailable(RuntimeError):
    """The API response cannot establish a complete evidence set."""


def classify_run_outcome(run: dict[str, Any], run_conclusion: str) -> str:
    """Classify startup failures only when deleted B-250 identity is exact."""
    classification = RUN_CLASSIFICATIONS[run_conclusion]
    if run_conclusion != "startup_failure":
        return classification

    workflow_id = run.get("workflow_id")
    workflow_path = run.get("path")
    if (
        isinstance(workflow_id, bool)
        or not isinstance(workflow_id, int)
        or workflow_id <= 0
        or not isinstance(workflow_path, str)
        or not workflow_path.strip()
    ):
        raise EvidenceUnavailable("startup_failure has malformed workflow identity")
    claims_b250_identity = workflow_id == B250_WORKFLOW_ID or workflow_path == B250_WORKFLOW_PATH
    if not claims_b250_identity:
        return classification
    if workflow_id != B250_WORKFLOW_ID or workflow_path != B250_WORKFLOW_PATH:
        raise EvidenceUnavailable("startup_failure has incomplete or conflicting B-250 workflow identity")
    return B250_RUN_CLASSIFICATION


def parse_time(value: str) -> dt.datetime:
    raw_value = value.strip()
    if any(len(component.group(1)) > 6 for component in FRACTIONAL_COMPONENTS.finditer(raw_value)):
        raise argparse.ArgumentTypeError("timestamps may contain at most six fractional digits")
    value = raw_value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 time: {value}") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("times must include a UTC offset")
    return parsed.astimezone(UTC)


def iso(value: dt.datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def run_gh(repo: str, endpoint: str) -> Any:
    """Read one API page through gh, keeping credentials out of argv/output."""
    for attempt in range(GH_MAX_ATTEMPTS):
        try:
            proc = subprocess.run(
                ["gh", "api", endpoint],
                check=False,
                capture_output=True,
                text=True,
                timeout=GH_API_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            if attempt < GH_MAX_ATTEMPTS - 1:
                time.sleep(GH_RETRY_DELAYS_SECONDS[attempt])
                continue
            # Do not render ``exc``: command arguments and partial output may
            # contain credentials or server-provided text.
            raise EvidenceUnavailable("gh api timed out after retries") from exc
        except OSError as exc:
            raise EvidenceUnavailable("gh api could not be started") from exc
        if proc.returncode == 0:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                raise EvidenceUnavailable("gh api returned non-JSON") from exc
        if attempt < GH_MAX_ATTEMPTS - 1:
            time.sleep(GH_RETRY_DELAYS_SECONDS[attempt])
    raise EvidenceUnavailable("gh api failed after retries")


def api_id(value: Any, kind: str) -> int:
    """Return a positive numeric API identifier or fail closed."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceUnavailable(f"{kind} has malformed id")
    return value


def conclusion(value: Any, kind: str, allowed: frozenset[str]) -> str | None:
    """Validate an Actions conclusion before any population filtering."""
    if value is None:
        return None
    if not isinstance(value, str) or value not in allowed:
        raise EvidenceUnavailable(f"{kind} has unknown conclusion")
    return value


def classify_log_text(text: str) -> str:
    """Classify retained text without returning or storing the text itself.

    This is intentionally conservative: an ENOSPC/linker signature wins only
    when no code-failure signature is present; otherwise the result remains
    ``indeterminate``.  Callers must still retain the original non-zero status.
    """
    if not isinstance(text, str):
        raise EvidenceUnavailable("log text is not a string")
    code_failure = re.search(r"error\s*\[E\d+\]|assertion failed|panicked at|tests? .*FAILED", text, re.I)
    storage = re.search(
        r"(no space left on device|\bENOSPC\b|disk\s+(?:is\s+)?full).{0,120}"
        r"(os error 28|write|create|cargo|rustc|filesystem|disk)|"
        r"(?:os error 28|write).{0,120}(no space left on device|\bENOSPC\b)",
        text,
        re.I,
    )
    linker = re.search(
        r"(?:collect2|\bld(?:\.exe)?\b|linker).{0,120}(bus error|signal\s+7)|"
        r"(?:bus error|signal\s+7).{0,120}(?:collect2|\bld(?:\.exe)?\b|linker)",
        text,
        re.I,
    )
    playwright = re.search(
        r"playwright.{0,160}(?:webserver|web server|webServer)|"
        r"(?:webserver|web server|webServer).{0,160}playwright|"
        r"config\.webServer|webServer command failed",
        text,
        re.I,
    )
    job_timeout = re.search(
        r"(?:job|workflow).{0,120}(?:timed out|timeout|maximum execution time)|"
        r"(?:timed out|timeout|maximum execution time).{0,120}(?:job|workflow)|"
        r"exceeded the maximum allowed execution time",
        text,
        re.I,
    )
    billing_startup = re.search(
        r"(?:billing|startup_failure|failed to start|runner.{0,80}(?:provision|startup|registration))",
        text,
        re.I,
    )
    runner = re.search(
        r"runner\s+(?:lost|disconnect|shutdown|unreachable)|"
        r"(?:job|workflow)\s+(?:was\s+)?cancel(?:led|ed)\b|"
        r"the operation was canceled|received\s+termination|\bSIGTERM\b",
        text,
        re.I,
    )
    if code_failure:
        return "test_failure"
    if storage or linker:
        return "enospc_or_linker_failure"
    if playwright:
        return "playwright_webserver"
    if job_timeout:
        return "job_timeout"
    if billing_startup:
        return "billing_or_startup"
    if runner:
        return "runner_cancellation"
    return "indeterminate"


def page_runs(repo: str, start: dt.datetime, end: dt.datetime, page: int) -> dict[str, Any]:
    query = urlencode({"per_page": PAGE_SIZE, "page": page, "created": f"{iso(start)}..{iso(end)}"})
    result = run_gh(repo, f"repos/{repo}/actions/runs?{query}")
    if not isinstance(result, dict) or not isinstance(result.get("workflow_runs"), list):
        raise EvidenceUnavailable("run page has no workflow_runs array")
    total = result.get("total_count")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise EvidenceUnavailable("run page has invalid total_count")
    if any(not isinstance(item, dict) for item in result["workflow_runs"]):
        raise EvidenceUnavailable("run page contains a malformed workflow run")
    for item in result["workflow_runs"]:
        conclusion(item.get("conclusion"), "run", RUN_CONCLUSIONS)
    return result


def collect_runs(repo: str, start: dt.datetime, end: dt.datetime) -> list[dict[str, Any]]:
    """Collect all runs, recursively avoiding GitHub's 1,000-result cap."""
    if start >= end:
        raise EvidenceUnavailable("start must be before end")
    first = page_runs(repo, start, end, 1)
    total = first["total_count"]
    # At the documented cap, the API cannot distinguish exactly 1,000 matches
    # from a larger result set truncated to 1,000.  Split that case too.
    if total >= MAX_SEARCH_RESULTS:
        midpoint = start + (end - start) / 2
        if midpoint <= start or midpoint >= end:
            raise EvidenceUnavailable("run search exceeds GitHub result cap at minimum interval")
        partitions = collect_runs(repo, start, midpoint) + collect_runs(repo, midpoint, end)
        selected: dict[int, dict[str, Any]] = {}
        for run in partitions:
            run_id = api_id(run.get("id"), "run")
            if run_id in selected:
                raise EvidenceUnavailable("run partitions contain a duplicate run id")
            selected[run_id] = run
        return list(selected.values())

    runs: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = first if page == 1 else page_runs(repo, start, end, page)
        if payload["total_count"] != total:
            raise EvidenceUnavailable("run pagination total_count changed during collection")
        batch = payload["workflow_runs"]
        expected = min(PAGE_SIZE, total - len(runs))
        if len(batch) != expected:
            raise EvidenceUnavailable("run pagination is incomplete or inconsistent")
        runs.extend(batch)
        if len(runs) == total:
            break
        page += 1
        if page > MAX_SEARCH_RESULTS // PAGE_SIZE:
            raise EvidenceUnavailable("run pagination exceeded the known GitHub result cap")

    # The API's created filter is date-granular in some deployments. Post-filter
    # exact UTC bounds; duplicated run IDs are inconsistent evidence and fail closed.
    selected: dict[int, dict[str, Any]] = {}
    for run in runs:
        try:
            created_value = run["created_at"]
            if not isinstance(created_value, str):
                raise EvidenceUnavailable("run page contains malformed identity/timestamp")
            created = parse_time(created_value)
            run_id = api_id(run["id"], "run")
        except (KeyError, ValueError, argparse.ArgumentTypeError) as exc:
            raise EvidenceUnavailable("run page contains malformed identity/timestamp") from exc
        if run_id in selected:
            raise EvidenceUnavailable("run page contains a duplicate run id")
        if start <= created < end:
            selected[run_id] = run
    return list(selected.values())


def collect_jobs(repo: str, run: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        run_id = api_id(run["id"], "run")
    except KeyError as exc:
        raise EvidenceUnavailable("run has malformed id") from exc
    jobs: list[dict[str, Any]] = []
    job_ids: set[int] = set()
    expected_total: int | None = None
    # A full page is not evidence that the listing ended.  In particular,
    # exactly 1,000 jobs requires a request for page 11 to distinguish a full
    # result from an API-side truncation.
    for page in range(1, 12):
        query = urlencode({"per_page": PAGE_SIZE, "page": page})
        payload = run_gh(repo, f"repos/{repo}/actions/runs/{run_id}/jobs?{query}")
        batch = payload.get("jobs") if isinstance(payload, dict) else None
        if not isinstance(batch, list):
            raise EvidenceUnavailable(f"run {run_id} jobs page has no jobs array")
        total = payload.get("total_count") if isinstance(payload, dict) else None
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise EvidenceUnavailable(f"run {run_id} jobs page has invalid total_count")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise EvidenceUnavailable(f"run {run_id} jobs total_count changed during collection")
        if total > MAX_SEARCH_RESULTS:
            raise EvidenceUnavailable(f"run {run_id} jobs exceed the API result cap")
        if any(not isinstance(item, dict) for item in batch):
            raise EvidenceUnavailable(f"run {run_id} jobs page contains a malformed job")
        for job in batch:
            job_id = api_id(job.get("id"), "job")
            conclusion(job.get("conclusion"), "job", JOB_CONCLUSIONS)
            if job_id in job_ids:
                raise EvidenceUnavailable(f"run {run_id} jobs page contains a duplicate job id")
            job_ids.add(job_id)
        expected = min(PAGE_SIZE, total - len(jobs))
        if len(batch) != expected:
            raise EvidenceUnavailable(f"run {run_id} jobs pagination is incomplete or inconsistent")
        jobs.extend(batch)
        if len(jobs) == total:
            # A full final page needs one explicit empty-page probe.  Otherwise
            # an API-side cap at exactly 100/…/1,000 is indistinguishable from
            # a complete listing.
            if len(batch) < PAGE_SIZE:
                return jobs
    raise EvidenceUnavailable(f"run {run_id} jobs pagination exceeded 1,100 jobs")


def whole_seconds(delta: dt.timedelta, evidence: str) -> int:
    """Reject negative or fractional evidence instead of silently truncating it."""
    if delta < dt.timedelta(0):
        raise EvidenceUnavailable(f"job has negative {evidence} duration")
    if delta.microseconds:
        raise EvidenceUnavailable(f"job has fractional {evidence} duration")
    return delta.days * 86_400 + delta.seconds


def duration(job: dict[str, Any]) -> int:
    try:
        started_value = job["started_at"]
        completed_value = job["completed_at"]
        if not isinstance(started_value, str) or not isinstance(completed_value, str):
            raise EvidenceUnavailable("job has malformed runtime timestamps")
        started = parse_time(started_value)
        completed = parse_time(completed_value)
    except (KeyError, ValueError, argparse.ArgumentTypeError) as exc:
        raise EvidenceUnavailable("job has malformed runtime timestamps") from exc
    return whole_seconds(completed - started, "runtime")


def queue_duration(job: dict[str, Any]) -> int:
    """Return runner queue wait as job.created_at -> job.started_at."""
    try:
        created_value = job["created_at"]
        started_value = job["started_at"]
        if not isinstance(created_value, str) or not isinstance(started_value, str):
            raise EvidenceUnavailable("job has malformed queue timestamps")
        created = parse_time(created_value)
        started = parse_time(started_value)
    except (KeyError, ValueError, argparse.ArgumentTypeError) as exc:
        raise EvidenceUnavailable("job has malformed queue timestamps") from exc
    return whole_seconds(started - created, "queue")


def optional_timestamp(value: Any, label: str) -> str | None:
    """Validate an optional Actions timestamp without normalizing evidence."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceUnavailable(f"{label} is not a timestamp")
    try:
        parse_time(value)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        raise EvidenceUnavailable(f"{label} is not a timestamp") from exc
    return value


def summarize_queue(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = sorted(
        item["queue_duration_seconds"]
        for item in records
        if item.get("queue_duration_seconds") is not None
    )
    if not values:
        return {"count": 0, "min_seconds": None, "median_seconds": None, "max_seconds": None}
    middle = len(values) // 2
    median = values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2
    return {
        "count": len(values),
        "min_seconds": values[0],
        "median_seconds": median,
        "max_seconds": values[-1],
    }


def classify_job(job: dict[str, Any], run: dict[str, Any], low: int, high: int) -> dict[str, Any]:
    job_conclusion = conclusion(job.get("conclusion"), "job", JOB_CONCLUSIONS)
    steps = job.get("steps")
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise EvidenceUnavailable("job has malformed step evidence")
    if any(
        not isinstance(step.get("name"), str)
        # Membership in a set raises TypeError for list/dict statuses.  Check
        # the JSON scalar type first so every malformed API value becomes the
        # same sanitized, fail-closed evidence result.
        or not isinstance(step.get("status"), str)
        or step["status"] not in STEP_STATUSES
        for step in steps
    ):
        raise EvidenceUnavailable("job has malformed step evidence")
    workflow = run.get("name")
    lane = job.get("name")
    runner_name = job.get("runner_name")
    if not isinstance(workflow, str) or not isinstance(lane, str):
        raise EvidenceUnavailable("job has malformed workflow or lane evidence")
    if runner_name is not None and not isinstance(runner_name, str):
        raise EvidenceUnavailable("job has malformed runner evidence")
    in_progress = [step["name"] for step in steps if step["status"] == "in_progress"]
    not_completed = [step["name"] for step in steps if step["status"] in ACTIVE_STEP_STATUSES]
    step_records = []
    for step in steps:
        number = step.get("number")
        if number is not None and (isinstance(number, bool) or not isinstance(number, int) or number <= 0):
            raise EvidenceUnavailable("job has malformed step identity")
        step_conclusion = step.get("conclusion")
        if step_conclusion is not None and (
            not isinstance(step_conclusion, str) or step_conclusion not in STEP_CONCLUSIONS
        ):
            raise EvidenceUnavailable("job has malformed step conclusion")
        step_records.append({
            "step_id": number,
            "name": step["name"],
            "status": step["status"],
            "conclusion": step_conclusion,
            "started_at": optional_timestamp(step.get("started_at"), "step.started_at"),
            "completed_at": optional_timestamp(step.get("completed_at"), "step.completed_at"),
        })
    checkout = [
        s for s in steps
        if "checkout" in s["name"].lower()
        # Post-checkout cleanup is pending after an external kill and does
        # not mean that source checkout itself was incomplete.
        and not s["name"].lower().startswith("post ")
    ]
    checkout_incomplete = any(s.get("status") != "completed" for s in checkout)
    seconds = duration(job)
    return {
        "run_id": api_id(run.get("id"), "run"),
        "job_id": api_id(job.get("id"), "job"),
        "workflow": workflow,
        "lane": lane,
        "conclusion": job_conclusion,
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "duration_seconds": seconds,
        "queue_duration_seconds": queue_duration(job),
        "runner_name": runner_name,
        "step_in_progress": in_progress,
        "step_not_completed": not_completed,
        # GitHub can retain the job identity/timing object after its step
        # metadata has disappeared.  Preserve that distinction explicitly so
        # a later empty ``steps`` array is not mistaken for evidence that all
        # steps completed cleanly.
        "step_evidence_available": bool(steps),
        "steps": step_records,
        "checkout_incomplete": checkout_incomplete,
        "checkout_observed": bool(checkout),
        "in_window": seconds is not None and low <= seconds <= high,
        # Metadata is a signal only.  A 600-second kill with an unfinished
        # step points away from a test assertion, but cannot name the external
        # cause without retained logs/runner evidence.
        "metadata_signal": (
            "runner_death_candidate"
            if low <= seconds <= high and not_completed
            else "job_failure_candidate"
        ),
    }


def collect_evidence(repo: str, start: dt.datetime, end: dt.datetime, low: int, high: int) -> dict[str, Any]:
    runs = collect_runs(repo, start, end)
    # Validate every run again here because tests/callers may provide a
    # pre-collected list rather than going through page_runs().
    validated_runs: list[dict[str, Any]] = []
    run_outcomes: list[dict[str, Any]] = []
    run_conclusion_counts: Counter[str] = Counter()
    for run in runs:
        run_id = api_id(run.get("id"), "run")
        run_conclusion = conclusion(run.get("conclusion"), "run", RUN_CONCLUSIONS)
        validated_runs.append(run)
        if run_conclusion is not None:
            run_conclusion_counts[run_conclusion] += 1
        if run_conclusion in NON_SUCCESS_RUN_CONCLUSIONS:
            classification = classify_run_outcome(run, run_conclusion)
            outcome = {
                "run_id": run_id,
                "conclusion": run_conclusion,
                "classification": classification,
                "workflow": run.get("name") if isinstance(run.get("name"), str) else None,
                "event": run.get("event") if isinstance(run.get("event"), str) else None,
                "created_at": run.get("created_at"),
                "updated_at": run.get("updated_at"),
            }
            if classification == B250_RUN_CLASSIFICATION:
                outcome.update({"workflow_id": B250_WORKFLOW_ID, "workflow_path": B250_WORKFLOW_PATH})
            run_outcomes.append(outcome)
    failed_runs = [r for r in validated_runs if r.get("conclusion") == "failure"]
    records: list[dict[str, Any]] = []
    all_job_ids: set[int] = set()
    for run in failed_runs:
        jobs = collect_jobs(repo, run)
        for job in jobs:
            job_id = api_id(job.get("id"), "job")
            if job_id in all_job_ids:
                # GitHub job IDs are globally unique.  Reuse across runs means
                # the evidence identity contract is broken; never overwrite a
                # record and accidentally undercount the death rate.
                raise EvidenceUnavailable("job id is repeated across selected runs")
            all_job_ids.add(job_id)
            if job.get("conclusion") == "failure":
                records.append(classify_job(job, run, low, high))
    return {
        "schema": SCHEMA,
        "collection": {
            "source": "GitHub Actions REST API via gh api",
            "read_only": True,
            "logs_persisted": False,
            "zero_window_jobs_is_not_closure": True,
        },
        "repo": repo,
        "window": {"start": iso(start), "end_exclusive": iso(end)},
        "duration_window_seconds": {"low": low, "high": high},
        "run_count": len(runs),
        "run_ids": sorted(api_id(r.get("id"), "run") for r in validated_runs),
        "run_conclusion_counts": dict(sorted(run_conclusion_counts.items())),
        "run_classification_counts": dict(sorted(Counter(item["classification"] for item in run_outcomes).items())),
        "non_success_run_count": len(run_outcomes),
        "run_outcomes": run_outcomes,
        "failed_run_count": len(failed_runs),
        "failed_job_count": len(records),
        "window_jobs": [r for r in records if r["in_window"]],
        "failed_jobs": records,
        "lane_distribution": dict(Counter(r["lane"] for r in records if r["in_window"])),
        "metadata_signal_distribution": dict(
            Counter(r["metadata_signal"] for r in records if r["in_window"])
        ),
        "queue_duration": {
            "measured_from": "job.created_at -> job.started_at",
            "not_run_started_at": True,
            "summary_for_window_jobs": summarize_queue(r for r in records if r["in_window"]),
        },
        "limitations": [
            "job duration is completed_at - started_at, not declared timeout-minutes",
            "run started_at is not runner queue wait; queue wait requires job created_at - started_at",
            "absence in this window is not proof of cure",
        ],
    }


def _http_status(value: Any) -> int | None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return None
    match = HTTP_STATUS.search(value)
    return int(match.group(1)) if match else None


def fetch_job_log(repo: str, job_id: int) -> tuple[bool, str | None]:
    """Return log availability after a bounded, sanitized retrieval attempt."""
    available, error, _signature, _digest, _http_code = fetch_job_log_details(repo, job_id)
    return available, error


def fetch_job_log_details(repo: str, job_id: int) -> tuple[bool, str | None, str, str | None, int | None]:
    """Fetch a log only in memory and retain a digest/classification, never its body."""
    for attempt in range(GH_MAX_ATTEMPTS):
        try:
            proc = subprocess.run(
                ["gh", "api", f"repos/{repo}/actions/jobs/{job_id}/logs"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                timeout=GH_API_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            if attempt < GH_MAX_ATTEMPTS - 1:
                time.sleep(GH_RETRY_DELAYS_SECONDS[attempt])
                continue
            return False, "log retrieval timed out", "indeterminate", None, None
        except OSError as exc:
            raise EvidenceUnavailable("gh api could not be started while fetching logs") from exc
        if proc.returncode == 0:
            payload = proc.stdout
            if not isinstance(payload, (bytes, bytearray)):
                raise EvidenceUnavailable("log response body is malformed")
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            signature = classify_log_text(bytes(payload).decode("utf-8", errors="replace"))
            return True, None, signature, digest, 200
        if attempt < GH_MAX_ATTEMPTS - 1:
            time.sleep(GH_RETRY_DELAYS_SECONDS[attempt])
    # gh writes the HTTP response status to stderr for API errors.  Parse only
    # the status code and never retain/render the provider's error text.
    return False, "log retrieval failed", "indeterminate", None, _http_status(getattr(proc, "stderr", None))


def fetch_logs(repo: str, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fetch logs without persisting them; 404/transport errors remain indeterminate."""
    result = []
    for record in records:
        job_id = record["job_id"]
        available, error, signature, digest, http_status = fetch_job_log_details(repo, job_id)
        result.append({
            "job_id": job_id,
            "available": available,
            "status": "available" if available else "indeterminate",
            "causal": False if available else "indeterminate",
            "http_status": http_status,
            "log_signature": signature,
            "log_sha256": digest,
            "error": error,
        })
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    parser.add_argument("--start", required=True, type=parse_time)
    parser.add_argument("--end", required=True, type=parse_time)
    parser.add_argument("--low", type=int, default=594)
    parser.add_argument("--high", type=int, default=615)
    parser.add_argument("--known-run", action="append", type=int, default=[])
    parser.add_argument("--fetch-logs", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        from server_repository import resolve_server_repository
    except ModuleNotFoundError:  # imported as scripts.b152_actions_diagnostic
        from scripts.server_repository import resolve_server_repository
    try:
        repo = resolve_server_repository(args.repo)
    except (OSError, ValueError) as exc:
        parser.error(f"cannot safely resolve server repository: {exc}")
    if args.low < 0 or args.high < args.low:
        parser.error("duration bounds are invalid")
    try:
        report = collect_evidence(repo, args.start, args.end, args.low, args.high)
        # Controls may be successful/cancelled, so compare against all selected
        # run IDs, not only failed jobs.  This also avoids a second API walk.
        missing = [run_id for run_id in args.known_run if run_id not in set(report.get("run_ids", []))]
        if missing:
            raise EvidenceUnavailable(f"known run(s) absent from complete window: {','.join(map(str, missing))}")
        if args.fetch_logs:
            report["logs"] = fetch_logs(repo, report["window_jobs"])
            unavailable = [item for item in report["logs"] if item["status"] == "indeterminate"]
            report["log_signature_distribution"] = dict(
                Counter(item.get("log_signature", "indeterminate") for item in report["logs"])
            )
            report["causal_classification"] = {
                "status": "indeterminate" if unavailable else "not_established",
                "causal": "indeterminate" if unavailable else False,
                "reason": (
                    "one or more job log blobs were unavailable; no causal conclusion is permitted"
                    if unavailable else "logs available, but availability alone does not establish a common cause"
                ),
                "unavailable_job_ids": [item["job_id"] for item in unavailable],
                "known_log_categories": sorted(report["log_signature_distribution"]),
            }
        else:
            report["causal_classification"] = {
                "status": "indeterminate",
                "causal": "indeterminate",
                "reason": "logs were not requested; no causal conclusion is permitted",
                "unavailable_job_ids": [],
                "known_log_categories": [],
            }
    except EvidenceUnavailable as exc:
        print(f"INDETERMINATE: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    try:
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except OSError:
        print("INDETERMINATE: report output could not be written", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
