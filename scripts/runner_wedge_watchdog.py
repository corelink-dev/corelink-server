#!/usr/bin/env python3
"""Recover the self-hosted Mac fleet when it wedges `busy=true` with no work.

`scripts/check_runner_fleet.py` already NAMES this failure ("the fleet wedges
`busy=true` with no work"), and the `runner-fleet health` workflow already
detects it. Neither can fix it: they run on the ephemeral Cloudflare fabric,
with no repository-admin token and no access to the Mac's `launchctl`. So the
condition was detected and then simply persisted.

Measured cost of that gap on 2026-08-25: every job on
`[self-hosted, mac, corelink-builder]` — `dco`, `changelog-validate`, the label
and size-bucket jobs, `Docs Reality Gate` — sat `queued` for **12 hours**, which
blocks every merge, because those are the checks the merge gate requires. The
Cloudflare fabric was healthy throughout (jobs on the `corelink` label ran
normally the whole time), which is exactly why the outage read as "CI is slow"
rather than as a wedged host. `launchctl kickstart -k` on the five builder
services recovered it in under a minute.

This script is that remedy, automated, and it runs ON the Mac (launchd), which
is the only place `launchctl` exists.

# The safety property

Restarting a listener that is RUNNING A JOB kills that job. So the decision is
deliberately conservative and requires BOTH halves:

  1. GitHub reports work queued for our labels, older than `--min-age-s`; and
  2. this host has NO `Runner.Worker` process alive — the process the listener
     spawns for the duration of a job, and therefore local proof that no job is
     executing here.

(2) is the interlock. It is read from the host's own process table, not from
GitHub's `busy` flag, because `busy` is precisely the field that lies when the
fleet is wedged — and because reading `busy` needs a repository-admin token
this host does not have (BACKLOG B-012). A wedged listener holds no
`Runner.Worker`, so the kickstart is safe; a busy one does, so we leave it
alone and simply report.

# What it does NOT do

It never `pkill`s. Killing by pattern on this host has taken down the CI runner
itself before, and the runner processes are the thing being repaired. Recovery
is `launchctl kickstart -k <service>`, which asks launchd to restart the job it
already manages, by name.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass

try:
    from server_repository import resolve_server_repository
except ModuleNotFoundError:  # imported as scripts.runner_wedge_watchdog
    from scripts.server_repository import resolve_server_repository


# The launchd services that back `[self-hosted, mac, corelink-builder]`. Named
# explicitly rather than discovered: a wildcard over `actions.runner.*` would
# also match the runners of every OTHER project sharing this Mac (hugr-wallet,
# githugr, hugit, corelink-workspaces …), and restarting someone else's runner
# mid-job is exactly the cross-project damage this file exists to avoid.
BUILDER_SERVICES = (
    "actions.runner.HuGR-Labs-corelink-server.corelink-builder-1",
    "actions.runner.humangr-labs-corelink-server.corelink-builder-2",
    "actions.runner.humangr-labs-corelink-server.corelink-builder-3",
    "actions.runner.humangr-labs-corelink-server.corelink-builder-4",
    "actions.runner.humangr-labs-corelink-server.corelink-builder-5",
)

# The label set those services advertise. A queued job is only our problem if it
# asked for these.
BUILDER_LABELS = frozenset({"self-hosted", "mac", "corelink-builder"})


@dataclass(frozen=True)
class Verdict:
    """What the watchdog decided, and why — the `why` is what gets logged."""

    act: bool
    reason: str


def decide(
    *,
    queued_job_ages_s: list[float],
    local_worker_count: int,
    min_age_s: float,
) -> Verdict:
    """Decide whether to kickstart, from the two independent observations.

    Pure so the decision is testable without a GitHub API or a process table —
    every branch below is covered by `tests/test_runner_wedge_watchdog.py`.
    """
    if local_worker_count > 0:
        # The interlock. Something is genuinely executing here; a restart would
        # kill it. This is the branch that must never be "optimised away".
        return Verdict(False, f"a job is running here ({local_worker_count} Runner.Worker alive)")
    stale = [a for a in queued_job_ages_s if a >= min_age_s]
    if not stale:
        if queued_job_ages_s:
            return Verdict(False, f"{len(queued_job_ages_s)} queued but none older than {min_age_s:.0f}s")
        return Verdict(False, "nothing queued for our labels")
    return Verdict(
        True,
        f"{len(stale)} job(s) queued ≥{min_age_s:.0f}s (oldest {max(stale):.0f}s) and no job running here",
    )


def _gh_json(path: str) -> dict:
    out = subprocess.run(
        ["gh", "api", path],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


def queued_builder_job_ages(repo: str, now_s: float) -> list[float]:
    """Ages, in seconds, of queued jobs that asked for the builder labels."""
    runs = _gh_json(f"/repos/{repo}/actions/runs?status=queued&per_page=30")
    ages: list[float] = []
    for run in runs.get("workflow_runs") or []:
        jobs = _gh_json(f"/repos/{repo}/actions/runs/{run['id']}/jobs")
        for job in jobs.get("jobs") or []:
            if job.get("status") != "queued":
                continue
            if not BUILDER_LABELS.issubset(set(job.get("labels") or [])):
                continue
            started = job.get("started_at") or job.get("created_at") or run.get("created_at")
            if not started:
                continue
            ages.append(now_s - _parse_iso8601_s(started))
    return ages


def _parse_iso8601_s(value: str) -> float:
    # GitHub returns `2026-08-25T05:40:05Z`. `fromisoformat` handles the `Z`
    # only from 3.11; normalise so this also runs on an older interpreter.
    from datetime import datetime, timezone

    text = value.replace("Z", "+00:00")
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


def local_runner_worker_count() -> int:
    """How many job-executing `Runner.Worker` processes are alive on this host.

    `Runner.Listener` is the idle poller and is always present; `Runner.Worker`
    exists only while a job runs. Counting the wrong one would make the
    interlock always-true and the watchdog a no-op.
    """
    out = subprocess.run(["ps", "ax", "-o", "command"], capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines() if "Runner.Worker" in line)


def kickstart(service: str, *, dry_run: bool) -> str:
    target = f"gui/{_uid()}/{service}"
    if dry_run:
        return f"DRY-RUN would kickstart {target}"
    proc = subprocess.run(
        ["launchctl", "kickstart", "-k", target],
        capture_output=True,
        text=True,
    )
    status = "ok" if proc.returncode == 0 else f"rc={proc.returncode} {proc.stderr.strip()}"
    return f"kickstart {target}: {status}"


def _uid() -> int:
    import os

    return os.getuid()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    ap.add_argument(
        "--min-age-s",
        type=float,
        default=600.0,
        help="how long a job must sit queued before the fleet counts as wedged (default 600)",
    )
    ap.add_argument("--dry-run", action="store_true", help="decide and report, change nothing")
    args = ap.parse_args(argv)

    try:
        repo = resolve_server_repository(args.repo)
    except (OSError, ValueError) as exc:
        print(f"watchdog: cannot resolve server repository ({exc}); doing nothing", file=sys.stderr)
        return 0

    now = time.time()
    try:
        ages = queued_builder_job_ages(repo, now)
    except subprocess.CalledProcessError as exc:
        # A GitHub read failure is NOT a wedge. Report and exit 0 — a watchdog
        # that restarts runners because it could not see is worse than one that
        # sleeps through an outage.
        print(f"watchdog: cannot read GitHub ({exc}); doing nothing", file=sys.stderr)
        return 0

    verdict = decide(
        queued_job_ages_s=ages,
        local_worker_count=local_runner_worker_count(),
        min_age_s=args.min_age_s,
    )
    print(f"watchdog: {'ACT' if verdict.act else 'hold'} — {verdict.reason}")
    if not verdict.act:
        return 0
    for service in BUILDER_SERVICES:
        print(kickstart(service, dry_run=args.dry_run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
