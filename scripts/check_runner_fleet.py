#!/usr/bin/env python3
"""Fail when the self-hosted Mac fleet is smaller, or more stuck, than it claims.

Three failure modes have each cost this project a day, and none of them was
visible while it was happening:

1. **A slot silently disappears.** `corelink-builder-1` was registered in
   launchd and absent from GitHub for long enough that GitHub *deleted its
   registration* (it auto-removes a runner offline for ~14 days). Restarting
   the service could never fix that — the local config was orphaned and the
   listener exited with "The runner registration has been deleted from the
   server". Nobody noticed the fleet had been running at 4/5 capacity.
2. **The fleet wedges `busy=true` with no work.** On 2026-08-24 all four live
   runners reported busy while zero jobs were in progress, with seven runs
   queued behind them — one for six hours.
3. **A queue backs up behind either of the above** and simply looks like slow
   CI.

This checks all three against GitHub's own view, so it cannot be fooled by
local bookkeeping — the same lesson as B-002's reaper: start from platform
truth, not from our own records.

Two levels, because they need different credentials:

* **queue health** (always runs) needs only `actions: read`, which the workflow
  `GITHUB_TOKEN` has. It catches a wedged or under-capacity fleet by its
  symptom: runs sitting queued while nothing is in progress.
* **slot census** (runners registered / online / busy) needs repository ADMIN.
  `GITHUB_TOKEN` cannot do it — `administration` is not even a grantable
  workflow permission — so in CI it requires a real token in `GH_ADMIN_TOKEN`.
  That credential is BACKLOG B-012, still unprovisioned.

The census is not silently skipped when the credential is absent: this exits
non-zero unless `FLEET_SLOT_CENSUS=skip` is set explicitly. A check that quietly
drops half of itself for a missing credential reports health it never observed —
the exact defect B-020 was opened for.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:
    from server_repository import resolve_server_repository
except ModuleNotFoundError:  # imported as scripts.check_runner_fleet
    from scripts.server_repository import resolve_server_repository

# The Mac fleet this repo is supposed to have. Five launchd slots exist on the
# host; a count below this means a slot died or was deregistered, which is the
# state that went unnoticed for days.
EXPECTED_MAC_SLOTS = 5
MAC_PREFIX = "corelink-builder"

# How long a run may sit queued before the fleet is considered stuck. Ten
# minutes is generous for a fleet that normally picks a job up in seconds.
QUEUE_STUCK_MINUTES = 10


def gh_json(path: str, paginate: bool = True) -> dict:
    cmd = ["gh", "api"] + (["--paginate"] if paginate else []) + [path]
    out = subprocess.run(
        cmd,
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        print(f"FAIL: `gh api {path}` failed — cannot see the fleet, so cannot "
              f"claim it is healthy.\n{out.stderr.strip()[:400]}", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(out.stdout)


def age_minutes(iso: str) -> float:
    started = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - started).total_seconds() / 60.0


def census_available(repo: str) -> bool:
    """True when this token can actually read the runner list."""
    out = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runners?per_page=1"],
        capture_output=True, text=True, check=False,
    )
    return out.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    parser.add_argument("--expected-slots", type=int, default=EXPECTED_MAC_SLOTS)
    parser.add_argument("--queue-stuck-minutes", type=float,
                        default=QUEUE_STUCK_MINUTES)
    args = parser.parse_args()

    try:
        repo = resolve_server_repository(args.repo)
    except (OSError, ValueError) as exc:
        print(f"FAIL: cannot safely resolve server repository: {exc}", file=sys.stderr)
        return 2

    do_census = census_available(repo)
    if not do_census:
        if os.environ.get("FLEET_SLOT_CENSUS") != "skip":
            print("FAIL: this token cannot list self-hosted runners, so the slot "
                  "census cannot run. That credential is BACKLOG B-012. Set "
                  "FLEET_SLOT_CENSUS=skip to run queue health alone — and then "
                  "know that a missing slot will NOT be detected.",
                  file=sys.stderr)
            return 2
        print("census: SKIPPED — no admin token (B-012). A slot that disappears "
              "will not be caught by this run.")

    macs: list[dict] = []
    online: list[dict] = []
    busy: list[dict] = []
    if do_census:
        runners = gh_json(f"repos/{repo}/actions/runners").get("runners", [])
        macs = [r for r in runners if r["name"].startswith(MAC_PREFIX)]
        online = [r for r in macs if r["status"] == "online"]
        busy = [r for r in online if r["busy"]]

    # NOT paginated: --paginate here walks the repo's entire run history, which
    # takes minutes and tells us nothing — only the newest page can contain a
    # run that is still queued or in progress.
    runs = gh_json(f"repos/{repo}/actions/runs?per_page=50", paginate=False).get(
        "workflow_runs", [])
    in_progress = [r for r in runs if r["status"] == "in_progress"]
    queued = [r for r in runs if r["status"] == "queued"]

    census_line = (f"mac slots: {len(online)}/{args.expected_slots} online "
                   f"({len(busy)} busy) | " if do_census else "")
    print(f"{census_line}runs: {len(in_progress)} in progress, "
          f"{len(queued)} queued")

    failures: list[str] = []

    if do_census and len(online) < args.expected_slots:
        missing = args.expected_slots - len(online)
        names = sorted(r["name"] for r in macs)
        failures.append(
            f"{missing} of {args.expected_slots} Mac slots are not online "
            f"(registered: {names or 'none'}). If a slot is missing entirely "
            f"rather than offline, GitHub has deleted its registration and the "
            f"launchd service cannot recover by restarting — it must be "
            f"re-registered with `config.sh remove --local` then `config.sh "
            f"--replace`.")

    # The wedge: runners claim to be working while nothing is running. One
    # in-progress run is enough to explain any number of busy runners (a matrix
    # occupies several), so this only fires on the unambiguous case.
    if do_census and busy and not in_progress:
        failures.append(
            f"{len(busy)} runner(s) report busy=true while zero runs are in "
            f"progress: {sorted(r['name'] for r in busy)}. That is the wedge "
            f"signature. Restart the affected slot by launchd label "
            f"(`launchctl kickstart -k gui/$(id -u)/<label>`) — never pkill by "
            f"pattern, which kills the CI runner itself.")

    stuck = [r for r in queued if age_minutes(r["created_at"]) > args.queue_stuck_minutes]
    if stuck:
        oldest = max(age_minutes(r["created_at"]) for r in stuck)
        failures.append(
            f"{len(stuck)} run(s) queued longer than "
            f"{args.queue_stuck_minutes:.0f} min (oldest {oldest:.0f} min). "
            f"Either the fleet is wedged or capacity is short.")

    if failures:
        print()
        for f in failures:
            print(f"FLEET: {f}", file=sys.stderr)
        return 1

    print("ok: every expected slot is online and nothing is stuck.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
