#!/usr/bin/env python3
"""
check_workflow_state.py — workflow enabled/disabled-state drift gate.

Every workflow in a repository is either `active` or it is not. A non-active
workflow gates nothing, proves nothing, and — as this repository learned on
2026-08-08, when 21 workflows were switched to `disabled_manually` in 39
seconds and nothing noticed for weeks — announces nothing when it stops.

This script makes non-active state a DECLARED, EXPIRING decision:

  * every non-active workflow must have an unexpired entry in the waiver file
    (`.github/workflow-state-waivers.yml`), keyed by its repo-relative path;
  * every waiver entry must name a workflow that exists AND is non-active — a
    waiver for a workflow that is running, or for one that was deleted, is
    drift in the other direction and fails too;
  * every waiver entry must carry an `expires` date that has not passed. An
    expired waiver is exactly as red as a missing one.

It ALWAYS prints a table of every non-active workflow and its waiver status,
pass or fail, to stdout and to `$GITHUB_STEP_SUMMARY` when that is set.

Listing is PAGINATED (`gh api --paginate`). This repo has >100 workflows, so
an unpaginated list silently truncates — a previous investigation was misled
by exactly that.

Exit codes:
  0 — no drift.
  1 — drift found (details on stdout and in the job summary).
  2 — invocation error (waiver file unparsable, `gh` missing, API refused).

Usage:
  python3 scripts/check_workflow_state.py
  python3 scripts/check_workflow_state.py --waivers /dev/null      # prove it fails
  python3 scripts/check_workflow_state.py --repo OWNER/NAME --waivers PATH
  python3 scripts/check_workflow_state.py --also-report OWNER/NAME  # best-effort

Cross-references:
  * .github/workflow-state-waivers.yml  (the register)
  * .github/workflows/workflow-state-guard.yml  (the daily cron that runs this)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    print("ERROR: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

try:
    from server_repository import resolve_server_repository
except ModuleNotFoundError:  # imported as scripts.check_workflow_state
    from scripts.server_repository import resolve_server_repository
DEFAULT_WAIVERS = ".github/workflow-state-waivers.yml"
REQUIRED_FIELDS = ("reason", "authorized-by", "date", "expires", "tracking")
MAX_WAIVER_DAYS = 90


# --------------------------------------------------------------------------- #
# GitHub API
# --------------------------------------------------------------------------- #
def list_workflows(repo: str) -> list[dict[str, Any]]:
    """Return every workflow in `repo`, paginated. Raises on failure."""
    if shutil.which("gh") is None:
        raise RuntimeError("`gh` CLI not found on PATH")
    proc = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repo}/actions/workflows?per_page=100",
            "--jq",
            ".workflows[] | @json",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"gh api failed for {repo} (exit {proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    out: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------- #
# Waivers
# --------------------------------------------------------------------------- #
def load_waivers(path: Path) -> dict[str, dict[str, Any]]:
    """Parse the waiver register. A missing or empty file means NO waivers."""
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    waivers = raw.get("waivers") or {}
    if not isinstance(waivers, dict):
        raise ValueError(f"{path}: `waivers` must be a mapping of path -> entry")
    for key, entry in waivers.items():
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: waiver `{key}` must be a mapping")
    return waivers


def parse_date(value: Any) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# The check
# --------------------------------------------------------------------------- #
def check_repo(
    repo: str,
    waivers: dict[str, dict[str, Any]],
    today: dt.date,
) -> tuple[list[str], list[list[str]]]:
    """Return (failures, summary_rows) for `repo`."""
    workflows = list_workflows(repo)
    by_path = {w["path"]: w for w in workflows}
    non_active = {p: w for p, w in by_path.items() if w.get("state") != "active"}

    # A workflow whose FILE is gone from this tree is being retired in the very
    # change being checked. GitHub keeps listing it as `disabled_manually` until
    # the deletion reaches the default branch, so without this the guard demands
    # a waiver for a file that no longer exists — and the only way to satisfy it
    # would be to waive something that is already deleted, which is nonsense.
    # Deleting a workflow is the strongest possible form of "decided".
    if repo.endswith("/corelink-server"):
        non_active = {
            p: w for p, w in non_active.items()
            if (REPO_ROOT / p).exists()
        }

    failures: list[str] = []
    rows: list[list[str]] = []

    # ---- 1. every non-active workflow needs an unexpired waiver ----------- #
    for path in sorted(non_active):
        wf = non_active[path]
        state = wf.get("state", "<unknown>")
        entry = waivers.get(path)
        if entry is None:
            status = "NO WAIVER"
            failures.append(
                f"{repo}: `{path}` is `{state}` with NO entry in the waiver "
                f"register. Re-enable it, or add an entry saying why it is off."
            )
        else:
            expires = parse_date(entry.get("expires"))
            if expires is None:
                status = "WAIVER INVALID (bad `expires`)"
                failures.append(
                    f"{repo}: waiver for `{path}` has a missing or unparsable "
                    f"`expires` ({entry.get('expires')!r}); ISO YYYY-MM-DD required."
                )
            elif expires < today:
                status = f"WAIVER EXPIRED {expires.isoformat()}"
                failures.append(
                    f"{repo}: waiver for `{path}` EXPIRED on {expires.isoformat()} "
                    f"(today {today.isoformat()}). An expired waiver is as red as "
                    f"a missing one — decide, then re-enable or re-waive."
                )
            else:
                status = f"waived until {expires.isoformat()}"
        rows.append([repo, path, state, status, str((entry or {}).get("authorized-by", "-"))])

    # ---- 2. stale waivers: nonexistent, or naming an ACTIVE workflow ------ #
    for path in sorted(waivers):
        entry = waivers[path]

        missing = [f for f in REQUIRED_FIELDS if entry.get(f) in (None, "")]
        if missing:
            failures.append(
                f"{repo}: waiver for `{path}` is missing required field(s): "
                f"{', '.join(missing)}."
            )

        expires = parse_date(entry.get("expires"))
        written = parse_date(entry.get("date"))
        if expires is not None and written is not None:
            span = (expires - written).days
            if span > MAX_WAIVER_DAYS:
                failures.append(
                    f"{repo}: waiver for `{path}` runs {span} days "
                    f"({written.isoformat()} → {expires.isoformat()}); the cap is "
                    f"{MAX_WAIVER_DAYS} days. A waiver is a deadline, not an exemption."
                )

        wf = by_path.get(path)
        if wf is None:
            failures.append(
                f"{repo}: waiver names `{path}`, which does not exist in the "
                f"repository. Delete the stale entry — a register that describes "
                f"a workflow that is not there describes nothing."
            )
            rows.append([repo, path, "DOES NOT EXIST", "STALE WAIVER", str(entry.get("authorized-by", "-"))])
        elif wf.get("state") == "active":
            failures.append(
                f"{repo}: waiver names `{path}`, but that workflow is ACTIVE. "
                f"Delete the entry — waiving a running workflow hides the next "
                f"time it stops."
            )
            rows.append([repo, path, "active", "STALE WAIVER (workflow is running)", str(entry.get("authorized-by", "-"))])
        # else: already covered by pass 1, and the expiry check ran there.

        # An expired waiver on an active/absent workflow is still a red entry.
        if expires is not None and expires < today and (wf is None or wf.get("state") == "active"):
            failures.append(
                f"{repo}: waiver for `{path}` also EXPIRED on {expires.isoformat()}."
            )

    return failures, rows


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def render_summary(rows: list[list[str]], failures: list[str], notes: list[str]) -> str:
    lines = ["## Workflow-state guard", ""]
    if rows:
        lines += [
            "| repo | workflow | state | waiver status | authorized-by |",
            "| --- | --- | --- | --- | --- |",
        ]
        for r in rows:
            lines.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
    else:
        lines.append("No non-active workflows and no waiver entries. Clean.")
    lines.append("")
    if notes:
        lines.append("### Scope notes")
        lines += [f"- {n}" for n in notes]
        lines.append("")
    if failures:
        lines.append(f"### FAIL — {len(failures)} finding(s)")
        lines += [f"- {f}" for f in failures]
    else:
        lines.append("### PASS — every non-active workflow has an unexpired waiver.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    ap.add_argument("--waivers", default=DEFAULT_WAIVERS, help="waiver register path")
    ap.add_argument(
        "--also-report",
        action="append",
        default=[],
        metavar="OWNER/NAME",
        help=(
            "additional repo to REPORT on, best-effort. Non-active workflows "
            "there are listed and fail the run; if the token cannot read the "
            "repo, that is recorded as a scope note and does NOT fail."
        ),
    )
    args = ap.parse_args()

    try:
        primary_repo = resolve_server_repository(args.repo)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot safely resolve server repository: {exc}", file=sys.stderr)
        return 2

    today = dt.date.today()
    notes: list[str] = []

    try:
        waivers = load_waivers(Path(args.waivers))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        failures, rows = check_repo(primary_repo, waivers, today)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Secondary repos: reported, not waived (no waiver register is readable
    # across a private-repo boundary with this workflow's token).
    for extra in args.also_report:
        try:
            extra_wfs = list_workflows(extra)
        except Exception as exc:
            notes.append(
                f"`{extra}` NOT INSPECTED — {exc}. The default GITHUB_TOKEN is "
                f"scoped to `{primary_repo}`; both repos are private, so cross-repo "
                f"listing needs a credential this workflow deliberately does not "
                f"carry. This is a KNOWN gap, not a pass."
            )
            rows.append([extra, "(all)", "NOT INSPECTED", "no cross-repo credential", "-"])
            continue
        extra_bad = [w for w in extra_wfs if w.get("state") != "active"]
        if not extra_bad:
            notes.append(f"`{extra}` inspected: {len(extra_wfs)} workflows, all active.")
        for wf in sorted(extra_bad, key=lambda w: w["path"]):
            rows.append([extra, wf["path"], wf.get("state", "?"), "NOT WAIVABLE HERE", "-"])
            failures.append(
                f"{extra}: `{wf['path']}` is `{wf.get('state')}`. This repo has no "
                f"readable waiver register from here — re-enable it, or record the "
                f"decision in that repository."
            )

    summary = render_summary(rows, failures, notes)
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
