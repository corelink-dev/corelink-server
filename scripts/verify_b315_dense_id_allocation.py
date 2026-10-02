#!/usr/bin/env python3
"""B-315 executable population, wiring and landing-behaviour guard.

Four layers, each a refusal on its own:

1. wiring — the merge gate plus its helper still carry every token of the
   PR-API landing design and none of the retired designs (the direct dual-ref
   push that branch protection declined, the `gh pr merge` CLI); and the gate
   wrapper itself has exactly one helper call site, which forwards
   ``"$DRY_RUN"``, and names no merge call of its own (REST ``pulls/…/merge``,
   ``gh pr merge``, or a GraphQL ``mergePullRequest(`` / auto-merge mutation).
   Tokens are a tripwire for an accidental revert, not a proof: a token can sit
   in a comment, and a merge spelled some other way (a query read from a file,
   say) is not detected. Layer 4 is the proof for the helper (its fake `gh`
   also refuses every call it does not model, so a helper that fetched bytes
   through the API would fail there); nothing here EXECUTES the wrapper.
2. the allocator's fixture self-test;
3. the allocator on the real BACKLOG.md population;
4. behaviour — scripts/b315_merge_harness.py runs the REAL helper against a
   fake GitHub in throwaway repositories (land, dry run, every race, a 409, a
   405, a merge on an unvalidated main, a wrong tree, a lost response, a stale
   lease, a busy lock, a refs/replace-substituted BACKLOG.md blob, a graft that
   hides a BEHIND head), and at every merge-endpoint call checks that the local
   allocation lock and the remote lease are still held. It proves the helper
   against the harness's model of GitHub; that GitHub enforces the model is
   argued, not proven, here.

Trust: the BASE-owned candidate gate in scripts/backlog_verify.py, when it runs
(its lane, backlog-verify.yml, was disabled_manually on 2026-10-01), refuses a
PR that changes this file or the harness (the harness is imported through the
`scripts` package so that gate's static import closure reaches it). The helper,
the gate wrapper and the allocator are run by path, so they are NOT in that
closure: a PR may change them without that refusal, and what judges the change
is this verifier and its harness when they run on the changed tree.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOCATOR = ROOT / "scripts/backlog_id_alloc.py"
GATE = ROOT / "scripts/pre-merge-gate-check.sh"
ATOMIC = ROOT / "scripts/b315_atomic_merge.sh"
HARNESS = ROOT / "scripts/b315_merge_harness.py"

REQUIRED = (
    # one authority, crash-safe lock across allocation AND merge
    "start_backlog_allocation_lock",
    "backlog_lock_healthy",
    "--common-dir",
    # exact base/main/head capture and same-repository ownership
    "CAPTURED_HEAD",
    "CAPTURED_BASE",
    "CAPTURED_MAIN",
    "CAPTURED_BASE_NAME",
    "CAPTURED_HEAD_REF",
    "headRepositoryOwner",
    "isCrossRepository",
    "baseRefName",
    '[ "$CAPTURED_BASE" = "$CAPTURED_MAIN" ]',
    'git merge-base --is-ancestor "$CAPTURED_MAIN" "$CAPTURED_HEAD"',
    # revalidation after allocation and at the merge boundary
    "main_sha_before",
    "main_sha_after",
    "main_sha_final",
    "moved during allocation",
    "main moved at merge boundary",
    "candidate force-pushed at merge boundary",
    # allocator on exact object bytes, with local object substitution off:
    # refs/replace disabled for every git the helper runs, a graft file refused
    "backlog_id_alloc.py",
    "--base",
    'git cat-file blob "$1:BACKLOG.md"',
    "export GIT_NO_REPLACE_OBJECTS=1",
    "git rev-parse --path-format=absolute --git-path info/grafts",
    "rewrites commit parents",
    # cross-machine lease, owner-safe release
    "REMOTE_LEASE_REF",
    "REMOTE_LEASE_CONFIRMED",
    "release_remote_backlog_lease",
    '--force-with-lease="$REMOTE_LEASE_REF:$REMOTE_LEASE_OID"',
    # the landing: one head-pinned squash through the PR merge API
    "MERGE_METHOD=squash",
    'gh api -X PUT "repos/{owner}/{repo}/pulls/$PR/merge" -f sha="$CAPTURED_HEAD" -f merge_method="$MERGE_METHOD"',
    "merge endpoint NOT called",
    # post-merge proof
    "no false merged claim",
    "head_tree",
    "actual_tree",
    '[ "$parents" = "$merge_oid $CAPTURED_MAIN" ]',
    "LANDED_UNPROVEN",
)

# Retired designs. The first three were the pre-B-315 squash CLI; the rest are
# the direct dual-ref push that branch protection declines on main.
OBSOLETE = (
    "--match-head-commit",
    "gh pr merge",
    "--squash",
    "--atomic",
    'commit-tree "$head_tree"',
    '--force-with-lease="refs/heads/main',
)


def wiring_problems(text: str) -> list[str]:
    """Return one line per missing/obsolete token in ``text`` (gate + helper)."""
    if not text.strip():
        return ["gate + helper text is EMPTY: nothing to check"]
    problems = [f"missing: {token}" for token in REQUIRED if token not in text]
    problems += [f"obsolete: {token}" for token in OBSOLETE if token in text]
    if re.search(r"gh api -X DELETE[^\n]*corelink-backlog-id-merge-lock", text):
        problems.append("obsolete: unconditional lease DELETE")
    # Any push whose refspec names main is the retired design, however spelled
    # on one line; branch protection would decline it anyway.
    for line in text.splitlines():
        if re.search(r"\bgit\b[^\n]*\bpush\b", line) and re.search(r"(?:^|[:\s\"'])(?:refs/heads/)?main\b", line):
            problems.append(f"direct push to main: {line.strip()[:120]}")
    return problems


HELPER_CALL = "bash scripts/b315_atomic_merge.sh"
HELPER_CALL_ARGS = 'bash scripts/b315_atomic_merge.sh "$PR" "$CAPTURED_HEAD" "$DRY_RUN" '
# A merge issued by the wrapper itself would bypass the helper's lock, its
# allocator check and its dry-run stop. Raw lines, comments included: a hit in
# a comment is a false alarm a human clears in one edit, never a miss.
WRAPPER_MERGE_CALL = re.compile(
    r"pulls/[^\s\"']*/merge\b|\bgh\s+pr\s+merge\b|\bmergePullRequest\s*\(|\benablePullRequestAutoMerge\b"
)


def gate_problems(gate: str) -> list[str]:
    """Return one line per way the wrapper could merge without the helper."""
    if not gate.strip():
        return ["gate wrapper text is EMPTY: nothing to check"]
    problems: list[str] = []
    call_sites = [line.strip() for line in gate.splitlines() if HELPER_CALL in line and not line.lstrip().startswith("#")]
    if len(call_sites) != 1:
        problems.append(f"gate wrapper has {len(call_sites)} helper call sites, expected exactly 1")
    elif HELPER_CALL_ARGS not in call_sites[0]:
        problems.append(f"helper call site does not forward \"$DRY_RUN\": {call_sites[0][:160]}")
    for number, line in enumerate(gate.splitlines(), start=1):
        if WRAPPER_MERGE_CALL.search(line):
            problems.append(f"gate wrapper names its own merge call at line {number}: {line.strip()[:120]}")
    return problems


def main() -> int:
    missing_files = [str(p.relative_to(ROOT)) for p in (ALLOCATOR, GATE, ATOMIC, HARNESS) if not p.is_file()]
    if missing_files:
        print(f"B-315 instrument broken: missing {missing_files}", file=sys.stderr)
        return 2
    gate = GATE.read_text(encoding="utf-8")
    text = gate + "\n" + ATOMIC.read_text(encoding="utf-8")
    problems = wiring_problems(text) + gate_problems(gate)
    if problems:
        print("B-315 merge wiring:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    result = subprocess.run(
        [sys.executable, str(ALLOCATOR), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1
    # The self-test only sees fixtures. From 2026-09-22 to 2026-10-01 the real
    # ledger carried an id the allocator did not know (B-1630), every --merge was
    # refused, and this verifier stayed green. Run the allocator on the real
    # population too: if it cannot allocate on BACKLOG.md, no merge can.
    backlog = str(ROOT / "BACKLOG.md")
    result = subprocess.run(
        [sys.executable, str(ALLOCATOR), "--main", backlog, "--candidate", backlog, "--base", backlog],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or "added=none" not in result.stdout:
        print("B-315 allocator refuses the real BACKLOG.md population:", file=sys.stderr)
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1
    # Layer 4 is only as trustworthy as the harness file it imports. The
    # BASE-owned candidate gate (scripts/backlog_verify.py) freezes a verifier's
    # imports only when they are spelled through the `scripts` package, so the
    # harness is imported that way: once this verifier is BASE, a PR that edits
    # the harness (say, to stub self_test) is refused as a mutated trusted
    # control. A bare `import b315_merge_harness` left it outside that closure.
    # `scripts` has no __init__.py, so a regular `scripts` package anywhere on
    # sys.path would win over it; the file check below refuses that instead of
    # trusting whatever module answered to the name.
    sys.path.insert(0, str(ROOT))
    from scripts import b315_merge_harness as harness  # noqa: E402

    loaded_from = Path(getattr(harness, "__file__", None) or "").resolve()
    if loaded_from != HARNESS.resolve():
        print(
            f"B-315 instrument broken: scripts.b315_merge_harness loaded from {loaded_from}, "
            f"not {HARNESS}",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="b315-verify-") as directory:
        problems = harness.self_test(Path(directory))
    if problems:
        print("B-315 landing behaviour:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    print(
        f"B-315 dense allocation, PR-API landing wiring ({len(REQUIRED)} required / "
        f"{len(OBSOLETE)} retired tokens) and {len(harness.SCENARIOS)} landing scenarios: PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
