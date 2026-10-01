#!/usr/bin/env python3
"""B-315 executable population and mutation guard."""

from __future__ import annotations

import subprocess
import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOCATOR = ROOT / "scripts/backlog_id_alloc.py"
GATE = ROOT / "scripts/pre-merge-gate-check.sh"
ATOMIC = ROOT / "scripts/b315_atomic_merge.sh"


def main() -> int:
    if not ALLOCATOR.is_file() or not GATE.is_file() or not ATOMIC.is_file():
        print("B-315 instrument broken: allocator or merge gate is missing", file=sys.stderr)
        return 2
    gate = GATE.read_text(encoding="utf-8") + "\n" + ATOMIC.read_text(encoding="utf-8")
    required = (
        "start_backlog_allocation_lock",
        "main_sha_before",
        "main_sha_after",
        "main_sha_final",
        "CAPTURED_HEAD",
        "CAPTURED_BASE_NAME",
        "CAPTURED_HEAD_REF",
        "headRepositoryOwner",
        "isCrossRepository",
        "baseRefName",
        "bk_base_name",
        "bk_base",
        "backlog_id_alloc.py",
        "--common-dir",
        "--base",
        "backlog_lock_healthy",
        "REMOTE_LEASE_REF",
        "REMOTE_LEASE_CONFIRMED",
        "release_remote_backlog_lease",
        "git ls-remote origin",
        "commit-tree",
        "-p \"$bk_base\" -p \"$bk_head\"",
        "--atomic",
        "--force-with-lease=\"refs/heads/main:$main_sha_before\"",
        "--force-with-lease=\"$HEAD_REF:$bk_head\"",
        "neither ref changed",
        "--force-with-lease=\"$REMOTE_LEASE_REF:$REMOTE_LEASE_OID\"",
        "head_tree",
        "actual_tree",
        "head_oid",
        "no false merged claim",
        "cmp -s \"$TMP/main-before.md\" \"$TMP/main-after.md\"",
    )
    missing = [token for token in required if token not in gate]
    obsolete = [token for token in ("--match-head-commit", "gh pr merge", "--squash") if token in gate]
    if re.search(r"gh api -X DELETE[^\n]*corelink-backlog-id-merge-lock", gate):
        obsolete.append("unconditional lease DELETE")
    if obsolete:
        print(f"B-315 gate retains obsolete merge/race claims: {obsolete}", file=sys.stderr)
        return 1
    if missing:
        print(f"B-315 gate wiring missing: {missing}", file=sys.stderr)
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
    print("B-315 dense allocation and merge revalidation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
