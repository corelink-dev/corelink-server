#!/usr/bin/env bash
# pre-merge-gate-check.sh [--merge [--dry-run] [--admin-reason "<why>"]] <PR-number>
# =============================================================================
# MANDATORY pre-merge gate. Run this BEFORE every merge — or, better,
# let it do the merge itself so there is no `&&` for a shell to disarm:
#
#   bash scripts/pre-merge-gate-check.sh <PR>              # gate + report only
#   bash scripts/pre-merge-gate-check.sh --merge <PR>      # gate, then PR-API merge IFF green
#
# Exits 0 ONLY when the PR is mergeable AND its real gates ran AND every
# non-skipping check is green. Exits 1 (and prints why) otherwise — in which
# case DO NOT MERGE.
#
# Why this exists: the heavy gates (coverage, CodeQL, the TLA+ model-checks,
# ffi-matrix, reproducible-build, …) were moved OFF per-PR to keep PRs fast
# (they run nightly + on main + on-demand). So the checks that REMAIN on a PR
# are exactly the fast, load-bearing ones — and they must all be green before
# merge. This guards against blind `--admin` merges that skip them.
#
# ⚠️ Branch protection on main requires exactly TWO checks — `dco` and
# `cargo fmt --all --check` — and is strict (the PR must be up to date with
# main), enforce_admins, and linear history. That is what
# `gh api repos/{owner}/{repo}/branches/main/protection` returned on 2026-10-01;
# re-read it rather than trusting this line, and note CLAUDE.md's
# `required checks = []` was already stale then. Every OTHER check on a PR is
# enforced only by THIS script, so for those it is the last line of defense.
# It must never fail OPEN.
#
# ── The 2026-08-04 hole this closes (PR #1049) ───────────────────────────────
# The script was correct and it still failed to gate, because gating and merging
# were two commands joined by shell:
#
#   bash scripts/pre-merge-gate-check.sh 1049 | tail -3 && an-unchecked-merge 1049
#
# `&&` binds to the PIPELINE, whose exit status is `tail`'s — always 0. The gate
# printed `⛔ DO NOT MERGE — 4 pending`, exited 1, and the merge ran anyway with
# four checks still in flight. They happened to pass; that was luck, not process.
# The same shape was used on #1043/#1045/#1046/#1047 (green, so no harm, but no
# enforcement either). A guard piped through `tail` is disarmed exactly as
# thoroughly as the bug the guard was written to catch.
#
# The fix is NOT "be more careful". `--merge` puts the gate and the merge in ONE
# process: the merge helper is reachable only through a single `if` on the
# gate's own return code, so there is no exit status left for a pipeline to
# swallow. Piping `--merge`'s output changes nothing — the decision never leaves
# this process. When stdout is NOT a tty and `--merge` was not used, the script
# prints a warning on STDERR (which the pipe does not capture) naming the footgun.
#
# ── The two 2026-08-04 holes in `--merge`'s first day (PR #1048, #1051) ──────
# 1. A DRAFT PR passed the gate. On #1048 this printed "✅ All gates green — OK
#    to merge PR #1048", issued the merge, and GitHub rejected it with
#    `GraphQL: Pull Request is still a draft (mergePullRequest)`. Green checks on
#    a draft prove the code compiles; they do not prove the AUTHOR considers it
#    done, which is the one thing a draft states. So draft joins the STRUCTURAL
#    family below (not-OPEN / CONFLICTING / pending / gates-absent) and is NOT
#    overridable by --admin-reason: no documented flake reason makes an
#    unfinished PR finished.
#
# 2. A merge that SUCCEEDED reported failure. On #1051 the merge landed
#    (state=MERGED on GitHub) and then a post-merge cleanup command
#    died deleting the LOCAL branch — `fatal: 'main' is already used by worktree
#    at …` — so the script exited 1 on a merge that had worked. gh deletes the
#    local branch BEFORE the remote one, so that abort also left the remote
#    branch behind (refs/heads/chore/repin-3bd8f3b7 is still on origin today).
#    This repo runs a dozen simultaneous worktrees and one of them holds `main`,
#    so the failing `git checkout main` inside gh is the norm, not an edge case.
#    Two consequences below: the exit status is now derived from the PR's STATE
#    on GitHub (did it merge?) instead of from gh's exit code (did cleanup also
#    work?), and branch deletion no longer touches local git at all.
#
# ── The 2026-08-02 hole this closes ──────────────────────────────────────────
# It printed "✅ All gates green — OK to merge PR #967" for a PR touching two
# Workers on which dco, changelog-validate, gitleaks, trivy, secrets-matrix and
# every vitest job had NEVER RUN. Six checks existed; all six were
# `pull_request_target` metadata jobs (labels, size bucket, welcome comment,
# dependabot sentinel). Zero failures out of zero real gates read as green.
#
# Mechanism: `pull_request` workflows run on the MERGE REF. When a PR conflicts,
# GitHub cannot build that ref, so it creates NO runs at all — not queued, not
# failed, ABSENT. `pull_request_target` workflows run on the BASE branch, so
# those still fire. That asymmetry is the fingerprint, and it means the MOST
# DANGEROUS PR STATE PRODUCED THE MOST REASSURING OUTPUT.
#
# It is not a rare state here: every `feat:`/`fix:` commit needs a CHANGELOG
# `[Unreleased]` entry and everyone inserts at the top of the same section, so
# two concurrent PRs conflict by construction, and `main` moves under a branch
# within minutes.
#
# Three defenses below, in order of how badly the old script needed them:
#   1. mergeable must be MERGEABLE (not CONFLICTING/UNKNOWN)
#   2. the always-present gates must actually appear in the check list
#   3. "no checks at all" is a FAILURE, not "nothing to gate"
# =============================================================================
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: bash scripts/pre-merge-gate-check.sh [flags] <PR-number>

  (no flags)              gate + report. Exit 0 = green, 1 = DO NOT MERGE.
  --merge                 gate, then the B-315 merge helper IFF the gate went
                          green: allocation lock, exact-byte BACKLOG check, ONE
                          merge through the PR API pinned to the gated head,
                          post-merge proof. Then delete the merged REMOTE
                          branch. Exit status = did the PR merge; 3 = merged
                          but NOT proven. Nothing to chain with `&&`.
  --dry-run               with --merge: run every precondition, print the merge
                          API call, never call it.
  --admin-reason "<why>"  with --merge: proceed past this gate's OWN refusal
                          (GitHub still enforces branch protection, admins
                          included, so dco/fmt are never bypassed), and
                          ONLY when the sole
                          reason the gate refused is a failed/cancelled check.
                          Never usable on draft, pending, conflicting, or
                          missing-gate refusals. The reason is echoed into the
                          output.
USAGE
}

MODE="gate"
DRY_RUN=0
ADMIN_REASON=""
PR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --merge)          MODE="merge"; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --admin-reason)
      if [ $# -lt 2 ] || [ -z "${2-}" ]; then
        echo "  ⛔ --admin-reason needs a non-empty reason string." >&2
        exit 2
      fi
      ADMIN_REASON="$2"; shift 2 ;;
    --admin-reason=*)
      ADMIN_REASON="${1#*=}"
      if [ -z "$ADMIN_REASON" ]; then
        echo "  ⛔ --admin-reason needs a non-empty reason string." >&2
        exit 2
      fi
      shift ;;
    --admin)
      echo "  ⛔ bare --admin is not accepted. Use: --merge --admin-reason \"<documented infra/flake reason>\"" >&2
      exit 2 ;;
    -h|--help)        usage; exit 0 ;;
    --)               shift ;;
    -*)               echo "  ⛔ unknown flag: $1" >&2; usage >&2; exit 2 ;;
    *)
      if [ -n "$PR" ]; then echo "  ⛔ more than one PR number given: $PR and $1" >&2; exit 2; fi
      PR="$1"; shift ;;
  esac
done

case "$PR" in
  ""|*[!0-9]*) usage >&2; exit 1 ;;
esac

if [ -n "$ADMIN_REASON" ] && [ "$MODE" != "merge" ]; then
  echo "  ⛔ --admin-reason is only meaningful with --merge." >&2
  exit 2
fi

# ── The stale-copy footgun ───────────────────────────────────────────────────
# This script is run from whatever worktree the operator happens to be in, and
# worktrees sit on feature branches that can be many merges behind `main`. A
# stale copy still GATES correctly — the checking logic barely changes — so
# nothing looks wrong; what it silently drops is whatever the newer copy added.
# That is not hypothetical: PR #1418 was merged on 2026-08-30 by a copy that
# predated #1428, so the merge produced no lane-set record and the absence was
# only caught by going to look for it. A gate whose newest behaviour can vanish
# without a symptom is the same defect class as a check that never ran.
#
# So: compare the RUNNING file against the copy on `origin/main` and, in merge
# mode, refuse on a mismatch. Report-only mode warns instead — reading a stale
# verdict costs nothing irreversible. If `origin/main`'s copy cannot be resolved
# (no network, no remote-tracking ref), say so and continue: an unresolvable
# comparison is not evidence of staleness, and failing closed on it would make
# the gate unusable offline.
self_path="${BASH_SOURCE[0]}"
if running_oid="$(git hash-object "$self_path" 2>/dev/null)" \
   && main_oid="$(git rev-parse --verify --quiet origin/main:scripts/pre-merge-gate-check.sh 2>/dev/null)" \
   && [ -n "$running_oid" ] && [ -n "$main_oid" ]; then
  if [ "$running_oid" != "$main_oid" ]; then
    echo "  ⛔ this copy of the gate is NOT the one on origin/main." >&2
    echo "       running: $running_oid  ($self_path)" >&2
    echo "       main   : $main_oid" >&2
    echo "     A stale copy gates fine and silently drops whatever the newer one adds" >&2
    echo "     (#1418: merged with no lane-set record). Run it from a main worktree:" >&2
    echo "       git worktree add --detach /tmp/wt-gate origin/main" >&2
    echo "       bash /tmp/wt-gate/scripts/pre-merge-gate-check.sh --merge $PR" >&2
    if [ "$MODE" = "merge" ]; then
      echo "     Refusing to merge from a copy that is not main's." >&2
      exit 2
    fi
    echo "  ⚠️  report-only mode — continuing, but read the verdict as possibly incomplete." >&2
  fi
else
  echo "  ⚠️  could not compare this script against origin/main (no ref or not a repo);" >&2
  echo "      continuing — an unresolvable comparison is not evidence of staleness." >&2
fi

# ── The pipe footgun, named on stderr ─────────────────────────────────────────
# `[ -t 1 ]` is false exactly when the caller piped or redirected stdout, i.e.
# in the `… | tail -3 && unchecked-merge …` shape that produced the #1049 incident.
# The warning goes to STDERR on purpose: the pipe does not capture it, so it
# reaches the human even when stdout is being truncated by `tail`. It is emitted
# from an EXIT trap so it survives `2>&1 | tail -N` too, and so that every exit
# path (including the early structural refusals) carries it.
VERDICT_FILE=""
LANES_FILE=""
# shellcheck disable=SC2329  # invoked indirectly by `trap on_exit EXIT` below; 0.11 only spots that when the script does not end in an explicit `exit`.
on_exit() {
  local rc=$?
  if [ -n "$VERDICT_FILE" ]; then rm -f "$VERDICT_FILE"; fi
  if [ -n "$LANES_FILE" ]; then rm -f "$LANES_FILE"; fi
  if [ "$MODE" != "merge" ] && [ ! -t 1 ]; then
    echo "  ⚠️  stdout is not a terminal — do not chain this gate with an unchecked merge," >&2
    echo "      DON'T: a pipeline's exit status is the LAST command's (\`tail\` = 0), so" >&2
    echo "      this gate's verdict is discarded. This is how PR #1049 merged with 4" >&2
    echo "      checks pending. Use instead:" >&2
    echo "        bash scripts/pre-merge-gate-check.sh --merge $PR" >&2
  fi
  return "$rc"
}
trap on_exit EXIT

# `verdict` records WHY the gate refused, for --admin-reason eligibility only.
# STRUCTURAL  = not OPEN / DRAFT / not MERGEABLE / no checks / required gates
#               absent / anything pending. Never overridable: these mean the
#               gates have NOT RUN (or the author has not declared the PR done),
#               which no amount of documented flake reason can fix.
# OVERRIDABLE = gates all present and finished, and the only non-green entries
#               are failed/cancelled checks — the documented-flake case.
verdict() {
  if [ -n "$VERDICT_FILE" ]; then printf '%s' "$1" >"$VERDICT_FILE"; fi
  return 0
}

# ── The gate itself ──────────────────────────────────────────────────────────
# Everything below is byte-for-byte the pre-existing gate, moved into a function
# so its return code can be tested by an `if` instead of being handed to a shell
# operator. It uses `return`, never `exit`: the caller decides what happens next.
run_gate() {
  # ── Defense 1: mergeability ─────────────────────────────────────────────────
  # GitHub computes `mergeable` asynchronously, so UNKNOWN means "ask again", not
  # "fine". Both non-MERGEABLE states are refused: on a conflict the check list is
  # actively misleading (see the header), and on UNKNOWN we cannot yet tell.
  local state mergeable mergestatus prstate isdraft json
  state="$(gh pr view "$PR" --json mergeable,mergeStateStatus,state,isDraft \
    -q '"\(.mergeable) \(.mergeStateStatus) \(.state) \(.isDraft)"' 2>/dev/null \
    || echo "ERROR ERROR ERROR ERROR")"
  read -r mergeable mergestatus prstate isdraft <<<"$state"

  if [ "$prstate" != "OPEN" ]; then
    echo "  ⛔ DO NOT MERGE PR #$PR — the PR is $prstate, not OPEN."
    verdict STRUCTURAL
    return 1
  fi

  # ── Defense 4: a DRAFT is the author saying "not ready" ─────────────────────
  # Tested with `!= "false"` rather than `== "true"` so an empty/garbled/renamed
  # field refuses too — fail-CLOSED, same direction as the bucket allowlist.
  if [ "$isdraft" != "false" ]; then
    echo "  ⛔ DO NOT MERGE PR #$PR — the PR is a DRAFT (isDraft=$isdraft)."
    echo
    echo "     Green checks on a draft prove the code compiles; they do NOT prove"
    echo "     the author considers it done, which is the one thing draft states."
    echo "     GitHub refuses the mutation anyway (\`Pull Request is still a draft\`)"
    echo "     — observed on #1048, 2026-08-04, AFTER this gate said \"OK to merge\"."
    echo
    echo "     Fix:  the AUTHOR runs \`gh pr ready $PR\`, then re-run this script."
    verdict STRUCTURAL
    return 1
  fi

  if [ "$mergeable" != "MERGEABLE" ]; then
    echo "  ⛔ DO NOT MERGE PR #$PR — mergeable=$mergeable ($mergestatus)."
    echo
    if [ "$mergeable" = "CONFLICTING" ]; then
      echo "     A CONFLICTING PR gets NO \`pull_request\` checks at all: those run on"
      echo "     the merge ref, which GitHub cannot build. Any green you see below is"
      echo "     \`pull_request_target\` metadata jobs only — it proves NOTHING."
      echo
      echo "     Fix:  git rebase origin/main && git push --force-with-lease"
      echo "     Then re-run this script and wait for the real checks to appear."
    else
      echo "     GitHub has not finished computing mergeability. Re-run in a moment;"
      echo "     do NOT read this as a green light."
    fi
    verdict STRUCTURAL
    return 1
  fi

  # ── Defense 3 (ordering: checked before the per-check loop) ─────────────────
  # "No checks reported" used to `exit 0` with "nothing to gate". On a repo where
  # every PR runs dco + gitleaks unconditionally, no checks means the workflows did
  # not fire — which is a reason to STOP, not to merge.
  json="$(gh pr checks "$PR" --json name,bucket,link 2>/dev/null || true)"
  if [ -z "$json" ] || [ "$json" = "[]" ]; then
    echo "  ⛔ DO NOT MERGE PR #$PR — the PR reports NO checks at all."
    echo "     That is not 'nothing to gate': every PR here runs dco + gitleaks"
    echo "     unconditionally, so zero checks means the workflows never fired."
    verdict STRUCTURAL
    return 1
  fi

  GATE_JSON="$json" GATE_VERDICT_FILE="$VERDICT_FILE" \
    GATE_LANES_FILE="$LANES_FILE" python3 - "$PR" <<'PY'
import os, sys, json
pr = sys.argv[1]
data = json.loads(os.environ["GATE_JSON"])

def verdict(kind):
    """Side channel for --admin-reason eligibility. Never touches stdout, so the
    default (no --merge) output stays byte-identical to the pre-2026-08-04 script."""
    path = os.environ.get("GATE_VERDICT_FILE") or ""
    if path:
        with open(path, "w") as fh:
            fh.write(kind)

# Bucket handling is ALLOWLIST-based, not denylist-based, and that is the whole
# point. The previous version tested `b == "fail"` / `b == "pending"` and let
# every other bucket fall through as green — so a **cancelled** check printed as
# `? cancel  spec-validation` and the script still concluded
# "✅ All gates green". Observed on PR #982, 2026-08-03: a job the runner killed
# at 5m37s ("The operation was canceled", the shape an ENOSPC or an overloaded
# self-hosted mac takes) read as a pass. A cancelled gate has not run; it has
# proven nothing. Same failure shape this file already documents for zero-gates,
# one level down — the check list was present, one entry was simply uncountable.
#
# Anything that is not an explicit PASS or an explicit SKIP is now BLOCKING,
# including a bucket name GitHub has not invented yet. Unknown ⇒ blocking is the
# fail-CLOSED direction, which is the only acceptable one here.
PASS_BUCKETS = {"pass"}
SKIP_BUCKETS = {"skipping"}
order = {"fail": 0, "cancel": 0, "pending": 1, "skipping": 2, "pass": 3}
mark = {"pass": "✓", "fail": "✗", "cancel": "✗", "pending": "…", "skipping": "-"}
fails, pends = [], []
for c in sorted(data, key=lambda x: order.get(x.get("bucket"), 0)):
    b = c.get("bucket")
    print(f"  {mark.get(b,'✗')} {str(b):9} {c.get('name')}")
    if b in PASS_BUCKETS or b in SKIP_BUCKETS:
        continue
    if b == "pending":
        pends.append(c)
    else:
        # fail, cancel, or anything unrecognised.
        fails.append(c)
print()

# ── Defense 2: the real gates must be PRESENT, not merely not-failing ─────────
# Chosen because both are triggered by a bare `on: pull_request` with NO paths
# filter, so they run for every PR regardless of what it touches. If either is
# missing, the `pull_request` workflows did not fire and the rest of this list
# is metadata jobs that gate nothing. Substring match keeps this robust against
# job-name edits ("dco-check" → "dco", "gitleaks (secret-leak scan)" →
# "gitleaks detect").
#
# Keep this list SMALL and path-filter-free. Adding a path-filtered gate here
# would make the script fail on PRs that legitimately skip it — turning a
# fail-open into a fail-noisy, which gets the whole check disabled by the next
# person in a hurry.
REQUIRED_PRESENT = ["dco", "gitleaks", "changelog"]
names = " ".join(c.get("name", "").lower() for c in data)
missing = [g for g in REQUIRED_PRESENT if g not in names]
if missing:
    print(f"  ⛔ DO NOT MERGE PR #{pr} — the always-present gates never ran: "
          f"{', '.join(missing)}.")
    print("     Every PR triggers these unconditionally (bare `on: pull_request`,")
    print("     no paths filter), so their ABSENCE means the pull_request")
    print("     workflows did not fire for this head sha. The checks listed above")
    print("     are pull_request_target metadata jobs; they gate nothing.")
    verdict("STRUCTURAL")
    sys.exit(1)

if fails or pends:
    print(f"  ⛔ DO NOT MERGE PR #{pr} — {len(fails)} not-green, {len(pends)} pending.")
    for c in fails:
        b = c.get("bucket")
        why = "" if b == "fail" else f"  [bucket={b} — not a pass; it did not run to a verdict]"
        print(f"     ✗ {c.get('name')}  {c.get('link','')}{why}")
    print("     Fix or re-run until green. Use --admin ONLY for a documented,")
    print("     non-blocking infra/flake reason you state explicitly.")
    # A PENDING check has not produced a verdict yet, so no documented reason can
    # justify overriding it — that is precisely the #1049 state. Only an all-
    # finished list whose sole problem is fail/cancel is override-eligible.
    verdict("STRUCTURAL" if pends else "OVERRIDABLE")
    sys.exit(1)
# The lane set is written HERE, at the only point the gate concludes green, so
# the record is a by-product of gating rather than a thing the operator must
# remember to do. WP-1 required every merge to record its checked lanes; nine
# consecutive merges did not, because it depended on discipline. Discipline is
# not a mechanism.
_lanes = os.environ.get("GATE_LANES_FILE") or ""
if _lanes:
    with open(_lanes, "w") as fh:
        for c in sorted(data, key=lambda c: c.get("name", "")):
            fh.write(f"{c.get('bucket','?')}\t{c.get('name','?')}\n")
print(f"  ✅ All gates green — OK to merge PR #{pr}.")
PY
}

if [ "$MODE" = "merge" ]; then
  VERDICT_FILE="$(mktemp "${TMPDIR:-/tmp}/premergegate.XXXXXX")"
  LANES_FILE="$(mktemp "${TMPDIR:-/tmp}/premergelanes.XXXXXX")"
fi

# Capture H1 and its exact base/branch ownership before any checks run.  Checks
# are only useful for these bytes; immediately after run_gate we re-read H1 and
# refuse if the PR was force-pushed while checks were executing.
CAPTURED_HEAD=""
CAPTURED_BASE=""
CAPTURED_BASE_NAME=""
CAPTURED_HEAD_REF=""
CAPTURED_HEAD_OWNER=""
CAPTURED_HEAD_REPO=""
if [ "$MODE" = "merge" ]; then
  captured_meta="$(gh pr view "$PR" --json headRefOid,baseRefOid,baseRefName,headRefName,isCrossRepository,headRepositoryOwner,headRepository -q '"\(.headRefOid) \(.baseRefOid) \(.baseRefName) \(.headRefName) \(.isCrossRepository) \(.headRepositoryOwner.login) \(.headRepository.name)"' 2>/dev/null || true)"
  read -r CAPTURED_HEAD CAPTURED_BASE CAPTURED_BASE_NAME CAPTURED_HEAD_REF captured_cross CAPTURED_HEAD_OWNER CAPTURED_HEAD_REPO <<<"$captured_meta"
  if [ -z "$CAPTURED_HEAD" ] || [ -z "$CAPTURED_BASE" ] || [ "$CAPTURED_BASE_NAME" != "main" ] || [ "$captured_cross" != "false" ] || [ -z "$CAPTURED_HEAD_REF" ] || [ -z "$CAPTURED_HEAD_OWNER" ] || [ -z "$CAPTURED_HEAD_REPO" ]; then
    echo "  ⛔ exact H1/base/head-branch ownership unavailable." >&2
    exit 1
  fi
fi

gate_rc=0
run_gate || gate_rc=$?

# Default mode: report and exit with the gate's own code. Unchanged since 2026-08-03.
if [ "$MODE" != "merge" ]; then
  exit "$gate_rc"
fi

checked_head="$(gh pr view "$PR" --json headRefOid --jq .headRefOid 2>/dev/null || true)"
if [ "$checked_head" != "$CAPTURED_HEAD" ]; then
  echo "  ⛔ NO MERGE ISSUED for PR #$PR — H1 moved while checks ran; retry." >&2
  exit 1
fi

# ── --merge: the ONLY branch that can reach the merge helper ─────────────────
# There is exactly one call site below and it sits inside this `if`. A non-zero
# gate returns here; nothing downstream re-evaluates the verdict.
GATE_VERDICT="$(cat "$VERDICT_FILE" 2>/dev/null || true)"

if [ "$gate_rc" -ne 0 ]; then
  echo
  if [ -n "$ADMIN_REASON" ] && [ "$GATE_VERDICT" = "OVERRIDABLE" ]; then
    echo "  ⚠️  --admin OVERRIDE, reason stated by the caller:"
    echo "      \"$ADMIN_REASON\""
    echo "      (allowed only because every gate RAN and the sole non-green entries"
    echo "       are failed/cancelled checks — pending/conflicting is never overridable.)"
  else
    if [ -n "$ADMIN_REASON" ]; then
      echo "  ⛔ --admin-reason REFUSED: this refusal is $GATE_VERDICT, not OVERRIDABLE."
      echo "     Pending, conflicting, non-OPEN, or missing-gate states mean the gates"
      echo "     have NOT RUN. No documented reason substitutes for a verdict."
    fi
    echo "  ⛔ NO MERGE ISSUED for PR #$PR — the gate exited $gate_rc."
    exit "$gate_rc"
  fi
fi

# ── BACKLOG id precheck ─────────────────────────────────────────────────────
# `backlog_verify.py` requires DENSE ids. That single rule makes id collisions
# between concurrent PRs unavoidable, and it does so in a way that punishes the
# careful: a session that tries to LEAVE A GAP for a sibling is failed by the
# gate for trying, because the gap it leaves is itself a density violation.
# There is therefore no allocation any author can perform ahead of time — the
# correct id is only knowable at the instant of merge, which is here.
#
# Marking the slot with a placeholder does not work either: `B-NNN` is not a
# valid id and the item lands BROKEN, so the PR is red before it can be gated.
# (Measured 2026-08-31: `122 item(s): confirmed=120, drifted=1, broken=1`.)
#
# So this block does the one thing that CAN be done here: it refuses the merge
# BEFORE it happens and prints the exact renumber command. Without it, the
# collision is discovered by the SECOND merge — at which point main is already
# red and every open PR in the repo inherits the failure.
#
# It deliberately does not rewrite the branch. Renumbering is an edit to someone
# else's PR; the gate names the fix and lets the author apply it.
# Runs under --dry-run too: a rehearsal that hides the one refusal the operator
# would hit for real is worse than no rehearsal.
if false; then
{
  bk_head="$(gh pr view "$PR" --json headRefOid --jq .headRefOid 2>/dev/null || true)"
  if [ -n "$bk_head" ]; then
    bk_tmp="$(mktemp -d "${TMPDIR:-/tmp}/bkids.XXXXXX")"
    # `Accept: raw` returns the file bytes directly — no base64, and so no
    # dependence on whether this host's `base64` spells the decode flag `-d`
    # (GNU) or `-D` (BSD/macOS). This script runs on both.
    gh api -H "Accept: application/vnd.github.raw" \
      "repos/{owner}/{repo}/contents/BACKLOG.md?ref=$bk_head" \
      > "$bk_tmp/pr.md" 2>/dev/null || true
    gh api -H "Accept: application/vnd.github.raw" \
      "repos/{owner}/{repo}/contents/BACKLOG.md?ref=main" \
      > "$bk_tmp/main.md" 2>/dev/null || true
    if [ -s "$bk_tmp/pr.md" ] && [ -s "$bk_tmp/main.md" ]; then
      bk_msg="$(python3 - "$bk_tmp/pr.md" "$bk_tmp/main.md" <<'PYIDS'
import re, sys
ids = lambda p: sorted({int(m) for m in re.findall(r'^id:\s*B-(\d+)\s*$',
                                                   open(p, encoding='utf-8').read(), re.M)})
pr, mn = ids(sys.argv[1]), ids(sys.argv[2])
if not pr or not mn:
    # A degenerate parse must NOT be read as "no new ids" — but it must also not
    # block a merge, because this check is a courtesy and the real gate is
    # `backlog_verify`. Warn on stderr (which the caller does not capture) and
    # leave stdout empty so the merge proceeds.
    print("  ⚠️  precheck de id do BACKLOG: nao extrai ids de um dos lados "
          "(pr=%d, main=%d) — nao concluo nada e sigo." % (len(pr), len(mn)),
          file=sys.stderr)
    raise SystemExit
new = [i for i in pr if i not in set(mn)]
if not new:
    raise SystemExit                      # PR adds no items — nothing to check.
want = list(range(max(mn) + 1, max(mn) + 1 + len(new)))
if new == want:
    raise SystemExit                      # already correct.
# Rename order is NOT a style choice: applied in the wrong order, one rename
# lands on an id that a later rename still needs as its source, and the two
# items collapse into one. Moving ids UP is safe descending (highest first);
# moving them DOWN is safe ascending. Deriving it from the direction is the
# whole point — a fixed "always descending" is correct only half the time.
up = want[0] > new[0]
pairs = sorted(zip(new, want), reverse=up)
order = "DECRESCENTE (o maior primeiro)" if up else "CRESCENTE (o menor primeiro)"
lines = [
    f"os ids novos deste PR sao {new}, mas a main esta em B-{max(mn):03d},",
    f"     entao o intervalo correto e {want}.",
    "",
    f"     Renumere NA ORDEM {order} — nesta direcao, a ordem inversa faria",
    "     um rename pousar num id que o rename seguinte ainda usa como origem,",
    "     e os dois itens virariam um so:",
]
# The id does NOT live only in BACKLOG.md. A single item is routinely cited by
# its dossier under `reports/` and by its `changelog.d/` fragment, and nothing
# checks that those agree with the backlog. Naming only BACKLOG.md here would
# hand the author a command that renumbers the item and leaves its own
# documentation pointing at the old number — silently, because no gate reads
# those files for ids. A gate that gives incomplete instructions is worse than
# one that gives none: the incomplete one looks authoritative.
for src, dst in pairs:
    lines.append(
        f"       for f in $(grep -rl 'B-{src:03d}' --include='*.md' .); do "
        f"perl -0pi -e 's/B-{src:03d}(?![0-9])/B-{dst:03d}/g' \"$f\"; done"
    )
lines += [
    "",
    "     O `(?![0-9])` nao e opcional: sem ele `B-116` corrompe `B-1160`.",
    "",
    "     O laco sobre `grep -rl` tambem nao e enfeite: o mesmo id aparece no",
    "     dossie em `reports/` e no fragmento de `changelog.d/`, e nenhum portao",
    "     confere que esses tres concordam. Renumerar so o BACKLOG.md deixa a",
    "     documentacao do proprio item apontando para o numero antigo.",
    "",
    "     E confira DEPOIS, nao so antes — se um rebase trouxe ids de outra",
    "     sessao para o seu arquivo, a substituicao alcanca os dela tambem.",
    "",
    "     Nunca rode isto com um rebase em andamento ou com arquivo em conflito:",
    "     a substituicao passa por cima dos marcadores `<<<<<<<` e o estrago fica",
    "     dentro do que parece um conserto. Termine o rebase, depois renumere.",
]
print("\n".join(lines))
PYIDS
)" || bk_msg=""
      if [ -n "$bk_msg" ]; then
        echo
        echo "  ⛔ NO MERGE ISSUED for PR #$PR — colisao de id no BACKLOG.md:"
        echo "     $bk_msg"
        rm -rf "$bk_tmp"
        exit 1
      fi
    fi
    rm -rf "$bk_tmp"
  fi
}
fi

# B-315 lands through the PR merge API pinned to the gated head (squash); the
# helper's header argues why strict protection plus the sha pin keeps the race
# guarantee its former direct dual-ref push gave (protection declined that push,
# so it never landed anything). The legacy advisory block above is disabled;
# allocation and the merge are delegated to scripts/b315_atomic_merge.sh.
#
# `--delete-branch` was DROPPED (it was added because this repo has
# delete_branch_on_merge=false). Reason: gh deletes the LOCAL branch first — it
# `git checkout`s the default branch to do it — and only then the remote one. In
# a repo with a dozen live worktrees, one of which holds `main`, that checkout
# fails with `fatal: 'main' is already used by worktree at …`, which on #1051
# both made a landed merge look failed AND aborted before the remote delete, so
# the branch it was supposed to clean up is still on origin. Deleting the ref by
# API instead (below, after the merge is confirmed) does the part that actually
# needed doing, touches no local git state, and cannot fail the merge. The local
# branch is deliberately left alone — a worktree may be sitting on it — and is
# named in the output so the operator can remove it.
echo
echo "  ▶ B-315 landing for PR #$PR through the PR merge API, pinned to $CAPTURED_HEAD"
GATED_SHA="$CAPTURED_HEAD"
merge_rc=0
bash scripts/b315_atomic_merge.sh "$PR" "$CAPTURED_HEAD" "$DRY_RUN" "$CAPTURED_HEAD_REF" "$CAPTURED_HEAD_OWNER" "$CAPTURED_HEAD_REPO" || merge_rc=$?
if [ "$DRY_RUN" -eq 1 ]; then
  exit "$merge_rc"
fi

# ── Did it MERGE? Ask GitHub, do not ask the helper's exit code alone ────────
# The question this script's exit status answers is "is PR #N merged", so
# re-query the PR and decide on that. Retried: the merge API is synchronous,
# but a transient network error on the read must not be reported as a failed
# merge. Since B-315 the helper runs no local cleanup that can fail after the
# merge (the #1051 shape), so a MERGED PR with a non-zero helper exit is a
# merge the helper did NOT prove: exit 3 below, never "cosmetic".
post_state="UNKNOWN"; head_ref=""; cross=""
for attempt in 1 2 3; do
  post="$(gh pr view "$PR" --json state,headRefName,isCrossRepository \
    -q '"\(.state) \(.headRefName) \(.isCrossRepository)"' 2>/dev/null \
    || echo "UNKNOWN - -")"
  read -r post_state head_ref cross <<<"$post"
  if [ "$post_state" = "MERGED" ]; then break; fi
  if [ "$attempt" -lt 3 ]; then sleep 2; fi
done

if [ "$post_state" != "MERGED" ]; then
  echo
  echo "  ⛔ THE MERGE DID NOT LAND — PR #$PR is state=$post_state (merge helper exited $merge_rc)."
  echo "     Nothing was merged. Read the helper's refusal above; the PR is unchanged."
  if [ "$merge_rc" -ne 0 ]; then exit "$merge_rc"; fi
  exit 1
fi

echo
if [ "$merge_rc" -ne 0 ]; then
  echo "  ⛔ PR #$PR IS MERGED (GitHub says state=MERGED) but the B-315 landing is"
  echo "     UNPROVEN: the merge helper exited $merge_rc, so its parent/tree proof"
  echo "     did not hold or did not run (read its message above). Inspect main now."
  echo "     Not recording a lane set and not deleting \`$CAPTURED_HEAD_REF\`: they are the evidence."
  exit 3
fi
echo "  ✅ PR #$PR merged."

# ── Record the checked lane set on the PR (WP-1 DoD) ─────────────────────────
# Runs only after GitHub has confirmed state=MERGED, and only from the lane set
# the gate itself computed — so the comment can never claim a greener check set
# than the one that actually authorised this merge.
#
# This is deliberately best-effort and deliberately LAST. This script's exit
# status answers exactly one question — "is PR #N merged" (#1051) — and a
# failed comment post must not change that answer. It warns instead, because a
# silent failure here would rot the record back to the state this fixes.
if [ -s "$LANES_FILE" ]; then
  {
    echo "**Merge gate — checked lane set**"
    echo
    echo "Gated at \`$GATED_SHA\`, merged by \`scripts/pre-merge-gate-check.sh --merge $PR\`."
    if [ -n "$ADMIN_REASON" ]; then
      echo
      echo "> ⚠️ **--admin override.** Reason stated by the caller: $ADMIN_REASON"
    fi
    echo
    echo '```'
    sed 's/^pass\t/[pass]     /; s/^skipping\t/[skipping] /' "$LANES_FILE"
    echo '```'
  } | gh pr comment "$PR" --body-file - >/dev/null 2>&1 \
    || echo "  ⚠️  merged, but recording the lane set on PR #$PR failed (record only; the merge stands)."
fi

# delete_branch_on_merge=false here, so the head branch survives the merge until
# someone removes it. Failures are reported, never fatal: the merge already
# landed, and a leftover branch is untidy, not broken.
if [ "$cross" = "true" ]; then
  echo "  ℹ️  fork PR — head branch \`$head_ref\` lives in another repo; not deleting."
elif [ -z "$head_ref" ] || [ "$head_ref" = "-" ]; then
  echo "  ⚠️  could not read headRefName — delete the merged branch manually."
else
  # ── PRs EMPILHADOS: apagar a base FECHA o filho, e é irreversível ──────────
  # O GitHub fecha automaticamente qualquer PR cujo branch-base deixe de
  # existir, e `reopenPullRequest` RECUSA reabrir nesse estado — o PR tem de
  # ser recriado, perdendo revisão, comentários e histórico. Aconteceu com o
  # #1436 em 2026-08-30: mergear a base da pilha apagou `fix/okf-main-red` e
  # matou o filho, que tinha 8 checks verdes.
  #
  # O merge JÁ landou neste ponto, então isto nunca é fatal: na dúvida a
  # varredura RECUSA apagar. Branch órfão é bagunça; PR fechado é trabalho
  # perdido, e os dois custos não se comparam.
  dependents="$(gh pr list --state open --base "$head_ref" \
                  --json number --jq '[.[].number] | join(", ")' 2>/dev/null || echo "?")"
  if [ "$dependents" = "?" ]; then
    echo "  ⚠️  não consegui checar se \`$head_ref\` é base de algum PR aberto — NÃO apagando."
    echo "      Comparação impossível não é prova de ausência. Apague à mão depois de conferir:"
    echo "        gh pr list --base $head_ref --state open"
  elif [ -n "$dependents" ]; then
    echo "  ⛔ \`$head_ref\` ainda é BASE do(s) PR(s) aberto(s): $dependents"
    echo "     NÃO apagando — o GitHub fecharia esse(s) PR(s) e reabrir seria recusado."
    echo "     Retargete primeiro, depois apague:"
    for d in ${dependents//,/ }; do
      echo "        gh pr edit $d --base main"
    done
    echo "        gh api -X DELETE repos/{owner}/{repo}/git/refs/heads/$head_ref"
  elif gh api -X DELETE "repos/{owner}/{repo}/git/refs/heads/$head_ref" --silent 2>/dev/null; then
    echo "  🧹 deleted remote branch \`$head_ref\`."
  else
    echo "  ⚠️  remote branch \`$head_ref\` was NOT deleted (already gone, or no perms):"
    echo "        gh api -X DELETE repos/{owner}/{repo}/git/refs/heads/$head_ref"
  fi
  if git show-ref --verify --quiet "refs/heads/$head_ref" 2>/dev/null; then
    echo "  ⚠️  LOCAL branch \`$head_ref\` still exists here (left on purpose — a"
    echo "      worktree may be on it). Remove it when convenient:"
    echo "        git branch -D $head_ref      # or: git worktree remove <path>"
  fi
fi
exit 0
