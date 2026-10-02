#!/usr/bin/env bash
# B-315 landing transaction: exclusive allocation lock, exact byte authorities,
# allocator validation, then ONE merge through the pull-request merge API pinned
# to the exact head, then a post-merge MERGED/parent/tree proof.
#
# usage: b315_atomic_merge.sh <PR> <captured-head> <dry-run 0|1> <head-branch> <head-owner> <head-repo>
#
# ── Why the PR API and not a push (2026-10-01) ───────────────────────────────
# The first B-315 design built a signed two-parent merge commit locally and
# landed it with one atomic two-ref push carrying exact lease values for main
# and the head branch. Branch protection on main declines every
# direct push ("protected branch hook declined": strict required checks,
# enforce_admins, required linear history), so that path could land nothing,
# and the one-command merge never merged a PR. The ref update now goes through
# `PUT repos/{owner}/{repo}/pulls/<n>/merge` with `sha=<captured head>`.
#
# ── Why that keeps the race guarantee the dual-ref push gave ─────────────────
# The push rejected the update if EITHER ref had moved. The API gives the same
# two refusals from two different mechanisms:
#   * head: `sha=<H>` makes GitHub refuse (HTTP 409) unless the PR head is
#     still exactly H, the bytes this helper validated.
#   * main: strict status checks make GitHub refuse unless the PR is up to
#     date, i.e. the main tip at merge time is an ancestor of H. With linear
#     history and force pushes disabled, main only moves forward, and every
#     merge appends a NEW commit (squash/rebase) that H does not contain. So a
#     merge that lands after our capture leaves main outside H's history, and
#     GitHub refuses ours.
# This helper does not lean on GitHub alone: it requires the PR's base
# snapshot to equal current main, checks locally that main is an ancestor of H
# (a BEHIND PR is refused here, before any API call), and re-reads main and
# the head after allocation and again after taking the remote lease.
#
# The one case the API cannot refuse: main moves to a commit that is ALREADY
# in H's history (a direct push of an ancestor of H). The landed tree is still
# exactly tree(H), whose whole BACKLOG population the allocator validated, but
# the merge sits on a main this helper did not validate. The post-merge proof
# requires the merge commit's only parent to be the captured main, so this case
# exits LANDED_UNPROVEN (3) and is never reported as a clean merge.
#
# merge_method is squash: required linear history refuses merge commits, and
# squash is what this repository's history is made of. Under the up-to-date
# precondition the squash commit's tree is exactly tree(H); the proof checks it.
#
# ── The merge call does NOT pin the base (2026-10-02 review) ────────────────
# `sha=` pins the head only. The REST merge endpoint takes no base parameter,
# and GraphQL mergePullRequest also pins only expectedHeadOid. GitHub merges
# into whatever base the PR names when the PUT arrives, under THAT branch's
# protection. So the last read before the PUT is the PR's own base and head,
# and it must still say base=main at the captured main sha. A retarget seen by
# any read before then is a refusal.
#   Residual window: a retarget AFTER that last read and BEFORE GitHub acts on
#   the PUT. On the client, only the start-up of one `gh api` process and one
#   HTTPS request separate them; five full `gh pr view` calls measured
#   2026-10-02 on the founder's Mac (load average 55-60) took 1.1-1.6 s each,
#   start-up included. Exploiting it needs an actor with write
#   access retargeting the PR inside that gap. It cannot be closed from here,
#   so it is detected instead: the post-merge proof requires the PR's base to
#   read main and the merge commit to be reachable from refs/heads/main, and
#   anything else exits MERGED_INTO_UNEXPECTED_BASE (4) with recovery steps.
#   This helper never writes main itself, so the worst case is a merge into
#   another branch that is detected and reported, never a silent one.
#
# ── Local object substitution (2026-10-01 review) ───────────────────────────
# Every read below names an oid that GitHub also names, and the claim "the
# allocator validated the bytes GitHub merges" holds only if local git serves
# the REAL object for that oid. Two documented git features break that:
#   * refs/replace/*: `git cat-file`, `merge-base` and `rev-list` read the
#     replacement. Replacing an invalid candidate BACKLOG.md blob with a valid
#     one let the allocator pass bytes GitHub never merges, and because a blob
#     replacement leaves every tree oid unchanged the tree proof passed too.
#     GIT_NO_REPLACE_OBJECTS turns replacement off for this process and every
#     git it starts; it overrides core.useReplaceRefs (measured, git 2.51).
#   * grafts (<common-dir>/info/grafts, or GIT_GRAFT_FILE): they rewrite
#     commit parents for `merge-base --is-ancestor` and `rev-list --parents`,
#     and GIT_NO_REPLACE_OBJECTS does NOT turn them off (measured, git 2.51).
#     A BEHIND head can be grafted onto main. So a graft file in effect is a
#     refusal, checked before any ancestry read.
# Both are tested against the real helper in scripts/b315_merge_harness.py.
#
# ── Only a successful merge call can end in success (2026-10-02 review) ─────
# A refused (409/405) or lost merge call is never reported as a clean merge.
# After it, the PR can still show MERGED: the response was lost, OR another
# actor merged a DIFFERENT head H2 after the head moved, and H2 can carry the
# very same tree, so base, reachability, parent and tree proofs all pass for
# it. So the proof first requires the PR's merged head (headRefOid) to be the
# captured head, else MERGED_BY_OTHER_ACTOR (5); and after a non-success
# response a landing that passes every proof still exits 3, unclaimed.
#
# ── The local lock spans the merge call itself ──────────────────────────────
# backlog_lock_healthy is the LAST statement before the PUT (a holder that died
# or released during the boundary reads is a refusal) and the FIRST after it (a
# loss during the call is reported loudly and the landing exits 3). It asks the
# process table, so a holder that died but is not yet reaped (a zombie, which
# no longer holds the flock) reads as lost.
#
# Exit status: 0 = merged and proven (or a clean dry run); 1 = refused and NOT
# merged; 2 = bad arguments; 3 = LANDED_UNPROVEN (GitHub says MERGED but the
# parent/tree proof failed or could not be read, or the merge call did not
# report success, or the lock was lost during it; inspect main);
# 4 = MERGED_INTO_UNEXPECTED_BASE (GitHub says MERGED, but the PR's base is not
# main or the merge commit is not on refs/heads/main; follow the printed
# recovery steps); 5 = MERGED_BY_OTHER_ACTOR (GitHub says MERGED, but at a head
# this helper did not validate; follow the printed recovery steps).
# A dry run stops before the remote lease and before the merge endpoint.
set -euo pipefail
export GIT_NO_REPLACE_OBJECTS=1
PR=${1:?PR number required}; EXPECTED_HEAD=${2:?captured head required}; DRY_RUN=${3:-0}
EXPECTED_HEAD_REF=${4:?captured head branch required}; EXPECTED_OWNER=${5:?captured head owner required}; EXPECTED_REPO=${6:?captured head repository required}
case "$PR" in ""|*[!0-9]*) echo "⛔ PR must be a number, got '$PR'." >&2; exit 2 ;; esac
case "$DRY_RUN" in 0|1) ;; *) echo "⛔ dry-run flag must be 0 or 1, got '$DRY_RUN'." >&2; exit 2 ;; esac
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOC="$SCRIPT_DIR/backlog_id_alloc.py"
MERGE_METHOD=squash
LANDED_UNPROVEN=3
MERGED_INTO_UNEXPECTED_BASE=4
MERGED_BY_OTHER_ACTOR=5
REMOTE_LEASE_REF=refs/heads/corelink-backlog-id-merge-lock
REMOTE_LEASE_OID=; REMOTE_LEASE_HELD=0; REMOTE_LEASE_CONFIRMED=0
LOCK_PID=; LOCK_READY=; TMP=
BACKLOG_TMP=
CAPTURED_HEAD=; CAPTURED_BASE=; CAPTURED_MAIN=

cleanup_lease() {
  # owner-safe release: only this exact unique lease object may be removed.
  if [ "$REMOTE_LEASE_HELD" -eq 1 ] && [ "$REMOTE_LEASE_CONFIRMED" -eq 1 ]; then
    if git push --quiet --force-with-lease="$REMOTE_LEASE_REF:$REMOTE_LEASE_OID" origin ":$REMOTE_LEASE_REF"; then
      REMOTE_LEASE_HELD=0; REMOTE_LEASE_CONFIRMED=0
    else
      echo "⛔ remote lease cleanup refused (owner/token changed); leaving ref in place." >&2
    fi
  fi
}
release_remote_backlog_lease() { cleanup_lease; }
stop_backlog_allocation_lock() {
  if [ -n "$LOCK_PID" ]; then kill "$LOCK_PID" 2>/dev/null || true; wait "$LOCK_PID" 2>/dev/null || true; LOCK_PID=; fi
  [ -z "$LOCK_READY" ] || rm -f -- "$LOCK_READY"; LOCK_READY=
}
cleanup() {
  local rc=$?; release_remote_backlog_lease || true
  stop_backlog_allocation_lock; [ -z "$BACKLOG_TMP" ] || rm -rf -- "$BACKLOG_TMP"
  return "$rc"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM

refuse() { echo "⛔ $*" >&2; exit 1; }
is_oid() { [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; }
# git resolves the graft path itself (GIT_GRAFT_FILE, else the common-dir copy
# that linked worktrees share), so this asks git rather than guessing the path.
graft_file="$(git rev-parse --path-format=absolute --git-path info/grafts 2>/dev/null)" && [ -n "$graft_file" ] || refuse "git graft path unreadable; refusing to read ancestry it may rewrite."
[ ! -e "$graft_file" ] && [ ! -L "$graft_file" ] || refuse "git graft file $graft_file rewrites commit parents for every ancestry check and for the parent proof; remove it and re-run."

start_backlog_allocation_lock() {
common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
[ -n "$common_dir" ] && [ -d "$common_dir" ] && [ ! -L "$common_dir" ] || { echo "⛔ invalid git common-dir lock authority." >&2; exit 1; }
lock="$common_dir/corelink-backlog-id-allocation.lock"; LOCK_READY="$(mktemp "$common_dir/backlogalloc.ready.XXXXXX")"
python3 "$ALLOC" --hold-lock "$lock" --common-dir "$common_dir" --ready "$LOCK_READY" </dev/null & LOCK_PID=$!
for _ in $(seq 1 200); do
  if [ -s "$LOCK_READY" ]; then grep -q '^locked ' "$LOCK_READY" && break; echo "⛔ local allocation lock busy/invalid." >&2; exit 1; fi
  kill -0 "$LOCK_PID" 2>/dev/null || { echo "⛔ local allocation lock failed." >&2; exit 1; }; sleep 0.05
done
grep -q '^locked ' "$LOCK_READY" || { echo "⛔ local allocation lock did not become ready." >&2; return 1; }
}
start_backlog_allocation_lock || exit 1
# Healthy = the holder process exists and is not a zombie (a dead holder no
# longer holds the flock, and `kill -0` still succeeds on an unreaped zombie),
# and it reported the lock taken and never reported it lost.
backlog_lock_healthy() {
  local stat
  stat="$(ps -o stat= -p "$LOCK_PID" 2>/dev/null)" || return 1
  stat="${stat//[[:space:]]/}"
  case "$stat" in ""|Z*) return 1 ;; esac
  [ -s "$LOCK_READY" ] && grep -q '^locked ' "$LOCK_READY"
}

# json_fields <json> <dotted.path>... prints the scalar values on one line. A
# parse error, a missing key, or an empty/whitespace-bearing value fails: every
# way of not getting the field is a refusal, never a blank that compares equal.
json_fields() {
  python3 -c '
import json, sys
try:
    data = json.loads(sys.argv[1])
except ValueError:
    sys.exit(1)
out = []
for path in sys.argv[2:]:
    value = data
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            sys.exit(1)
        value = value[key]
    if isinstance(value, bool):
        value = "true" if value else "false"
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        sys.exit(1)
    out.append(value)
print(" ".join(out))
' "$@"
}
pr_snapshot() {
  local json
  json="$(gh pr view "$PR" --json headRefOid,baseRefOid,baseRefName,headRefName,isCrossRepository,headRepositoryOwner,headRepository 2>/dev/null)" || return 1
  json_fields "$json" headRefOid baseRefOid baseRefName headRefName isCrossRepository headRepositoryOwner.login headRepository.name
}
# remote_ref_oid fails when the remote cannot be read, so "unreadable" can never
# be mistaken for "absent" (which, for the lease ref, would mean "free").
remote_ref_oid() { local out; out="$(git ls-remote origin "$1" 2>/dev/null)" || return 1; awk 'NR==1 {print $1}' <<<"$out"; }
remote_main() { remote_ref_oid refs/heads/main; }
# Exact bytes: the blob inside the fetched commit object, no API transcoding,
# no checkout filters. The oid binds the bytes only because replacement
# objects are off (GIT_NO_REPLACE_OBJECTS above); with them on, this read
# returned a substituted blob for the same oid.
backlog_at() { git cat-file blob "$1:BACKLOG.md" >"$2" 2>/dev/null; }

# ── 1. capture exact authorities ─────────────────────────────────────────────
snapshot="$(pr_snapshot)" || refuse "PR #$PR metadata unavailable."
read -r bk_head bk_base bk_base_name bk_head_ref bk_cross bk_owner bk_repo <<<"$snapshot"
main_sha_before="$(remote_main)" || refuse "origin main unreadable."
[ "$bk_head" = "$EXPECTED_HEAD" ] && is_oid "$bk_head" && is_oid "$bk_base" && [ "$bk_base_name" = main ] && [ "$bk_head_ref" = "$EXPECTED_HEAD_REF" ] && [ "$bk_cross" = false ] && [ "$bk_owner" = "$EXPECTED_OWNER" ] && [ "$bk_repo" = "$EXPECTED_REPO" ] && is_oid "$main_sha_before" || refuse "exact base/head/main authority or same-repo head ownership changed."
CAPTURED_HEAD="$bk_head"; CAPTURED_BASE="$bk_base"; CAPTURED_MAIN="$main_sha_before"
[ "$CAPTURED_BASE" = "$CAPTURED_MAIN" ] || refuse "candidate base/head is stale: PR base snapshot $CAPTURED_BASE is not current main $CAPTURED_MAIN; update the branch and re-gate."
git fetch --no-tags --quiet origin "$CAPTURED_MAIN" "$CAPTURED_HEAD" >/dev/null 2>&1 || refuse "immutable base/head objects unavailable locally."
git merge-base --is-ancestor "$CAPTURED_MAIN" "$CAPTURED_HEAD" || refuse "PR head $CAPTURED_HEAD does not contain current main $CAPTURED_MAIN (BEHIND); strict branch protection refuses it. Update the branch, let checks re-run, re-gate."
head_tree="$(git rev-parse --verify --quiet "$CAPTURED_HEAD^{tree}")" && is_oid "$head_tree" || refuse "candidate tree unavailable."

# ── 2. allocator validation on the exact bytes ──────────────────────────────
TMP="$(mktemp -d "${TMPDIR:-/tmp}/b315-merge.XXXXXX")"; BACKLOG_TMP="$TMP"
backlog_at "$CAPTURED_HEAD" "$TMP/candidate.md" || refuse "candidate BACKLOG unavailable."
backlog_at "$CAPTURED_BASE" "$TMP/base.md" || refuse "base BACKLOG unavailable."
backlog_at "$CAPTURED_MAIN" "$TMP/main-before.md" || refuse "main BACKLOG unavailable."
python3 "$ALLOC" --main "$TMP/main-before.md" --candidate "$TMP/candidate.md" --base "$TMP/base.md" || refuse "allocation refused."

# ── 3. revalidate: nothing moved while we allocated ─────────────────────────
after="$(pr_snapshot)" || refuse "PR #$PR metadata unavailable after allocation."
main_sha_after="$(remote_main)" || refuse "origin main unreadable after allocation."
[ "$after" = "$snapshot" ] && [ "$main_sha_after" = "$CAPTURED_MAIN" ] || refuse "main/head moved during allocation; retry."

merge_cmd="gh api -X PUT repos/{owner}/{repo}/pulls/$PR/merge -f sha=$CAPTURED_HEAD -f merge_method=$MERGE_METHOD"
echo "▶ B-315 landing: $merge_cmd"
echo "  preconditions held: head=$CAPTURED_HEAD base=main=$CAPTURED_MAIN (head contains main), allocation valid, tree(head)=$head_tree"
if [ "$DRY_RUN" -eq 1 ]; then echo "⏸ dry-run: merge endpoint NOT called; no remote lease taken."; exit 0; fi

# ── 4. cross-machine lease (create-only, owner-safe release) ────────────────
observed="$(remote_ref_oid "$REMOTE_LEASE_REF")" || refuse "remote lease ref unreadable; refusing to treat it as free."; [ -z "$observed" ] || { echo "⛔ stale remote lease observed ($observed); refusing to break or take over automatically." >&2; echo "   recovery: git push --force-with-lease=$REMOTE_LEASE_REF:$observed origin :$REMOTE_LEASE_REF" >&2; echo "   refusing to break it automatically; obtain independent owner/admin recovery." >&2; exit 1; }
REMOTE_LEASE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"; empty_tree="$(git mktree </dev/null)"; payload="B-315 merge lease token=$REMOTE_LEASE_TOKEN main=$CAPTURED_MAIN"; REMOTE_LEASE_OID="$(printf '%s\n\nSigned-off-by: %s <%s>\n' "$payload" "$(git config user.name)" "$(git config user.email)" | git commit-tree "$empty_tree")"
git push --quiet origin "$REMOTE_LEASE_OID:$REMOTE_LEASE_REF" || { observed="$(remote_ref_oid "$REMOTE_LEASE_REF" || true)"; echo "⛔ lease acquisition lost race; observed=${observed:-unavailable}; no takeover." >&2; echo "   recovery: git push --force-with-lease=$REMOTE_LEASE_REF:${observed:-unknown} origin :$REMOTE_LEASE_REF" >&2; exit 1; }; REMOTE_LEASE_HELD=1; observed="$(remote_ref_oid "$REMOTE_LEASE_REF" || true)"; [ "$observed" = "$REMOTE_LEASE_OID" ] || { echo "⛔ lease replacement detected; refusing merge." >&2; echo "   recovery packet: ref=$REMOTE_LEASE_REF observed_oid=${observed:-unavailable} expected_oid=$REMOTE_LEASE_OID; owner-safe conditional release only." >&2; exit 1; }; REMOTE_LEASE_CONFIRMED=1
# SIGKILL cannot run cleanup; the fcntl lock is released by the kernel and any
# surviving remote lease is intentionally handled as stale on the next run.
backlog_lock_healthy || refuse "local lock lost."

# ── 5. merge boundary: the PR, main, then the PR again as the LAST read ─────
# boundary_pr_check refuses unless the PR still names base=main at the captured
# main, the captured head, and the captured head ownership. It runs twice:
# before the final main read, and as the very last read before the PUT,
# because the PUT pins the head but not the base (see the header).
boundary_pr_check() {
  local snap b_head b_base b_base_name
  snap="$(pr_snapshot)" || refuse "PR #$PR metadata unavailable at the merge boundary."
  read -r b_head b_base b_base_name _ <<<"$snap"
  [ "$b_base_name" = main ] && [ "$b_base" = "$CAPTURED_MAIN" ] || refuse "PR base retargeted at merge boundary: the PR names '$b_base_name' at $b_base, not main at the captured $CAPTURED_MAIN; not merging."
  [ "$b_head" = "$CAPTURED_HEAD" ] || refuse "candidate force-pushed at merge boundary; retry."
  [ "$snap" = "$snapshot" ] || refuse "head ownership changed at merge boundary; retry."
}
boundary_pr_check
main_sha_final="$(remote_main)" || refuse "origin main unreadable at the merge boundary."
[ "$main_sha_final" = "$CAPTURED_MAIN" ] || refuse "main moved at merge boundary; retry."
boundary_pr_check   # the LAST read before the PUT: only gh's start-up separates them
api_sha=""; api_ok=0; put_rc=0; merge_json=""
backlog_lock_healthy || refuse "local allocation lock lost before the merge call; not merging."
merge_json="$(gh api -X PUT "repos/{owner}/{repo}/pulls/$PR/merge" -f sha="$CAPTURED_HEAD" -f merge_method="$MERGE_METHOD" 2>"$TMP/merge.err")" || put_rc=$?
lock_held_after_put=1; backlog_lock_healthy || lock_held_after_put=0
[ "$lock_held_after_put" -eq 1 ] || echo "⛔ LOCK LOST DURING THE MERGE CALL: the local allocation lock (holder pid $LOCK_PID) was not held when the merge call returned; whatever GitHub did, this landing will not be reported as clean." >&2
if [ "$put_rc" -eq 0 ]; then
  read -r api_sha api_merged <<<"$(json_fields "$merge_json" sha merged || true)"
  if [ "${api_merged:-}" = true ] && is_oid "${api_sha:-}"; then api_ok=1; else api_sha=""; fi
  post_tries=6
fi
if [ "$api_ok" -ne 1 ]; then
  echo "⛔ merge API call for PR #$PR at head $CAPTURED_HEAD did not report success (exit $put_rc):" >&2
  cat "$TMP/merge.err" >&2; [ -z "${merge_json:-}" ] || printf '%s\n' "$merge_json" >&2
  post_tries=1   # a refusal is final; one read only to catch a merge that happened anyway
fi

# ── 6. post-merge proof ─────────────────────────────────────────────────────
post_state=UNKNOWN; merge_oid=; post_base=; post_head=; main_oid=
for try in $(seq 1 "$post_tries"); do
  post_json="$(gh pr view "$PR" --json state,mergeCommit,baseRefName,headRefOid 2>/dev/null || echo '{}')"
  post_state="$(json_fields "$post_json" state || echo UNKNOWN)"
  merge_oid="$(json_fields "$post_json" mergeCommit.oid || true)"
  post_base="$(json_fields "$post_json" baseRefName || true)"
  post_head="$(json_fields "$post_json" headRefOid || true)"
  [ "$post_state" = MERGED ] && break
  [ "$try" -eq "$post_tries" ] || sleep 2
done
[ "$post_state" = MERGED ] || { echo "⛔ PR #$PR is not MERGED (state=$post_state); no false merged claim." >&2; exit 1; }
unproven() { echo "⛔ PR #$PR is MERGED but the B-315 landing proof FAILED: $*" >&2; echo "   Inspect main now; do not treat this as a clean merge." >&2; exit "$LANDED_UNPROVEN"; }
wrong_base() {
  echo "⛔ merged_into_unexpected_base: PR #$PR is MERGED, but NOT into main: $*" >&2
  echo "   merge commit=${merge_oid:-unreadable} PR base=${post_base:-unreadable} refs/heads/main=${main_oid:-unread} captured main=$CAPTURED_MAIN head=$CAPTURED_HEAD" >&2
  echo "   This helper never writes main. Do NOT re-run it for PR #$PR: a merged PR cannot be merged again." >&2
  echo "   Recovery: 1) gh pr view $PR --json baseRefName,mergeCommit   (confirm where it landed)" >&2
  echo "             2) if '${post_base:-that base}' was not meant to receive it, revert ${merge_oid:-the merge commit} there through a revert PR" >&2
  echo "             3) open a new PR from head $CAPTURED_HEAD into main and gate it again; the head branch is left in place." >&2
  exit "$MERGED_INTO_UNEXPECTED_BASE"
}
other_actor() {
  echo "⛔ merged_by_other_actor: PR #$PR is MERGED, but not at the head this helper validated: $*" >&2
  echo "   merged head=${post_head:-unreadable} captured head=$CAPTURED_HEAD merge commit=${merge_oid:-unreadable} merge call exit=$put_rc success=$api_ok" >&2
  echo "   That head's BACKLOG.md was never allocated or validated here. Do NOT re-run this helper for PR #$PR." >&2
  echo "   Recovery: 1) gh pr view $PR --json headRefOid,mergeCommit,baseRefName   (what landed, and where)" >&2
  echo "             2) run scripts/backlog_id_alloc.py --main/--candidate/--base on the landed BACKLOG.md bytes" >&2
  echo "             3) if its ids collide or it was not meant to land, revert ${merge_oid:-the merge commit} through a revert PR." >&2
  exit "$MERGED_BY_OTHER_ACTOR"
}
is_oid "$merge_oid" || unproven "PR mergeCommit unreadable."
[ -z "$api_sha" ] || [ "$api_sha" = "$merge_oid" ] || unproven "API merge sha $api_sha != PR mergeCommit $merge_oid."
# WHICH head merged? First: another actor's merge of a different head with the
# same tree passes every proof below.
[ "$post_head" = "$CAPTURED_HEAD" ] || other_actor "the PR's merged head reads '${post_head:-unreadable}', not the captured $CAPTURED_HEAD."
# Where did it land? Asked before the parent/tree proof, which could pass on
# another base: a branch cut from the captured main has the same tip.
[ -n "$post_base" ] || unproven "PR base unreadable after merge."
[ "$post_base" = main ] || wrong_base "the PR's base reads '$post_base' (retargeted after the last pre-merge read)."
main_oid="$(remote_main || true)"; is_oid "$main_oid" || unproven "main unreadable after merge."
git fetch --no-tags --quiet origin "$merge_oid" "$main_oid" >/dev/null 2>&1 || unproven "merge commit $merge_oid not fetchable."
# A read of main that lags the merge is retried before the verdict.
for try in 1 2 3; do
  git merge-base --is-ancestor "$merge_oid" "$main_oid" && break
  [ "$try" -lt 3 ] || wrong_base "merge commit $merge_oid is not reachable from refs/heads/main $main_oid."
  sleep 2
  main_oid="$(remote_main || true)"; is_oid "$main_oid" || unproven "main unreadable after merge."
  git fetch --no-tags --quiet origin "$main_oid" >/dev/null 2>&1 || unproven "main $main_oid not fetchable."
done
parents="$(git rev-list --parents -n 1 "$merge_oid" 2>/dev/null || true)"
[ "$parents" = "$merge_oid $CAPTURED_MAIN" ] || unproven "merge commit parents [${parents#"$merge_oid"} ] != [ $CAPTURED_MAIN ]: it landed on a main this helper did not validate."
actual_tree="$(git rev-parse --verify --quiet "$merge_oid^{tree}" || true)"
[ "$actual_tree" = "$head_tree" ] || unproven "resulting main tree mismatch: $actual_tree != tree(head) $head_tree."
# Only a successful merge call can end in success: after a refused or lost call
# this helper cannot tell its own merge from an identical one made by others.
[ "$api_ok" -eq 1 ] || unproven "merge_response_not_success: the merge call did not report success (exit $put_rc), so this helper does not claim the merge, although the PR is MERGED at the captured head with parent=captured main and tree=tree(head)."
[ "$lock_held_after_put" -eq 1 ] || unproven "the local allocation lock was lost during the merge call."
echo "✅ PR #$PR MERGED via the PR API: commit=$merge_oid parent=$CAPTURED_MAIN tree=$actual_tree = tree(head $CAPTURED_HEAD)"
