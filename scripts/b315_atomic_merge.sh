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
# Exit status: 0 = merged and proven (or a clean dry run); 1 = refused and NOT
# merged; 2 = bad arguments; 3 = LANDED_UNPROVEN (GitHub says MERGED but the
# parent/tree/reachability proof failed or could not be read; inspect main).
# A dry run stops before the remote lease and before the merge endpoint.
set -euo pipefail
PR=${1:?PR number required}; EXPECTED_HEAD=${2:?captured head required}; DRY_RUN=${3:-0}
EXPECTED_HEAD_REF=${4:?captured head branch required}; EXPECTED_OWNER=${5:?captured head owner required}; EXPECTED_REPO=${6:?captured head repository required}
case "$PR" in ""|*[!0-9]*) echo "⛔ PR must be a number, got '$PR'." >&2; exit 2 ;; esac
case "$DRY_RUN" in 0|1) ;; *) echo "⛔ dry-run flag must be 0 or 1, got '$DRY_RUN'." >&2; exit 2 ;; esac
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOC="$SCRIPT_DIR/backlog_id_alloc.py"
MERGE_METHOD=squash
LANDED_UNPROVEN=3
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
backlog_lock_healthy() { kill -0 "$LOCK_PID" 2>/dev/null && [ -s "$LOCK_READY" ] && grep -q '^locked ' "$LOCK_READY"; }

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
# no checkout filters. The oid binds the bytes, so a re-read cannot differ.
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

# ── 5. merge boundary: re-read both refs, then one pinned API merge ─────────
final="$(pr_snapshot)" || refuse "PR #$PR metadata unavailable at the merge boundary."
main_sha_final="$(remote_main)" || refuse "origin main unreadable at the merge boundary."
[ "$main_sha_final" = "$CAPTURED_MAIN" ] || refuse "main moved at merge boundary; retry."
[ "$final" = "$snapshot" ] || refuse "candidate force-pushed at merge boundary; retry."
api_sha=""
if merge_json="$(gh api -X PUT "repos/{owner}/{repo}/pulls/$PR/merge" -f sha="$CAPTURED_HEAD" -f merge_method="$MERGE_METHOD" 2>"$TMP/merge.err")"; then
  read -r api_sha api_merged <<<"$(json_fields "$merge_json" sha merged || true)"
  [ "${api_merged:-}" = true ] && is_oid "${api_sha:-}" || api_sha=""
  post_tries=6
else
  echo "⛔ merge API call for PR #$PR at head $CAPTURED_HEAD did not return success:" >&2
  cat "$TMP/merge.err" >&2; [ -z "${merge_json:-}" ] || printf '%s\n' "$merge_json" >&2
  post_tries=1   # a refusal is final; one read only to catch a merge whose response was lost
fi

# ── 6. post-merge proof ─────────────────────────────────────────────────────
post_state=UNKNOWN; merge_oid=
for try in $(seq 1 "$post_tries"); do
  post_json="$(gh pr view "$PR" --json state,mergeCommit 2>/dev/null || echo '{}')"
  post_state="$(json_fields "$post_json" state || echo UNKNOWN)"
  merge_oid="$(json_fields "$post_json" mergeCommit.oid || true)"
  [ "$post_state" = MERGED ] && break
  [ "$try" -eq "$post_tries" ] || sleep 2
done
[ "$post_state" = MERGED ] || { echo "⛔ PR #$PR is not MERGED (state=$post_state); no false merged claim." >&2; exit 1; }
unproven() { echo "⛔ PR #$PR is MERGED but the B-315 landing proof FAILED: $*" >&2; echo "   Inspect main now; do not treat this as a clean merge." >&2; exit "$LANDED_UNPROVEN"; }
is_oid "$merge_oid" || unproven "PR mergeCommit unreadable."
[ -z "$api_sha" ] || [ "$api_sha" = "$merge_oid" ] || unproven "API merge sha $api_sha != PR mergeCommit $merge_oid."
main_oid="$(remote_main || true)"; is_oid "$main_oid" || unproven "main unreadable after merge."
git fetch --no-tags --quiet origin "$merge_oid" "$main_oid" >/dev/null 2>&1 || unproven "merge commit $merge_oid not fetchable."
parents="$(git rev-list --parents -n 1 "$merge_oid" 2>/dev/null || true)"
[ "$parents" = "$merge_oid $CAPTURED_MAIN" ] || unproven "merge commit parents [${parents#"$merge_oid"} ] != [ $CAPTURED_MAIN ]: it landed on a main this helper did not validate."
actual_tree="$(git rev-parse --verify --quiet "$merge_oid^{tree}" || true)"
[ "$actual_tree" = "$head_tree" ] || unproven "resulting main tree mismatch: $actual_tree != tree(head) $head_tree."
git merge-base --is-ancestor "$merge_oid" "$main_oid" || unproven "merge commit $merge_oid is not reachable from main $main_oid."
echo "✅ PR #$PR MERGED via the PR API: commit=$merge_oid parent=$CAPTURED_MAIN tree=$actual_tree = tree(head $CAPTURED_HEAD)"
