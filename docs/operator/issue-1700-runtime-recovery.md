# Issue 1700 runtime recovery

Run 36649066490 lost its host result after the probe subprocess timed out. Historical
query run 36653980457 returned 16 events but no attributable native receipt. Execution
and cleanup remain unknown; do not replay that candidate's nonce or use
`complete_existing` to retry it. `verify_existing` remains read-only.

Run 36670281036 remained waiting for a distinct reviewer until its compiled v3
window expired at 12:00 UTC. It never deployed. Root preserves/cancels that run;
approving or replaying it cannot renew the immutable Worker/Container window.
The v5 renewal requires both runtimes to be rebuilt, with no runtime expiry
override. It starts at **2026-09-30 18:00 UTC** and expires exclusively at
**23:59 UTC** on the same date, using nonce
`issue-1700-recovery-20260930-v5` and cron `* * 30 9 *`. No entry may be
started after 22:44 UTC, preserving the 75-minute reserve.

One protected `deploy` on reviewed main builds both runtimes with nonce
`issue-1700-recovery-20260930-v5`. The shared
`crates/corelink-container/src/routes/staging_d1_probe_window.json` allows only
**2026-09-30 18:00 through 23:59 UTC**, exclusive at the end. The nonce plus the
new merged `SENTRY_RELEASE` selects a fresh dedicated DO. Host receipt freshness
remains bounded to the current invocation and its 16-minute deadline.

The v4 attempt used Worker release `9d8fdbfa04dd16d4099056de6e16ea8343ebba46`;
its schedule readback failed, and the captured schedule/tail inventories were
empty. That is not runtime proof and its nonce is not replayable. The original
v3 candidate was release `0f785fb9b096afe01247f1057d46377b9f604f13` with nonce
`issue-1700-recovery-20260929`.

Before the fresh probe, source checks only the exact v4 release-derived D1
table prefix and requires an empty catalog; it never deletes v4 tables. This
does not establish whether a v4 DO exists or is stopped. The v4 DO state remains
unknown unless an authorized provider read-only inventory proves the exact
object absent. The v3 retirement below is a separate exact target.

Before the fresh probe, source checks only the exact v4 release-derived D1
table prefix and requires an empty catalog; it never deletes v4 tables. This
does not establish whether a v4 DO exists or is stopped. The v4 DO state remains
unknown unless an authorized provider read-only inventory proves the exact
object absent. The v3 retirement below is a separate exact target.

Before entering the fresh DO, the Worker retires only the named original probe DO for
release `0f785fb9b096afe01247f1057d46377b9f604f13` and nonce
`issue-1700-recovery-20260929`. Retirement verifies DO identity, staging/account/D1
and the fresh window, preserves the old claim/receipt, persists a retirement fence,
and refuses active work. Old fetch, alarm and probe entry cannot restart it. A
present Container binding must prove stopped and its alarm must be absent before
any D1 cleanup; tenant credential-cleanup obligations are not traversed.

SQL cleanup inventories the entire old release's exact synthetic-table prefix.
Allowed names derive from minute boundaries within the original host interval
**00:12:03–00:34:18 UTC**. Every object, table schema, foreign key and row ownership
check must pass before the first DROP. Unexpected timestamps, schema, triggers,
indexes or rows stop cleanup. Only verified synthetic tables may be dropped;
absence is read back. No row payload is logged. Fresh proof requires both old-DO
retirement and old-table absence, plus the seven existing native D1 checks.

The protected job refuses provider access unless 75 minutes remain before expiry.
Its 75-minute budget bounds deployment to 30 minutes, exact-preimage Container
convergence to 10 minutes, the host step to 18 minutes, and runtime rollback to
12 minutes. Convergence retries reads only; unexpected app/digest/version drift
fails closed. Partial runtime progress and sanitized diagnostics are artifacts.

The host removes only its own cron and tail. Rollback requires exact candidate
ownership, Container state and route-free readback. Before its first mutation and
again immediately before restoring the pre-retirement Worker version, fresh
schedule and tail inventories must both be empty. Unknown/nonempty inventories
block that restore and preserve a sanitized residual receipt, including whether
Container restoration was already attempted. Never restore old code over an
unproven active probe schedule.

The fresh native probe uses only its dedicated synthetic table, verifies the
parameterized read and failed-batch rollback, then drops that table and destroys
its dedicated Container before issuing a receipt. Hard expiry remains enforced
in both runtimes. Successful closure also requires empty schedules/tails, zero
canonical staging routes, exact immutable candidate attribution and unchanged
postflight resources. A code merge or historical receipt alone is not provider
proof. Root owns publication, protected dispatch, rollback decisions and closure.


## Existing v5 candidate completion after account-list staleness

Run `36767025427` deployed reviewed source `cc32b3d819181bf9175e795868f66212aa5456c1` but exhausted its ten-minute Container convergence deadline before runtime. The account-wide list remained at version 8/image e44 while the exact application GET returned version 9/image a70 and five healthy instances. Do not redeploy or treat the stale list as rollback evidence.

The protected `complete_existing` operation is pinned only to this run and its immutable Worker/Container preimages. It reads the exact application endpoint, validates account/application identity, immutable image, version and all health counters, then requires empty schedules/tails and zero canonical staging routes before the existing native probe. Both entry and immediate pre-probe admission require at least 75 minutes remaining in the unchanged v5 window (latest entry strictly before 22:44 UTC). No image rebuild or Worker/Container source change is involved.

A pass requires invocation-fresh release/nonce/image receipts including original retirement and exact v4 catalog absence, plus unchanged candidate/health/routes and empty schedules/tails after cleanup. It does not prove the v4 DO was retired. Failure preserves a sanitized partial/residual receipt; it never triggers a blind legacy rollback or replay when native execution/cleanup is unknown. Operator rollback requires separate exact-ownership and quiescence evidence. Readiness, rotation and teardown remain separate #1700 acceptance requirements.
