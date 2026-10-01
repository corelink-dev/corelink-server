# Issue 1700 runtime recovery

Run 36649066490 lost its host result after the probe subprocess timed out. Historical
query run 36653980457 returned 16 events but no attributable native receipt. Execution
and cleanup remain unknown; do not replay that candidate's nonce or use
`complete_existing` to retry it. `verify_existing` remains read-only.

Run 36670281036 remained waiting for a distinct reviewer until its compiled v3
window expired at 12:00 UTC. It never deployed. Root preserves/cancels that run;
approving or replaying it cannot renew the immutable Worker/Container window.
The v5 renewal described below was consumed and remains UNKNOWN for native
execution/cleanup. Its timestamp and nonce are historical only; do not replay
it. The current source candidate compiles v6 with a new nonce and fixed
cross-midnight window; it is not provider authorization.

The v5 `complete_existing` operation below remains pinned to its historical
rollout. A future approved v6 deployment must rebuild both runtimes from the
same exact source SHA and use the compiled shared window; it cannot replay v5.

The v4 attempt used Worker release `9d8fdbfa04dd16d4099056de6e16ea8343ebba46`;
its schedule readback failed, and the captured schedule/tail inventories were
empty. That is not runtime proof and its nonce is not replayable. The original
v3 candidate was release `0f785fb9b096afe01247f1057d46377b9f604f13` with nonce
`issue-1700-recovery-20260929`.

Before the fresh probe, source checks only the exact v4 release-derived D1
table prefix and requires an empty catalog; it never deletes v4 tables. This
does not establish whether a v4 DO exists or is stopped. The v4 DO state remains
unknown unless an authorized provider read-only inventory proves the exact
object absent. The v3 and v5 retirements below are separate exact targets. V5's
native execution/cleanup remains UNKNOWN; empty host schedule/tail inventory is
not evidence about its Durable Object or D1 tables.

Before entering the fresh DO, the Worker retires only the named original probe DO for
release `0f785fb9b096afe01247f1057d46377b9f604f13` and nonce
`issue-1700-recovery-20260929`. Retirement verifies DO identity, staging/account/D1
and the fresh window, preserves the old claim/receipt, persists a retirement fence,
and refuses active work. Old fetch, alarm and probe entry cannot restart it. A
present Container binding must prove stopped and its alarm must be absent before
any D1 cleanup; tenant credential-cleanup obligations are not traversed.

The v5 retirement targets only DO name
`_staging_d1_binding_probe_v2:issue-1700-recovery-20260930-v5:cc32b3d819181bf9175e795868f66212aa5456c1`.
It persists a distinct retirement fence and preserves v5's existing claim and
receipt as unknown. It proves that exact Container stopped and its alarm absent.
Its D1 inventory is limited to the release-derived prefix
`corelink_staging_d1_probe_cc32b3d819181bf9_` and minute boundaries within
the approved v5 window **18:00–23:59 UTC**. It drops only tables whose exact
schema, row ownership, and absence readback pass. The v3 target remains separate;
neither target's retirement rewrites the other's evidence. No row payload is
logged. Fresh proof requires both retirement receipts and the native D1 checks.
The v3 retirement separately validates its original release prefix and only the
minute-derived table names from **00:12:03–00:34:18 UTC**; unexpected objects,
schema, foreign keys, or rows stop cleanup before the first DROP.

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


## Historical v5 candidate completion after account-list staleness

Run `36767025427` deployed reviewed source `cc32b3d819181bf9175e795868f66212aa5456c1` but exhausted its ten-minute Container convergence deadline before runtime. The account-wide list remained at version 8/image e44 while the exact application GET returned version 9/image a70 and five healthy instances. Do not redeploy or treat the stale list as rollback evidence.

The protected `complete_existing` operation is pinned only to this run and its immutable Worker/Container preimages. It reads the exact application endpoint, validates account/application identity, immutable image, version and all health counters, then requires empty schedules/tails and zero canonical staging routes before the existing native probe. Both entry and immediate pre-probe admission require at least 75 minutes remaining in the unchanged v5 window (latest entry strictly before 22:44 UTC). No image rebuild or Worker/Container source change is involved.

A pass requires invocation-fresh release/nonce/image receipts including original retirement and exact v4 catalog absence, plus unchanged candidate/health/routes and empty schedules/tails after cleanup. It does not prove the v4 DO was retired. Failure preserves a sanitized partial/residual receipt; it never triggers a blind legacy rollback or replay when native execution/cleanup is unknown. Operator rollback requires separate exact-ownership and quiescence evidence. Readiness, rotation and teardown remain separate #1700 acceptance requirements.
Failure readback is point-in-time only: a queued Cron event may still claim the
one-shot lease after schedules appear empty, so its `queued_event_state` is
reported as unresolved and requires admission/receipt reconciliation.

## v6 source candidate

The compiled tuple is Cron `*/2 * * * *`, start **2026-09-30 22:00 UTC**,
entry cutoff **2026-10-01 02:15 UTC** (the final `*/2` Cron tick before it
is **02:14 UTC**), and exclusive expiry **03:30 UTC**; nonce `issue-1700-recovery-20260930-v6`. The 75-minute reserve applies after
the final permitted entry. The host permits at most 25 minutes for tail
observation and installs Cron once. It renews short-lived tails only when the
provider reports at least four minutes of remaining TTL, connects the next
`trace-v1` tail and confirms control PING/PONG before switching, and limits the
run to eight owned tails under the same absolute deadline. Tail create/open
each have a 20-second bound and replacement PONG has a 10-second bound within
the 60-second renewal lead. One tracked renewal task is awaited before final
cleanup enumerates owned IDs, preventing a late tail create from leaking. It
deletes the old tail after the replacement is live, then deletes the active tail
on every exit.
Each owned tail has an ID-bound DELETE receipt with HTTP status and UTC
millisecond time; any failed delete leaves the result inconclusive. A stale
pong from an older socket cannot satisfy the active socket's heartbeat.

The release-specific Durable Object atomically persists one admission before
the v4 catalog read or either exact historical retirement begins. Its release, nonce, and original
scheduled timestamp are immutable. The first admission must occur by 02:15 UTC;
that same admission may finish retirement and the Container/Rust proof before
03:30 UTC if work crosses the cutoff. Later or foreign admissions cannot claim
the Container again.

After the latest-entry cutoff, a Cron invocation can only read the immutable
existing receipt. An already queued event before the cutoff may still make the
single first claim after host-side schedule cleanup. If the host fails early,
the run is inconclusive; reconciliation must inspect the exact admission,
receipt, schedule, tail, and historical retirement state. The nonce is never
replayed, and this source adds no private host-to-DO close channel.
