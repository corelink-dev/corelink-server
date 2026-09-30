# Issue 1700 runtime recovery

Run 36649066490 lost its host result after the probe subprocess timed out. Historical
query run 36653980457 returned 16 events but no attributable native receipt. Execution
and cleanup remain unknown; do not replay that candidate's nonce or use
`complete_existing` to retry it. `verify_existing` remains read-only.

One protected `deploy` on reviewed main builds both runtimes with nonce
`issue-1700-recovery-20260930-v3`. The shared
`crates/corelink-container/src/routes/staging_d1_probe_window.json` allows only
**2026-09-30 00:00 through 12:00 UTC**, exclusive at the end. The nonce plus the
new merged `SENTRY_RELEASE` selects a fresh dedicated DO. Host receipt freshness
remains bounded to the current invocation and its 16-minute deadline.

Before entering the fresh DO, the Worker retires only the named old probe DO for
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
