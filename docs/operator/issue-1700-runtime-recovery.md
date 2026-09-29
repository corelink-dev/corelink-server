# Issue 1700 runtime recovery

The previous deployment cannot complete its probe: its compiled window expired.
A new protected `deploy` on reviewed main is required. `verify_existing` stays read-only.

The shared `crates/corelink-container/src/routes/staging_d1_probe_window.json` is compiled into
both runtimes and read by the host. The authorized UTC window is **2026-09-29 22:00 through
2026-09-30 12:00**, exclusive at the end. Nonce `issue-1700-recovery-20260929` plus the exact
new `SENTRY_RELEASE` selects a fresh dedicated Durable Object. Old nonce, old release,
pre-window and expired receipts fail. The host additionally requires a receipt from its
current invocation, within its 16-minute deadline. No clock override is supported.

Deployment refuses to start unless 60 minutes remain before expiry. The job budget is
60 minutes to accommodate a cold Container build, three-minute bounded image convergence,
16-minute proof, and cleanup/rollback. Only the exact captured preimage may be retried during
readback; any unexpected app, digest or version is drift and stops progress.

The probe writes only its dedicated `corelink_staging_d1_probe_<release>_<time>` table in the
fixed staging database. It checks a parameterized read, forces and verifies a batch rollback,
and drops its table before issuing a successful receipt. Ordinary HTTP forwarding rejects
the internal endpoint. There is no customer-table operation.

The host removes only its exact temporary cron, verifies the schedule is empty, and deletes
its tail on success or failure. Schedule drift is left untouched and reported as failure.
Both runtimes reject calls at the hard expiry even if a job is interrupted before cleanup.
The dedicated Container is destroyed and its alarm deleted after the attempt. Provider
rollback requires unchanged Worker marker/version, exact Container state, and a fresh empty
canonical-route inventory; unrelated drift stops rollback for operator inspection.

Protected dispatch and issue closure belong to the lead after the focused pack and independent
review pass. This code correction does not itself prove D1 provider execution or close #1700.
