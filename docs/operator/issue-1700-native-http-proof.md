# Native Container/D1 proof through authenticated HTTP

Issue #1700's native acceptance requires the real staging Container to use the
bound D1 database, execute a parameterized read, observe a deliberately failed
batch, prove rollback absence, and drop its owned probe table. Cron and Tail
delivery remain separately **UNPROVEN**. HTTP delivery does not establish either.

The existing `/_internal/staging/d1-binding-runtime-probe` literal is intercepted
by the staging Worker before generic internal authentication. It requires the
existing dedicated `CORELINK_ADMIN_AUTH_KEY` through `x-corelink-internal-auth`;
the shared internal key is never a fallback. Non-staging returns 404. The DO's
HTTP forwarding path still returns 404. Only a numeric admission tag reaches
the coordinator RPC; HTTP authentication never enters the native Container.

The POST body has exactly `worker_release`, `probe_nonce`, and
`scheduled_time_ms`, at most 512 bytes. The timestamp is the current two-minute
bucket and the nonce is `issue-1700-recovery-20261002-v16`. Its source admission
window is 2026-10-02T21:06:00Z through 23:06:00Z inclusive; completion expires at
2026-10-03T00:21:00Z exclusively. The deployment guard permits dispatch only from
21:06:00Z inclusive through 21:26:00Z exclusive, retaining its 75-minute cleanup
reserve. The cleanup-only authorization uses 2026-10-02T21:06:00Z–2026-10-03T00:21:00Z; the old v8/v9 invocation
windows and namespaces are unchanged. Retired v10 is never replayed. The v11
window (2026-10-01T20:00:00Z–23:15:00Z) expired unused: the protected deploy
workflow was never dispatched inside it, and its nonce is never reused. The v12
window (2026-10-02T15:00:00Z–18:15:00Z) was superseded by v13 before it opened
and was never dispatched; its nonce `issue-1700-recovery-20261002-v12` is never
reused. The v13 window (2026-10-02T07:00:00Z–10:15:00Z) was dispatched once
(run 36976287686) and failed closed at the first bootstrap write, before any
candidate deploy; an independent readback showed no provider change. Its nonce
`issue-1700-recovery-20261002-v13` is never reused. The v14 window
(2026-10-02T10:00:00Z–13:15:00Z) passed unused: the protected deploy workflow
was never dispatched inside it, and its nonce `issue-1700-recovery-20261002-v14`
is never reused. The v15 window (2026-10-02T18:00:00Z–21:15:00Z) was dispatched
once (run 37044496198) and failed closed at the bootstrap's script-level secret
PUT: Cloudflare answered 400 with code 10215 because the newest uploaded Worker
version was not the deployed one. An independent readback showed no change, and
its nonce `issue-1700-recovery-20261002-v15` is never reused. These source
bounds do not independently authorize a runtime dispatch. A GET
of the same path on the canonical domain reads persisted status without admission or cleanup. Query
parameters, Authorization/Cookie headers, and other methods are rejected.
The temporary workers.dev origin admits only that authenticated POST and a GET
of the same exact literal for persisted status. Its other paths, methods and
preview/alias origins return 404. The normal
canonical-domain routing pipeline remains unchanged.

The exact release DO persists a separate operation claim before any cleanup.
It retires the immutable v8 namespace (`7d18bcfc450db97b1b987923050b92971da530a8`)
and v9 namespace (`5da497051f0b11dbfc8b87d1dfa8e753304e2719`) before fresh native
admission. Their original admission, execution-state and receipt keys stay
intact; prior execution remains unknown. Every cleanup rechecks the stopped
Container, absent alarm and exact owned catalog. The v9 table timestamp must
lie within the actual 12:35:18Z–13:00:22Z invocation. An extra catalog object,
unowned row, missing admission with a table, incoming or outgoing foreign key,
or 129th catalog table prevents deletion. Each v8/v9 cleanup uses at most five
statements and one DROP.

The response carries nine fixed fields: `contract`, `carrier`,
`worker_release`, `probe_nonce`, `status`, `rollback_safe`, `native_receipt`,
`v8_cleanup`, and `v9_cleanup`. The carrier is `authenticated_http`. A complete
response requires the unchanged strict twenty-field native receipt and two
separate ten-field cleanup receipts. `scheduled_time_ms` and the native `cron`
tag remain admission protocol fields; neither is evidence of a scheduled event.

Execution has one cumulative deadline of 600 seconds. Quiescence and cleanup have a
separate cumulative deadline of 600 seconds. A client timeout does not cancel a
submitted provider operation. Failed or unresolved execution persists
`unknown`, prohibits a new admission, and prevents automatic preimage rollback.
Late resolution never resumes the execution pipeline. A lost HTTP response
remains unknown unless at most three authenticated status GETs recover the
complete receipt within the original lease; the POST is never retried.
Only a validated complete response with `rollback_safe=true` can
authorize rollback after an HTTP execution attempt, together with the existing
empty schedules/tails and exact preimage guards.

The authorized metadata-only read on 2026-10-01 identified
`https://corelink-staging.gmhelmold.workers.dev`, with `enabled=false` and
`previews_enabled=false`. The Worker secret-name list was empty; this did not
inspect values or non-secret variables. A future runtime therefore needs a
separate finite authorization for dedicated credential custody and temporary
reachability, preserving exact preimages and mandatory restoration. No public
Custom Domain, route, secret provisioning, HTTP execution, or runtime lease is
authorized by this document or credentialless CI. A second names/types-only
read checked all 35 bindings and confirmed the admin name absent at every type.

The source bootstrap uses a private runner process to generate an ephemeral 32-byte
admin key in memory. A Unix socket carries fixed commands and sanitized receipts;
the key is never a process argument, artifact, log, environment export or IPC
response. The bootstrap makes no script-level secret write. Cloudflare refuses
script-level secret edits (code 10215) whenever the newest uploaded version is not
the deployed one, and every exact-preimage rollback leaves exactly that state. The
exact deployed preimage *version* must prove the admin name absent at every type;
an existing or ambiguous binding stops the operation. The broker then writes the
key once to an exclusive, no-follow, owner-only file in its private directory. The
deploy step passes that file to `wrangler deploy --secrets-file`, so the key rides
only the candidate version, and removes it however the step ends. The broker also
removes it at bind. The candidate version must carry the key as `secret_text` and
no other secret, compared by name and type. An upload inherits secret *values* from
the newest upload, which after every rollback is not the preimage, so values cannot
be proven to be the preimage's. A preimage that carries any other secret is
therefore refused before the key file is written.

A bind that fails after its candidate tuple parsed becomes `bind_failed`. That state
is fenced: admission is closed and no probe is ever admitted. The positive
never-executed fact survives the failure. Cleanup then re-proves the exact
candidate. If workers.dev is enabled, it disables it, but only when this broker
attempted the enable, and it reads back that it is disabled. After that the
workflow may restore the exact preimage. A bind interrupted by close, expiry or
an unparseable tuple stays `unknown`.
Temporary workers.dev activation follows verified candidate identity and preserves
the disabled preview setting. Only proven quiescence, or a positively fenced
never-executed broker state, permits restoration of its owned bootstrap changes.
An absent attempt file alone is not evidence that execution never started.

A probe refused for insufficient remaining broker time remains a failed workflow
step. Before cleanup, the rollback gate obtains fresh status through the actual
private IPC command. It accepts this narrow `never_execute` case only when the
broker has closed admission, has never seen a probe execution command, and still
owns the exact operation, release, candidate, image and preimages inside its
original 45-minute expiry. The observation must be no more than five seconds old;
unknown, expired, mismatched or stale state is rejected. An existing HTTP attempt
ledger also rejects this case. The second rollback gate reads fresh broker status
again and requires completed cleanup with `cleanup_basis=never_execute`; the
broker stays alive until that check. This exception never manufactures native
proof or changes the failed probe outcome.

After all provider cleanup and rollback branches, an `always()` step performs
local broker shutdown and verifies that the owned process has exited. It runs
after unknown status and cleanup failures too. The helper binds PID, owner,
launch time and exact command before any fallback signal; its shutdown receipt
does not claim provider cleanup. The workflow cannot report success without this
verified exit. These fresh status and shutdown operations are local only. The
broker makes at most 15 management API calls (3 prepare, 5 bind, 2 probe, 5
cleanup); a failed bind skips the probe. Each restore adds two read-only readbacks.

Worker versions are immutable, and an upload inherits the newest upload's secrets.
Rollback uploads can therefore leave an undeployed version that still names the
admin key. Settings can follow that newest upload, so no check reads them; checks
read the exact deployed version.
See the official [Cloudflare secrets lifecycle](https://developers.cloudflare.com/workers/configuration/secrets/).

This finite native proof always restores the exact Worker and Container
preimages after accepted proof and owned bootstrap cleanup. Cleanup verifies the
exact candidate and disables workers.dev. Restoring the exact preimage version
then removes the key from the deployed path. A read-only `verify_restored` readback
proves that version is active at 100%, carries no admin key and left no key file.
The rollback upload inherits the candidate's key. So once quiescence and broker
cleanup have succeeded, an `EXIT` trap attempts the exact Worker preimage restore
and its readback however the later Container waits, digest checks or the second
quiescence gate end. The step keeps its failure outcome, and the Worker and
Container preimages are verified separately. The retained native proof
describes that execution; it is not a claim that the candidate remains active.

Native proof is only one part of #1700. Canonical Custom Domain publication,
scoped `GET /v1/users/me` readiness and its negative controls, synthetic tenant
custody, rotation and teardown still require their own actual receipts before
the issue can close.


The private HTTP operation stores its immutable start, execution deadline and
outer kill deadline before any old-object cleanup or fresh native admission.
Execution ends at start +600 seconds; the outer lifetime ends at start +1200
seconds, capped by the compiled expiry. Startup must read back the dedicated
alarm and lifetime record. Health, status reads and DO eviction cannot renew it.

The native process receives three computed, nonsecret timestamps only through
private startup. The loopback D1 interceptor receives the same typed context
through service-binding props. HTTP headers and Worker vars carry no deadline
authority. Both native and proxy reject new D1 dispatch after the execution
deadline, including a cleanup DROP after a delayed query or batch. Already
submitted D1 can still settle remotely; expiry is not cancellation.

A dedicated stop-only alarm can request one SIGKILL after the outer deadline.
Its durable attempt marker does not prove that the Container stopped, and it
cannot start work, clean D1, replay native execution or make rollback safe. An
independent PID1 GNU timeout supervisor in the same runtime image also applies
the original outer deadline if the broker or DO disappears. The ordinary
Container entrypoint is unchanged. A failed or uncertain stop remains UNKNOWN.

The hosted image oracle checks actual GNU timeout process-tree termination and
private-launcher/PID1 wiring. These software controls do not establish an
unconditional Cloudflare billing ceiling: VM scheduling and provider deallocation
latency are outside their proof. Old/preexisting instances remain separate from
the fresh instance bound. A new provider charter is required; no source test or
merge renews the compiled window, authorizes a new nonce or accepts live staging.
