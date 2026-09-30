# B-072 owner packet — protected one-shot code and external delivery remain outstanding

Status: open. The repository now contains the fail-closed receiver Worker and
the dormant default/dev `SCHEDULED_DRILL_DELIVERY` service binding. The root
Worker has no active synthetic cron. The receiver stores
the trigger before any external delivery. Configured PagerDuty mode records
delivery only after PagerDuty accepts the canonical dedup key and accepts
signed acknowledgement/escalation webhooks only after that durable receipt.
Explicit `provider_deferred` mode requires no PagerDuty credentials and records
a terminal D1 receipt bound to the scheduled execution, the configured
`SENTRY_RELEASE` scheduler revision/source SHA, receiver
version metadata, and receiver result. It makes no claim about
alert delivery or human reachability. Repository contracts still do not prove
that the receiver was deployed or that a live D1 row exists.

Before changing B-072 to `done`, the owner must:

1. Deploy the committed receiver Worker in the same Cloudflare account and
   verify the committed `SCHEDULED_DRILL_DELIVERY` binding for the non-production
   environment that will own any explicitly reactivated Worker trigger. There
   is no active trigger at this commit; receiver deployment alone is not trigger
   evidence. The receiver validates the
   fixed synthetic scheduler contract and deduplicates the
   `x-corelink-scheduled-drill-id`. For synthetic
   week 3, it must honor `delivery_mode=deferred` and schedule `emit_at_ms` for the
   following Sunday at exactly 23:59:00 UTC; it must not page immediately at
   the Monday cron time.
2. Keep PagerDuty deferred under the current owner decision. If an owner later
   restores configured PagerDuty delivery, use the dedicated `synthetic-drill`
   service key and exact signed webhook callback; both secrets stay outside
   this Worker source and its payload/logs.
3. After an owner-approved non-production trigger is explicitly reactivated,
   prove one provider-deferred path end to end: trigger log → receiver request
   → correlated D1 `synthetic_page_provider_receipts` row and
   `provider_deferred` audit event. Bind the row to scheduled execution,
   scheduler revision, serving SHA, receiver revision, and receiver result.
   Do not claim alert delivery or human acknowledgement; do not commit secrets
   or customer data.
4. Re-run the B-072 focused Vitest, static verifier, and an adversarial retry
   test where the receiver returns 5xx after accepting the dedup key. Only then
   update the backlog status and `last-verified` evidence.

The current scheduler intentionally reports a non-2xx/exception as failure and
does not call `noRetry()` for those cases, preserving Cloudflare retry behavior.
Unknown cron values call `noRetry()` and fail, so a configuration drift cannot
create an unbounded external page loop.

## Issue #1652 one-shot code boundary

The repository's B-072 `* * * * *` handler is an independent, staging-only
path. It requires the frozen staging account and D1 IDs, a 40-hex serving SHA,
provider mode `provider_deferred`, an immutable issue-1652 authorization row,
an operator-created activation after schedule readback, and a successful
singleton SQL claim before it can issue its single receiver service-binding
POST. Both wall-clock time and `scheduledTime` must be inside the recorded
finite UTC window. Unknown cron, invalid state, duplicate claims, D1 failures,
and ambiguous receiver results call staging `noRetry()` and never reset the
claim. The weekly Monday cron and development retry behavior are unchanged.

The minute envelope is accepted only by the staging receiver in
`provider_deferred` mode. That path has no PagerDuty call. The receiver records
an independent durable ingress counter, then correlated receipt/audit rows;
the protected operator requires exact equality across those records. The
counter distinguishes one accepted receiver ingress from the root's unique
claim row. A terminal response alone is not completion.

## Protected operator and future gates

`.github/workflows/issue-1652-b072-evidence.yml` runs the PR evidence pack on
the exact PR head with no provider or staging credentials. Its separate
workflow-dispatch operator accepts only current protected `main` in the
existing GitHub `staging` environment and verifies the actual independent
environment approval for that run. It also requires the exact successful
machine-readable #1700 runtime completion artifact, three separately scoped
credentials (`B072_STAGING_CF_WORKERS_TOKEN`,
`B072_STAGING_D1_WRITE_TOKEN`, and
`B072_STAGING_CF_ROUTE_READ_TOKEN`), and the fixed account/database IDs.
Missing environment protection, approval evidence, #1700 PASS, or scoped
secret fails closed with the named setup requirement; there is no fallback to
generic Cloudflare secrets. The ordinary receiver deployment entrypoint is
retired and has no token or deployment command.

There is deliberately no B-072 `prepare_root` deployment operation. The
eventual root Worker/Container installation uses the existing centrally
controlled #1700 protected deploy operation after B-072 code is merged. That
deploy must leave the Worker route-free, preserve the approved Container
image/bindings, and read back root schedules as `[]`. B-072 preflight then
requires the exact active root version and `SENTRY_RELEASE` to equal the
current protected-main SHA; stale or mismatched root state is a setup failure,
not an instruction to deploy from this operator.

The execute run records an allowlisted/redacted preimage, migration checksum,
approval reviewer identity, exact schedule PUT/readback, terminal receipt,
ingress count, and cleanup readbacks. It applies and verifies migration 0153
only on the fixed staging D1 before authorization. Receiver version upload is
inactive until its unique version ID and resources (including the run-ID marker) are read back; authorization
pins that version, then the receiver is activated/read back, then the root
minute schedule is armed/read back, and only then is durable activation
inserted. The immutable authorization records its issue time; the activation
row records the actual schedule-arm time, and SQL requires the window to begin
at least 20 minutes after that observed arm. Approval evidence records only reviewer login/ID,
environment and run ID, with the local time at which the approval was verified;
the GitHub approval endpoint supplies no approval ID or approval timestamp. Worker bindings and provider responses are not copied
raw into artifacts. Recovery reads the original run artifact and durable nonce, never
re-arms or replays a trigger.

Cleanup always attempts an immutable revocation before schedule disarm and
restores the exact previously disabled receiver version. If revocation write
or readback fails while authorization remains live and claim is empty, the
operator is unsuccessful even if it disarms and rolls back. It records that at
most one `provider_deferred` service-binding POST could still occur until
revocation or window expiry; the singleton claim forbids a second POST, and
there are zero PagerDuty/provider dispatches. Cleanup is complete only after
durable revocation or expiry plus independent schedule/version/route/D1
readbacks. Do not call the issue terminal, merge, deploy, activate a live
trigger, or close it from this code packet. Provider execution and closure
remain separate central gates.
