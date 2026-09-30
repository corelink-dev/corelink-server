# B-216 staging durable-receiver operation

This runbook is the finite staging-only continuation for B-216. It does not authorize production work, PagerDuty, arbitrary queue targets, zone or custom-host route publication, or retrying an ambiguous message push. The protected Cloudflare staging environment is the only signup-worker target.

## Required protected names

The staging deployment environment names `STAGING_CF_WORKER_API_TOKEN` and `STAGING_CF_ROUTE_READ_TOKEN` are for Worker deployment and route readback. Neither credential is authorized for the D1 migration operation. Do not substitute `STAGING_CF_API_TOKEN`, `CF_API_TOKEN`, or a #1700 token. The D1 operation uses the already authenticated local Wrangler OAuth profile only after root verifies that profile’s identity and D1-write scope for staging account `6a1fc1c626fc2628823e60b9db01f5cd`. The operator pins that account and D1 UUID in a temporary config, verifies the OAuth account readback, rejects Cloudflare API-token environment variables, and reads the preimage before invoking Wrangler. The receiver has its own independently provisioned `B216_CF_RECEIVER_BOOTSTRAP_TOKEN` in `b216-receiver-bootstrap` and its own alert bearer in `b216-receiver-nonprod`.

After the receiver's `exercise_once` artifact reports the exact workers.dev URL and accepted durable receipt, put that exact URL in the protected staging secret `STAGING_DSR_DLQ_ALERT_ENDPOINT`. Bind the matching receiver bearer as `STAGING_DSR_DLQ_ALERT_AUTH_TOKEN`. The Worker-side names are `DSR_DLQ_ALERT_ENDPOINT` and `DSR_DLQ_ALERT_AUTH_TOKEN`. Keep both values out of workflow inputs, artifacts, repository files, and logs. If the bearer cannot be provisioned independently in the two protected environments, stop before signup-worker deployment.

## Fixed staging schema operation

After the reviewed source patch is merged and the existing credentialless B-216 contract workflow passes on the exact `main` SHA, root runs the local OAuth-only operator from that exact checkout:

```sh
env -u CLOUDFLARE_API_TOKEN -u CF_API_TOKEN \
  -u CLOUDFLARE_API_KEY -u CLOUDFLARE_EMAIL -u CF_API_EMAIL \
  -u STAGING_CF_WORKER_API_TOKEN -u STAGING_CF_API_TOKEN \
  -u STAGING_CF_ROUTE_READ_TOKEN \
  python3 -B scripts/apply_staging_b216_dsr_schema.py
```

The operator invokes the official `npx --yes wrangler@4.145.0` CLI through the verified OAuth profile. Its temporary config pins account `6a1fc1c626fc2628823e60b9db01f5cd`, database `corelink-config-staging`, UUID `d72a6b39-6a48-4338-bfda-1111dda98604`, and `CONFIG_DB`; only the exact reviewed 0138 and 0145 SQL files are copied there. It reads the migration ledger and relevant tables first, and stops if their state disagrees. Review Wrangler’s displayed migration names before accepting its prompt. It then applies the isolated two-file set and runs the read-only schema verifier against the same temporary config. Preserve the command output, OAuth account readback, preimage names, and post-readback. Do not run the general D1 migration fleet or use a shared Worker token for D1.

## Signup-worker and one-message exercise

Before deploying, render only the canonical `signup` staging config (`workers_dev=false`, with no route), read back its exact D1 and DLQ bindings, and verify that the receiver URL and bearer secret names are bound to `corelink-signup-staging`. Deploy that config on the exact merged `main` SHA, then read back the active version, queue consumer binding, D1 ID, and no-route/no-workers.dev settings. Record the immutable Worker version and deployment time in `b216-deployed-signup-worker.json`.

For the bounded exercise, verify the fixed main and DLQ queue names/IDs against staging topology and read back zero DLQ backlog immediately before the operation. Push exactly one synthetic `DsrQueuedV1` body directly to the fixed staging DLQ queue with `_dlq_requeue: 1`; use a fresh synthetic UUID/salt and never write those fields to output. This marker deliberately selects the consumer's bounded terminal branch, avoiding a main-queue redrive or erasure side effect. The Cloudflare push is a single request: on timeout or ambiguous response, do not retry; reconcile by the opaque event ID first.

Verify all of the following against the same opaque event ID before disposition:

- Signup D1 `dsr_dlq_delivery_receipts` is `terminal`, has `paging_claimed=1`, and `requeue_claimed=0`; the redrive audit/envelope shows no requeue claim.
- The receiver's D1 `dsr_alert_receipts` contains the exact accepted event contract. Signup's bounded alert response is recorded as HTTP 202.
- The receiver workflow's synthetic receipt has completed its fixed workers.dev disable/readback cleanup. Keep its D1 receipt as audit evidence.
- The stakeholder on-call acknowledges the durable alert in the designated internal response path and records the opaque event reference. The operator records the terminal hold/no-redrive disposition and the acknowledgment reference; no raw DSR, tenant, subject, salt, queue body, token, or provider response is attached.

Write `b216-alert-delivery.json` and `b216-exhausted-observation.md` only from these readbacks and acknowledgments. A terminal marker=1 DLQ observation proves the bounded terminal outcome; do not describe it as an automatic source-queue exhaustion. If any readback, alert acknowledgment, or cleanup is ambiguous, preserve the evidence, do not retry the push, and keep B-216 open for reconciliation.
