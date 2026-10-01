# B-216 staging durable-receiver operation

This runbook is the finite staging-only continuation for B-216. It does not authorize production work, PagerDuty, arbitrary queue targets, zone or custom-host route publication, or retrying an ambiguous message push. The protected Cloudflare staging environment is the only signup-worker target. Alert binding remains disabled by default.

## Protected alert binding and authority

The B-216 pair is bound only to `corelink-signup-staging` by the existing protected `update-existing-secrets` operation when `enable_b216_dsr_alert` is explicitly true and the confirmation is exactly `update-existing-secrets-staging-1700-b216-alert`. The normal mode and normal confirmation leave alert binding disabled. This does not alter `.github/workflows/signup-worker-deploy.yml`, production defaults, or the staging topology’s required-secret set.

Before provisioning or opting in, obtain a successful `readback_only` artifact from `.github/workflows/b216-receiver-deploy-nonprod.yml` on the exact same protected `main` SHA as the staging update. Its redacted receipt must identify account `51284495e71acdb5a7677e7383ab026b` and Worker `corelink-dsr-b216-alert-receiver-20260927`, show the Worker exists, show workers.dev and previews disabled, and contain a known custom-route pattern hash matching the configured host. The artifact must be no more than 30 minutes old when the protected update runs. The readback receipt contains hashes, not raw custom route patterns or endpoint values.

The protected `staging` environment stores `STAGING_DSR_DLQ_ALERT_ENDPOINT_HOST` as the owner-approved lowercase custom hostname, `STAGING_DSR_DLQ_ALERT_ENDPOINT` as exactly `https://<host>/`, and `STAGING_DSR_DLQ_ALERT_AUTH_TOKEN` as a dedicated receiver bearer. The host must already route to that fixed receiver; this operation never creates or enables a route. The endpoint and bearer values stay out of workflow inputs, artifacts, repository files, and logs. The synthetic exercise’s temporary workers.dev URL must never be bound: that exercise disables workers.dev during cleanup.

Record the owner’s response-path acknowledgement as a comment on issue #1678 and use that comment URL as the acknowledgement reference. The comment must include these exact fields: `B-216 staging response-path acknowledgement`, `Source SHA: <main SHA>`, `Receiver account: 51284495e71acdb5a7677e7383ab026b`, `Receiver worker: corelink-dsr-b216-alert-receiver-20260927`, `Readback receipt SHA-256: <receipt SHA-256>`, `Authorized endpoint host: <host>`, and `Acknowledged response path: <internal response path>`. The workflow confirms that the comment is from a repository owner and matches the exact SHA, host, and receipt.

Dispatch the protected staging update with B-216 enabled, the successful receiver readback run ID, the receipt SHA-256, and the owner acknowledgement comment URL. Do not supply endpoint or token values as inputs. The workflow verifies the readback run came from the exact successful fixed-receiver `readback_only` workflow on the same SHA; then checks the artifact digest, fixed account/Worker, disabled workers.dev, fresh timestamp, exact host route hash, and owner acknowledgement before making any Cloudflare provider request. Missing, stale, mismatched, or incomplete evidence stops before provider traffic. A receiver with no existing reachable custom route cannot be enabled by this workflow; leave alert binding disabled until an owner-approved reachable path is independently established.

The worker-side secret names are `DSR_DLQ_ALERT_ENDPOINT` and `DSR_DLQ_ALERT_AUTH_TOKEN`. A normal existing-secret update tolerates an already-present complete pair by name only; it neither reads nor overwrites their values. A partial pair is an error. An explicit repeat B-216 opt-in is idempotent and also never overwrites existing values.

The staging deployment environment names `STAGING_CF_WORKER_API_TOKEN` and `STAGING_CF_ROUTE_READ_TOKEN` are for Worker deployment and route readback. Neither credential is authorized for the D1 migration operation. Do not substitute `STAGING_CF_API_TOKEN`, `CF_API_TOKEN`, or a #1700 token. The D1 operation uses the `corelink-dsr-nonprod` Wrangler OAuth profile only after root verifies identity and D1-write scope for staging account `6a1fc1c626fc2628823e60b9db01f5cd`; activate it for the bounded command and deactivate it in `finally`. The operator pins that account and D1 UUID in a temporary config, verifies the OAuth account readback, rejects Cloudflare API-token environment variables, and reads the preimage before invoking Wrangler. The receiver has its own independently provisioned `B216_CF_RECEIVER_WRITE_TOKEN` in `b216-receiver-nonprod` and its own alert bearer in that environment.

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

Before deploying, render only the canonical `signup` staging config (`workers_dev=false`, with no route), read back its exact D1 and DLQ bindings, and verify that the receiver endpoint and bearer secret names are bound to `corelink-signup-staging` only when the preceding explicit opt-in and authority checks passed. Deploy that config on the exact merged `main` SHA, then read back the active version, queue consumer binding, D1 ID, and no-route/no-workers.dev settings. Record the immutable Worker version and deployment time in `b216-deployed-signup-worker.json`.

For the bounded exercise, verify the fixed main and DLQ queue names/IDs against staging topology and read back zero DLQ backlog immediately before the operation. Push exactly one synthetic `DsrQueuedV1` body directly to the fixed staging DLQ queue with `_dlq_requeue: 1`; use a fresh synthetic UUID/salt and never write those fields to output. This marker deliberately selects the consumer's bounded terminal branch, avoiding a main-queue redrive or erasure side effect. The Cloudflare push is a single request: on timeout or ambiguous response, do not retry; reconcile by the opaque event ID first.

Verify all of the following against the same opaque event ID before disposition:

- Signup D1 `dsr_dlq_delivery_receipts` is `terminal`, has `paging_claimed=1`, and `requeue_claimed=0`; the redrive audit/envelope shows no requeue claim.
- The receiver's D1 `dsr_alert_receipts` contains the exact accepted event contract. Signup's bounded alert response is recorded as HTTP 202.
- The receiver workflow's synthetic receipt has completed its fixed workers.dev disable/readback cleanup. Keep its D1 receipt as audit evidence.
- The stakeholder on-call acknowledges the durable alert in the designated internal response path and records the opaque event reference. The operator records the terminal hold/no-redrive disposition and the acknowledgment reference; no raw DSR, tenant, subject, salt, queue body, token, or provider response is attached.

Write `b216-alert-delivery.json` and `b216-exhausted-observation.md` only from these readbacks and acknowledgments. A terminal marker=1 DLQ observation proves the bounded terminal outcome; do not describe it as an automatic source-queue exhaustion. If any readback, alert acknowledgment, or cleanup is ambiguous, preserve the evidence, do not retry the push, and keep B-216 open for reconciliation.
