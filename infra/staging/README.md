# Canonical staging provisioning boundary (#1700)

`topology.json` is the canonical desired state for the isolated non-production
target used by the load and endurance workflows. Keep `deployment_state` as
`unprovisioned` until provider readback, authenticated readiness, and the
run-scoped teardown dependency are evidenced. The base-resource receipt records
the D1, four R2 buckets, three KV namespaces, and queue/DLQ as empty or
unbound; it does not prove deployed Workers, DNS, routes, TLS, or readiness.

## Approval and operating limits

The SRE Lead owns provisioning. The SRE Lead and Security Lead approve the
boundary and any teardown. Use only the protected GitHub `staging` environment
for staging operations. The topology contract names `corelink` as the intended
readiness runner, while the current load and endurance workflows declare
`ubuntu-24.04`; reconcile that runner mismatch in a reviewed change before
claiming readiness from the intended fleet. The target is
`https://staging.corelink.humangr.com` in the `humangr.com` zone. Its limit is
USD 25 per load run, USD 50 per endurance run, and USD 250 per month, with a
24-hour lease, teardown after two idle hours, and 24-hour R2 object TTL. Data
must be synthetic and staging-only. Teardown is manual, fail-closed, and ordered
as load data, queues, Workers, bindings, then DNS.

## Protected quarantine apply

The only provider-write path before health is
`.github/workflows/staging-quarantine-apply.yml`. Its provider job requires a
manual dispatch of protected `main`, the exact confirmation
`quarantine-apply-staging-1700`, and release of the protected `staging`
environment by its required reviewers. Pull requests run credentialless
topology, renderer, and quarantine-only workflow checks. The workflow deploys
the three Workers with no `workers.dev`, DNS, custom-domain, or route
publication, binds only staging secret names, and captures a redacted
quarantine readback. Health and route publication require separately reviewed
workflows after this receipt.

Before dispatch, the `staging` environment must contain these bootstrap inputs
by name. Values stay in the protected environment and must never appear in git,
issue text, logs, or artifacts:

| Purpose | Required names |
| --- | --- |
| Cloudflare account and zone | `STAGING_CF_API_TOKEN`, `STAGING_CF_ACCOUNT_ID`, `STAGING_CF_WORKER_API_TOKEN`, `CF_ZONE_ID` (environment variable) |
| R2 endpoint and access | `STAGING_R2_S3_ENDPOINT`, `STAGING_R2_S3_ACCESS_KEY_ID`, `STAGING_R2_S3_SECRET_ACCESS_KEY` |
| Clerk test tenant | `STAGING_CLERK_ISSUER_URL`, `STAGING_CLERK_SECRET_KEY`, `STAGING_CLERK_WEBHOOK_SECRET` |
| Synthetic operations | `STAGING_ERASURE_SALT_KEY`, `STAGING_DSR_DLQ_REDRIVE_AUTH_KEY` |
| Load and teardown | `K6_STAGING_BYOK_CMK_ID`, `K6_STAGING_MFA_STUB`, `K6_STAGING_PAT`, `K6_STAGING_STRIPE_WHSEC`, `K6_STAGING_TEARDOWN_TOKEN`, `K6_TARGET_IDENTITY_RECEIPT`, `K6_TARGET_HOST` |

The two Cloudflare tokens must be distinct and scoped to this target. `K6_TARGET_HOST`
must resolve to the canonical origin. The bootstrap workflow checks every input
before mutation; it generates the internal Worker auth keys itself and reads
back secret names without exposing values. The staging environment must not
carry Terraform backend credentials; Terraform drift workflows use their own
repository-scoped backend inputs.

The workflow checks provider ownership and an empty canonical route set, deploys
the three named Workers without `workers.dev` or public routes, verifies their
staging bindings and secret names, and only then publishes the two exact
canonical routes. Signup remains route-free and uses its service binding. This
route-free phase does not disable scheduled handlers: the signup Worker retains
its hourly trigger and the synthetic receiver retains its weekly trigger during
bootstrap. Review those handlers and their staging guards before dispatch; a
missing public route does not prevent scheduled execution. A failed preflight,
incomplete binding readback, or unexpected route stops the run before route
publication. Do not add a partial `[env.staging]` to `wrangler.toml`.

The separate `staging-provision-plan.yml` workflow is read-only. Its redacted
artifact is evidence of what that run could read; it does not authorize or
perform provisioning. Keep the exact dispatch SHA, workflow run URL, and
redacted postflight readback summary with the owner action record. Never treat
workflow configuration or a green PR check as provider readiness.

## Readiness, load, and teardown

After bootstrap, capture current provider identity and route/DNS/TLS readback,
then run the bounded authenticated readiness probe through its protected
workflow. The current `i1675-live-probe.yml` runner is `ubuntu-24.04`; this does
not satisfy the topology's declared `corelink` runner until owners reconcile
that contract. Retain `evidence/staging/readiness.json` with DNS/TLS, HTTP and
Worker/container health, migration head, deployment identity, binding
isolation, owner, timestamp, and run ID. Do not mark the topology provisioned
unless the exact Workers, routes, resources, and isolated bindings match
`topology.json`.

Issue #2161 must provide the live authenticated, exact-run teardown endpoint
before either synthetic-data lane starts. A successful readiness receipt alone
does not satisfy that dependency. Once readiness and teardown proof pass, the
SRE Lead and Security Lead may approve one bounded five-scenario load run and a
separate two-hour endurance run. Retain each lane's exact-head, identity,
threshold, artifact-digest, lifecycle, and teardown receipts. Keep schedules
disabled until a separate cadence decision.

Rotation and teardown procedures must be exercised and recorded. Delete only
the exact staging run's synthetic data, and abort cleanup if inventory is
incomplete. Update `deployment_state` only in a reviewed change that includes
the complete current provider readback and accepted receipts.

## Readback snapshot (2026-09-25)

The protected `staging` environment readback permits `main` and requires the
SRE and Security reviewers with self-review prevented. Secret metadata shows
`K6_TARGET_HOST` and two legacy `TF_BACKEND_*` names; the other bootstrap
inputs above and `CF_ZONE_ID` are absent. Move the Terraform backend names out
of this environment before provisioning. The latest public DNS query returned
NXDOMAIN. The last provider resource receipt (2026-09-09) records all three
Workers absent and the canonical DNS/route unavailable; a current provider
readback is required before acting on that older snapshot.

No provider mutation, secret write, live probe, load run, or readiness claim is
authorized by this runbook alone. Attach redacted, attributable owner/provider
receipts before changing the deployment state.
