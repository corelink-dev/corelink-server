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
for staging operations. The intended readiness, load and endurance fleet is
GitHub-hosted `ubuntu-24.04`, matching their existing workflow jobs. The topology
and target verifier enforce that fixed label for every job in those workflows.
This reconciles the obsolete `corelink` label; it does not claim that a
self-hosted readiness probe ran. The target is
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
quarantine readback. The root Worker is the application origin, so publication
uses the exact `staging.corelink.humangr.com` Custom Domain, not a Worker Route.
The separately reviewed
`.github/workflows/issue-1700-staging-custom-domain.yml` previews provider
inventory, confirms runtime secret binding names, and publishes only that Custom
Domain after the protected staging environment is released. Cloudflare creates
the DNS record and certificate for a Custom Domain; the workflow does not invent
an origin record or wildcard route.

Cloudflare recommends Custom Domains when the Worker is the application origin;
routes instead sit in front of an existing proxied origin. The workflow reads
the exact Worker-domain, DNS, zone, account, `workers.dev`, and full zone-route
inventories first, and rejects malformed or conflicting state. Repeating a
publish against the exact existing Worker/domain/DNS binding is an idempotent
readback. If a domain created in that same run fails DNS/TLS `/health`, the
workflow detaches only the returned domain ID after verifying its exact target,
then verifies the hostname is clear. Cloudflare can retain the automatically
issued certificate after detach; the receipt carries its certificate ID for
owner custody and the workflow never deletes certificates.
Authenticated readiness remains a separate protected `i1675-live-probe.yml`
dispatch. Publish requires the exact runtime secret names already bound to the
root and signup Workers, plus all protected `K6_*` readiness inputs.
The root Worker config also pins `enable_request_signal` and
`request_signal_passthrough` alongside `nodejs_compat`; the publisher reads back
that exact flag set before attaching the Custom Domain.

Provider semantics: [Workers Routes](https://developers.cloudflare.com/workers/configuration/routing/routes/),
[Workers Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/),
[Attach Worker Domain API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/),
[List Worker Domains API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/list/),
and [Detach Worker Domain API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/delete/).

Before dispatch, the `staging` environment must contain these bootstrap inputs
by name. Values stay in the protected environment and must never appear in git,
issue text, logs, or artifacts:

| Purpose | Required names |
| --- | --- |
| Cloudflare account and zone | `STAGING_CF_API_TOKEN`, `STAGING_CF_ACCOUNT_ID`, `STAGING_CF_WORKER_API_TOKEN`, `STAGING_CF_ROUTE_READ_TOKEN`, `CF_ZONE_ID` (environment variable) |
| R2 endpoint and access | `STAGING_R2_S3_ENDPOINT`, `STAGING_R2_S3_ACCESS_KEY_ID`, `STAGING_R2_S3_SECRET_ACCESS_KEY` |
| Clerk test tenant | `STAGING_CLERK_ISSUER_URL`, `STAGING_CLERK_SECRET_KEY`, `STAGING_CLERK_WEBHOOK_SECRET` |
| Synthetic operations | `STAGING_ERASURE_SALT_KEY`, `STAGING_DSR_DLQ_REDRIVE_AUTH_KEY` |
| Load and teardown | `K6_STAGING_BYOK_CMK_ID`, `K6_STAGING_MFA_STUB`, `K6_STAGING_PAT`, `K6_STAGING_STRIPE_WHSEC`, `K6_STAGING_TEARDOWN_TOKEN`, `K6_TARGET_IDENTITY_RECEIPT`, `K6_TARGET_HOST` |

The provider API token, per-Worker API token, and routes-read token must be distinct and scoped to this target. The root Worker's D1 client uses the existing `CONFIG_DB` binding through a host/path-pinned outbound proxy; no Cloudflare D1 API token is forwarded to the container. `K6_TARGET_HOST`
must resolve to the canonical origin. The bootstrap workflow checks every input
before mutation; it generates the internal Worker auth keys itself and reads
back secret names without exposing values. The staging environment must not
carry Terraform backend credentials; Terraform drift workflows use their own
repository-scoped backend inputs.

The workflow checks provider ownership and an empty canonical route set, deploys
the three named Workers without `workers.dev` or public routes, verifies their
staging bindings and secret names, and leaves the root Custom Domain unpublished.
Signup remains route-free and uses its service binding. This
route-free phase does not disable scheduled handlers: the signup Worker retains
its hourly trigger and the synthetic receiver retains its weekly trigger during
bootstrap. Review those handlers and their staging guards before dispatch; a
missing public domain does not prevent scheduled execution. A failed preflight,
incomplete binding readback, or unexpected route stops the run before domain
publication. Do not add a partial `[env.staging]` to `wrangler.toml`.

The separate `staging-provision-plan.yml` workflow is read-only. Its redacted
artifact is evidence of what that run could read; it does not authorize or
perform provisioning. Keep the exact dispatch SHA, workflow run URL, and
redacted postflight readback summary with the owner action record. Never treat
workflow configuration or a green PR check as provider readiness.

## Readiness, load, and teardown

The [native Container/D1 proof operator](../../docs/operator/issue-1700-native-http-proof.md)
uses the existing dedicated authenticated HTTP boundary. Its strict native
receipt and separate v8/v9 cleanup receipts do not establish Cron or Tail
delivery. Unresolved provider operations persist an unknown state and block
automatic rollback or replay. Source and credentialless CI do not authorize
the temporary endpoint or credential bootstrap.

After bootstrap, capture current provider identity and Custom Domain/DNS/TLS readback,
then run the bounded authenticated readiness probe through its protected
workflow on the declared GitHub-hosted `ubuntu-24.04` fleet. Configuration and
credentialless CI do not prove authenticated readiness: retain the actual
protected probe's runner, run ID and exact release alongside
`evidence/staging/readiness.json` with DNS/TLS, HTTP and
Worker/container health, migration head, deployment identity, binding
isolation, owner, timestamp, and run ID. Do not mark the topology provisioned
unless the exact Workers, Custom Domain, resources, and isolated bindings match
`topology.json`.

Use `issue-1700-staging-readiness.yml` and the
[scoped readiness operator](../../docs/operator/issue-1700-scoped-readiness.md)
for `GET /v1/users/me`, its missing/invalid PAT controls and credential lifecycle
observations. The B152 `i1675-live-probe.yml` chaos client is a separate contract.
Bind a privately checked synthetic tenant and deployed release through the
existing protected `K6_TARGET_IDENTITY_RECEIPT`; HTTP identity does not itself
prove a deployed release. Credential issuance, replacement and revocation
require their own finite custody charter and actual mutation receipts.

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
Workers absent and the canonical DNS/Custom Domain unavailable; a current provider
readback is required before acting on that older snapshot.

No provider mutation, secret write, live probe, load run, or readiness claim is
authorized by this runbook alone. Attach redacted, attributable owner/provider
receipts before changing the deployment state.
