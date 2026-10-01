# Scoped staging readiness and credential lifecycle

The protected `issue-1700-staging-readiness.yml` operator verifies the existing
`GET /v1/users/me` route on `https://staging.corelink.humangr.com`. It runs on
GitHub-hosted `ubuntu-24.04` and retains status codes, booleans and release/run
attribution. It does not mint, rotate, revoke or publish anything. The existing
B152 `i1675-live-probe.yml` exercises a different chaos-client contract and is
not a readiness gate.

## Admission and evidence custody

Before a dispatch, the issue owner must bind the accepted native Container/D1
receipt, its mandatory previous-namespace cleanup, the current Worker version
and deployment IDs, and the exact Custom Domain/DNS/TLS publication receipt.
Record the provider account, all three isolated Workers and their resources,
the deployed release, source SHA, run IDs and protected staging review. A green
source test, anonymous `/health`, or a phase marker does not satisfy this gate.

`K6_TARGET_IDENTITY_RECEIPT` retains the existing seven-field staging identity
contract (`schema`, `environment`, `target`, `tenant_id`, `deployment_sha`,
`issued_at`, `expires_at`). Store it only in the protected `staging` environment
after its fields have been checked against those actual provider receipts and
the synthetic tenant's custody. The HTTP response does not expose a release;
the output explicitly attributes `deployment_release` to this protected owner
receipt. `expected_sha` identifies the operator source and `expected_release`
identifies the deployed Worker; they need not be equal.

Bind `K6_TARGET_HOST` to the exact canonical origin and `K6_STAGING_PAT` to one
ephemeral read-only PAT for that synthetic staging tenant. Retain its issuance
authority, exact private PAT ID, scope, expiry and owner in restricted custody;
never place the credential or tenant in a workflow input, artifact, log or PR.
The existing load scenario bindings remain separately required for their lanes;
readiness does not claim that MFA, Stripe, BYOK or synthetic teardown works.

The whole owner obtains an exact finite provider/custody charter before any
secret binding, credential issuance, replacement or revocation. Names-only
inventory precedes an absence claim. A forbidden organization-secret inventory
does not prove that no organization binding exists.

## Bounded verification

Dispatch from protected main with the exact operator SHA, accepted deployment
release and `confirm=verify-scoped-staging-1700`. The protected environment must
retain required independent reviewers and prevent self-review. Provider modes
share the existing staging lock; credentialless PR tests have separate queues.

Every mode first checks that missing and deliberately invalid credentials are
rejected. `readiness` then requires the current PAT to return HTTP 200 with the
exact identity response and the privately expected tenant. `rotation` requires
the replacement PAT to succeed and the separately bound
`K6_STAGING_PREVIOUS_PAT` to fail. `teardown` requires the current PAT and, when
bound, the previous PAT to fail. Every request is GET to the same fixed path,
without redirects or retries, bounded to ten seconds and 4096 response bytes.
No Container admin-health credential, CAS/AC request, or raw response is used.

These are observations, not standalone issuance, rotation or revocation proof.
Pair them with the exact mutation receipts and prove each observed credential
was still inside its original lifetime. Expiry alone must not be reported as
successful revocation. A rejected current credential is not a readiness PASS.

## Ephemeral replacement and teardown

The existing `/internal/v1/auth/rotate` endpoint creates a fresh 90-day PAT and
is unsuitable for this ephemeral operation. The existing runner-mint broker
accepts only `cas:rw` and `read-write`, with a positive TTL capped at 90 minutes;
it rejects a `read-only` request. A GET-only readiness operation does not make
that mint authority read-only. The broker requires its dedicated
`CORELINK_RUNNER_MINT_AUTH_KEY`, a server-derived tenant, repository allowlist and
entitlement. `CORELINK_RUNNER_PROVISION_AUTH_KEY` is a different authority. An
installation mapping or a valid acquiring PAT is required; the caller cannot
invent the tenant in the mint body. Consequently this broker alone cannot
satisfy this read-only PAT custody contract. Establish an existing issuer route
that actually grants read-only scope and the required finite lifetime, and
verify its staging authority before issuance; do not substitute an admin key. A production
dogfood token and the production-default admin mint script are not staging
custody.

The approved custody charter must enumerate at most two ephemeral credentials,
their common exact synthetic tenant and read-only scope, absolute expiry,
mint/revoke call counts, secret writes and failure cleanup. Prove original
acceptance, issue and accept the replacement, then revoke the original through
the existing tenant-qualified runner-revoke route. Retain the original only as
the protected previous credential for the bounded rejection check. Finally
revoke the replacement, verify both rejections before expiry, and remove only
the temporary secret bindings owned by this operation after names-only
readback. If any issuance response or exact ID is unavailable, stop mutations
and preserve restricted custody for reconciliation. Do not revoke a preexisting
or unrelated credential.

This credential cleanup does not delete synthetic scenario data or prove the
separate exact-run teardown endpoint owned by issue 2161. Keep the topology
unprovisioned and the issue open until all resource isolation, credential,
readiness, rotation and required teardown receipts are accepted.
