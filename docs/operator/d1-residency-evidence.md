---
title: "B-086 D1 residency and contract decision packet"
status: "OPEN_EXTERNAL_DECISION"
issue: 1654
backlog_id: "B-086"
credentialless: true
network_calls: false
mutating_actions: false
---

# B-086 — D1 residency and contract decision packet

This is a source review and decision packet. It is not legal advice, an
executed amendment, provider evidence, or a production change. It records
what the repository can prove and the owner/counsel decision that remains.

## Decision status

**OPEN — counsel sign-off required.** The selected prelaunch architecture keeps
one shared D1 database. The corrected source text scopes tenant pinning to R2
and Durable Object state, and discloses the D1 control plane as global.

The remaining closure artifact is counsel approval of the applicable transfer
basis, safeguards, and effective customer-facing terms. No draft, source
verifier, or this packet converts `PENDING LEGAL REVIEW` into an executed
obligation.

## Measured repository topology

| Production environment | Binding | Database name | `database_id` | Jurisdiction key |
|---|---|---|---|---|
| `prod` | `CONFIG_DB` | `corelink-config-prod` | `d64742ea-e102-40b2-a844-ff02e3f94562` | absent |
| `prod-sam` | `CONFIG_DB` | `corelink-config-prod` | same | absent |
| `prod-lhr` | `CONFIG_DB` | `corelink-config-prod` | same | absent |
| `prod-nrt` | `CONFIG_DB` | `corelink-config-prod` | same | absent |
| `prod-syd` | `CONFIG_DB` | `corelink-config-prod` | same | absent |

These are the active bindings at `wrangler.toml:546-550`, `745-749`,
`922-926`, `1093-1097`, and `1260-1264`. The only active `jurisdiction =
"eu"` keys are R2 bucket bindings under `prod-lhr` (`wrangler.toml:841-860`);
they do not apply to `CONFIG_DB`. The repository therefore proves five
bindings and one D1 identity. It does not prove the physical location of the
D1 primary or its replicas.

The shared D1 is material to the decision. The schema contains tenant and
control-plane records, including `tenant`, PAT and membership records, billing
and quota state, and audit outbox state. See the D1 migrations under
`migrations/d1/` (for example `0023_residency_check_constraints.sql` and the
tables enumerated by the DSR D1 adapter). A region label on a row is an
application routing value; it is not proof that the D1 row is physically or
legally resident in that region.

## Tenant selection and routing

The deployed edge path takes the tenant from authenticated state, not from a
client-supplied residency field:

1. `worker/src/index_auth_stage.ts` resolves `auth.tenantId` into
   `resolvedTenantId`.
2. `worker/src/index_routing_stage.ts:50-92` resolves that tenant's
   `tenant.primary_region` through `CONFIG_DB`, with L1 isolate and L2 KV
   caching, then stamps the trusted `x-corelink-primary-region` header.
3. `worker/src/index_routing_stage.ts:104-134` fans out non-IAD tenants to
   the matching regional Service Binding; an absent binding or unknown region
   returns `503 RESIDENCY_UNAVAILABLE`.
4. `crates/corelink-container/src/routes/residency.rs:63-110` rejects a
   trusted region/container mismatch with `409 residency_violation` before
   handler storage I/O.

This protects the R2/data-plane route when a valid tenant row and binding are
available. A missing tenant row or null `primary_region` is deliberately
treated as the existing IAD-local fall-through in
`worker/src/lib/tenant_residency_cache.ts:266-271`; that behavior must not be
advertised as a tenant residency guarantee without a separate product/legal
decision.

## Migration promise versus deployed path

The DPA says the tenant's `primary_region` may change only through
customer-initiated migration with 30 days' advance notice
(`legal/dpa-residency-amendment.md:122-145`). The repository has supporting
schema and pure logic:

- `migrations/d1/0028_tenant_primary_region.sql:48-59` rejects direct changes
  after insert and requires a canonical region;
- `migrations/d1/0023_residency_check_constraints.sql:89-105` creates
  `region_migration_request` with status and a 30-day application-layer
  cooldown;
- `crates/corelink-privacy/src/residency/migration.rs:63-92` models the
  request and cooldown.

The migration crate is not a deployed production dependency, and its request
path is a doc-comment/pure in-memory surface rather than a production D1
workflow. Therefore the repository proves **immutable pinning and write
guards**, but does not prove that a customer can complete the promised
customer-initiated migration. Counsel/product must either (a) block or amend
that promise until the production workflow exists, or (b) authorize a
separate implementation and its review.

## Failover behavior and residency boundary

The DPA permits WEUR read-replica failover only within WEUR and APAC read
failover only where provisioned (`legal/dpa-residency-amendment.md:136-148`).
The live container middleware behaves as follows:

- writes in a degraded region are rejected with `503 failover_readonly`
  (`crates/corelink-container/src/routes/failover.rs:660-677`);
- reads continue through the local handler and receive
  `x-corelink-failover-read-region` and `x-corelink-failover-active` hints
  (`crates/corelink-container/src/routes/failover.rs:679-691`);
- no Worker or JavaScript consumer of `x-corelink-failover-read-region` is
  present in this repository. The hint therefore does not establish that a
  read was routed to a replica. The current behavior is local-read plus an
  unconsumed hint, while the intended transparent reroute remains a separate
  design claim.

This distinction matters for the contract: a WEUR tenant cannot be promised
that the current failover path performs an actual read replica transfer. If a
future edge consumer is added, its cross-jurisdiction policy and approval gate
must be reviewed before deployment; this packet does not authorize one.

## Failure and downgrade behavior

The current source behavior is:

| Condition | Current result | Contract significance |
|---|---|---|
| D1 lookup fails with no cached region | `503 RESIDENCY_UNAVAILABLE` | fail-closed for an unknown placement |
| D1 lookup fails with a cached region | cached route is used | bounded stale routing; container backstop can return `409` |
| regional Service Binding missing | `503 RESIDENCY_UNAVAILABLE` | no silent IAD fallback for a known non-IAD region |
| direct request lands on wrong regional container | `409 residency_violation` | no handler storage I/O |
| degraded region write | `503 failover_readonly` | write availability is sacrificed |
| degraded region read | local read plus unconsumed failover hint | no evidence of transparent replica routing |
| tenant has no row or no region | IAD-local fall-through | not sufficient evidence for a tenant residency promise |

These outcomes are operational behavior, not legal approval. A commercial
downgrade or outage policy must state whether a tenant receives an error,
local service, or a legally reviewed transfer path.

## Reconciled source surfaces and remaining authority

- The DPA, TIA, sub-processor commitments, data-handling copies, and sales
  templates distinguish tenant-pinned R2/DO state from the shared global D1
  control plane. The DPA and TIA remain `PENDING LEGAL REVIEW`.
- `legal/sub-processors.md:14,173` already uses the same R2/DO versus global
  D1 distinction under SCC/TIA safeguards.

The source posture is aligned. No source file can approve a transfer basis,
select an effective date, or become an executed instrument.

## Required closure evidence

Provide counsel's approval of the applicable transfer basis, safeguards and
effective customer-facing terms for the shared global D1 control plane. It must
cover the affected data categories, migration limitations, failover-read and
outage/downgrade behavior, and effective date.

The existing `evidence/i1654/d1-residency-contract-manifest.json` and
`scripts/verify_b086_d1_residency.py` are credentialless source checks. They
confirm the aligned source posture; they do not supply counsel approval or an
executed instrument.
