---
type: "TenancyControl"
title: "Storage-quota / byte-accounting header"
description: "The Worker-trusted storage-cap header and the atomic byte-accounting that makes the per-tier storage quota live, plus the RFC 9331 over-quota response taxonomy."
source_files:
  - "crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs"
  - "crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs"
  - "crates/corelink-rate-headers/src/headers.rs"
  - "crates/corelink-container/src/byte_accounting.rs"
source_blobs:
  - "crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs@c0c4fa248f7be243efe0ea0d44016a56311c30af"
  - "crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs@bd65dfc70297a7fea8ef25cb614c6404feac220e"
  - "crates/corelink-rate-headers/src/headers.rs@fd8664f17eeb5f7128f09c8280ccc0766aa1b02c"
checkpoint_sha: "a65c7d7caed03adf00acd3a227dc20c4e857f7f0"
provenance: "AUTHORED"
tags: ["tenancy", "quota", "storage", "byte-accounting", "rfc-9331", "fail-closed"]
timestamp: "2026-06-29T00:00:00Z"

---
# Storage-quota / byte-accounting header

The `tenant_storage_state` row carries the authoritative `bytes_used` counter the eviction worker and the
storage-quota policy read — but on the container data plane NOTHING incremented it: a successful CAS/AC/
Turbo write committed bytes to R2 and returned success without touching `bytes_used`, so the storage cap
was structurally inert (a Free tenant could store unbounded TB at `$0`). This control closes that gap.
The Worker — the quota-resolution authority — sets a server-trusted header carrying the tenant's resolved
per-tier storage cap, and after a successful write the billable handler does an ATOMIC check-and-accrue
against `tenant_storage_state`. Over-cap or unaccountable writes fail CLOSED; the public over-quota
boundary is surfaced to clients through the RFC 9331 response-header taxonomy.

# Role

This is the bytes axis of the tenancy abuse triad, alongside the
[$-ceiling](/tenancy/dollar-ceiling.md) (dollar axis) and the
[request-quota](/tenancy/request-quota.md) (count axis). The header is the seam between the Worker's
quota resolution and the container's enforcement; the accountant is the enforcement; the rate-headers
crate is the customer-facing signal that an over-plan boundary (not a bug) caused the rejection.

# How it works

- `STORAGE_QUOTA_HEADER` (`x-corelink-storage-quota-bytes`) is set SOLELY by the Worker and stripped from
  any client-supplied value, exactly like `x-corelink-tenant-id`
  (`crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs:212-215`).
- `storage_quota_from_headers` parses it fail-CLOSED: absent/empty/non-ASCII/non-`i64`/negative → `None`
  (indeterminate), `"0"` means genuine-unlimited
  (`crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:28-37`).
- After a successful write the handler calls an atomic DB-side check-and-accrue
  (`bytes_used = bytes_used + n` gated by the cap in ONE statement), so concurrent over-cap writes cannot
  both read the same baseline and pass — the executed INSERT…ON CONFLICT…RETURNING statement is at
  `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:274-299`, whose serialized cap predicate
  (`WHERE ?5 = 0 OR tenant_storage_state.bytes_used + ?3 <= ?5`) is at
  `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:282-289`.
- `AccrueOutcome::OverCap` means the caller must reject the write (bytes NOT counted) and `Indeterminate`
  means a missing row with no resolved cap — never seed an uncapped row from absence
  (`crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:39-57`).
- The size reserved is the **committed** (stored) size, not the raw request length: for a BYOK-`active`
  tenant the R2 object is the ciphertext blob, and `byok_committed_len` is now mode-aware — Mode A
  (convergent) reserves `plaintext + CLB1` (32 B: 4-byte magic + 12-byte nonce + 16-byte AEAD tag), Mode B
  (random) reserves `plaintext + CLB2` (20 B: 4-byte magic + 16-byte tag, the Mode-B nonce living in the
  `byok_envelope` D1 row, not inline) — so the decorator reserves THAT size and the delete path releases
  the same (`reserve == release`, so `bytes_used` cannot drift once encryption engages). A non-BYOK /
  inactive tenant reserves the plaintext length, byte-identical to before; a config-read error fails
  CLOSED. The sizing decision is `byok_committed_len`
  (`crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:530-561`).
- The over-quota rejection carries the `over_quota` arm of the RFC 9331 `X-Rate-Limit-Type` taxonomy
  (storage/bandwidth 100% boundary) (`crates/corelink-rate-headers/src/headers.rs:30-37`).
- `counts_against_sli` classifies `over_quota` as legitimate over-plan (NOT counted against the SLO),
  distinct from a within-quota bug (`crates/corelink-rate-headers/src/headers.rs:101-105`).

# Invariants

- The cap header is server-trusted only — set by the Worker and stripped from client input
  (`crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs:212-214`).
- A fresh tenant with an indeterminate cap is NEVER seeded uncapped; absence fails CLOSED rather than
  defaulting to unlimited (`crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:47-56`).
- The cap check is serialized with the increment in one SQL statement, so two concurrent over-cap writes
  cannot both pass (`crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:282-289`).
- `over_quota` 429s are excluded from the SLO denominator as legitimate over-plan traffic
  (`crates/corelink-rate-headers/src/headers.rs:101-105`).

# Gotchas

- When the row's `bytes_quota` is `0` (not yet synced from `tenant_quota` by the DO) the write is
  uncapped, but the counter STILL moves — so the cap becomes live the instant the DO populates the quota,
  with no lost history (`crates/corelink-container/src/byte_accounting.rs:39-41`).
- Deletes call the inverse `release`, a SATURATING decrement clamped at `0` by a DB `CHECK` and a `MAX(0,
  …)` in SQL, so reclaimed bytes free headroom without ever underflowing
  (`crates/corelink-container/src/byte_accounting.rs:50-55`).
- The accountant is `None` (accounting simply not enforced) when the storage env is unset, mirroring the
  other D1 adapters' dev/CI gate (`crates/corelink-container/src/byte_accounting.rs:57-64`).

# Citations

1. `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:274-299` — the executed atomic check-and-accrue SQL (DB-side add via INSERT…ON CONFLICT…RETURNING).
2. `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:282-289` — the cap check serialized with the increment (the `WHERE` predicate in the one statement).
3. `crates/corelink-container/src/byte_accounting.rs:39-41` — uncapped `bytes_quota = 0` still moves the counter.
4. `crates/corelink-container/src/byte_accounting.rs:50-55` — `release` saturating decrement on delete.
5. `crates/corelink-container/src/byte_accounting.rs:57-64` — `None` accountant when the storage env is unset.
6. `crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs:212-214` — `STORAGE_QUOTA_HEADER` is server-trusted, stripped from client input.
7. `crates/corelink-container/src/byte_accounting/b126_m2_impl_02.rs:212-215` — the header name + value semantics.
8. `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:28-37` — fail-CLOSED header parse (`None` indeterminate, `"0"` unlimited).
9. `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:39-57` — `AccrueOutcome` (`OverCap` / `Indeterminate` fail-closed).
10. `crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs:47-56` — a fresh row is never seeded uncapped from absence.
11. `crates/corelink-rate-headers/src/headers.rs:30-37` — the `over_quota` arm of the `X-Rate-Limit-Type` taxonomy.
12. `crates/corelink-rate-headers/src/headers.rs:101-105` — `counts_against_sli` excludes `over_quota` from the SLO.
