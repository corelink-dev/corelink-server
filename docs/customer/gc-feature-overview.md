# How CoreLink Reclaims Storage Safely

> **Sprint:** S-06 · **Lane:** HIGH_RISK · **Date:** 2026-05-02
> **Status:** SCAFFOLD — finalisation at S-19 onboarding SEAL

This document explains how CoreLink reclaims storage that is no longer
referenced — without ever risking the loss of a reachable blob.

## TL;DR

CoreLink runs a **mark-and-sweep** garbage collector with a **72h
reversible grace window**. We are the only remote-cache vendor in the
industry that ships **TLA+ formal verification** of the load-bearing
correctness invariants. If a bug ever lets us miss a reachable blob,
the formal verification gate goes red and we stop reclaiming until
the bug is fixed. If a bug ever lets us delete a reachable blob, the
72h grace window gives us 3 days to undelete via re-upload.

## How it works

CoreLink's GC runs in **four phases** per (tenant, region) per daily
cron tick:

1. **Mark phase** — scan `blob_meta`, `ac_meta.outputs`, and
   `manifest_chunks` to compute the union of reachable digests. Any
   digest NOT in this union is a candidate for sweep.
2. **Sweep phase** — for each candidate, re-check whether any
   `ac_meta` entry references the digest with `created_at >=
   mark_started_at` (the canonical TLA `protect-if-equal-or-newer`
   predicate). If yes, mark the candidate `ProtectedReRef` and do
   NOT delete. Otherwise soft-delete `blob_meta.deleted_at = now()`
   and emit `corelink.gc.sweep.soft_deleted` audit event with the
   forensic `prev_state` snapshot.
3. **Physical-delete phase** — for each candidate whose
   `deleted_at < now() - grace_period` (strict `>` boundary), delete
   the R2 object first, then purge the D1 row. Audit
   `corelink.gc.physical_deleted`. Idempotent (R2 404 = success).
4. **Reconcile phase** — daily cross-check that `blob_meta.refcount`
   matches `count(ac_meta where blob_refs CONTAINS digest AND
   deleted_at IS NULL)` via the `json_each` JSON-aware membership
   idiom (NOT a string-substring match). Auto-fix small drifts
   (count ≤ 5 AND percent ≤ 0.01%); larger drifts paused for manual
   SRE review.

## What "reachable" means

A blob is **reachable** in CoreLink if any of these hold:

- `blob_meta.refcount > 0` (some manifest or ActionCache entry
  references it).
- `ac_meta.outputs` contains the digest (the blob is the output of a
  cached action).
- `manifest_chunks` contains the digest (the blob is a chunk of a
  multipart-uploaded blob).

The mark phase computes the union of all three; the sweep phase
re-checks the second condition with the canonical TLA semantic to
catch races where an `ac_meta` row arrives during the mark window.

## Why we are safe

### TLA+ formal verification

CoreLink ships `gc_correctness.tla` — a TLA+ specification that
formally verifies two load-bearing invariants:

- **`InvGCReachableNeverDeleted`** — no reachable blob is ever
  deleted, regardless of mark + sweep + UpdateActionResult
  interleaving.
- **`InvGCReRefProtected`** — any blob re-referenced via
  `UpdateActionResult` during the mark window is protected from
  deletion (the canonical `protect-if-equal-or-newer` predicate at
  L152-154 of the spec).

The TLA+ model checker (TLC v1.8.0, SHA-256 supply-chain pinned per
ADR-0042 §A1) runs on every PR that touches GC code, the data model,
or the invariant registry. A red gate blocks merge.

### Property test cross-validation (100k iter)

The TLA+ verification is then **cross-validated** against the real
Rust implementation via a 100k-iteration property test that runs
nightly. The test exercises the boundary case `ac.created_at_ms ∈
{mark_started_at_ms - 1, mark_started_at_ms, mark_started_at_ms + 1}`
exhaustively per iteration; ZERO violations sustained over 100k iter
is the canonical sprint contract DoD gate.

### 72h grace window

If any bug ever slips through both gates, the soft-delete grace
window (72h CAS / 24h AC) gives us 3 days to recover. Customers can
re-upload the same digest (idempotent CAS write) OR an admin can
trigger the undelete endpoint (S-13 forward).

### Reconcile auto-fix

Refcount reconciliation runs daily and auto-corrects small drifts
(count ≤ 5 AND percent ≤ 0.01%). Larger drifts trigger an
`SEV-1`/`SEV-2` alert and pause auto-fix until an SRE has reviewed
the audit chain.

## What customers see

**Roadmap / not yet wired:** the customer-visible metric
`corelink_gc_reclaimed_bytes_total{tenant_id, tier}` (aggregated as
`bytes_reclaimed_last_30d` per tier) has no emitter in the codebase today
— it exists only as a query referenced by Grafana dashboards
(`dashboards/grafana/DASH-GC.json`, `dashboards/alerts/dash-gc-alerts.yml`,
`infra/grafana/dashboards/dash-capacity-planning.json`), not as a metric
any Rust code actually records. Until an emitter ships, this section
describes the target customer-dashboard experience (S-16 forward), not a
live capability.

We do NOT delete:

- audit log rows (retention is subject to an approved policy; no production
  R2 Object Lock or storage-enforced seven-year guarantee is claimed);
- DSR erasure trail (cross-referenced for regulatory compliance);
- any blob during a degrade-mode `gc-pause` window (admin-triggered
  emergency stop).

## Failure modes

CoreLink ships three runbooks for the GC failure modes:

- **[RB-FM-300](../../specs/05_quality/runbooks/RB-FM-300-gc-refcount-bug.md)** —
  GC deletes a reachable blob (CRITICAL; SEV-1; recover ≤ 1h via
  72h grace undelete). Detection ≤ 5 min via reconcile alerts.
- **[RB-FM-404](../../specs/05_quality/runbooks/RB-FM-404-gc-write-race.md)** —
  GC sweep conflicts with a concurrent write (CRITICAL; SEV-1).
  Detection ≤ 1 min via 100k race property test alert.
- **[RB-FM-305](../../specs/05_quality/runbooks/RB-FM-305-tombstone-lost.md)** —
  Cron not re-armed; GC stalled; storage growth detected via
  SLO-FRESH-GC sustained metric (≤ 5 min target).

All three runbooks have been **dry-run executed** at WI-S06-007 SEAL
(host-side harness; staging dry-run forward).

## Compliance

- **LGPD Art. 16** retention compliance via grace period 72h CAS /
  24h AC enforced.
- **GDPR Art. 17** erasure compliance via DSR bypass (S-11 forward).
- **SOC 2 Type II** alignment — full audit chain emission per
  CTRL-OBS-001 alignment.
- **ISO 27001** A.10.7 (information transfer) + A.18.1.4 (privacy
  protection) — addressed via INV-AUDIT-NO-RAW-PII enforcement.

## References

- [SLA addendum](./gc-sla-addendum-s06-ga.md)
- [Release notes S-06](./release-notes-s06.md)
- [PRR-S06 promotion decision](../../specs/04_sprints/_sealed/S06/PRR-S06.md)

## Change log

| Version | Date | Change |
|---|---|---|
| 1.0.0-scaffold | 2026-05-02 | Initial scaffold for WI-S06-007 SEAL; finalisation at S-19 onboarding SEAL. |

---

**End feature overview scaffold.**
