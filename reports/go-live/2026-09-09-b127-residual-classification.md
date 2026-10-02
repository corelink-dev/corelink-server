# B-127 residual classification — production, redacted

Read-only production D1 queries on 2026-09-09 classified four unexplained
tenant identifiers as stable aliases (`orphan_1` … `orphan_4`) and classified
the reserved `_public` namespace separately. No raw tenant, request, digest,
subject, or payload value was retained in this report.
The reproducible redacted query is `scripts/b127_residual_classification.sql`.
It excludes `_public` from orphan numbering and emits that reserved namespace
separately as `reserved_public` / `reserved_namespace` when rows exist.

> **2026-10-02 note.** The query's erased condition was narrowed from "any
> `dsr_erasure_log` entry" to a completed D1 erasure (`backend = 'd1' AND
> outcome = 'erased'`), the same condition as `scripts/verify_audit_residency.py`
> (#1669). A read-only aggregate production read on 2026-10-02 found the counts
> below unchanged. All 170 erased tenants (3,526 rows) have a `d1`/`erased`
> entry, and the four aliases (13 rows) have no erasure-log entry at all. The
> numbers in this report remain the 2026-09-09 measurement.

## Population

The raw full census was 84,932 audit rows. The earlier tenant-only partition
reported 81,262 satisfied, zero violated, and 3,670 unevaluable across 175
identifiers because it incorrectly treated `_public` as a missing tenant.

The corrected namespace-aware reconciliation is exact:

- **84,932 = 84,801 customer-scoped + 131 reserved `_public`**;
- customer-scoped: **84,801 = 81,262 satisfied + 0 violated + 3,539 unevaluable**;
- customer unevaluable: **3,539 = 3,526 DSR-erased / 170 tenants + 13 unexplained / 4 tenants**;
- the former 144/5 residual is fully reconciled as **144 = 131 reserved `_public` + 13 unexplained tenant rows**.

All 131 `_public` rows are in its required `wnam` region and are classified as
`reserved_namespace`, not as satisfied, violated, or unevaluable customer data.

| Alias | Class | Audit rows | Audit evidence and UTC window | Remaining operational rows |
| --- | --- | ---: | --- | --- |
| `orphan_1` | `unexplained_tenant` | **4** | 3 `corelink.dsr.access` plus 1 rejected pilot token, 2026-08-18 through 2026-08-27 | none in the sampled tenant lifecycle/data tables; one retained chain head |
| `orphan_2` | `unexplained_tenant` | **1** | 1 pilot reservation on 2026-08-23 | none in the sampled tenant lifecycle/data tables; one retained chain head |
| `orphan_3` | `unexplained_tenant` | **4** | one WEUR write/read pair on 2026-08-18 | LHR storage row (19 bytes) and one daily usage row (1 read, 1 write, 1 hit); one retained chain head |
| `orphan_4` | `unexplained_tenant` | **4** | one APAC write/read pair on 2026-08-18 | NRT storage row (56 bytes) and one daily usage row (1 read, 1 write, 1 hit); one retained chain head |
| `reserved_public` | `reserved_namespace` | **131** | 130 CAS audit events plus 1 `public.revoke`, 2026-07-19 through 2026-08-20; all `wnam` | five `tenant_storage_state` rows created 2026-06-21; IAD reports 244,377,715 bytes, four peer rows report zero; one retained chain head |

The regional event shapes, exact one-write/one-read usage, LHR/NRT state, small
byte counts, and absence of billing, identity, entitlement, DSR, or live tenant
rows make the probe classification high confidence. The repository also
contained a proven causal mechanism for the signup residues:
`scripts/e2e-clerk-signup.sh` directly deleted tenant state after producing
retained audit events, while its Clerk cleanup separately triggered the real
asynchronous DSR path.

## Causal repair

Migration `0122_b127_tenant_delete_residency_guard.sql` rejects deletion of a
tenant which has audit evidence unless a durable `dsr_requested` legitimacy
anchor already exists. Together with migration 0107, this closes both orderings:

1. unknown/deleted tenant followed by audit insert — rejected by 0107;
2. audit insert followed by direct tenant delete — rejected by 0122.

The signup E2E no longer deletes D1 rows itself. It deletes the Clerk test user
and fails unless the `user.deleted` webhook persists the DSR anchor, leaving the
normal audited pipeline responsible for asynchronous erasure.

## Historical remediation posture

No production mutation was executed. There is no existing idempotent runbook
that previews these exact four aliases, proves their original tenant identity,
deletes every non-retained backend residue, and establishes an unequivocal
post-condition. Deleting the 13 retained tenant audit rows or the 131 reserved
`_public` rows is explicitly forbidden.
The residual therefore remains visible and failing in the denominator; the
classification explains it without laundering it into DSR evidence.
