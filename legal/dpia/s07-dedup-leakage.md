---
id: "DPIA-S07-001"
type: "dpia"
doc_status: "DRAFT"
version: "1.0.0"
created: "2026-05-13"
updated: "2026-05-13"
feature: "S-07 Content-Addressable Storage Deduplication"
sprint: "S-07"
owner: "Gustavo Schneiter"
privacy_officer: "Gustavo Schneiter (interim)"
dpo: "TBD"
tags: ["dpia", "s07", "dedup", "cross-tenant-inference", "gdpr-art-35", "lgpd-art-38"]
evidence_event: "EVT-045"
evidence_retain: "7y"
evidence_path: "evidence-legal/dpia-s07-dedup-leakage.md"
---

# DPIA: S-07 Content-Addressable Storage (CAS) Deduplication — Cross-Tenant Inference Attack Risk

> **Superseded data-store assumption (B-316, 2026-10-02).** This draft was
> written when a Neon Postgres control plane was planned. Neon was never used
> by the product: account, billing and metadata state live in Stripe and the
> Cloudflare D1 control-plane database. Every Neon-specific statement below
> describes that abandoned design; none of its Neon measures are in place.
> The current sub-processors are listed in `legal/sub-processors.md`.

> **GDPR Art. 35 / LGPD Art. 38 (RIPD) Data Protection Impact Assessment**
> Template: `specs/_templates/dpia.md` v1.0.0 — WI-S11-008

---

## Metadata

| Field | Value |
|---|---|
| DPIA ID | DPIA-S07-001 |
| Feature / Sprint | S-07 CAS deduplication (content-addressable blob storage, per-tenant dedup default) |
| Data Controller | HuGR Labs Ltda (LGPD) / HuGR Labs Ltd (GDPR) |
| Encarregado / DPO | TBD (interim: Gustavo Schneiter) |
| Privacy Officer | Gustavo Schneiter (interim) |
| Processing basis | contract (GDPR Art. 6(1)(b) / LGPD Art. 7 V) — storage efficiency integral to service delivery |
| Date initiated | 2026-05-13 |
| Target review date | 2026-06-13 |
| Legal frameworks | GDPR Art. 35 + LGPD Art. 38 + WP29 WP248rev01 (2017) endorsed by EDPB + ANPD Res. CD/ANPD nº 4/2023 |
| EVT evidence path | `evidence-legal/dpia-s07-dedup-leakage.md` (R2 retain 7y per EVT-045) |

---

## Section 1 — Description of Processing

### 1.1 Processing purpose(s)

The CAS deduplication feature computes a BLAKE3 content hash of each uploaded blob and stores a single copy in R2 CAS, with a reference count table in D1 (`ac_meta`). The primary purpose is storage efficiency: identical blobs uploaded by different users or tenants are stored once, with shared references.

In the default configuration (per ADR-0019 + ADR-0020), deduplication is scoped **per-tenant**: blob equality is checked only within a single tenant's namespace. Cross-tenant deduplication is **disabled by default** to prevent cross-tenant inference attacks.

Purpose enum (privacy_model.md §5.6.1): `service_delivery`.

### 1.2 Data subjects affected

- **Registered users** of all tenants: any user whose uploaded data (files, build artifacts, container layers, ML model weights) is subject to deduplication.
- **Tenant administrators**: control tenant-level dedup policy.
- **Scale:** potentially millions of blobs across thousands of tenants. CoreLink targets enterprise SaaS builders; each tenant may have 1 – 1,000,000 users.
- **Geographic spread:** global (multi-region: wnam, enam, weur, sam, apac, afr).

### 1.3 Personal data categories processed

| Data category | Classification | Backend(s) | Notes |
|---|---|---|---|
| Content hash (BLAKE3) | Pseudonym (not directly identifying in isolation, but potentially identifying via rare-blob inference) | R2 CAS, D1 ac_meta | Ordinary data; hash leakage risk |
| Blob content (if PII embedded) | Ordinary / special-category depending on content | R2 CAS | User controls; CoreLink is processor |
| Access metadata (tenant_id, subject_id, blob_id) | Ordinary | D1 ac_meta, Neon | Links hash to subject |
| Upload timestamps | Ordinary | D1, Neon | Temporal correlation possible |

Special-category data: not processed directly by CAS layer; however tenants may embed special-category data in blobs (health records, biometrics in ML models). CoreLink acts as data processor; tenant is data controller for embedded content.

### 1.4 Data flows

1. User uploads blob → CF Worker → BLAKE3 hash computed in memory (corelink-hash crate).
2. Hash lookup in D1 `ac_meta` (within tenant namespace — per-tenant dedup default).
3. If not found: blob stored in R2 CAS (`r2_cas` backend).
4. If found (within same tenant): refcount incremented; blob not re-stored.
5. Cross-tenant dedup: **DISABLED by default** (per ADR-0019/ADR-0020 + INV-TENANT-ISOLATION).
6. No cross-border transfer at the CAS layer. R2 data stored in tenant's pinned region (WI-S11-007 residency pinning).

### 1.5 Retention periods

| Data category | Retention | Legal basis |
|---|---|---|
| Blob content | Until explicitly deleted by tenant/user; DSR erasure within 30d | LGPD Art. 16 III; GDPR Art. 17 |
| Content hash + refcount | Same as blob content | Co-terminous with blob |
| Access metadata (ac_meta) | Until tenant account deleted; DSR erasure within 30d | GDPR Art. 17; LGPD Art. 18 IV |
| Audit logs (Loki) | 7 years (legal hold) | LGPD Art. 16 I (cumprimento de obrigação legal) + Art. 37 (RoPA); GDPR Art. 5(2) accountability (Lote 10.11.0-ter legal-citation re-validation 2026-05-15 corrigida cite anterior "LGPD Art. 40" — Art. 40 trata de padrões ANPD para anonimização, não retenção de audit log) |

### 1.6 WP29 WP248rev01 high-risk criteria checklist

| Criterion | Met? | Justification |
|---|---|---|
| 1. Evaluation/scoring (profiling) | NO | Dedup is not profiling — no behavioral inference intended by system |
| 2. Automated decision-making with legal effect | NO | Storage efficiency only; no legal decisions |
| 3. Systematic monitoring | NO | Not monitoring data subjects; monitoring blob duplicates |
| 4. Sensitive data (special categories) | PARTIAL | Tenants may embed special-category data in blobs (CoreLink is processor) |
| 5. Large-scale processing | YES | Millions of blobs across thousands of tenants |
| 6. Matching or combining datasets | YES | Hash matching across uploads creates implicit cross-upload linkability |
| 7. Data on vulnerable subjects | NO | No targeting of vulnerable groups by CAS layer |
| 8. Innovative use or new technology | YES | BLAKE3 CAS with refcount-aware erasure is novel approach |
| 9. Data transfer outside EU/EEA or BR | NO | Regional pinning enforced; no inherent cross-border at CAS layer |

**Criteria count: 3–4/9 — DPIA mandatory** (large-scale + matching/combining + innovative technology; partial sensitive data as processor).

---

## Section 2 — Necessity and Proportionality Assessment

### 2.1 Legal basis

Processing basis: **contract** (GDPR Art. 6(1)(b) / LGPD Art. 7 V) — deduplication is integral to the service delivery promise (storage efficiency is a core feature). Additionally, **legitimate interest** of data controller for operational efficiency (GDPR Art. 6(1)(f) / LGPD Art. 10) as a secondary basis for the hash computation itself.

For tenants embedding PII in blobs: CoreLink is data processor (GDPR Art. 28); the tenant (data controller) is responsible for the legal basis of the underlying data.

### 2.2 Necessity test

Deduplication is necessary to deliver the cost-efficiency value proposition of CoreLink. Without it, storage costs would be 10–100x higher for workloads with duplicate build artifacts or container layers, making the service economically non-viable.

The per-tenant dedup design (ADR-0019) is the minimum-scope version: dedup benefits without cross-tenant linkability. Cross-tenant global dedup — the more privacy-invasive alternative — is explicitly disabled.

### 2.3 Proportionality assessment

- **Data minimization:** only the BLAKE3 hash is stored; blob content is not duplicated. The hash alone is not sufficient to reconstruct content (one-way function).
- **Storage limitation:** blobs retained only while reference count > 0; when all references deleted, blob is garbage-collected (S-06 GC worker, INV-GC-NO-ZOMBIE).
- **Purpose limitation:** hash only used for dedup refcounting; not used for profiling, behavioral analysis, or cross-subject inference.
- **Accuracy:** hash is deterministic; no accuracy concern.

### 2.4 Data protection by design measures

| Measure | Implementation | Reference |
|---|---|---|
| Per-tenant dedup isolation | Dedup lookup scoped to tenant namespace (tenant_id partition) | ADR-0019, ADR-0020 |
| INV-TENANT-ISOLATION enforcement | RLS + tenant_id predicates in all D1 + Neon queries | invariant_registry.md §3.X |
| BLAKE3 one-way hash | Content hash cannot reverse to blob content | corelink-hash crate |
| DSR erasure integration | Erasure worker (WI-S11-002) handles blob deletion with refcount-aware GC | privacy_model.md §6.2 |
| Regional data residency | R2 CAS data pinned to tenant.primary_region | WI-S11-007, ADR-0041 |
| Audit logging | All blob operations logged to Loki (EVT-022, EVT-048) | observability_model.md §7.2 |
| Encryption at rest | R2 AES-256 encryption at rest (Cloudflare-managed) | sub-processors.md |

### 2.5 Sub-processor obligations

| Sub-processor | Role | Location | DPA/SCC status |
|---|---|---|---|
| Cloudflare Inc. (R2, CF Workers) | Blob storage + compute | US (global CDN) | Cloudflare DPA + SCCs in place (Cloudflare Enterprise DPA 2024) |

Cross-border transfer analysis: Cloudflare R2 stores data in the tenant's pinned region. The control plane (CF Workers runtime) may route through US infrastructure. SCCs per CJEU C-311/18 (Schrems II) apply. TIA: Cloudflare has adopted Binding Corporate Rules (BCRs) for processor transfers; standard SCCs (Module 2 Controller-to-Processor) supplemented by Cloudflare's Privacy Shield successor commitments.

---

## Section 3 — Risk Identification

### 3.1 Risk register

| ID | Threat (LINDDUN) | Description | Likelihood | Severity | Risk Level | Mitigation |
|---|---|---|---|---|---|---|
| R-001 | Linkability (L) | **Cross-tenant inference attack**: if cross-tenant dedup were enabled, Tenant A could infer that Tenant B has uploaded a specific blob by uploading the same content and observing whether a dedup match occurs (timing side-channel or refcount response). | MEDIUM (if cross-tenant dedup enabled) | HIGH | HIGH | Cross-tenant dedup **DISABLED by default** (ADR-0019/ADR-0020). Per-tenant isolation: INV-TENANT-ISOLATION enforced via RLS. No cross-tenant blob lookup API exposed. |
| R-002 | Identifiability (I) | BLAKE3 hash of rare/unique content (e.g., a unique document) could be used to identify the document if hash is exposed in API responses. | LOW | MEDIUM | LOW | Hash not exposed in public API responses in meaningful form. ac_meta table protected by tenant_id RLS. No hash-to-subject mapping exposed. |
| R-003 | Disclosure (D) | Incomplete erasure: if blob is deleted but refcount not decremented, blob persists beyond DSR deadline, exposing PII past retention period. | LOW | CRITICAL | MEDIUM | Refcount-aware erasure worker (WI-S11-002) decrements refcount and triggers GC when count = 0. INV-DATA-ERASURE-COMPLETE (TLA+ proof in dsr_erasure_atomicity.tla). INV-GC-NO-ZOMBIE. |
| R-004 | Non-compliance (N) | Tenant embeds special-category data (GDPR Art. 9) in blobs without informing CoreLink. CoreLink processes without appropriate safeguards. | LOW | HIGH | MEDIUM | CoreLink DPA clauses require tenants to inform of special-category data. Tenant is data controller; CoreLink is processor. Onboarding TOS requires disclosure. |
| R-005 | Linkability (L) | Upload timestamp correlation: adversary correlates upload timestamps across tenants to infer common build pipeline or shared code. | LOW | LOW | LOW | Timestamps stored only in tenant-scoped Neon tables; not cross-tenant accessible. |

---

## Section 4 — Mitigation Measures

### 4.1 Technical mitigations

**R-001 (Cross-tenant inference — CRITICAL RISK, mitigated to LOW):**
- Per-tenant dedup is the enforced default (ADR-0019). Cross-tenant dedup requires explicit opt-in by both tenants with written consent + Privacy Officer sign-off.
- INV-TENANT-ISOLATION: all D1 and Neon queries include `tenant_id` predicate enforced at the ORM layer and verified by RLS policies.
- No cross-tenant blob hash comparison API exists or will be added without a new DPIA.

**R-003 (Incomplete erasure — CRITICAL severity):**
- WI-S11-002 erasure worker implements refcount-aware blob deletion: `r2_cas` backend decrements refcount; when count reaches 0, blob is physically deleted from R2.
- INV-DATA-ERASURE-COMPLETE (CRITICAL) formally proven via TLA+ `dsr_erasure_atomicity.tla` (WI-S11-008).
- 24h verification job confirms erasure completeness (EVT-042).
- PAT-RETRY-IDEMPOTENT-001 ensures erasure retries do not create inconsistencies.

**R-004 (Special-category data from tenants):**
- Tenant DPA (GDPR Art. 28 agreement) requires disclosure of special-category data processing.
- CoreLink DPA includes sub-processing obligations.

### 4.2 Organizational mitigations

- Privacy Officer review before enabling cross-tenant dedup (if ever requested).
- DPIA re-assessment required before any architectural change enabling cross-tenant dedup.
- DPIA CI hook (`scripts/validate_dpia.py`) triggers re-assessment if CAS dedup logic changes in PRs.

### 4.3 Contractual / legal mitigations

- Cloudflare DPA: Module 2 Controller-to-Processor SCCs for EU data subjects. TIA: Cloudflare BCRs as processor (EU-approved).
- Neon DPA: Module 2 SCCs; data stored in tenant.primary_region (EU tenants → weur bucket).

### 4.4 Residual risk after mitigation

| Risk ID | Residual Likelihood | Residual Severity | Residual Level | Accepted by |
|---|---|---|---|---|
| R-001 | LOW (cross-tenant dedup disabled) | HIGH (if enabled) | LOW | Privacy Officer (per-tenant default is non-negotiable gate) |
| R-002 | LOW | LOW | LOW | Privacy Officer |
| R-003 | LOW | CRITICAL | MEDIUM | Privacy Officer + Architect (TLA+ proof covers atomicity; verification job covers completeness) |
| R-004 | LOW | HIGH | LOW | Privacy Officer (DPA contractual safeguard) |
| R-005 | LOW | LOW | LOW | Privacy Officer |

---

## Section 5 — Residual Risk Assessment + Sign-off

### 5.1 Overall residual risk assessment

The primary risk (cross-tenant inference attack, R-001) is reduced to LOW through architectural isolation (per-tenant dedup default, INV-TENANT-ISOLATION). The incomplete erasure risk (R-003) is reduced to MEDIUM through the erasure worker + TLA+ proof + verification job; residual severity remains CRITICAL if the erasure pipeline fails, but probability is LOW given the formal guarantee and retry idempotency.

**Overall residual risk: MEDIUM.** Processing may commence with the mitigations documented above in place.

### 5.2 Consultation (GDPR Art. 36 / LGPD Art. 38 §3)

Prior supervisory authority consultation is **not required** at this stage — residual risk is MEDIUM (not HIGH/unmitigable after mitigation). Revisit if cross-tenant dedup is enabled or if scale exceeds 10M subjects.

### 5.3 Sign-off

| Role | Name | Date | Status |
|---|---|---|---|
| Privacy Officer | Gustavo Schneiter (interim) | 2026-05-13 | Pending final sign-off pre-PRR |
| DPO / Encarregado | TBD | TBD | Pending hire |
| Legal (external) | TBD | TBD | Pending engagement |
| Compliance | TBD | TBD | Pending |

> **EVT-045:** Upload to `evidence-legal/dpia-s07-dedup-leakage.md` (R2 retain 7y) upon first sign-off.
> **EVT-044 LEGAL_REVIEW:** Record upon legal review completion.

---

## Section 6 — Quarterly Review Schedule

| Review cycle | Target date | Trigger condition | Reviewer |
|---|---|---|---|
| Initial | 2026-06-13 | Pre-PRR | Privacy Officer |
| Q3 2026 | 2026-09-01 | Quarterly | Privacy Officer |
| Q4 2026 | 2026-12-01 | Quarterly | Privacy Officer |
| Q1 2027 | 2027-03-01 | Quarterly | Privacy Officer |
| Change-triggered | On any PR modifying CAS dedup logic or INV-TENANT-ISOLATION | CI hook detect | Privacy Officer |

### 6.1 DPIA changelog

| Version | Date | Author | Change summary |
|---|---|---|---|
| 1.0 | 2026-05-13 | Gustavo Schneiter | Initial DPIA — WI-S11-008 |
