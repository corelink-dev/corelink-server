---
id: "DPA-ONBOARDING"
type: "customer_doc"
doc_status: "PRELAUNCH_REVIEW_REQUIRED"
version: "1.1.0"
created: "2026-05-14"
updated: "2026-09-30"
owner: "Gustavo Schneiter"
audience: "internal_prelaunch_review"
distribution: "not_for_customer_distribution"
wi: "WI-S14-008"
tags:
  - "dpa"
  - "onboarding"
  - "enterprise"
  - "gdpr"
  - "residency"
  - "customer-facing"
  - "s14"
supersedes: null
superseded_by: null
---

# CoreLink DPA Onboarding Guide
## Enterprise Customer — Data Processing Agreement

> **PRELAUNCH — DO NOT DISTRIBUTE OR USE AS A CUSTOMER COMMITMENT.** The owner confirms CoreLink has not launched, has no customers, and this guide is not approved for customer distribution. Its prior customer-onboarding wording is retained only as a historical source. Counsel has not approved the current shared-D1 transfer posture or the feature claims below.

---

## Overview

CoreLink is a content-addressable shared cache service by HuGR Labs. CoreLink is prelaunch. No customer DPA package, approved transfer impact assessment, or customer evidence pack is currently offered. This document is a draft inventory for counsel review only.

---

## Step 1 — Select Your Data Residency Region

The source configuration has regional R2/DO paths, but these do not establish D1 placement or a customer residency commitment. Five production Worker environments reference one shared D1 database without a D1 jurisdiction binding. D1 holds tenant, membership, PAT, quota, billing-state, and audit-outbox records. A read-only Wrangler 4.145.0 readback on 2026-09-30 identified `corelink-prod-d1` (ID `d64742ea-e102-40b2-a844-ff02e3f94562`), with `running_in_region=ENAM`, `jurisdiction=null`, automatic read replication, and 162 tables. These are provider metadata, not a physical-location guarantee or legal approval; the root owner selected this technical prelaunch posture. No region-specific D1 placement or transfer basis is approved. CoreLink has not launched and no customer data migration is authorized.

---

## Step 2 — Review the DPA Package

Your DPA package includes:

1. **DPA Amendment Template** (`legal/dpa-residency-amendment.md`) — structural draft pending qualified counsel review. It is not approved or executed. Covers:
   - 15 sections: parties, definitions, data categories, residency commitment, sub-processors, security measures, data subject rights, breach notification, international transfers, audit rights, termination.
   - 3 appendices: technical measures evidence pack, organisational measures, contractual measures.

2. **Transfer Impact Assessment template** (`legal/tia-template.md`) — an incomplete assessment framework, not an approved conclusion. Counsel must assess the shared D1 control plane separately. SCCs, Cloudflare contract terms, and provider-managed encryption do not by themselves establish an approved transfer basis or effective supplementary measures. BYOK is not available at launch and does not cover D1.

3. **Technical evidence** — no customer evidence pack is available; these are source references for future review:
   - BYOK FIPS compliance documentation (`docs/compliance/byok-fips-evidence.md`) — available when BYOK is provisioned
   - Erasure attestation mechanism (Ed25519-signed; WI-S14-007)
   - SOC 2 Type II report (available on request)
   - Cloudflare sub-processor DPA (`https://www.cloudflare.com/cloudflare-customer-dpa/`)

---

## Step 3 — Key DPA Commitments

### Data Residency
- No customer residency offer is currently active.
- R2/DO source controls and regional Worker bindings do not establish placement for the shared D1 control plane.
- The shared D1 transfer basis and applicable safeguards remain pending counsel review; this draft makes no physical-location or no-transfer guarantee.

### Encryption and Storage Security

**Prelaunch source posture:** No customer data is being processed. The service source uses provider-managed R2 encryption for object storage. This does not establish placement or encryption controls for all shared D1 control-plane records. The historical Cloudflare contract and security certifications are not a transfer assessment or approval.

**BYOK (Bring Your Own Key): unavailable at launch.** Although source code contains a BYOK provider feature, no authenticated evidence establishes a complete customer-controlled KMS lifecycle in the shipped CoreLink runtime. BYOK, CMK activation, key revocation, crypto-erase, and FIPS-backed BYOK are not available or offered. No provider support or customer capability is implied by repository code.

**Kill switch:** The previously listed ≤ 5-minute p99 target is not a verified measurement or active SLA. No kill-switch timing commitment is made.

### Erasure — Cryptographic Proof
Erasure uses the ordinary DSR workflow. This draft does not claim that a signed erasure attestation or Object Lock retention is currently issued or available.

### Breach Notification
- CoreLink will notify your DPO within **72 hours** of becoming aware of any breach affecting your Personal Data (GDPR Art. 33 / LGPD Art. 48).

### Sub-processors
The current source configuration includes the following provider; no customer data processing has launched:
1. **Cloudflare, Inc.** — infrastructure (Workers, R2, D1, KV, Durable Objects). Cloudflare DPA: `https://www.cloudflare.com/cloudflare-customer-dpa/`

No BYOK KMS provider is currently enabled or represented as an active sub-processor. Any future provider requires separate security, legal, and launch approval.

No other sub-processors access your Personal Data.

---

## Step 4 — DPA Signing Process

```
1. No customer onboarding is currently offered.
2. Counsel reviews the DPA, transfer basis, and evidence against the actual deployed target.
3. No customer instrument is effective until approved through the applicable legal and release process.
```

No signing timeline is promised.

**CoreLink DPO contact**: `dpo@corelink.io`

---

## Step 5 — Ongoing Rights and Controls

### Annual Audit
You may request an annual audit of CoreLink's data processing activities. CoreLink will provide:
- SOC 2 Type II report (under NDA).
- Written responses to security questionnaire (CAIQ/SIG).

### Sub-processor Changes
CoreLink will notify you at least **30 days** before engaging a new sub-processor or making material changes to existing sub-processors. You have the right to object.

### Data Subject Rights
CoreLink's admin API enables you to:
- Export all tenant data (right of access / portability).
- The ordinary DSR workflow supports erasure requests; this draft does not promise a signed attestation or CMK-based crypto-erase.
- Restrict processing (disable tenant).

### Termination
Upon termination:
- Applicable retention and deletion timing must be established in the approved service terms; this draft does not claim a BYOK path or Object Lock guarantee.
- No signed erasure-attestation availability or audit-log retention duration is established here.

---

## Frequently Asked Questions

**Q: What transfer safeguards apply to shared D1 data?**
A: The shared D1 control plane is not tenant-pinned. Its transfer basis and supplementary measures have not been approved. BYOK does not cover D1 and is unavailable at launch. No conclusion about government access or transfer compliance is made in this draft; counsel must assess the actual target and applicable terms before any launch.

**Q: Is this an approved customer DPA?**
A: No. This is a prelaunch draft pending qualified counsel review; CoreLink has no customers and this copy has not been distributed.

**Q: Is customer data stored in Brazil, the EU, or a selected region?**
A: No customer region is currently offered. A shared global D1 database serves the production Worker environments; the 2026-09-30 provider readback reports `running_in_region=ENAM` and `jurisdiction=null`, which does not establish physical residency. Transfer and regional terms require counsel approval.

**Q: Can we request custom DPA clauses?**
A: Yes, for enterprise customers. Custom clauses require a review cycle with our external legal counsel. Timeline: +2-4 weeks; potential additional cost.

**Q: Is there a lighthouse customer reference?**
A: No. CoreLink has no customers; no customer DPA or BYOK case study exists or has been distributed.

---

*Version 1.1.0 · 2026-06-15 · WI-S14-008 · Distribution: post-NDA enterprise customers.*
*Historical change note retained for attribution. Superseding prelaunch correction: CoreLink has not launched, has no customers, and this guide is not approved for customer distribution. The current draft discloses one shared D1 control plane, removes unproved Object Lock and BYOK/SLO claims, and leaves transfer terms pending counsel review.*
