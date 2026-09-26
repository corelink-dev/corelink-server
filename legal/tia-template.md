---
id: "TIA-SCHREMS-II"
type: "legal_template"
doc_status: "PENDING_LEGAL_REVIEW"
version: "1.0.0"
created: "2026-05-14"
updated: "2026-05-14"
owner: "Gustavo Schneiter"
legal_review_status: "PENDING"
legal_review_firm: "TBD"
wi: "WI-S14-008"
framework: "EDPB Recommendations 01/2020"
tags:
  - "tia"
  - "schrems-ii"
  - "edpb-01-2020"
  - "gdpr-art-46"
  - "lgpd-art-33"
  - "transfer-impact-assessment"
  - "supplementary-measures"
  - "s14"
reviewers:
  - "Compliance Officer"
  - "Privacy Officer"
  - "Legal Counsel (Legal externo)"
supersedes: null
superseded_by: null
---

# Transfer Impact Assessment (TIA) — Schrems II
## CoreLink by HuGR Labs — Template v1.0.0

> **Framework**: EDPB Recommendations 01/2020 on measures that supplement transfer tools to ensure compliance with the EU level of protection of personal data (adopted 18 June 2021).
>
> **Legal basis**: GDPR Art. 46(2)(c) (Standard Contractual Clauses) · LGPD Art. 33 §1 · C-311/18 (Schrems II, CJEU 16 July 2020).
>
> **IMPORTANT LEGAL NOTICE**: This document is a **structural template** prepared to facilitate external Legal counsel review. It is **NOT a finalised legal instrument**. Legal review status: **PENDING**.

---

## Section 1 — Transfer Description

### 1.1 Parties to the Transfer

| Role | Party | Jurisdiction |
|---|---|---|
| **Data Controller** | `[CUSTOMER_LEGAL_NAME]` | `[CUSTOMER_JURISDICTION]` |
| **Data Processor** | HuGR Labs Ltda. (CoreLink) | Brazil (incorporated) / operational: multi-region |
| **Sub-processor** | Cloudflare, Inc. | United States (HQ); EU infrastructure available |

### 1.2 Data Flows

```
Customer (Controller, EEA or Brazil)
  → CoreLink (Processor, multi-region)
    → Cloudflare R2/D1/DO/KV/Workers (Sub-processor, infrastructure)
      [R2/DO tenant-pinned; D1 control-plane data is shared global]
```

- **Transfer 1**: Customer → CoreLink (via HTTPS; TLS 1.2 floor, 1.3 negotiated). Personal Data enters CoreLink's processing environment.
- **Transfer 2**: CoreLink → Cloudflare infrastructure (Workers runtime + R2/D1/DO storage). R2/DO state follows the tenant residency posture; the shared D1 control plane is currently reported with a primary in ENAM, no D1 jurisdiction, and automatic read replication.
- **Transfer direction**: EEA-originating data may be processed by Cloudflare infrastructure with US parent company jurisdiction (FISA 702 / EO 12333 / CLOUD Act risk scope).

### 1.3 Categories of Personal Data Transferred

Per DPA Amendment Section 6 (`legal/dpa-residency-amendment.md`):
- Identifiers (hashed user IDs, pseudonymised email hashes in audit chain)
- Audit metadata (timestamps, operation types, tenant_id, region)
- Blob content (customer-uploaded; encrypted at rest — CoreLink/Cloudflare cannot access plaintext)
- Access logs (pseudonymised IP addresses, request paths)

### 1.4 Purpose and Legal Basis

Purpose: Provision of CoreLink content-addressable cache service (storage, retrieval, deduplication, access control, audit logging).

Legal basis for processing (Controller side): `[CUSTOMER TO SPECIFY: e.g., GDPR Art. 6(1)(b) contract / Art. 6(1)(f) legitimate interest]`.

---

## Section 2 — Transfer Mechanism

### 2.1 Primary Transfer Tool

**EU Standard Contractual Clauses (SCCs)** per GDPR Art. 46(2)(c):
- Module 2 (Controller to Processor): Customer ↔ CoreLink.
- Module 3 (Processor to Sub-processor): CoreLink ↔ Cloudflare (via Cloudflare Customer DPA incorporating SCCs).

**LGPD Art. 33 §1**: For Brazil-originating transfers, CoreLink relies on:
- Adequate level of protection provided by applicable safeguards.
- Supplementary measures documented in Section 4 of this TIA.

### 2.2 Supporting Instruments

- CoreLink DPA Amendment (`legal/dpa-residency-amendment.md`) — data processing terms + residency commitment.
- Cloudflare Customer DPA (`https://www.cloudflare.com/cloudflare-customer-dpa/`) — sub-processor terms + Cloudflare SCCs.
- CoreLink Sub-processors list (`legal/sub-processors.md`).

---

## Section 3 — Third-Country Law Assessment

### 3.1 United States (Cloudflare Sub-processor HQ Jurisdiction)

#### 3.1.1 Identified Legal Instruments Posing Surveillance Risk

| Instrument | Scope | Risk to Transfer |
|---|---|---|
| **FISA Section 702** (50 U.S.C. § 1881a) | Compels US-based electronic communication service providers to disclose communications of non-US persons located outside the US to US intelligence agencies | HIGH — Cloudflare is a US entity subject to FISA 702 orders |
| **Executive Order 12333** | Authorises collection of foreign intelligence data in transit | MEDIUM — affects data in transit; mitigated by TLS 1.3 |
| **CLOUD Act** (18 U.S.C. § 2713) | Authorises US government to compel US-based providers to disclose data stored abroad | HIGH — Cloudflare, as US entity, subject to CLOUD Act |

#### 3.1.2 Assessment

**Without supplementary measures**: The transfer to Cloudflare (US-headquartered) cannot be guaranteed to meet the EU level of protection solely on the basis of SCCs, given FISA 702 / CLOUD Act compelled-disclosure risk. This conclusion is consistent with the CJEU ruling in Schrems II (C-311/18).

**Current assessment**: not completed. BYOK has no verified customer rollout and
does not cover the shared D1 control plane; this template cannot assess the
transfer as effective until counsel reviews the applicable safeguards.

#### 3.1.3 EU-US Data Privacy Framework (DPF)

Cloudflare participates in the EU-US Data Privacy Framework (as of 2023). However, this TIA documents supplementary measures as an additional layer, consistent with the EDPB's guidance that supplementary measures provide defence-in-depth regardless of adequacy decisions.

### 3.2 Brazil (LGPD transfer context; SAM is not provisioned)

- Brazil is a regulated customer context, not a provisioned CoreLink macro.
  CoreLink does not promise SAM localization: `sam` has no Cloudflare SAM
  location, is not provisioned, and signup rejects it. A Brazilian customer
  must use a provisioned region and receive the corresponding residency terms.
- LGPD Art. 33 §1: transfers require adequate protection or appropriate safeguards.
- The supplementary measures in Section 4 apply to transfers involving
  Brazilian customers without representing an unavailable SAM data plane.

---

## Section 4 — Supplementary Measures

> Per EDPB Recommendations 01/2020, supplementary measures are categorised as: **Technical** (§80-83), **Organisational** (§84-87), and **Contractual** (§88-91).

> **Current scope boundary:** Customer-managed BYOK, CMK revocation, and
> crypto-erase have no verified customer rollout and are not active
> supplementary measures. They cannot mitigate transfer risk for the shared D1
> control plane, which contains tenant, membership, PAT, quota, billing, and
> audit-outbox records. Counsel must assess that control plane separately before
> approving any transfer posture.

### 4.1 Technical Measures (EDPB Recommendations 01/2020 §80-83)

#### 4.1.1 Encryption at Rest — BYOK future design

**Design, not active measure**: the planned architecture wraps blob DEKs with
a Customer CMK. No verified customer rollout proves this design is active, and
it does not apply to the shared D1 control-plane records.

**Implementation evidence**:
- WI-S14-004 (BYOK trait, envelope encryption architecture)
- WI-S14-005 (4 providers: AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault — all FIPS 140-2/140-3 validated)
- `docs/compliance/byok-fips-evidence.md`

**EDPB §83 effectiveness test**: not established. A future blob-only BYOK
implementation would require separate evidence; it cannot be used to claim
that Cloudflare holds only ciphertext or that the shared D1 control plane is
unreadable to a compelled disclosure request.

**Reference**: GDPR Art. 46 · EDPB Recommendations 01/2020 §83 Use Case 1 (encryption of data in transit) and Use Case 6 (pseudonymisation). This measure most closely aligns with EDPB Use Case 6 (data encrypted at rest with keys held by data exporter or trusted party, not by data importer).

#### 4.1.2 Encryption in Transit

**Measure**: TLS 1.2 floor enforced for all client-to-CoreLink and CoreLink-to-Cloudflare communications, with TLS 1.3 negotiated by every client that supports it (the floor was lowered from 1.3-only on 2026-07-19 so that native-tls clients could connect at all — ADR-0072). Mutual TLS (mTLS) for Vault operations. Certificate management via Cloudflare.

**Effectiveness**: Protects against EO 12333 interception-in-transit risk. **Assessment: EFFECTIVE (additional layer).**

#### 4.1.3 Pseudonymisation — Audit Chain

**Measure**: Audit chain logs use pseudonymised identifiers (hashed `user_id`, hashed email). Direct identifiers not stored in audit chain. (CTRL-AUDIT-002, inherited from S-09.)

**Effectiveness**: Limits identifiability of Data Subjects in audit log transfers. **Assessment: PARTIAL (supplementary).**

#### 4.1.4 Erasure via Crypto-Erase + Ed25519 Attestation — future design

**Design, not active measure**: Customer CMK revocation and the described
crypto-erase attestation have no verified customer rollout. They do not cover
shared D1 control-plane records.

**Effectiveness**: not established for the current launch posture.

#### 4.1.5 Envelope Encryption — Per-blob DEK Isolation future design

**Design, not active measure**: Each blob would receive a unique DEK wrapped
by a CMK. This proposed blob control does not apply to shared D1 control-plane
records.

**Effectiveness**: not established for the current launch posture.

#### 4.1.6 Per-Region Key Isolation — future design

**Design, not active measure**: per-region key isolation is not evidence of
shared D1 control-plane placement or a current transfer safeguard.

**Effectiveness**: not established for the current launch posture.

---

### 4.2 Organisational Measures (EDPB Recommendations 01/2020 §84-87)

#### 4.2.1 DPA Amendment — 4 Regions Enumerated

**Prelaunch disclosure**: the DPA template distinguishes tenant-pinned R2/DO
state from the shared global D1 control plane. The D1 primary is currently
reported in ENAM with no D1 jurisdiction and automatic read replication. This
template is pending legal review and does not itself approve a transfer basis
or establish a customer commitment.

**EDPB §84 alignment**: Transparency obligation; data exporter knows where data is processed.

#### 4.2.2 DPO Contact and Data Subject Rights

**Measure**: DPO contact designated (DPA Section 1 + Section 11.2). Data Subject rights supported (DPA Section 10). Breach notification SLA 72h (DPA Section 11).

**EDPB §86 alignment**: Organisational accountability and data subject rights support.

#### 4.2.3 Breach Notification SLA 72 Hours

**Measure**: CoreLink commits to notifying Customer DPO within 72 hours of becoming aware of a Breach. (GDPR Art. 33 / LGPD Art. 48.) Runbook `RB-breach-notification` governs response.

**Effectiveness**: Enables Customer to fulfil its own supervisory authority notification obligations within regulatory deadlines. **Assessment: COMPLIANT.**

#### 4.2.4 Sub-processor Disclosure and Audit Rights

**Measure**: All Sub-processors disclosed in DPA Section 8 and `legal/sub-processors.md`. Customer has right to audit Sub-processors (DPA Section 13). 30-day advance notice of Sub-processor changes.

**EDPB §87 alignment**: Contractual chain transparency.

#### 4.2.5 Quarterly Legal Review Cycle

**Measure**: CoreLink conducts quarterly Legal review of this TIA and the DPA, monitoring EDPB guidance updates, Schrems II legal landscape changes, and regulatory enforcement. Template at `legal/quarterly-legal-review-template.md`.

**Effectiveness**: Ensures TIA remains current with evolving legal landscape. **Assessment: EFFECTIVE (ongoing governance).**

---

### 4.3 Contractual Measures (EDPB Recommendations 01/2020 §88-91)

#### 4.3.1 DPA + SCCs

**Prelaunch disclosure**: the repository describes the shared D1 control plane
under SCC/TIA safeguards. The DPA amendment and this TIA remain pending legal
review; neither document establishes an executed SCC arrangement or counsel
approval for the D1 transfer posture.

**EDPB §88 alignment**: Counsel review is required before relying on a
contractual transfer mechanism for this prelaunch D1 posture.

#### 4.3.2 Sub-processor Agreement — Cloudflare

**Measure**: Cloudflare Customer DPA (`https://www.cloudflare.com/cloudflare-customer-dpa/`) in force. Incorporates SCCs. Cloudflare commits to GDPR-compliant processing. Signed 2026-04-23 (see `legal/sub-processors.md`).

**EDPB §89 alignment**: Sub-processor contractual obligations flow down.

#### 4.3.3 Customer Audit Rights + SOC 2 Type II

**Measure**: Customer may request CoreLink SOC 2 Type II report (under NDA) and exercise audit rights annually (DPA Section 13). CoreLink to facilitate access to Cloudflare compliance evidence.

**EDPB §90 alignment**: Audit rights to verify compliance.

#### 4.3.4 Termination + Data Deletion 30 Days + Erasure Attestation

**Current measure**: the launched DSR/erasure pipeline applies. BYOK
crypto-erase and an Ed25519-signed erasure attestation have no verified
customer rollout and do not establish deletion handling for shared D1 records.

**EDPB §91 alignment**: pending counsel review of the current DSR pipeline and
shared-D1 control-plane posture.

---

## Section 5 — Effectiveness Assessment

### 5.1 Overall Assessment

> Per EDPB Recommendations 01/2020 Step 6: "You must assess whether the supplementary measures you identified are effective in the light of the specific circumstances of the transfer."

**Assessment pending**: the shared D1 control plane contains tenant,
membership, PAT, quota, billing, and audit-outbox records. Its primary is
currently reported in ENAM with no D1 jurisdiction and automatic read
replication. BYOK and crypto-erase have no verified customer rollout and are
not available to assess or mitigate that control-plane transfer.

### 5.2 Residual Risk

| Risk | Assessment | Residual Risk |
|---|---|---|
| Shared D1 control-plane disclosure | Tenant, membership, PAT, quota, billing, and audit-outbox records are globally placed | Pending counsel assessment |
| R2/DO residency boundary | R2/DO source posture is tenant-pinned; it does not establish D1 placement | Pending counsel assessment |
| Future BYOK/crypto-erase design | No verified customer rollout | Not a current safeguard |

### 5.3 Conclusion

**Conclusion: pending counsel approval.** This prelaunch template records the
current shared-D1 facts and does not conclude that a transfer can proceed or
that an effective customer-facing transfer mechanism exists.

---

## Section 6 — Sign-off

> This section to be completed upon Legal externo review completion.

| Role | Name | Date | Status |
|---|---|---|---|
| CoreLink DPO | Gustavo Schneiter (interim) | _pending_ | PENDING |
| Compliance Officer | _TBD_ | _pending_ | PENDING |
| Privacy Officer | _TBD_ | _pending_ | PENDING |
| Legal Counsel (Legal externo) | _TBD (external firm)_ | _pending_ | PENDING |
| Customer DPO | `[CUSTOMER_DPO_NAME]` | _to be completed by Customer_ | PENDING |

**Legal externo review**: This TIA will be reviewed and redlined by a qualified GDPR-experienced external law firm (engagement per `legal/legal-externo-engagement-contract.md`). Legal review status: **PENDING**.

**Quarterly review**: This TIA shall be reviewed quarterly per `legal/quarterly-legal-review-template.md`. Next review: `[DATE + 90 DAYS FROM RATIFICATION]`.

---

## Appendix — EDPB Recommendations 01/2020 Compliance Matrix

| EDPB Step | Requirement | CoreLink Implementation | Section |
|---|---|---|---|
| Step 1 | Know your transfers | Data flow documented (Section 1.2) | Section 1 |
| Step 2 | Identify transfer tools | SCCs + DPA identified (Section 2) | Section 2 |
| Step 3 | Assess third-country law | US FISA 702 / CLOUD Act assessed (Section 3) | Section 3 |
| Step 4 | Identify supplementary measures | Technical + Organisational + Contractual (Section 4) | Section 4 |
| Step 5 | Adopt supplementary measures | Pending counsel review; BYOK and crypto-erase are not current measures | Section 4 |
| Step 6 | Re-evaluate at intervals | Quarterly Legal review cycle | Section 4.2.5 |

---

*Document status: PENDING LEGAL REVIEW — not a finalised legal instrument. Version 1.0.0 · 2026-05-14 · WI-S14-008.*
