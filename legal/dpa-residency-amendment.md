---
id: "DPA-RESIDENCY-AMENDMENT"
type: "legal_template"
doc_status: "PENDING_LEGAL_REVIEW"
version: "1.0.0"
created: "2026-05-14"
updated: "2026-05-14"
owner: "Gustavo Schneiter"
legal_review_status: "PENDING"
legal_review_firm: "TBD (Schellman Legal / Cooley / DLA Piper / Bird & Bird / Fenwick & West / Latham & Watkins)"
legal_review_budget: "$15,000–$30,000"
legal_review_lead_time: "6 weeks"
wi: "WI-S14-008"
tags:
  - "dpa"
  - "gdpr-art-28"
  - "gdpr-art-46"
  - "lgpd-art-33"
  - "schrems-ii"
  - "residency"
  - "4-regions"
  - "data-processing-agreement"
  - "s14"
reviewers:
  - "Compliance Officer"
  - "Privacy Officer"
  - "Legal Counsel (Legal externo)"
supersedes: null
superseded_by: null
---

# Data Processing Agreement — Residency Amendment
## CoreLink by HuGR Labs — Template v1.0.0

> **IMPORTANT LEGAL NOTICE**: This document is a **structural template** prepared to facilitate external Legal counsel review. It is **NOT a finalised legal instrument**. The redlined, legally verified version will be produced by a qualified GDPR-experienced external law firm engaged per `legal/legal-externo-engagement-contract.md`. **Legal review status: PENDING.**
>
> **References**: GDPR Art. 28, Art. 33, Art. 37, Art. 46 · LGPD Art. 33 §1, Art. 46, Art. 48 · Schrems II (C-311/18) · EDPB Recommendations 01/2020 · NIST SP 800-88 Rev.1 §2.4 · INV-DATA-RESIDENCY · INV-REGION-NO-CROSS-LEAK · INV-BYOK-CRYPTO-SOVEREIGNTY · INV-ERASURE-ATTESTATION-SIGNED

> **CURRENT LAUNCH BOUNDARY (DD-051 / B-204):** BYOK is not enabled or provisioned in the launched CoreLink data plane. No FIPS-validated BYOK module, CMK activation path, BYOK kill switch, or set of four KMS providers is currently available. The live service uses provider-managed R2 encryption and its ordinary DSR erasure pipeline. Every BYOK, FIPS, CMK, crypto-erase, and four-provider reference below is a **future-state design requirement**, conditional on separately approved production enablement and current evidence; it is not an unconditional customer commitment or a statement that the feature is available today.

---

## Section 1 — Parties

**Data Controller ("Customer"):**
- Legal name: `[CUSTOMER_LEGAL_NAME]`
- Registration number: `[CUSTOMER_REG_NUMBER]`
- Registered address: `[CUSTOMER_ADDRESS]`
- DPO / Privacy contact: `[CUSTOMER_DPO_NAME]` · `[CUSTOMER_DPO_EMAIL]`

**Data Processor ("CoreLink" / "HuGR Labs"):**
- Legal name: HuGR Labs Ltda. (operating as CoreLink)
- Registered address: `[HUGR_REGISTERED_ADDRESS]`
- DPO contact: Gustavo Schneiter (interim, sole-founder dual-hat) · `dpo@corelink.io`
- Emergency contact: `security@corelink.io`

**Relationship:** The parties have entered into a Master Service Agreement ("MSA") or equivalent order form ("Service Agreement") under which CoreLink acts as Processor and Customer acts as Controller in respect of Personal Data processed through the CoreLink content-addressable cache service.

---

## Section 2 — Definitions

| Term | Definition |
|---|---|
| **Personal Data** | Any information relating to an identified or identifiable natural person as defined in GDPR Art. 4(1) and LGPD Art. 5(I). |
| **Processing** | Any operation performed on Personal Data as defined in GDPR Art. 4(2) and LGPD Art. 5(X). |
| **Data Subject** | The natural person to whom Personal Data relates. |
| **Sub-processor** | Any third party engaged by CoreLink to process Personal Data on behalf of Customer. |
| **CMK** | Customer-Managed Key — cryptographic key held exclusively by Customer, used to wrap the DEK. |
| **DEK** | Data Encryption Key — AES-256-GCM key generated per-blob, wrapped by the CMK. |
| **Region** | A named geographic grouping corresponding to CoreLink's Cloudflare infrastructure footprint. See Section 7 for enumeration. |
| **Tenant** | A Customer's isolated workspace within the CoreLink service, identified by `tenant_id`. |
| **Erasure Attestation** | An Ed25519-signed cryptographic receipt confirming irreversible data erasure per NIST SP 800-88 Rev.1 §2.4. |
| **BYOK** | Bring Your Own Key — cryptographic architecture where Customer supplies and exclusively controls the CMK. |
| **Breach** | A personal data breach as defined in GDPR Art. 4(12). |
| **EDPB Recommendations 01/2020** | European Data Protection Board Recommendations 01/2020 on measures that supplement transfer tools, as adopted 18 June 2021. |

---

## Section 3 — Subject-Matter and Duration

**Subject-matter:** CoreLink processes Personal Data solely to provide the content-addressable cache service described in the Service Agreement, including: blob storage, retrieval, deduplication, and associated access-control and audit services.

**Duration:** This DPA Amendment remains in force for the duration of the Service Agreement. Upon termination or expiry, Section 14 (Termination) applies.

---

## Section 4 — Nature and Purpose of Processing

CoreLink processes Personal Data on documented instruction from Customer solely for the following purposes:
1. Storage and retrieval of cache blobs uploaded by Customer or Customer's authorised users.
2. Access control enforcement (tenant isolation and RBAC; BYOK key operations only if separately enabled for a tenant).
3. Audit log generation for compliance, integrity, and forensic purposes (7-year retention per CTRL-AUDIT-005).
4. Breach detection, incident response, and security operations.

CoreLink shall not process Personal Data for its own purposes, use it for training machine-learning models, or disclose it to third parties except as required by applicable law or as necessary to deliver the service via authorised Sub-processors (Section 8).

---

## Section 5 — Categories of Data Subjects

- Customer's end-users (individuals whose data is contained in cache blobs uploaded by Customer).
- Customer's tenant organisation members (individuals who access the CoreLink service using Customer's credentials).

---

## Section 6 — Categories of Personal Data

Categories of Personal Data that may be processed are determined by Customer. CoreLink's data model (per `privacy_model.md` CTRL-PRIV-001 through CTRL-PRIV-030) supports but does not mandate the following categories:

| Category | Examples | CTRL Reference |
|---|---|---|
| Identifiers | User IDs, email addresses (hashed in audit chain) | CTRL-PRIV-001 |
| Audit metadata | Timestamps, operation type, tenant\_id, region | CTRL-PRIV-002 |
| Blob content | Customer-uploaded cache blobs (encrypted at rest with provider-managed R2 encryption; BYOK plaintext-separation is not active at launch) | CTRL-PRIV-010 |
| Access logs | IP addresses (pseudonymised), request paths, response codes | CTRL-PRIV-020 |

CoreLink does not knowingly process special-category data (GDPR Art. 9) or data concerning children. Customer is responsible for ensuring such data is not uploaded without appropriate safeguards.

---

## Section 7 — R2 and Durable Object Residency Commitment per Region

This template's regional statements apply to R2 objects and tenant-pinned
Durable Object state. They do not apply to the shared D1 control plane. The
five production Workers currently bind one D1 database whose primary Cloudflare
reports in ENAM, with no D1 jurisdiction and automatic read replication. That
database holds tenant, membership, PAT, quota, billing, and audit-outbox data.
This is a prelaunch technical disclosure, not an approved transfer mechanism
or executed customer commitment.

### 7.1 Enumerated Regions

| Region Code | Geographic Area | Cloudflare Infrastructure | Data Localization Commitment |
|---|---|---|---|
| **WNAM** | Western North America | Cloudflare us-west infrastructure | R2 objects and tenant-pinned DO state use us-west facilities. |
| **ENAM** | Eastern North America | Cloudflare us-east infrastructure | R2 objects and tenant-pinned DO state use us-east facilities. |
| **WEUR** | Western Europe | Cloudflare eu-west infrastructure | R2 objects and tenant-pinned DO state use eu-west facilities. `jurisdictional_restriction = "eu"` enforced (WI-S14-001). |
| **APAC** | Asia-Pacific | Cloudflare Tokyo (`nrt`) infrastructure and APAC R2 bucket | R2 objects and tenant-pinned DO state use the provisioned APAC path. This is a physical-location statement, not an APAC legal-jurisdiction claim. |
| **SAM** | South America | **Not provisioned** | New SAM residency provisioning is rejected; this template makes no claim that SAM data is stored in Brazil. |

### 7.2 Failover Restrictions

R2 objects and tenant-pinned Durable Object state may replicate to a secondary
region solely for high-availability purposes, subject to the following hard
restrictions (enforced by INV-DATA-RESIDENCY and INV-REGION-NO-CROSS-LEAK).
These restrictions do not describe D1 replication or placement.

| Primary Region | Permitted Failover Destinations |
|---|---|
| WNAM | ENAM (US sibling pair only) |
| ENAM | WNAM (US sibling pair only) |
| WEUR | WEUR read-replica only; no cross-jurisdiction transfer |
| APAC | APAC read-replica only, where provisioned |
| SAM | Not applicable — SAM is not provisioned |

**WEUR R2/DO state NEVER replicates outside the EU jurisdiction.** This
restriction is enforced at the infrastructure level (Cloudflare DO
`jurisdictional_restriction`) and validated by `PAT-REGION-FAILOVER-001`
(WI-S14-003). It is not a D1 replication claim.

### 7.3 International Transfer Mechanism

The repository disclosure describes the shared D1 control plane under SCC/TIA
safeguards. This template does not establish that a transfer mechanism has been
approved or executed. Counsel must approve the applicable transfer basis,
safeguards, and effective date before any customer-facing residency term is
published.

SAM is not a provisioned signup region. A future SAM deployment would require a
separate residency decision and legal review under LGPD Art. 33; this template
does not make a current Brazil-localisation commitment.

---

## Section 8 — Sub-processors

CoreLink engages the following Sub-processors. Customer authorises their engagement. CoreLink shall: (a) impose equivalent data protection obligations on each Sub-processor; (b) notify Customer at least 30 days before engaging a new Sub-processor or making material changes; and (c) remain fully liable for Sub-processor acts and omissions.

### 8.1 Authorised Sub-processors

| Sub-processor | Role | Data Categories | DPA Reference | Region Scope |
|---|---|---|---|---|
| **Cloudflare, Inc.** | Infrastructure: Workers, R2, D1, KV, Durable Objects, Custom Domains | Blob content (encrypted), audit metadata, access logs | [cf-dpa.cloudflare.com](https://www.cloudflare.com/cloudflare-customer-dpa/) | R2/DO tenant-pinned; shared D1 control plane is global (primary reported ENAM, no D1 jurisdiction) |
| **Customer KMS Provider (future only)** | No current service processing; candidate BYOK CMK integration | Not applicable while BYOK is unavailable | Would require a separately enabled customer agreement | Not an active sub-processor |

### 8.2 Customer KMS Provider Options

The following are **design candidates only**, not currently available or enabled
providers. CoreLink makes no FIPS validation or four-provider availability claim
until a production provider is explicitly provisioned and its current evidence
is recorded in `docs/compliance/byok-fips-evidence.md`:
- AWS Key Management Service (KMS)
- Google Cloud Key Management Service
- Azure Key Vault (Premium tier, HSM-backed)
- HashiCorp Vault (Enterprise, transit secrets engine)

### 8.3 Sub-processor Audit Rights

Customer has the right to request information about Cloudflare's compliance posture, including access to Cloudflare's SOC 2 Type II report (available at [trust.cloudflare.com](https://www.cloudflare.com/trust-hub/compliance-resources/)). CoreLink shall facilitate such requests within 30 days.

---

## Section 9 — Security Measures

CoreLink implements and maintains the following technical and organisational security measures:

### 9.1 Encryption at Rest

- **Current encryption**: The launched service uses provider-managed R2 encryption. BYOK envelope encryption (unique DEK wrapped by a customer CMK) is a future-state design, not an active control.
- **BYOK FIPS Verification (future only)**: No FIPS-backed BYOK endpoint is enabled and no FIPS validation is claimed. A future enablement would require provider-specific evidence in `docs/compliance/byok-fips-evidence.md` before any customer commitment.
- **Per-region Key Isolation**: Any future BYOK key isolation is conditional on production enablement; this template is not evidence that such a control is active.

### 9.2 Encryption in Transit

- TLS 1.2 floor, 1.3 negotiated, for all client-to-CoreLink and CoreLink-to-Cloudflare communications (ADR-0072).
- Mutual TLS (mTLS) for HashiCorp Vault key operations.
- Certificate management via Cloudflare-managed certificates.

### 9.3 Access Controls

- Least-privilege IAM with role-based access control (RBAC) enforced at tenant level.
- Admin role requires dual-approval for sensitive operations (WI-S13-002).
- Multi-factor authentication (MFA) mandatory for all CoreLink personnel with production access.
- Personnel access log retained 7 years (CTRL-AUDIT-005).

### 9.4 Audit Chain Integrity

- Append-only audit chain with tamper-evident Ed25519 signatures (S-09).
- Daily integrity verification (continuous auditor job).
- Audit logs retained 7 years (CTRL-AUDIT-005).

### 9.5 Erasure Attestation

- **Current erasure**: Erasure uses the launched DSR pipeline and its documented retention/SLA controls. BYOK CMK revocation and a five-minute crypto-erase are not available at launch and are not a current commitment.
- Any future Ed25519-signed attestation or NIST SP 800-88 crypto-erase mode is conditional on production enablement and evidence; this template does not itself prove either control.

---

## Section 10 — Data Subject Rights

CoreLink shall assist Customer in fulfilling Data Subject rights requests within the following SLAs, as required by GDPR Chapter III and LGPD Chapter III:

| Right | Mechanism | SLA |
|---|---|---|
| **Right of Access** | Customer exports tenant data via CoreLink admin API (S-11) | 30 days (GDPR Art. 12) |
| **Right to Portability** | Customer exports blobs in standard format via admin API (S-11) | 30 days |
| **Right to Correction** | Customer updates metadata via standard write operations | Immediate |
| **Right to Erasure** | Launched DSR/erasure pipeline; BYOK kill switch and crypto-erase are unavailable unless separately enabled | Per the applicable service SLA and legal deadline |
| **Right to Restriction** | Customer disables tenant via admin API | Immediate |

**Erasure Note**: This template does not assert that a BYOK crypto-erase mechanism
or signed attestation is active. Those are future-state controls requiring legal
review, production enablement, and retained evidence; the current service relies
on its ordinary DSR/erasure pipeline.

**Cooling-off period**: 7 calendar days between erasure request and irreversible execution (S-11), during which Customer may cancel the request.

---

## Section 11 — Breach Notification

### 11.1 CoreLink Obligations

Upon becoming aware of a Breach affecting Customer Personal Data, CoreLink shall:

1. Notify Customer DPO (Section 1) **within 72 hours** of becoming aware of the Breach. (GDPR Art. 33 / LGPD Art. 48.)
2. Notification shall include (to the extent then known):
   - Nature of the Breach (categories and approximate number of Data Subjects affected).
   - Likely consequences of the Breach.
   - Measures taken or proposed to address the Breach.
   - Name and contact details of the CoreLink DPO.
3. Initial notification may be made in stages; CoreLink shall provide complete information as soon as reasonably practicable.
4. CoreLink shall cooperate with Customer to facilitate Customer's own notifications to supervisory authorities and Data Subjects.

### 11.2 Contact Details

- **CoreLink DPO**: Gustavo Schneiter · `dpo@corelink.io`
- **Emergency security hotline**: `security@corelink.io` (monitored 24/7)
- **Incident runbook**: `RB-breach-notification` (internal reference)

### 11.3 Breach Response SLA

| Step | SLA |
|---|---|
| Initial Customer notification | ≤ 72 hours of CoreLink awareness |
| Incident containment | Per `RB-breach-notification` severity levels |
| Root-cause analysis | ≤ 14 days post-containment |
| Post-mortem report to Customer | ≤ 30 days post-containment |

---

## Section 12 — International Transfers

### 12.1 Transfer Mechanism

Where Personal Data is transferred from the European Economic Area (EEA) to a third country (including the United States, where Cloudflare is headquartered), such transfers are made on the basis of:
- EU Standard Contractual Clauses (Module 1: Controller to Controller; Module 2: Controller to Processor) per GDPR Art. 46(2)(c).
- Cloudflare's SCCs with CoreLink (incorporated by reference in Cloudflare DPA).

### 12.2 Schrems II Transfer Impact Assessment

CoreLink has conducted a Transfer Impact Assessment (TIA) per EDPB Recommendations 01/2020. The TIA:
- Assesses US surveillance law (FISA 702, EO 12333, CLOUD Act) risk.
- Documents supplementary measures (technical, organisational, contractual) rendering the transfer compliant.
- Does not rely on BYOK to conclude that a transfer is compliant: BYOK is not
  active in the launched data plane. Any future TIA must be re-reviewed after a
  real CMK path and provider evidence are provisioned.

Full TIA available at `legal/tia-template.md`.

### 12.3 LGPD Art. 33 §1 (Brazil — SAM is not provisioned)

SAM is not currently provisioned. CoreLink therefore makes no commitment that
SAM data is stored in Cloudflare sa-east or that a Brazil-local processing path
is available. A future SAM path would require an explicit deployment decision,
LGPD Art. 33 review, and an amended DPA before signup is enabled.

---

## Section 13 — Audit Rights

### 13.1 Customer Audit Rights

Customer may, on reasonable notice (minimum 30 days) and no more than once per calendar year, request an audit of CoreLink's data processing activities, limited to matters relevant to this DPA. CoreLink may satisfy this right by:
- Providing its current SOC 2 Type II report (under NDA).
- Providing written responses to a standard security questionnaire (CAIQ/SIG).
- Facilitating a third-party audit (at Customer's cost, subject to scheduling constraints).

### 13.2 Regulatory Audit Cooperation

CoreLink shall cooperate with supervisory authorities (including ANPD, European DPAs) conducting audits or investigations related to Customer Personal Data processing.

---

## Section 14 — Termination and Data Deletion

### 14.1 Data Deletion

Upon termination or expiry of the Service Agreement for any reason:
- CoreLink shall, within **30 days**, delete or return (at Customer's option) all Customer Personal Data.
- Deletion shall use the launched DSR/erasure pipeline. A BYOK crypto-erase
  mechanism (Section 9.5 / Section 10) is future-state only and unavailable
  unless separately enabled.
- Any **Ed25519-signed erasure attestation** is likewise future-state evidence;
  this template does not promise that it is issued by the current service.

### 14.2 Audit Log Retention Post-Termination

Anonymised or pseudonymised audit logs (from which Personal Data has been removed) may be retained for up to 7 years from the date of the event, solely for CoreLink's internal audit, legal compliance, and integrity-verification purposes.

### 14.3 Return of Data

At Customer's written request (within 30 days of termination notice), CoreLink shall export Customer blobs in a standard format for Customer retrieval, prior to deletion.

---

## Section 15 — Governing Law and Jurisdiction

| Customer Tenant Region | Governing Law | Jurisdiction |
|---|---|---|
| WEUR (EU/EEA customers) | Laws of Ireland (EU Member State) | Courts of Ireland; GDPR supervisory authority: Data Protection Commission (Ireland) |
| WNAM / ENAM (US customers) | Laws of the State of Delaware, USA | Courts of Delaware, USA |
| APAC (current physical-location path) | `[TO BE DETERMINED BY LEGAL EXTERNO REVIEW]` | `[TO BE DETERMINED]` |
| SAM (not provisioned) | No active commitment | No active commitment |
| Default (unspecified) | `[TO BE DETERMINED BY LEGAL EXTERNO REVIEW]` | `[TO BE DETERMINED]` |

> Note: Governing law and jurisdiction clauses require Legal externo review and finalisation. The above is a structural placeholder.

---

## Appendix A — Technical Measures Evidence Pack

The following CoreLink implementation artefacts evidence the technical security measures committed in Section 9:

| Measure | Evidence Reference | Sprint WI |
|---|---|---|
| BYOK envelope encryption (future design; not enabled) | `docs/compliance/byok-fips-evidence.md` (status unavailable) | WI-S14-004, WI-S14-005 |
| BYOK kill switch (future design; not enabled) | `specs/04_sprints/S14/work_items/WI-S14-006-*.md` | WI-S14-006 |
| Erasure attestation (future design; not enabled) | `specs/04_sprints/S14/work_items/WI-S14-007-*.md` | WI-S14-007 |
| Region pinning + INV-REGION-NO-CROSS-LEAK | `specs/04_sprints/S14/work_items/WI-S14-002-*.md` | WI-S14-002 |
| Failover restriction PAT-REGION-FAILOVER-001 | `specs/04_sprints/S14/work_items/WI-S14-003-*.md` | WI-S14-003 |
| Audit chain integrity (Ed25519 + 7y retention) | S-09 audit chain | S-09 |
| FIPS-validated BYOK (future design; zero providers enabled) | `docs/compliance/byok-fips-evidence.md` (no evidence yet) | WI-S14-005 |
| TLS 1.2 floor / 1.3 negotiated + mTLS | Cloudflare certificate management | S-06 |

---

## Appendix B — Organisational Measures

| Measure | Description |
|---|---|
| DPO designation | Gustavo Schneiter (interim dual-hat); external DPO to be contracted per ADR-0034 Option C |
| Personnel training | Annual data protection training; GDPR + LGPD awareness |
| Access control policy | Least-privilege; MFA mandatory; dual-approval for admin operations |
| Incident response | `RB-breach-notification` runbook; 72h notification SLA; quarterly breach-response drills |
| Vendor management | Sub-processor disclosure (Section 8); 30-day advance notice of changes |
| Quarterly Legal review | EDPB monitoring; Schrems II landscape; DPA + TIA updates if needed |
| Sub-processor audit | Annual Cloudflare DPA review; SOC 2 Type II verification |
| 4 regions enumerated | WNAM / ENAM / WEUR / APAC — current provisioned paths (Section 7); SAM is not provisioned |

---

## Appendix C — Contractual Measures (Sub-processor Agreements)

| Sub-processor | Agreement | Status |
|---|---|---|
| Cloudflare, Inc. | [Cloudflare Customer DPA](https://www.cloudflare.com/cloudflare-customer-dpa/) (incorporating SCCs) | Signed 2026-04-23 (see `legal/sub-processors.md`) |
| Customer KMS Provider (future only) | Would require a separately enabled provider agreement | Not an active sub-processor or service option |

**Customer right to audit Sub-processors**: Customer may request CoreLink to exercise its audit rights under the Cloudflare DPA on Customer's behalf, subject to Cloudflare's audit procedures and reasonable scheduling constraints.

---

*Document status: PENDING LEGAL REVIEW — not a finalised legal instrument. Version 1.0.0 · 2026-05-14 · WI-S14-008.*
