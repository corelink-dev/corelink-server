---
id: "DPIA-S10-001"
type: "dpia"
doc_status: "DRAFT"
version: "1.0.0"
created: "2026-05-13"
updated: "2026-05-13"
feature: "S-10 Billing Data Cross-Border Transfer (Stripe US)"
sprint: "S-10"
owner: "Gustavo Schneiter"
privacy_officer: "Gustavo Schneiter (interim)"
dpo: "TBD"
tags: ["dpia", "s10", "billing", "cross-border", "stripe", "schrems-ii", "scc", "tia", "gdpr-art-35", "lgpd-art-38"]
evidence_event: "EVT-045"
evidence_retain: "7y"
evidence_path: "evidence-legal/dpia-s10-billing-cross-border.md"
---

# DPIA: S-10 Billing Data Cross-Border Transfer — Stripe US-Based Processing

> **Superseded data-store assumption (B-316, 2026-10-02).** This draft was
> written when a Neon Postgres control plane was planned. Neon was never used
> by the product: account, billing and metadata state live in Stripe and the
> Cloudflare D1 control-plane database. Every Neon-specific statement below
> describes that abandoned design; none of its Neon measures are in place.
> The current sub-processors are listed in `legal/sub-processors.md`.

> **GDPR Art. 35 / LGPD Art. 38 (RIPD) Data Protection Impact Assessment**
> Template: `specs/_templates/dpia.md` v1.0.0 — WI-S11-008
> **Schrems II (CJEU C-311/18) analysis: SCC + TIA documented here.**

---

## Metadata

| Field | Value |
|---|---|
| DPIA ID | DPIA-S10-001 |
| Feature / Sprint | S-10 billing pipeline (usage-based billing, Stripe Checkout, webhook reconciliation) |
| Data Controller | HuGR Labs Ltda (LGPD) / HuGR Labs Ltd (GDPR) |
| Encarregado / DPO | TBD (interim: Gustavo Schneiter) |
| Privacy Officer | Gustavo Schneiter (interim) |
| Processing basis | contract (GDPR Art. 6(1)(b) / LGPD Art. 7 V) — billing is necessary for service delivery; legal_obligation (GDPR Art. 6(1)(c) / LGPD Art. 7 II) for fiscal retention |
| Date initiated | 2026-05-13 |
| Target review date | 2026-06-13 |
| Legal frameworks | GDPR Art. 35 + LGPD Art. 38 + CJEU C-311/18 (Schrems II) + GDPR Art. 46(2)(c) SCCs + WP29 WP248rev01 (2017) endorsed by EDPB + ANPD Res. CD/ANPD nº 4/2023 + EDPB Recommendations 01/2020 (supplementary measures) |
| EVT evidence path | `evidence-legal/dpia-s10-billing-cross-border.md` (R2 retain 7y per EVT-045) |

---

## Section 1 — Description of Processing

### 1.1 Processing purpose(s)

S-10 processes billing data to enable usage-based charging for CoreLink services:
1. **Billing metering:** counting API calls, blob storage usage, and DSR operations per tenant.
2. **Payment processing:** Stripe Checkout for subscription and pay-as-you-go plans.
3. **Invoice generation and fiscal compliance:** Brazilian NF-e (Nota Fiscal eletrônica) compliance for BR tenants; EU VAT invoicing.
4. **Billing reconciliation:** 3-layer reconciliation (WI-S10-007) ensuring no billing loss or duplication.

Purpose enum (privacy_model.md §5.6.1): `service_delivery` + `regulatory_compliance`.

### 1.2 Data subjects affected

- **Tenant administrators** responsible for billing (card holder or bank account holder): primary billing contact.
- **Individual users** whose API activity drives usage-based charges: usage data linked to subject_id → tenant billing total.
- **Scale:** all paying tenants + their active users. At GA scale: 1,000–100,000 tenants; 1M+ users whose activity contributes to billing.
- **Geographic spread:** global. Specifically EU/EEA data subjects (GDPR applicable) and Brazilian data subjects (LGPD applicable).

### 1.3 Personal data categories processed

| Data category | Classification | Backend(s) | Retention | Notes |
|---|---|---|---|---|
| Name + email (billing contact) | Ordinary — directly identifying | Stripe Customer object, Neon billing | 7 years (fiscal) | Required for invoicing |
| Payment card data (PAN, expiry, CVV) | Financial — sensitive | Stripe (only; never CoreLink) | Per Stripe PCI-DSS | CoreLink never stores raw card data; tokenized only |
| Stripe Customer ID (tokenized reference) | Ordinary pseudonym | Neon billing, D1 | 7 years | Token only; real card data at Stripe |
| Billing address | Ordinary | Stripe, Neon billing | 7 years | Required for VAT/NF-e |
| Tax ID (CPF/CNPJ for BR; VAT number for EU) | Legally required — sensitive in BR context | Neon billing | 7 years (fiscal) | LGPD Art. 7 II / GDPR Art. 6(1)(c) |
| Usage metering (per-tenant aggregated) | Ordinary | D1 billing tables, Neon billing | 7 years (fiscal) | Aggregate per tenant; not per-user |
| Per-user usage event (subject_id + timestamp + operation) | Ordinary | D1 usage_events | 90 days operational; 7y audit trail pseudonymized | Per WI-S10-007 3-layer reconciliation |
| Stripe webhook events (invoice created/paid/failed) | Ordinary | D1 stripe_idem_keys | 7 years | Idempotency keys |
| Bank transfer details (for EU enterprise invoicing) | Financial | Neon billing (encrypted) | 7 years | GDPR Art. 6(1)(c) / LGPD Art. 7 II |

**No special-category data** processed in billing pipeline.

### 1.4 Data flows

**Cross-border transfer — CRITICAL SECTION:**

1. EU/BR tenant admin enters billing details → Stripe Checkout (Stripe JS hosted; card data never touches CoreLink servers).
2. Stripe creates Customer object in Stripe US → returns Stripe Customer ID to CoreLink.
3. CoreLink stores Stripe Customer ID (token, not card data) in Neon billing (tenant's primary region — weur for EU).
4. Usage metering aggregated in D1 (tenant's primary region).
5. Monthly invoice generation: CoreLink backend calls Stripe API (US-based) → passes invoice line items → Stripe charges card and returns invoice object.
6. **Cross-border transfer:** billing contact name + email + address + tax ID are sent to Stripe US for invoice generation. This constitutes a transfer of personal data from EU/EEA/BR to the United States.
7. Stripe stores billing data in Stripe US infrastructure.
8. CoreLink retains Stripe invoice ID + amount in Neon billing (tenant primary region); full invoice data at Stripe.

**Cross-border transfer summary:**
- **From:** EU/EEA (GDPR) + Brazil (LGPD) → **To:** Stripe Inc., USA
- **Data transferred:** name, email, billing address, tax ID (no payment card PAN — tokenized at Stripe)
- **Legal instrument:** Stripe DPA + EU Standard Contractual Clauses (SCCs) Module 2 (Controller-to-Processor) + Transfer Impact Assessment (see §2.5)

### 1.5 Retention periods

| Data category | Retention | Legal basis |
|---|---|---|
| Billing contact (name, email, address) | 7 years from last transaction | LGPD Art. 16 IV; GDPR Art. 6(1)(c) + fiscal obligations |
| Tax ID (CPF/CNPJ/VAT) | 7 years | Fiscal law (Lei 9.430/1996 BR; EU VAT Directive) |
| Usage events (D1) | 7 years (operational 90d; fiscal 7y archival pseudonymized) | GDPR Art. 6(1)(c); LGPD Art. 7 II |
| Stripe Customer ID | 7 years | Co-terminous with billing relationship |
| Stripe webhook idempotency keys | 7 years | Audit trail; billing reconciliation |

### 1.6 WP29 WP248rev01 high-risk criteria checklist

| Criterion | Met? | Justification |
|---|---|---|
| 1. Evaluation/scoring (profiling) | NO | Billing metering is not profiling |
| 2. Automated decision-making with legal effect | PARTIAL | Automated billing suspension on payment failure has significant effect on service access |
| 3. Systematic monitoring | NO | Billing events only; not systematic behavioral monitoring |
| 4. Sensitive data (special categories) | NO | Tax IDs are sensitive in BR context but not GDPR Art. 9 special category |
| 5. Large-scale processing | YES | All paying tenants + their users at GA scale |
| 6. Matching or combining datasets | NO | Billing data not combined with external datasets |
| 7. Data on vulnerable subjects | NO | Enterprise B2B context; no targeting of vulnerable groups |
| 8. Innovative use or new technology | NO | Stripe is standard payment processor |
| 9. Data transfer outside EU/EEA or BR | YES | Name, email, address, tax ID transferred to Stripe US |

**Criteria count: 2–3/9 — DPIA mandatory** (large-scale + cross-border transfer; partial automated decision-making).

---

## Section 2 — Necessity and Proportionality Assessment

### 2.1 Legal basis

**Contract (GDPR Art. 6(1)(b) / LGPD Art. 7 V):** billing processing is necessary to perform the service contract — without it, CoreLink cannot charge for services and the contract cannot be fulfilled.

**Legal obligation (GDPR Art. 6(1)(c) / LGPD Art. 7 II):** fiscal retention of billing records (7 years) required by Brazilian fiscal law (Lei 9.430/1996, Lei 8.212/1991) and EU VAT law.

### 2.2 Necessity test

Payment processing via Stripe is necessary: CoreLink requires a PCI-DSS-compliant payment processor. Direct card processing would require full PCI-DSS Level 1 audit (cost prohibitive at startup stage; no less intrusive alternative with equivalent compliance posture). Stripe is the industry standard for SaaS billing; alternatives (Adyen, Braintree) would present the same cross-border transfer issue.

### 2.3 Proportionality assessment

- **Data minimization:** CoreLink sends only the minimum data to Stripe required for invoicing (name, email, address, tax ID). No behavioral data, no usage detail beyond invoice line items.
- **Tokenization:** card PAN never stored or transmitted by CoreLink; only Stripe token stored.
- **Storage limitation:** Neon billing tables retain Stripe Customer ID (token) + aggregate amounts; raw invoice data at Stripe per their retention policy.
- **Purpose limitation:** billing data not used for marketing; no cross-purpose data sharing.

### 2.4 Data protection by design measures

| Measure | Implementation |
|---|---|
| Stripe-hosted payment form (no PAN on CoreLink servers) | Stripe.js + Stripe Checkout; card data never touches CoreLink |
| Encryption at rest (Neon billing) | Neon AES-256 encryption at rest; HKDF-derived key for fiscal data |
| DSR erasure integration | Billing tables included in erasure worker 12-backend model (WI-S11-002); Neon billing + D1 backends erased; Stripe Customer deletion via `Customer.update` (GDPR Art. 17 / LGPD Art. 18 IV) |
| INV-DATA-ERASURE-COMPLETE | TLA+ proof in dsr_erasure_atomicity.tla covers Stripe backend as one of 8 effective backends |
| Residency pinning | Neon billing data stored in tenant's primary region; Stripe US-hosted (SCC covered) |
| Audit logging (7y) | EVT-048 billing audit events retained 7y in R2 evidence-* bucket (pseudonymized) |
| 3-layer reconciliation | WI-S10-007 ensures no billing loss or duplication (INV_BILLING_NO_LOSS + INV_BILLING_NO_DUP) |

### 2.5 Sub-processor obligations — Schrems II analysis

**Transfer:** name + email + billing address + tax ID → Stripe Inc., 510 Townsend Street, San Francisco, CA 94103, USA.

**Legal instrument for cross-border transfer (GDPR Chapter V):**

1. **Standard Contractual Clauses (SCCs):** Stripe has published EU SCCs (Module 2: Controller-to-Processor) as part of its DPA. HuGR Labs and Stripe have entered the Stripe DPA (available at stripe.com/legal/dpa) which incorporates the 2021 EU SCCs (Commission Decision 2021/914/EU).

2. **Transfer Impact Assessment (TIA) — Schrems II compliance (CJEU C-311/18):**

   | TIA Factor | Assessment |
   |---|---|
   | Destination country rule-of-law + data protection | USA: CLOUD Act (18 U.S.C. § 2523) creates government access risk. Section 702 FISA applicable to electronic communication service providers. |
   | Nature of data transferred | Name, email, billing address, tax ID — ordinary PII; not sensitive/special category. Low intelligence interest. |
   | Stripe's security measures | Stripe is PCI-DSS Level 1 certified; SOC 2 Type II certified; ISO 27001 certified; employs encryption in transit (TLS 1.3) and at rest (AES-256). |
   | Supplementary measures (EDPB Rec. 01/2020) | (a) **Technical:** data transmitted via TLS 1.3 (encryption in transit); Stripe encrypts at rest; no unencrypted transfer. (b) **Contractual:** Stripe DPA includes government access notification obligation (where legally permissible); Stripe commits to challenging government orders. (c) **Organizational:** Stripe publishes transparency report on government data requests. |
   | EU-US Data Privacy Framework (DPF) | Stripe Inc. is certified under the EU-US Data Privacy Framework (DPF) as of 2023 (certification at dataprivacyframework.gov). This provides an Art. 45 adequacy-equivalent basis for EU→US transfers covered by DPF certification scope. |
   | Brazil → US (LGPD Art. 33 II — controller demonstrates adequate guarantees via SCCs; complementarmente Art. 33 IX c/c Art. 7 V para o vínculo contratual) | LGPD permits cross-border transfer to countries providing adequate protection or where the controller provides adequate guarantees (SCCs per ANPD resolution). Stripe DPA SCCs satisfy this requirement. ANPD has not yet issued a formal adequacy decision for the US; SCCs are the operative instrument. (Lote 10.11.0-ter legal-citation re-validation 2026-05-15 corrigida cite anterior "Art. 33 IV" — IV é "proteção da vida ou da incolumidade física", não o instrumento de garantias adequadas; instrumento correto é Art. 33 II.) |
   | TIA conclusion | Transfer is permissible under GDPR (SCCs + DPF as supplementary basis) and LGPD (SCCs). The ordinary nature of the data (billing PII; not health/political/biometric) reduces the practical risk of government access. Supplementary technical measures (TLS 1.3 + at-rest encryption) further reduce risk. |

3. **CoreLink–Stripe DPA status:** Stripe's DPA is accepted as part of Stripe's Terms of Service (enterprise customers may execute separate DPA); Module 2 SCCs incorporated.

---

## Section 3 — Risk Identification

### 3.1 Risk register

| ID | Threat (LINDDUN) | Description | Likelihood | Severity | Risk Level | Mitigation |
|---|---|---|---|---|---|---|
| R-001 | Disclosure (D) | US government access to billing data via CLOUD Act / Section 702 FISA | LOW | HIGH | MEDIUM | Stripe DPF certification; ordinary PII (low intelligence interest); TLS 1.3 + at-rest encryption; Stripe challenges orders; transparency report |
| R-002 | Non-compliance (N) | Stripe invalidates DPA/SCCs; transfer loses legal basis | LOW | CRITICAL | MEDIUM | Stripe is core infrastructure; immediate replacement not feasible. Monitor Stripe DPF status quarterly. Escalation: data transfer suspension + customer notification if legal basis invalidated |
| R-003 | Disclosure (D) | Stripe data breach exposing billing contact PII | LOW | HIGH | LOW | PCI-DSS L1 + SOC 2 Type II + ISO 27001; card PAN never at CoreLink; limited PII at Stripe (name, email, address only) |
| R-004 | Non-compliance (N) | Incomplete erasure: DSR subject requests deletion but Stripe Customer.update fails silently | LOW | CRITICAL | MEDIUM | Erasure worker (WI-S11-002) includes Stripe as one of 8 effective backends; PAT-RETRY-IDEMPOTENT-001; INV-DATA-ERASURE-COMPLETE TLA+ proof; 24h verification job (EVT-042) |
| R-005 | Identifiability (I) | Tax ID (CPF/CNPJ) is highly identifying in BR context; breach exposes financial identity | LOW | HIGH | LOW | Neon billing field encrypted with HKDF-derived key; access restricted to billing worker service account |
| R-006 | Linkability (L) | Billing data combined with usage events enables inference of user behavior patterns | LOW | LOW | LOW | Usage events stored as aggregate per tenant; per-user detail pseudonymized and kept separate from billing contact data |

---

## Section 4 — Mitigation Measures

### 4.1 Technical mitigations

**R-001 + R-003 (US government access + Stripe breach):**
- TLS 1.3 for all CoreLink → Stripe API calls; mutual TLS for webhook verification (Stripe-Signature header HMAC verification).
- Only minimum billing data sent to Stripe; no usage detail, no behavioral data.
- Card data: Stripe-hosted form; CoreLink never sees PAN.

**R-004 (Incomplete Stripe erasure):**
- Stripe backend in erasure worker: `Customer.update` sets metadata `gdpr_erasure_requested=true` + `Customer.delete` if no active subscriptions; retry with exponential backoff (MaxAttempts=5, PAT-RETRY-IDEMPOTENT-001).
- INV-DATA-ERASURE-COMPLETE (CRITICAL) — TLA+ `dsr_erasure_atomicity.tla` models Stripe as one of 8 effective backends; proof validates all 8 must ack before completion.
- 24h post-erasure verification job (EVT-042) confirms Stripe Customer object deleted.

**R-005 (Tax ID sensitivity):**
- CPF/CNPJ field encrypted at rest in Neon billing using HKDF-derived key (info=`corelink/v1/billing-taxid`).
- Access restricted to billing worker service account + Finance role only.

### 4.2 Organizational mitigations

- Quarterly review of Stripe DPF certification status.
- Annual TIA review (or on material change to Stripe legal status).
- Privacy Officer notification if Stripe receives government data request affecting CoreLink data.
- DPIA re-assessment trigger: any change to billing data schema or new sub-processor.

### 4.3 Contractual / legal mitigations

- **Stripe DPA** (Module 2 SCCs Controller-to-Processor): incorporated in Stripe TOS; covers EU and BR data subjects.
- **DPF basis (EU → US):** Stripe DPF certification (dataprivacyframework.gov) as supplementary adequacy basis alongside SCCs.
- **LGPD Art. 33 II SCCs:** Stripe DPA SCCs satisfy ANPD requirements for cross-border transfer from Brazil (controller demonstrates adequate guarantees). Lote 10.11.0-ter legal-citation re-validation 2026-05-15 corrigida cite anterior "Art. 33 IV" (IV trata de proteção da vida).
- **Stripe government access notification commitment:** documented in Stripe DPA §7 (government requests).
- **WI-S11-007 residency pinning:** Neon billing data stored in tenant.primary_region (weur for EU tenants); only invoice line items transmitted cross-border to Stripe.

### 4.4 Residual risk after mitigation

| Risk ID | Residual Likelihood | Residual Severity | Residual Level | Accepted by |
|---|---|---|---|---|
| R-001 | LOW | MEDIUM | LOW | Privacy Officer (ordinary PII; DPF + SCCs + encryption) |
| R-002 | LOW | HIGH | MEDIUM | Privacy Officer (quarterly monitoring; escalation plan documented) |
| R-003 | LOW | LOW | LOW | Privacy Officer |
| R-004 | LOW | MEDIUM | LOW | Privacy Officer (TLA+ proof + 24h verification mitigates) |
| R-005 | LOW | LOW | LOW | Privacy Officer (field-level encryption) |
| R-006 | LOW | LOW | LOW | Privacy Officer |

---

## Section 5 — Residual Risk Assessment + Sign-off

### 5.1 Overall residual risk assessment

The primary residual risk is R-002 (Stripe DPA/SCCs invalidation) at MEDIUM — mitigated by quarterly monitoring and DPF dual basis. All other risks reduced to LOW. **Overall residual risk: MEDIUM.** Processing may commence. The cross-border transfer is lawful under SCCs + DPF (EU) and SCCs (BR).

### 5.2 Consultation (GDPR Art. 36 / LGPD Art. 38 §3)

Prior supervisory authority consultation is **not required** — residual risk is MEDIUM (not HIGH after mitigation). The SCC + DPF basis provides a well-established legal framework. Revisit if Schrems III invalidates SCCs or DPF.

### 5.3 Sign-off

| Role | Name | Date | Status |
|---|---|---|---|
| Privacy Officer | Gustavo Schneiter (interim) | 2026-05-13 | Pending final sign-off pre-PRR |
| DPO / Encarregado | TBD | TBD | Pending hire |
| Legal (external) | TBD | TBD | **Mandatory — SCC + TIA review** |
| Compliance | TBD | TBD | Pending |

> **EVT-045:** Upload to `evidence-legal/dpia-s10-billing-cross-border.md` (R2 retain 7y) upon first sign-off.
> **EVT-044 LEGAL_REVIEW:** Record upon legal review of SCC + TIA.

---

## Section 6 — Quarterly Review Schedule

| Review cycle | Target date | Trigger condition | Reviewer |
|---|---|---|---|
| Initial | 2026-06-13 | Pre-PRR; Legal review of SCC + TIA | Privacy Officer + Legal |
| Q3 2026 | 2026-09-01 | Quarterly + Stripe DPF status check | Privacy Officer |
| Q4 2026 | 2026-12-01 | Quarterly | Privacy Officer |
| Q1 2027 | 2027-03-01 | Quarterly | Privacy Officer |
| Change-triggered | New billing data category; new sub-processor; Stripe DPA material change | CI hook detect | Privacy Officer |
| Schrems III trigger | On any CJEU/EDPB ruling invalidating SCCs or DPF | Immediate | Privacy Officer + Legal |
| TIA annual review | 2027-05-13 | Annual | Privacy Officer + Legal |

### 6.1 DPIA changelog

| Version | Date | Author | Change summary |
|---|---|---|---|
| 1.0 | 2026-05-13 | Gustavo Schneiter | Initial DPIA — WI-S11-008; SCC + TIA for Stripe US |
