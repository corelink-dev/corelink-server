---
document_type: "sub_processor_commitments"
version: "1.0.0"
effective_date: "2026-05-14"
legal_basis: "GDPR Art. 28(2); LGPD Art. 39 (operador)"
wi_origin: "WI-S20-005"
canonical_compliance_matrix: "specs/03_architecture/compliance_matrix.md"
related_documents:
  - "legal/sub-processors.md"
  - "legal/dpa/v1.0.0.en-US.md"
  - "legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md"
---

# CoreLink Sub-Processor Commitments

> Effective 2026-05-14 · Origin WI-S20-005 · Canonical reference `specs/03_architecture/compliance_matrix.md`.

This document is the authoritative list of CoreLink sub-processors that
receive personal data, with the data-protection commitments flowed down
from CoreLink's DPA (`legal/dpa/v1.0.0.*.md`) and the EU SCCs Module 3
(`legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md`). The operational registry
(YAML, versioned by `legal/sub-processors.md`) is the system of record for
discovery and notification; this document is the legal commitment view.

Customer notification of any addition, replacement, or scope expansion is
provided at least **30 calendar days** in advance per DPA §3.1.

---

## 1. Active sub-processors (S-20 / GA)

### 1.1 Cloudflare, Inc.

| Field | Value |
|---|---|
| Role | Infrastructure provider — Workers, R2, D1, KV, Durable Objects, Pages, Email Routing. |
| Data categories | Account metadata; blob content (encrypted); audit logs; telemetry. |
| Region | R2 objects and jurisdictional Durable Object state are tenant-pinned per `INV-DATA-RESIDENCY` (WNAM / ENAM / WEUR / APAC). The D1 control plane is one shared global database; its primary is currently reported in ENAM with no D1 jurisdiction and automatic read replication. `SAM` is not provisioned and is not promised. |
| DPA reference | <https://www.cloudflare.com/cloudflare-customer-dpa/> |
| Sub-processor list | <https://www.cloudflare.com/sub-processors/> |
| SCCs / transfer mechanism | The repository disclosure describes the shared D1 control plane under SCC/TIA safeguards. This prelaunch record does not establish an executed transfer mechanism or counsel approval. |
| Certifications | SOC 2 Type II; ISO 27001; ISO 27018; PCI-DSS Level 1; HIPAA-compliant infra. |
| Vendor review evidence | `docs/compliance/vendor-reviews/cloudflare-dpa-review-2026-04.md` |
| Contract signed | 2026-04-23 |
| Schrems II TIA | Pending legal review; this record does not represent it as completed or approved. |

### 1.2 Clerk, Inc.

| Field | Value |
|---|---|
| Role | Authentication & identity (email verification, MFA, session management). |
| Data categories | Account email; auth tokens; device metadata; minimal profile. |
| Region | US (primary); EU read-replica for EU tenants. |
| DPA reference | <https://clerk.com/legal/dpa> |
| Sub-processor list | <https://clerk.com/legal/subprocessors> |
| SCCs / transfer mechanism | EU SCCs Module 3 + UK IDTA. |
| Certifications | SOC 2 Type II; ISO 27001 (in progress). |
| Vendor review evidence | `docs/compliance/vendor-reviews/clerk-dpa-review-2026-04.md` |
| Contract signed | 2026-04-23 |
| Schrems II TIA | Completed; flow-down clauses + US-based government-access reporting. |

### 1.3 Stripe, Inc.

| Field | Value |
|---|---|
| Role | Billing, invoicing, payment processing, tax computation. |
| Data categories | Billing entity name and address; tax ID; payment method tokens; invoice line items. |
| Region | US (Stripe primary) with EU sub-processors for EU customers. |
| DPA reference | <https://stripe.com/legal/dpa> |
| Sub-processor list | <https://stripe.com/legal/service-providers> |
| SCCs / transfer mechanism | EU SCCs Module 3; UK IDTA. |
| Certifications | SOC 1 / SOC 2 Type II; PCI-DSS Level 1; ISO 27001. |
| Vendor review evidence | `docs/compliance/vendor-reviews/stripe-dpa-review-2026-04.md` |
| Contract signed | 2026-04-23 |
| Schrems II TIA | Completed; payment-data government-access regime documented. |

### 1.4 Neon, Inc. *(optional / tenant-selectable Postgres)*

| Field | Value |
|---|---|
| Role | Postgres control plane (DSR tickets, account, tenant, billing records). |
| Data categories | Billing data; account data; DSR ticket metadata. |
| Region | US or EU (selectable per tenant). |
| DPA reference | <https://neon.tech/dpa> |
| Sub-processor list | <https://neon.tech/subprocessors> |
| SCCs / transfer mechanism | EU SCCs Module 3 + UK IDTA. |
| Certifications | SOC 2 Type II; ISO 27001; HIPAA-compliant. |
| Vendor review evidence | `docs/compliance/vendor-reviews/neon-dpa-review-2026-04.md` |
| Contract signed | 2026-04-23 |
| Schrems II TIA | Completed; EU-region option satisfies EU data-residency promises. |

---

## 2. Flow-down obligations

Each sub-processor is contractually bound to materially equivalent
protections to those Processor owes Controller under the DPA, including:

1. **Documented instructions** only (GDPR Art. 28(3)(a); LGPD Art. 39).
2. **Confidentiality** of authorised personnel (GDPR Art. 28(3)(b)).
3. **Security measures** appropriate to risk (GDPR Art. 32; LGPD Art. 46).
4. **No engagement of further sub-processors** without advance written
   notice and a right to object.
5. **Assistance with data-subject rights** (GDPR Arts. 12–22; LGPD Art. 18).
6. **Personal-data breach notification** without undue delay so Processor
   can meet the 72-hour Controller-notification SLA.
7. **Return or deletion** of personal data on termination.
8. **Audit rights** (documentary by default; on-site as required by law).
9. **International transfers** governed by EU SCCs Module 3 (or local
   equivalents) and EDPB Recommendations 01/2020 supplementary measures.

The flow-down language is reviewed by Legal Counsel as part of vendor
onboarding (`docs/compliance/vendor-reviews/*.md`).

---

## 3. Schrems II supplementary measures (applied across sub-processors)

1. **Technical.** Encryption in transit (TLS 1.3+) and at rest (AES-256 /
   XChaCha20-Poly1305 for BYOK); per-tenant key separation; data-residency
   pinning; cryptographic erasure NIST SP 800-88 Rev. 1 equivalence.
2. **Organisational.** Vendor security questionnaires renewed annually;
   continuous monitoring (Drata/Vanta); transparency reporting; warrant
   canary; legal challenge of overbroad government requests.
3. **Contractual.** SCCs Module 3 incorporated; flow-down audit, breach
   notification, and DSR-cooperation clauses; commitments documented in
   this file and tracked in `legal/sub-processors.md`.

---

## 4. Process changes and updates

| Action | Notice period | Where tracked |
|---|---|---|
| Add new sub-processor | 30 days written notice | `legal/sub-processors.md` + this document update + customer notification |
| Replace existing sub-processor | 30 days written notice | same |
| Scope expansion (new data categories) | 30 days written notice | same |
| Termination of sub-processor relationship | post-event notification within 30 days | same |

The change-control workflow `.github/workflows/legal-changes-review.yml`
gates all PRs that modify this document.

---

## 5. Compliance mapping

| Framework | This document section |
|---|---|
| GDPR Art. 28(2) (sub-processor engagement) | §§1, 2, 4 |
| GDPR Art. 28(4) (flow-down) | §2 |
| GDPR Art. 32 (TOMs) | §3 |
| GDPR Art. 46 + EDPB 01/2020 | §3 |
| LGPD Art. 39 (operador) | §§1, 2 |
| EU SCCs Module 3 | §§1, 2, 3 |
| SOC 2 CC9.2 (vendor management) | §§1, 4 |

Canonical control IDs catalogued in
`specs/03_architecture/compliance_matrix.md`.

---

*End of sub-processor commitments v1.0.0.*
