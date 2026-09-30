---
id: "BREACH-TMPL-GDPR-IRISH-DPC-EN"
type: "breach_notification_template"
doc_status: "DRAFT"
jurisdiction: "EU"
authority: "Irish DPC"
language: "en"
legal_basis: "GDPR Art. 33 + EDPB Guidelines 9/2022"
version: "1.0.0"
created: "2026-05-13"
owner: "Privacy Officer (Gustavo Schneiter interim)"
legal_review_status: "PENDING"
legal_review_evt_044_path: "r2://evidence-legal/breach-notification/gdpr-irish-dpc-template-legal-review.pdf"
privacy_officer_review: false
template_variables:
  - "{{breach_id}}"
  - "{{breach_detected_at}}"
  - "{{data_categories_affected}}"
  - "{{count_subjects_affected}}"
  - "{{containment_actions}}"
  - "{{mitigation_offered}}"
  - "{{contact_email}}"
  - "{{breach_severity}}"
---

# Personal Data Breach Notification to the Irish Data Protection Commission
## (Pursuant to GDPR Article 33 + EDPB Guidelines 9/2022)

**COMPLETION INSTRUCTIONS**: This is a pre-drafted template. Before sending:
1. Complete ALL `{{...}}` variables with actual incident data.
2. Remove these completion instructions.
3. Review with external Legal counsel (≤ 2h additional buffer).
4. Submit via: https://www.dataprotection.ie/en/organisations/data-security/personal-data-breaches
5. Emit audit event `breach.notification_dispatched.v1` post-dispatch.

---

**SUBJECT**: Personal Data Breach Notification — Reference `{{breach_id}}`

---

**TO**: Data Protection Commission of Ireland (Lead Supervisory Authority)
**FROM**: HuGR Labs (Controller)
**DATE OF NOTIFICATION**: *(fill with dispatch date/time)*
**INCIDENT REFERENCE**: `{{breach_id}}`
**SEVERITY CLASSIFICATION**: `{{breach_severity}}`

---

## Article 33(3)(a) — Nature of the Personal Data Breach

On `{{breach_detected_at}}` (UTC), HuGR Labs became aware of a personal data breach as defined under GDPR Article 4(12): a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data transmitted, stored or otherwise processed.

**Type of breach** (tick all that apply):
- [ ] Confidentiality breach (unauthorised disclosure or access)
- [ ] Integrity breach (unauthorised or accidental alteration)
- [ ] Availability breach (accidental or unauthorised loss of access to or destruction of personal data)

**Description of incident**: *(provide a factual, non-speculative description of how the breach occurred)*

**How the breach was discovered**: *(automated alert / user report / internal monitoring / third-party notification)*

**Timeline**:
| Event | Date/Time (UTC) |
|---|---|
| Breach occurred (estimated) | *(fill)* |
| Breach detected | `{{breach_detected_at}}` |
| Breach declared internally | *(fill)* |
| This notification submitted | *(fill)* |

---

## Article 33(3)(b) — Categories and Approximate Number of Data Subjects Concerned

**Categories of data subjects affected**: *(e.g., CoreLink platform users / business customers / employees)*

**Approximate number of data subjects concerned**: `{{count_subjects_affected}}`

---

## Article 33(3)(c) — Categories and Approximate Number of Records Concerned

**Categories of personal data affected**:

`{{data_categories_affected}}`

*(examples: names, email addresses, usage metadata, cache keys, WebAuthn public keys, billing information)*

**Special categories of personal data** (Article 9) involved: *(Yes/No — specify if applicable)*

**Approximate number of records concerned**: *(fill)*

---

## Article 33(3)(d) — Likely Consequences of the Breach

*(Describe the likely consequences for data subjects, including the nature of the risks posed — e.g., identity theft, financial loss, discrimination, reputational damage, loss of confidentiality)*

**Risk assessment for data subjects**: *(High / Medium / Low — with justification)*

**Cross-border dimension**: *(confirm whether the breach affects data subjects in multiple EU member states; if yes, confirm that Irish DPC is the Lead Supervisory Authority per GDPR Art. 56 — HuGR Labs' EU main establishment is in Ireland)*

---

## Article 33(3)(e) — Measures Taken or Proposed to Address the Breach

**Technical security measures in place at time of breach**:
- Encryption at rest (INV-CONF-AT-REST: R2 SSE-S3, D1/Neon server-side encryption).
- TLS 1.2 floor on all endpoints, 1.3 negotiated by every capable client (INV-CONF-IN-FLIGHT; ADR-0072).
- Current audit-integrity controls must be verified for the incident. Production R2 Object Lock COMPLIANCE retention and a seven-year storage-enforced guarantee are not established; do not state them without fresh target-bound evidence.
- Tenant isolation enforced at infrastructure level (INV-TENANT-ISOLATION).

**Containment measures applied**:

`{{containment_actions}}`

**Remediation and mitigation measures**:

`{{mitigation_offered}}`

---

## Communication to Data Subjects

**Has communication been made to data subjects?** *(Yes / No / Planned)*

*If YES*: Date of communication: *(fill)*; Channel: *(email / status page / both)*

*If NO*: Justification: *(GDPR Art. 34(3)(a)-(c) exemption — specify which applies — OR provide planned date)*

**Under GDPR Art. 34, we assess that this breach** *(is likely / is not likely)* **to result in a high risk to the rights and freedoms of natural persons** because: *(provide reasoning)*

---

## Article 33(5) — Documentation

HuGR Labs has documented this breach, the facts relating to it, its effects and the remedial action taken, in accordance with Article 33(5). Internal reference: `{{breach_id}}`. Documentation retained for ≥ 7 years per LGPD Art. 16 + SOC 2 CC7.4 alignment.

---

## Controller Details and Data Protection Officer

| Field | Value |
|---|---|
| **Controller** | HuGR Labs |
| **EU Representative** | *(to be confirmed — DPO interim handles; formal EU rep per GDPR Art. 27 pre-GA)* |
| **Data Protection Officer** | Gustavo Schneiter (interim — see compliance_matrix.md §9 GAP-01 for DPO hire timeline) |
| **DPO Email** | `{{contact_email}}` |
| **DPO Availability** | 24/7 for matters related to this breach |

---

*This notification is submitted pursuant to GDPR Article 33 and the EDPB Guidelines 09/2022 on personal data breach notification under GDPR. The Irish Data Protection Commission is the Lead Supervisory Authority for HuGR Labs' EU processing activities.*

*Breach reference for audit purposes: `{{breach_id}}`*
