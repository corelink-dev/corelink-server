---
document_type: "scc_reference"
version: "1.0.0"
effective_date: "2026-05-14"
legal_basis: "Commission Implementing Decision (EU) 2021/914 of 4 June 2021"
wi_origin: "WI-S20-005"
canonical_compliance_matrix: "specs/03_architecture/compliance_matrix.md"
---

# EU Standard Contractual Clauses — Reference

> Effective: 2026-05-14 · Origin: WI-S20-005 · Canonical reference: `specs/03_architecture/compliance_matrix.md`.

This document is the controlling reference for the EU Standard Contractual
Clauses ("**SCCs**") incorporated by reference into the CoreLink Data
Processing Agreement (DPA v1.0.0) for international transfers of personal
data under GDPR Art. 46.

## 1. Instrument

- **Instrument:** Annex of Commission Implementing Decision (EU) 2021/914 of
  4 June 2021 on standard contractual clauses for the transfer of personal
  data to third countries pursuant to Regulation (EU) 2016/679.
- **Module incorporated:** **Module 2 — Transfer Controller to Processor**
  (Controller = customer; Processor = HuGR Labs).
- **Module 3 — Processor to Processor** applies between HuGR Labs and any
  sub-processor listed in `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md` that
  receives personal data outside the EEA.
- **UK addendum:** UK International Data Transfer Addendum to the EU
  Commission SCCs ("**UK IDTA**") issued by the ICO, version B1.0, applies
  to transfers subject to the UK GDPR.
- **Switzerland:** the SCCs are read in the manner published by the Swiss
  FDPIC for transfers subject to the revised FADP.

## 2. Optional clauses elected

| Clause | Election | Notes |
|---|---|---|
| **7 (Docking clause)** | **Elected** | Permits additional Controllers to accede. |
| **9(a) (general written authorisation for sub-processors)** | **Elected — Option 2** | 30-day prior written notice per DPA §3.1. |
| **11(a) (independent dispute resolution body)** | **Not elected** | Standard supervisory authority + court remedy applies. |
| **17 (governing law)** | Republic of Ireland | EU jurisdiction with developed data-protection case law. |
| **18 (choice of forum and jurisdiction)** | Courts of Ireland | Member State courts of the data subject's habitual residence remain available. |

## 3. Annex I — Description of the transfer

### A. List of Parties

- **Data exporter:** the customer ("Controller"), as identified in the master
  agreement.
- **Data importer:** HuGR Labs ("Processor"), operating the CoreLink service.
  Contact: privacy@humangr.com. DPO: dpo@humangr.com.

### B. Description of the transfer

| Item | Value |
|---|---|
| Categories of data subjects | Customer's employees, contractors, and end-users; any natural persons whose personal data the Controller chooses to process via CoreLink. |
| Categories of personal data | Object metadata; access tokens (Argon2id-hashed); audit-chain events; billing records; DSR metadata; end-user PII as placed by Controller. |
| Special categories | None by design. Excluded unless Controller obtains prior written authorisation and provides a TIA. |
| Frequency of transfer | Continuous (on-demand transfers via API). |
| Nature of processing | Storage, retrieval, deduplication, integrity verification, audit logging, DSR fulfilment. |
| Purpose | Delivery of the CoreLink shared content-addressable cache service. |
| Retention | Per DPA §5. |
| Sub-processor transfers | Per `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`. |

### C. Competent supervisory authority

The **Irish Data Protection Commission** (DPC) acts as the lead supervisory
authority for the purposes of these Clauses, without prejudice to the
competence of other EU/EEA supervisory authorities under Article 56 GDPR
where applicable.

## 4. Annex II — Technical and organisational measures

The TOMs required under Clause 8.6 and Annex II are described in DPA §8 and
`specs/03_architecture/security_model.md`. Highlights:

- Pseudonymisation and encryption in transit (TLS 1.2 minimum; TLS 1.3
  negotiated where supported). At-rest encryption uses AES-256/XChaCha20-Poly1305
  for BYOK; per-tenant key separation; Enterprise BYOK.
- Confidentiality, integrity, availability, and resilience of processing
  systems (multi-region active-active; PAT-REGION-FAILOVER-001).
- Restoration of availability after an incident (RTO/RPO per
  `specs/03_architecture/resilience_patterns.md`).
- Process for regularly testing, assessing, and evaluating effectiveness
  (annual external pentest; weekly chaos drills; continuous monitoring via
  Drata/Vanta).
- User access management (RBAC + MFA admin plane + dual-approval for
  destructive operations).
- Logging and audit-chain immutability (R2 Object Lock, 7-year retention,
  INV-AUDIT-IMMUTABLE).
- Personnel screening and confidentiality undertakings.
- Sub-processor management per Clause 9 and DPA §3.

## 5. Annex III — List of sub-processors

The list of sub-processors authorised at the effective date is at
`legal/sub-processors.md`. Per-sub-processor commitments are at
`legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`. Notification of changes is per
DPA §3.1 (30-day prior written notice).

## 6. Government access requests (Schrems II supplementary measures)

Per EDPB Recommendations 01/2020 and the CJEU judgment in *Schrems II*
(C-311/18), HuGR Labs implements supplementary measures including:

- **Technical:** end-to-end encryption with tenant-scoped keys; BYOK with
  Enterprise customer-managed roots; data-residency pinning per
  `INV-DATA-RESIDENCY`; cryptographic erasure NIST SP 800-88 Rev. 1
  equivalence.
- **Organisational:** challenge of overbroad government requests through
  legal counsel; transparency reporting; warrant-canary publication; staff
  training on US Cloud Act and FISA 702 implications.
- **Contractual:** flow-down obligations in the SCCs Module 3 to all
  sub-processors; commitments in `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`.

## 7. Signature

The Parties signify acceptance of the SCCs by executing the underlying
master agreement and this DPA reference. Updates to the SCCs will follow
the change-control workflow `.github/workflows/legal-changes-review.yml`
and the runbook `specs/_runbooks/RB-DPA-CHANGE.md`.

## 8. Compliance mapping

| Reference | Section |
|---|---|
| Decision (EU) 2021/914 | §§1, 2, 3 |
| EDPB Recommendations 01/2020 | §6 |
| UK IDTA (ICO, version B1.0) | §1 |
| Swiss FADP (revised) | §1 |
| GDPR Art. 46 | §§1, 6 |

Canonical control IDs are catalogued in
`specs/03_architecture/compliance_matrix.md`.

---

*End of EU SCC reference v1.0.0.*
