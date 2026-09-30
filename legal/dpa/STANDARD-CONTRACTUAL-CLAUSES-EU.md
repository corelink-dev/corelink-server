---
document_type: "scc_reference"
version: "1.0.0"
effective_date: null
historical_source_date: "2026-05-14"
document_status: "PRELAUNCH_INTERNAL_REFERENCE_DRAFT_NOT_INCORPORATED"
legal_basis: "Commission Implementing Decision (EU) 2021/914 of 4 June 2021"
wi_origin: "WI-S20-005"
canonical_compliance_matrix: "specs/03_architecture/compliance_matrix.md"
---

# EU Standard Contractual Clauses — Historical Internal Reference Draft

> PRELAUNCH INTERNAL REFERENCE DRAFT — not executed, not incorporated into a customer DPA, and not operative. Historical source date: 2026-05-14 · Origin: WI-S20-005 · Canonical reference: `specs/03_architecture/compliance_matrix.md`.

This repository copy preserves a historical SCC reference draft for internal
review. It is not a controlling or incorporated customer instrument, no transfer
terms are approved or executed here, and it creates no present commitment. Any
future use requires counsel review, approval of an applicable transfer basis,
and execution by the parties before it can become operative.

## 1. Instrument

- **Instrument:** Annex of Commission Implementing Decision (EU) 2021/914 of
  4 June 2021 on standard contractual clauses for the transfer of personal
  data to third countries pursuant to Regulation (EU) 2016/679.
- **Historical source module proposal:** **Module 2 — Transfer Controller to
  Processor** was listed in the source draft. No module is currently
  incorporated into a customer instrument.
- **Module 3 draft reference:** Processor-to-Processor language was proposed
  for review; no present sub-processor transfer term is established by this
  copy.
- **UK addendum draft reference:** the UK IDTA was identified as a possible
  input for later counsel review; it is not currently applied to a customer
  transfer.
- **Switzerland draft reference:** the source noted the Swiss FDPIC approach
  for future legal review; it creates no current transfer term.

## 2. Optional clauses elected

| Clause | Election | Notes |
|---|---|---|
| **7 (Docking clause)** | Historical proposal only | No clause election is currently effective. |
| **9(a) (general written authorisation for sub-processors)** | Historical proposal only | No authorization or notice term is currently effective. |
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
  negotiated where supported). The configured object-storage source uses
  provider-managed R2 encryption. BYOK and per-tenant customer-managed keys are
  future design only, not active launch controls.
- Confidentiality, integrity, availability, and resilience of processing
  systems (multi-region active-active; PAT-REGION-FAILOVER-001).
- Restoration of availability after an incident (RTO/RPO per
  `specs/03_architecture/resilience_patterns.md`).
- Process for regularly testing, assessing, and evaluating effectiveness
  (annual external pentest; weekly chaos drills; continuous monitoring via
  Drata/Vanta).
- User access management (RBAC + MFA admin plane + dual-approval for
  destructive operations).
- Logging and audit-integrity controls. Production R2 Object Lock COMPLIANCE
  retention and seven-year storage-enforced immutability are unavailable or
  unproven; no such guarantee is made here.
- Personnel screening and confidentiality undertakings.
- Sub-processor management per Clause 9 and DPA §3.

## 5. Annex III — List of sub-processors

The historical source referred to a proposed sub-processor list; this copy does not authorize any sub-processor or establish an effective date. See the separate owner-maintained vendor register for its own current status.
`legal/sub-processors.md`. Per-sub-processor commitments are at
`legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`. Notification of changes is per
DPA §3.1 (30-day prior written notice).

## 6. Government access requests (Schrems II supplementary measures)

Per EDPB Recommendations 01/2020 and the CJEU judgment in *Schrems II*
(C-311/18), HuGR Labs implements supplementary measures including:

- **Technical:** available transport and storage controls described in the
  current source. BYOK, tenant-scoped customer-managed roots, and cryptographic
  erasure are not active controls. Regional R2/DO paths do not establish the
  placement or transfer basis of the shared D1 control plane.
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
