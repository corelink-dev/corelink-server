---
id: "SALES-SIG-LITE-2026-PREFILLED"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.1.0"
created: "2026-05-15"
updated: "2026-08-02"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "R-PREP-SALES-ENABLEMENT"
tags: ["sales", "legal", "questionnaire", "sig-lite", "shared-assessments", "procurement", "r-prep", "ga"]
---

# SIG Lite 2026 — CoreLink Pre-Filled Response

> **Audience:** CoreLink CS / SE running an enterprise SIG Lite response cycle. Fill the prospect's actual SIG Lite workbook with the canonical answers below. Every answer is sourced to a concrete artifact in this repo or the Trust Center.
>
> **Source standard:** Shared Assessments SIG Lite 2026 (mapped to ISO/IEC 27002:2022 + NIST CSF 2.0 + AICPA TSC 2017). SIG Lite covers ~130 questions across 14 control categories (A–N). The structure below mirrors the workbook one-to-one.
>
> **Scoping caveats (read first):**
> - CoreLink is **SOC 2 Type I target Q4-2026** (fieldwork; report Q1-2027) — we have **not** yet issued a Type I report. Readiness is 83.7% weighted, 96.4% green on Drata as of 2026-05-15 (`specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`).
> - CoreLink is **ISO 27001:2022 target Q1-2027** — 98.9% in-scope Annex A coverage on internal crosswalk, certificate not yet issued (`apps/docs/docs/trust/iso27001.mdx`).
> - CoreLink is **PCI DSS SAQ-A self-attested 2026-05-15** — not externally audited; Stripe (PCI L1 Service Provider) handles all CHD (`specs/_compliance/PCI-DSS-SAQ-A-2026-05-15.md`).
> - CoreLink does **not** claim FedRAMP, HIPAA BAA, or any government certification. Crosswalk to NIST 800-53 Rev 5 Moderate available on request (`specs/_compliance/FEDRAMP-MODERATE-CROSSWALK-2026-05-15.md`); not a substitute for ATO.
>
> **Evidence delivery:** all NDA-gated artifacts route via `trust@humangr.com` within 1 business day of countersigned NDA.
>
> **Companion docs:** `CAIQ-V4-pre-filled.md`, `VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md`, `EVIDENCE-PACK-INDEX.md`, `RESPONSE-SLA-POLICY.md`.

---

## How to use this file

1. Open the prospect's SIG Lite workbook (`.xlsx`).
2. For each row, copy the answer column verbatim from the matching row below. Paraphrase only if the prospect's question wording is materially narrower.
3. For every "Yes" answer, the **Evidence** column points to the canonical artifact. Bundle those into the response pack per `EVIDENCE-PACK-INDEX.md`.
4. For every "Partial" or "Compensating Control" answer, the rationale + remediation ETA is explicit. Do not soften.
5. Target turnaround: **5 business days** for full SIG Lite (`RESPONSE-SLA-POLICY.md`).

Legend:

- **Y** = Yes, implemented and evidenced.
- **P** = Partial — control exists; full evidence pending (GAP closure ETA stated).
- **CC** = Compensating Control — primary control N/A; equivalent control documented.
- **N/A** = Not applicable (scoping reason stated).
- **N** = No (rare; rationale always stated).

---

## A. Risk Management (8 questions)

| # | Question (canonical SIG Lite paraphrase) | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| A.1 | Do you maintain a formal information security risk-management program? | Y | Yes. Quarterly risk register reviewed by Founder + VP-Sec; methodology in `specs/_compliance/VENDOR-RISK-METHODOLOGY.md` and applied to 19 vendors in `specs/_compliance/VENDOR-RISK-REGISTER.md`. Internal threat model + STRIDE matrix at `specs/_audits/matrix-stride-ctrl.csv`. | `specs/_compliance/VENDOR-RISK-METHODOLOGY.md`; `specs/_compliance/VENDOR-RISK-REGISTER.md`; `specs/03_architecture/failure_modes.md` |
| A.2 | Is your risk assessment performed at least annually? | Y | Yes — quarterly cadence for Critical vendors; biannual for Important; annual for Standard. Operational runbook `specs/_runbooks/RB-VENDOR-RISK-QUARTERLY-REVIEW.md`. Next full register refresh 2026-08-15. | `specs/_compliance/VENDOR-RISK-REGISTER.md` §1 |
| A.3 | Do you maintain an issue/exception/waiver register? | Y | Yes — 33-GAP register in `specs/_compliance/SOC2-GAP-ANALYSIS.md` with severity, owner, ETA. Waiver pattern `WAIVER-YYYYMMDD-NNN` enforced by `scripts/validate_references.py`. Top-5 GAPs published in SOC 2 evidence rollup §3.4. | `specs/_compliance/SOC2-GAP-ANALYSIS.md`; `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md` §3.4 |
| A.4 | Have you completed a third-party risk assessment / pentest in the last 12 months? | P | **No external pentest has been contracted or completed.** Internal adversarial-review summaries + cargo-fuzz evidence are available at `specs/_audits/sealed/2026-05-14-cargo-fuzz-summary-s15.md`; an external pentest is only scoped as future R-6 staging-bake work (T-30d pre-GA). | `specs/_audits/sealed/2026-05-14-cargo-fuzz-summary-s15.md`; `apps/docs/docs/trust/index.mdx` |
| A.5 | Do you carry cyber-liability insurance? | P | Founder-stage; broker engagement scheduled Q3-2026 with ≥ $5M aggregate target. Evidence available on award of contract. | Available on request at `trust@humangr.com` |
| A.6 | Is there an executive sponsor accountable for information security? | Y | Yes — Founder + VP-Sec (Gustavo Schneiter, 13-role sign-off model documented in `specs/_governance/`). DPO appointment per `specs/_compliance/DPO-APPOINTMENT-2026-05-15.md`. | `specs/_compliance/DPO-APPOINTMENT-2026-05-15.md`; `specs/_governance/` |
| A.7 | Do you align to a published security framework (NIST CSF, ISO 27001, CIS)? | Y | Aligned to AICPA TSC 2017+2022 PoF (SOC 2 target Q4-2026) and ISO/IEC 27001:2022 (cert target Q1-2027; 98.9% in-scope Annex A coverage on internal crosswalk). NIST 800-53 Rev 5 Moderate crosswalk informational. | `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`; `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md`; `apps/docs/docs/trust/iso27001.mdx` |
| A.8 | Do you have a continuous compliance / GRC platform? | Y | Yes — Drata. 6 EvidenceStream variants; 90.7% strict auto-collection; 96.4% green; weekly digest landed 2026-05-15. | `specs/_compliance/DRATA-INTEGRATION-COVERAGE.md`; `specs/_compliance/weekly-digests/` |

## B. Security Policy (6 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| B.1 | Do you maintain a formally documented information security policy? | Y | Yes — distributed across `specs/03_architecture/security_model.md` (CTRL catalog), `specs/03_architecture/privacy_model.md` (CTRL-PRIV catalog), `specs/03_architecture/compliance_matrix.md` (framework crosswalk). All version-controlled in `HuGR-dev/corelink-server` (private). | `specs/03_architecture/security_model.md`; `specs/03_architecture/compliance_matrix.md` |
| B.2 | Is the policy reviewed and approved at least annually? | Y | Yes — `quarterly-legal-review-template.md` cadence; sprint-contract sign-off model. Next full review 2026-Q3. | `legal/quarterly-legal-review-template.md` |
| B.3 | Is the policy communicated to all personnel? | Y | All personnel sign DCO + Code of Conduct on onboarding (`CODE_OF_CONDUCT.md` + DCO line on every commit, CI-enforced via `.github/workflows/dco-check.yml`). OSS licensing under `LICENSE-APACHE-2.0` + `LICENSE-MIT`. Internal-comms via sprint-contract distribution. | `CODE_OF_CONDUCT.md`; `.github/workflows/dco-check.yml`; commit `44cdf15` |
| B.4 | Do you maintain acceptable-use policies? | P | Currently informal (covered by Code of Conduct + sprint contracts); standalone signed Acceptable Use Policy is **GAP-ISO-02** (closes T+1m, before Q4-2026 Stage 1 ISO audit). | `specs/_compliance/ISO27001-GAP-ANALYSIS.md` GAP-ISO-02 |
| B.5 | Do you have a documented exception process? | Y | Yes — `WAIVER-YYYYMMDD-NNN` pattern; explicit expiry; `validate_references.py` enforces ID format. Fallback ADRs documented per WI (e.g., `WI-S20-003 §5.2`). | `scripts/validate_references.py`; SOC 2 rollup §3.3 fallback ADR |
| B.6 | Does your security policy address mobile / remote-work scenarios? | P | Remote-first organization. Clear-desk / clear-screen policy is **GAP-ISO-06** (closes T+1m). MDM-lite documentation **GAP-ISO-07** (closes T+3m). | `specs/_compliance/ISO27001-GAP-ANALYSIS.md` GAP-ISO-06, GAP-ISO-07 |

## C. Organizational Security (6 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| C.1 | Do you have a designated CISO / security lead? | Y | Yes — Founder + VP-Sec (Gustavo Schneiter). 13-role sign-off matrix in `specs/_governance/`. | `specs/_governance/` |
| C.2 | Is there a designated Data Protection Officer? | Y | Yes — DPO appointed 2026-05-15 (`specs/_compliance/DPO-APPOINTMENT-2026-05-15.md`); contact `dpo@humangr.com`. Responsibilities matrix `specs/_compliance/DPO-RESPONSIBILITIES-MATRIX.md`. | `specs/_compliance/DPO-APPOINTMENT-2026-05-15.md`; `specs/_compliance/DPO-RESPONSIBILITIES-MATRIX.md` |
| C.3 | Are security responsibilities documented at the role level? | Y | Yes — sprint-contract §5.1 sign-off model; WI frontmatter (`assignee`/`owner`/`final_approver`/`reviewers`) validated via `scripts/validate_specs.py`. | `scripts/validate_specs.py`; `specs/04_sprints/` |
| C.4 | Do you maintain a segregation-of-duties model? | Y | Dual-approval pattern `PAT-DUAL-APPROVAL-001` for destructive operations; GitHub branch protection; signed-deploy pipeline. | `specs/03_architecture/security_model.md` PAT-DUAL-APPROVAL-001; SOC 2 rollup §2.8 (CC8.1) |
| C.5 | Do you contract with external legal / compliance counsel? | Y | Yes — external counsel engagement per `legal/legal-externo-engagement-contract.md`. Three DPA locales (EN-EU+UK, PT-BR, ES-LATAM) reviewed by external counsel. | `legal/legal-externo-engagement-contract.md`; `legal/dpa/v1.0.0` |
| C.6 | Are advisors / board members under NDA? | P | Advisor-pool formalization in progress — **GAP-04** in SOC 2 rollup §2.1 (CC1.2); advisor-pool doc planned under `specs/_governance/` (not yet published). Today: per-advisor NDA at engagement; CVs reviewed annually. | SOC 2 rollup §2.1 (CC1.2); GAP-04 |

## D. Asset Management (8 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| D.1 | Do you maintain a formal asset inventory? | P | Drata asset inventory active; formal asset register (ISO-grade) is **GAP-ISO-01** (closes T+1m before ISO Stage 1). | `specs/_compliance/DRATA-INTEGRATION-COVERAGE.md`; GAP-ISO-01 |
| D.2 | Is each asset assigned an owner? | Y | All WIs, runbooks, ADRs frontmatter-bound to a single `owner` + `final_approver`. CI-enforced by `scripts/validate_specs.py`. | `scripts/validate_specs.py` |
| D.3 | Are assets classified by sensitivity / criticality? | Y | Data classes documented at `apps/docs/docs/trust/data-handling.mdx#what-we-store`: 8 data classes mapped to storage substrate + retention. | `apps/docs/docs/trust/data-handling.mdx` |
| D.4 | Do you maintain a data inventory / data flow map? | Y | High-level data flow at `apps/docs/docs/trust/data-handling.mdx#customer-data-flow-high-level`. Detailed crate-level data model at `specs/03_architecture/data_model.md` + storage semantics at `specs/03_architecture/storage_semantics_matrix.md`. ROPA at `specs/_compliance/LGPD-ROPA-2026-05-15.md`. | `apps/docs/docs/trust/data-handling.mdx`; `specs/_compliance/LGPD-ROPA-2026-05-15.md`; `specs/03_architecture/data_model.md` |
| D.5 | Are removable media and BYO devices governed? | CC | Remote-first; no removable-media transit of customer data (all storage cloud-side). MDM-lite documentation **GAP-ISO-07** (closes T+3m). | GAP-ISO-07 |
| D.6 | Are licenses (OSS + commercial) tracked? | Y | OSS license allowlist enforced in CI by `.github/workflows/license-policy.yml` (green, 28 runs) + CycloneDX SBOM at `.sbom/`. `LICENSE-APACHE-2.0` (code) + `LICENSE-MIT` (selected) + OSS matrix landed 2026-05-15 (commit `44cdf15`). Dependency-Track ingestion is wired but not yet operating (see D.7). | `LICENSE-APACHE-2.0`; commit `44cdf15`; `.github/workflows/license-policy.yml`; ADR-0024 |
| D.7 | Do you maintain a software bill of materials (SBOM)? | P | CycloneDX 1.6 SBOM maintained in-repo and shared under NDA: `.sbom/cyclonedx-rust.json` (413 components) + admin-ui (50) + docs (25), generated 2026-05-28. It is **not** published per release and **not** signed — the release-attachment job has never completed green, and there are no Cosign signatures, no Rekor entries and no SLSA attestation today (roadmap). Public integrity evidence = per-binary SHA-256 checksums on CLI releases. | `.sbom/cyclonedx-rust.json` (NDA); `https://github.com/HuGR-Labs/corelink-cli/releases/download/v0.1.1/checksums.txt`; `EVIDENCE-PACK-INDEX.md` §1.1 |
| D.8 | Are media-disposal / data-destruction procedures documented? | Y | Verifiable erasure workflow: `INV-DATA-ERASURE-COMPLETE` + `INV-ERASURE-ATTESTATION-SIGNED` + salt-rotation pattern `ADR-S11-003`. 35-day backup tombstone window. | `apps/docs/docs/trust/data-handling.mdx#right-to-erasure`; ADR-S11-003 |

## E. HR Security (6 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| E.1 | Are background checks performed at hire? | P | Practice in place for employees + contractors; formal documented procedure consolidated under HR-policy refresh Q3-2026. Available on award. | Available on request at `trust@humangr.com` |
| E.2 | Do you maintain confidentiality / NDA agreements? | Y | All personnel sign NDA at onboarding; per-advisor NDA at engagement (advisor-pool consolidation pending — GAP-04). Customer-facing DPA at `legal/dpa/v1.0.0`. | `specs/_governance/`; `legal/dpa/v1.0.0` |
| E.3 | Is security-awareness training provided at hire + annually? | P | Drata-tracked attestation (employee-attestation tracker is one of Drata's modules — see vendor row 7 in VRR). Annual refresh cadence in place. | `specs/_compliance/VENDOR-RISK-REGISTER.md` row 7 |
| E.4 | Are role-based training tracks defined (eng, privacy, support)? | P | Role-based competence matrix planned T+3m — **GAP-05** in SOC 2 rollup §2.1 (CC1.4). | SOC 2 rollup CC1.4; GAP-05 |
| E.5 | Are termination procedures documented (access revocation, asset return)? | P | Signed offboarding checklist standalone is **GAP-ISO-05** (closes T+2m, before Stage 1). Today: Clerk de-provisioning at access removal; same-day GitHub revocation. | GAP-ISO-05 |
| E.6 | Is access reviewed when personnel change roles? | Y | Clerk RBAC + access reviews (`CC6.3`). Quarterly access-review cadence target (automation pending — **GAP-01**). | SOC 2 rollup §2.6 (CC6.3) |

## F. Physical & Environmental Security (4 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| F.1 | Are physical access controls in place at data center locations? | CC | CoreLink **operates no owned data centers or offices**. The served product's compute and storage are hosted by Cloudflare; AWS / GCP / Azure are prospective customer-side BYOK KMS providers, not evidenced data hosts. Physical controls are inherited from the actual hosting provider, referenced in `legal/sub-processors.md`. | `legal/sub-processors.md`; ISO 27001 page §"What we'll formally certify (vs what's inherited)" |
| F.2 | Are visitor logs maintained at facilities? | N/A | No owned facilities. Remote-first organization. | `apps/docs/docs/trust/iso27001.mdx` (A.7.3, A.7.6 marked N/A) |
| F.3 | Are environmental controls (fire, HVAC, power) documented? | CC | Inherited from the served product's Cloudflare hosting provider; prospective customer-side KMS providers are not asserted as current data hosts. | `legal/sub-processors.md` |
| F.4 | Is a secure-disposal procedure documented for physical media? | N/A | CoreLink holds no physical media in scope. Cloud substrate disposal is inherited from sub-processors. | `legal/sub-processors.md` |

## G. Communications & Operations Management (12 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| G.1 | Are operational procedures documented? | Y | 60+ runbooks under VCS at `specs/_runbooks/RB-*.md`. SOC 2 rollup §2.5 (CC5.3). | `specs/05_quality/runbooks/`; SOC 2 rollup §2.5 |
| G.2 | Is change management formally controlled? | Y | GitHub branch protection + `PAT-DUAL-APPROVAL-001` + signed-deploy pipeline + sprint-contract §5.1 sign-off. Rust changes are covered by the paths-scoped clippy/test, cargo-audit and cargo-deny PR lanes; CodeQL is nightly/on demand and Semgrep is dispatch-only, so neither is claimed as an every-PR gate here. | SOC 2 rollup §2.8 (CC8.1) |
| G.3 | Are dev / staging / prod environments separated? | Y | Cloudflare Workers + Pages: staging tenant isolated from production tenant; R-6 staging-bake gate enforces 30-day soak. | `specs/_compliance/GA-GATE-CRITERIA.md` |
| G.4 | Is capacity / performance monitored? | Y | SLO catalog `specs/03_architecture/slo_catalog.md` + chaos region-outage drill + DASH-GA-READINESS dashboard. | SOC 2 rollup §2.10 (A1.1) |
| G.5 | Are backups performed and tested? | Y | Backups encrypted same envelope as source. **Cold-restore drill sealed** (DR-15, `specs/_compliance/COLD-RESTORE-DRILL-SPEC.md` + `specs/_runbooks/RB-COLD-RESTORE-FROM-ZERO.md`); first dry-run T-30d pre-GA. **Active-region warm failover** sealed (DR-16, RTO ≤ 15min / RPO ≤ 5min). | `specs/_compliance/COLD-RESTORE-DRILL-SPEC.md`; `specs/_compliance/ACTIVE-FAILOVER-DRILL-SPEC.md`; `specs/_compliance/BCP-DR-DRILL-CADENCE.md` |
| G.6 | Are audit logs maintained, protected, reviewed? | Y | Append-only BLAKE3 hash-chained audit log (`INV-AUDIT-APPEND-ONLY`, `INV-OBS-AUDIT-CHAIN-INTEGRITY`). Daily fail-closed chain verifier; sealed-chain chunks archived offsite to R2. 7-year retention. Verify offline by replaying the chain. | `apps/docs/docs/trust/data-handling.mdx`; SOC 2 rollup §2.12 (PI1.2) |
| G.7 | Is network security monitored (IDS/IPS, WAF)? | P | Cloudflare WAF + Access + mTLS edge-to-origin + per-tenant DO namespace. OWASP CRS 4.0 upgrade is **GAP-10** (compensating: immutable Workers). | SOC 2 rollup §2.6 (CC6.6) |
| G.8 | Are anti-malware controls in place? | CC | Edge workload (V8 isolates) — no persistent runtime; not a traditional anti-malware surface. Defense-in-depth via in-repo SBOM, Dependency-Track, log-redaction (PII/PAN). | `crates/corelink-logpush/tests/pii_redaction_100k_synthetic.rs` |
| G.9 | Is patch management automated for OS / runtime? | Y | Cloudflare-managed runtime; CoreLink crates are covered by pull-request tests and the daily `cargo-deny` advisory/policy lane. Dependency-Track ingestion is wired but not operating as a live daily scanner. | `.github/workflows/cargo-deny.yml`; ADR-0024 Dependency-Track |
| G.10 | Are vulnerability scans performed at least quarterly? | P | **Partial cadence.** `cargo-audit` and `cargo-deny` have PR lanes plus daily scheduled lanes; CodeQL is nightly/on demand with no PR trigger; Semgrep is workflow-dispatch-only (its schedule is parked); `cargo-fuzz` is workflow-dispatch-only (its schedule is parked). The available cadence is quarterly-or-better for the dependency lanes, not a daily all-tool claim. | SOC 2 rollup §2.7 (CC7.1) |
| G.11 | Are pentest findings tracked to remediation? | P | Internal adversarial summaries tracked; external pentest scoped under R-6 staging-bake. | `specs/_audits/sealed/2026-05-14-cargo-fuzz-summary-s15.md` |
| G.12 | Is information transfer secured (encryption, agreement)? | Y | TLS 1.2 floor, 1.3 negotiated (ADR-0072) + HSTS preload (`max-age=63072000`) + AEAD-only cipher suite. DPA §6 governs onward transfer (SCC Modules 2/3). | `apps/docs/docs/trust/data-handling.mdx#in-flight`; `legal/dpa/v1.0.0` §6 |

## H. Access Control (10 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| H.1 | Is multi-factor authentication enforced for administrative access? | Y | WebAuthn-bound admin sessions + MFA freshness gate (`INV-ADMIN-MFA-FRESHNESS`) + `PAT-DUAL-APPROVAL-001` for destructive ops. Customer-tenant MFA enforced via Clerk (CUEC). | SOC 2 rollup §2.3 (CC3.3); `apps/docs/docs/trust/iso27001.mdx` §A.8.2 |
| H.2 | Is access provisioned via documented approval workflow? | Y | Clerk identity provisioning + `WI-S19-001` onboarding + `INV-ONBOARD-DPA-FIRST` (DPA acceptance gate). | SOC 2 rollup §2.6 (CC6.2) |
| H.3 | Is access reviewed at least quarterly? | P | Clerk RBAC + `INV-DATA-ERASURE-COMPLETE`; quarterly target (automation pending — **GAP-01** + **GAP-26**). | SOC 2 rollup §2.6 (CC6.3) |
| H.4 | Are privileged accounts uniquely identified? | Y | Per-individual Clerk identities; no shared credentials; PAT-DUAL-APPROVAL pattern adds second-individual approval for destructive ops. | SOC 2 rollup §2.3 (CC3.3) |
| H.5 | Are unused accounts disabled within defined window? | Y | Same-day Clerk revocation on offboarding (signed-checklist GAP-ISO-05 closes T+2m for formal evidence). | GAP-ISO-05 |
| H.6 | Is password / credential management enforced? | Y | Clerk-managed; no CoreLink-side credentials in flight or at rest. Secrets matrix (108 rows) enforced via `scripts/validate_secrets_matrix.py` + daily drift gate `.github/workflows/secrets-drift.yml`; DEBT-001 closed 2026-05-15 commit `52624e7`. | SOC 2 rollup §2.6 (CC6.1) |
| H.7 | Is tenant isolation enforced (multi-tenant SaaS)? | Y | **Cross-tenant blast radius is zero** — `INV-TenantIsolation` is TLA+ model-checked and CI-gated. Tenant-scoped R2 prefixes, Durable Object instances, and Clerk namespaces isolate tenant access. The D1 control plane is one shared global database and is not a per-tenant database. | `apps/docs/docs/trust/index.mdx`; `specs/03_architecture/invariant_registry.md` |
| H.8 | Is network access restricted by least privilege? | Y | Cloudflare Access + mTLS edge-to-origin + per-tenant DO namespace + immutable Workers. | SOC 2 rollup §2.6 (CC6.6, CC6.7) |
| H.9 | Are remote-access sessions encrypted? | Y | TLS 1.2 floor, 1.3 negotiated, for all external traffic. Internal calls routed through Cloudflare's encrypted internal fabric. | `apps/docs/docs/trust/data-handling.mdx#in-flight` |
| H.10 | Are API keys / tokens rotatable + revocable? | Y | PAT lifecycle managed; secrets-matrix drift gate prevents drift; admin API supports revocation. | SOC 2 rollup CC6.1 |

## I. System Acquisition, Development & Maintenance (10 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| I.1 | Is a secure-development lifecycle (SDLC) documented? | Y | Spec-first / TDD / sprint-contract methodology; preflight reviews per sprint; STRIDE matrix + ADR per architecture decision. | `specs/03_architecture/adrs/`; `specs/_audits/matrix-stride-ctrl.csv` |
| I.2 | Is threat modeling performed for new features? | Y | STRIDE matrix at `specs/_audits/matrix-stride-ctrl.csv`; failure-mode taxonomy `specs/03_architecture/failure_modes.md` (FM-XXX). | SOC 2 rollup §2.3 (CC3.2) |
| I.3 | Are security requirements specified before development? | Y | Sprint contracts include security requirements + INV / CTRL / PAT references; preflight review gate. | SOC 2 rollup §2.3 (CC3.4) |
| I.4 | Are code reviews mandatory? | Y | GitHub branch protection + dual-approval (`PAT-DUAL-APPROVAL-001`). | SOC 2 rollup §2.8 (CC8.1) |
| I.5 | Is static application security testing (SAST) automated? | P | **Partial cadence.** CodeQL is nightly/on demand with no PR trigger; Semgrep is workflow-dispatch-only (its schedule is parked). Rust PRs still gate on paths-scoped clippy/test, cargo-audit and cargo-deny. Baseline `specs/_audits/sealed/2026-05-15-static-analysis-baseline.md`; triage runbook `specs/_runbooks/RB-STATIC-ANALYSIS-TRIAGE.md`. | SOC 2 rollup §2.8 (CC8.1) |
| I.6 | Is dynamic / fuzz testing performed? | P | `cargo-fuzz` is **not daily**: its schedule is parked and the workflow is workflow-dispatch-only. Property tests do run in the Rust test lanes (including the 100k synthetic PAN and 10k concurrent-signup suites); the historical summary is at `specs/_audits/sealed/2026-05-14-cargo-fuzz-summary-s15.md`. | `crates/corelink-logpush/tests/pii_redaction_100k_synthetic.rs` |
| I.7 | Is software composition analysis (SCA) automated? | Y | `cargo-deny` + license allowlist are automated in PR and daily scheduled lanes. Dependency-Track ingestion is wired but not operating as a live daily scanner; no cadence is claimed for it. | `.github/workflows/cargo-deny.yml`; SOC 2 rollup §2.7 (CC7.1) |
| I.8 | Are production deployments signed / attested? | P | Reproducible builds + immutable Workers (`CTRL-CRYPTO-001`) + public per-binary SHA-256 checksums. Release signing is a placeholder — **no Cosign signatures / Rekor entries today** (roadmap; see `EVIDENCE-PACK-INDEX.md` §1.1). | SOC 2 rollup §2.6 (CC6.7); `EVIDENCE-PACK-INDEX.md` §1.1 |
| I.9 | Is a software-supply-chain attestation (SLSA) maintained? | N | No SLSA attestation today — the attestation workflow has never produced one (roadmap). Public integrity evidence: per-binary SHA-256 checksums. ISO 27001 page §A.5.21 marks the roadmap state. | `EVIDENCE-PACK-INDEX.md` §1.1 |
| I.10 | Are third-party libraries inventoried + monitored? | Y | In-repo CycloneDX SBOM (NDA-shared; hand-refreshed, not per-release — `EVIDENCE-PACK-INDEX.md` §1.1) + Dependency-Track + `INV-SUPPLY-NO-YANKED`. | SOC 2 rollup §2.6 (CC6.8) |

## J. Incident Management (8 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| J.1 | Do you have a documented incident-response plan? | Y | `specs/_compliance/IR-TABLETOP-PLAYBOOK.md` (NIST 800-61 Rev. 2 aligned, 6 scenarios); customer-facing summary at `apps/docs/docs/trust/incident-response.mdx`. | `specs/_compliance/IR-TABLETOP-PLAYBOOK.md`; `apps/docs/docs/trust/incident-response.mdx` |
| J.2 | Are incident-response roles defined (commander, comms, legal)? | Y | RB-BREACH-NOTIF + RB-DATA-RESIDENCY-LEAK + 13-role sign-off matrix; on-call commander identified by name in customer comms. | `specs/05_quality/runbooks/RB-BREACH-NOTIF.md` |
| J.3 | Is the IR plan exercised / tabletop'd? | P | Tabletop playbook + 2026 schedule landed; **first live tabletop TT-01 scheduled 2026-07-22** (GAP-03 — execution pending). | `specs/_compliance/IR-TABLETOP-SCHEDULE-2026.md`; SOC 2 rollup §2.7 (CC7.3) |
| J.4 | Is 24×7 incident detection in place? | P | Cloudflare-native monitoring + Grafana SLO dashboards are present. The weekly synthetic page does **not** fire in production: its cron is present only in dev/staging, and the pager image remains unpinned (`<PIN_AT_RELEASE>`). The PagerDuty 24/7 rotation lives outside this repository; request the account schedule export rather than asserting it here. | `apps/docs/docs/trust/incident-response.mdx`; `wrangler.toml` |
| J.5 | Are customers notified of breaches within a defined window? | Y | **72h to ANPD (LGPD Art. 33) + 72h to EU supervisory authority (GDPR Art. 33) + 24h to affected enterprise tenant (DPA §7).** 4h internal escalation to DPO + Security Lead. | `apps/docs/docs/trust/incident-response.mdx#breach-notification`; `legal/dpa/v1.0.0` §7 |
| J.6 | Are post-mortems published? | Y | Public post-mortem within 72h on status page; internal review T+14d with corrective-action register. | `apps/docs/docs/trust/incident-response.mdx#communicating-during-a-sev1` |
| J.7 | Is forensic / evidence preservation procedure documented? | Y | Append-only BLAKE3 hash-chained audit log with offline verification; sealed-chain chunks archived offsite to R2; chain-of-custody documented in RB-BREACH-NOTIF. | `apps/docs/docs/trust/iso27001.mdx` §A.5.28 |
| J.8 | Has any customer-impacting incident occurred to date? | N | **No customer-impacting SEV1 since first paid traffic.** Disclosure history is public on status page. | `apps/docs/docs/trust/incident-response.mdx#past-incidents` |

## K. Compliance & Regulatory (10 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| K.1 | Do you hold a SOC 2 Type I or Type II report? | P | **Not yet** — SOC 2 Type I target Q4-2026 fieldwork, report Q1-2027; Type II Q3-2027. Auditor Schellman & Co. Readiness 83.7% weighted; 96.4% green on Drata. SOC 2 readiness rollup available under NDA. | `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`; `specs/_compliance/SOC2-ROADMAP.md` |
| K.2 | Do you hold ISO 27001 certification? | P | **Not yet** — ISO/IEC 27001:2022 cert target Q1-2027 with Schellman. Today: 98.9% in-scope Annex A coverage on internal crosswalk; NDA-gated pack available. | `apps/docs/docs/trust/iso27001.mdx`; `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md` |
| K.3 | Are you PCI DSS compliant? | Y | **SAQ-A self-attested 2026-05-15** (validity through 2027-05-14). CoreLink itself is not in your PCI CDE — Stripe (PCI L1 Service Provider) tokenizes via Stripe Elements; CoreLink stores only opaque IDs. | `apps/docs/docs/trust/pci-dss.mdx`; `specs/_compliance/PCI-DSS-SAQ-A-2026-05-15.md`; `specs/_compliance/PCI-DSS-BOUNDARY-DIAGRAM.md` |
| K.4 | Do you support GDPR? | P | Counsel approval of effective customer-facing transfer terms remains pending for the shared global D1 control plane. EU (`weur`) CAS/AC blobs use physically-EU R2 buckets via London/`lhr`, but that R2 fact does not establish D1 residency or an executed transfer mechanism. | `apps/docs/docs/trust/data-handling.mdx#residency`; `legal/tia-template.md` |
| K.5 | Do you support LGPD (Brazil)? | P | Brazil/SAM physical residency is not provisioned. The shared D1 control plane is currently reported with a primary in ENAM and no D1 jurisdiction; counsel must approve applicable customer-facing transfer terms before launch. | `apps/docs/docs/explanation/residency/lgpd-brazil.mdx`; `legal/tia-template.md` |
| K.6 | Do you have a HIPAA BAA? | N | **Out of scope by design.** CoreLink is a build-artefact cache; it does not handle PHI. We do **not** sign BAAs. Infrastructure substrate (CF/AWS/GCP/Azure) is HIPAA-aligned but CoreLink product surface is not engineered for PHI. | `apps/docs/docs/trust/compliance.mdx`; FAQ-MASTER C5 |
| K.7 | Are you FedRAMP authorized? | N | **No, and not in the near-term roadmap.** NIST 800-53 Rev 5 Moderate crosswalk at 87% (informational only — not a substitute for ATO). FedRAMP rationale: `specs/_compliance/FEDRAMP-NOT-IN-SCOPE-RATIONALE.md`. CSA STAR Level 1 / CAIQ available on request. | `specs/_compliance/FEDRAMP-MODERATE-CROSSWALK-2026-05-15.md`; `apps/docs/docs/trust/fedramp-info.mdx` |
| K.8 | Are you CSA STAR (CAIQ) listed? | P | CAIQ v4 self-assessment pre-filled response available immediately on request (~1 business day via `trust@humangr.com`); STAR Registry submission decision pending Q1-2027 post SOC 2 Type I issuance. See companion `CAIQ-V4-pre-filled.md`. | `marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md` |
| K.9 | Are sub-processors disclosed? | Y | Public list at `apps/docs/docs/trust/subprocessors.mdx` (auto-generated from `VENDOR-RISK-REGISTER.md`); 6 active sub-processors. 30-day advance notice on additions/replacements per DPA §6. | `apps/docs/docs/trust/subprocessors.mdx`; `legal/sub-processors.md` |
| K.10 | Are cross-border data transfers contractually governed? | P | The shared global D1 control plane requires counsel approval of the applicable transfer basis and effective customer-facing terms. BYOK and crypto-erase have no verified customer rollout and are not current safeguards. EU R2/DO residency does not establish D1 transfer compliance. | `legal/tia-template.md`; `docs/operator/d1-residency-evidence.md` |

## L. Endpoint Security (6 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| L.1 | Are corporate endpoints managed? | P | Remote-first organization; MDM-lite documentation is **GAP-ISO-07** (closes T+3m). Today: disk encryption mandatory at hire; OS-vendor-managed patching cadence. | GAP-ISO-07 |
| L.2 | Is full-disk encryption enforced on endpoints? | Y | Yes — mandatory at hire; documented in onboarding (`signed offboarding checklist` GAP-ISO-05 covers asset return). | GAP-ISO-05 (offboarding side) |
| L.3 | Is endpoint anti-malware / EDR deployed? | P | OS-vendor anti-malware enforced; commercial EDR consolidation under Q3-2026 IT-budget refresh. | Available on request |
| L.4 | Are personal devices governed (BYOD)? | CC | BYOD restricted to approved-device list; production access requires WebAuthn-bound session via managed device. | `apps/docs/docs/trust/iso27001.mdx` §A.8.2 |
| L.5 | Are screen locks enforced? | P | OS-vendor screen-lock policy; formal clear-desk / clear-screen policy is **GAP-ISO-06** (closes T+1m). | GAP-ISO-06 |
| L.6 | Are endpoints inventoried? | P | Drata employee-attestation tracker; formal asset register **GAP-ISO-01** (closes T+1m). | GAP-ISO-01 |

## M. Data Privacy (10 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| M.1 | Do you publish a privacy notice? | Y | Yes — privacy notice published; LGPD ROPA at `specs/_compliance/LGPD-ROPA-2026-05-15.md`. | `specs/_compliance/LGPD-ROPA-2026-05-15.md`; `apps/docs/docs/trust/data-handling.mdx` |
| M.2 | Do you appoint a DPO / Privacy Officer? | Y | Yes — DPO appointed 2026-05-15 (`dpo@humangr.com`). Privacy contact `privacy@humangr.com`. | `specs/_compliance/DPO-APPOINTMENT-2026-05-15.md` |
| M.3 | Do you maintain a Records of Processing Activities (ROPA)? | Y | Yes — `specs/_compliance/LGPD-ROPA-2026-05-15.md`; equivalent GDPR ROPA covered under DPA §3. | `specs/_compliance/LGPD-ROPA-2026-05-15.md`; `legal/dpa/v1.0.0` §3 |
| M.4 | Do you perform DPIAs for high-risk processing? | Y | DPIA library at `specs/_compliance/GDPR-DPIA-LIBRARY.md`; CI validator `scripts/validate_dpia.py`. | `specs/_compliance/GDPR-DPIA-LIBRARY.md` |
| M.5 | Is consent captured and provable? | Y | 6-field consent JWT receipt (WI-S19-002) + `INV-CONSENT-PROOF-VERIFIABLE`. LIA template at `legal/lia/`. | SOC 2 rollup §2.13 (P-CONSENT); ADR-S11-003 |
| M.6 | Do you support data-subject rights (access, rectification, erasure, portability)? | Y | DSR runbooks (`RB-DSR-INTAKE-FAILURE`, `RB-DSR-ERASURE-INCOMPLETE`). Verifiable erasure via `INV-DATA-ERASURE-COMPLETE` + `INV-ERASURE-ATTESTATION-SIGNED`. Portability validation **GAP-17** (T+3m). 15-business-day resolution target. | `apps/docs/docs/trust/data-handling.mdx#right-to-erasure` |
| M.7 | Are data-residency commitments enforced? | Y | **EU residency is enforced and delivered:** EU (`weur`) tenants are served via the `lhr` cluster, whose CAS/AC blobs live in physically-EU R2 buckets (EEUR); the residency guard maps `weur`→`lhr` and refuses cross-region access (`INV-REGION-NO-CROSS-LEAK`). US (`enam`) is the default region (US storage). Additional jurisdictions — Brazil/`sam` (note: Cloudflare R2 has no South-America region, so BR physical residency is not yet possible) and APAC — are on the roadmap, available to Enterprise on request. | `apps/docs/docs/trust/data-handling.mdx#residency` |
| M.8 | Are minors / sensitive categories handled? | N/A | CoreLink is a B2B build-cache; not directed at minors. Sensitive personal data (health, biometric, etc.) is **out of product scope**. | `apps/docs/docs/trust/data-handling.mdx#what-we-store` |
| M.9 | Is data minimization documented? | Y | "What we store" list at `apps/docs/docs/trust/data-handling.mdx`: 8 data classes only — no PHI, no CHD, no copies of customer code outside CAS. | `apps/docs/docs/trust/data-handling.mdx#what-we-store` |
| M.10 | Is the 72h breach-notification SLA committed in writing? | Y | Yes — `legal/dpa/v1.0.0` §7 + `apps/docs/docs/trust/incident-response.mdx#breach-notification`. 24h to enterprise tenant; 72h to ANPD / supervisory authority; without-undue-delay to high-risk affected data subjects. | `legal/dpa/v1.0.0` §7 |

## N. Cloud Hosting / IT Outsourcing (10 questions)

| # | Question | A | CoreLink answer | Evidence |
|---|---|---|---|---|
| N.1 | Where is customer data physically hosted? | Y | US tenants' CAS/AC data is stored in US Cloudflare R2; **EU (`weur`) tenants' CAS/AC data is stored in physically-EU R2 buckets** (`corelink-cas-eu` / `corelink-ac-eu`, both EEUR) served via London/`lhr`. Those are R2 residency statements. The D1 control plane holds metadata in one shared global database; its primary is currently reported in ENAM with no D1 jurisdiction. DO state is tenant-scoped. The prelaunch DPA/TIA text does not establish approved customer transfer terms for D1. Other jurisdictions are roadmap items, not GA. | `apps/docs/docs/trust/data-handling.mdx#residency` |
| N.2 | Who are your hosting / IaaS providers? | Y | Cloudflare primary data plane (Workers / R2 / D1 / DO / KV / Pages / Email). **No other IaaS provider hosts customer data.** AWS / GCP / Azure / HashiCorp Vault appear in the BYOK design as customer-side KMS custodians, but **BYOK has no verified customer rollout** (activation returns `501 byok_not_available` if provider construction or CMK access fails; the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence — see N.6), so today **no tenant-to-KMS use has been verified in the B-083 receipt and no provider custody is claimed without evidence.** They are listed for the designed flow only, not as anything in service. | `apps/docs/docs/trust/subprocessors.mdx` |
| N.3 | Do hosting providers hold SOC 2 Type II / ISO 27001 / FedRAMP? | Y | Cloudflare: SOC 2 Type II + ISO 27001/27018 + PCI L1 + HIPAA-compliant infra + FedRAMP Moderate. AWS / GCP / Azure: SOC 2 Type II + ISO 27001/17/18 + FedRAMP High + PCI L1 + FIPS-validated KMS endpoints. | `specs/_compliance/VENDOR-RISK-REGISTER.md` rows 1, 4, 5, 6 |
| N.4 | Is data encrypted at rest? | Y | AES-256-GCM on R2 / D1 / KV / DO, under provider-managed keys. Customer-managed BYOK envelope encryption per blob has **no verified customer rollout**. The Dockerfile production build selects `byok-aws-real`, but activation returns `501 byok_not_available` if provider construction or CMK access fails, and customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See N.6. | `apps/docs/docs/trust/data-handling.mdx#encryption`; `crates/corelink-container/src/routes/byok_admin.rs` |
| N.5 | Is data encrypted in transit? | Y | TLS 1.2 floor, 1.3 negotiated (ADR-0072) + HSTS `max-age=63072000; includeSubDomains; preload` + AEAD-only ciphers (AES-256-GCM, ChaCha20-Poly1305) + mTLS edge-to-origin. | `apps/docs/docs/trust/data-handling.mdx#in-flight` |
| N.6 | Are customer-managed encryption keys supported (BYOK / CMK)? | N | **No — BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`), and the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. Four-provider envelope encryption is designed and wired into CAS+AC storage; the Dockerfile selects AWS KMS only and no active BYOK tenant is evidenced. The weekly kill-switch drill workflow (`.github/workflows/byok_kill_switch_drill_weekly.yml`, `cron: 0 3 * * 0`) is real and its 8 most recent runs (all `schedule`, 2026-07-05 → 2026-08-30) are green — but **the drill itself is a shell simulation with the PASS values hard-coded**. `scripts/byok_kill_switch_drill.sh` contacts no customer KMS (every KMS credential in the job is commented out), no CoreLink API, and **not the compiled AWS KMS runtime path either** — it invokes no CoreLink binary. `TENANT_STATUS="active"` (`:51`), `DETECTED=true` (`:82`), `TENANT_STATUS_POST="degraded_read_only"` (`:101`) and the rest are literals, so no assertion can fail; the `byok-kill-switch-rtt` "≤ 5 min" figure is `date +%s` across a `sleep 2` (`:62`, `:81`, `:112`) and measures nothing — `DETECT_LATENCY_S` (`:75` → `:86`) and `TOTAL_S` (`:62` → `:112`) span the **same** single `sleep 2`, and the two `sleep 1` calls (`:126`, `:128`) run after `:112`, outside both. The report step commits without pushing, so no run has left an artifact — `specs/_audits/` contains **zero** `*-byok-kill-switch-drill-*.md` files. Data at rest is AES-256-GCM under provider-managed keys. | `crates/corelink-container/src/routes/byok_admin.rs`; CAIQ CEK-09.1 / CEK-10.1 |
| N.7 | Can customers delete all their data? | Y | Yes — admin API `DELETE /v1/tenant/me` triggers verifiable erasure. Backup tombstones propagate within 35-day backup window. Audit-chain salt-rotation pattern preserves chain integrity while making PII-bearing claims cryptographically unrecoverable. | `apps/docs/docs/trust/data-handling.mdx#right-to-erasure` |
| N.8 | Is there contractual right to audit hosting providers? | Y | Sub-processor termination clauses per `legal/sub-processors-templates/`. Right-to-audit flows through CoreLink DPA §8 + sub-processor DPAs (linked in `apps/docs/docs/trust/subprocessors.mdx`). Cloudflare/AWS/GCP/Azure SOC 2 Type II reports are auditor-inheritance basis. | `apps/docs/docs/trust/subprocessors.mdx`; SOC 2 rollup §2.6 (CC6.4, CC6.5) |
| N.9 | Are sub-processor changes communicated in advance? | Y | **30 calendar days advance notice** per DPA §6 + GDPR Art. 28 §2 + LGPD Art. 27 §4º. Notification channels: tenant-registered email distribution + status page + RSS post-GA. | `apps/docs/docs/trust/subprocessors.mdx#notice-of-changes-30-day-grace` |
| N.10 | Is exit / off-boarding documented? | Y | DPA termination clauses; tenant data export (admin API); verifiable erasure on termination + signed attestation; sub-processor termination clauses per `legal/sub-processors-templates/`. | `legal/dpa/v1.0.0` §10; `apps/docs/docs/trust/data-handling.mdx#right-to-erasure` |

---

## Question count summary

| Category | Questions |
|---|---|
| A. Risk Management | 8 |
| B. Security Policy | 6 |
| C. Organizational Security | 6 |
| D. Asset Management | 8 |
| E. HR Security | 6 |
| F. Physical & Environmental | 4 |
| G. Communications & Operations | 12 |
| H. Access Control | 10 |
| I. System Acq, Dev & Maintenance | 10 |
| J. Incident Management | 8 |
| K. Compliance & Regulatory | 10 |
| L. Endpoint Security | 6 |
| M. Data Privacy | 10 |
| N. Cloud Hosting / IT Outsourcing | 10 |
| **Total** | **114** |

The actual SIG Lite 2026 workbook includes ~130 questions; the remaining ~16 are workbook-specific metadata cells (vendor name, contact, date, version) auto-fillable per response.

---

## Pre-flight checklist (before sending to prospect)

- [ ] Confirm prospect NDA on file with Legal.
- [ ] Confirm `trust@humangr.com` is the response sender alias.
- [ ] Bundle artifacts per `EVIDENCE-PACK-INDEX.md`.
- [ ] Watermark the response with prospect name + date.
- [ ] Run answer-key against latest commit SHA (cite the SHA in cover letter).
- [ ] Cross-check every answer against `apps/docs/docs/trust/` for consistency with public statements.
- [ ] Spot-check at least 5 evidence links resolve in the worktree (`find . -name '<artifact>'`).

---

## Related

- `marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md` — companion CAIQ v4.0.x mapping.
- `marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md` — generic vendor-form response template.
- `marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md` — what-artifact-answers-which-question-family index.
- `marketing/sales/legal-questionnaires/RESPONSE-SLA-POLICY.md` — turnaround commitments.
- `marketing/sales/FAQ-MASTER.md` §Compliance — canonical phrasing per topic.
- `apps/docs/docs/trust/` — public trust center.
- `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md` — master evidence rollup.
- `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` — enterprise tier engagement playbook.

## Contact

| What you need | Where to send it |
|---|---|
| SIG Lite response request (countersigned NDA on file) | `trust@humangr.com` |
| Privacy / data-subject question | `privacy@humangr.com` |
| Security vulnerability report | `security@humangr.com` |
| Procurement / vendor-review forms | `trust@humangr.com` |
