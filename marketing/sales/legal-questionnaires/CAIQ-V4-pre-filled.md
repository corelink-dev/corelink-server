---
id: "SALES-CAIQ-V4-PREFILLED"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "R-PREP-SALES-ENABLEMENT"
tags: ["sales", "legal", "questionnaire", "caiq", "csa", "ccm", "v4", "procurement", "r-prep", "ga"]
---

# CSA CAIQ v4.0.x — CoreLink Pre-Filled Response

> **Audience:** CoreLink CS / SE responding to a Cloud Security Alliance Consensus Assessment Initiative Questionnaire (CAIQ) v4.0.x request — typical channel: STAR Registry self-assessment, enterprise procurement RFP attachment, or hyperscaler-marketplace listing.
>
> **Source standard:** CSA CCM v4.0.x (Cloud Controls Matrix) + CAIQ v4.0.x. **197 questions across 17 control domains.** This pre-fill maps every CCM v4 control to (a) our canonical answer, (b) SOC 2 TSC cross-reference, (c) evidence artifact.
>
> **Auditor mode:** if you are a STAR auditor or 3PAO, this document is **NDA-gated for full evidence**. The summary table is shareable; deep-link artifacts require countersigned NDA via `trust@humangr.com`.
>
> **Scoping caveats (read first):**
> - CoreLink is **SOC 2 Type I target Q4-2026** (fieldwork; report Q1-2027). No Type I report yet issued. Readiness 83.7% weighted, 96.4% green on Drata.
> - CoreLink is **ISO 27001:2022 cert target Q1-2027** (Stage 1 Q4-2026, Stage 2 Q1-2027, Schellman & Co.).
> - CoreLink is **PCI DSS SAQ-A self-attested** 2026-05-15 (not externally audited; Stripe handles all CHD).
> - CoreLink is **not FedRAMP-authorized**; NIST 800-53 Rev 5 Moderate crosswalk at 87% (informational).
> - **CSA STAR Registry submission decision pending Q1-2027** post SOC 2 Type I issuance — this CAIQ self-assessment is currently distributed on direct request via `trust@humangr.com`.
>
> **Companion:** `SIG-LITE-2026-pre-filled.md`, `EVIDENCE-PACK-INDEX.md`, `RESPONSE-SLA-POLICY.md`.

---

## Legend

- **Y** = Yes — implemented and evidenced.
- **P** = Partial — control exists, evidence gap with stated ETA.
- **CC** = Compensating Control — primary control N/A; equivalent control documented.
- **N/A** = Not applicable; scoping reason stated.
- **N** = No (with rationale).
- **TSC** = AICPA SOC 2 TSC 2017 cross-reference.

CSP / CSC responsibility column:

- **CSP** = CoreLink (we own it).
- **CSC** = Customer (you own it).
- **Shared** = both responsible per stated split.

---

## A&A — Audit & Assurance (6 questions, A&A-01 .. A&A-06)

| # | Question (CCM v4 paraphrase) | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| A&A-01.1 | Audit & assurance policies established? | Y | CSP | Yes — quarterly cadence, owner VP-Sec. `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`; `legal/quarterly-legal-review-template.md`. | CC1.1, CC4.1 |
| A&A-02.1 | Independent audit performed at planned intervals? | P | CSP | SOC 2 Type I fieldwork Q4-2026 (Schellman); Type II fieldwork Q3-2027; ISO 27001 Stage 1 Q4-2026 stacked. Drata continuous compliance 96.4% green today. | CC4.1 |
| A&A-03.1 | Risk-based audit plan documented? | Y | CSP | `specs/_audits/` registry + sprint preflight reviews. 33-GAP SOC 2 register prioritized by severity. | CC3.1, CC4.1 |
| A&A-04.1 | Right-to-audit clause in customer contracts? | Y | CSP | DPA §8 right-to-audit + reasonable-notice + cost responsibility per industry norm. Auditor-walkthrough script `specs/_compliance/AUDITOR-WALKTHROUGH-SCRIPT.md`. | CC1.1 |
| A&A-05.1 | Corrective actions tracked to closure? | Y | CSP | 33-GAP register with severity / owner / ETA in `SOC2-GAP-ANALYSIS.md` + weekly compliance digest. | CC4.2 |
| A&A-06.1 | Evidence of continuous compliance? | Y | CSP | Drata: 6 EvidenceStream variants, 90.7% strict auto-collection, 95.3% effective. Weekly digest `specs/_compliance/weekly-digests/`. | CC4.1 |

## AIS — Application & Interface Security (7 questions, AIS-01 .. AIS-07)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| AIS-01.1 | Application security policies established? | Y | CSP | `specs/03_architecture/security_model.md` CTRL catalog + secure-SDLC; sprint-contract security gates. | CC8.1 |
| AIS-02.1 | Application security baseline requirements? | Y | CSP | INV registry (189 INVs) + CTRL catalog (96 controls) + PAT patterns + STRIDE matrix. | CC5.1 |
| AIS-03.1 | Secure SDLC integrated into development? | Y | CSP | Spec-first + TDD + sprint preflight + PR template + dual approval. ADR-driven decisions. | CC8.1 |
| AIS-04.1 | Application security testing performed? | P | CSP | **Partial — read the cadence, not the tool list.** CodeQL runs **nightly + on demand**, not per-PR: `codeql.yml` has `schedule: '30 5 * * *'` + `workflow_dispatch` and **no `pull_request` lane**. Semgrep does **not run on a schedule at all** — the cron in `semgrep.yml` is commented out (parked 2026-08-10 after 0 of 8 runs succeeded); it is `workflow_dispatch`-only. `cargo-fuzz` is **not daily** — the cron in `fuzz-nightly.yml` is commented out and the file states dispatch is "currently the ONLY trigger". What **does** gate a PR that touches Rust code (`pull_request` with a `crates/**` + `Cargo.*` path filter, so a docs-only PR is not gated by these): `cargo clippy --package corelink-server --all-targets -- -D warnings` and `cargo test --package corelink-server --all-targets` (`corelink-server.yml`), plus `cargo-audit` and `cargo-deny` (`cargo-audit.yml`, `cargo-deny.yml`, each also on a daily cron). Property tests exist and run inside that `cargo test` lane (e.g. `crates/corelink-signup/tests/prop_signup_orchestration.rs`). A prior version of this row answered "Y" and described all three scanners as per-PR or daily; that was wrong and is withdrawn. | CC7.1 |
| AIS-05.1 | Vulnerabilities remediated within SLA? | Y | CSP | Severity-based SLA per `RB-STATIC-ANALYSIS-TRIAGE.md`; baseline `specs/_audits/sealed/2026-05-15-static-analysis-baseline.md`. | CC7.1 |
| AIS-06.1 | API authentication / authorization documented? | Y | CSP | Clerk JWT + RBAC + `auth_model.md` + per-tenant DO routing (CTRL-AUTHZ-001, CTRL-AUTHZ-002). | CC6.2 |
| AIS-07.1 | Input validation enforced? | Y | CSP | `CTRL-INPUT-001..004` + schema validation `specs/_schemas/` + property tests. | PI1.1 |

## BCR — Business Continuity & Operational Resilience (11 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| BCR-01.1 | BCP / DR plan documented? | Y | CSP | `specs/_compliance/BCP-DR-DRILL-CADENCE.md` (14-drill cadence); `specs/05_quality/runbooks/RB-DR-DRILL.md`. | A1.2 |
| BCR-02.1 | Business impact analysis performed? | P | CSP | BIA depth per-business-process is **GAP-ISO-04** (T+2m); top-level RTO/RPO documented (15min/5min for active failover). | A1.2 |
| BCR-03.1 | RTO / RPO defined per system? | Y | CSP | **RTO ≤ 15 min write-flip / RPO ≤ 5 min** for active-region warm failover (DR-16). Cold-restore-from-zero (DR-15) RTO documented. | A1.2 |
| BCR-04.1 | Backups encrypted? | Y | CSP | Same envelope as source: AES-256-GCM, provider-managed keys. 35-day rolling window. **BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. Backups are encrypted; they are not customer-key-encrypted. | C1.1 |
| BCR-05.1 | Backups tested? | P | CSP | Cold-restore drill spec sealed; first dry-run T-30d pre-GA. Active-failover drill sealed; first cycle outstanding. | A1.3 |
| BCR-06.1 | Recovery procedures tested at planned intervals? | P | CSP | Cadence: QUARTERLY (cold-restore) + MONTHLY (active-failover) post-GA. Region-outage chaos drill SEALED (`specs/_audits/sealed/2026-05-14-region-outage-chaos-s14.md`). | A1.3 |
| BCR-07.1 | Customer notified of material outages? | Y | CSP | Status page within 5 min (SEV1); email to affected tenants within 30 min; per-tenant `incident-comms` distribution. | CC2.3 |
| BCR-08.1 | Capacity planning performed? | Y | CSP | SLO catalog + `CTRL-GC-001` quota + Cloudflare-elastic D1+DO+R2 (US/ENAM default region + physically-EU/WEUR region live; further regions on roadmap). | A1.1 |
| BCR-09.1 | Equipment redundancy across regions? | P | CSP | Two regions live today (US/ENAM + physically-EU/WEUR), each backed by Cloudflare's intra-region durability + per-tenant DO redundancy. Active-active cross-region replication is on the roadmap (and always within a tenant's residency boundary), not GA. | A1.1 |
| BCR-10.1 | Crisis-communication procedure documented? | Y | CSP | `marketing/launch/CRISIS-COMMS-TEMPLATES.md` (5 templates) + status page operated separately from production fabric (Atlassian Statuspage). | CC2.3 |
| BCR-11.1 | BCP / DR plan reviewed annually? | P | CSP | Cadence calendarized in `BCP-DR-DRILL-CADENCE.md`; first full review post-GA. GAP-13 closure tracked. | A1.2 |

## CCC — Change Control & Configuration Management (9 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| CCC-01.1 | Change management policy established? | Y | CSP | Sprint-contract §5.1 sign-off + branch protection + `PAT-DUAL-APPROVAL-001` + signed-deploy pipeline. | CC8.1 |
| CCC-02.1 | Changes approved before deployment? | Y | CSP | Dual approval on protected branches; per-release approver enumerated in commit metadata. | CC8.1 |
| CCC-03.1 | Emergency changes documented post-implementation? | Y | CSP | Waiver pattern `WAIVER-YYYYMMDD-NNN` with explicit expiry; fallback ADR per WI. | CC8.1 |
| CCC-04.1 | Production / non-production separation enforced? | Y | CSP | Staging tenant isolated from production; 30-day R-6 staging-bake gate. | CC8.1 |
| CCC-05.1 | Configuration baselines documented? | Y | CSP | ADR-driven configuration; immutable Workers (no runtime drift); CycloneDX SBOM maintained in-repo (NDA-shared; hand-refreshed — see `EVIDENCE-PACK-INDEX.md` §1.1). | CC5.1 |
| CCC-06.1 | Unauthorized changes detected? | Y | CSP | Canonical-consistency validator on every PR (`.github/workflows/canonical-consistency.yml`) + secrets-drift gate. | CC4.1 |
| CCC-07.1 | Source-code repositories access-controlled? | Y | CSP | GitHub Enterprise; branch protection; signed commits; DCO; CODEOWNERS. | CC6.1 |
| CCC-08.1 | Configuration changes logged? | Y | CSP | Append-only BLAKE3 hash-chained audit log (`INV-AUDIT-APPEND-ONLY`). GitHub audit log retained per Microsoft Enterprise. | PI1.2 |
| CCC-09.1 | Rollback procedures defined? | Y | CSP | Sprint contracts include rollback criteria; immutable Workers enable instant rollback via Cloudflare deploy ID. | CC8.1 |

## CEK — Cryptography, Encryption & Key Management (21 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| CEK-01.1 | Cryptography policy established? | Y | CSP | `apps/docs/docs/trust/data-handling.mdx#encryption` + security overview cryptography baseline. | C1.1 |
| CEK-02.1 | Encryption at rest enforced? | Y | CSP | AES-256-GCM on R2 / D1 / KV / DO, provider-managed keys. No customer-managed encryption envelope is evidenced for a production tenant: **BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. | C1.1 |
| CEK-03.1 | Encryption in transit enforced? | Y | CSP | TLS 1.2 floor with 1.3 negotiated by every capable client (ADR-0072) + HSTS preload + AEAD-only ciphers + mTLS edge-to-origin. | C1.1 |
| CEK-04.1 | Cryptographic algorithms compliant with industry standards (FIPS / NIST)? | P | CSP | AES-256-GCM, ChaCha20-Poly1305, BLAKE3 / SHA-256, Ed25519. The per-provider FIPS attestation matrix (`specs/_compliance/BYOK-FIPS-ATTESTATION-MATRIX.md`, **GAP-02**) describes BYOK KMS endpoints and is therefore **not in effect**. **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. No FIPS-validated-module claim is made for the served path. | C1.1 |
| CEK-05.1 | Key generation procedures documented? | P | CSP | Documented, not served. KMS-side per provider (AWS / GCP / Azure / Vault); CoreLink never generates root keys. **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. | C1.1 |
| CEK-06.1 | Key rotation supported? | P | CSP | **Customer-key rotation: no.** **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. Provider-managed key rotation for data at rest is Cloudflare-side and transparent. | C1.1 |
| CEK-07.1 | Key escrow / recovery documented? | P | CSP | Documented as customer-side (the KMS provider handles escrow per the customer's IAM policy) — and CoreLink has no evidenced customer CMK custody. **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. | C1.1 |
| CEK-08.1 | Cryptographic keys protected throughout lifecycle? | P | CSP | Cloudflare-managed at-rest encryption is the verified baseline. The shipped native container compiles the AWS BYOK path, not a V8-only DEK lifecycle; B-083 contains no customer CMK activation or CAS/AC round-trip proving DEK handling in production. No universal plaintext-DEK lifetime or wrapped-only-at-rest assurance is claimed for an unverified customer deployment. | C1.1 |
| CEK-09.1 | Customer-managed key option (BYOK) available? | N | CSP | **No verified customer BYOK rollout.** The Dockerfile production build selects AWS KMS via `byok-aws-real`, but the B-083 receipt has no provisioned test tenant, image digest, CMK access, activation, CAS/AC round-trip, revocation, or p99 drill. The other three providers remain design-only for this build. `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails; it is not an unconditional 501 route. Self-serve CMK onboarding is not an evidenced current capability. | C1.1 |
| CEK-10.1 | Kill-switch / key-revocation supported? | N | CSP | The `/deactivate` Shred route is implemented, but customer key revocation and the contractual kill-switch p99 have **no verified customer rollout**. `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. **On the weekly drill, stated precisely, because the workflow is real but the drill is not:** `.github/workflows/byok_kill_switch_drill_weekly.yml` exists, is on `cron: 0 3 * * 0`, and its 8 most recent runs (all `schedule`, 2026-07-05 → 2026-08-30) are all `success`. What runs is `scripts/byok_kill_switch_drill.sh` (181 lines of shell), and **it is a shell simulation with the PASS values written into it as literals.** It contacts nothing: no customer KMS (every KMS credential in the job is commented out, `# AWS_ACCESS_KEY_ID: …`), no CoreLink API or D1 — and **not the compiled AWS KMS provider either**, because the script invokes no CoreLink binary at all. Every asserted outcome is a hard-coded assignment: `TENANT_STATUS="active"` (`:51`), `DETECTED=true` (`:82`), `DEK_CACHE_EMPTY=true` (`:100`), `TENANT_STATUS_POST="degraded_read_only"` (`:101`), `RECOVERY_STATUS="active"` (`:129`); the provider revoke/restore calls exist only as comments (`:64-67`, `:125`). The timing is `date +%s` taken before and after a `sleep 2` (`:62`, `:81`, `:112`), so **the `byok-kill-switch-rtt` "≤ 5 min" figure is a measurement of that sleep, not of any revocation**. Precisely: `DETECT_LATENCY_S` (`:75` → `:86`) and `TOTAL_S` (`:62` → `:112`) span the **same** single `sleep 2`, so the two reported numbers are not independent measurements; the two `sleep 1` calls (`:126`, `:128`) run after `:112` and fall outside both. And because no assertion can be false, the green result is structurally unfailable. No run has ever left evidence in the repo: the "Commit drill report" step of the workflow `git commit`s without `git push` (cited by step name, not line number, because the file shifts), and `specs/_audits/` contains **zero** `*-byok-kill-switch-drill-*.md` files. Treat the drill as unexecuted for assurance purposes. | C1.1 |
| CEK-11.1 | HSM-protected key material? | N | CSP | No HSM protection for customer CMK material is evidenced by the B-083 runtime receipt; **BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. The HSM posture described in `BYOK-FIPS-ATTESTATION-MATRIX.md` is a prospective provider posture, not a proven customer deployment. | C1.1 |
| CEK-12.1 | Certificate management documented? | Y | CSP | Cloudflare-managed TLS certificates; HSTS preload submitted. | CC6.7 |
| CEK-13.1 | Random number generation cryptographically secure? | Y | CSP | OS-level CSPRNG (getrandom / /dev/urandom). Rust `rand_chacha` for application RNG. | C1.1 |
| CEK-14.1 | Cryptography reviewed for vulnerabilities? | Y | CSP | Dependency-Track + cargo-deny daily; CodeQL crypto checks. | CC7.1 |
| CEK-15.1 | Algorithms hardened against quantum risk? | P | CSP | Today: classical (Curve25519, AES-256). PQC roadmap tracked under post-GA R&D. | C1.1 |
| CEK-16.1 | Key-management audit logged? | P | CSP | The audit chain and `INV-AUDIT-APPEND-ONLY` are real and cover served key operations. The `EVT-KMS-*` events are BYOK events and have **no verified production emission**. **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. | PI1.2 |
| CEK-17.1 | Key destruction / decommissioning documented? | P | CSP | **The `/deactivate` Shred route is implemented, but customer-controlled crypto-shredding is not runtime-verified.** **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. What IS served is verifiable erasure: `DELETE /v1/tenant/me` with `INV-DATA-ERASURE-COMPLETE` + `INV-ERASURE-ATTESTATION-SIGNED` (see DSP-08.1). | C1.1 |
| CEK-18.1 | Cryptographic boundaries documented? | P | CSP | `specs/03_architecture/security_model.md` documents the served boundaries. The BYOK key flow is documented at `apps/docs/docs/explanation/security/byok.mdx`, but it documents a **design**, not a served boundary: **BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. | C1.1 |
| CEK-19.1 | Key-management roles separated? | P | CSP | Internal break-glass requires PAT-DUAL-APPROVAL-001 — that half is served. The claim that CoreLink staff cannot access customer CMK material is **unverified**, not established by the absence of a B-083 customer deployment receipt. **Customer BYOK not verified: the Dockerfile production build selects `byok-aws-real`, but protected CMK activation, revocation and kill-switch p99 have no runtime evidence; provider or CMK-access failure maps to `501 byok_not_available` — see CEK-09.1.** This row describes the designed customer-KMS lifecycle, which no tenant has a verified runtime entry into. | CC6.1 |
| CEK-20.1 | Encryption coverage across data classes? | Y | CSP | All 8 data classes (per `data-handling.mdx#what-we-store`) encrypted at rest. | C1.1 |
| CEK-21.1 | Crypto agility maintained? | Y | CSP | Algorithm choice abstracted via crate boundaries; ADR-required for algorithm change. | CC5.1 |

## DCS — Datacenter Security (15 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| DCS-01.1 .. DCS-15.1 | All physical-DC controls (badge access, visitor logs, environmental, fire, HVAC, media disposal, secure areas, server racks, etc.) | CC | CSP-inherited | **CoreLink operates no owned data centers or offices.** The served product's compute and storage are hosted by Cloudflare; AWS / GCP / Azure are prospective customer-side KMS providers in the BYOK design, not evidenced hosts of customer data. Physical / environmental controls are **inherited** from the actual hosting provider, referenced in `legal/sub-processors.md` and CoreLink vendor risk register `specs/_compliance/VENDOR-RISK-REGISTER.md`. ISO 27001 page §"What we'll formally certify (vs what's inherited)" documents the inheritance pattern. | CC6.4, CC6.5 |

(15 line items collapsed since the inheritance answer is identical; per CAIQ convention, repeat the standard "inherited from CSP" answer with provider-specific SOC 2 Type II report references on full-response submission.)

## DSP — Data Security & Privacy Lifecycle (19 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| DSP-01.1 | Data classification policy established? | Y | CSP | 8 data classes in `apps/docs/docs/trust/data-handling.mdx#what-we-store`. | C1.1 |
| DSP-02.1 | Data inventory maintained? | Y | CSP | ROPA `specs/_compliance/LGPD-ROPA-2026-05-15.md`. | C1.1, P-DSR |
| DSP-03.1 | Data flow mapping documented? | Y | CSP | `apps/docs/docs/trust/data-handling.mdx#customer-data-flow-high-level` + `specs/03_architecture/data_model.md` + `specs/03_architecture/storage_semantics_matrix.md`. | C1.1 |
| DSP-04.1 | Data ownership clearly defined? | Y | CSP | DPA §3: Customer = controller; CoreLink = processor (joint controller for limited service-telemetry). | P-CONSENT |
| DSP-05.1 | Data minimization applied? | Y | CSP | "What we don't store" list at `data-handling.mdx`: no PHI, no CHD, no copies of customer code outside CAS. | P-CONSENT |
| DSP-06.1 | Sensitive data masking / pseudonymization? | Y | CSP | PII redaction in logpush (`pii_redaction_100k_synthetic.rs`); audit-chain salt-rotation pattern (ADR-S11-003) makes PII-bearing claims unrecoverable while preserving chain integrity. | C1.2 |
| DSP-07.1 | Data retention policy enforced? | Y | CSP | Per data class: blobs 90d LRU (customer-tunable); audit chain 7yr; backups 35d rolling; telemetry 13mo. | C1.1 |
| DSP-08.1 | Data disposal verifiable? | Y | CSP | `INV-DATA-ERASURE-COMPLETE` + `INV-ERASURE-ATTESTATION-SIGNED`; admin API `DELETE /v1/tenant/me`. | C1.2 |
| DSP-09.1 | Cross-border transfers governed? | P | CSP | SCC Modules 2/3 executed (`GDPR-SCC-EXECUTION-2026-05-15.md`), and **region pinning is a real supplementary measure** — a served, fail-closed two-layer guard. **BYOK is NOT one, and this row previously claimed it as one:** **BYOK has no verified customer rollout.** `POST /v1/admin/byok/activate` fails closed with `501 Not Implemented` / `byok_not_available` if provider construction or CMK access fails (`crates/corelink-container/src/routes/byok_admin.rs:245-257`); the Dockerfile production build selects `byok-aws-real`, but customer CMK activation, revocation and kill-switch p99 lack runtime evidence. See CEK-09.1. A transfer-impact assessment that counted customer-held keys as a supplementary measure must be re-done without them. | P-CONSENT |
| DSP-10.1 | Consent captured and revocable? | Y | CSP | 6-field JWT receipt + LIA template + `INV-CONSENT-PROOF-VERIFIABLE`. | P-CONSENT |
| DSP-11.1 | Data-subject rights supported? | Y | CSP | DSR runbooks (RB-DSR-INTAKE-FAILURE, RB-DSR-ERASURE-INCOMPLETE). 5-day acknowledge / 15-day resolve (LGPD Art. 18). | P-DSR |
| DSP-12.1 | DPIA performed for high-risk processing? | Y | CSP | DPIA library `specs/_compliance/GDPR-DPIA-LIBRARY.md` + `scripts/validate_dpia.py`. | P-CONSENT |
| DSP-13.1 | Privacy-by-design integrated into SDLC? | Y | CSP | `specs/03_architecture/privacy_model.md` CTRL-PRIV catalog; INV-ONBOARD-DPA-FIRST. | P-CONSENT |
| DSP-14.1 | Pseudonymization / tokenization for sensitive identifiers? | Y | CSP | Tenant IDs are opaque; salt-rotation for audit-chain PII; payment IDs are Stripe-tokens only. | C1.2 |
| DSP-15.1 | Encrypted backups? | Y | CSP | Same envelope as source. | C1.1 |
| DSP-16.1 | Data residency commitments enforced? | Y | CSP | **EU residency enforced/delivered:** EU (`weur`) tenants are served via the `lhr` cluster with CAS/AC blobs in physically-EU R2 buckets (EEUR); the residency guard maps `weur`→`lhr` and refuses cross-region access (`INV-REGION-NO-CROSS-LEAK`). US (`enam`) is the default region (US storage). Brazil/`sam` (no Cloudflare South-America region exists) and APAC physical residency are roadmap, Enterprise-on-request. | P-CONSENT |
| DSP-17.1 | Customer-initiated data export supported? | Y | CSP | Admin API export endpoint; verifiable erasure on termination. | P-DSR |
| DSP-18.1 | Privacy notice published? | Y | CSP | Published; LGPD ROPA + GDPR DPIA library; `privacy@humangr.com` contact. | P-CONSENT |
| DSP-19.1 | DPO appointed and contact published? | Y | CSP | DPO appointed 2026-05-15 (`dpo@humangr.com`). | P-DSR |

## GRC — Governance, Risk & Compliance (8 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| GRC-01.1 | Governance policies established? | Y | CSP | 13-role sign-off matrix; `specs/_governance/`. | CC1.1 |
| GRC-02.1 | Risk-management framework adopted? | Y | CSP | Vendor risk methodology + STRIDE matrix + failure-mode taxonomy. | CC3.1 |
| GRC-03.1 | Compliance program integrates third-party assessments? | Y | CSP | Drata vendor module + 19 vendors in `VENDOR-RISK-REGISTER.md`. | CC9.2 |
| GRC-04.1 | Compliance status reported to executive leadership? | Y | CSP | Weekly compliance digest landed 2026-05-15; quarterly executive review. | CC4.2 |
| GRC-05.1 | Policy exceptions tracked? | Y | CSP | Waiver pattern + GAP register. | CC4.2 |
| GRC-06.1 | Whistleblower / ethics reporting channel? | Y | CSP | `legal@humangr.com` + Code of Conduct; advisor-pool escalation per `specs/_governance/`. | CC1.1 |
| GRC-07.1 | Legal / regulatory monitoring performed? | Y | CSP | External counsel engagement (`legal/legal-externo-engagement-contract.md`); quarterly review. | CC1.1 |
| GRC-08.1 | Insurance maintained? | P | CSP | Cyber-liability broker engagement Q3-2026; ≥ $5M aggregate target. | CC1.1 |

## HRS — Human Resources (13 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| HRS-01.1 | Background verification before hire? | P | CSP | Practice in place; formal documented procedure consolidated Q3-2026 HR refresh. | CC1.4 |
| HRS-02.1 | Acceptable use policy signed at hire? | P | CSP | Code of Conduct + DCO; standalone AUP is **GAP-ISO-02** (T+1m). | CC1.1 |
| HRS-03.1 | Confidentiality agreements signed? | Y | CSP | All personnel + advisors under NDA. | CC1.1 |
| HRS-04.1 | Code of conduct distributed? | Y | CSP | `CODE_OF_CONDUCT.md`; commit `44cdf15`. | CC1.1 |
| HRS-05.1 | Security training delivered? | P | CSP | Drata employee-attestation tracker; annual refresh cadence. | CC1.4 |
| HRS-06.1 | Role-specific security training? | P | CSP | Competence matrix is **GAP-05** (T+3m). | CC1.4 |
| HRS-07.1 | Disciplinary process documented? | Y | CSP | `CODE_OF_CONDUCT.md` enforcement section; Founder + Legal escalation. | CC1.1 |
| HRS-08.1 | Termination procedure documented? | P | CSP | Signed offboarding checklist is **GAP-ISO-05** (T+2m). Today: same-day Clerk + GitHub revocation. | CC6.2 |
| HRS-09.1 | Assets returned at termination? | Y | CSP | Captured in offboarding checklist (GAP-ISO-05 formalizes). | CC6.2 |
| HRS-10.1 | Access revoked at termination? | Y | CSP | Same-day Clerk de-provisioning. | CC6.2 |
| HRS-11.1 | Remote-work security guidance documented? | P | CSP | Remote-first org; clear-desk policy is **GAP-ISO-06** (T+1m); MDM-lite **GAP-ISO-07** (T+3m). | CC6.1 |
| HRS-12.1 | Personnel security incidents tracked? | Y | CSP | IR-TABLETOP-PLAYBOOK + RB-BREACH-NOTIF. | CC7.3 |
| HRS-13.1 | Compliance with HR policies audited? | P | CSP | Drata employee-attestation tracker; manual audit cadence. | CC1.4 |

## IAM — Identity & Access Management (16 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| IAM-01.1 | IAM policy established? | Y | CSP | `specs/03_architecture/auth_model.md` + Clerk identity provisioning. | CC6.1 |
| IAM-02.1 | Strong authentication enforced? | Y | CSP | WebAuthn for admin; MFA enforced via Clerk for customer tenants (CUEC). | CC6.1 |
| IAM-03.1 | Privileged access controlled? | Y | CSP | `PAT-DUAL-APPROVAL-001` + MFA freshness gate + WebAuthn-bound sessions. | CC6.1 |
| IAM-04.1 | Account lifecycle managed? | Y | CSP | Clerk identity provisioning + INV-ONBOARD-DPA-FIRST + same-day offboarding revocation. | CC6.2 |
| IAM-05.1 | Periodic access reviews? | P | CSP | Quarterly cadence target; automation pending — **GAP-01 + GAP-26**. | CC6.3 |
| IAM-06.1 | Segregation of duties? | Y | CSP | PAT-DUAL-APPROVAL-001 for destructive ops; CODEOWNERS for sensitive code paths. | CC6.1 |
| IAM-07.1 | Federated authentication / SSO? | Y | CSP | Clerk SSO; SAML / OIDC supported. | CC6.1 |
| IAM-08.1 | Password / credential policy enforced? | Y | CSP | Clerk-managed; secrets matrix (108 rows) CI-enforced; DEBT-001 closed 2026-05-15 commit `52624e7`. | CC6.1 |
| IAM-09.1 | Session management documented? | Y | CSP | Clerk session lifetime + WebAuthn-bound admin sessions + freshness gate. | CC6.1 |
| IAM-10.1 | Tenant isolation enforced? | Y | CSP | `INV-TenantIsolation` TLA+ model-checked + CI-gated. Per-tenant R2 / D1 / DO / Clerk namespace. **Cross-tenant blast radius zero.** | CC6.1 |
| IAM-11.1 | Customer-administered IAM supported? | Y | CSP | Clerk admin API + tenant-side role assignment. | CC6.2 |
| IAM-12.1 | API key / token lifecycle managed? | Y | CSP | PAT lifecycle managed; revocation API; secrets-drift gate. | CC6.1 |
| IAM-13.1 | Just-in-time / break-glass access logged? | Y | CSP | Append-only BLAKE3 hash-chained audit log; PAT-DUAL-APPROVAL-001 for break-glass. | PI1.2 |
| IAM-14.1 | Identity events logged? | Y | CSP | Clerk audit log + CoreLink audit chain. | PI1.2 |
| IAM-15.1 | RBAC / ABAC enforced? | Y | CSP | Clerk RBAC + per-tenant DO namespace + CTRL-AUTHZ-002. | CC6.2 |
| IAM-16.1 | Customer's IdP integration supported? | Y | CSP | Clerk SAML / OIDC; per-tenant configuration. | CC6.1 |

## IPY — Interoperability & Portability (4 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| IPY-01.1 | Data portability supported? | Y | CSP | Admin API export + CAS bulk-export; REAPI v2 standard format. Portability validation is **GAP-17** (T+3m for full automation evidence). | P-DSR |
| IPY-02.1 | Standard APIs documented? | Y | CSP | REAPI v2 + REST admin API; OpenAPI specs at `apps/docs/docs/reference/`. | CC2.1 |
| IPY-03.1 | Data export format documented? | Y | CSP | REAPI v2 (build artefacts) + JSON (metadata) + NDJSON audit-chain export (BLAKE3 hash chain, offline verification). | P-DSR |
| IPY-04.1 | Vendor-lock-in mitigations published? | Y | CSP | Content-addressable (BLAKE3 / SHA-256) blobs are inherently portable; REAPI v2 standard; export documented in `apps/docs/docs/how-to/migrate/`. | CC2.1 |

## IVS — Infrastructure & Virtualization (9 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| IVS-01.1 | Infrastructure security policy? | Y | CSP | Cloudflare-managed substrate + ISO 27001 §A.8.x crosswalk. | CC6.6 |
| IVS-02.1 | Network segmentation enforced? | Y | CSP | Cloudflare Workers + per-tenant DO + Cloudflare Access edge controls. | CC6.6 |
| IVS-03.1 | Production / non-production isolated? | Y | CSP | Separate tenants; R-6 staging-bake gate. | CC8.1 |
| IVS-04.1 | Virtualization hardened? | CSP-inherited | CSP | Cloudflare Workers use the V8 isolate model; that claim applies to the Worker layer, not the native CoreLink container. Container controls are separately scoped in IVS-05.1. | CC6.6 |
| IVS-05.1 | Container security applied? | P | CSP | The served product includes a native CoreLink container. Its Dockerfile pins the runtime base image digest and runs as non-root `corelink`; an in-repo CycloneDX SBOM covers build-side inventory. This does not by itself establish a complete container hardening or runtime scanning program. | CC6.6 |
| IVS-06.1 | Hypervisor patched? | CSP-inherited | CSP | Cloudflare-managed. | CC6.6 |
| IVS-07.1 | Network monitoring active? | Y | CSP | Grafana SLO dashboards + Cloudflare-native + PagerDuty. | CC7.2 |
| IVS-08.1 | DDoS protection? | Y | CSP | Cloudflare-native DDoS protection (inherited). | CC6.6 |
| IVS-09.1 | DNS / IP allowlisting supported? | Y | CSP | Cloudflare Access + per-tenant allowlist API. | CC6.6 |

## LOG — Logging & Monitoring (13 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| LOG-01.1 | Logging policy established? | Y | CSP | `specs/03_architecture/observability_model.md` + Prometheus catalog. | CC7.2 |
| LOG-02.1 | Logs centralized? | Y | CSP | Grafana Cloud (telemetry) + R2 (audit chain). | CC7.2 |
| LOG-03.1 | Audit log immutability enforced? | P | CSP | **Tamper-EVIDENT, not immutable.** Append-only BLAKE3 hash-chained audit log with a keyed signed head (**`INV-AUDIT-APPEND-ONLY`**); daily fail-closed chain verifier; sealed-chain chunks archived to R2 (`/_internal/audit/archive`). Tampering is *detected at verify time*; it is not *prevented*. The 2026-08-25 R2 Object Lock probe returned `NotImplemented`; the latest 2026-09-09 probe was `INDETERMINATE` because the credential shape was rejected before capability testing. This deployment has no evidenced WORM retention; current provider capability requires a valid fresh probe. A lawful order to delete an audit event is technically executable. | PI1.2 |
| LOG-04.1 | Logs encrypted? | Y | CSP | Same envelope as data class. | C1.1 |
| LOG-05.1 | Logs retained per policy? | Y | CSP | Audit chain 7yr; telemetry 13mo. | PI1.2 |
| LOG-06.1 | Logs reviewed periodically? | Y | CSP | DASH-COMPLIANCE-S20 + Drata daily tick + weekly compliance digest. | CC4.1 |
| LOG-07.1 | Time synchronization enforced? | Y | CSP | NTP via Cloudflare-managed; audit chain timestamps signed. | PI1.2 |
| LOG-08.1 | Privileged-access events logged? | Y | CSP | All admin-API calls + PAT-DUAL-APPROVAL-001 events. | PI1.2 |
| LOG-09.1 | Log tampering detected? | Y | CSP | BLAKE3 hash-chain integrity check (`INV-OBS-AUDIT-CHAIN-INTEGRITY`); reconcile job S-13. | PI1.3 |
| LOG-10.1 | Customer audit logs accessible? | Y | CSP | Admin API + offline hash-chain verification against published heads. | PI1.2 |
| LOG-11.1 | Anomaly detection active? | Y | CSP | SLO burn-rate alerts + Grafana dashboards + PagerDuty. | CC4.1 |
| LOG-12.1 | Forensic-grade log integrity? | Y | CSP | BLAKE3 hash-chained audit log + daily fail-closed integrity verifier (`INV-OBS-AUDIT-CHAIN-INTEGRITY`). No Rekor/Sigstore entries today (roadmap — see `EVIDENCE-PACK-INDEX.md` §1.1). | PI1.2 |
| LOG-13.1 | Logs include sufficient detail for investigation? | Y | CSP | CloudEvents schema with tenant / actor / resource / action / timestamp / signature. | PI1.2 |

## SEF — Security Incident Management, E-Discovery & Cloud Forensics (8 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| SEF-01.1 | Incident response policy? | Y | CSP | `IR-TABLETOP-PLAYBOOK.md` (NIST 800-61 Rev. 2 aligned, 6 scenarios). | CC7.3 |
| SEF-02.1 | IR plan tested? | P | CSP | First live tabletop TT-01 scheduled 2026-07-22. | CC7.3 |
| SEF-03.1 | 24×7 detection? | P | CSP | **The weekly synthetic page does not fire in production.** The Monday 14:00 UTC cron lives in the default `[triggers]` block of `wrangler.toml` (dev) and in `[env.staging.triggers]`; the production environments deliberately omit `[triggers]` — the file says so in its own comment: *"production env intentionally omits `[triggers]`"*. The synthetic-pager image is also still unpinned (`ghcr.io/HumanGuardrail/corelink-synthetic-pager@sha256:<PIN_AT_RELEASE>`). The PagerDuty 24/7 rotation itself is **not verifiable from this repository** — it lives in the PagerDuty account, not in code — so this row neither asserts nor denies it; ask for the schedule export. | CC7.3 |
| SEF-04.1 | Customer breach notification within defined window? | Y | CSP | **72h to ANPD / supervisory authority; 24h to enterprise tenant.** DPA §7. | P-BREACH |
| SEF-05.1 | E-discovery / forensics supported? | Y | CSP | BLAKE3 hash-chained audit log with offline verification; exportable NDJSON. Chain-of-custody in RB-BREACH-NOTIF. | PI1.2 |
| SEF-06.1 | Post-mortem published? | Y | CSP | Public post-mortem within 72h on status page. | CC2.3 |
| SEF-07.1 | Incident history shared with customers? | Y | CSP | `apps/docs/docs/trust/incident-response.mdx#past-incidents`. No customer-impacting SEV1 to date. | CC2.3 |
| SEF-08.1 | Coordinated vulnerability disclosure / safe harbor? | Y | CSP | `apps/docs/docs/security/policy` VDP + RFC 9116 contact card + PGP. | CC7.3 |

## STA — Supply Chain Management, Transparency & Accountability (14 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| STA-01.1 | Sub-processor inventory maintained? | Y | CSP | 8 active sub-processors at `apps/docs/docs/trust/subprocessors.mdx`, each linking its own terms and DPA; 22 total vendors in `VENDOR-RISK-REGISTER.md`. | CC9.2 |
| STA-02.1 | Sub-processor risk-assessed? | Y | CSP | Methodology `specs/_compliance/VENDOR-RISK-METHODOLOGY.md`; 5 Critical-vendor DD files. | CC9.2 |
| STA-03.1 | Sub-processor SLA / DPA in place? | Y | CSP | Each of the 8 active sub-processors is engaged on its own standard online terms and DPA, accepted at account signup and linked from `apps/docs/docs/trust/subprocessors.mdx`. No countersigned copies exist and no acceptance dates are recorded. | CC9.2 |
| STA-04.1 | Sub-processor changes communicated? | Y | CSP | 30-day advance notice per DPA §6 + GDPR Art. 28 §2 + LGPD Art. 27 §4º. | CC2.3 |
| STA-05.1 | Sub-processor SOC 2 / ISO held? | Y | CSP | 13/19 vendors current SOC 2 Type II (≤ 12 mo). | CC9.2 |
| STA-06.1 | Right to audit sub-processors? | Y | CSP | Flow-through via CoreLink DPA §8 + sub-processor DPAs. | CC9.2 |
| STA-07.1 | Sub-processor termination procedures? | Y | CSP | `legal/sub-processors-templates/` termination clauses. | CC6.5 |
| STA-08.1 | Software supply chain attestation? | P | CSP | CycloneDX SBOM maintained in-repo (NDA-shared; hand-refreshed, not per-release) + reproducible builds + public per-binary SHA-256 checksums. **No Cosign signatures, no Rekor entries, no SLSA attestation today** (roadmap — see `EVIDENCE-PACK-INDEX.md` §1.1). | CC6.7 |
| STA-09.1 | Software components inventoried? | Y | CSP | In-repo CycloneDX SBOM (NDA-shared; hand-refreshed, not per-release — `EVIDENCE-PACK-INDEX.md` §1.1); Dependency-Track; license allowlist. | CC6.8 |
| STA-10.1 | Yanked / vulnerable components blocked? | Y | CSP | `INV-SUPPLY-NO-YANKED` + cargo-deny daily + ADR-0037. | CC7.1 |
| STA-11.1 | Build provenance verifiable? | N | CSP | Not today — no transparency-log entry has ever been created (roadmap). Public integrity evidence today: per-binary SHA-256 checksums on releases. | CC6.7 |
| STA-12.1 | Open-source license compliance? | Y | CSP | License allowlist enforced; OSS matrix landed 2026-05-15 (commit `44cdf15`). | CC5.2 |
| STA-13.1 | Sub-processor SOC 2 inheritance documented? | Y | CSP | `legal/sub-processors.md` + ISO 27001 page §"What we'll formally certify vs inherited". | CC6.4 |
| STA-14.1 | Vendor failover tested for Critical vendors? | Y | CSP | 6 of 7 Critical vendors have tested failover (Drata is monitoring-only, no failover required). | A1.2 |

## TVM — Threat & Vulnerability Management (10 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| TVM-01.1 | Vulnerability management policy? | Y | CSP | `specs/03_architecture/security_model.md` + ADR-0024 Dependency-Track. | CC7.1 |
| TVM-02.1 | Scanning at planned intervals? | P | CSP | **Partial cadence.** `cargo-audit` and `cargo-deny` have PR lanes plus daily scheduled lanes; CodeQL is nightly/on demand with no PR trigger; Semgrep is workflow-dispatch-only (its schedule is parked); `cargo-fuzz` is workflow-dispatch-only (its schedule is parked). Do not represent these as one daily or every-PR scanner set. | CC7.1 |
| TVM-03.1 | Severity-based SLA for remediation? | Y | CSP | `RB-STATIC-ANALYSIS-TRIAGE.md`. | CC7.1 |
| TVM-04.1 | Pentest performed at planned intervals? | P | CSP | No external pentest has been commissioned; `CAP-GA-002` remains an unmet hard pre-GA gate. Internal adversarial reviews + cargo-fuzz summary exist, but no external report, NDA availability, or date is promised. | CC7.1 |
| TVM-05.1 | Threat intelligence consumed? | Y | CSP | Dependency-Track CVE feeds + GitHub Advisory Database + cargo-deny daily. | CC3.2 |
| TVM-06.1 | Coordinated disclosure / VDP? | Y | CSP | `apps/docs/docs/security/policy` + RFC 9116 `/.well-known/security.txt` + PGP. | CC7.3 |
| TVM-07.1 | Bug bounty / responsible disclosure? | P | CSP | VDP + safe harbor in place; formal bug bounty deferred to post-GA. | CC7.3 |
| TVM-08.1 | Endpoint scanning? | P | CSP | OS-vendor anti-malware; commercial EDR consolidation Q3-2026. | CC7.1 |
| TVM-09.1 | Web-application scanning? | Y | CSP | Cloudflare WAF + Access + mTLS edge-to-origin. OWASP CRS 4.0 upgrade is **GAP-10**. Static-analysis tools are covered separately under AIS-04.1 and are not represented here as a web-scanning cadence. | CC7.1 |
| TVM-10.1 | Cloud-config drift detection? | Y | CSP | Canonical-consistency validator + secrets-drift gate on every PR; baseline `specs/_audits/sealed/2026-05-15-canonical-consistency-baseline.md`. | CC4.1 |

## UEM — Universal Endpoint Management (14 questions)

| # | Question | A | Resp | Answer + Evidence | TSC |
|---|---|---|---|---|---|
| UEM-01.1 .. UEM-14.1 | All endpoint-management controls (MDM, FDE, anti-malware, OS hardening, patch, inventory, USB control, etc.) | P | CSP | Remote-first organization. **MDM-lite documentation is `GAP-ISO-07` (T+3m)**; full-disk encryption mandatory at hire (`GAP-ISO-05` formal offboarding T+2m); OS-vendor patching cadence; commercial EDR consolidation Q3-2026. Per-control detail available on request. | CC6.1 |

(14 line items collapsed — endpoint posture is the smallest CoreLink attack surface since production access requires WebAuthn-bound session through Cloudflare Access.)

---

## Question count summary

| Domain | Count |
|---|---|
| A&A — Audit & Assurance | 6 |
| AIS — Application & Interface Security | 7 |
| BCR — Business Continuity & Operational Resilience | 11 |
| CCC — Change Control & Configuration Management | 9 |
| CEK — Cryptography, Encryption & Key Management | 21 |
| DCS — Datacenter Security | 15 |
| DSP — Data Security & Privacy Lifecycle | 19 |
| GRC — Governance, Risk & Compliance | 8 |
| HRS — Human Resources | 13 |
| IAM — Identity & Access Management | 16 |
| IPY — Interoperability & Portability | 4 |
| IVS — Infrastructure & Virtualization | 9 |
| LOG — Logging & Monitoring | 13 |
| SEF — Security Incident Management, E-Discovery & Cloud Forensics | 8 |
| STA — Supply Chain, Transparency & Accountability | 14 |
| TVM — Threat & Vulnerability Management | 10 |
| UEM — Universal Endpoint Management | 14 |
| **Total** | **197** |

Matches CSA CCM v4.0.x — 197 questions across 17 domains.

---

## CSP / CSC responsibility summary

For each domain, the canonical CCM v4 responsibility split:

| Domain | CSP-owned | Shared | CSC-owned |
|---|---|---|---|
| A&A | Audit program | Audit-result review | Audit-evidence acceptance |
| AIS | App + API security | API-key custody | App use compliance |
| BCR | Infrastructure resilience | RTO acceptance | Customer-side backup |
| CCC | Production change mgmt | Customer config | Customer-side change |
| CEK | Encryption infrastructure | BYOK key custody | Customer CMK lifecycle |
| DCS | Inherited from sub-processors | — | — |
| DSP | Privacy infrastructure | DSR coordination | Data classification at source |
| GRC | CoreLink governance | Sub-processor risk | Customer governance |
| HRS | CoreLink personnel | — | Customer personnel |
| IAM | Authentication infrastructure | RBAC config | User account custody |
| IPY | Export endpoints | — | Customer use |
| IVS | Cloud substrate | — | Customer cloud-side |
| LOG | Audit chain | Customer log review | Customer-side SIEM |
| SEF | Incident response | Customer comms accept | Customer-side IR |
| STA | CoreLink supply chain | DPA acceptance | Customer supply chain |
| TVM | CoreLink vuln mgmt | Disclosure coordination | Customer-side vuln mgmt |
| UEM | CoreLink endpoints | — | Customer endpoints |

The DPA at `legal/dpa/v1.0.0` formally documents the shared-responsibility split per CCM v4.

---

## Pre-flight checklist

- [ ] Confirm prospect NDA on file with Legal.
- [ ] Send response via `trust@humangr.com`.
- [ ] Bundle artifacts per `EVIDENCE-PACK-INDEX.md`.
- [ ] Watermark response with prospect name + date + CAIQ version (v4.0.x).
- [ ] Cite commit SHA in cover letter.
- [ ] If prospect is targeting CSA STAR Registry submission, advise that CoreLink STAR submission decision is **pending Q1-2027 post SOC 2 Type I report issuance** (rationale: avoid pre-SOC 2 STAR L1 self-assessment then re-listing as STAR L2 post-Type-I — single high-quality submission preferred).

---

## Related

- `marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md` — companion SIG Lite 2026 mapping.
- `marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md` — generic vendor-form response template.
- `marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md` — evidence-pack index.
- `marketing/sales/legal-questionnaires/RESPONSE-SLA-POLICY.md` — turnaround commitments.
- `marketing/sales/FAQ-MASTER.md` §Compliance — canonical phrasing per topic.
- `apps/docs/docs/trust/` — public trust center.
- `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md` — master evidence rollup.
- `specs/_compliance/FEDRAMP-MODERATE-CROSSWALK-2026-05-15.md` §5.1 — for federal-adjacent prospects.
- `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md` §7.1 — for ISO-driven prospects.
- `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` — enterprise-tier engagement playbook.

## Contact

| What you need | Where to send it |
|---|---|
| CAIQ v4 response request (countersigned NDA on file) | `trust@humangr.com` |
| Privacy / data-subject question | `privacy@humangr.com` |
| Security vulnerability report | `security@humangr.com` |
| Procurement / vendor-review forms | `trust@humangr.com` |
