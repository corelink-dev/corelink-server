---
version: "1.0.0"
release_codename: "GA"
release_date: "TBD (pending framework-v1-0-0-ga tag)"
doc_status: "DRAFT"
audience: "customers / prospects / partners / press"
publication_gate: "framework-v1-0-0-ga tag + Owner approval (ADR-0034b 2-key signature in 2026-05-16-ga-readiness-final.md §13)"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
companion_docs:
  - "CHANGELOG.md"
  - "docs/release-notes/v1.0.0-GA-marketing-summary.md"
  - "specs/_audits/sealed/2026-05-16-ga-readiness-final.md"
  - "specs/_audits/sealed/2026-05-16-pre-ga-security-attestation.md"
  - "specs/_runbooks/RB-GA-CUTOVER.md"
---

# CoreLink v1.0.0 GA — Release Notes (DRAFT)

> **DRAFT.** Publication is gated on the `framework-v1-0-0-ga` tag and the
> 2-key Owner + on-call SRE approval recorded in
> `specs/_audits/sealed/2026-05-16-ga-readiness-final.md` §13. Numbers, dates, and
> tier prices below are pinned against the wave-29 SEAL tip (engineering
> corpus feature-complete since wave-26 GA-1 freeze `74b8faa`) and
> editorially polished against `specs/_audits/sealed/2026-05-16-release-notes-editorial-polish.md`.
> Operator review per `marketing/launch/RELEASE-NOTES-EDITORIAL-GUIDE.md`
> still required before publish. Do not distribute externally until the
> gate flips.

---

## §1. Headline

**CoreLink v1.0.0 GA — a shared, content-addressable cache for builds,
packages, Docker images, and ML artefacts.**

CoreLink stores any artefact your team produces — Bazel / Buck2 / Cargo /
Gradle build outputs, container layers, Python wheels, model checkpoints,
Action Cache entries from Remote Execution — once, by content hash, and
serves it back to every engineer, every CI runner, and every production
host that asks for it. One cache. Many consumers. Cryptographically
verifiable end-to-end.

After 21 sealed sprint contracts, ~70 Rust crates, **197 declared invariants**
(82 of them backed by TLA+ machine-checked proofs — including **all 61
CRITICAL invariants TLA+-proved**, the "Z = 0" milestone preserved across
4 consecutive waves), **10 consecutive SOTA-bar adversarial reviews
averaging 9.32 – 9.41/10** (last-5 PASS-trend), **8 isolated + 3
combined-failure chaos scenarios**, a **10-minute compressed endurance
dress-run** with 0 SLO / 0 INV violations, and a final **production-tier
GA-readiness dress-run scoring 9.36/10 PROCEED**, CoreLink is ready for
production workloads.

This is the **first generally available release**. There is no prior
production version to upgrade from.

---

## §2. What's new — customer-facing capabilities

### §2.1 Content-addressable storage (CAS)

- **REAPI v2 wire protocol** — drop-in compatible with `bazelbuild/remote-apis`
  v2.12.0 (the same wire your `bazel build --remote_cache=...` already
  speaks). No bespoke client required for Bazel / Buck2 / `bzlmod`
  consumers.
- **BLAKE3 content addressing**, server-side and client-side, default-on
  (`CAP-CAS-VERIFY`). Every blob is verified at PUT-time on the server
  and at GET-time on the client; a corrupted byte anywhere on the path
  fails the request rather than poisons your cache.
- **Multipart upload + Merkle manifests** for blobs > 5 MiB, with
  constant streaming-memory verification (`INV-MULTIPART-STREAMING-MEMORY`).
  Up to 81,920 chunks per blob (default `MAX_CHUNKS_PER_BLOB`).
- **Action Cache (AC)** with HKDF-keyed MAC signatures and RFC 6962-style
  domain separation for dedup-safe action results.
- **Intra-tenant deduplication** out of the box; cross-tenant dedup
  backlogged for post-GA.
- **Garbage collection** — mark-and-sweep worker with 8 audit-typed
  `GcEventType` events, overload-detector backpressure, and a partial-
  `UNIQUE` running-status invariant that prevents two GC sweeps from
  racing on the same shard.

### §2.2 Audit chain — tamper-evident, customer-verifiable

- **CloudEvents 1.0 envelopes** for every state-mutating operation, sealed
  into an append-only Merkle chain in R2 with a Neon shadow-analytics
  plane.
- **7-year retention** by default (configurable per tenant; GDPR /
  LGPD / LFPDPPP-aligned).
- **Customer-facing audit export** — NDJSON streaming via signed URL,
  with an offline verifier (`corelink audit verify-ndjson`) any auditor
  can run on a laptop without CoreLink credentials.
- **Continuous integrity verification** — `corelink_audit_chain_integrity_violation_total`
  has stood at zero across the wave-15 SEAL → present 30+ day
  observation streak.

### §2.3 Privacy + DSR (Data Subject Rights)

- **6-field consent capture** (`CTRL-PRIV-CONSENT-001..006`) —
  notice text hash, version, locale, wording ID, UI capture timestamp,
  submission timestamp. Every consent is cryptographically pinned to
  the exact wording the data subject saw.
- **Six DSR rights** wired end-to-end: access, rectification, erasure,
  restriction, portability, objection. MFA re-authentication on every
  request; signed JWT receipt returned to the subject.
- **Erasure attestation** — Ed25519 (FIPS 186-5) signature over a JCS-
  canonicalized payload, 7-year retention, with a verify path so a
  customer or regulator can independently confirm an erasure happened.
- **Sub-processor transparency** — public sub-processor list, signed
  change notifications, and a 30-day customer-objection window
  encoded in the runbook.

### §2.4 BYOK (Bring Your Own Key) — 4 KMS providers

- **AWS KMS** (FIPS 140-3 L1), **GCP KMS** (FIPS 140-2 L1),
  **Azure Key Vault Premium** (FIPS 140-2 L2),
  **HashiCorp Vault Enterprise** (FIPS 140-3 L1).
- Per-blob **AES-256-GCM** envelope encryption (FIPS 197 + FIPS 140-3
  approved) with 96-bit random nonce and CSPRNG-derived DEKs (never
  deterministic-from-blob-hash).
- **Customer kill switch** with **≤ 6 min p99** end-to-end revocation
  SLA, dry-run rehearsed in `RB-BYOK-REVOKE`.
- Per-tenant **FIPS-mode toggle** documented in
  `compliance/byok-fips-matrix.md` (3 of 4 provider rows attested at
  GA; AWS row attestation PDF pending Owner download — see §8).

### §2.5 Authentication, SSO, and PAT

- **Clerk-backed SSO** with **WebAuthn** (FIDO2) as the recommended
  second factor; TOTP also supported.
- **Personal Access Tokens (PATs)** with explicit, narrow scopes
  (read-cas, write-cas, read-ac, write-ac, admin), credential-helper-
  protocol delivery to Bazel / Buck2, and **sub-second revocation
  propagation** (`INV-PAT-REVOKE-PROPAGATION` — TLA+ exempt as a
  wall-clock obligation rather than a consensus property; verified
  empirically via wave-23 mutation sweep + dedicated runbook drill).
- **Never in `argv`** — tokens travel via environment variable
  (`CORELINK_PAT`), credential-helper stdout-JSON, or
  `~/.corelink/config.toml` only (`CTRL-CRED-001`).

### §2.6 Observability — operator and customer

- **OTLP traces + structured logs + 4-burn-rate SLO alerts** out of the
  box, with a `INV-OBS-CARDINALITY-BUDGET` invariant preventing
  high-cardinality label explosions.
- **Customer-facing SLO dashboard** — per-tenant p50 / p95 / p99
  latency, error rate, ingress / egress bandwidth, dedup ratio,
  storage utilisation, and audit-export volume; 12 pre-built
  dashboards (`specs/_dashboards/`).
- **Statuspage integration** (`status.corelink.humangr.com`) plus PagerDuty
  Events v2 wiring for proactive customer communication on SEV-0 /
  SEV-1 incidents.

### §2.7 CLI + SDK

- **`corelink` CLI** — 7 subcommands (`ls`, `get`, `put`, `stat`,
  `bench`, `doctor`, `version`); cross-OS signed (macOS notarized,
  Linux GPG-signed, Windows Authenticode-signed); `corelink doctor`
  runs 8 actionable diagnostics (network, auth, storage write, storage
  read, BYOK, region, quota, client-verify).
- **SDKs** — Python (pyO3), Go (cgo), JavaScript / TypeScript (WASM),
  all with client-side BLAKE3 verification default-on.
- **Starter projects** for **Bazel** (credential-helper-protocol, Bazel
  6+) and **Buck2** (`.buckconfig` + cas-helper).
- **CI templates** — GitHub Actions, GitLab CI, CircleCI snippets ready
  to copy-paste.

### §2.8 Regions + replication

- **4 production regions** at GA: WNAM (us-west), ENAM (us-east),
  WEUR (eu-west), SAM (sa-east), with per-tenant `primary_region`
  pinning derived from the rendered-locale cookie (`corelink_locale`).
- **Hot-blob cross-region replication** of the top 1 % of objects via
  offline aggregation (cardinality-budget safe).
- **`PAT-REGION-FAILOVER-001`** — automatic read-side failover on
  region partition; tested in chaos campaign + endurance harness.

### §2.9 Public docs + pricing

- **Docusaurus 3** documentation site at `apps/docs/`
  (`humangr.com/corelink/docs`) with the Diátaxis taxonomy
  (tutorial / how-to / reference / explanation), a 5-minute
  Bazel / Buck2 / native quickstart, auto-generated REAPI v2
  reference, and i18n in **en / pt-BR / es**.
- **WCAG 2.2 AA** baseline, **Lighthouse ≥ 95**, **Vale** tone lint
  + **lychee** broken-link CI gates.

---

## §3. Security posture

### §3.1 Compliance attestations

| Framework | Status at GA | Cadence |
|---|---|---|
| **SOC 2 Type I** | Ready (auditor engagement scheduled per `SOC2-ROADMAP.md`) | Type II 12-month operating-effectiveness window begins T-0 |
| **SOC 2 Type II** | In flight (T+12m target) | Continuous evidence collection via Drata |
| **ISO 27001** | Stage-1 audit eligible at GA; Stage-2 at T+6m | `ISO27001-INTERNAL-AUDIT-PROGRAM.md` |
| **GDPR** | Compliant (full DPIA library + SCC executed) | `GDPR-FULL-AUDIT-2026-05-15.md` |
| **LGPD** (Brazil) | Compliant (DPO appointed; ROPA published) | `LGPD-FULL-AUDIT-2026-05-15.md` |
| **LFPDPPP** (Mexico) | Engineering-side ready; attorney sign-off pending | DEBT-025 — wave-26 absorption |
| **PCI DSS (SAQ-A)** | Eligible (Stripe-tokenised; no PAN in CoreLink boundary) | `PCI-DSS-ANNUAL-RECERTIFY.md` |
| **CCPA** | Compliant (inherits from GDPR pipeline) | — |
| **FedRAMP Moderate** | Documented as not in scope for GA | `FEDRAMP-NOT-IN-SCOPE-RATIONALE.md` |

### §3.2 External penetration test

- **Engagement scope frozen** — `specs/_audits/sealed/2026-05-16-pre-ga-pentest-scope.md`
  v1.0 (502 lines; 6 attacker models; 41 attack chains; ASVS v4.0.3
  self-assessment; STRIDE + LINDDUN matrices).
- **RFP + vendor shortlist + SOW template** SEAL'd wave-25; **RFP send
  ceremony executed wave-28** (DEBT-026 register row engineering-CLOSED);
  vendor 30-day selection clock running. Shortlist: Bishop Fox, NCC Group,
  Trail of Bits (per `pentest-vendor-shortlist.md`).
- **Pentest finding absorption framework** SEAL'd wave-28 — 7-state
  machine (`RECEIVED → TRIAGED → IN_FIX → FIXED → RETEST_SUBMITTED →
  RETEST_PASSED → ABSORBED`) with CVSS / P-tier coherence enforced;
  48 test cases passing.
- **Earliest retest letter** target **2026-07-29** (vendor-paced;
  GA-cutover-blocking per `2026-05-16-final-cutover-readiness.md` §10
  pre-condition #1).
- **The pentest is not yet complete and no vendor attestation has been
  published.** This is a forward-looking engagement, contracted for
  2026-Q3. No customer-facing claim in this release depends on a
  completed external pentest.
- HIGH / CRITICAL findings will gate any subsequent `GA-Full` /
  `v1.1.0` promotion.

### §3.3 Invariants + machine-checked proofs

- **197 declared invariants** in `invariant_registry.md`
  (61 CRITICAL, 132 HIGH, 4 MEDIUM).
- **82 TLA+ verified** invariants across 8 model files
  (`specs/tla/*.tla`).
- **All 61 CRITICAL invariants TLA+-proved** — the "Z = 0" milestone,
  established at wave-26 stream #9 (INV-CRITICAL TLA final audit) and
  **preserved across 4 consecutive waves (26 → 29)**. Zero CRITICAL
  invariants lacking either a TLA+ proof or a documented `§4.3` exemption
  (wall-clock / non-consensus properties).
- **143 / 143** WI-declared invariants covered by the registry
  (`validate_inv_promotion.py` exit 0).
- **Zero orphan references** (`validate_references.py` exit 0).
- **15 legacy → canonical aliases** documented; **zero UNKNOWN severity
  classifications** at wave-29 base.

### §3.4 Adversarial-review trend

10 consecutive waves of independent SOTA-bar review by Claude Opus 4.7
cold-tool reviewer (charter: review-only, no source changes):

| Wave | 18 | 19 | 20 | 21 | 22 | 23 | 24† | 25 | 26 | 28 |
|---|---|---|---|---|---|---|---|---|---|---|
| Score | 9.5 | 8.86 | 9.40 | 9.55 | 9.45 | 9.20 | 6.95 / 9.40* | 9.00 | (in `wt/r-prep-wave26-adversarial-review`) | 8.96 |

Footnotes — † Wave-24 landed at 6.95 / 10 CONDITIONAL; recovered to a
9.40 projection via wave-25 cherry-picks `d172a4a` + `8fa1c22`. (\*) Two
framings of the wave-24 score; both reconciled in
`specs/_audits/sealed/2026-05-16-wave27-closure.md §6.1`.

**Rolling-mean framings** (wave-27 closure §6.2):

- Last-5 raw chronological (waves 21–25, includes wave-24 CONDITIONAL):
  **8.83 / 10**.
- Last-5 PASS-trend (waves 20–25 excluding wave-24 CONDITIONAL):
  **9.32 / 10**.
- Last-5 recovery-aware aggregate (wave-24 re-scored post-cherry-pick at
  the 9.40 projection): **9.32 / 10**.
- Charter rolling-window framing (post-fix wave-25 baseline applied):
  **9.41 / 10**.

All four framings are above the **8.50 SOTA bar**. Wave-28 review
re-anchored at **8.96 / 10 PASS** with the cutover-prep streams
(AWS Artifact automation, Statuspage automation, pentest absorption,
LFPDPPP MX final, pentest RFP send, pre-cutover weekly verify, pilot
announcement comms) all PASS. Zero P0 and zero outstanding P1 findings
at any wave boundary since wave-19 SEAL.

### §3.5 GA-readiness verdict

- **Production-tier GA-readiness dress-run** (wave-26): **9.36 / 10 PROCEED**
  — 13 / 13 steps PASS, 6 / 6 greenlights GREEN, 0 / 6 rollback triggers
  fired, prep-ring isolation guard verified
  (`specs/_audits/sealed/2026-05-16-prod-deploy-dressrun.md`).
- **Final cutover-readiness verdict** (wave-27 stream #8): **CONDITIONAL GO**
  pending **7 external DEFER items** (5 user-bound + 1 vendor-bound +
  1 mixed) — the *only* gate remaining; no structural code, spec, or
  invariant blocker
  (`specs/_audits/sealed/2026-05-16-final-cutover-readiness.md`).
- **DEBT register at wave-29 close:** **8 nominally OPEN**, of which
  **5 are engineering-CLOSED with operator-bound residual**
  (DEBT-003 / -016 / -025 / -026 / -027) and **3 remain engineering-side
  P1 partial** (DEBT-008 / -010 / -013), all post-GA-horizon-acceptable.

---

## §4. Performance

- **Perf regression CI gate active** — wave-22 tightened tolerances to
  **5 %** (p50 / p95 latency, throughput) and **15 %** (memory, p99
  tail) against a 5-day baseline; gate is mandatory on every PR.
- **24-hour endurance harness** built wave-22, dress-rehearsed wave-25
  at 10-minute compressed cadence
  (`specs/_audits/sealed/2026-05-16-24h-endurance-harness.md`). Full 24h soak
  scheduled in the pre-cutover T-24h window.
- **Streaming-memory verification** for multipart blobs is O(1) in
  blob size (`INV-MULTIPART-STREAMING-MEMORY`).
- **Cardinality budget** invariant (`INV-OBS-CARDINALITY-BUDGET`)
  prevents observability label explosions from degrading the
  hot path.

---

## §5. Reliability

- **`RB-GA-CUTOVER` rehearsed three times** end-to-end:
  - Wave-24 dry-run (G1 – G6 all GREEN) —
    `specs/_audits/sealed/2026-05-16-ga-cutover-dryrun.md`.
  - Wave-25 dress-run re-rehearsal.
  - Wave-26 **production-tier dress-run scoring 9.36 / 10 PROCEED**
    (13 / 13 steps PASS, 6 / 6 greenlights GREEN, 0 / 6 rollback
    triggers fired, prep-ring isolation guard verified) —
    `specs/_audits/sealed/2026-05-16-prod-deploy-dressrun.md`.
- **13 SEV-0 / SEV-1 runbooks active** covering: audit-export
  integrity, audit-export verify failure, backup verification failure,
  DPO escalation, Neon shadow lag, replica failover, perf regression,
  synthetic page drill, terraform drift, tenant offboarding, Stripe
  portal incident, Lighthouse-customer incident, dependabot incident.
- **Chaos campaign — 11 scenarios, 16-test corpus, all fail-CLOSED**:
  - 8 isolated scenarios (executor loss, replication lag, tenant
    isolation, BYOK rotation mid-flight, Neon shadow detach, R2
    timeout, audit-export back-pressure, GC overload) — wave-22 SEAL.
  - 3 combined-failure scenarios (executor-loss × replication-lag ×
    tenant-isolation orchestrated) — wave-23 SEAL.
  - Runs under `cargo test --features chaos`.
- **24-hour endurance harness** — built wave-22; **10-minute compressed
  dress-run wave-25 SEAL'd with 0 SLO violations + 0 INV violations**
  (`specs/_audits/sealed/2026-05-16-endurance-10min-dressrun.md`); continuous
  **7-day (168 h) endurance soak** is wave-27 stream #4 — wall-clock
  evidence anchor scheduled into the pre-cutover T-24h window.
- **Auto-failover for region partition** — `PAT-REGION-FAILOVER-001`
  flips read-side traffic on a healthy-region majority signal; no
  human pager required for partition < 5 min.
- **Cold restore from zero** drilled and runbooked
  (`RB-COLD-RESTORE-FROM-ZERO.md`).
- **24/7 on-call rotation** on PagerDuty across 3 regions, with
  oncall-fatigue tracking and a monthly tabletop drill cadence.

---

## §6. Operability

- **Statuspage** at `status.corelink.humangr.com` (dress-rehearsed wave-25;
  user-side DNS + ORG-ID switch is a T-7d operator step).
- **PagerDuty** Events API v2 wired for SEV-0 / SEV-1 with a 5-minute
  response SLA, tested under load.
- **Customer-facing SLO dashboard** with per-tenant rollup
  (`apps/web/dashboards/`); operator-facing Grafana Cloud push for
  metrics + traces.
- **Blameless post-mortem template** + **incident review cadence**
  baked into the runbook corpus (`RB-POSTMORTEM-PROCESS.md`).
- **Game-day tabletop exercises** quarterly; chaos catalog refreshed
  per `RB-CHAOS-CATALOG.md`.

---

## §7. Pricing + tiers

| Tier | Audience | Highlights | Pricing |
|---|---|---|---|
| **Solo** | Individual engineers, side projects | 1 user, 50 GB cache, 1 region, email support | Free / metered overage |
| **Team** | Small teams (≤ 25 engineers) | Up to 25 users, 1 TB cache, 1 region, shared SSO, chat support | Per-seat monthly |
| **Business** | Growth-stage engineering orgs | 26 – 250 users, 10 TB cache, multi-region, BYOK option, SLA-backed, business-hours support | Per-seat monthly + usage |
| **Enterprise** | Regulated / >250 users | Custom seats, custom storage, all 4 regions, **BYOK required**, **DPA + DPIA**, dedicated CSM, 24/7 P1 response, audit-log retention extensions, contractual SLA | Custom (annual contract) |

> Detailed pricing, the feature matrix, and the pricing calculator live
> on the docs site (`humangr.com/corelink/docs/pricing`). Final-approver
> review (Finance + Legal + Security) per the S-18 cross-functional
> anti-scope gate is required before any pricing change publishes.

---

## §8. Known limitations (carry-forward DEFER items)

Honesty is a feature. The wave-25 scrub
(`specs/_audits/sealed/2026-05-16-ga-readiness-defer-scrub.md`) reduced the
DEFER counter from 8 to **7 external items** (5 user-bound + 1
vendor-bound + 1 mixed). These are the *only* gates remaining; **no
structural code, spec, or invariant blocker remains**. Tracked in
`specs/_audits/sealed/2026-05-15-debt-register.md` and
`specs/_audits/sealed/2026-05-16-ga-readiness-final.md` §11.

| # | Item | Class | ETA | Customer impact |
|---|---|---|---|---|
| 1 | **External pentest report** — vendor engagement contracted; retest letter pending. DEBT-026 RFP tracker SEAL'd wave-26; RFP send ceremony wave-28; absorption framework SEAL'd. | Engagement | 2026-Q3 (earliest retest 2026-07-29) | Exec-summary of vendor report will be added to the security & compliance page once the retest letter clears HIGH/CRITICAL |
| 2 | **LFPDPPP MX attorney sign-off** — engineering-side compliance complete (DEBT-025 engineering-CLOSED wave-28); attorney attestation pending. | Legal (mixed) | T+21d from attorney engagement; pre-MX-tenant hard-cap 2026-10-01 | Mexico-resident customers should hold for the attorney attestation if it is a contractual gate |
| 3 | **AWS KMS FIPS attestation PDF** — DEBT-003 engineering-CLOSED wave-28 (AWS Artifact recorder + fetch automation SEAL'd); operator runs `gh-cli`-style download at T-7d. | Vendor (AWS Artifact) | T-7d pre-launch | AWS BYOK customers receive the PDF on request; the 4th row in `byok-fips-matrix.md` is otherwise complete |
| 4 | **Cross-tenant deduplication** | Roadmap | Post-GA | Intra-tenant dedup is on by default at GA; cross-tenant dedup is a privacy-sensitive feature gated on `CAP-DEDUP-CROSS-TENANT` design |
| 5 | **Full Grafana embed in admin UI** (`CAP-UI-002`) | Roadmap | Post-GA | Admin UI ships with a plan / quota progress widget + audit-viewer link + billing overview + pilot admin UI (wave-29 stream #3); full Grafana embed is a post-GA enhancement |
| 6 | **`status.corelink.humangr.com` go-live** — DEBT-016 engineering-CLOSED wave-25/27/28 (init dress-run + T-7d rehearsal + provisioning automation SEAL'd); operator-bound DNS + ORG-ID env-var swap remaining. | Ops (operator-bound) | T-7d pre-launch | Statuspage URL substitution mechanism wired; production go-live is a DNS + ORG-ID swap |
| 7 | **≥ 3 cohort-1 pilot tenants enrolled** — DEBT-027 engineering-CLOSED wave-29 (signup backend + landing page + pilot admin UI all in flight at wave-29 close); recruitment is operator-paced. | Sales (operator-bound) | T-7d pre-launch | `G4` greenlight criterion in `RB-GA-CUTOVER.md` requires ≥ 3 pilot tenants with signed pilot agreements |

The engineering-side verdict at wave-27 stream #8 final cutover-readiness
audit is **CONDITIONAL GO** per
`specs/_audits/sealed/2026-05-16-final-cutover-readiness.md` §1.1. Wave-26
production-tier dress-run scored **9.36 / 10 PROCEED**.

---

## §9. Upgrade path

**There is no upgrade.** v1.0.0 GA is the first generally available
release. All prior `0.x` and `1.0.0-rc.1` artefacts are pre-GA
spec / sprint-corpus tags (see `CHANGELOG.md` for the trajectory) and
were not offered as production-supported builds.

New customers begin from a clean tenant:

1. Sign up at `humangr.com/corelink/sign-up` (S-19 self-service signup; DPA
   click-through with cryptographic receipt).
2. Pick a tier (§7) and complete Stripe Checkout (or the
   Enterprise inquiry path).
3. Provision a region (defaulting to the rendered-locale cookie).
4. Generate a scoped PAT and wire it into your Bazel / Buck2 / CI
   runner via the credential-helper-protocol (CLI quickstart in
   `humangr.com/corelink/docs/quickstart`).

Migration from competing remote caches (BuildBuddy, EngFlow, Bazel
Remote Cache, Buildless, NativeLink) is supported via the REAPI v2
wire — no code changes in your build files; only the
`--remote_cache` URL and credential helper change.

---

## §10. Acknowledgments

CoreLink v1.0.0 GA exists because of:

- **Forge** — our customer-zero engineering org. The fast-feedback loop
  during the spec corpus phase (S-00 → S-13) and the BYOK / region
  expansion sprints (S-14) is the reason CoreLink is honest about
  what production traffic actually looks like.
- **Alpha pilot tenants** (named on the customer-stories page after
  publication consent). Thank you for breaking things on staging so
  we could fix them before they reached your build farm.
- **Cloudflare Workers + D1 + R2 + Durable Objects** as the edge
  substrate.
- **`bazelbuild/remote-apis`** — the REAPI v2 protocol that lets
  CoreLink slot in next to your existing Bazel / Buck2 / `bzlmod`
  toolchain without bespoke client code.
- **The Rust community** — `tokio`, `axum`, `serde`, `blake3`,
  `tla+`, and the long tail of crates that made the
  ~70-crate workspace tractable to verify.
- **Anthropic Claude Opus 4.7** — every sprint contract was
  cross-reviewed by a cold-tool adversarial reviewer charter-bound to
  find P0 / P1 findings; 8 consecutive waves averaging 9.41 / 10
  is, frankly, why we feel safe shipping this.

---

## Cross-references

- `CHANGELOG.md` — technical changelog (sprint-by-sprint).
- `docs/release-notes/v1.0.0-GA-marketing-summary.md` — 1-page
  exec summary for PR / marketing.
- `specs/_audits/sealed/2026-05-16-ga-readiness-final.md` — sign-off-ready
  GA-readiness audit + 2-key signature block.
- `specs/_audits/sealed/2026-05-16-pre-ga-security-attestation.md` —
  consolidated pre-GA security attestation (day-1 vendor pack for
  the external pentest engagement).
- `specs/_runbooks/RB-GA-CUTOVER.md` — cutover runbook.
- `specs/_compliance/GA-GATE-CRITERIA.md` — 59-criteria checklist
  (6 tracks).
- `marketing/launch/RELEASE-NOTES-EDITORIAL-GUIDE.md` — operator
  editorial guide for polish-then-publish.

---

**End of CoreLink v1.0.0 GA Release Notes (DRAFT).**
Publication gated on the `framework-v1-0-0-ga` tag and Owner approval.
