---
id: "SALES-FAQ-MASTER"
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
tags: ["sales", "faq", "objection-handling", "r-prep", "ga", "customer-facing-source"]
---

# CoreLink Sales FAQ — Master (50 Questions)

> **Audience:** anyone running a CoreLink pre-purchase conversation — Founder, Customer Success, partner SE. Each answer is the **canonical phrasing**. Use it as-is in a doc; paraphrase in conversation.
> **Tone:** factual, falsifiable, no marketing varnish. Every numeric claim has a source pointer in `PROOF-POINTS.md`.
> **What this is not:** a contract. The DPA, MSA, and order form override anything here.
> **Companion docs:** `marketing/sales/OBJECTION-HANDLING.md` · `marketing/sales/COMPETITIVE-MATRIX.md` · `marketing/sales/PROOF-POINTS.md` · `apps/docs/docs/trust/` · `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` · `marketing/launch/LAUNCH-CHECKLIST-V2.md` · `marketing/sales/legal-questionnaires/` (SIG Lite + CAIQ v4 + vendor template + evidence index + response SLA).

---

## How to use this file

- The 50 questions are grouped into six topic blocks: **Pricing (8), Security (12), Compliance (8), Performance (6), Operations (8), Migration (8)**.
- Each entry has: **Q**, **A** (short canonical answer), **Sources** (doc / spec / commit pointers).
- If a prospect's question isn't here, route to `trust@humangr.com` rather than improvising — and file the new question against this doc.

---

## Pricing (8)

### P1 — How do the tiers compare (Free / Solo / Starter / Pro / Max / Enterprise)?

**Q:** What do I actually get at each tier?

**A:** Six tiers on one self-serve ladder — Free is instant-activation, Solo / Starter / Pro / Max self-serve via Stripe Checkout, and Enterprise routes through the inquiry form. The differences that matter at sales time are storage cap, egress allowance, audit retention, region count, and the SLA we sign (BYOK is **not shipped on any tier** — see P3/S1) — not capability (every tier runs the same data plane and SLO catalog).

| Limit | **Free** | **Solo** | **Starter** | **Pro** | **Max** | **Enterprise** |
| --- | --- | --- | --- | --- | --- | --- |
| Monthly price | $0 | $15 | $35 | $50 | $149 | Contact us |
| Storage cap | 10 GB | 50 GB | 150 GB | 500 GB | 2 TB | Custom |
| Egress / mo | 50 GB | 500 GB | 1.5 TB | 5 TB | 20 TB | Custom |
| Audit retention | 7d | 30d | 30d | 90d | 90d | 365d+ |
| BYOK | **not shipped** | **not shipped** | **not shipped** | **not shipped** | **not shipped** (was listed as a $99/mo add-on) | **not shipped** (was listed as included) |
| Region pin | shared | 1 of 4 | 1 of 4 | up to 2 | up to 2 | all 4 |
| Uptime SLO | best-effort | 99.5% | 99.5% | 99.9% | 99.9% | 99.95% |

**Lighthouse** is our design-partner pilot **program**, not a separate billing tier — a Lighthouse customer still lands on one of the six tiers above (typically comped or discounted) and gets the extra concierge playbook (`marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`) layered on top. Per-tier TPS ceilings live in the rate-limit ladder (`marketing/sales/RATE-LIMIT-FAQ.md` RL1) — that ladder is versioned separately from this pricing ladder; check `crates/corelink-ratelimit/src/tier.rs` for the current mapping before quoting a number.

The egress numbers are *generous* by build-cache standards because the underlying R2 substrate has zero egress fees on cache reads (see `BLOG-POSTS/05-fast-cache-hit-economics.md`); the cap exists to prevent abuse, not to extract bandwidth rent.

**Sources:** `apps/docs/docs/explanation/pricing/index.mdx`; `crates/corelink-tier-selection/src/tier.rs`; `marketing/sales/PRICING-WORKSHEET.md`.

### P2 — How does overage work? Do we get rate-limited or billed?

**Q:** If we blow through our tier's storage / TPS / egress cap, what happens?

**A:** Hard cap, not overage billing. At v0.1 **every priced tier is hard-capped** (`hardCap: true` in `apps/docs/src/lib/pricing.ts`; `PRICING-WORKSHEET.md` agrees). Concretely: at 80% of your storage cap we notify you (webhook + email); at 100% writes return `429` with an upgrade CTA until you upgrade or free space — there is **no metered overage invoice** (metered overage is deferred to v0.2 per `PRICING-WORKSHEET.md`). TPS above your token bucket simply gets `429` + `Retry-After` per the rate ladder. For Enterprise, caps and any burst headroom are governed by your order form. We are happy to convert a cap ceiling into a contractual tier upgrade with no penalty (see P5 — migration discount).

**Sources:** SLO catalog (`specs/03_architecture/slo_catalog.md` — internal; no public SLO page is published today, `/slo` 404s); overage runbook (`specs/_runbooks/RB-BILLING-OVERAGE.md`); quickstart-faq Q8.

### P3 — Is BYOK a premium? How much more?

**Q:** What does BYOK actually cost on top of Enterprise base?

**A:** **BYOK is not shipped, and must not be sold or priced today.** The activation endpoint returns `501 byok_not_available`: `crates/corelink-container/src/routes/byok_admin.rs:249` refuses activation whenever no real KMS provider is compiled in, and none is — `Dockerfile:182` builds `corelink-server` with no `--features`, and `crates/corelink-container/Cargo.toml:16` declares `default = []`, so the four `byok-*-real` features (AWS, GCP, Azure, Vault) are not enabled by any build path. The provider that the released binary actually links is selected at **compile time**: `crates/corelink-container/src/byok_orchestrator.rs:263-271` carries a `#[cfg(not(any(feature = "byok-aws-real", … "byok-vault-real")))]` arm whose body is `Ok(Arc::new(InMemoryFake::new()))`. With no feature set, that arm is the one compiled. `InMemoryFake`'s own doc comment (`:279`) says **"Not for production"** and describes wrapping a DEK by "storing the plaintext bytes as the ciphertext (XOR-masked with a fixed module-private key)"; the mask constant's own comment (`:296`) states that it "offers no cryptographic confidentiality".

A prior version of this answer sold BYOK as included on Enterprise and as a $99/mo add-on on Max, and justified the premium with "(4) the weekly synthetic kill-switch chaos drill we run on your tenant", closing with *"we don't run BYOK as a marketing checkbox; the kill switch is exercised on a schedule and recorded in the audit chain."* **No such drill runs on any tenant, against any KMS** — see S11 for the precise shape of what does run on a schedule (`byok_kill_switch_drill_weekly.yml`, a shell simulation with hard-coded PASS values that contacts no KMS and no CoreLink binary). Reps must not quote a BYOK price or a drill cadence until the feature ships; pricing is a fresh decision at that point, not a restatement of the withdrawn numbers.

**Sources:** `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md`; `apps/docs/docs/trust/data-handling.mdx#encryption`.

### P4 — What enterprise discounts are available?

**Q:** What levers do you have on price?

**A:** Three structural levers, in order of usual impact: (1) **multi-year commit** — 1y / 2y / 3y discounts; the 3y is the largest single move and triggers Founder-level approval. (2) **annual prepay** vs. monthly. (3) **volume commit** — committed storage / egress / TPS bands negotiated above the next-tier list. We do *not* discount on SLO (the SLO catalog is canonical — adding or weakening SLOs requires a spec contract waiver, see `marketing/lighthouse-kit/07-pricing-comparison-internal.md` §4). We do *not* discount on audit-chain retention — it is a structural invariant, not a negotiable line item. (A prior version of this line also listed "BYOK kill-switch latency" as non-negotiable; BYOK is not shipped, so there is no latency to negotiate or refuse — see P3/S1.)

**Sources:** `marketing/lighthouse-kit/07-pricing-comparison-internal.md` §4 (decision rules for negotiating off standard offer).

### P5 — Migration discount: what is it and who qualifies?

**Q:** If we're switching from bazel-remote / BuildBuddy / a self-hosted cache, do we get a transition price?

**A:** Yes — the **migration credit**. Customers actively decommissioning a competing remote-cache deployment receive 3 months at 50% of list on their paid self-serve tier (Solo / Starter / Pro / Max, or Enterprise equivalent), conditional on (a) signing the standard MSA, (b) committing to a minimum 12-month term, and (c) participating in a non-binding 30-minute "what made you switch" interview at month 4 (used internally for product roadmap; not published without your sign-off). The credit does not stack with the lighthouse program (which is more generous but capacity-constrained — see P7).

**Sources:** `marketing/lighthouse-kit/07-pricing-comparison-internal.md`; sales decision tree (internal).

### P6 — Churn refund: if we leave, do we get money back?

**Q:** If we cancel mid-term, what's the refund posture?

**A:** Two cases. (1) **You cancel for convenience** (mid-annual-prepay): you receive a prorated refund of unused months minus a 30-day notice equivalent. We do not enforce minimum-term penalties beyond the unused-prepay clawback. (2) **You cancel for cause** (an SLA breach we've acknowledged via the public status page, or a material DPA breach): full refund of the current paid period plus an exit-assistance window. The audit-chain export is included free in either case — your data is yours, content-addressed, and portable by construction (you can leave any time; we are aware "BLAKE3 digests are content-addressed" is *itself* an escape hatch, see P34).

**Sources:** standard MSA §10 (cancellation); `legal/dpa/v1.0.0` §11 (termination).

**Self-service surface.** Free, Solo, Starter, Pro, and Max cancel through the Stripe Customer Portal — see the customer guide at `apps/docs/docs/how-to/billing/manage-subscription.mdx` (published as `/how-to/billing/manage-subscription`). Enterprise cancellation routes through your sales contact for the paper amendment + DPA closure (see `specs/_audits/sealed/2026-05-15-stripe-customer-portal-spec.md` §2.2 — Enterprise downgrade rule).

### P7 — Can we sign a multi-year contract?

**Q:** What does 2y or 3y look like?

**A:** Both available. The trade is depth-of-discount-for-commit-length, with two protections written in:

- **Price-lock for the term.** List-price increases during the term do not apply to you.
- **Annual re-baseline option.** You can renegotiate downward (not upward) once per year if your actual usage falls below the committed band — we don't want to be the vendor your CFO has to justify a clawback against.
- **Exit ramp.** If at the 12-month or 24-month mark you'd rather not continue, you give us 90 days notice and a one-time exit fee that is *less* than the discount you've already received. We make the math defensible internally and verbal in the negotiation.

**Sources:** sales playbook (internal); `marketing/lighthouse-kit/07-pricing-comparison-internal.md` §4.

### P8 — Is pricing different per region?

**Q:** Do you charge more for any region, or for cross-region replication?

**A:** CoreLink operates today from a **US (ENAM) region** (the default) and a physically-EU (WEUR) region for EU tenants — both with flat single-region pricing, so there is no per-region price differential. The R2 substrate's zero-egress economics are what make cache-hit pricing flat (see `BLOG-POSTS/05-fast-cache-hit-economics.md`). Additional regions (Brazil/`sam`, APAC) and cross-region replication are on the **roadmap** (see `BLOG-POSTS/04-multi-region-residency.md`); when replication ships it will be an Enterprise opt-in with a metered, transparent per-replicated-blob storage line shown on the invoice.

**Sources:** `marketing/launch/BLOG-POSTS/04-multi-region-residency.md`; `apps/docs/docs/trust/data-handling.mdx#residency`.

---

## Security (12)

### S1 — What does "BYOK" actually mean at CoreLink? Are you holding our keys?

**Q:** Is your BYOK real, or is it "we'll let you bring an opaque token we still hold the keys to"?

**A:** **Not today — the design below is what BYOK *will* do, and none of it is in the released binary.** The activation endpoint returns `501 byok_not_available` (`crates/corelink-container/src/routes/byok_admin.rs:249`), because no real KMS provider is compiled in (`Dockerfile:182`, no `--features`; `Cargo.toml:16`, `default = []`). The provider that *is* linked is chosen at compile time by the `#[cfg(not(any(feature = "byok-aws-real", …)))]` arm at `crates/corelink-container/src/byok_orchestrator.rs:263-271`, which constructs `InMemoryFake` — documented at `:279` as **"Not for production"**, wrapping a DEK by storing the plaintext XOR-masked with a fixed module-private key whose own comment (`:296`) says it "offers no cryptographic confidentiality". A prior version of this answer opened with the single word "Real." — it must not be restored. What follows is the DESIGN, and every sentence of it should be read in the future tense.

Your KMS holds the **Key Encryption Key (KEK)**. CoreLink generates per-blob **Data Encryption Keys (DEKs)**, wraps each DEK under your KEK, and stores the wrapped DEK alongside ciphertext. To read a blob we call your KMS to unwrap. We do **not** hold a copy of your KEK, encrypted or otherwise. There is **no break-glass path** that re-derives plaintext from CoreLink-side material alone. The DEK cache TTL is **hard-capped at 5 minutes** — a code path, not a config knob — which bounds your kill-switch window. When you disable your KEK, within 5 minutes every in-flight DEK expires and CoreLink simply cannot read your data. This is the `INV-BYOK-CRYPTO-SOVEREIGNTY` CRITICAL invariant.

**Sources:** `crates/corelink-container/src/routes/byok_admin.rs` (the `501`); `crates/corelink-container/src/byok_orchestrator.rs:263-296` (the `InMemoryFake`); `Dockerfile:182` + `Cargo.toml:16` (no provider feature compiled in).

> **Do not send a prospect to the old sources for this answer.** `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md`, `ADR-S14-004 / S14-005 / S14-006` and `apps/docs/docs/trust/data-handling.mdx#encryption` all describe BYOK **in the present tense, as delivered**, and therefore contradict this answer. They are the design record; they are not evidence, and they are not customer-safe until they are corrected (tracked under B-083).

### S2 — Show me an audit-chain inclusion proof I can verify offline.

**Q:** How do I, the auditor, verify that an event I received was actually in the chain at the time you say it was?

**A:** Three steps you (or your external auditor) run yourself, with no CoreLink-side trust required: (1) JCS-canonicalize the event payload per RFC 8785; (2) recompute the BLAKE3 chain links across the exported window containing the event; (3) compare the recomputed head against any later published head. Verification cost is linear in the window you replay — the chain is deliberately a simple hash chain, not a Merkle tree, so there is no logarithmic inclusion proof; in exchange, any insertion, deletion, or reorder breaks every subsequent link and cannot hide. We publish a reference verifier in Rust + TypeScript that produces bitwise-identical canonical output. This is `INV-AUDIT-APPEND-ONLY` + `INV-OBS-AUDIT-CHAIN-INTEGRITY`, both CRITICAL, both modeled in `audit_immutability.tla` and checked in CI.

**Sources:** `marketing/launch/BLOG-POSTS/03-audit-chain-merkle-proofs.md` (full walk-through); `/security/audit-chain` (docs).

### S3 — What are the tenant-isolation guarantees? Specifically, what's the cross-tenant blast radius?

**Q:** If tenant A is compromised, what's the worst case for tenant B?

**A:** Cross-tenant blast radius is engineered to **zero**. Tenant A cannot read, write, or enumerate tenant B's blobs. This is the `INV-TenantIsolation` invariant — TLA+ model-checked (`tenant_isolation.tla`) and gated in CI. Every CAS read, every AC write, every audit append carries a verified tenant binding; cross-tenant access is structurally impossible. AAD binding (`tenant_id || blob_hash || cache_id`) means even if an attacker could substitute ciphertext, the AEAD primitive (AES-GCM-256 / ChaCha20-Poly1305 per provider) would reject the decryption. An external penetration test with a tenant-isolation adversarial scenario is planned pre-GA; no report exists yet.

**Sources:** `apps/docs/docs/trust/index.mdx#posture-at-a-glance`; `marketing/launch/BLOG-POSTS/01-introducing-corelink.md`; `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md` (AAD binding); `specs/03_architecture/security_model.md`.

### S4 — What's your SOC 2 status?

**Q:** Do you have a SOC 2 report?

**A:** Not yet — and we're explicit about it. **Internal readiness:** 83.7% weighted as of 2026-05-15 (per the auditor-grade Drata rollup, not a marketing percentage). **Type I fieldwork:** target Q4 2026, report Q1 2027. **Type II fieldwork:** target Q3 2027, report Q4 2027. **Audit partner:** Schellman & Co. (engagement letter executed). **Continuous-evidence platform:** Drata. We crosswalk to **ISO 27001:2022 at 98.9% in-scope** today (Stage 1 stacked with SOC 2 Q4-2026, certificate Q1-2027). Today's evidence is available under NDA from `trust@humangr.com` (1 business day SLA on the routing).

**Sources:** `apps/docs/docs/trust/compliance.mdx#soc-2`; `apps/docs/docs/trust/iso27001.mdx`; `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`.

### S5 — Have you done an external pentest?

**Q:** When was the last pentest? Can we see the report?

**A:** No — and we say so plainly: **no external penetration test has been commissioned.** No firm is engaged and no report, NDA availability, publication date, or cadence is promised. `CAP-GA-002` remains a hard pre-GA gate; it requires independent report and retest evidence with no outstanding HIGH or CRITICAL findings before GA may be claimed. In the meantime, internal adversarial reviews and cargo-fuzz summaries are tracked (SIG Lite G.11). We will never describe a pentest as run or clean until a report exists.

**Sources:** `apps/docs/docs/explanation/compliance/pentest-summary.mdx`; `marketing/sales/PROOF-POINTS.md` 2.12; SIG Lite A.4 / G.11.

### S6 — What encryption do you use, and where?

**Q:** At rest, in flight, in use — be specific.

**A:** **At rest:** AES-256-GCM. R2 blobs are Cloudflare-managed SSE by default. Customer-side envelope encryption per blob (per-tenant DEK wrapped by your KMS root) is what BYOK **will** add; BYOK is not shipped today, so Cloudflare-managed SSE is the whole of the at-rest story right now — see S1. D1, KV, DO are Cloudflare-managed encryption at rest. Backups same envelope as source. **In flight:** TLS 1.2 minimum (TLS 1.3 negotiated with every client that supports it — the 1.2 floor is deliberate so `native-tls`/SecureTransport clients like `sccache` connect, per ADR-0072); HSTS (`max-age=63072000; includeSubDomains; preload`); HTTP/2 + HTTP/3 available; cipher suites limited to AEAD (AES-256-GCM, ChaCha20-Poly1305); mTLS edge-to-origin per CTRL-NET-002. **In use:** Worker isolates provide per-request memory isolation (V8 isolate model); customer bytes are not held in long-lived memory across requests; under the BYOK design, plaintext DEKs would never leave the request scope and would be discarded before the isolate recycles — but BYOK is not shipped, so this is design, not a current property.

**Sources:** `crates/corelink-container/src/routes/byok_admin.rs` (BYOK returns `501`); ADR-0072 (the TLS 1.2 floor); CTRL-NET-002 (mTLS edge-to-origin).

> Same caveat as S1: `apps/docs/docs/trust/data-handling.mdx#encryption` and `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md` describe BYOK as shipped and contradict this answer (B-083).

### S7 — How does key rotation work?

**Q:** When and how are KEKs / DEKs rotated?

**A:** **KEK rotation is a customer operation.** CoreLink does not initiate KEK rotation; we observe it. When you roll your CMK, we re-wrap existing DEKs against the new KEK in an online background job, with progress visible in your dashboard and recorded in the audit chain. You can run with multiple active CMK versions; we choose the right one per object based on wrapped-DEK metadata. **DEKs are per-blob** and never re-used across blobs, tenants, or regions — there is no DEK rotation cadence because every blob already has a fresh DEK. **PAT rotation:** revocation propagates globally in **< 60s** (P95 measured by the FM-061 rotation drill).

**Sources:** `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md#rotation-audit-operational-details`; `apps/docs/docs/tutorials/quickstart-faq.mdx#10`.

### S8 — What's your breach-notification commitment?

**Q:** If you confirm a personal-data breach, when do we hear about it?

**A:** **72 hours** to authorities (LGPD Art. 33 / GDPR Art. 33), **24 hours** to the affected enterprise tenant (per DPA §7), and **without undue delay** to affected high-risk data subjects (GDPR Art. 34). The 72-hour clock starts at **awareness** — the moment we have reasonable certainty a breach occurred. We have a documented internal escalation that puts the decision in front of the DPO and Security Lead within 4 hours of suspicion — well inside the regulatory window.

**Sources:** `apps/docs/docs/trust/incident-response.mdx#breach-notification`; `specs/_runbooks/RB-BREACH-NOTIF.md`.

### S9 — Where do my secrets / PATs live?

**Q:** How are personal access tokens stored, and how do I avoid leaking them?

**A:** Stored hashed in our Clerk-backed identity store (server side never sees plaintext after issuance). The CLI **does not accept** `--pat` as a flag (security control `CTRL-CRED-001` — flags leak into shell history and `ps aux`); reads from `CORELINK_PAT` env var or `~/.corelink/config.toml`. Token format `corelink_<env>_t_xxx.xxx.xxx` makes the environment explicit (`sandbox / dev / staging / prod`); mixing environments is rejected at the edge with `COR_AUTH_TENANT_MISMATCH`. Revocation propagates in < 60s globally.

**Sources:** `apps/docs/docs/tutorials/quickstart-faq.mdx#9-11`.

### S10 — Does the CLI verify bytes after download?

**Q:** Could I receive a corrupted or tampered blob?

**A:** No — client-side BLAKE3 re-hash is **default-on** (control `CTRL-CAS-002`). A mismatch raises `COR_CAS_DIGEST_MISMATCH` and the process exits non-zero **before the bytes touch your filesystem**. The single Rust truth `corelink-client-verify` is wrapped by all four official SDKs (Rust / Python / Go / JS); there is no per-language hash drift. You can opt out via SDK construction (`client_verify=False`) but we don't recommend it; the CLI does not offer an opt-out flag.

**Sources:** `apps/docs/docs/tutorials/quickstart-faq.mdx#12, #6`.

### S11 — How is the kill switch tested? What proves it actually works?

**Q:** "We support BYOK kill switch" is easy to claim. How do you exercise it?

**A:** **Nothing proves it, because the kill-switch loop has never run.** There is no weekly synthetic chaos drill, on any tenant, against any KMS. The kill-switch loop is written — `crates/corelink-byok/src/byok_revocation/detector.rs:147` defines `pub async fn run_loop(self)`, described in its own comment as *"the core kill switch implementation"* — but it has **no caller anywhere in the workspace**. Measured over **every `.rs` file in the repository** (not just `crates/`): `grep -rn --include='*.rs' "run_loop" .` returns exactly **one** line, and that line is the definition itself — not the released binary, not another crate, not a test. **State the scope precisely, because the adjacent claim is false and a hostile reader will use it:** the per-cycle body *is* covered — `RevocationDetector::run_one_cycle`, which `run_loop` calls every iteration via `run_cycle_inner`, has **five** test call sites over the same population (`crates/corelink-byok/tests/byok_revocation_prop_revocation.rs:101` and `:288`; `crates/corelink-byok/tests/byok_revocation_adversarial.rs:120` and `:158`; `tests/e2e-byok-revoke/tests/happy_revoke_flow.rs:139`), and `detector.rs:144` says so in its own doc comment (*"Use `run_one_cycle` in tests"*). So: the revocation **logic** is exercised by property and adversarial tests; what has never run is the **loop that would drive it in production**, and no drill has ever exercised it against a real KMS or a real tenant. Do not say "not a test" without that qualification. And the crate is not merely absent — it *ships*: `cargo tree -p corelink-server --target x86_64-unknown-linux-gnu --edges normal -i corelink-byok` shows `corelink-byok` linked directly into `corelink-server`. The kill-switch loop is compiled into the binary we deploy and never entered. BYOK activation itself returns `501` (see S1).

A prior version of this answer described a *"**Weekly synthetic chaos drill** scheduled at a time you prefer, on your tenant, against your KMS"*, measuring round-trip time against a ≤ 5 min target and recorded in the audit chain, plus cross-tenant adversarial scenarios in staging. **None of that happens.** If a prospect asks how the kill switch is exercised, the honest answer is that it is not, and that BYOK is not available.

**What a prospect may nonetheless see, stated precisely so we are never caught understating it:** a workflow named `.github/workflows/byok_kill_switch_drill_weekly.yml` **does exist, is on `cron: 0 3 * * 0`, and its 8 most recent runs (all `schedule`, 2026-07-05 → 2026-08-30) are green.** It proves nothing, because what it executes — `scripts/byok_kill_switch_drill.sh`, 181 lines of shell — **contacts no KMS, no CoreLink API, and no CoreLink binary at all** (every KMS credential in the job is commented out). Every asserted outcome is a shell literal: `TENANT_STATUS="active"` (`:51`), `DETECTED=true` (`:82`), `DEK_CACHE_EMPTY=true` (`:100`), `TENANT_STATUS_POST="degraded_read_only"` (`:101`), `RECOVERY_STATUS="active"` (`:129`). The "≤ 5 min" round-trip is `date +%s` taken before and after a `sleep 2` (`:62`, `:81`, `:112`). No assertion in it can be false, so the green is structurally inevitable, and no run has ever left evidence in the repo — the report step `git commit`s without `git push`, and `ls specs/_audits/ | grep -c byok-kill-switch-drill` returns **0**. These are the same **facts** the CAIQ `CEK-10.1` and SIG-LITE `N.6` carry — the wording is not identical across the three documents (`N.6` omits two of the shell literals, the CAIQ adds a code citation and a closing instruction, and only this FAQ states outright that the drill proves nothing), so cite the facts, not a shared sentence. Do not describe those facts any other way.

**Sources:** `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#what-were-measuring-daily-automated`; `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md#the-kill-switch`; `.github/workflows/byok_kill_switch_drill_weekly.yml`; `scripts/byok_kill_switch_drill.sh`.

### S12 — Has anyone ever cross-tenant-leaked? Has there been any customer-impacting incident?

**Q:** What's the incident history?

**A:** Today (2026-05-15): **No customer-impacting SEV1 incidents since the platform's first paid traffic.** This is published on the Trust Center incident-response page and will be populated as needed (with post-mortem links) when an incident occurs. We are aware "no incidents yet" is partly a function of how young the production fleet is; we don't claim it as evidence of perfection. Our 24/7 on-call across three regions and a weekly synthetic page (sustained for 30 days pre-GA) verify the rotation actually pages — `marketing/launch/STATUS-PAGE-SPEC.md`.

**Sources:** `apps/docs/docs/trust/incident-response.mdx#past-incidents`.

---

## Compliance (8)

### C1 — SOC 2 status?

**Q:** Type I when? Type II when?

**A:** Type I fieldwork Q4 2026, report Q1 2027. Type II fieldwork Q3 2027 (after the minimum 6-month observation), report Q4 2027. Auditor: Schellman & Co. Continuous-evidence platform: Drata. Readiness today: 83.7% weighted (113 of 135 weighted criterion-points green; 2 reds, both BYOK-FIPS attestation gaps with D+30 closure cap and a fallback ADR if attestation letters slip). All major gaps close before Type I fieldwork; all minor gaps close before the Type II observation window cuts. See S4.

**Sources:** `apps/docs/docs/trust/compliance.mdx#soc-2`.

### C2 — LGPD (Brazil)?

**Q:** Are you LGPD compliant?

**A:** Brazil/SAM physical residency is not provisioned. R2 residency statements do not apply to the shared global D1 control plane, whose primary is currently reported in ENAM with no D1 jurisdiction. Counsel approval of applicable customer-facing transfer terms remains pending; this prelaunch FAQ does not claim an executed SCC or supplementary-measures posture for D1.

**Sources:** `apps/docs/docs/trust/compliance.mdx#lgpd`; `apps/docs/docs/trust/data-handling.mdx#residency`; `/residency/lgpd-brazil`.

### C3 — GDPR?

**Q:** Are you GDPR compliant?

**A:** EU (`weur`) CAS and AC blobs use physically-EU R2 buckets through London/`lhr`; that is an R2 residency statement. The D1 control plane is shared globally, with its primary currently reported in ENAM and no D1 jurisdiction. Counsel approval of applicable customer-facing transfer terms remains pending, so this prelaunch FAQ does not claim an executed SCC, BYOK, or crypto-erase safeguard for D1.

**Sources:** `apps/docs/docs/trust/compliance.mdx#gdpr`; `marketing/launch/BLOG-POSTS/04-multi-region-residency.md`.

### C4 — ISO 27001?

**Q:** Are you ISO 27001 certified?

**A:** Not yet — **certification target Q1-2027** with Schellman (Stage 1 audit Q4-2026 stacked with SOC 2 Type I fieldwork; Stage 2 + certificate issuance Q1-2027). Today's crosswalk: **98.9% in-scope Annex A coverage** (89 of 90 applicable controls Implemented or Partial). 91% overlap with SOC 2 Type I evidence collection in Drata. Single Gap row (A.5.10 Acceptable Use Policy formalization) closes in T+1m. First-year cert cost envelope $55–90k (Stage 1 + Stage 2 combined).

**Sources:** `apps/docs/docs/trust/iso27001.mdx`.

### C5 — HIPAA?

**Q:** Can we use CoreLink for PHI?

**A:** **Out of scope by design.** CoreLink is a build-artefact cache; it does not handle PHI. We will **not** sign Business Associate Agreements (BAAs) for production PHI workflows. The underlying infrastructure (Cloudflare / AWS / GCP / Azure) is HIPAA-aligned at the substrate level, but CoreLink's product surface is not engineered, scoped, or tested for PHI, and we do not commit to the Privacy / Security / Breach Notification rules. If your build artefacts contain PHI, that's likely an upstream tagging bug — raise a SEV-2 with your account team.

**Sources:** `apps/docs/docs/trust/compliance.mdx#hipaa`.

### C6 — PCI DSS?

**Q:** Can we use CoreLink in a PCI cardholder-data environment?

**A:** **SAQ-A compliant (self-attested 2026-05-15)** — meaning CoreLink itself is *not* in your PCI CDE, and we never see card data. All cardholder data is tokenized at the edge via Stripe Elements (PCI DSS Level 1 Service Provider); CoreLink only stores opaque Stripe IDs (`cus_…`, `sub_…`, `pm_…`, `in_…`). We do not store, transmit, or process card data — zero, never. Stripe AOC is inherited via the Drata vendor module. Next recertification: 2027-05-15 (annual cadence).

**Sources:** `apps/docs/docs/trust/pci-dss.mdx`; `specs/_compliance/PCI-DSS-SAQ-A-2026-05-15.md`.

### C7 — FedRAMP?

**Q:** Do you have FedRAMP authorization?

**A:** **No, and not in the near-term roadmap.** FedRAMP authorization (Moderate or High) requires a 12–18 month engagement with a 3PAO, an authorizing-official sponsor in a federal agency, and operational evidence at a maturity level we have not yet committed to. We crosswalk to **NIST 800-53 Rev 5 Moderate at 87%** today (informational — `specs/_compliance/NIST-800-53-CROSSWALK.md`), and GAP-24 closes T+6m. If you have a federal-sponsorship requirement, talk to us at Founder level; we will be honest about the gap and whether we can credibly close it on your timeline. (Most federal-adjacent customers we've spoken to need their *vendor's* SOC 2 + ISO 27001, not FedRAMP — see C1 / C4.)

**Sources:** `apps/docs/docs/trust/compliance.mdx#quick-scope-map`; `specs/_compliance/NIST-800-53-CROSSWALK.md`.

### C8 — Data residency: where does my data physically live?

**Q:** Pick one — where does my tenant's data live?

**A:** Either the **United States** (default) or the **EU**, depending on your tenant's region. The US (`enam`, Eastern North America) region is the default — CAS/AC data physically lives in US Cloudflare R2 buckets. **EU (`weur`) residency is live too:** EU tenants are served via our London/`lhr` cluster, whose CAS and AC blobs are stored in physically-EU Cloudflare R2 buckets (`corelink-cas-eu` / `corelink-ac-eu`, both EEUR) — EU-origin data physically stays in the EU. **Other jurisdictions are on the roadmap** — `sam` (South America — São Paulo) and APAC (`oce` Sydney, `apc` Tokyo / Singapore, `mea` Dubai) — available to Enterprise on request as we provision the jurisdiction-local R2 buckets and per-region endpoints that physical residency requires (note: Cloudflare R2 has no South-America region today, so Brazilian-jurisdiction physical residency is not yet available — `sam` data would reside in the US or EU under SCCs). The region-isolation guard maps `weur`→`lhr` and refuses cross-region access.

**Sources:** `apps/docs/docs/trust/data-handling.mdx#residency`; `marketing/launch/BLOG-POSTS/04-multi-region-residency.md`.

> **Pre-sales legal questionnaire toolkit:** for SIG Lite / CAIQ v4 / custom vendor-form responses, see `marketing/sales/legal-questionnaires/` — pre-filled SIG Lite (114 question-rows mapped to canonical evidence), CAIQ v4 (197 questions across 17 CCM v4 domains), generic vendor response template, evidence pack index, and response SLA policy (5d SIG Lite / 10d SIG Full / 7d CAIQ).

---

## Performance (6)

### PF1 — What's the p99 cache-hit latency?

**Q:** When my CI runner asks for a blob and you have it, how long does it take?

**A:** **p99 CAS GET latency target ≤ 300 ms** in-region (SLO `SLO-LAT-CAS-GET`, customer-tenant scope). For lighthouse customers we measure daily; representative steady-state runs are well below target (typical observed p99: **180–220 ms** depending on region and blob-size mix; the calculator at `corelink-docs.humangr.com` exposes your projected value). Audit-append p99 target ≤ 500 ms. The fast path does *not* call your KMS — DEK is unwrapped at first read into the bounded 5-min in-memory cache and re-used until expiry. Cache-miss reads pay one KMS unwrap RTT (provider-specific; AWS / GCP / Azure / Vault all sub-100 ms p99 in practice).

**Sources:** SLO catalog (`specs/03_architecture/slo_catalog.md` — internal; no public SLO page is published today, `/slo` 404s); `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#what-were-measuring-daily-automated`; `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md`.

### PF2 — What hit rates are realistic?

**Q:** What cache hit ratio should we expect?

**A:** Hit rate is partly *your* property (build-graph stability) and partly *vendor* policy (cache key stability, negative caching policy, eviction policy, dedup). CoreLink optimizes the vendor-side terms hard: BLAKE3-keyed byte-stable content addressing, REAPI-canonical action-cache keys, bounded explicit negative caching, content-aware tunable eviction, structural dedup via content addressing. We do **not** publish a headline hit-rate number because it depends on your build. We publish the *curve shape* (see `REMOTE-CACHE-PRODUCT-PROFILE`) and expose your actual measured hit rate in the Grafana dashboard from D+1. Cold-start ramp: expect the first week to ramp from low single-digits to your steady state; subsequent weeks plateau.

**Sources:** `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md#cache-hit-ratio-a-model`; `REMOTE-CACHE-PRODUCT-PROFILE`.

### PF3 — What's the throughput ceiling?

**Q:** How many puts/gets per second?

**A:** Per-tier TPS ceilings are in the rate-limit ladder (`marketing/sales/RATE-LIMIT-FAQ.md` RL1). The **Enterprise tier is negotiated** — we've stress-tested in staging to 5× our highest self-serve tier's sustained TPS with no observed degradation, and the Cloudflare R2 + Workers substrate scales horizontally per region. If you need a specific committed TPS, name it in the order form; we'll either commit or come back with a fact-based pushback. We do not artificially throttle below the published cap; sustained traffic above your bucket receives `429` + `Retry-After`, and v0.1 plans are hard-capped rather than overage-billed (see P2).

**Sources:** `apps/docs/docs/tutorials/quickstart-faq.mdx#8`; SLO catalog.

### PF4 — Cache-miss latency? Latency in the worst case?

**Q:** When the cache *doesn't* have it, what's the cost?

**A:** Cache-miss = first PUT against an unseen digest. The cost is **the upload itself** (size-bound, on your CI runner's egress) plus a small CoreLink-side append (typically < 50 ms over the upload). There is no "miss penalty" beyond the actual transfer; we don't synthesize artificial backoff on misses. Once BYOK ships, a cold DEK cache will add one KMS unwrap RTT to a read miss (provider-specific; expected < 100 ms p99). BYOK is not shipped today, so no read path pays that cost — see S1.

**Sources:** `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md`; `marketing/launch/BLOG-POSTS/02-byok-deep-dive.md`.

### PF5 — Multi-region performance: will a future SAM region underperform?

**Q:** When the Brazil region ships, will it be slower than the US?

**A:** There is no SAM region to benchmark yet — Brazil/`sam` is on the roadmap (and gated on Cloudflare adding a South-America R2 region). Architecturally there's no reason a future `sam` deployment would underperform — it would run on Cloudflare's São Paulo colos with the same R2 + D1 + Workers substrate. The honest caveat that will apply (and applies today between our live US and EU regions): CI runners *outside* a tenant's region pay round-trip latency, so keep your runners and tenant in the same region. We do not plan implicit cross-region failover (it would violate the residency contract); cross-region active-active will be an explicit opt-in when it ships.

**Sources:** `marketing/launch/BLOG-POSTS/04-multi-region-residency.md#failover-within-a-region-set`; `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md#honest-caveats`.

### PF6 — Cold start: what's the ramp?

**Q:** First week — what do we measure?

**A:** Cold-start curve: first build of a fresh repo populates the cache (every blob is a miss, paying upload cost). Hit rate climbs over D+1 to D+7 as the working set warms. **Steady state is typically observable by D+7** for Bazel monorepos with typical build profiles; very large polyglot graphs may take longer to warm. The calculator at `corelink-docs.humangr.com` projects steady-state economics from your inputs; the dashboard shows your *actual* warming curve from D+1. This is true of every remote cache — we name it explicitly because some vendors don't.

**Sources:** `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md#honest-caveats`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#phase-1-days-1-7-mirror-your-ci`.

---

## Operations (8)

### O1 — Where's the status page?

**Q:** Where do I subscribe to status?

**A:** [hugrl.betteruptime.com](https://hugrl.betteruptime.com) — operated by **Better Stack**, on infrastructure separate from the CoreLink production fabric (if CoreLink is down, the status page is up). It is served from the vendor's own hostname deliberately: a branded name would have to run through infrastructure we operate, and a status page that shares our fate goes quiet in exactly the incident it exists to report. **Two components are tracked today** — CoreLink API Health and CoreLink Container Storage. Programmatic state: `https://hugrl.betteruptime.com/index.json` (`data.attributes.aggregate_state`). **Email / SMS / RSS / webhook subscriptions are not available yet** — subscriptions are switched off on the page; ask support@humangr.com to be added to the incident list by hand. Do not quote eight components, per-region status, `history.rss` or `api/v2/summary.json`: none of those exist on this vendor.

**Sources:** `apps/docs/docs/trust/incident-response.mdx#status-page`; `marketing/launch/STATUS-PAGE-SPEC.md`.

### O2 — What's on-call coverage?

**Q:** Who's awake at 3am Brazil time when our build cache goes down?

**A:** **24/7 paging across three regions** per PagerDuty rotation. Weekly synthetic page (sent every Monday 14:00 UTC, sustained for 30 days pre-GA) verifies the rotation actually pages — not just that it's configured. PagerDuty page acknowledgement target ≤ 10 min, 24/7. Phone callback on a P0 within 1 hour. For Enterprise tenants, the dedicated Slack Connect channel SEV-1 acknowledgement is ≤ 1 hour business hours / ≤ 4 hours outside.

**Sources:** `apps/docs/docs/trust/incident-response.mdx#reporting-an-incident-to-us`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#support-slas`.

### O3 — What are the support SLAs?

**Q:** How fast do you respond?

**A:** Tier-dependent (see the support row of the P1 feature matrix for the Free/Solo/Starter/Pro/Max ladder). **Self-serve tiers:** community Slack (`#help`) median < 1 hour weekday response; GitHub Issues / Discussions for design + bugs; email `support@humangr.com` for billing / account. **Enterprise:** dedicated Slack Connect channel; SEV-1 response SLA **4 hours**; weekly account review available. **Lighthouse** (design-partner pilot program, not a billing tier — the customer is on one of the tiers above): the full playbook applies (`marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#support-slas`) — Slack acknowledge ≤ 1h business / ≤ 4h outside, PagerDuty ≤ 10 min 24/7, P1 engineering response ≤ 24h, attestation draft delivery ≤ 24h after D+40.

**Sources:** `apps/docs/docs/tutorials/quickstart-faq.mdx#15`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#support-slas`.

### O4 — Incident response process?

**Q:** What happens during a SEV1?

**A:** Deliberate cadence. **≤ 5 min:** status page flips affected components; initial "Investigating" post. **≤ 30 min:** email to affected tenants (security@ + registered tech contact + incident-comms address); initial scope statement. **Every 30 min:** status update with the *change since last update* — even if "no change". **Until resolved:** continuous updates; on-call commander identified by name. **≤ 72h:** public post-mortem published on status page and linked from Trust Center. **T+14d:** internal post-mortem review with corrective-action register; summary delta added to public post-mortem if material. Templates in `marketing/launch/CRISIS-COMMS-TEMPLATES.md`.

**Sources:** `apps/docs/docs/trust/incident-response.mdx#communicating-during-a-sev1`.

### O5 — Status communication during partial impairment?

**Q:** What about a SEV2 — single region, degraded performance?

**A:** Status page within **15 minutes** if customer-facing; otherwise internal only. Per-component, per-region status shown. SEV2 does not trigger the SEV1 email cadence but does appear on the status page with running updates. Enterprise pre-registered incident-comms addresses still receive SEV2 notifications. Severity definitions on `apps/docs/docs/trust/incident-response.mdx#severity-definitions`.

**Sources:** `apps/docs/docs/trust/incident-response.mdx`.

### O6 — Planned maintenance: how much notice?

**Q:** Do you do maintenance windows? When and how do we hear about them?

**A:** **30 calendar days advance notice** for sub-processor changes (per DPA §6 / GDPR Art. 28 / LGPD Art. 27 §4º) — published as a *Maintenance / Informational* item on the status page; email digest via the `subprocessor-changes@` distribution address inside tenant settings; RSS feed. **For routine deploys** that touch a customer's hot path: 24h notice in the Slack Connect channel with rollback plan. Customers can request a freeze on their tenant during a critical period (e.g., your own product launch window) — tell us. Material spec or DPA changes follow `specs/_runbooks/RB-DPA-CHANGE.md`.

**Sources:** `apps/docs/docs/trust/subprocessors.mdx#notice-of-changes-30-day-grace`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#faq` Q12.

### O7 — Backups, RPO, RTO?

**Q:** Recovery point objective? Recovery time objective?

**A:** **Backup snapshots:** 35-day rolling retention, encrypted at rest with the same envelope as source. **Failover semantics:** CoreLink runs from a US (ENAM) region and a physically-EU (WEUR) region; resilience is provided by Cloudflare R2's intra-region durability and Workers/D1 redundancy within each region — and EU-tenant data stays in the EU during recovery (failover is always within the tenant's residency boundary). Additional regions and cross-region active-active are on the roadmap and will be an explicit opt-in when they ship. **RPO / RTO** targets are tier-dependent and published in your scoping doc for lighthouse / Enterprise; ask Sales for the current targets if your procurement requires them in writing.

**Sources:** `apps/docs/docs/trust/data-handling.mdx#retention`; `marketing/launch/BLOG-POSTS/04-multi-region-residency.md#failover-within-a-region-set`; `specs/_runbooks/RB-DR-DRILL.md`.

### O8 — Audit chain retention?

**Q:** How long do you keep audit events?

**A:** **7 years.** Customer-controlled? No — compliance-driven minimum. Audit chain is append-only, BLAKE3 hash-chained, with JCS-canonicalized leaves; any window re-verifies offline against a later published head. Backup snapshots of the chain follow the same 35-day rolling window with tombstones recorded on day 0 so a Type II auditor can trace the chain. Right-to-erasure under GDPR Art. 17 / LGPD Art. 18: erasure is fulfilled today via an operator-assisted request (the erasure pipeline is live); PII-bearing claims are made cryptographically unrecoverable via the salt-rotation pattern (`ADR-S11-003`) while the audit record itself remains for integrity. A customer-served signed Ed25519 erasure attestation is on the near-term roadmap.

**Sources:** `apps/docs/docs/trust/data-handling.mdx#retention`; `marketing/launch/BLOG-POSTS/03-audit-chain-merkle-proofs.md`; the operator procedure behind "operator-assisted erasure" is `specs/_runbooks/RB-DSR-GDPR.md` §2.3 (Art. 17, 30-day SLA, MFA-gated) and its LGPD sister `specs/_runbooks/RB-DSR-LGPD-FULL.md`.

---

## Migration (8)

### M1 — Migrating from bazel-remote: what's the path?

**Q:** We're running `bazel-remote` standalone today. How do we switch?

**A:** You don't install anything — there is **no CoreLink component in your build path**. `.bazelrc` changes by a cache URL and a host-scoped credential helper; the protocol translation runs on our side. Two live schemes, both helper-authenticated with a Bearer PAT: (1) **stock plain-HTTP cache** — `--remote_cache=https://corelink-api.humangr.com/bazel/cache`, which serves the `/cas/<hash>` and `/ac/<hash>` paths vanilla Bazel emits; (2) **REAPI v2 / ByteStream** — `--remote_cache=https://corelink-api.humangr.com/bazel/v2` with `--remote_instance_name=${CORELINK_TENANT}` (your tenant UUID is the REAPI instance segment). Configure `--credential_helper=corelink-api.humangr.com=%workspace%/.bazel/corelink-credential-helper.sh`; the helper reads `CORELINK_PAT` from the environment without putting it in argv. We recommend the **mirror-then-cutover** pattern (see M5) — keep bazel-remote primary for 1–2 weeks, validate hit ratio, then flip. The full self-serve guide is `apps/docs/docs/how-to/migrate/from-bazel-remote-cache.mdx`.

**Sources:** `apps/docs/docs/integrations/bazel.md`; `apps/docs/docs/how-to/migrate/from-bazel-remote-cache.mdx`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#phase-1-days-1-7-mirror-your-ci`.

### M2 — Migrating from S3-based self-hosted cache?

**Q:** We rolled our own on S3 + a custom HTTP shim. How does that move?

**A:** Three components to migrate: (1) **The cache surface** — point your build tool at CoreLink's HTTP/REAPI endpoint; we support any client that does PUT/GET against a content-addressable backend. (2) **Existing blobs** — optional; you can either let CoreLink warm naturally (recommended; cold-start is < 1 week to steady state — see PF6) or bulk-pre-warm yourself with `corelink import <dir>` (content-addressed, so dedup happens for free — and re-runs are free too). Reading straight out of your bucket isn't wired yet, so sync the objects down first, or ask us for an operator-assisted import. (3) **Egress economics** — the migration *itself* costs you one final S3 egress charge if you pre-warm; ongoing reads then run on R2 with zero egress (see PF1 / `BLOG-POSTS/05`). Migration guide: `apps/docs/docs/how-to/migrate/from-s3-only.mdx`.

**Sources:** `apps/docs/docs/how-to/migrate/from-s3-only.mdx`; `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md`; CLI behaviour: `tools/cli/src/commands/import_cmd.rs` (local dir wired; `s3://` hard-errors with the flagged gap).

> **Internal — the operator-assisted import has no runbook.** Offering it is fine as a *service* (a human does it on request), but as of this edit no procedure for it exists in `specs/_runbooks/` or `docs/operator/` — the phrase appears nowhere outside `marketing/`. Same for the operator-assisted push-to-your-bucket export in M4. Get Founder sign-off before promising either, and file the runbook gap. Contrast O8: operator-assisted **erasure** is fully documented (`specs/_runbooks/RB-DSR-GDPR.md` §2.3).

### M3 — Migrating from Docker registry / Harbor?

**Q:** We're using a Docker registry for layer caching today. Does CoreLink replace it?

**A:** **Partial overlap.** CoreLink stores any content-addressable blob — Docker layer caching (gzipped tar layers keyed by digest) is a valid CAS workload, and customers do use CoreLink as a layer-cache backend. **CoreLink is not a full Docker registry** (no manifest API surface, no OCI registry HTTP spec conformance at GA — that's roadmap). For *layer caching only*, the migration is the same shape as M2: point your build tool at CoreLink's CAS endpoint, optionally pre-warm. For *registry + layer caching combined*, keep Harbor / your registry for manifests and offload the heavy layer-cache traffic to CoreLink. We're explicit about this scope; Phase 2 — Remote Execution — and an OCI front are both post-GA roadmap items.

**Sources:** `marketing/launch/BLOG-POSTS/01-introducing-corelink.md#what-is-next`; `REMOTE-CACHE-PRODUCT-PROFILE`.

### M4 — Data egress: what does it cost to leave?

**Q:** If we leave you for another vendor, what do we pay to extract our data?

**A:** **Zero, structurally.** Two ways out: (1) Your data is content-addressed by BLAKE3 / SHA-256 — every blob can be fetched by digest over the standard REAPI/HTTP GET-by-digest surface against your tier-included egress allowance. (2) For a full bulk extraction, `corelink cas export --tenant me --out <dir>` pulls every blob in your tenant plus an index, self-serve, and `corelink tenant export` produces a content-addressed portability bundle; both bill at the same R2-zero-egress economics that govern read traffic (no surcharge for departure). Shipping directly into a destination bucket you control is operator-assisted for now. Audit-chain export is always free. We mean it: the content-addressed nature of CAS is *itself* the escape hatch (see P34 in objection handling).

**Sources:** `marketing/launch/BLOG-POSTS/05-fast-cache-hit-economics.md`; `marketing/sales/OBJECTION-HANDLING.md` Obj-22.

### M5 — Mirror / parallel-run period: how long, and what does it look like?

**Q:** How do we run CoreLink alongside our existing cache for a while?

**A:** Recommended pattern: **mirror, not cut-over.** Your existing cache (bazel-remote, BuildBuddy, your S3 thing) stays primary. CoreLink runs as secondary destination: writes go to both, reads come from existing cache. If CoreLink misbehaves, your builds don't break. The practical pattern today is a **dual `--remote_cache` write** — configure your build to write cache entries to both your existing cache and CoreLink (Bazel supports multiple cache backends; Buck2 cannot mirror to CoreLink at all — it is gRPC-only and CoreLink serves no gRPC ingress), read from the incumbent, and compare hit ratios before cutover. A turnkey sidecar-mirror helper and a BES-consumer ingest path are on the roadmap. **Duration:** 1–2 weeks for typical customers; lighthouse customers do 14 days of mirror (Phase 1) before optional cutover.

**Sources:** `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#phase-1-days-1-7-mirror-your-ci`; `apps/docs/docs/how-to/migrate/`.

### M6 — Rollback: if we cut over and it doesn't work, can we revert?

**Q:** What's the rollback story?

**A:** Two layers. (1) **Build-tool rollback** — flip `--remote_cache` back to your previous cache URL. Trivial; minutes. We recommend keeping your previous cache running for at least 30 days after cutover for exactly this reason. (2) **Data rollback** — your data on CoreLink doesn't get destroyed when you flip; it remains under the retention policy you've configured (default 90-day LRU on the self-serve tiers). If you flip back and then forward later, the cache repopulates from your live build traffic. There is no "decision penalty" for trying us, finding it doesn't fit, and rolling back; that's the point of the mirror-then-cutover pattern (M5).

**Sources:** `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md#phase-1-days-1-7-mirror-your-ci`; rollback runbook (`specs/_runbooks/RB-CUSTOMER-ROLLBACK.md`).

### M7 — Cutover support: do we get help during the switch?

**Q:** During the actual cutover, what support is available?

**A:** Tier-dependent. **Self-serve tiers:** community Slack, GitHub Issues, written migration guides; we'll review your `.bazelrc` / `buckconfig.local` on request via `support@humangr.com`. **Enterprise:** named Customer Success engineer for the cutover window, scheduled cutover-day Slack Connect call, post-cutover review at 24h / 7d / 30d. **Lighthouse** (pilot program, not a billing tier): the full Customer Playbook applies — dedicated engineer, weekly check-in, daily SLA samples, attestation at D+30 (`marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`). We do **not** charge for cutover support on Enterprise — it's part of the contract.

**Sources:** `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`; `apps/docs/docs/tutorials/quickstart-faq.mdx#15`.

### M8 — Migration timeline: how long, realistically?

**Q:** End-to-end, when can we be off the old cache?

**A:** Typical timelines we've observed (with the obvious caveat that your build is your build):

- **Single-pipeline pilot:** D+0 sign → D+1 first cache write → D+7 measurable hit ratio → D+14 cutover-ready.
- **Full monorepo cutover:** D+0 → D+30 (the lighthouse playbook timeline; runs in parallel with attestation).
- **Multi-team enterprise migration:** D+0 → D+60–90 depending on team count and tooling heterogeneity (Bazel + Gradle + a home-grown HTTP cache in the same shop is the typical worst case; the Buck2 and Pants teams in such a shop cannot migrate at all today — both are gRPC-only).

The mirror-then-cutover pattern means you're not blocked on full cutover to get value — you start measuring hit ratio and latency from D+1.

**Sources:** `marketing/lighthouse-kit/03-integration-timeline.md`; `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`.

---

## Cross-references

- **Lighthouse playbook:** `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` — for the prospect who's becoming a customer.
- **Launch checklist V2:** `marketing/launch/LAUNCH-CHECKLIST-V2.md` — for the prospect asking about GA timing.
- **Trust Center:** `apps/docs/docs/trust/` — full compliance posture, sub-processors, incident response.
- **Objection handling:** `marketing/sales/OBJECTION-HANDLING.md` — top 30 objections with structured responses.
- **Competitive matrix:** `marketing/sales/COMPETITIVE-MATRIX.md` — honest comparison vs. bazel-remote / BuildBuddy / S3 / Harbor.
- **Proof points:** `marketing/sales/PROOF-POINTS.md` — every numeric claim with a doc / commit pointer.

---

**Fim SALES-FAQ-MASTER.**
