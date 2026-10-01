---
id: "ROADMAP-TO-GA"
type: "roadmap"
doc_status: "ACTIVE"
audit_status: "ACTIVE"
version: "1.2.0"
created: "2026-05-14"
updated: "2026-05-27"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
tags: ["roadmap", "ga", "production-ready", "post-spec-corpus", "solo-founder-realistic-rewrite"]
---

# CoreLink — Roadmap to Launch & Beyond (Solo-Founder Edition)

**Baseline:** 2026-05-27. Wave 32 production deploy SEALed (tag `corelink-prod-deploy-v1`; 5/5 customer endpoints live). Waves 33-36 code reorg SEALed (107 → 87 packages; cargo-deny lockdown enforced; wasm32 build restored). All 21 sprint specs SEALed. Status page live (BetterStack); Stripe wired; charter SOTA compliance verified (`forbid(unsafe_code)`, INV-AUDIT, property tests across 21 sprints).

**Target:** First paying customer before "GA" word matters. Continuous improvement, not a calendar date.

**Execution model:** solo founder (Gustavo) + on-demand agent assistance for fixes. No 15-agent parallel waves; no formal sprint cadence on R-track.

---

## 0. Why this roadmap exists

CoreLink's spec corpus (S-00..S-20) + code reorg (Wave 33-36) + production deploy (Wave 32) shipped the **engineering substrate**. What remains is **not more engineering**; it is **customer contact**. The previous version of this document (v1.1.0) framed the next 90-120 days as an enterprise GA campaign: 15-agent parallel waves, pentest + SOC 2 Type 1 + 30-day sustained staging observation + 13-signer Go/No-Go gate + T-7..T+7 launch orchestration with PR firm + press wire.

That framing is wrong scale for a 1-person SaaS pre-revenue. Cost-without-revenue is founder death. The rewrite below replaces enterprise-theater with a startup playbook: ship a landing page, invite 3-5 friendly users, fix what breaks, do enterprise certifications **only when a paying customer explicitly asks**.

The retired enterprise plan (R-1..R-8) is preserved at the bottom of this document as a **historical appendix** because the R-1..R-4 substrate did in fact land via Waves 32-36 — it's a useful record, not a forward-looking plan.

---

## 1. Phase: Launch Readiness (1-2 weeks; solo)

| # | Item | Owner | Effort | Done when |
|---|---|---|---|---|
| L1 | **Landing page live** at `humangr.com/corelink` explaining what CoreLink is + 30-sec demo + signup CTA | Gustavo | 4-8h | Public URL serves; first-visitor-can-understand test passes (5/5 friends "get it") |
| L2 | **Signup flow end-to-end working** — Clerk auth → DPA accept → first cache write within 5 min | Gustavo + agent for fixes | 6-12h | One stranger can complete onboarding without help |
| L3 | **Pricing page** — free tier + 1 paid tier ($X/GB or $Y/month), Stripe Checkout integration | Gustavo + agent | 2-4h | Pricing visible; "Subscribe" button charges real card |
| L4 | **Privacy Policy + Terms of Service** posted (template via Termly/Iubenda ~$10/mo OR one-time lawyer review ~$200-500) | Gustavo | 1-2h | Both pages live + linked from footer |
| L5 | **2-3 friendly customers** invited (HackerNews Show, Twitter, friend's startups with CI pain) — NOT formal LOI, just users willing to try + give feedback | Gustavo | ongoing | First 3 sessions logged; first feedback captured |

**Gate:** all 5 items GREEN. Public launch tweet.

---

## 2. Phase: Iterate from Real Customers (4-8 weeks)

Replace the enterprise R-6 "30-day sustained staging observation" with **real production usage from L5 customers**. Fix what breaks. Improve what surprises them. NO formal gate; you're the gate.

| # | Trigger | Action |
|---|---|---|
| I1 | First customer hits an error | Fix within 24h |
| I2 | Customer asks for missing feature | Decide in 48h: build / defer / decline |
| I3 | Customer churns | 30-min retro: why? what to change? |
| I4 | Customer says "yes I'll pay" | Send invoice via Stripe |
| I5 | Customer says "I need SOC 2 / DPA / pentest report" | THAT's when enterprise gate matters (Phase 3 below) |

---

## 3. Phase: Enterprise-When-Asked (variable; only on customer ask)

Trigger: a customer explicitly says they need X to commit. Then (and only then):

| Trigger ask | Response |
|---|---|
| "Do you have SOC 2 Type II?" | Start SOC 2 with Drata/Vanta ($15-30k, 3-6 months); you have most controls already via charter |
| "Can you sign our DPA?" | Use a template DPA (Iubenda $10/mo includes; or copy from competitor public DPA; or $500 lawyer review) |
| "Have you been pentested?" | Hire small firm $5-15k; turnaround 2-3 weeks |
| "Where's your security page?" | Publish a trust page (now `humangr.com/corelink/docs/trust/overview`) listing your charter controls (you ALREADY have them; just expose) |

DO NOT do any of this preemptively. Cost without revenue = founder death.

---

## 4. Phase: Scale (only past PMF)

Roadmap to GA-Full retired as concept. "GA" was an enterprise word. Replace with **continuous improvement**:

- v0.1 → v0.2 when first 3 customers retained 1 month
- v0.5 when 10 paying customers
- v1.0 when $10k MRR

No fixed-date "GA Full 2026-08-31". Date depends on customers, not calendar.

---

## 5. What was retired

The original 90-120 day roadmap had: SOC 2 + Pentest + 30d staging + 7d gate + 14d launch orchestration + 15 agents in parallel for R-2 wiring. Most of this is enterprise-theater for a 1-person SaaS. Specifically retired:

- R-5 "External Engagements" → Phase 3 (only when customer asks)
- R-6 "30d Sustained Staging" → Phase 2 (real customer traffic instead)
- R-7 "Evidence Gate" → Phase 1 gate (Gustavo decides)
- R-8 "Launch Orchestration" → "send a tweet"

---

## 9. Human Track (trimmed)

Non-delegatable actions. The bulk of the original H-1..H-18 enterprise procurement list (pentest RFP, SOC 2 firm contract, law firm DPA review, advisor pool, translators for 3 locales, EV code-signing cert, Apple Developer enrollment) is **deferred to Phase 3** and triggered only on customer ask.

Active Human Track for Phase 1 (Launch Readiness):

| # | Action | Phase | Cost (USD) | Blocks |
|---|---|---|---|---|
| H-L1 | **Domain + DNS** for the flat `corelink-*.humangr.com` hosts + the `humangr.com/corelink` landing | Phase 1 | ~$10/yr | L1 |
| H-L2 | **Stripe account** — already set up + Live keys obtained | Phase 1 (done) | $0 | L3 |
| H-L3 | **Clerk account** + production app + publishable+secret keys | Phase 1 | $25/mo Pro | L2 |
| H-L4 | **Privacy/ToS template** — Termly or Iubenda subscription OR one-time lawyer pass | Phase 1 | $10/mo OR $200-500 one-time | L4 |
| H-L5 | **Outreach list** — pick 3-5 friendly devs/startups to invite | Phase 1 | $0 | L5 |

Phase 3 triggers (only when a paying customer explicitly asks):

| Trigger ask | Action item | Cost (USD) |
|---|---|---|
| "Do you have SOC 2?" | Start Drata or Vanta + Schellman audit | $15-30k + $10k/yr |
| "Can you sign our DPA?" | Iubenda or $500 lawyer template review | $10/mo or $500 |
| "Have you been pentested?" | Hire small firm; 2-3 week turnaround | $5-15k |
| "Trust page?" | Publish a trust page (now `humangr.com/corelink/docs/trust/overview`; controls already exist via charter) | $0 (your time) |
| "Apple notarization / Windows EV cert?" | Apple Developer Program + DigiCert/Sectigo | $99/yr + $300-500/yr |

**Estimated Phase 1 spend: <$1k.** Phase 3 spend variable; gated on customer revenue.

**Secrets drift gate (carried forward):** every credential acquired must be reflected in `docs/internal/secrets-checklist.md`. Daily 04:00 UTC cron + PR gate (`.github/workflows/secrets-drift.yml`) still enforced.

---

## 10. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-X1 | **First 3 users churn before feedback captured** | M | H | Hand-deliver onboarding for first 3; weekly 15-min check-in calls |
| R-X2 | **No customer asks for SOC 2 / DPA / pentest — but enterprise lead asks for everything at once and you can't deliver** | L | M | Have a "we're starting SOC 2 next month" honest answer ready; many startups accept a roadmap commitment in lieu of cert |
| R-X3 | **Real-world traffic surfaces invariant bugs not caught in property tests** | M | H | Canary deploy (5% → 25% → 100%) per S-13 admin plane rollout; auto-rollback at error budget breach (substrate from Wave 32 already covers this) |
| R-X4 | **Vendor outage during a customer's first hour** (Clerk / Stripe / CF) | L | M | Vendor SLAs; status page (`hugrl.betteruptime.com`) already live; document fallback per WI-S19-001 chaos handling |
| R-X5 | **Solo-founder burnout from oncall** | M | H | Phase 1 oncall is best-effort, NOT 24/7 SLA; honest with customers about response window |
| R-X6 | **Free-tier abuse before pricing is enforced** | M | L | Rate limits + per-tenant quotas already wired (S-10 + S-13); monitor R2 storage cost daily |
| R-X7 | **Landing page misrepresents what works** | M | M | Only advertise features that ship; "coming soon" labels for everything else |
| R-X8 | **Stripe Checkout breaks mid-launch** | L | H | Webhook signature verify + idempotency already wired (WI-S19-004); test with real $1 charge before L3 marked done |

---

## 11. Wave dependency graph

```
Phase 1 (Launch Readiness) ──> Phase 2 (Iterate) ──> Phase 4 (Scale)
                                       │
                                       └──> Phase 3 (Enterprise-When-Asked)
                                              (only on customer trigger)
```

Critical path: **L1..L5 (1-2 weeks) → first 3 users → first paying customer (variable)**. No fixed calendar.

---

## 12. Orchestrator (Opus) protocol per phase

For Phase 1 (Launch Readiness):

1. Gustavo writes copy + designs.
2. Agent assists with fixes when something breaks during L2 signup flow.
3. No multi-agent waves; on-demand assistance only.

For Phase 2 (Iterate):

1. Triage incoming feedback hourly during week 1, daily thereafter.
2. Dispatch single Sonnet agent per bug/feature; verify diff; merge.
3. No formal sprint cadence; ship-when-ready.

For Phase 3 (Enterprise-When-Asked):

1. When customer asks: dispatch a procurement task (e.g., "draft SOC 2 vendor RFP based on charter compliance matrix").
2. Pre-existing spec corpus (262 docs, 136 invariants) is your evidence base — most enterprise asks can be answered with what's already shipped.

---

## 13. Decision points where orchestrator must ask user

1. **L4 legal templates** — Termly subscription vs. lawyer review is a $/recurring tradeoff; confirm before purchasing.
2. **L5 outreach list** — who to invite first matters; confirm names before reaching out.
3. **Phase 3 enterprise spend** — pentest + SOC 2 are $$$ commitments. Confirm a paying customer's commitment in writing before spending.
4. **Pricing changes** — any change to L3 pricing after launch requires user confirmation (irreversible for existing subscribers).

---

## 14. Success criteria — what "ready" means

Phase 1 (Launch Readiness) done when:

- ✅ Landing page live at `humangr.com/corelink` and a friend who hasn't seen the product can explain it back after 60 seconds
- ✅ One stranger completes signup → first cache write unaided
- ✅ Pricing page live; Stripe Checkout charges a real card; webhook signature verify passes against real Stripe
- ✅ Privacy Policy + ToS posted + footer-linked
- ✅ 3 friendly customers invited and at least 1 first-feedback session logged

Phase 2 (Iterate) done when:

- ✅ First customer retained 1 month
- ✅ First $1 of revenue from a non-friend customer

Phase 3 (Enterprise-When-Asked) done when:

- ✅ Triggered (a customer asked); responded honestly with timeline; no pre-emptive spend.

Phase 4 (Scale) milestones:

- v0.2: 3 customers retained 1 month
- v0.5: 10 paying customers
- v1.0: $10k MRR

No "100% SOTA GA-approved" framing. Customer revenue is the gate.

---

## 15. Change log

| Versão | Data | Autor | Mudança |
|---|---|---|---|
| 1.0.0 | 2026-05-14 | Gustavo (via Claude Opus 4.7) | Initial roadmap post `ga-engineering-gate-complete` tag; 6 phases × 8 waves; 15 agents simultaneous peak (Wave R-2); 90-120 day path to GA Full; $200-400k Human Track spend. |
| 1.1.0 | 2026-05-27 | Gustavo (via Claude Opus 4.7) | Waves 32-36 SEALED — Wave 32 production deploy (tag `corelink-prod-deploy-v1`; 5/5 customer endpoints live); Waves 33-36 code reorg campaign (tags `wave-35-phase-2-sealed` + `wave-36-stage-2-sealed` + `wave-36-final-sealed`; 63 crates absorbed via 14 autonomous agents; 149→87 packages; cargo-deny lockdown enforced; +14 proptests; materializer dep cycle resolved via traits extraction; wasm32 build restored). Closure-followups audit_status flipped CLOSED. R-5/R-6/R-7/R-8 remaining (human + time-bounded). |
| 1.2.0 | 2026-05-27 | Gustavo (via Claude Opus 4.7) | **Solo-founder realistic rewrite.** User mandate: enterprise R-5/R-6/R-7/R-8 retired as scale-mismatched theater for a 1-person SaaS. Replaced with: Phase 1 Launch Readiness (5 items, 1-2 weeks: landing/signup/pricing/legal/3-customers); Phase 2 Iterate (4-8 weeks of real customer traffic instead of 30d staging observation); Phase 3 Enterprise-When-Asked (SOC 2 / pentest / DPA only on customer demand); Phase 4 Scale (version cadence tied to customer count, not calendar). R-1..R-4 retained at bottom as historical record completed via Waves 32-36. Human Track trimmed from H-1..H-18 ($200-400k pre-GA spend) to H-L1..H-L5 (<$1k Phase 1) + Phase 3 triggers. |

---

**Status:** ACTIVE. Phase 1 (Launch Readiness) authorized 2026-05-27. Waves 32-36 substrate complete. Next deliverable: L1 landing page.

---
---

# HISTORICAL APPENDIX — Original R-1..R-4 Plan (Completed via Waves 32-36)

> **Status:** completed historical record. The R-1..R-4 substrate (cleanup, production wiring, integration/E2E, apps deploy) landed during the autonomous Waves 32-36 campaign (2026-05-15 → 2026-05-27). Kept here for traceability — not a forward-looking plan. R-5..R-8 (external engagements, 30d staging, evidence gate, T-7..T+7 launch orchestration) were retired as scale-mismatched and replaced with Phases 1-4 above.

## H.A1. Wave R-1 — Cleanup & Verification (delivered 2026-05-14..15)

Pre-conditions: none (start now).

| # | Work item | Owner | Effort | Success criterion |
|---|---|---|---|---|
| R1-1 | **S-20 sprint-close round-2 review** post-P0 remediation (verify 7.2→8.5+) | 1 Sonnet | 2h | Audit doc committed; verdict `SEAL APPROVED` or `CONDITIONALLY APPROVED (P1 only)` |
| R1-2 | **Fix 14 pre-existing validate_specs failures** on S-11/S-12/S-13 ADRs (frontmatter `parent` field schema drift) | 1 Sonnet | 3h | `python3 scripts/validate_specs.py` zero failures (down from 14) |
| R1-3 | **S-11 backlog: round-2 truth-table sweep V2 + WI fixes + legal citation re-validation** (tasks #116-119) | 1 Sonnet | 6h | S-11 spec corpus passes validate_specs + audit doc with PASS verdict |
| R1-4 | **S-06 backlog: 2-agent review + P0 fix cascade** (tasks #85-86 abandoned mid-cycle) | 1 Sonnet | 4h | S-06 spec passes validate + WI frontmatters SEALED if not already |
| R1-5 | **S-09 backlog: review cycle + 3 layers of P0 fixes** (tasks #93-97) | 1 Sonnet | 6h | S-09 spec passes validate + audit shows ≥ 8.5 score |
| R1-6 | **Opus eyeball pass on ~70 Cargo.toml + lib.rs** — verify `#[non_exhaustive]`, audit-fail-CLOSED ordering, zero unsafe, PROPTEST_CASES runtime fn, no `prop_assert!(matches!(..., Variant { .. }))` anti-pattern | 1 Opus | 4h | Charter constraint compliance matrix doc with per-crate pass/fail |
| R1-7 | **Worktree cleanup** (S-18/S-19/S-20 = ~15GB after agents done) | 1 Sonnet | 30min | Disk space recovered; only active worktrees remain |
| R1-8 | **Dependency audit** — `cargo audit` + `cargo deny check` + `pnpm audit` on `apps/{admin-ui,docs}` + dependabot PR backlog | 1 Sonnet | 2h | Zero HIGH/CRITICAL advisories; report doc |
| R1-9 | **Engineering onboarding doc live** — Day-0..Day-30 path + 5 domain tracks + first-PR backlog + glossary + buddy protocol | 1 Sonnet | 3h | Doc set committed; README cross-linked; quarterly-refresh owner named |
| R1-10 | **CI workflow optimization audit** — 71 GHA workflows audited; 11 P1/P2/P3 followup tickets filed; best-practice template authored | 1 Opus orchestrator (delivered 2026-05-15) | 2h | Audit + tickets + template committed |
| R1-11 | **TLA+ coverage audit + 1 new spec** — 11 TLA+ specs audited; 9 followup tickets filed; new `specs/tla/auth_revocation.tla` covering 3 CRITICAL invariants | 1 Opus orchestrator (delivered 2026-05-15) | 2h | Audit + new spec + tickets + CI matrix committed |

## H.A2. Wave R-2 — Production Wiring (delivered via Wave 32)

Replaces InMemory fakes with real HTTP/CF/KMS clients. Tracked via Wave 32 production deploy SEAL (tag `corelink-prod-deploy-v1`; 5/5 customer endpoints live; commit `4d4fb8f6`).

| # | Work item | Crate | Reference |
|---|---|---|---|
| R2-1 | **Stripe HTTPS client** (replace `InMemoryStripeClient`) — Checkout Session create, webhook signature verify, subscription state sync | `corelink-stripe-real` / `corelink-tier-selection` patch | WI-S19-004 + S-10 billing pipeline |
| R2-2 | **Clerk session validator** real HTTP JWKS fetch + JWT verify | `corelink-clerk-real` (patch `corelink-clerk` + `corelink-clerk-cf`) | S-03 |
| R2-3 | **PagerDuty Events API v2** real client | `corelink-pagerduty-real` (patch `corelink-oncall::pagerduty`) | WI-S17-005 |
| R2-4 | **Slack incoming webhook** real client | `corelink-slack-real` | WI-S19-005 |
| R2-5 | **HubSpot CRM** real client + alt Salesforce stub | `corelink-crm-real` | WI-S19-005 |
| R2-6 | **AWS KMS real client** (replace `AwsKmsStub`) — encrypt/decrypt/grant/access-check | `corelink-byok-aws-real` | WI-S14-004 |
| R2-7 | **GCP KMS real client** | `corelink-byok-gcp-real` | WI-S14-005 |
| R2-8 | **Azure Key Vault real client** | `corelink-byok-azure-real` | WI-S14-005 |
| R2-9 | **HashiCorp Vault real client** | `corelink-byok-vault-real` | WI-S14-005 |
| R2-10 | **CF Worker bindings wiring** — R2/D1/KV/DO in `apps/server`, `corelink-clerk-cf`, admin-ui middleware | `apps/server` + multiple | WI-S01-001 + all sprints |
| R2-11 | **HubSpot encryption-at-rest** (close S-19 P1-NEW-3: `encrypted_payload_b64` envelope actually called) | `corelink-enterprise-inquiry::ledger` | S-19 sprint-close P1 |
| R2-12 | **Stripe webhook endpoint** routed in `apps/server` with signature verify + idempotency | `apps/server` + `corelink-tier-selection` | WI-S19-004 |
| R2-13 | **D1 migrations applied to staging DB** — run `wrangler d1 migrations apply` for all 43 migrations on staging | infra | all sprints |
| R2-14 | **Production env secrets matrix** — document required secrets in `docs/internal/secrets-checklist.md`; populate via wrangler secrets | docs | cross-cutting |

## H.A3. Wave R-3 — Integration & E2E (delivered alongside Wave 32-36)

| # | Work item | Scope |
|---|---|---|
| R3-1 | **E2E: signup → DPA → tier → Stripe Checkout → first PAT → R2 put/get** | `tests/e2e/signup-to-cas.rs` |
| R3-2 | **E2E: BYOK CMK revoke → DEK cache evict → audit → kill switch metric** (real AWS KMS staging key) | `tests/e2e/byok-revoke-flow.rs` |
| R3-3 | **E2E: DSR access → MFA → JWT receipt → erasure worker → verification artifact** | `tests/e2e/dsr-erasure.rs` |
| R3-4 | **E2E: chaos drill → SLO impact → audit** (against real staging chaos cron) | `tests/e2e/chaos-staging.rs` |
| R3-5 | **E2E: oncall page → MTTA → resolution → postmortem template generated** | `tests/e2e/oncall-page.rs` |
| R3-6 | **admin-ui Playwright suite un-FIXME** — un-skip 14 tests waiting Clerk tokens; provision Clerk test-mode + run | `apps/admin-ui/playwright/` |
| R3-7 | **Integration: signup atomic under Stripe outage** (chaos-injected) | `tests/integration/signup-stripe-chaos.rs` |
| R3-8 | **TLA+ 4 invariant specs verified** — `cd specs/tla && tlc tenant_isolation.tla` etc. | `specs/tla/` |
| R3-9 | **Workspace clippy --release** + `cargo test --release` | CI |
| R3-10 | **`pnpm build` on admin-ui + docs on Node 20** — verify CI pipeline green on real GHA runner | `.github/workflows/` |

## H.A4. Wave R-4 — App Hardening + Deploy (delivered via Wave 32 customer-endpoint deploy)

| # | Work item | Owner | Notes |
|---|---|---|---|
| R4-1 | **admin-ui CF Pages deploy** with real Clerk publishable key | 1 Sonnet + Gustavo (Clerk dashboard) | Path mount `humangr.com/corelink` (no custom subdomain) |
| R4-2 | **docs CF Pages deploy** to `humangr.com/corelink/docs` | 1 Sonnet + Gustavo (DNS) | Algolia DocSearch registration |
| R4-3 | **DNS setup**: flat `corelink-*.humangr.com` hosts + email DKIM/SPF/DMARC | Gustavo (registrar) | 24h propagation |
| R4-4 | **Cookie consent UI live** — Cookiebot or equivalent + integration with consent ledger (WI-S11-003) | 1 Sonnet | LGPD + GDPR + ePrivacy |
| R4-5 | **Privacy/legal pages real content** | 1 Sonnet | (Now handled via Phase 1 L4 template) |
| R4-6 | **4-locale stub translations replaced with real translations** | Translators (hired contractors) | (Deferred to Phase 3 enterprise demand) |
| R4-7 | **Status page** at `hugrl.betteruptime.com` — BetterStack (live as of 2026-05-22) | 1 Sonnet + Gustavo | Customer-facing — DONE |
| R4-8 | **Email + SMS providers** — SES (transactional) + Twilio (SMS) wired into notification path | 1 Sonnet + Gustavo (AWS/Twilio accounts) | DSR notifications, breach alerts |

---

> **R-5 (External Engagements), R-6 (30d Sustained Staging), R-7 (Evidence Gate), R-8 (T-7..T+7 Launch Orchestration):** *retired in v1.2.0*. See §5 "What was retired" above and §3 "Phase: Enterprise-When-Asked" for the replacement framing. The full R-5..R-8 plan is recoverable from git history at tag `v1.1.0` if needed.
