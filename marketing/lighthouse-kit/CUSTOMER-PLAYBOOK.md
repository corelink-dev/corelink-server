---
id: "LIGHTHOUSE-KIT-CUSTOMER-PLAYBOOK"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-14"
updated: "2026-05-14"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "WI-S20-004"
tags: ["lighthouse", "marketing", "playbook", "customer-facing", "onboarding", "30d", "r5-2"]
---

# CoreLink Lighthouse Customer Playbook — Day 1 to Day 30+

> **Audience:** YOU — the engineering, SRE, or platform leader at the customer who has agreed to be a CoreLink lighthouse customer.
> **What this is:** the single document your CoreLink account contact hands you on Day 1. It walks you through everything: the first 60 minutes, the first week, the 30-day observation, the attestation, and the case-study handoff.
> **What this isn't:** a sales pitch (you already said yes), a legal contract (your DPA + LOI are separate), or a product manual (CLI docs are at `docs/cli/`).
> **Internal companion:** our team works the other side of this playbook from `specs/_runbooks/RB-LIGHTHOUSE-PHASE-MANAGEMENT.md`. Post-attestation retention motion (when lighthouse alumni become paid tenants) is governed by `marketing/retention/CHURN-RISK-SIGNALS.md` + `marketing/retention/RETENTION-PLAYBOOK.md` + `marketing/retention/CANCELLATION-FLOW.md`; internal RACI in `specs/_runbooks/RB-CHURN-RISK-RESPONSE.md`.
> **Self-serve alternative:** if you're not in the lighthouse program but want to migrate, see the self-serve migration guides at `apps/docs/docs/how-to/migrate/` (Bazel / S3 / Docker registry). They cover the same phase structure (pre-flight → parallel-run → cutover → rollback) without the dedicated-engineer commitment.

---

## Welcome

Three sentences:

1. **You're one of 3** — 2 Team-tier + 1 Enterprise BYOK. We never run more than 3 lighthouse customers concurrently. Your engagement is named, scoped, and dedicated.
2. **The deal is symmetric** — you get 6 months of CoreLink at no charge plus a dedicated engineer; we get a 30-day SLA attestation and a case study you co-author. Either side can withdraw with 5 business days' notice during the observation window without penalty.
3. **The timebox is 60 days** — D+0 (today) to D+60 (case-study publication). Your engineering effort across the entire 60 days is capped at **≤ 8 hours**.

If at any point the math stops working for you — concern about the product, internal priority shift, vendor-management process — say so. We mean it.

---

## Scope — what you're testing, what you're not

### You ARE testing
- **Content-addressable cache (CAS):** the cache backend behind your Bazel / Buck2 / Pants / equivalent build tool. PUT, GET, GET-by-digest, retention. This is the load-bearing one.
- **Action cache (AC):** if your build tool uses an action cache distinct from CAS (Bazel does), we cache that too. Hit ratio over 30 days is the headline metric.
- **Audit chain access:** you can query the audit chain for your tenant via CLI. You'll exercise this during attestation.
- **SLA dashboard:** per-customer Grafana embed showing your SLOs in real time.
- **(Enterprise BYOK only)** Your KMS provider key wiring; the BYOK kill-switch; the weekly BYOK chaos drill.
- **(Enterprise only)** Your procurement-side legal questionnaire path. CoreLink pre-stages SIG Lite (5 business days), CSA CAIQ v4 (7 business days), and custom vendor-questionnaire response packs (3–10 business days depending on size) under `marketing/sales/legal-questionnaires/`. Your DPO / vendor-management team can request the bundle via `trust@humangr.com` with countersigned NDA on file — turnaround per `RESPONSE-SLA-POLICY.md`.

### You are NOT testing
- **Public production at scale** — staging is its own environment; we're not asking you to redirect prod traffic.
- **Billing flows** — you don't have a credit card on file. Stripe paths don't apply.
- **The marketing site / signup funnel** — you skipped that on purpose.
- **Multi-tenant noisy-neighbor scenarios** — lighthouse customers run on dedicated capacity during this window.

If anything in your use case is ambiguous about which list it falls in, ask your Customer Success engineer in week 1.

---

## The 60-minute onboarding session — agenda

This call happens on D+0 (today, or within the first 48 hours of your LOI countersigning). One time. After this you go back to your day job and we go back to ours.

| Time | Topic | Who's needed from your side |
|---|---|---|
| 0:00–0:05 | Intros + this playbook walkthrough | You + your eng lead |
| 0:05–0:15 | Confirm scope (above) + what success looks like for both sides | Same |
| 0:15–0:25 | Region pin, retention policy, CI integration target (which one job/pipeline gets mirrored first) | Eng lead |
| 0:25–0:35 | **(Enterprise only)** BYOK provider declaration + Schrems II TIA kickoff | Eng lead + Privacy/Security counterpart |
| 0:35–0:45 | Auth setup — first PAT issued live; CLI installed on a laptop in real time | Eng lead with terminal access |
| 0:45–0:55 | Comms protocol — Slack Connect channel created; PagerDuty escalation rights activated; weekly check-in scheduled | Same |
| 0:55–1:00 | Q&A; what happens between today and the next check-in | Same |

If your team can't do a full hour, we can split this into two 30-min sessions: the eng/CLI half and the comms/governance half. Tell us before the call.

---

## Sandbox setup checklist

Print this. Tick it. Bring questions to the D+0 call or to your Slack Connect channel.

### Before the call
- [ ] LOI + NDA countersigned (DocuSign envelope id from us).
- [ ] **(Enterprise)** Internal privacy/security review scheduled or completed.
- [ ] One designated "eng lead" identified — single accountable person on your side.
- [ ] One designated "ops/SRE" identified — receives the daily SLA samples and is paged on incidents.

### During the call
- [ ] CLI installed — **your Customer Success engineer gives you the current install command on the call.** Do not use an `install.sh` URL under the dotted `corelink.` subdomain: that hostname does not resolve (verified 2026-08-02; prod hostnames are flat, see `docs/operator/host-scheme-canonical-2026-06-09.md`), and no replacement one-liner has been verified to serve a script, so this checklist will not print a guess. Whatever command you are given, the binary verifies its signature against our Sigstore bundle.
- [ ] First PAT minted in the dashboard (`https://humangr.com/corelink/customer/keys`) and saved locally with `corelink login --token {your-pat}`.
- [ ] First CAS write: `corelink put ./README.md` returns a `blake3:` digest.
- [ ] First CAS read: `corelink cas get blake3:{digest}` returns the same bytes.
- [ ] Audit chain access verified: `corelink audit tail` (trailing hour by default) lists the two events above.
- [ ] **(Enterprise)** BYOK provider declared in the call; first KMS key id captured in our tracker.
- [ ] Region pin confirmed (wnam / enam / weur / sam — chosen by you with our latency advice).
- [ ] Slack Connect channel `#corelink-{your-slot-id}` joined by your eng lead.
- [ ] PagerDuty escalation rights confirmed — your eng lead receives a test page during the call.
- [ ] Grafana dashboard URL bookmarked.

### Within 48h of the call
- [ ] Eng lead skims `marketing/lighthouse-kit/03-integration-timeline.md` (the full schedule contract).
- [ ] Ops/SRE skims this playbook §"Phase 2" so they know what they're sampling.
- [ ] One question filed in the Slack Connect channel (even just "got it, no questions" — we want to confirm the channel works).
- [ ] Eng lead skims the RBAC docs (`apps/docs/docs/explanation/rbac/`) — overview, role catalog, permission matrix, and the two how-tos (invite team member; audit role changes). Owners/Admins should also note the dual-approval gate that fires on the 5 destructive admin ops (`ConfigRollback`, `RetentionPolicyReduce`, `FeatureFlagDisable`, `SecretRotationStart`, `TenantTombstone`).

---

## Phase 1 (Days 1–7): "Mirror your CI"

The headline goal of week 1: **pick one CI job and run it against CoreLink in parallel** with your existing cache. We don't ask you to cut over; we ask you to mirror.

### Why mirror, not cut over

- You keep your existing cache (bazel-remote-cache, BuildBuddy, Buck2's `https`, custom) as primary.
- CoreLink runs as a secondary destination: writes go to both, reads come from your existing cache.
- If CoreLink misbehaves, your builds don't break.
- After week 2, if everything's clean, you can choose to flip primary/secondary or not. We don't require it.

### Concrete steps

**Bazel** — add to your `.bazelrc`:

```
# Existing primary cache
build:ci --remote_cache=https://your-existing-cache.example.com

# CoreLink as additional write destination
build:ci --experimental_remote_cache_async=true
build:ci --remote_executor=
build:ci --remote_upload_local_results=true
# CoreLink, over the same plain-HTTP cache protocol Bazel already speaks.
# NOTE: Bazel honors only the LAST --remote_cache flag, so this line REPLACES
# the primary above — it is your cutover line, not a second destination.
build:ci --remote_cache=https://corelink-api.humangr.com/bazel/cache
build:ci --credential_helper=corelink-api.humangr.com=%workspace%/.bazel/corelink-credential-helper.sh
```

(Bazel doesn't natively support dual-write to two remote caches in one flag. One practical pattern today:

1. **Directory mirror** — `corelink ci mirror --from /var/cache/bazel-remote --to corelink` does a one-shot, idempotent copy of your existing cache's on-disk directory into CoreLink CAS. (A live streaming sidecar that speaks the source cache's wire protocol is not built yet — point `--from` at the directory, not at the service.)

**Build-event-protocol (BES) ingest — not available today.** `--bes_backend` is a **gRPC** endpoint (Bazel publishes the build event stream over the Build Event Service protocol), and CoreLink has no gRPC ingress — same topology reason as Buck2 and Pants below: the edge runs on Cloudflare Workers, which implement no HTTP trailers, so native gRPC cannot work. There is no address to point `--bes_backend` at, and we are not going to hand you one that fails to connect. Our own sales material already treats BES ingest as roadmap (`marketing/sales/OBJECTION-HANDLING.md` Obj-23, `marketing/sales/FAQ-MASTER.md` M5); this playbook now agrees with it.

Your Customer Success engineer will walk the directory mirror with you on the D+3 scoping call.)

**Buck2 — not supported today.** Buck2's cache/RE client (`[buck2_re_client]` `engine_address` / `cas_address` / `action_cache_address`) connects over **gRPC**, and CoreLink exposes no gRPC endpoint — so there is no Buck2 configuration that works, and we won't hand you one that fails to connect. (Buck2 has no plain-HTTP cache backend either; the upstream request for one was closed `wontfix` — facebook/buck2#459.) If Buck2 is your build tool, say so on the scoping call and we'll tell you straight whether the pilot makes sense.

**Bazel-remote-cache replacement candidates** — if you're already running `bazel-remote` standalone, you don't deploy anything of ours: CoreLink answers the same plain-HTTP cache protocol Bazel already speaks, at `--remote_cache=https://corelink-api.humangr.com/bazel/cache` with the host-scoped credential helper `--credential_helper=corelink-api.humangr.com=%workspace%/.bazel/corelink-credential-helper.sh` (`/cas/<hash>` + `/ac/<hash>`, same as bazel-remote). The helper reads `CORELINK_PAT` from the environment without putting it in argv. Keep your bazel-remote running as primary through the mirror period; cutover and rollback are the one `--remote_cache` line. Full setup: `apps/docs/docs/how-to/migrate/from-bazel-remote-cache.mdx`.

**Pants — not supported today.** Pants' `reapi` provider accepts only `grpc://` / `grpcs://` addresses, and CoreLink has no gRPC ingress: the edge runs on Cloudflare Workers, which implement no HTTP trailers, and native gRPC cannot work without them. That is a property of the topology, not a missing feature we're about to add — so we are not going to give you a `grpc://` address that cannot connect, and there is no date to promise. Same answer as Buck2, same reason.

*(The contrast is the point: Bazel works today precisely because it can speak plain HTTP. Buck2 and Pants cannot.)*

### What to look for in week 1

| Day | What you should see |
|---|---|
| D+1 | First CI run hits CoreLink. Look at the Grafana dashboard: `cache_put_total` increments. |
| D+2 | Cache hit ratio on the dashboard climbs above 0%. Even 10% is fine — it'll grow as the cache warms. |
| D+3 | Scoping call with your CS engineer to confirm everything is wired right. We'll have looked at your dashboard before this call. |
| D+5 | Scoping doc shared back to you (`docs/internal/lighthouse-migration-{slot}.md`). You countersign. |
| D+7 | First cache hit on a non-trivial action (not just a re-build of the same input). Hit ratio comfortably > 0%. |

### Red flags in week 1 — escalate same-day

- CoreLink writes 5xx-ing more than 1% of attempts.
- Latency on CoreLink GETs > 1 second p99 (target is 300ms).
- CoreLink returning bytes that don't hash-verify on your side. (We'd see this server-side too; surface it anyway.)
- Anything that increases your build wall time observably.

Escalation: PagerDuty page using the URL in your Grafana dashboard, OR Slack Connect channel with `@here`. Either works.

---

## Phase 2 (Days 8–21): observation period

Once Phase 1 ends and you're in `Observing` state (we tell you when — typically D+10), the 30-day window starts. **The single most important thing in Phase 2 is: behave normally.** We are explicitly NOT asking you to stress-test or run synthetic loads. We want to know what CoreLink looks like in your real workflow.

### What we're measuring (daily, automated)

Every day at 00:00 UTC, our cron job samples your per-customer SLOs and writes one `SlaSample` row. Over the 30-day window we accumulate 30 samples. The SLOs we sample:

| SLO id | What it means | Target |
|---|---|---|
| `cache-get-p99-latency` | p99 latency on CAS GET, your tenant | ≤ 300 ms |
| `cache-availability` | success rate on CAS reads | ≥ 99.9% |
| `audit-append-latency-p99` | p99 latency on audit chain append | ≤ 500 ms |
| `byok-kill-switch-rtt` *(Enterprise only)* | time from kill-switch trigger to cache decline | ≤ 5 min |
| `byok-key-health` *(Enterprise only)* | KMS key reachable + access OK | bool true |

Your full per-customer SLO catalog is in your scoping doc.

### What to look for, what to escalate

| Pattern | Action |
|---|---|
| Single SLO miss on a single day | We page ourselves. You'll get a written notification within 1h (template 5.1 in our internal runbook). Your observation window is preserved if it doesn't recur. |
| Recurring miss (≥ 2 days in 7) | We will proactively call you. The 30d observation window may need to reset. **Your call** whether to accept the reset or withdraw. |
| Ergonomic friction (slow CLI, confusing error, missing doc) | Not an SLO miss but real. Flag it in Slack Connect or queue for the next weekly check-in. We log every one of these even if no SLO breached. |
| BYOK kill-switch drill *(Enterprise)* | Weekly drill, scheduled at the time you prefer. Latency measured against ≤ 5 min target. |

### Daily metrics report — sample

You receive a daily email (or Slack DM if preferred) with this structure:

```
Subject: CoreLink — Daily SLA sample for LH-EXAMPLE — 2026-MM-DD

Date sampled: 2026-MM-DD 00:00 UTC
Observation window: Day 12 of 30
30-day cumulative: 12 / 30 samples, 0 / 12 misses

SLO results:
  cache-get-p99-latency     186ms ≤ 300ms   PASS  (budget remaining: 38%)
  cache-availability        99.98% ≥ 99.9%  PASS  (budget remaining: 80%)
  audit-append-latency-p99  342ms ≤ 500ms   PASS  (budget remaining: 31%)

Notable events (24h):
  - 2026-MM-DD 14:22Z: scheduled BYOK chaos drill, kill-switch RTT 3m12s (target ≤ 5 min, PASS)
  - 2026-MM-DD 21:08Z: 1 transient cache GET 502 (retry succeeded, no customer impact)

Usage console: https://humangr.com/corelink/en/customer/usage
Audit chain query: corelink audit export --tenant LH-EXAMPLE --since {epoch_ms} --until {epoch_ms}

Reply with questions or page on PagerDuty for urgent items.
```

If you want a different cadence (weekly digest, or only on misses), tell your Customer Success engineer — it's a setting.

### Weekly check-in cadence

30 min on your calendar, weekly, same time each week. Default agenda:

| Time | Topic |
|---|---|
| 0:00–0:05 | Anything urgent from your side? |
| 0:05–0:15 | Walk the dashboard together (SLO status + cache hit ratio + audit volume) |
| 0:15–0:25 | Soft signals — ergonomic friction, doc gaps, things we should know |
| 0:25–0:30 | What we're shipping this week that touches you |

If there's nothing to discuss, we cut it short. The point is the channel, not the meeting.

---

## Phase 3 (Days 22–30): exit criteria + attestation

Days 22–30 (mapped to integration-timeline.md as D+36..D+45) is when we converge on the attestation. Two things happen in parallel: you finish the observation window and we draft the attestation for you to countersign.

### Exit criteria (must ALL be true to flip to `Attested`)

1. **30 daily samples collected** with zero unresolved SLA misses.
2. **(Enterprise BYOK only)** Latest BYOK key health check: pass. KMS reachable, customer policy allows our access.
3. **Attestation form** (instantiated from `specs/_lighthouse/sla-attestation-template.md`) signed by:
   - Your SRE or ops lead (factual countersign on §2 numbers).
   - Your procurement / Legal (binding signature on §5.1).
   - Our Customer Success, Engineering S-20 lead, Privacy Officer (Enterprise), and Legal Counsel.

### Attestation form — what's in it

Six sections. We fill §1, §2, §3. You countersign §5.1 after confirming §2's numbers.

| Section | Content | Who fills |
|---|---|---|
| §1 | Customer identity (you), CoreLink identity, slot id, observation window dates | Us |
| §2 | Measured SLO actuals over the 30d window (one row per SLO) | Us — you cross-check against your own observability |
| §3.1 | Incident log (every P0 + P1 logged during observation) | Us — you confirm completeness |
| §3.2 | Mitigations applied | Us |
| §3.3 | Open known issues at attestation time | Us — you flag any we missed |
| §4 | Aggregate attestation language (SLA met / not met) | Us |
| §5.1 | Your binding signature | You |
| §5.2–§5.4 | Our countersignatures | Us |

Full form instructions in `marketing/lighthouse-kit/05-sla-attestation-instructions.md`.

### Hard deadlines

- **D+45:** soft deadline. We expect signatures by here.
- **D+50:** hard deadline. If unsigned, we either extend observation 30d OR re-slot. Your call.

### Case-study interview (D+46 if attestation signed on time)

After attestation, we set up a 60-min interview with your engineering or platform leader. Script in `marketing/lighthouse-kit/06-case-study-interview-script.md`. You'll see every quote before publication; you have right of refusal on any specific phrasing.

For Enterprise BYOK customers under NDA, the published case study is fully sanitized — no customer name, no specific scale numbers, no architecture details that would identify you. You countersign the sanitized version before it ships.

---

## Comms protocol

### Cadence

| Channel | Purpose | Cadence | SLA |
|---|---|---|---|
| Slack Connect `#corelink-{slot}` | Daily ops, questions, soft escalations | Async | Reply within 4 business hours; 1h acknowledge for tagged messages |
| Weekly check-in call | Structured review | 30 min/week | Scheduled D+15 onwards |
| Email (daily SLA digest) | Automated daily report | Daily 00:00 UTC | No reply expected |
| PagerDuty direct page | P0 incidents | As needed | Phone callback within 1h |
| Quarterly reference call | Post-engagement | Up to 2/quarter for 12 months | Scheduled by DevRel |

### Escalation matrix

| Level | Who | When | How |
|---|---|---|---|
| L0 | Customer Success engineer (yours, named) | Any non-P0 question | Slack Connect, email |
| L1 | Customer Success lead | L0 unresponsive > 4 business hours | Slack Connect `@cs-lead` |
| L2 | Engineering S-20 lead | Technical correctness, architecture decisions | Slack Connect `@eng-lead` |
| L3 | Founder (Gustavo Schneiter) | Withdrawal threats, procurement deadlock, anything we're getting wrong | Email gustavo@humangr.com OR Slack Connect `@gustavo` |
| P0 | SRE on-call | Live incident, SLO breach, BYOK kill-switch event | PagerDuty page |

L0 → L1 → L2 → L3 escalation takes a maximum of 16 business hours. Go straight to L3 if the conversation is about whether to continue the engagement.

### Support SLAs

| Item | Target |
|---|---|
| Slack Connect acknowledgement (tagged) | ≤ 1 hour during business hours; ≤ 4 hours outside |
| PagerDuty page acknowledgement | ≤ 10 min, 24/7 |
| Engineering response on classified P1 | ≤ 24 hours |
| Weekly check-in cancel notice (either side) | ≥ 4 hours in advance |
| Attestation draft delivery after D+40 | ≤ 24 hours |

---

## FAQ — 20 anticipated questions

**1. What if we hit a P0 incident on our side that has nothing to do with CoreLink — does it pause the observation window?**
No. The observation window measures CoreLink SLOs against your tenant. Your unrelated incidents don't affect our SLA samples. If your incident causes you to need to pause check-ins, just tell us.

**2. Do we have to use the dedicated engineer's time?**
No. The engineer is there if you need them. Many lighthouse customers go full weeks without paging us. That's fine. Light usage is a positive signal.

**3. What happens to our data if we withdraw mid-window?**
You issue a DSR (data subject request) from the privacy portal in your CoreLink dashboard — the **Erasure** action under `/dsr`, or `POST /v1/privacy/dsr/erasure` if you'd rather script it — and we honor it within 30 days per our DPA. Your audit chain entries are retained per regulatory requirement (we anonymize the customer reference) but the cached blobs are evicted within 24h.

**4. Can we extend beyond 6 months free?**
At the end of the 60-day engagement we'll talk about going onto a paid tier. The 6 months free runs from your `Engaged` state regardless — even if attestation takes 60 days, you still get a full 6 months at no charge from D+0.

**5. Do we need to write any code beyond the CI integration?**
For Team tier: no. For Enterprise BYOK: a small amount of IAM/KMS policy configuration on your side to grant CoreLink workload identity access to your customer-managed key. We provide the policy snippets.

**6. What's the difference between us and a typical pilot customer?**
A pilot is "try this for free and tell us if it works." A lighthouse is "be one of 3 reference customers publicly attesting our SLA at GA." The engagement is more structured, the symmetry tighter, the legal scope clearer.

**7. Can we run CoreLink on-prem?**
Not in the lighthouse program — we're attesting our SaaS SLA. We have on-prem and self-hosted offerings on the roadmap but they aren't part of this evidence gate.

**8. Who else are the other 2 lighthouse customers?**
We don't disclose. Your published case study mentions you (with your sign-off) and references "two other lighthouse customers" without naming them. Same protection applies to them.

**9. What if our team's primary build tool isn't Bazel/Buck2/Pants?**
Talk to us before signing. We support a generic HTTP cache API (any client that can do PUT/GET against a content-addressable backend works), and adapters for common alternatives. We won't admit you as a lighthouse customer if your build tool integration would require new product work.

**10. Can we use CoreLink for things other than build caching during the engagement?**
Yes, but we only attest the SLOs you actually exercise during the 30-day window. ML training data caching, Docker layer caching, generic CAS — all are in-scope use cases, all get sampled if you exercise them.

**11. What about a security audit on our side — can we pentest CoreLink?**
Subject to our responsible-disclosure policy. Email `security@humangr.com` before any probing. We have not engaged an external pentest firm, so there is no third-party summary to share; under NDA we can share internal adversarial-review and sealed cargo-fuzz summaries.

**12. What happens during the 30-day window if you ship a CoreLink update that affects us?**
Any deploy that touches your tenant's hot path: 24h notice in Slack Connect, with rollback plan. You can request a freeze on your tenant during a critical period of your own work — tell us. Material spec or DPA changes follow `specs/_runbooks/RB-DPA-CHANGE.md`.

**13. Is the attestation form publicly disclosable?**
A sanitized version goes into `specs/_audits/2026-MM-DD-lighthouse-customer-{slot}-attestation.md` with `audit_status: ACTIVE` — public, redacted of any identifying info per the version you countersigned. You decide what's redacted before sign-off.

**14. What's the case study turnaround time?**
Draft within 7 days of the interview. Your review cycle is up to 2 round-trips. Publication target is D+60.

**15. Can we hold a quote back from the case study?**
Yes. Any specific quote you don't want published, we cut it.

**16. What if our internal Legal won't sign the LOI?**
Talk to us at L3 (Founder). The LOI is short and mutual; we've cleared it with our own counsel and we can adapt to your form if needed.

**17. Are we subject to your DPA?**
Yes — your standard CoreLink DPA applies (v1.0.0 with the locale appropriate for your jurisdiction; pt-BR / en-US / es-419 available). The lighthouse engagement does not change DPA terms.

**18. What metrics will appear in the public case study?**
Cache hit ratio, build-minute savings (your number, your reporting), p99 latency, attestation status. NOT: your absolute build minute spend, your engineer count, your tenant id, your KMS provider (Enterprise — KMS *family* yes if you allow, specific provider/region no by default).

**19. Can we add SLOs to our per-customer catalog during the window?**
Once observation has started, the SLO set is frozen for that window. Additions trigger a new 30-day observation. We'd rather get the right SLOs at scoping than chase them mid-window.

**20. What do we get post-GA if we stay as a paying customer?**
Lighthouse alumni get: priority routing for support escalations, first access to new features in private beta, named status on the CoreLink reference list (with your sign-off), and the 6 months of free service. We'll discuss the steady-state contract in month 5 of the engagement.

---

## Quick reference

| You need | Go to |
|---|---|
| Schedule contract (timeline) | `marketing/lighthouse-kit/03-integration-timeline.md` |
| Weekly check-in agenda | `marketing/lighthouse-kit/04-weekly-checkin-agenda.md` |
| Attestation form instructions | `marketing/lighthouse-kit/05-sla-attestation-instructions.md` |
| Case-study interview script | `marketing/lighthouse-kit/06-case-study-interview-script.md` |
| Your case-study template | `marketing/lighthouse-kit/case-study-template/{your-variant}.md` |
| CLI install + usage | `docs/cli/` |
| Our DPA + privacy notice | `specs/_legal/` |
| Security questionnaire answers | `specs/_security/` (request access via your CS engineer) |
| Your daily SLA dashboard | URL provided D+10 — bookmark it |

---

**Fim CUSTOMER-PLAYBOOK.**
