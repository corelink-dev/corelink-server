---
id: "SALES-RATE-LIMIT-FAQ"
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
parent: "SALES-FAQ-MASTER"
tags: ["sales", "faq", "rate-limit", "429", "throughput", "tier", "r-prep", "ga"]
---

# CoreLink Sales FAQ — Rate Limits (9 Questions)

> **Audience:** anyone running a CoreLink pre-purchase conversation
> who gets a rate-limit / TPS / 429 question. This is a topical
> subset of `FAQ-MASTER.md` focused on rate-limit UX. Use as-is in a
> doc; paraphrase in conversation.
> **Tone:** factual, falsifiable, no marketing varnish. Every numeric
> claim is sourced.
> **What this is not:** a contract. The DPA, MSA, and order form
> override anything here. Engineering source of truth:
> `apps/docs/docs/explanation/rate-limits.mdx`.

---

## How to use this file

- 9 questions covering the full 429 conversation: the canonical
  ladder, what 429 looks like, why we picked RFC 9331, the
  upgrade-tier path, and the 5-arm taxonomy.
- Each entry has: **Q**, **A** (short canonical answer), **Sources**.
- If a prospect's question isn't here, route to the engineering doc
  at `https://humangr.com/corelink/docs/explanation/rate-limits` or to
  `trust@humangr.com`.

---

### RL1 — What are the per-tier rate limits?

**Q:** What sustained throughput does each tier get, and what burst
capacity?

**A:** Five tiers; the rate-limit ladder is:

| Tier | Sustained (RPS) | Burst capacity (tokens) |
|------|----------------:|------------------------:|
| Free | 10 | 50 |
| Solo | 50 | 200 |
| Team | 200 | 1 000 |
| Business | 1 000 | 5 000 |
| Enterprise | 10 000 (negotiable per contract) | 50 000 |

Burst capacity is always **≥ 4× sustained RPS** so a normal
parallel-build spike (CI matrix of 8-16 shards) does not 429 you.
Enterprise rates are negotiated in the order form; AWS API Gateway
default 10k RPS is the benchmark we anchor on.

**Sources:** `crates/corelink-ratelimit/src/tier.rs`
(`TIER_RATE_LADDER` constant);
`apps/docs/docs/explanation/rate-limits.mdx#per-tier-rate-limit-ladder`.

### RL2 — What does a 429 response actually look like?

**Q:** When my client hits the ceiling, what do we get back?

**A:** A standard HTTP 429 with:

- **Headers** — IETF RFC 9331 `RateLimit` + `RateLimit-Policy`, RFC
  6585 `Retry-After`, a CoreLink discriminator `X-Rate-Limit-Type`
  (5 canonical values), and three informational `X-CoreLink-*`
  headers (`-Tier`, `-Quota-Reset-UTC`, `-Tier-Upgrade-URL`).
- **JSON body** — a stable envelope:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "kind": "tenant_quota",
    "message": "…",
    "retry_after_seconds": 5,
    "tier": "free",
    "tier_upgrade_url": "https://corelink-docs.humangr.com/pricing",
    "docs_url": "https://corelink-docs.humangr.com/explanation/rate-limits",
    "request_id": "01HFXY…",
    "limit": 10,
    "remaining": 0,
    "reset_seconds": 5,
    "reset_utc": "2026-05-15T14:30:25Z"
  }
}
```

> ⚠️ **The two URLs in that body are dead in production — and the sample is correct anyway.** `tier_upgrade_url` and `docs_url` are frozen canonical constants in the service (`crates/corelink-rate-headers/src/headers.rs:164,173`), pinned by a property test (`INV-BODY-FROZEN-URLS`, `crates/corelink-rate-headers/tests/prop_rate_headers.rs:969-971`), so this is byte-for-byte what a customer receives today. Both hostnames are NXDOMAIN (verified 2026-08-02): the live equivalents are `https://humangr.com/corelink/en/pricing` (200; the locale-less `/corelink/pricing` 404s) and `https://humangr.com/corelink/docs/explanation/rate-limits` (200). **Do not "fix" it here** — editing the sample would make this FAQ diverge from the wire. The fix belongs in the constants + the frozen-URL test, in its own PR; if a prospect asks, tell them the links in the error body are stale and hand them the live ones.

Your SDK pattern-matches on `error.kind`; humans read
`error.message`; long deferred retries use `error.reset_utc`
(RFC 3339, robust against clock skew). Every field is mirrored in
both the headers and the body so single-channel consumers
(headers-only or body-only) work without compromise.

**Sources:**
`crates/corelink-rate-headers/src/headers.rs::RateLimitErrorBody`;
`specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` §2.

### RL3 — Why RFC 9331 and not `X-RateLimit-Limit / -Remaining / -Reset`?

**Q:** Stripe, GitHub, and most vendors I've used send
`X-RateLimit-*`. Why did CoreLink go IETF?

**A:** The legacy custom `X-RateLimit-*` family varies between
vendors — Bazel / Buck2 / Stripe / GitHub all interpret slightly
differently (especially `Reset` — epoch vs seconds-from-now), so an
SDK that wants to be portable has to fork per-vendor. RFC 9331
(`RateLimit: limit=N, remaining=M, reset=S` + `RateLimit-Policy`) is
the IETF-stable canonical form that Stripe, GitHub, and major CDNs
have **already adopted** in parallel; adopting it means your SDK
works against CoreLink with **zero per-vendor adaptation**. This is
the explicit decision in spec contract §14.s08.5.

**Sources:** `crates/corelink-rate-headers/src/lib.rs` (module-level
docs, "Why RFC 9331" section);
[RFC 9331](https://datatracker.ietf.org/doc/rfc9331/).

### RL4 — What are the 5 different kinds of 429?

**Q:** What does `X-Rate-Limit-Type` tell me?

**A:** Every 429 carries one of 5 canonical values:

| Value | Layer | Customer action |
|-------|-------|-----------------|
| `tenant_quota` | per-tenant token bucket | back off + retry; consider tier upgrade if sustained |
| `per_ip` | edge IP throttle | fix egress / rotate IP / authenticate (per-PAT bucket is higher) |
| `per_pat` | per-PAT misuse signal | **rotate the credential** — likely compromised |
| `over_quota` | storage / bandwidth cap | wait for monthly reset OR upgrade plan |
| `global_circuit_open` | system-wide breaker | retry in 60s (we are shedding load region-wide) |

This taxonomy is `#[non_exhaustive]` in code but **frozen at GA** —
your SDK can match on these 5 and trust them not to silently change.
Pattern-match on the body's `error.kind` (mirrors the header).

**Sources:** `crates/corelink-rate-headers/src/headers.rs`
(`XRateLimitTypeKind`); sprint contract §5 R-S08-8.

### RL5 — How should our SDK handle 429s?

**Q:** What's the canonical backoff curve you want clients to use?

**A:**

1. **Honour `Retry-After` first** — always present on CoreLink 429s;
   in seconds form.
2. **Add jitter** — full-random in `[0, Retry-After * 1.5]` to avoid
   thundering-herd at the `reset` instant.
3. **Fall back to exponential** only if `Retry-After` is absent —
   canonical 250ms → 500ms → 1s → 2s → 4s → 8s.
4. **Use `reset_utc`** (absolute RFC 3339) for long deferred retries
   (cron); `reset_seconds` is stale by the time a delayed job runs.
5. **Stop retrying on `over_quota`** — storage caps don't reset on
   exponential backoff; they reset on the 1st UTC.
6. **Treat `per_pat` as a security incident** — rotate the PAT and
   audit your CI logs.

The official Rust + TypeScript SDKs implement (1)-(4) automatically;
you only need to handle (5) and (6) in your application code.

**Sources:** `apps/docs/docs/explanation/rate-limits.mdx#how-to-back-off`.

### RL6 — When should we upgrade tier?

**Q:** What's the signal that we need to move from Free → Solo, Solo
→ Team, etc.?

**A:** Three concrete signals:

1. **Your `remaining` value sits at zero for ≥ 5 consecutive
   seconds** during a hot workflow. The token bucket is structurally
   empty; sustained ceiling is the bottleneck.
2. **You see `tenant_quota` 429s every CI run**, not just rare
   bursts. Burst capacity is meant to absorb spikes, not run as your
   steady state.
3. **Your `X-CoreLink-Tier-Upgrade-URL` redirects open in dashboards
   recurringly** — your team is hitting the CTA path the SDK
   prints.

You should **not** upgrade for `per_ip` (fix egress), `per_pat`
(rotate credential), or `global_circuit_open` (transient; recovers
≤ 2min). Upgrades are self-service for Solo / Team / Business via
Stripe Checkout; Enterprise routes through the inquiry form.

**Sources:** `apps/docs/docs/explanation/rate-limits.mdx#when-to-upgrade-tier`;
`marketing/sales/FAQ-MASTER.md#p1` (tier comparison).

### RL7 — Do you hard-fail builds when we hit the rate limit?

**Q:** Will a 429 break my CI matrix?

**A:** Not directly — a 429 is a **soft signal** for the client to
back off, not a refusal of service. The canonical behaviour:

- CoreLink-issued SDKs retry 429s with jitter automatically.
- A burst that consumes the entire bucket forces a brief pause (the
  `Retry-After` window — typically 1-5 seconds for a Free / Solo
  tenant), then resumes.
- The build completes; total wall-clock cost is the cumulative
  backoff time.
- You can self-diagnose retry pressure via the
  `RateLimit: remaining=…` header — when it bottoms out you know
  you're at the ceiling.

If your **CI matrix is so wide that 429s dominate wall-clock time**,
that's the signal in RL6 — upgrade tier. The hard-fail story is
reserved for `over_quota` storage at the 100% boundary (we serve
429 there until the monthly reset, since allowing PUT past 100%
would silently overage you).

**Sources:** `crates/corelink-ratelimit/src/limiter.rs` (token
bucket implementation); `marketing/sales/FAQ-MASTER.md#p2`
(overage policy).

### RL8 — What about Enterprise — is the 10k RPS real or marketing?

**Q:** When you say Enterprise gets 10k RPS, is that the actual
default, and is it negotiable?

**A:** 10 000 sustained RPS / 50 000 burst is the **default
enterprise ceiling** — it's wired into the canonical
`ENTERPRISE_REFILL_RPS` constant in
`crates/corelink-ratelimit/src/tier.rs` and benchmarked against AWS
API Gateway's default 10k RPS (spec contract §16). It is
**negotiable per contract** — admin override via the S-13 admin
plane sets a per-tenant override that supersedes the default. The
override is signed into the order form; we won't surprise you with
a different number than what's contractually committed.

For prospects that need >10k RPS, the conversation is: (a) do you
actually need sustained-10k or is it 10k burst across a narrow
window (Enterprise burst is 50k, which absorbs most "10k+" claims),
and (b) which regions — multi-region quotas compose, so a 5-region
deployment effectively gets 5×10k = 50k aggregate.

**Sources:** `crates/corelink-ratelimit/src/tier.rs`
(`ENTERPRISE_REFILL_RPS = 10_000`,
`enterprise_rate_matches_aws_api_gateway_baseline` test);
spec contract §16.

### RL9 — How do I tell if a 429 is "our fault" vs "your system being overloaded"?

**Q:** When we see a 429 in production, how do we know if it's a
real CoreLink incident vs us being rate-limited normally?

**A:** Read `X-Rate-Limit-Type`. The 5 arms split cleanly between
**customer-side** (legitimate, expected) and **system-side**
(actionable incident):

- **Customer-side, expected:** `tenant_quota`, `per_ip`, `per_pat`,
  `over_quota`. These are all **excluded from the SLO-AVAIL
  denominator** (sprint contract §7.10.s08.1 — we explicitly do not
  count legitimate over-plan responses against our availability
  number). Action: handle in your SDK; no escalation.
- **System-side, our problem:** `global_circuit_open`. This is the
  system-wide breaker tripped on multi-signal overload. It **is
  counted** in our SLO numerator. Action: check
  [hugrl.betteruptime.com](https://hugrl.betteruptime.com); if no
  incident is posted, escalate via `support@humangr.com` with the
  `error.request_id` from the 429 body.

The single most useful diagnostic value is the `request_id` — every
429 carries one (UUIDv7), and our support team can pull the full
audit trail from it within minutes.

**Sources:** `crates/corelink-rate-headers/src/headers.rs`
(`counts_against_sli` predicate); sprint contract §7.10.s08.1 (SLI
correctness fix);
`apps/docs/docs/explanation/rate-limits.mdx#the-5-arm-taxonomy`.

---

## Maintainer notes

- This file is a **topical extract** from `FAQ-MASTER.md`; the
  master is the source of truth for cross-topic phrasing.
- If a customer-visible answer changes, update **both** docs and
  bump the master's `version`.
- Engineering source of truth lives in `apps/docs/docs/explanation/
  rate-limits.mdx` and `crates/corelink-rate-headers/src/headers.rs`
  — change those FIRST when the surface evolves.
