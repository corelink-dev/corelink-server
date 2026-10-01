---
id: "STATUS-PAGE-SPEC"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "SRE Lead"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "ROADMAP-TO-GA.md §H-18 (Statuspage.io account)"
tags:
  - "marketing"
  - "launch"
  - "status-page"
  - "statuspage-io"
  - "sre"
  - "incident-comms"
  - "wt-r8-1"
---

# CoreLink Public Status Page — Specification

> ## ⛔ SUPERSEDED — do not execute (2026-08-24)
>
> This document plans a status page on **Atlassian Statuspage** reached at a
> branded `status.` hostname. Neither happened.
>
> **What shipped:** the status page is on **Better Stack**, at
> **https://hugrl.betteruptime.com**, and that vendor URL is the one customers
> are given.
>
> **Why the branded hostname is gone:** it is a third-level name, outside the
> one-level `*.humangr.com` coverage of Cloudflare Universal SSL, so Cloudflare
> holds no certificate for it — and Better Stack refuses a custom Host because
> a custom domain is a paid-plan feature. Neither side could terminate TLS, and
> it never served. The owner decided on 2026-08-24 not to buy the plan, so the
> CNAME was deleted from the zone and the hostname is retired, not pending.
>
> **Do not follow the provisioning steps below.** They would have you create an
> account with a vendor we do not use and request a custom domain we have
> decided not to pay for. The three scripts that automate these steps now
> refuse to run. Kept for the record — and because ~20 other documents cite
> these files — not as a plan.
>
> Closed as **B-041**. See `CHANGELOG.md` (2026-08-24) for what the status page
> was found to be claiming while this was left standing.


> **Purpose:** describe the public status page CoreLink runs from GA. What hosts it, what components it advertises, who subscribes, how severity maps to public messaging, how it auto-publishes from PagerDuty, and who approves what.
> **Audience:** SRE (operators), VPSec (severity gating), VPMkt (non-incident comms), CEO (final approver for non-incident comms).
> **Cross-references:** `LAUNCH-CHECKLIST-V2.md` (operational use during launch), `CRISIS-COMMS-TEMPLATES.md` (templated incident messages), `specs/_runbooks/ONCALL-ESCALATION-MATRIX.md`.

---

## 1. Choice: Statuspage.io vs. self-hosted

**Recommendation: Statuspage.io for GA. Migrate to self-hosted after Q3 2026.**

| Criterion | Statuspage.io (Atlassian) | Self-hosted (e.g., Cachet, Gatus, custom) |
|---|---|---|
| Time-to-GA | Ready in < 1 day; H-18 already covers procurement. | 2-3 weeks of engineering + ops. |
| Subscriber notifications (email + SMS + RSS + webhooks) | Native, battle-tested. | We build it. |
| Page hosting reliability | Atlassian's SLA, geo-distributed. | We run it (ironic during our own outage). |
| Brand fit | Adequate; custom domain `status.corelink.humangr.com` supported. | Full brand control. |
| Cost at GA scale | $99-299/mo (Business plan; supports private components for lighthouse). | $0 software + engineering + ops time. |
| Audit trail | Native export; integrates with Drata for SOC 2. | We build retention. |
| Auto-publish from PagerDuty | First-class integration. | We build it. |
| Component limit | 50 components on Business plan (we need 8). | Unlimited. |

**Decision rationale.** During launch, "status page itself goes down" is the worst possible time to discover a self-host bug. Statuspage.io removes the page-hosting from our incident surface. The migration trigger is when we exceed Statuspage.io's per-component or per-incident pricing tier, or when we need a feature it doesn't ship (e.g., per-tenant scoped private status pages). Re-evaluate Q3 2026.

**ADR placeholder:** if/when we migrate, file ADR-0035 (Status page sovereignty) referencing this spec.

---

## 2. Domain + branding

- **Public URL:** `https://status.corelink.humangr.com` (CNAME → Statuspage.io).
- **Fallback URL:** `https://humangr.com/corelink/status` — a static-HTML page in the CF Pages site, manually updated, served if Statuspage.io is itself down. Pre-staged with a "checking with our status provider" message.
- **Brand:** CoreLink logo, neutral typography matching `humangr.com/corelink`; status indicator colors follow industry convention (green/yellow/orange/red).
- **Footer:** RFC 9116 link to `security.txt`; link to `SECURITY.md`; link to trust center.

---

## 3. Components

The status page advertises exactly the following 8 components. Each maps to a CoreLink-internal service and its primary SLO. Each component is independently set-able to Operational / Degraded Performance / Partial Outage / Major Outage.

| # | Component name | What it advertises | Primary SLO mapped | Owner |
|---|---|---|---|---|
| C1 | **API** | The CoreLink control-plane API (`corelink-api.humangr.com`) — REAPI surface, admin endpoints, signup/billing endpoints, BYOK key-management calls. | API p99 ≤ 250 ms; error rate ≤ 0.1%. | SRE-OC |
| C2 | **CAS Read Path** | Content-addressable storage read serving — `GetBlob`, `BatchGetBlobs`, cache hits. | CAS read p99 ≤ 100 ms (hit); error rate ≤ 0.05%. | SRE-OC |
| C3 | **CAS Write Path** | CAS write serving — `UpdateBlob`, `BatchUpdateBlobs`, deduplication, GC backpressure. | CAS write p99 ≤ 500 ms; error rate ≤ 0.1%. | SRE-OC |
| C4 | **BYOK** | Customer-managed-key envelope encryption against AWS KMS / GCP KMS / Azure Key Vault / HashiCorp Vault. | BYOK envelope p99 ≤ 50 ms; vendor success rate ≥ 99.9%. | SRE-OC + VPSec |
| C5 | **Audit** | Audit-chain ingest + Merkle-proof issuance; SIEM forwarding (S3 + Splunk-compatible). | Audit ingest lag ≤ 60 s; proof issuance p99 ≤ 200 ms. | VPSec |
| C6 | **Billing** | Stripe webhook ingest, invoice generation, metering aggregation. | Webhook ingest success ≥ 99.9%; billing freshness ≤ 1 h. | Finance + SRE-OC |
| C7 | **Docs** | `corelink-docs.humangr.com` Docusaurus site + CDN; including security.txt + trust center. | Docs availability ≥ 99.95%. | VPMkt + Engineering |
| C8 | **Admin Console** | `humangr.com/corelink/admin` operator console — Clerk-gated; org/tenant/user admin. | Admin availability ≥ 99.9%. | SRE-OC |

**Hidden / private components.** None at GA. (If we add tenant-scoped private status visibility post-GA, file ADR-0036.)

---

## 4. Subscribers

### 4.1 Pre-subscribed (mandatory) at GA

- **3 lighthouse customers** — primary contact + SRE/oncall contact each, totaling 6 emails minimum. Subscribed during onboarding per `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` Day-1 step.
- **CoreLink internal:** SRE on-call distribution (PagerDuty service email), `security@humangr.com`, `support@humangr.com`, `compliance@humangr.com`, `ceo@humangr.com`.

### 4.2 Public opt-in channels (live at T-0)

- **Email subscription** — visitors at `status.corelink.humangr.com` click "Subscribe to updates" → email + per-component filter UI.
- **RSS feed** — `status.corelink.humangr.com/history.rss` and `status.corelink.humangr.com/incidents.rss`.
- **Atom feed** — `status.corelink.humangr.com/history.atom`.
- **Webhook subscription** — for power users / paid customers, Statuspage POSTs incident payloads to a customer-provided URL.
- **SMS subscription** — Statuspage Business plan; opt-in only; SEV1 messages only (cost control).
- **Slack integration** — public CoreLink community Slack receives a `#status-updates` feed (one-way).

### 4.3 Notification policy

- **SEV1 (Major Outage)** → email-blast to **all subscribers** including SMS opt-in; RSS update; Slack update.
- **SEV2 (Partial Outage)** → email to **per-component subscribers**; RSS update.
- **SEV3 (Degraded Performance)** → **silent on the page (no email blast)**; RSS update only; status indicator changes to yellow. Rationale: avoid notification fatigue; ops-grade observers monitor RSS.
- **Scheduled maintenance** → email to subscribers per their per-component subscription filter.

---

## 5. Severity mapping

This table is **canonical**. PagerDuty integrations and the approval workflow both reference it.

| Internal SEV | Statuspage status | Subscriber notification | Approval to publish | Time-to-publish target |
|---|---|---|---|---|
| **SEV1** — customer-impacting outage affecting > 10% of traffic OR core invariant violation (e.g., CAS write rejection storm, audit chain breakage, BYOK plane unavailable). | **Major Outage** (red) + incident timeline | **Email blast + SMS opt-in + RSS + Slack feed** | **NO APPROVAL — instant publish.** Auto-published by PagerDuty → Statuspage integration. CEO/CTO informed asynchronously via PagerDuty escalation. | < 5 min from PagerDuty SEV1 declaration. |
| **SEV2** — degraded service affecting < 10% of traffic, or single-component partial outage (e.g., BYOK degraded for one vendor, Billing webhook backlogged). | **Partial Outage** (orange) + incident timeline | **Per-component email + RSS + Slack feed** | **Oncall L1 approves.** SRE-OC pushes after 60-sec sanity check; no exec approval needed. | < 10 min from PagerDuty SEV2 declaration. |
| **SEV3** — performance degradation, error budget burn elevated, no customer-impacting outage (e.g., elevated p99 latency without violating SLO). | **Degraded Performance** (yellow), silent on the page (no email blast) | **RSS only**, no email | SRE-OC sole discretion. | < 30 min, or batched into next status sweep. |
| **Maintenance** — planned change (window per §6). | **Under Maintenance** (blue) | Per-component email + RSS, scheduled in advance | VPSec + SRE Lead approve schedule; CEO informed. | Posted at scheduling time (7d advance per §6). |
| **Non-incident comms** (launch announcements, general updates, post-incident retrospectives published publicly). | Status banner, no component change | RSS + email subscribers | **CEO approves**, drafted by VPMkt. | Per scheduling. |

**Hard rule:** **SEV1 publishes BYPASS all human approval.** Speed-of-light incident transparency is more important than wording polish. The system publishes a default-templated SEV1 message; humans refine the message *after* the page is live, not before. See `CRISIS-COMMS-TEMPLATES.md` §A for the SEV1 default template that auto-publishes.

---

## 6. Maintenance window template

**Hard rule:** **7-day advance notice required for any planned maintenance.** Exceptions: emergency security patches (covered under SEV1 emergency-maintenance with retro-justified posting; see §7).

**Template** (post in Statuspage 7+ days before the window):

```
Title: Scheduled Maintenance: <component(s)> — <window start (UTC)>
Components affected: <C1..C8>
Status during window: Under Maintenance
Expected duration: <hh:mm>
Expected user impact: <user-readable: "no impact", "elevated latency", "API unavailable in <region>", etc.>

What we are doing: <one paragraph of plain English>
Why: <one paragraph: change motivation + invariant we preserve>
Rollback: <one paragraph: how we revert if the change misbehaves>

Subscribers will receive a reminder 24 hours before the window opens and a
final confirmation when the window closes.

Questions: status@humangr.com (replies monitored 24/7 during launch period;
standard business hours after T+30d).
```

**Cadence enforced:** Maintenance windows are batched: at most 1 window per component per calendar week. The maintenance-scheduling spreadsheet lives at `specs/_runbooks/maintenance-schedule.md` (created at H-18 provisioning).

---

## 7. Auto-publish hook: PagerDuty → Statuspage

PagerDuty native integration. Configured per service.

### 7.1 Service mapping

| PagerDuty service | Statuspage component | Auto-status mapping |
|---|---|---|
| `corelink-api-prod` | C1 (API) | Triggered (SEV1) → Major Outage; Acknowledged → Identified; Resolved → Operational. |
| `corelink-cas-read-prod` | C2 (CAS Read Path) | Same mapping. |
| `corelink-cas-write-prod` | C3 (CAS Write Path) | Same mapping. |
| `corelink-byok-prod` | C4 (BYOK) | Same mapping. |
| `corelink-audit-prod` | C5 (Audit) | Same mapping. |
| `corelink-billing-prod` | C6 (Billing) | Same mapping. |
| `corelink-docs-prod` | C7 (Docs) | Same mapping. |
| `corelink-admin-prod` | C8 (Admin Console) | Same mapping. |

### 7.2 Config snippet (Statuspage component mapping, schematic)

```yaml
# config/statuspage-integration.yaml — committed to ops repo; secrets via env
pagerduty:
  api_token: ${PD_API_TOKEN}
statuspage:
  page_id: ${SP_PAGE_ID}
  api_key: ${SP_API_KEY}

mappings:
  - pagerduty_service: corelink-api-prod
    statuspage_component_id: ${SP_COMPONENT_API}
    severity_to_status:
      SEV1: major_outage
      SEV2: partial_outage
      SEV3: degraded_performance
    auto_publish_template: "templates/sev1-default.md"   # see CRISIS-COMMS-TEMPLATES.md §A
    notify_subscribers:
      SEV1: true        # email + SMS + RSS
      SEV2: true        # per-component email + RSS
      SEV3: false       # RSS only
  - pagerduty_service: corelink-cas-read-prod
    statuspage_component_id: ${SP_COMPONENT_CAS_READ}
    severity_to_status: *default
    # ... (same shape for C3..C8)

webhook:
  url: https://hooks.statuspage.io/incidents
  signing_secret: ${SP_WEBHOOK_SECRET}
  retry: { max_attempts: 3, backoff_seconds: [5, 15, 45] }

approval_bypass:
  SEV1: true            # auto-publish instantly; no human gate
  SEV2: false           # SRE-OC must press confirm in PagerDuty mobile
  SEV3: false           # SRE-OC discretion
```

### 7.3 Failure mode

If PagerDuty → Statuspage webhook fails (3 attempts exhausted), the integration emits a SEV2 internal page-out to SRE-OC titled "Statuspage publish failed" with the original incident payload attached. SRE-OC then either (a) manually pushes to Statuspage from the PagerDuty mobile app, or (b) updates the static fallback page at `humangr.com/corelink/status` and tweets from `@corelinkdev`.

---

## 8. Approval workflow (summary)

| Posting type | Default approver | Bypass condition | Time-to-publish |
|---|---|---|---|
| SEV1 page status | **None** (auto-publish) | Always bypass. | < 5 min. |
| SEV1 message refinement | VPSec or VPMkt (whoever is in war room first) | — | After page is live; aim < 30 min. |
| SEV2 page status | SRE-OC L1 | None. | < 10 min. |
| SEV3 page status | SRE-OC | None. | < 30 min. |
| Scheduled maintenance | VPSec + SRE Lead | None. | 7d in advance. |
| Non-incident comms (launches, announcements, post-incident retros) | **CEO** | None. | Per scheduling. |
| Public post-incident retro | CEO (with VPSec + Legal review) | None. | Within 14d of incident closure. |

---

## 9. Operational notes

- **Status page must never lie about CAS write.** A CAS write outage is the single biggest reputational risk and a direct invariant-violation surface. If in doubt about whether C3 is degraded → mark it degraded.
- **Quiet period:** during a SEV1 the page may update *frequently* — every 15-30 min the on-call posts a brief update even if "still investigating". Silence > 60 min during SEV1 is itself a reputational incident.
- **Recovery confirmation:** before marking a component back to Operational, wait for the SLO recovery window (typically 15 min of clean signal). Premature green is worse than a slightly-prolonged yellow.
- **Post-incident retros (public).** All SEV1 incidents get a public retro post within 14d, drafted by SRE Lead + VPSec, reviewed by Legal, approved by CEO. Style: blameless, structured per `specs/_runbooks/RB-POSTMORTEM-PROCESS.md`.

---

## 10. Cross-references

- `LAUNCH-CHECKLIST-V2.md` — references this spec at rows L8 (preparing), L22 (T-0 flip to operational), L28+ (incident-driven updates).
- `CRISIS-COMMS-TEMPLATES.md` — references SEV1 auto-publish template (§A) and SEV2/SEV3 manual templates.
- `specs/_runbooks/ONCALL-ESCALATION-MATRIX.md` — referenced for who-pages-whom at each SEV.
- `specs/_runbooks/RB-POSTMORTEM-PROCESS.md` — referenced for public retro format.
- `ROADMAP-TO-GA.md` §H-18 — Statuspage.io account provisioning.
- `SECURITY.md` + `apps/docs/static/.well-known/security.txt` — referenced from status page footer.
