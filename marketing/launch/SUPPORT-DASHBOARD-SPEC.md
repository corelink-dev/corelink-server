---
id: "SUPPORT-DASHBOARD-SPEC"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "Support Lead + VPMkt (dual)"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "specs/_runbooks/RB-CUSTOMER-SUPPORT-T-90.md"
tags:
  - "marketing"
  - "launch"
  - "support"
  - "dashboard"
  - "spec"
  - "metrics"
  - "sla"
  - "nps"
  - "wt-r-prep-support-runbook"
---

# Support Dashboard — Specification

> **Purpose:** specify the **support team's operational dashboard** — the single screen the Support Shift Lead keeps open during shifts and the screen the Support Lead reviews each morning + Friday.
> **Companion:** `marketing/launch/DAY-1-DASHBOARD-SPEC.md` is the **war-room launch-day** dashboard (T-24h..T+72h). This dashboard is the **steady-state support** dashboard (T+0..T+90 first 90 days; surviving thereafter).
> **Audience:** Support T1 + T2, Support Shift Lead, Support Lead, VPMkt, Founder (weekly skim).
> **Hosting:** Grafana (dedicated folder `Support / T-90`) consuming from the ticket-queue vendor + `corelink-dsr` + Postgres `support_audit` schema. ⚠️ **No hosted CoreLink Grafana instance exists yet:** the dotted `grafana.corelink` name is NXDOMAIN (dig, 2026-10-01), so this spec prints no embed address; one is assigned when the instance is stood up (same note as `marketing/retention/customer-health/HEALTH-DASHBOARD-SPEC.md`).

---

## 1. Layout (single-screen, 1440×900 minimum)

```
+----------------------------------+----------------------------------+
| 1. Open tickets by severity      | 2. SLA burn-down                 |
|    (stacked bar; live)           |    (per-severity gauges)         |
+----------------------------------+----------------------------------+
| 3. Top 10 issue categories       | 4. Customer NPS sample           |
|    (rolling 7d / 30d toggle)     |    (rolling 30d gauge + trend)   |
+----------------------------------+----------------------------------+
| 5. Ticket aging heatmap (severity × age bucket; live)               |
+---------------------------------------------------------------------+
| 6. DSR panel  | 7. Billing panel | 8. Conversion | 9. Channel health|
|  (queue +     |  (queue + $ at   |   (ticket→    |  (intake rate    |
|   timer)      |   stake)         |   incident)   |   per channel)   |
+---------------+------------------+---------------+------------------+
```

---

## 2. Panel specifications

### 2.1 Panel 1 — Open tickets by severity (live)

| Property | Value |
|---|---|
| Visualisation | Stacked horizontal bar, 4 segments (P0, P1, P2, P3) |
| Refresh | 60 seconds |
| Data source | Ticket queue API (`GET /tickets?state=open`) |
| Aggregation | `count(*) GROUP BY severity` |
| Thresholds | P0 > 0: red banner; P1 > 5: amber banner; P2 > 25: amber; P3 > 50: yellow |
| Drill-down | Click segment → opens ticket-list filtered by that severity, ordered by SLA-burn |
| Owner | Support Shift Lead reviews on shift start |

**Why this matters:** the single most important number is "are there P0s open right now?" — visible from across the room.

### 2.2 Panel 2 — SLA burn-down (per-severity gauges)

| Property | Value |
|---|---|
| Visualisation | 4 gauges (P0, P1, P2, P3); each shows % of open tickets within their first-touch SLA window |
| Refresh | 5 minutes |
| Data source | Ticket-created timestamp + ticket-acked timestamp |
| Calculation | `% acked within SLA = acked_within_target / total_open` per `RB-CUSTOMER-SUPPORT-T-90.md` §4 |
| Thresholds | P0 < 100%: red; P1 < 95%: amber; P2 < 90%: amber; P3 < 90%: yellow |
| Drill-down | Click gauge → list of tickets currently breaching that severity's SLA |
| Owner | Support Shift Lead — must hit 100% on P0 always |

### 2.3 Panel 3 — Top 10 issue categories

| Property | Value |
|---|---|
| Visualisation | Horizontal bar chart, top 10 issue-category tags by ticket count |
| Refresh | Hourly |
| Time window toggle | Rolling 7d / 30d (default 7d) |
| Data source | Ticket-tag aggregation; tags applied at ticket close per RB-CUSTOMER-SUPPORT-T-90 §9 |
| Categories (initial taxonomy — extensible) | `cache-perf`, `byok-config`, `audit-query`, `billing-invoice`, `billing-refund`, `dsr-access`, `dsr-erasure`, `sandbox-quota`, `tier-upgrade`, `auth-mfa`, `cli-install`, `docs-gap`, `feature-request`, `security-questionnaire`, `dpa-request`, `multi-tenant-confusion`, `bazel-integration`, `buck2-integration`, `pants-integration`, `other` |
| Drill-down | Click bar → list of tickets with that tag |
| Owner | Support Lead — review weekly in Friday sync; feed top patterns into Product roadmap monthly |

**Why this matters:** the top 10 list is the leading indicator of doc gaps, UX papercuts, and feature gaps. If `docs-gap` is in the top 3, our docs are the problem; if `byok-config` is, our onboarding flow is.

### 2.4 Panel 4 — Customer NPS sample

| Property | Value |
|---|---|
| Visualisation | Gauge (current NPS score 0–100; -100..+100 range with center marker) + 30-day trend line |
| Refresh | Weekly (Sundays 23:00 UTC) |
| Data source | NPS survey responses sent 24h after ticket CLOSED (per RB-CUSTOMER-SUPPORT-T-90 §9 + SR-RESOLVED template) |
| Calculation | NPS = (% promoters − % detractors) where promoter = 9–10, detractor = 0–6, on 0–10 "would you recommend CoreLink based on your support experience?" |
| Sample size requirement | ≥ 20 responses in rolling 30d for score to render; below threshold shows "insufficient sample" |
| Thresholds | NPS < 0: red; 0–30: amber; 30–50: green; > 50: dark green |
| Drill-down | Click → distribution histogram + verbatim comments (where consented) |
| Owner | Support Lead reviews monthly retro; trend, not single-snapshot |

### 2.5 Panel 5 — Ticket aging heatmap (severity × age bucket)

| Property | Value |
|---|---|
| Visualisation | Heatmap; rows = severity (P0..P3), columns = age buckets (< 1h, 1–4h, 4–24h, 1–3d, 3–7d, > 7d); cell = count |
| Refresh | 60 seconds |
| Data source | Ticket queue; `now() - created_at` per ticket grouped |
| Thresholds | Per-cell color: green if within SLA-target for that severity-age combo; amber if approaching; red if breached |
| Drill-down | Click cell → ticket list |
| Owner | Support Shift Lead — daily standup reviews any red cells |

**Why this matters:** age-bucket vs severity surface tickets that haven't breached yet but will if not actioned. Early-warning signal.

### 2.6 Panel 6 — DSR panel

| Property | Value |
|---|---|
| Visualisation | Mini-table: open DSRs by right-type (Access / Rectification / Erasure / Restriction / Portability / Objection) + days-to-deadline countdown for each |
| Refresh | 5 minutes |
| Data source | `corelink-dsr` API + ticket DSR-tag |
| Highlight | Any DSR with < 5 days to 30-day regulatory deadline: red. Any flagged `dsr:unusual:*`: amber with pending-DPO indicator. |
| Drill-down | Click → DSR ticket detail + link to `RB-DSR-TICKET-TRIAGE.md` |
| Owner | DPO reviews daily; Support Lead reviews weekly |

### 2.7 Panel 7 — Billing panel

| Property | Value |
|---|---|
| Visualisation | Mini-table: open billing tickets, separated by category (subscription-change / refund / dispute / reconciliation-question), with `$ at stake` aggregated |
| Refresh | 15 minutes |
| Data source | Ticket queue (`category:billing` tag) + Stripe-side dispute data |
| Highlight | Total `$ at stake` > $10k: red banner — auto-loop in Finance. Any dispute aging > 2 business days: amber. |
| Drill-down | Click → ticket detail + Stripe-side ref |
| Owner | Finance lead reviews daily; Support Shift Lead loops in immediately on red banner |

### 2.8 Panel 8 — Ticket→incident conversion

| Property | Value |
|---|---|
| Visualisation | Counter (rolling 7d) + trend sparkline (rolling 30d) |
| Refresh | Hourly |
| Data source | Ticket label `converted-to-incident:*` per `RB-CUSTOMER-SUPPORT-T-90.md` §6 |
| Thresholds | > 5 conversions/7d: amber (review trigger for support's first-touch triage calibration); > 10/7d: red (multi-tenant-signal weakness in triage) |
| Drill-down | Click → list of converted tickets + their resulting incident IDs |
| Owner | Support Lead + Engineering Manager L2 — joint review monthly |

### 2.9 Panel 9 — Channel health

| Property | Value |
|---|---|
| Visualisation | Sparkline per channel (`support@`, in-app widget, `billing@`, `dsr@`, Slack Connect) of intake rate (tickets/hour) |
| Refresh | 5 minutes |
| Data source | Ticket queue, `channel:*` tag |
| Anomalies | Auto-flag if any channel's intake rate exceeds rolling 30d mean + 3σ — possible coordinated event or channel-specific outage on customer side |
| Drill-down | Click → channel-filtered ticket list |
| Owner | Support Shift Lead — anomaly alert is a Slack ping |

---

## 3. Data sources + freshness

| Source | Refresh | Freshness SLO |
|---|---|---|
| Ticket queue API | Pull every 60s | < 90s end-to-end |
| `corelink-dsr` API | Pull every 5 min | < 6 min end-to-end |
| Stripe (billing) | Webhook → Postgres + 15-min reconciliation pull | < 16 min end-to-end |
| NPS survey vendor | Pull weekly (Sun 23:00 UTC) | < 7d |
| Audit log (`support_audit` schema) | Direct query (Grafana → Postgres) | live |

---

## 4. Alerting

| Alert | Trigger | Channel | Owner |
|---|---|---|---|
| P0 ticket open AND ack-SLA breached | Panel 2 P0 < 100% | PagerDuty `pd-support-p0` | Support Shift Lead |
| Aging cell turns red on Panel 5 | Heatmap cell breach | Slack `#support-live` | Support Shift Lead |
| DSR within 5d of deadline (Panel 6) | Days-to-deadline < 5 | Slack `#support-live` + DPO email | DPO |
| Billing `$ at stake` > $10k (Panel 7) | Threshold | Slack `#support-live` + Finance email | Finance |
| Conversion rate > 10/7d (Panel 8) | Threshold | Slack `#support-live` weekly digest | Support Lead |
| Channel intake anomaly (Panel 9) | 3σ deviation | Slack `#support-live` | Support Shift Lead |
| NPS drops > 10 points week-over-week (Panel 4) | Threshold | Email to Support Lead + Founder | Support Lead |

All alerts include a direct deep-link to the panel that fired.

---

## 5. Permissions

| Role | Read | Edit panels | Edit alerts |
|---|---|---|---|
| Support T1 / T2 | yes | no | no |
| Support Shift Lead | yes | no (suggest via PR) | no |
| Support Lead | yes | yes | yes |
| VPMkt | yes | no | no |
| VPSec | yes (security tags only) | no | no |
| Founder | yes | yes | yes |
| Finance Lead | yes (billing panel only by default; full on request) | no | no (own billing-alert tuning via PR) |

Dashboard config lives in `infra/grafana/dashboards/support-t-90.json` (Grafana-as-code; PRs reviewed by Support Lead).

---

## 6. Public read-only embed

A **redacted version** of Panels 1, 2, 3 (severity counts only, no customer detail) is suitable for embed in internal-tools / weekly-update emails. The redacted version is generated by `scripts/render-support-dashboard-snapshot.py --redacted` and exported as PNG.

NOT publicly disclosable: any panel showing customer-specific tickets, $-amounts, or DSR detail.

---

## 7. Build / ship plan

| Phase | When | What |
|---|---|---|
| Skeleton | T-7 pre-GA | Panels 1, 2, 5, 6 wired against existing ticket-queue (vendor TBD) + `corelink-dsr` |
| Launch-ready | T-1 pre-GA | All 9 panels live; alerts active; Grafana folder permissions set; embed URL provisioned |
| First-week tuning | T+0..T+7 | Thresholds tuned from real traffic; false-positive alerts silenced + retuned |
| Steady-state | T+30 | NPS panel reaches first sample threshold (≥ 20 responses); top-10 categories taxonomy reviewed + extended |
| First retro | T+90 | Dashboard reviewed; v1.1 spec drafted from observed gaps; this v1.0 sealed |

**Pre-GA gate:** at T-7 in `LAUNCH-CHECKLIST-V2.md`, panels 1, 2, 5 MUST be live (the must-haves for shift coverage on T+0). Panels 4 (NPS), 8 (conversion), 9 (channel health) can come up post-launch.

---

## 8. Cross-references

- `specs/_runbooks/RB-CUSTOMER-SUPPORT-T-90.md` — runbook this dashboard renders
- `specs/_runbooks/RB-DSR-TICKET-TRIAGE.md` — DSR panel feed
- `marketing/launch/SUPPORT-RESPONSE-TEMPLATES.md` — templates referenced in tickets
- `marketing/launch/DAY-1-DASHBOARD-SPEC.md` — war-room launch-day dashboard (sibling, different scope)
- `marketing/launch/METRICS-DASHBOARD.md` — overall product metrics (separate)
- `marketing/launch/STATUS-PAGE-SPEC.md` — public status page (separate outbound channel)
- `marketing/launch/LAUNCH-CHECKLIST-V2.md` — pre-launch gating
- `ROADMAP-TO-GA.md` §8 (Wave R-8 GA Launch)

---

**Fim SUPPORT-DASHBOARD-SPEC.**
