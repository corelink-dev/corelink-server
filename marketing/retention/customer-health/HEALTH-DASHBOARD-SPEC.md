---
id: "RETENTION-HEALTH-DASHBOARD-SPEC"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "CS Lead + VPMkt (dual)"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "ROADMAP-TO-GA.md §R-prep (post-GA retention)"
tags:
  - "marketing"
  - "retention"
  - "dashboard"
  - "spec"
  - "customer-health"
  - "cs-tooling"
  - "nps"
  - "post-ga"
  - "wt-r-prep-customer-health"
---

# Customer Health Dashboard — Internal CS Spec

> **Purpose:** specify the **internal Customer Success dashboard** that visualises per-tenant health scores, NPS trends, declining/improving accounts, and the action queue. This is the single screen the CSM (once hired) keeps open during their workday and the CS Lead reviews each morning.
> **Audience:** CS Lead (owner), CSM(s) once hired (primary consumer), VPMkt (weekly skim), Founder (weekly skim).
> **Companions:**
> - `marketing/launch/SUPPORT-DASHBOARD-SPEC.md` — different surface (support team, ticket ops). Two dashboards co-exist; this one is **retention-focused**.
> - `marketing/launch/DAY-1-DASHBOARD-SPEC.md` — launch war-room only.
> **Hosting:** Grafana, dedicated folder `CS / Retention`, consuming from the tenant datastore + ticket queue + billing service. ⚠️ **The host is not provisioned.** The dotted `grafana.corelink` name is NXDOMAIN and no hosted CoreLink Grafana instance is reachable under `humangr.com` (verified 2026-08-02); the repo has dashboard JSON (`dashboards/grafana/*.json`, internal SLO/on-call) but no instance serving it, and Grafana Cloud appears only as a customer-configurable *export* target (`CORELINK_GRAFANA_*`, `crates/corelink-container/src/routes/otel_layer.rs`). Standing up the instance and fixing the embed URL is part of building this dashboard — this spec deliberately does not print an address that resolves to nothing. Same auth/RBAC as other internal dashboards once it exists.
> **Hard rule:** **action queue panel MUST be in the top half of the screen above the fold**. CSMs have to act, not just observe.

---

## 1. Layout (single-screen, 1920 × 1080 baseline; degrades to 1440 × 900)

```
+----------------------------------------+----------------------------------------+
| 1. Portfolio summary                   | 2. Action queue (TOP-RIGHT, ABOVE FOLD)|
|    [scorecard: total tenants,         |    [list: highest-risk untouched     |
|     by tier, deltas vs 7d/30d]        |     in last 7d; max 12 rows]          |
+----------------------------------------+----------------------------------------+
| 3. Top declining (7d)                  | 4. Top improving (7d)                  |
|    [table: 10 worst score deltas]      |    [table: 10 best score deltas]       |
+----------------------------------------+----------------------------------------+
| 5. Score distribution histogram                                                |
|    [stacked bars: Healthy/At-Risk/Critical counts vs prior 30d snapshot]       |
+--------------------------------------------------------------------------------+
| 6. NPS trend (rolling 90d, by trigger type)                                    |
|    [line chart: aggregate NPS + detractor count]                               |
+----------------------------------------+----------------------------------------+
| 7. Per-tenant drilldown (search)       | 8. CSM workload                        |
|    [search box → tenant detail panel]  |    [per-CSM: assigned + open actions]  |
+----------------------------------------+----------------------------------------+
```

When narrower than 1440 × 900, panels 3+4 collapse into a single tabbed view; panels 7+8 stack below 6.

---

## 2. Panel 1 — Portfolio summary

**Source:** `cs.health_score_audit` (latest row per tenant) joined to `cs.tenants`.

**Scorecard tiles (4 across):**

| Tile | Value | Sub-text |
|---|---|---|
| Total active tenants | `count(distinct tenant_id) where status='active'` | Δ vs 7d ago, Δ vs 30d ago |
| Healthy | `count where tier='Healthy'` + % | Δ count vs 7d ago |
| At-Risk | `count where tier='At-Risk'` + % | Δ count vs 7d ago, RED if Δ > +5 |
| Critical | `count where tier='Critical'` + % | Δ count vs 7d ago, RED if any Critical |

**Refresh:** every 5 min (cached). Underlying score table updates nightly at 02:00 UTC; cache invalidates after the nightly job completes.

**Alerts feed to scorecard tile borders:**
- Critical-count rising ≥ 2 in 7d → red border + Slack `#cs-alerts`.
- At-Risk-count rising ≥ 5 in 7d → amber border.

---

## 3. Panel 2 — Action queue (load-bearing)

**This is the single most important panel.** CSM workflow: open dashboard, scan action queue top-down, act.

**Source:** `cs.health_score_audit` LEFT JOIN `cs.tenant_touches` (where `touch_at > now() - 7d`).

**Row inclusion criteria:**

```sql
SELECT tenant_id, score, tier, days_since_last_touch, primary_csm, ...
FROM cs.health_score_audit_latest
LEFT JOIN cs.tenant_touches USING (tenant_id)
WHERE tier IN ('At-Risk', 'Critical')
  AND COALESCE(days_since_last_touch, 999) >= 7
ORDER BY
  CASE tier WHEN 'Critical' THEN 0 ELSE 1 END,
  score ASC,
  days_since_last_touch DESC
LIMIT 12;
```

**Row columns:** `tenant` | `tier` | `score` | `Δ7d` | `Δ30d` | `last touch` | `assigned CSM` | `[Action button]`

**Action button** opens panel 7 (per-tenant drilldown) AND logs the click in `cs.dashboard_action_audit`. This means we can measure **CSM follow-through** — how often action-queue rows result in a touch within 24h.

**Visual treatment:**
- Critical rows: full-width red left border, bold tenant name.
- At-Risk rows: amber left border, regular weight.
- Hover over `last touch` shows the actual touch type (CSM call, ticket reply, NPS reach-out) and timestamp.

**What "touch" means:**
- CSM-initiated email, call, or Slack message (logged in `cs.tenant_touches`).
- NOT: automated email, support ticket reply by Tier-1.
- A ticket escalated to CSM and resolved by CSM = counts.

---

## 4. Panel 3 — Top declining (7d)

10-row table sorted by score delta over 7 days (most negative first).

| Column | Notes |
|---|---|
| Tenant | Linkifies to drilldown |
| Score (today) | |
| Score (7d ago) | |
| Δ | RED if ≤ -15 (matches `HEALTH-SCORE-METHODOLOGY.md` §5.2 alert threshold) |
| Driving input | Top 1 of the 6 inputs by contribution to the drop |
| Last touch | Same semantics as Panel 2 |

**Refresh:** 5 min cache.

**Drill-down on row click:** opens Panel 7 scoped to that tenant with the 6-input timeline pre-loaded.

---

## 5. Panel 4 — Top improving (7d)

10-row table sorted by score delta over 7 days (most positive first).

Same columns as Panel 3. Purpose: CSM celebration + identify upsell / case-study / promoter candidates. Improving tenants with NPS ≥ 9 are highlighted for VPMkt's case-study pipeline.

---

## 6. Panel 5 — Score distribution histogram

Stacked bar chart. X-axis: 10-point score buckets (0–9, 10–19, …, 90–100). Y-axis: tenant count.

- **Today** bars (full opacity)
- **30 days ago** bars (semi-transparent overlay)

Colour by tier: Critical (red, 0–39), At-Risk (amber, 40–69), Healthy (green, 70–100).

**Goal:** spot distribution shifts. If a customer chunk has moved left, the histogram makes it obvious before individual-tenant alerts catch it.

---

## 7. Panel 6 — NPS trend (rolling 90d)

Source: `cs.nps_response` joined to `cs.nps_send_audit`.

**Two overlaid series:**
1. **Aggregate NPS** (line, left axis) — standard NPS formula `(% promoters - % detractors)` over rolling 90d window.
2. **Detractor count** (bars, right axis) — count of detractors in same window.

Optional facet selector: filter by `trigger_type` (Day 7, D+30, quarterly, post-incident, pre-renewal). Default: all.

Click on a date opens that day's response list (in a side panel).

---

## 8. Panel 7 — Per-tenant drilldown

Triggered by Panel 2/3/4/5 row click or Panel 7 search box.

### 8.1 Tenant header

```
{tenant_name}              [Tier: Critical]   [Score: 32 (Δ -18 in 7d)]
{tenant_id}                                   [Assigned CSM: {name}]
                                              [Plan: Team / Enterprise BYOK]
                                              [Created: {date} ({days_old}d old)]
```

### 8.2 Six-input timeline

Six small sparklines (one per input from `HEALTH-SCORE-METHODOLOGY.md` §2), last 90 days each. Each sparkline labelled with current value + weight contribution to today's score.

```
Usage trajectory (U)   ▂▃▅▆▆▇▇▆▆▅▄▃▂▂  current: 23 / weight 30% → -8 pts
Feature adoption (B)   ▇▇▇▇▇▇▇▇▇▇▆▆▅▅  current: 60 / weight 20% → +12 pts
Support friction (S)   ▁▁▁▂▃▅▇▇▇▇▆▅▅▅  current: 25 / weight 20% → -10 pts
Payment (P)            ▇▇▇▇▇▇▇▇▇▇▇▇▇▇  current: 100 / weight 15% → +15 pts
Engagement (E)         ▅▅▅▄▄▃▃▃▂▂▁▁▁▁  current: 15 / weight 10% → -3.5 pts
NPS (N)                ─ ─ ─ ─ ─ ─ ─ ─  current: missing / weight redistributed
```

### 8.3 Recent activity (last 30 days)

| Time | Event | Source |
|---|---|---|
| 2026-MM-DD HH:MM | NPS response: 4 (detractor) — "Slow GET latency on EU traffic" | Trigger 3 quarterly |
| 2026-MM-DD HH:MM | Ticket P2 opened: "503 errors on CAS PUT" | Support T1 |
| 2026-MM-DD HH:MM | CSM call: "renewal concerns, EU latency" | CSM {name} |
| ... | | |

Max 50 rows; paginated. Sortable; filterable by event type.

### 8.4 Recommended actions

Computed from the active tier + driving inputs:

```
🔴 Critical tier — action within 48h required (per CSM-PLAYBOOK.md §3.3)
  • Top driver: Support friction. Review 3 open P2 tickets, escalate to L2.
  • Second driver: Engagement collapsed (2 humans → 0 in 14d). Investigate.
  • Recommended outreach: Founder + CSM Lead joint call.
```

The "recommended actions" string is **template-driven** from `cs.action_templates` keyed by `(tier, top_driver_input)`. Templates are versioned and reviewed by CS Lead quarterly.

---

## 9. Panel 8 — CSM workload

Per-assigned-CSM tile:

| CSM | Tenants assigned | At-Risk | Critical | Open actions | Avg score (portfolio) | Touches last 7d |
|---|---:|---:|---:|---:|---:|---:|
| {name} | 18 | 3 | 1 | 4 | 71 | 12 |
| (unassigned) | 14 | 2 | 0 | 0 | 78 | n/a |

**Goal:** CS Lead spots overloaded CSMs OR neglected portfolios. Defaults sort by `open actions` desc.

Click `(unassigned)` row to bulk-assign.

---

## 10. Data sources and refresh

| Source | Refresh cadence | Notes |
|---|---|---|
| `cs.health_score_audit` | Nightly 02:00 UTC; dashboard cache 5 min | Output of nightly score-compute job |
| `cs.nps_send_audit` + `cs.nps_response` | Real-time via Postgres replica | 5 min dashboard cache |
| `cs.tenants` | Real-time via Postgres replica | 5 min cache |
| `cs.tenant_touches` | Real-time (written by CRM-side integration) | 5 min cache |
| `support_tickets` view | Read from ticket queue API; 10 min cache | Used in Panel 7.3 |
| `billing.invoices` | Real-time | Used in §2.3.4 P input + Panel 7 |

**Dashboard SLA:** First-load p99 < 3s. Panel refresh p99 < 1s. Drilldown open p99 < 800ms.

---

## 11. Access control

| Role | Access |
|---|---|
| CSM | Full dashboard for tenants where `assigned_csm = self` OR `assigned_csm IS NULL`. Search box searches all tenants but drilldown is read-only for non-assigned. |
| CS Lead | Full dashboard for all tenants. |
| VPMkt | Read-only, all tenants, all panels. |
| Founder | Read-only, all tenants. |
| Engineering | Read-only Panels 1, 5, 6 (aggregate only). No per-tenant drilldown without explicit grant. |

Audit log: every drilldown view of a tenant is logged in `cs.dashboard_view_audit` (viewer, tenant_id, viewed_at). Retention 18 months.

---

## 12. Alerts

| Alert | Source | Channel | Severity |
|---|---|---|---|
| `health.critical.new` | Tenant transitions to Critical | Slack `#cs-alerts` + email CS Lead | P1 |
| `health.score.large_drop` | Day-over-day drop ≥ 15 | Slack `#cs-alerts` | P2 |
| `health.atrisk.surge` | At-Risk count ↑ ≥ 5 in 7d | Slack `#cs-alerts` + email CS Lead | P2 |
| `health.action_queue.untouched` | Critical tenant in action queue > 48h with no touch | Slack `#cs-alerts` + email CSM + CS Lead | P1 |
| `nps.detractor.posted` | New detractor response (score 0–4) | Slack `#cs-alerts` | P2 |
| `nps.detractor.incident` | New detractor on post-incident trigger | Slack `#cs-alerts` + Founder email | P1 |
| `health.compute.failed` | Nightly job failed | PagerDuty (Eng) + Slack `#cs-alerts` | P1 |

Alert configs live in `grafana/provisioning/alerting/cs-retention.yaml`. Owned by CS Lead + Eng.

---

## 13. Export and reporting

**Weekly Founder digest (auto-generated, Mondays 09:00):**

```
Subject: CoreLink retention week — {ISO_week}

Portfolio: 47 active tenants (Δ +2 vs last week)
  Healthy: 39 (83%)  At-Risk: 7 (15%)  Critical: 1 (2%)

This week:
  • 2 tenants moved Healthy → At-Risk
  • 1 tenant moved At-Risk → Critical (acme-corp)
  • 1 tenant moved At-Risk → Healthy (recovery)
  • 0 churn events

Action queue (untouched > 7d): 3 tenants
  - acme-corp (Critical, 32, -18 in 7d)
  - blip-co (At-Risk, 58, -8 in 7d)
  - clover-eng (At-Risk, 62, -5 in 7d)

NPS aggregate (rolling 90d): +27 (Δ +3 WoW)
  Detractors this week: 2 (1 post-incident, 1 quarterly)

Full dashboard: <Grafana host not provisioned — see Hosting note above>
```

**Quarterly board export:** CSV of all tenant scores, tiers, churn events, NPS trends. Owned by VPMkt; emailed to board ≤ 5 business days after quarter end.

---

## 14. Quality gates and DoD

| Gate | Rule |
|---|---|
| Coverage | 100% of active tenants have a daily score row in `cs.health_score_audit` (or an `error` row, see §`HEALTH-SCORE-METHODOLOGY.md` §7 failure mode) |
| Freshness | Dashboard last-update timestamp ≤ 12h old (visible top-right; red if exceeded) |
| Drilldown completeness | Every tenant in panels 2/3/4/8 has a working drilldown (no broken IDs) |
| Action follow-through | ≥ 80% of action-queue rows result in a touch within 48h (measured monthly; CS Lead KPI) |

---

## 15. Cross-references

- **`HEALTH-SCORE-METHODOLOGY.md`** — produces the score this dashboard reads.
- **`NPS-SURVEY-SCHEDULE.md`** — produces the NPS responses this dashboard trends.
- **`CSM-PLAYBOOK.md`** — defines the actions CSMs take from this dashboard.
- **`CHURN-RISK-SIGNALS.md`** (sibling worktree): the raw-signal catalogue; this dashboard surfaces them via the score and per-tenant drilldown.
- **`marketing/launch/SUPPORT-DASHBOARD-SPEC.md`** — adjacent operational dashboard for ticket ops; complementary, not overlapping.
- **`specs/_runbooks/RB-CUSTOMER-SUPPORT-T-90.md`** — feeds support ticket data via §10 metrics.
- **`marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`** — lighthouse customers visible in this dashboard with `plan = lighthouse` flag; CSM workflow same.
- **`ROADMAP-TO-GA.md`** §R-prep — post-GA retention preparation package.

---

**Fim HEALTH-DASHBOARD-SPEC.**
