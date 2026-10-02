---
id: "STATUSPAGE-INIT"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "SRE Lead + DevOps (dual)"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "marketing/launch/STATUS-PAGE-SPEC.md"
tags:
  - "marketing"
  - "launch"
  - "status-page"
  - "statuspage-io"
  - "provisioning"
  - "playbook"
  - "wt-r8-1"
---

# Statuspage.io — Provisioning Playbook

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


> **Purpose:** the **concrete, click-by-click** provisioning playbook that takes us from "no account" to "`status.corelink.humangr.com` live with 8 components, PagerDuty hooks armed, lighthouse subscribers imported". This implements `STATUS-PAGE-SPEC.md` §1–§7.
> **Audience:** DevOps (executor) + SRE Lead (approver) + VPSec (severity-mapping signoff).
> **Cross-references:** `STATUS-PAGE-SPEC.md`, `docs/internal/secrets-checklist.md` (row 42), `scripts/statuspage-webhook-receiver.example.yaml`, `STATUSPAGE-SUBSCRIBER-IMPORT.md`, `STATUSPAGE-PRE-LAUNCH-TEST.md`.
> **Hard rule:** **status page URLs in this playbook are placeholders** until DevOps confirms account creation at step 1; do not flip DNS or publish links to `status.corelink.humangr.com` until §3 is complete.

---

## 0. Provider choice (recap)

`STATUS-PAGE-SPEC.md` §1 fixes the decision: **Atlassian Statuspage Business plan** for GA. This playbook executes that choice. The two alternatives we considered are documented here only so a future migration ADR can cite them without re-research:

| Provider | Plan / cost | Why **not chosen** for GA | Re-evaluation trigger |
|---|---|---|---|
| **Atlassian Statuspage** | Business — USD $99–$299/mo (8 components fits the entry tier; sub-component metric overlays are Business-plan-only). | **Chosen.** Native PagerDuty integration, SMS-on-SEV1, RSS/Atom out of the box, SOC 2 export, supports custom domain CNAME. | n/a |
| **Squadcast Status Page** | Bundled in Squadcast incident-management plan (USD $9–$21/user/mo) | We don't use Squadcast for paging; we use PagerDuty. Forces second incident-management stack at the worst moment. Squadcast→Statuspage automation requires a custom Lambda anyway, so we'd pay twice. | If we ever migrate paging from PagerDuty to Squadcast for cost reasons (post-Series-A). |
| **Cachet (self-host)** | $0 software + ~3 weeks engineering + ops. | Status page itself becomes an outage surface. We do not want to learn `helm upgrade cachet` during a SEV1. Migration trigger documented in `STATUS-PAGE-SPEC.md` §1 (post-Q3-2026). | Hit Statuspage.io per-component pricing ceiling, or need per-tenant private status pages. |

**Decision lock.** `STATUS-PAGE-SPEC.md` §1 + this row. No further debate before GA. If migration arises post-GA, file ADR-0035 (Status page sovereignty).

---

## 1. Account setup

### 1.1 Create the Atlassian account

1. DevOps signs into Atlassian under the **`humangr.com/corelink`** organization (Atlassian admin URL: `https://admin.atlassian.com/o/<org-id>`).
2. From the org admin console, click **Add product → Statuspage**.
3. Select **Business** plan. Confirm the **annual billing** option (≈ 17% discount vs. monthly; aligns with `ROADMAP-TO-GA.md` §H-18 budget).
4. Billing contact: `finance@humangr.com`. Technical contact: `sre@humangr.com`.
5. Accept Atlassian DPA (Data Processing Addendum). Cross-link to `docs/legal/vendor-dpa-registry.md`.

> **SOC 2 hook:** the signed DPA PDF must be archived to `specs/_audits/VENDOR-DPA-STATUSPAGE-<date>.pdf` and entered into the vendor registry within 7 days of signing.

### 1.2 Create the page

1. Open `https://manage.statuspage.io` after the Business plan is provisioned (≤ 5 min from signup).
2. **Create new page:**
   - Page name: `CoreLink`
   - Page URL slug: `corelink` (resulting default URL: `corelink.statuspage.io` — used only as a fallback; we will CNAME).
   - Time zone: **UTC** (do not localize; SLO/SLA math is in UTC).
   - Support URL: `https://humangr.com/corelink/support`
   - Notification "from" email: `status@humangr.com`
3. Capture the `page_id` shown in the URL bar after the page is created. This is your `SP_PAGE_ID`. Save as a placeholder for §5 secrets storage.

### 1.3 Team seats

- Add the following Atlassian accounts with **Page Admin** role:
  - `sre-lead@humangr.com`
  - `devops@humangr.com`
  - `vpsec@humangr.com` (read-write for severity gating)
- Add with **Page Editor** role:
  - `vpmkt@humangr.com`
  - `support-lead@humangr.com`
- Add with **Page Viewer** role:
  - `ceo@humangr.com`
  - `cto@humangr.com`
- **Do not** add personal Gmail accounts; only `humangr.com/corelink` SSO-backed accounts. Atlassian SSO is configured via the existing Atlassian Access subscription (`docs/internal/sso-vendor-registry.md`).

---

## 2. Branding

1. **Logo:** upload `apps/docs/static/img/corelink-logo-square-256.png` as page logo (manage page → Page → Style → Logo).
2. **Favicon:** upload `apps/docs/static/img/favicon.ico`.
3. **Colors:** set primary brand color to `#0E7C66` (CoreLink primary). Status indicator colors stay default (green/yellow/orange/red) — `STATUS-PAGE-SPEC.md` §2 fixes this.
4. **Footer:** in Page → Style → Custom HTML/CSS footer, paste:

   ```html
   <p>
     <a href="https://humangr.com/corelink/security.txt">security.txt</a> ·
     <a href="https://humangr.com/corelink/SECURITY.md">Security policy</a> ·
     <a href="https://humangr.com/corelink/trust">Trust center</a>
   </p>
   ```
5. **Tweet button:** disabled (CEO approves all public CoreLink tweets per `STATUS-PAGE-SPEC.md` §8).

---

## 3. Custom domain — `status.corelink.humangr.com`

### 3.1 Statuspage side

1. Page settings → **Domain & SSL** → **Use a custom domain** → enter `status.corelink.humangr.com`.
2. Statuspage shows the required **CNAME target** (e.g. `corelink.statuspage.io.`). Copy it.
3. Click **Enable Let's Encrypt** for automatic SSL certificate issuance.

### 3.2 DNS side (Cloudflare)

1. Open the Cloudflare zone for `humangr.com/corelink`.
2. Add a new DNS record:
   - **Type:** `CNAME`
   - **Name:** `status`
   - **Target:** `corelink.statuspage.io.` (from §3.1 step 2)
   - **Proxy status:** **DNS-only** (gray cloud). Do **not** orange-cloud — Statuspage manages the TLS cert; Cloudflare proxying would intercept SNI and break SSL issuance.
   - **TTL:** 5 min (during launch window; raise to 1h after T+72h).
3. Save.
4. Wait 5–10 min, then return to Statuspage and click **Verify**. Let's Encrypt issues the cert (typically < 5 min).
5. Confirm `https://status.corelink.humangr.com` resolves and shows the (still empty) status page.

### 3.3 Fallback static page

Per `STATUS-PAGE-SPEC.md` §2, pre-stage a static fallback at `https://humangr.com/corelink/status`:

1. Author `apps/docs/static/status/index.html` with the message:
   > "We are checking with our status provider. For real-time updates please follow `@corelinkdev` on X/Twitter or email `status@humangr.com`."
2. Commit + deploy as part of the `wt-r8-1` work-tree.
3. **Validation:** `curl -sI https://humangr.com/corelink/status` returns 200 before T-24h.

---

## 4. Component setup (the 8 components)

Each component below corresponds 1:1 with `STATUS-PAGE-SPEC.md` §3. **Create them in the order shown** — Statuspage preserves display order based on creation order, and the order below matches the order users will see on the public page.

For each component, in Statuspage UI: **Components → Add Component**. Set the fields exactly as shown.

| # | Display name | Description (paste verbatim) | Group | Visible? | Showcase metric? |
|---|---|---|---|---|---|
| **C1** | `API` | "CoreLink control-plane API — REAPI surface, admin endpoints, signup/billing, BYOK key-management." | `Core platform` | Public | p99 latency (linked metric from PagerDuty/Datadog) |
| **C2** | `CAS Read Path` | "Content-addressable storage read serving — GetBlob, BatchGetBlobs, cache hits." | `Core platform` | Public | p99 latency |
| **C3** | `CAS Write Path` | "CAS write serving — UpdateBlob, BatchUpdateBlobs, deduplication, GC backpressure." | `Core platform` | Public | p99 latency |
| **C4** | `BYOK` | "Customer-managed-key envelope encryption against AWS KMS / GCP KMS / Azure Key Vault / HashiCorp Vault." | `Security` | Public | vendor success rate |
| **C5** | `Audit` | "Audit-chain ingest + Merkle-proof issuance; SIEM forwarding (S3 + Splunk-compatible)." | `Security` | Public | ingest lag |
| **C6** | `Billing` | "Stripe webhook ingest, invoice generation, metering aggregation." | `Operations` | Public | webhook success rate |
| **C7** | `Docs` | "corelink-docs.humangr.com Docusaurus site + CDN; includes security.txt + trust center." | `Operations` | Public | availability |
| **C8** | `Admin Console` | "humangr.com/corelink/en/admin/tenants operator console — Clerk-gated; org/tenant/user admin." | `Operations` | Public | availability |

**After each component is created, copy the component ID from the URL** (`https://manage.statuspage.io/pages/<page-id>/components/<component-id>`). Each becomes one of the `SP_COMPONENT_*` placeholders in §5.

> **Hidden / private components.** None at GA per `STATUS-PAGE-SPEC.md` §3. If post-GA we add per-tenant private status visibility, file ADR-0036 and amend this playbook §4.

### 4.1 Component groups

Statuspage UI: **Components → Add Group**. Create 3 groups in this order:

1. `Core platform` (collapsed by default? **No, expanded** at GA so visitors see at-a-glance.)
2. `Security`
3. `Operations`

Then drag-assign C1..C3 into Core platform, C4..C5 into Security, C6..C8 into Operations.

---

## 5. API token provisioning + secret storage

### 5.1 Generate the API key

1. In `https://manage.statuspage.io`, click your avatar → **API Info**.
2. Click **Create API Key**. Name it `corelink-prod-pagerduty-bridge-2026-Q2`. Scope: **Page Admin** (required for incident create/update + component status set + subscriber bulk-add).
3. Copy the generated token (one-time display). This is `SP_API_KEY`.

### 5.2 Generate the webhook signing secret

Statuspage outbound webhooks (page → external subscribers) are signed with a per-page secret:

1. Page → **Webhook subscribers** → **Settings** → **Secret**.
2. Click **Rotate** to generate a fresh secret. Copy it. This is `SP_WEBHOOK_SECRET`.

### 5.3 Get the PagerDuty integration key

For inbound (PagerDuty → Statuspage) — separate from outbound:

1. In PagerDuty, navigate to the `corelink-api-prod` service.
2. **Integrations** tab → **Add an integration** → **Statuspage**.
3. PagerDuty generates an **Integration Key** specific to this PD service + SP page combo. Copy it as `PD_SP_INTEGRATION_KEY_API`.
4. Repeat for `corelink-cas-read-prod`, `corelink-cas-write-prod`, `corelink-byok-prod`, `corelink-audit-prod`, `corelink-billing-prod`, `corelink-docs-prod`, `corelink-admin-prod`. Result: 8 distinct PagerDuty integration keys, one per service.

### 5.4 Secret storage (where each value lives)

All values are placeholders in source control. Real values are stored per `docs/internal/secrets-checklist.md` row 42 (`STATUSPAGE_API_KEY`) plus the additions below. **Run `scripts/secrets-checklist-verify.sh` after this section to confirm matrix drift = 0.**

| Logical name | Env var | Storage tier | Owner | Rotation |
|---|---|---|---|---|
| Statuspage API key | `STATUSPAGE_API_KEY` | `cf-wrangler` (existing row 42) | DevOps | 365d |
| Statuspage page ID | `STATUSPAGE_PAGE_ID` | `cf-wrangler` (new row to append) | DevOps | rotate-on-compromise |
| Statuspage webhook signing secret | `STATUSPAGE_WEBHOOK_SECRET` | `cf-wrangler` (new row) | DevOps | 180d |
| Component IDs (8 vars) | `STATUSPAGE_COMPONENT_<API\|CAS_READ\|CAS_WRITE\|BYOK\|AUDIT\|BILLING\|DOCS\|ADMIN>` | `cf-wrangler` (8 new rows) | DevOps | rotate-on-compromise (treat as config, not secret) |
| PagerDuty SP integration keys (8 vars) | `PD_SP_INTEGRATION_KEY_<service>` | `cf-wrangler` (8 new rows) | DevOps | 180d |

> **Action:** open a PR against `docs/internal/secrets-checklist.md` to append the 17 new rows (1 page-ID + 1 webhook-secret + 8 component-IDs + 7 additional integration keys; row 42 already covers `STATUSPAGE_API_KEY`). Do this **in this same work-tree** if scoped here, or in a follow-up tracked under `wt-r8-1`. The verifier script must remain green.

### 5.5 Wrangler push commands

```bash
# Run once per env (staging, prod):
wrangler secret put STATUSPAGE_API_KEY --env prod
wrangler secret put STATUSPAGE_PAGE_ID --env prod
wrangler secret put STATUSPAGE_WEBHOOK_SECRET --env prod
wrangler secret put STATUSPAGE_COMPONENT_API --env prod
wrangler secret put STATUSPAGE_COMPONENT_CAS_READ --env prod
wrangler secret put STATUSPAGE_COMPONENT_CAS_WRITE --env prod
wrangler secret put STATUSPAGE_COMPONENT_BYOK --env prod
wrangler secret put STATUSPAGE_COMPONENT_AUDIT --env prod
wrangler secret put STATUSPAGE_COMPONENT_BILLING --env prod
wrangler secret put STATUSPAGE_COMPONENT_DOCS --env prod
wrangler secret put STATUSPAGE_COMPONENT_ADMIN --env prod
for svc in api cas_read cas_write byok audit billing docs admin; do
  wrangler secret put "PD_SP_INTEGRATION_KEY_$(echo $svc | tr '[:lower:]' '[:upper:]')" --env prod
done
```

---

## 6. PagerDuty → Statuspage automation hooks

`STATUS-PAGE-SPEC.md` §7 fixes the mapping. This section is the executable subset.

### 6.1 Native PagerDuty integration (preferred — covers SEV2/SEV3 manual + scheduled maintenance)

For each of the 8 PagerDuty services (`corelink-{api,cas-read,cas-write,byok,audit,billing,docs,admin}-prod`):

1. PagerDuty UI → **Service** → **Integrations** → **Statuspage** (already added in §5.3).
2. Edit the integration. Set:
   - **Status page:** `CoreLink`
   - **Component:** the matching SP component (C1..C8).
   - **Severity → status mapping:**
     - `critical` (SEV1) → `major_outage`
     - `error` (SEV2) → `partial_outage`
     - `warning` (SEV3) → `degraded_performance`
   - **Auto-create incident on Statuspage:** **enabled for SEV1 only**.
   - **Auto-resolve incident on Statuspage:** **enabled** (when PD incident resolves and component returns to normal SLO for 15 min, per `STATUS-PAGE-SPEC.md` §9 "Recovery confirmation").
3. **Auto-publish template** for SEV1: paste `CRISIS-COMMS-TEMPLATES.md` §A.1 verbatim.

### 6.2 Custom webhook receiver (for SEV2/SEV3 + cross-page logic + dedup)

The native integration is single-service. For SEV2/SEV3 logic that needs **cross-service correlation** (e.g., "BYOK degraded for one vendor only — open partial outage, not major") and **dedup** (same incident retriggers in PagerDuty within 5 min → single Statuspage incident with updated timeline), we run a small webhook receiver — **spec only at this stage, code follows in a subsequent WI**. The spec is committed to `scripts/statuspage-webhook-receiver.example.yaml`.

### 6.3 Bypass path for "Statuspage publish failed"

Per `STATUS-PAGE-SPEC.md` §7.3: if PagerDuty → Statuspage publish fails 3× (5s / 15s / 45s backoff per §7.2 config), the integration emits a SEV2 internal page-out titled **"Statuspage publish failed"**. SRE-OC then executes the fallback in this order:

1. Manual publish from PagerDuty mobile app (often the same integration retry button works on a fresh network path).
2. Manual login to `manage.statuspage.io` and create the incident by hand using the template from `CRISIS-COMMS-TEMPLATES.md` §A.
3. Update the static fallback page at `humangr.com/corelink/status` (single-line replacement via `apps/docs/static/status/index.html` push + `wrangler pages publish`).
4. Tweet from `@corelinkdev` (CEO or VPMkt — see `STATUS-PAGE-SPEC.md` §8 approval matrix; SEV1 bypasses approval).

---

## 7. Subscriber configuration

### 7.1 Public opt-in surfaces (enable in Statuspage UI)

Page → **Subscriptions** → set the following toggles:

- **Email:** enabled. (Required.)
- **SMS:** enabled. Restrict to SEV1 messages only (page-level filter). **Cost-control hard rule** per `STATUS-PAGE-SPEC.md` §4.2.
- **Webhook subscriptions:** enabled (for power users / paid customers).
- **Slack:** enabled, default channel `#status-updates` in the public CoreLink community Slack (one-way feed).
- **RSS / Atom:** enabled (automatic, no toggle needed).

### 7.2 Pre-subscribed mandatory list

The bulk import of lighthouse customers + internal mandatory subscribers is documented separately in `STATUSPAGE-SUBSCRIBER-IMPORT.md`. **Do not** execute it until §1–§6 are complete and the page is in `Operational` state.

---

## 8. Step-by-step click-through (numbered, end-to-end)

Reference checklist — a DevOps engineer working through this for the first time can follow these 28 steps without context-switching back to the prose above.

1. Atlassian admin → Add product → **Statuspage Business** (annual billing).
2. Sign DPA; archive to `specs/_audits/VENDOR-DPA-STATUSPAGE-<date>.pdf`.
3. Open `https://manage.statuspage.io` → **Create page** → name `CoreLink`, slug `corelink`, TZ `UTC`.
4. Capture `page_id` from URL → write to local secrets-staging file (not committed).
5. Add team seats per §1.3 role table.
6. Upload logo + favicon per §2 step 1–2.
7. Set primary brand color `#0E7C66` per §2 step 3.
8. Paste footer HTML per §2 step 4.
9. Disable Tweet button per §2 step 5.
10. Page → **Domain & SSL** → request custom domain `status.corelink.humangr.com`; copy CNAME target.
11. In Cloudflare DNS, add `CNAME status → corelink.statuspage.io.` **DNS-only (gray cloud)**, TTL 5min.
12. Back in Statuspage, click **Verify** → wait for Let's Encrypt cert (≤ 5 min).
13. Confirm `https://status.corelink.humangr.com` resolves with valid TLS.
14. Pre-stage `apps/docs/static/status/index.html` fallback page (§3.3); deploy.
15. Components → **Add Group** `Core platform`, then `Security`, then `Operations`.
16. Add components C1..C8 in order, with verbatim descriptions per §4 table.
17. Drag-assign components into their groups per §4.1.
18. Capture all 8 `component_id` values from URLs.
19. API Info → **Create API Key** → name `corelink-prod-pagerduty-bridge-2026-Q2` → capture `SP_API_KEY`.
20. Webhook subscribers → Settings → **Rotate Secret** → capture `SP_WEBHOOK_SECRET`.
21. PagerDuty: add Statuspage integration to each of 8 services → capture 8 `PD_SP_INTEGRATION_KEY_*` values.
22. Push all secrets to Cloudflare Workers via `wrangler secret put` (§5.5 batch).
23. Append 17 new rows to `docs/internal/secrets-checklist.md`.
24. Run `scripts/secrets-checklist-verify.sh` — must be **green**.
25. For each PagerDuty integration, configure severity-to-status mapping per §6.1.
26. Paste auto-publish template (`CRISIS-COMMS-TEMPLATES.md` §A.1) into PagerDuty SEV1 integration config.
27. Page → Subscriptions → enable Email, SMS (SEV1-only), Webhook, Slack feed, RSS per §7.1.
28. Run `STATUSPAGE-PRE-LAUNCH-TEST.md` end-to-end. Until that test passes, **do not** import lighthouse subscribers and **do not** announce `status.corelink.humangr.com` externally.

---

## 9. Operational notes (post-provisioning)

- **Key rotation cadence:** `STATUSPAGE_API_KEY` rotates every 365 days; `STATUSPAGE_WEBHOOK_SECRET` and the 8 `PD_SP_INTEGRATION_KEY_*` rotate every 180 days. Owner: DevOps. Tracking: `docs/internal/secrets-checklist.md`.
- **Account audit log export.** Page → **Audit log** → enable monthly export to S3 bucket `corelink-soc2-evidence-prod/statuspage-audit/`. Retention: 7 years (SOC 2 CC8.1).
- **Cost monitoring.** Atlassian invoice posts to `finance@humangr.com` monthly. Track against the budget line `H-18` in `ROADMAP-TO-GA.md`; SMS-fanout cost is the unpredictable variable — review monthly.
- **Migration trigger** (when to re-evaluate Statuspage.io). Per `STATUS-PAGE-SPEC.md` §1: (a) we exceed the per-component or per-incident pricing tier, (b) we need per-tenant private status pages, or (c) we hit Q3 2026 and want to file ADR-0035. None of these trigger pre-GA work.

---

## 10. Cross-references

- `STATUS-PAGE-SPEC.md` — canonical spec (severity mapping, components, subscriber policy).
- `scripts/statuspage-webhook-receiver.example.yaml` — webhook receiver spec for SEV2/SEV3 + dedup.
- `STATUSPAGE-SUBSCRIBER-IMPORT.md` — lighthouse bulk-import + opt-in confirmation flow.
- `STATUSPAGE-PRE-LAUNCH-TEST.md` — T-7d acceptance tests for this provisioning.
- `docs/internal/secrets-checklist.md` row 42 + 17 new rows added in §5.4.
- `CRISIS-COMMS-TEMPLATES.md` §A.1 — SEV1 auto-publish template.
- `LAUNCH-CHECKLIST-V2.md` rows L8 (T-12h banner), L22 (T-0 flip).
