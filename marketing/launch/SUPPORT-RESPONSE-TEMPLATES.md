---
id: "SUPPORT-RESPONSE-TEMPLATES"
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
  - "templates"
  - "response"
  - "canonical"
  - "p0"
  - "p1"
  - "p2"
  - "p3"
  - "dsr"
  - "billing"
  - "wt-r-prep-support-runbook"
---

# Support Response Templates — 15 Canonical Responses

> **Audience:** Support T1 + T2 agents, CS engineers (lighthouse), Finance (billing escalations), VPSec (security questionnaire fan-out).
> **Companion runbook:** `specs/_runbooks/RB-CUSTOMER-SUPPORT-T-90.md` (workflow + SLAs).
> **Hard rule:** **templates are starting points, not final text.** Always personalize the `{{tenant_context}}` block. Never send a template raw without at least one sentence of human-written context.
> **Hard rule:** **no template fabricates facts.** Where the agent does not know, the template says "we don't know yet" — that is correct content, not a gap to fill.
> **Sign-off:** every customer-facing template ends with `— {{agent_first_name}}, CoreLink Support` (T+0..T+30 pre-GA shared-alias-free policy per RB-CUSTOMER-SUPPORT-T-90 §7.1).

---

## Index — 15 templates

| ID | Name | Used in workflow stage | Severity |
|---|---|---|---|
| 01 | `SR-FIRST-TOUCH-P0` | First-touch acknowledgment | P0 |
| 02 | `SR-FIRST-TOUCH-P1` | First-touch acknowledgment | P1 |
| 03 | `SR-FIRST-TOUCH-P2` | First-touch acknowledgment | P2 |
| 04 | `SR-FIRST-TOUCH-P3` | First-touch acknowledgment | P3 |
| 05 | `SR-INVESTIGATING-HOLD-P0` | 15-min cadence hold while investigating | P0 |
| 06 | `SR-INVESTIGATING-HOLD-P1` | 1-hour cadence hold while investigating | P1 |
| 07 | `SR-ROOT-CAUSE` | Pre-fix root-cause notification | P0 / P1 |
| 08 | `SR-FIX-DEPLOYED` | Post-deploy notification | P0 / P1 |
| 09 | `SR-RESOLVED` | Confirmed resolved close | all |
| 10 | `SR-DSR-ACK` | DSR-specific first-touch (any DSR right) | DSR (any P) |
| 11 | `SR-DSR-COMPLETED` | DSR-specific resolution (per DSR right type) | DSR (any P) |
| 12 | `SR-BILLING-CHANGE` | Subscription change confirmation | P2/P3 |
| 13 | `SR-BILLING-REFUND` | Refund issued | P0/P1/P2 |
| 14 | `SR-BILLING-DISPUTE` | Dispute / chargeback acknowledgment | P0/P1 |
| 15 | `SR-SANDBOX-EXPIRY` | Sandbox expiry / tier upgrade prompt | P3 |

> **Auxiliary template (referenced by RB-CUSTOMER-SUPPORT-T-90 §4.2 but not part of the canonical 15):** `SR-BREACH-APOLOGY` — used internally when an SLA breach occurs; lives in §Appendix A.

---

## 01. `SR-FIRST-TOUCH-P0` — Production-down acknowledgment

**When:** within 15 minutes of P0 ticket creation. **Audience:** any tenant. **Variables:** `{{customer_first_name}}`, `{{ticket_id}}`, `{{tenant_context}}`, `{{agent_first_name}}`.

```
Subject: [CoreLink] {{ticket_id}} — We have your report, on it now

Hi {{customer_first_name}},

We've received your report and treated it as P0 — production-down. Our
on-call engineer is engaged and we're pulling tenant-scoped telemetry
right now.

{{tenant_context — one sentence summarizing what you understand the
customer is seeing, NO speculation about cause}}

What happens next:
- You'll hear from us again within 15 minutes with an update — even if
  the update is "still investigating, no new info." We don't go quiet.
- We will attempt a first fix within 1 hour. If we can't, you'll know
  why.
- If we find this is affecting other tenants, we'll convert to an
  incident and post to https://hugrl.betteruptime.com.

If you need to reach a human immediately, reply to this email with
"escalate" and our Support Lead will phone you.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 02. `SR-FIRST-TOUCH-P1` — Impaired-capability acknowledgment

**When:** within 1h of P1 ticket creation.

```
Subject: [CoreLink] {{ticket_id}} — We see your report on {{component}}

Hi {{customer_first_name}},

Thanks for the report. We've classified this as P1 — a capability is
impaired for your tenant — and assigned it to me.

{{tenant_context — what you understand the customer is seeing,
including any data they provided (timestamps, error codes, tenant id)}}

What happens next:
- I'll dig into tenant-scoped telemetry and reply with a substantive
  update within 4 hours.
- If I find this matches a multi-tenant pattern, I'll loop in
  engineering and we may convert to an incident — you'll be the first
  to know.
- If I find this is local to your tenant, we'll work through it
  together. Plan to be reachable for clarifying questions; I'll keep
  the loop tight.

In the meantime: if you have additional context (request IDs, screen
recordings, log excerpts), reply here — every bit speeds the diagnosis.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 03. `SR-FIRST-TOUCH-P2` — Limited / bounded annoyance acknowledgment

**When:** within 4 business hours of P2 ticket creation.

```
Subject: [CoreLink] {{ticket_id}} — Got your message, here's the plan

Hi {{customer_first_name}},

Thanks for writing in. I've opened ticket {{ticket_id}} and classified
this as P2 — your CoreLink is functional but constrained in some way.

{{tenant_context — restate what you understand the limitation is}}

What happens next:
- I'll send a substantive response within 24 hours — either an answer,
  a workaround, or a scoped commitment with a date.
- If this turns out to be a feature gap or a doc gap, I'll route it to
  the right team and keep you in the loop.

If anything changes on your side that bumps the urgency (production
impact, deadline pressure), reply here and we'll re-triage.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 04. `SR-FIRST-TOUCH-P3` — Question / feature-request acknowledgment

**When:** within 24 business hours of P3 ticket creation. Often combined with a substantive answer in a single touch.

```
Subject: [CoreLink] {{ticket_id}} — Thanks for the question

Hi {{customer_first_name}},

Thanks for reaching out. {{Optional: one-line direct answer if obvious.
Never send a support claim without checking the current product status; an
instructional counterexample follows:
e.g., "Yes, we support Pants 2.20 — see docs link below."}}

{{tenant_context — paraphrase the question + any caveats}}

I'll send a fuller response within 2 business days. If this is more
urgent than P3 (you have a deadline, this is blocking a decision),
just reply with "urgent" and I'll re-triage.

Useful links while you wait:
- Docs: https://corelink-docs.humangr.com
- Status: https://hugrl.betteruptime.com
- {{Optional context-specific link}}

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 05. `SR-INVESTIGATING-HOLD-P0` — Every-15-min hold

**When:** every 15 minutes while a P0 is in `INVESTIGATING` state and we have no new info OR new info that doesn't change the resolution path. **Hard rule:** send this on cadence even when nothing has changed.

```
Subject: [CoreLink] {{ticket_id}} — Update at {{HH:MM_UTC}} UTC

Hi {{customer_first_name}},

Quick update on {{ticket_id}}.

Status: still investigating.
Time elapsed: {{minutes_since_ack}} min.
What we know: {{one_sentence_factual; if nothing new since last
update, say "no new findings since {{last_update}} — investigation
continuing on {{specific_path}}"}}.
What we don't know: {{one_sentence_factual}}.
Next attempted action: {{one_sentence}}.

Next update from me by {{HH:MM_UTC + 15min}} UTC.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 06. `SR-INVESTIGATING-HOLD-P1` — Hourly hold

**When:** every 1 hour while a P1 is in `INVESTIGATING` state.

```
Subject: [CoreLink] {{ticket_id}} — Hourly update {{HH:MM_UTC}} UTC

Hi {{customer_first_name}},

Hourly check-in on {{ticket_id}}.

Status: {{INVESTIGATING / AWAITING-FIX / waiting-for-data-from-you}}.
What changed in the past hour: {{one_to_three_bullets; if nothing,
"no material change — we're following {{specific_diagnostic_path}}"}}.
Current hypothesis: {{one_sentence; if none, "no working hypothesis
yet — gathering more telemetry"}}.

If you can: {{customer_action_if_any — e.g., "share the full Bazel
build log from your most recent failing run" / nothing requested}}.

Next update by {{HH:MM_UTC + 1h}} UTC.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 07. `SR-ROOT-CAUSE` — Pre-fix root-cause notification

**When:** as soon as engineering has high confidence in the cause, BEFORE the fix is deployed. Sent on P0 and P1; optional on P2 (often combined with `SR-RESOLVED`).

```
Subject: [CoreLink] {{ticket_id}} — Root cause identified

Hi {{customer_first_name}},

We've identified what's causing {{symptom}}.

Root cause (plain English, no jargon):
{{one_to_three_sentences. Be specific. No vendor blame unless
Legal-cleared per CRISIS-COMMS-TEMPLATES Hard rule 5. If a vendor
dependency contributed, write "a dependency we rely on" without
naming.}}

Impact on your tenant:
{{tenant_specific_impact}}

Mitigation in progress:
{{what_we_are_doing_now. Include ETA if you have one; if not, say
"working on it, no ETA yet but I'll send one as soon as I have it"}}

What happens next:
- I'll send another update when the fix is deployed.
- After resolution, we'll publish a public retrospective within 14
  days for any incident-level event ({{include only if this converted
  to an incident; otherwise omit}}).
- If you have follow-up questions about the cause, this thread is the
  place — reply any time.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 08. `SR-FIX-DEPLOYED` — Post-deploy notification

**When:** immediately after the fix is deployed and CoreLink-side validation passes. Customer has NOT yet confirmed on their side.

```
Subject: [CoreLink] {{ticket_id}} — Fix deployed, please verify

Hi {{customer_first_name}},

The fix for {{symptom}} has been deployed as of {{deploy_timestamp_utc}} UTC.

What we validated on our side:
- {{check_1 — e.g., "cache PUT/GET round-trips passing on synthetic
  traffic for your region"}}
- {{check_2 — e.g., "p99 latency back below 300ms target"}}
- {{check_3 — only include checks that actually ran; do not pad}}

What we'd like you to verify:
- {{specific_customer_action — e.g., "re-run your failing CI job and
  confirm cache hits resume"}}
- {{specific_customer_action — e.g., "confirm the status page at
  https://hugrl.betteruptime.com shows the affected component as
  Operational"}}

Once you confirm on your side, I'll close the ticket as resolved. If
the issue persists or recurs, reply here immediately — we'll reopen
and re-page if needed.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
Deploy ref: {{deploy_id_or_commit_sha}}
```

---

## 09. `SR-RESOLVED` — Confirmed resolved close

**When:** customer confirms OR 48h of no-reply after `SR-FIX-DEPLOYED` (with auto-close-on-no-reply policy). Sent before transition to CLOSED state.

```
Subject: [CoreLink] {{ticket_id}} — Resolved

Hi {{customer_first_name}},

Marking {{ticket_id}} as resolved as of {{resolved_timestamp_utc}} UTC.

Summary:
- Reported: {{when_ticket_opened}}
- Symptom: {{one_line_symptom}}
- Root cause: {{one_line_cause; if "unknown, did not recur" — say
  that explicitly}}
- Fix: {{one_line_fix; if "no fix needed, resolved by retry / customer
  config change / external dependency" — say that}}
- Total time: {{duration}}

A quick 30-second survey if you have a moment (optional but
genuinely helpful): {{nps_survey_link}}.

This ticket auto-closes in 72 hours. If anything recurs within 7 days,
reply to this thread and we'll reopen the same ticket — you won't be
re-asked to re-explain.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 10. `SR-DSR-ACK` — DSR-specific first-touch (any right type)

**When:** within 24h of any DSR request landing in `dsr@humangr.com` or via in-app DSR form. Routes via `RB-DSR-TICKET-TRIAGE.md`. **Hard rule:** 30-day regulatory clock starts at receipt — `{{received_at}}` is canonical.

```
Subject: [CoreLink] DSR request received — {{dsr_id}}

Dear {{customer_name}},

We received your data subject request on {{received_at}} UTC,
identifier {{dsr_id}}.

The right you are exercising: {{right_type — one of: Access (Art. 15
GDPR / Art. 18 LGPD), Rectification (Art. 16 / Art. 18.III),
Erasure (Art. 17 / Art. 18.VI), Restriction (Art. 18 / Art. 18.IV),
Portability (Art. 20 / Art. 18.V), Objection (Art. 21 / Art. 18.IV)}}.

What happens next:
- We are required by law to respond within 30 days of receipt
  ({{deadline_date — receipt + 30 calendar days}}). We typically
  respond within 5 business days.
- We will verify your identity before processing. You will receive a
  separate verification step within 48 hours.
- If your request is unusual in scope or requires legal review, we
  may extend the response window by up to 60 additional days under
  GDPR Art. 12(3) / LGPD Art. 19; you will be notified before any
  extension is invoked.

If you did not submit this request, reply to this email immediately
with "did not submit" — we will pause processing and investigate.

— {{agent_first_name}}, CoreLink Privacy Support
DSR ID: {{dsr_id}}
Contact: dsr@humangr.com
```

---

## 11. `SR-DSR-COMPLETED` — DSR resolution (per right type)

**When:** DSR processing is complete. Use the right-specific block.

```
Subject: [CoreLink] DSR request completed — {{dsr_id}}

Dear {{customer_name}},

Your data subject request {{dsr_id}}, exercising the right of
{{right_type}}, has been completed as of {{completed_at}} UTC.

[Block for ACCESS] — choose this block if right_type == Access
Attached: a portable export of all personal data we process about
you, in JSON format. The export includes account data, audit-chain
references, BYOK envelope references (encrypted; we do not include
key material), and aggregated metering records. Categories of data
are documented in §2 of our DPA.

[Block for RECTIFICATION] — choose this block if right_type == Rectification
The following fields were corrected:
- {{field_1}}: {{old_value}} → {{new_value}}
- {{field_2}}: {{old_value}} → {{new_value}}
Audit-chain entry: {{audit_event_id}}.

[Block for ERASURE] — choose this block if right_type == Erasure
We have erased all personal data associated with your account from
production systems as of {{completed_at}} UTC. Audit-chain entries
referencing your account are anonymized (regulatory retention applies
per LGPD Art. 16 / GDPR Art. 17(3)); the customer identifier is
replaced with a pseudonymous token. Cached content-addressable
blobs were evicted within 24 hours of your request per our DPA. See
attached erasure certificate.

[Block for RESTRICTION] — choose this block if right_type == Restriction
Processing of your data has been restricted to storage-only as of
{{completed_at}} UTC. We will not perform further processing without
your consent or legal basis under GDPR Art. 18(2) / LGPD Art. 18.IV.

[Block for PORTABILITY] — choose this block if right_type == Portability
Attached: your data in machine-readable JSON format suitable for
transfer to another controller. The export covers the categories
specified in your request {{requested_scope}}.

[Block for OBJECTION] — choose this block if right_type == Objection
We have noted your objection to processing for {{objected_purpose}}.
Effective {{completed_at}} UTC, we have ceased that processing.

If anything in this response is unclear or incomplete, reply within
30 days and we will treat it as a continuation of the same request.
You also have the right to lodge a complaint with your supervisory
authority (ANPD for Brazil; lead EU DPA per One-Stop-Shop for EEA;
state attorneys general for US).

— {{dpo_name}}, Data Protection Officer
DSR ID: {{dsr_id}}
```

---

## 12. `SR-BILLING-CHANGE` — Subscription change confirmation

**When:** customer requests a subscription tier change (upgrade, downgrade, plan switch). Sent after Stripe-side change is confirmed.

```
Subject: [CoreLink] Subscription change confirmed — {{customer_name}}

Hi {{customer_first_name}},

Confirmed: your CoreLink subscription has been updated.

Previous plan: {{old_plan}} ({{old_price}}/mo)
New plan: {{new_plan}} ({{new_price}}/mo)
Effective: {{effective_date}}
Proration: {{prorated_amount; if applicable — "we credited
${{credit}} to your next invoice" / "we charged ${{prorate_charge}}
prorated for this billing cycle"}}

What changes:
- {{quota / feature change 1 — e.g., "Sandbox cap raised from 100GB
  to 1TB"}}
- {{quota / feature change 2 — e.g., "BYOK enabled; KMS configuration
  walkthrough scheduled with your CS engineer"}}

If you didn't request this change, reply immediately and we'll
investigate as a potential account-security issue.

Stripe receipt: {{stripe_invoice_url}}

— {{agent_first_name}}, CoreLink Support
```

---

## 13. `SR-BILLING-REFUND` — Refund issued

**When:** refund processed for a billing error, overcharge, or goodwill credit. **Posture:** refund-first per `CRISIS-COMMS-TEMPLATES.md` Scenario C.

```
Subject: [CoreLink] Refund issued — {{ticket_id}}

Hi {{customer_first_name}},

We issued a refund of ${{refund_amount}} to your account
{{stripe_account_id_masked}} as of {{refund_timestamp_utc}} UTC.

What happened:
{{one_to_three_sentences_plain_english. No jargon. If this is a
goodwill credit (not error-driven), say so explicitly: "this is a
goodwill credit for the inconvenience caused by {{ticket_context}}."}}

What you should expect:
- The refund will appear on your payment method within 5–10 business
  days, per Stripe's standard timeline.
- No action required from you.
- If your next invoice shows an issue related to this refund, reply
  here and we'll resolve immediately.

What we changed (if applicable):
{{one_sentence_on_guardrail_or_fix; if none, omit this paragraph}}

We're sorry. Billing should never be a surprise.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
Stripe refund ref: {{stripe_refund_id}}
```

---

## 14. `SR-BILLING-DISPUTE` — Dispute / chargeback acknowledgment

**When:** customer initiates a billing dispute OR Stripe notifies us of a chargeback. **Hard rule:** never argue billing on first touch; gather facts, route to Finance.

```
Subject: [CoreLink] Billing dispute received — {{ticket_id}}

Hi {{customer_first_name}},

We received your dispute regarding {{disputed_amount}} on
{{invoice_date}}.

What we're doing:
- I've pulled the underlying metering records and invoice line items
  for the disputed period.
- Our Finance team will review the dispute within 1 business day.
- A senior team member will respond with a detailed accounting of the
  charge — line items, metering aggregates, applicable plan terms —
  within 2 business days.

What you should know:
- If our review confirms the charge is incorrect, we will refund
  immediately (per our refund-first policy) and walk you through
  what we changed.
- If our review confirms the charge is correct, we will explain it
  in plain English with the underlying data attached. If you still
  disagree, we will escalate to our Founder for final review.
- A Stripe chargeback (if filed) creates a separate timeline outside
  our control; we recommend pausing chargeback action while we
  review — but you're not required to.

We take billing disputes seriously. Plan to hear from us within 2
business days.

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## 15. `SR-SANDBOX-EXPIRY` — Sandbox expiry / tier upgrade prompt

**When:** sandbox/trial customer is within 7 days of expiry OR has hit a sandbox cap (storage, requests, retention). Proactive, not reactive.

```
Subject: [CoreLink] Your sandbox expires in {{days_remaining}} days

Hi {{customer_first_name}},

A heads-up: your CoreLink sandbox account will expire on
{{expiry_date}} ({{days_remaining}} days from today).

What expires:
- Read/write access to your sandbox tenant ({{tenant_id}}).
- Cached blob retention rolls off 24 hours after expiry per our
  sandbox terms.
- Audit-chain references remain queryable for 30 days post-expiry
  (legal retention) but are otherwise read-only.

Your options:

1. **Upgrade to Team tier** — keep everything, no migration needed.
   Pricing: ${{team_tier_price}}/mo flat or usage-based per
   https://corelink-docs.humangr.com/pricing. Upgrade in-app or reply here.

2. **Upgrade to Enterprise (BYOK)** — best fit if you need
   customer-managed keys, dedicated capacity, or SLA. Reply here and
   I'll set up a 30-min scoping call.

3. **Export and walk away** — issue an `Access` DSR from the privacy
   portal in your dashboard (the `/dsr` section) and we'll deliver a
   portable JSON export within 5 business days. No hard feelings.

4. **Extend the sandbox** — one-time 14-day extension available on
   request. Reply with "extend" and I'll process it.

If you have any blockers to a decision (procurement, security
review, pricing question), reply here — we have ways to make most
of them easier.

— {{agent_first_name}}, CoreLink Support
Sandbox: {{tenant_id}}
Pricing: https://corelink-docs.humangr.com/pricing
```

---

## Appendix A — `SR-BREACH-APOLOGY` (auxiliary, internal trigger)

**When:** support's first-touch SLA itself breaches per `RB-CUSTOMER-SUPPORT-T-90.md` §4.2 (e.g., P1 ticket sat un-acked > 1h). Sent in addition to the substantive response.

```
Subject: [CoreLink] {{ticket_id}} — We missed our acknowledgment window

Hi {{customer_first_name}},

Before anything else: we missed our acknowledgment window on this
ticket. Our target was {{target_ack_minutes}} minutes; we took
{{actual_ack_minutes}} minutes.

That's on us. The substantive response on your issue follows below —
but the breach is logged internally and our Support Lead will review
it in our next retrospective. If a pattern emerges, we'll write to
you again about the corrective action.

{{...substantive response per the appropriate `SR-FIRST-TOUCH-Px`
template, inlined...}}

— {{agent_first_name}}, CoreLink Support
Ticket: {{ticket_id}}
```

---

## Cross-references

- `specs/_runbooks/RB-CUSTOMER-SUPPORT-T-90.md` — runbook these templates serve
- `specs/_runbooks/RB-DSR-TICKET-TRIAGE.md` — sibling, DSR routing
- `marketing/launch/CRISIS-COMMS-TEMPLATES.md` — incident-level templates (used after ticket→incident conversion)
- `marketing/launch/STATUS-PAGE-SPEC.md` — status-page (outbound channel referenced in templates)
- `marketing/launch/SUPPORT-DASHBOARD-SPEC.md` — dashboard rendering
- `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` — lighthouse comms overlay (Slack Connect uses adapted templates)
- `ROADMAP-TO-GA.md` §8 (Wave R-8 GA Launch)

---

**Fim SUPPORT-RESPONSE-TEMPLATES — 15 canonical templates + 1 auxiliary.**
