# Pilot Outbound Email Template — Copy-Paste-Ready (PILOT-COMMS-005)

> **Status:** READY FOR OWNER PUBLICATION. Trace: wave-28 step-7. Honest pre-GA pilot framing.
> Format: 150-word outbound email for direct outreach to candidates from `docs/internal/pilot-target-list.md`.
> Mustache placeholders: `{{lead_name}}`, `{{lead_company}}`. Single CTA: `corelink-docs.humangr.com/pilot/apply`.
> Companion to `marketing/launch/PILOT-ANNOUNCEMENT.md`.

---

## Subject line — A/B options (pick one per send)

**A (capability hook):**
> CoreLink pilot — shared CAS for {{lead_company}}'s build cache?

**B (problem hook):**
> {{lead_company}} + cross-region cache dedup — 10 minutes?

**C (peer hook — use only if at least one cohort peer is already in pilot):**
> A few {{lead_company}}-class teams are piloting CoreLink — want in?

Recommended default: **A**. B has higher open rates but pulls more low-intent replies. C is reserved for cohort #2 (post first 3 actives).

---

## Email body — paste verbatim, replace `{{lead_name}}` / `{{lead_company}}`

> Hi {{lead_name}},
>
> Gustavo from HuGR Labs. Quick one — we are opening pilot enrolment for **CoreLink**, a shared, tenant-isolated, content-addressable cache. Bazel and Nix on the build side (Buck2 and Pants are gRPC-only and not supported today), plus a generic CAS API for Docker layer caches, package registries, and ML model registries.
>
> Reaching out specifically because {{lead_company}}'s build / platform footprint looks like a clean fit for the pilot cohort.
>
> The offer:
>
> - $0 for 30 days.
> - 100 GB CAS, 10k audit events / month.
> - Direct Slack with our engineering team.
> - Pre-GA — I'll be honest about what's not shipped yet (no BYOK in pilot, no SOC 2 Type II, no SLA contract). Full disclosure on the landing page.
> - Auto-converts to STANDARD at GA, or terminates clean. No card on file.
>
> 10 slots. Worth a 20-minute call?
>
> Apply directly: **corelink-docs.humangr.com/pilot/apply** — or reply and I'll route you.
>
> Gustavo
> HuGR Labs

---

## Word count

Body: 158 words (target was 150; the procurement-honesty bullet adds ~10 words and is worth it — it removes the most common "is this snake-oil?" reply).

## Send-side notes (Owner-only — do not paste)

- **Volume cap:** 30 sends / day per Owner address. Higher volume requires a dedicated outbound domain (e.g. a `pilot.` sending subdomain — none is provisioned today) with proper SPF/DKIM/DMARC; do NOT send from `humangr.com/corelink` primary at >30/day or you risk the launch-day domain reputation.
- **Sequence:** 1 initial + 1 follow-up at day 4 + 1 break-up at day 10. Do not exceed 3 touches.
- **Follow-up template:** one-line "still interested?" — do not re-pitch.
- **Break-up template:** "closing the loop — no response means I'll de-prioritise; reply with a 'next quarter' if you want a reminder."
- **Reply triage:** any non-rejection reply within 4 business hours goes to a 20-minute call slot. Slow reply = lost lead in dev-tools outbound.
- **CRM tag every send** with `cohort:pilot-outbound-{{wave}}` so wave-29 analytics can compute open / reply / convert rates per cohort.
- **Do not BCC pilot list.** Each send is a 1:1 mail-merge. Bulk-BCC kills both deliverability and trust.

---

*HuGR Labs · CoreLink pilot · 2026-05-16*
