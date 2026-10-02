---
id: "LIGHTHOUSE-KIT-06-CASE-STUDY-INTERVIEW-SCRIPT"
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
tags: ["lighthouse", "marketing", "case-study", "interview", "script", "60min"]
---

# 06 — Case Study Interview Script (60 min)

> **Use:** Conduct the case-study interview at D+46, after the SLA attestation is signed and before the case study is drafted.
> **Format:** 60 min recorded call (with explicit consent). One CoreLink marketing lead + one Customer Success engineer (silent unless filling in technical detail). Customer side: signatory + an engineer who actually did the integration.
> **Output:** transcript + extracted quotes → fed into the relevant template under `specs/_lighthouse/case-study-templates/`.

---

## Pre-call checklist (24 hours before)

- [ ] Recording consent confirmed in writing (mail / Slack acknowledgment); explicit statement that transcript will be customer-reviewed.
- [ ] §2 of the signed attestation pre-loaded (numbers don't need to be re-asked).
- [ ] `02-intro-deck.md` slide 2 (customer-zero stats) + this customer's actual stats prepared as a one-pager.
- [ ] Case-study template (relevant one from `specs/_lighthouse/case-study-templates/`) open in a second window.
- [ ] Recording stack tested (Zoom cloud recording / Riverside / etc.) + transcript pipeline ready.

---

## Time-boxed agenda

| Block | Duration | Topic |
|---|---|---|
| 1. Background | 8 min | Customer + their use case |
| 2. Problem statement | 10 min | Pain before CoreLink |
| 3. Why CoreLink | 8 min | Evaluation + alternatives |
| 4. Integration narrative | 12 min | Timeline + helpful patterns + surprises |
| 5. Quantitative outcomes | 10 min | Hit ratio + cost savings + dev time |
| 6. Quote selections | 7 min | Specific punchy phrasings |
| 7. Permission to publish | 5 min | Sign-off on architecture diagram + quotes + distribution |

Total: 60 min.

---

## Block 1 — Background (8 min)

**Goal:** Set the scene for the reader. Capture company stage, team size, build stack.

**Questions (let the customer talk; interviewer takes notes):**
1. Could you introduce yourself, your role, and how long you've been with {Customer}?
2. Give me the one-paragraph version of what {Customer} does and who you build it for.
3. How big is the engineering team? How is it organized (squads / platform vs product / monorepo vs polyrepo)?
4. What build tooling do you use, and how long has it been in place?
5. What does a typical CI run look like for you, end to end?

**Notes target:** ~150 words for the "Background" section of the case study template.

---

## Block 2 — Problem statement (10 min)

**Goal:** Capture the pre-CoreLink pain in concrete, quantitative terms.

**Questions:**
1. Walk me through what your build / CI pipeline looked like before CoreLink. What cache backend were you using?
2. What were the symptoms that made you start looking? Slow CI? Cost? Reliability? Cache invalidation chaos?
3. Were there specific incidents or moments that crystallized the pain? (Get a story, not a generality.)
4. Pre-CoreLink baseline numbers — what was your cold build time? Warm build time? Cache hit ratio? Monthly CI minutes consumed?
5. What workarounds had you tried that didn't fix the problem?

**Notes target:** ~200 words. The narrative is more valuable than the numbers (numbers are in the attestation).

**Tip:** if the customer struggles to find a story, prompt with: "Was there a Friday-afternoon-deploy that went sideways because of a cache issue?" or "Did anyone on the team explicitly complain about it in a retro?"

---

## Block 3 — Why CoreLink (8 min)

**Goal:** Capture the evaluation criteria + alternatives considered.

**Questions:**
1. When you started looking at managed remote caches, what were the alternatives on the shortlist? (Be specific — vendor names if comfortable; categories if not.)
2. What were your top 3 evaluation criteria?
3. What made CoreLink stand out? (Don't pre-load the answer; let them.)
4. Were there things that gave you pause? What concerns did you have at signing?
5. (Enterprise) How important was BYOK / audit-chain / Schrems II posture in the decision? Walk me through how your security / compliance team evaluated it.
6. (OSS) How important was the OSS-friendly posture (community-visible roadmap, documented protocols)?

**Notes target:** ~150 words. This block produces the most quotable material — listen for specific phrasings.

---

## Block 4 — Integration narrative (12 min)

**Goal:** Capture the migration experience and surface helpful patterns for the next customer.

**Questions:**
1. Talk me through the integration timeline as you experienced it — from the intro call to first cache hit. Where did time actually go?
2. What was easier than expected?
3. What was harder than expected?
4. What did the CoreLink team do that was particularly helpful? Particularly unhelpful?
5. What's a pattern from your integration that you'd want the next customer to know about?
6. (Enterprise) How did BYOK setup actually go in practice? Where were the friction points?
7. (Enterprise) Did you run the kill-switch chaos drill? What did you learn?
8. What did your team say about it once it was live? (Engineering feedback, not management framing.)

**Notes target:** ~300 words. This block becomes the "Integration story" section of the case study, often the most read part.

---

## Block 5 — Quantitative outcomes (10 min)

**Goal:** Capture results in numbers the case study can publish.

**Questions:**
1. Looking at the 30-day window, what's the headline number for you? (Cache hit ratio? CI minutes saved? Dev-loop time?)
2. Cache hit ratio — what was it pre-CoreLink vs at the end of the 30-day window?
3. Build time — cold and warm — pre vs post?
4. CI minutes consumed per month — pre vs post? (Translate to engineering cost if comfortable.)
5. Developer experience — anything you've heard from contributors / engineers about local-loop speed?
6. Reliability — any incidents in the 30-day window? How did response time compare to your previous setup?
7. (Enterprise) Compliance — anything material in audit / DPA reviews that's easier now?
8. What's a number you'd be comfortable having in a case study with your name on it?

**Notes target:** ~200 words. Each number should be one the customer is OK signing off on publicly (OSS) or in NDA-distributed PDF (Enterprise).

**Cross-check:** every number quoted here must reconcile with the signed attestation §2 / §2.1. If a customer cites something different, flag it for verification before publication.

---

## Block 6 — Quote selections (7 min)

**Goal:** Get 3-5 punchy on-record quotes.

**Approach:**
1. "I'd love to use a quote from you in the case study. Some of what you said earlier was great — let me read a couple back and you tell me if you'd be comfortable with them being attributed."
2. Read back 2-3 candidate quotes from notes — verbatim if possible.
3. For each: confirm attribution (name + role), and ask if any phrasing should be tightened.
4. Optional fresh prompt: "If you had to summarize the impact of CoreLink in one sentence for a peer at another company, what would you say?"
5. Capture any quote the customer wants to add unprompted.

**Target:** 3-5 approved quotes; at least one of which is short and punchy enough to use as a pull quote.

---

## Block 7 — Permission to publish (5 min)

**Goal:** Lock down distribution scope before ending the call.

**Confirm:**

| Element | OSS Team tier (LH-OSS-01) | Enterprise BYOK (LH-ENT-BYOK-01) |
|---|---|---|
| Customer name in case study | Public | NDA-sanitized (industry + stage; no name) |
| Logo usage | On marketing site + decks | None unless explicit additional approval |
| Quote attribution | By name + role | Anonymized ("VP Platform at a Series B fintech") |
| Architecture diagram | Sanitized; reviewable | Sanitized; reviewable; redactions enforced |
| Numbers | Public | Range (e.g. "60-70% cache hit") rather than precise |
| Distribution | Public on humangr.com/corelink | NDA PDF to qualified sales prospects |
| Reference calls | Up to 2 / quarter for 12 months | Up to 2 / quarter for 12 months |

**Sign-off statement (read to customer at end of call):**

> "Just to confirm before we wrap: you're authorizing CoreLink to draft a case study based on this interview, send it back to you for review and approval before any external use, and — once you've approved — publish it according to {Path A / Path B} above. You can withdraw approval at any time before publication. Is that accurate?"

Capture verbal `yes`. Follow up with a written confirmation in the post-call email (≤ 4 business hours).

---

## Post-call (within 48 hours)

- [ ] Recording uploaded to internal-only storage; access limited to marketing + CS.
- [ ] Transcript generated; sensitive sections flagged for redaction.
- [ ] Customer receives the written publication-permission confirmation.
- [ ] Draft case study started using the relevant template under `specs/_lighthouse/case-study-templates/`.
- [ ] Quotes verified against transcript before insertion.
- [ ] Architecture diagram drafted; sanitization review by Customer Success + Engineer S-20 lead.

---

## Common pitfalls (interviewer self-check)

- Don't lead the witness — open-ended questions before specific ones in each block.
- Don't argue with negative feedback — capture it and thank them. Negative material in a case study (handled honestly) increases credibility.
- Don't promise roadmap items in the call — defer to the next quarterly roadmap review call.
- Don't quote numbers the customer didn't say — re-confirm any number before it appears in the draft.
- Don't skip Block 7 — without explicit permission scope, the draft cannot go to legal review.

---

**Fim 06-CASE-STUDY-INTERVIEW-SCRIPT.**
