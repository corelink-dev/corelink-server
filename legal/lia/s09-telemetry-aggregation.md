---
id: "LIA-S09-001"
type: "lia"
doc_status: "DRAFT"
version: "1.0.0"
created: "2026-05-13"
updated: "2026-05-13"
feature: "S-09 Telemetry Aggregation"
sprint: "S-09"
owner: "Gustavo Schneiter"
privacy_officer: "Gustavo Schneiter (interim)"
dpo: "TBD"
tags: ["lia", "s09", "telemetry", "legitimate-interest", "lgpd-art-10", "gdpr-art-6-1-f", "ico-3-part-test"]
evidence_event: "EVT-046"
evidence_retain: "3y"
evidence_path: "evidence-legal/lia-s09-telemetry-aggregation.md"
related_dpia: "legal/dpia/s09-telemetry-aggregation.md"
---

# LIA: S-09 Telemetry Aggregation — Legitimate Interest Assessment

> **LGPD Art. 10 / GDPR Art. 6(1)(f) — ICO Three-Part Test**
> Template: `specs/_templates/lia.md` v1.0.0 — WI-S11-008
> **Legal citations:** WP29 Opinion 06/2014 endorsed by EDPB (8 balancing criteria);
> ICO LIA guidance; LGPD Art. 10 + 18; GDPR Art. 6(1)(f) + 21.

---

## Metadata

| Field | Value |
|---|---|
| LIA ID | LIA-S09-001 |
| Feature / Sprint | S-09 telemetry aggregation pipeline |
| Data Controller | HuGR Labs Ltda (LGPD) / HuGR Labs Ltd (GDPR) |
| Encarregado / DPO | TBD (interim: Gustavo Schneiter) |
| Privacy Officer | Gustavo Schneiter (interim) |
| Legitimate interest claimed | Operational telemetry for service reliability, performance monitoring, abuse detection, and security — necessary to deliver a reliable, secure SaaS product and comply with SLA commitments |
| Processing basis | legitimate_interest (LGPD Art. 10 / GDPR Art. 6(1)(f)) |
| Date initiated | 2026-05-13 |
| Next review date | 2027-05-13 (annual) |
| Related DPIA | `legal/dpia/s09-telemetry-aggregation.md` |
| EVT evidence path | `evidence-legal/lia-s09-telemetry-aggregation.md` (R2 retain 3y per EVT-046) |

---

## Section 1 — Purpose Test

### 1.1 Statement of legitimate interest

HuGR Labs (CoreLink) processes pseudonymized operational telemetry — API call counts, latency histograms, error rates, rate-limit events, and cache hit/miss ratios — to pursue the following specific legitimate interests:

1. **Service reliability and SLA compliance:** CoreLink commits to 99.9% uptime SLAs with enterprise tenants. Without real-time telemetry, it is impossible to detect, diagnose, and remediate outages or performance degradations within SLA windows (typically 30-minute detection threshold). The operational necessity of monitoring is explicitly acknowledged in GDPR Recital 47 and WP29 Opinion 06/2014 §3.1 (IT security and network integrity as legitimate interest examples).

2. **Abuse and security detection:** CoreLink processes API requests from hundreds of tenants. Without rate-limit event monitoring and abuse pattern detection (S-08), credential stuffing attacks, tenant isolation violations, and API abuse cannot be detected. Security monitoring is a well-established legitimate interest under GDPR Rec. 47 + WP29 Op. 06/2014 §3.1 ("prevention of fraud" + "network security").

3. **Capacity planning and cost management:** Accurate usage telemetry drives infrastructure scaling. Without it, CoreLink cannot efficiently provision Cloudflare Workers and R2 storage — resulting in either over-provisioning (wasted cost) or under-provisioning (SLA breach). This is a direct operational efficiency interest of the data controller.

### 1.2 Lawfulness of the interest

All three interests are lawful:
- Service reliability and SLA compliance: lawful under contract fulfillment obligations; monitoring is incidental to service delivery.
- Security monitoring: GDPR Rec. 47 explicitly lists "prevention of fraud" as an example of legitimate interest; abuse detection is analogous.
- Capacity planning: pure operational efficiency; no harm to data subjects inherent in the interest itself.

No conflicting legal obligations are identified. LGPD Art. 10 I expressly permits processing for "legitimate purposes pursued by the controller or by a third party" that do not "prevail over the fundamental rights and freedoms of the data subjects."

### 1.3 Real and present interest

The interests are demonstrably real and present:
- CoreLink SLA commitments (99.9% uptime) are contractually binding and referenced in tenant contracts. Failure to monitor would constitute a material breach of contract.
- Security incidents (credential stuffing, API abuse) have been identified in pre-launch testing; abuse detection is not hypothetical.
- Infrastructure costs are directly observable; capacity optimization has reduced compute costs by ~30% in staging tests.

### 1.4 LGPD Art. 10 specific requirements

| LGPD Art. 10 requirement | Assessment |
|---|---|
| (I) Processing for legitimate purposes | YES — operational reliability, security, capacity planning are legitimate business purposes |
| (II) Necessary for the controller's purposes | YES — see necessity analysis §2. Service cannot be reliably operated or secured without telemetry |
| (III) Does not prevail over fundamental rights | YES (with safeguards) — pseudonymization + data minimization ensures fundamental rights are respected; see balance test §3 |

---

## Section 2 — Necessity Test

### 2.1 Link between processing and purpose

Direct link is established for each purpose:
- **Reliability:** API call counts, error rates, and latency directly and exclusively measure service health. There is no way to detect a latency spike or error rate increase without capturing these metrics.
- **Security:** Rate-limit events and access patterns are the direct signals used by the S-08 abuse detection algorithm. Without these, detection is impossible.
- **Capacity:** Usage counters directly drive scaling decisions. Without them, auto-scaling policies cannot function.

### 2.2 Data minimization analysis

CoreLink has applied aggressive data minimization:
- Subject identifiers pseudonymized (HKDF keyed hash) before log emission — raw subject_id never enters Loki.
- IP addresses truncated to /24 (IPv4) / /48 (IPv6) before emission.
- Per-request sampling at 1% for latency distribution (not all requests logged).
- Timestamps bucketed to 15-minute intervals for rate-limit events.
- Aggregate counters (not per-request detail) stored in CF Analytics Engine.

### 2.3 Less intrusive alternatives considered

| Alternative | Considered | Why insufficient |
|---|---|---|
| Pure aggregate metrics only (no pseudonymized per-request logs) | YES | Aggregate-only would not support latency distribution analysis (p95/p99 require sampled per-request data). Statistical deviation detection for abuse also requires some per-request context. |
| Completely anonymous metrics (k-anonymity k≥10) | YES | Anonymization at k=10 would suppress rare error conditions and early abuse signals when tenant is small. Not sufficient for reliability SLA. |
| Consent-based processing only | YES | Operational/security monitoring cannot be conditional on user consent — if all users opt out, system is unmonitorable. This is standard practice; GDPR Rec. 47 confirms legitimate interest as the appropriate basis for security processing. |
| Contractual necessity basis (Art. 6(1)(b)) | Considered | Not appropriate — monitoring is not strictly necessary to perform the contract with each individual user; it is necessary for the controller's service delivery obligations. Legitimate interest is the correct basis. |
| Synthetic/simulated traffic | YES | Cannot reflect real abuse patterns or real infrastructure load distributions. Not sufficient for production monitoring. |

**Conclusion:** The current design (pseudonymized + minimized + sampled) is the minimum necessary to achieve the legitimate purposes.

### 2.4 Storage limitation justification

| Data | Retention | Justification |
|---|---|---|
| Pseudonymized per-request sample (1%) | 90 days | 90 days covers one billing cycle + enough history for trend analysis. Shorter (30d) would miss quarterly patterns; longer (180d) unnecessary. |
| Truncated IP (abuse detection) | 30 days | 30 days covers typical campaign windows for credential stuffing; sufficient for pattern detection. Shorter would miss slow-roll attacks. |
| Aggregate metrics (CF Analytics Engine) | 90 days | 90 days supports capacity planning (one quarter). Longer not needed. |
| Ephemeral abuse detection state (KV) | 7 days | 7-day sliding window is the S-08 algorithm's detection window. |

---

## Section 3 — Balance Test

### 3.1 WP29 Opinion 06/2014 endorsed by EDPB — 8 balancing criteria

| Criterion | Assessment | Detail |
|---|---|---|
| 1. Nature of the legitimate interest (how compelling) | HIGH — very compelling | Service reliability and security are essential to the product's existence; SLA compliance is contractually binding; security monitoring protects all users (including data subjects) from abuse |
| 2. Nature of the data — ordinary vs sensitive | LOW IMPACT | No special-category data; pseudonymized ordinary identifiers; truncated IPs; aggregate counters. No financial, health, or political data in telemetry. |
| 3. Nature of processing — profiling, monitoring, disclosure risk | MEDIUM IMPACT | Systematic monitoring of API activity is present. Mitigated by: pseudonymization (no direct identification); aggregate storage; 1% sampling; no cross-tenant linkage; no profiling for marketing. |
| 4. Status of data subject — vulnerable? | LOW IMPACT | Enterprise/developer API users; not targeting consumers, children, or vulnerable groups specifically. |
| 5. Reasonable expectations | MEDIUM — partially expected | Enterprise SaaS users have reasonable expectation that service is monitored for reliability and security. This expectation is confirmed by privacy notice disclosure (WI-S11-004). Less obviously expected: per-request pseudonymized sampling. Mitigated by transparent privacy notice. |
| 6. Consequences of processing — potential harm | LOW | Pseudonymized data; re-identification risk is low (key-deletion on erasure). No financial harm, no social harm, no discrimination risk identified. |
| 7. Safeguards applied to reduce impact | STRONG | Pseudonymization (HKDF keyed); IP truncation/jitter; 1% sampling; 90-day retention; key-deletion on DSR erasure; opt-out mechanism; access controls on Loki. |
| 8. Overriding interests / fundamental rights | BALANCE FAVORS CONTROLLER | Fundamental right to privacy (EU Charter Art. 7 / LGPD Art. 18) vs controller's interest in reliable, secure service. Given the strong safeguards (pseudonymization + minimization + erasure), the balance favors the controller. The processing is not disproportionate to the legitimate interest. |

### 3.2 Balance verdict

**Balance favors the data controller.** The legitimate interests (service reliability, security, capacity) are compelling and necessary. The data subjects' rights and interests are protected by strong technical safeguards (pseudonymization, minimization, erasure) and organizational measures (transparent privacy notice, opt-out). The processing does not cause material harm to data subjects, and data subjects in the enterprise SaaS context have a reasonable expectation that their API activity is monitored for service delivery purposes.

This conclusion is consistent with WP29 Opinion 06/2014 endorsed by EDPB examples of acceptable legitimate interest processing (§3.3): security monitoring and fraud prevention.

### 3.3 Opt-out / objection mechanism (GDPR Art. 21 / LGPD Art. 18 II)

Data subjects may object to processing under legitimate interest via:
1. **Privacy settings:** Users can opt out of non-core telemetry (sampling and latency distribution) via account privacy settings (WI-S11-004). Core operational metrics (aggregate error counts, security rate-limit events) are retained under security legitimate interest override (cannot be opted out per GDPR Rec. 47 / LGPD Art. 10 §§).
2. **Written objection:** Objections submitted via DSR portal (WI-S11-001) → Privacy Officer review within 15 business days → response with grounds or opt-out confirmation.
3. **DSR erasure:** On erasure DSR, pseudonym key is deleted → all historical telemetry becomes permanently unlinked from the subject.

### 3.4 Privacy notice transparency

Legitimate interest processing is disclosed in the CoreLink Privacy Notice (WI-S11-004), Section "Operational Telemetry" with:
- Description of data collected (pseudonymized API activity).
- Purpose (reliability, security, capacity).
- Retention periods.
- Opt-out mechanism.
- Right to object (GDPR Art. 21 / LGPD Art. 18 II).

The LIA document is available on request to data subjects and supervisory authorities.

---

## Section 4 — Privacy Officer Review

### 4.1 Review conclusion

**Legitimate interest is a valid legal basis** for the S-09 telemetry aggregation processing as documented in this LIA. The three-part ICO test is satisfied:
1. **Purpose test:** Compelling, specific, lawful interests (reliability, security, capacity). PASSED.
2. **Necessity test:** Minimum necessary data with aggressive minimization. Less intrusive alternatives insufficient. PASSED.
3. **Balance test:** Balance favors controller given strong safeguards and compelling interests. Fundamental rights not overridden disproportionately. PASSED.

Processing may proceed under LGPD Art. 10 / GDPR Art. 6(1)(f) legitimate interest basis, subject to the conditions in §4.2.

### 4.2 Conditions / mitigations required

1. Pseudonymization (HKDF keyed subject ID) MUST remain in place — if removed, LIA must be re-assessed.
2. IP truncation to /24 (IPv4) / /48 (IPv6) MUST remain in place.
3. 1% sampling cap on per-request logs MUST remain in place.
4. 90-day retention hard limit for Loki per-request logs MUST remain in place.
5. DSR erasure via key-deletion MUST remain integrated in erasure worker (WI-S11-002).
6. Opt-out mechanism MUST be accessible and functional (WI-S11-004 privacy settings).
7. Annual LIA review (next: 2027-05-13).
8. DPIA companion document (`legal/dpia/s09-telemetry-aggregation.md`) must be kept in sync.

### 4.3 Sign-off

| Role | Name | Date | Status |
|---|---|---|---|
| Privacy Officer | Gustavo Schneiter (interim) | 2026-05-13 | Pending final sign-off pre-PRR |
| DPO / Encarregado | TBD | TBD | Pending hire |
| Legal (external) | TBD | TBD | Pending (recommended for LIA defensibility) |

> **EVT-046 evidence:** Upload to `evidence-legal/lia-s09-telemetry-aggregation.md` (R2 retain 3y) upon sign-off.

### 4.4 LIA changelog

| Version | Date | Author | Change summary |
|---|---|---|---|
| 1.0 | 2026-05-13 | Gustavo Schneiter | Initial LIA — WI-S11-008; ICO three-part test + WP29 Op. 06/2014 8 criteria |
