# Privacy Notice — HuGR CoreLink

> **PRELAUNCH INTERNAL REVIEW DRAFT — NOT PUBLISHED OR OPERATIVE.** CoreLink has not launched and has no customers. The present-tense descriptions below are preserved historical proposed notice text; they do not state current collection, use, sharing, retention, or processing practices and create no current commitment. Counsel review and owner approval are pending before any future customer use.
>
> **Source status:** The owner confirms CoreLink has not launched and has no customers. Counsel review and approval of processing, residency, and transfer terms are pending; this notice does not establish an approved transfer basis.

**Version:** 1.0.0
**Historical source date (not published):** 2026-05-13
**DPO Contact:** privacy@hugr.dev

---

## 1. Identity and Contact Details of the Controller

**Data Controller:** HuGR Labs Ltda. ("HuGR", "we", "us")
**Interim DPO:** privacy@hugr.dev

---

## 2. Categories of Personal Data Collected

The historical proposed notice listed the following categories of personal data; this is not a statement of current collection:

- **Identity data:** name, email address, data subject UUID.
- **Authentication data:** PAT (Personal Access Token) credentials, WebAuthn keys.
- **Usage data:** API call logs, build artifact metadata (BLAKE3 hash, size, timestamps).
- **Billing data:** payment information processed via Stripe (we do not store full card numbers).
- **Telemetry data:** infrastructure logs (Loki), performance metrics (Prometheus/Grafana).

---

## 3. Purposes of Processing

We process your personal data for the following purposes:

1. **Contract performance:** provision of the CoreLink service (CAS cache, build pipeline, billing).
2. **Legal obligation compliance:** fiscal records (LGPD Art. 16), regulatory audit trail (7-year retention).
3. **Legitimate interests:** abuse monitoring, fraud detection, platform security.
4. **Consent:** usage analytics (opt-in; revocable at any time).

---

## 4. Legal Basis

| Purpose | Legal Basis (GDPR) | Legal Basis (CCPA) |
|---|---|---|
| Contract performance | Art. 6.1(b) | Service provision |
| Legal obligation | Art. 6.1(c) | Legal compliance |
| Legitimate interests | Art. 6.1(f) | Business purpose |
| Consent (analytics) | Art. 6.1(a) | Opt-in consent |

---

## 5. Sub-processors

The historical proposed notice listed the following sub-processors for a future service; this is not a statement of current customer-data processing:

| Sub-processor | Purpose | Region |
|---|---|---|
| Cloudflare Inc. | CDN, Workers, R2, D1, Pages | Global |
| Stripe Inc. | Payment processing | US/EU |
| Neon Inc. | PostgreSQL database | US |
| Grafana Labs | Monitoring (Loki/Prometheus) | EU |

You will be notified at least 30 days before any changes to our sub-processor list.

---

## 6. International Transfers

No customer region is currently offered. The production Worker environments reference one shared global D1 control-plane database that is not tenant-pinned. It contains tenant, membership, PAT, quota, billing-state, and audit-outbox records. A read-only Wrangler 4.145.0 readback on 2026-09-30 identified `corelink-prod-d1` (ID `d64742ea-e102-40b2-a844-ff02e3f94562`), with `running_in_region=ENAM`, `jurisdiction=null`, automatic read replication, and 162 tables. The reported region is metadata, not a physical-location guarantee; this is the root owner’s technical launch posture, not legal approval. No transfer basis or supplementary measure for this shared D1 posture has been approved. This notice is a draft and makes no regional processing or international-transfer commitment.

---

## 7. Data Retention

| Category | Retention Period | Basis |
|---|---|---|
| Account data | Duration of contract + 5 years | Fiscal compliance |
| Audit logs | Retention period is not established here | No Object Lock guarantee; production COMPLIANCE retention is unavailable or unproven |
| Build logs (artifacts) | As configured by data subject | Contractual |
| Billing data | 5 years (fiscal) | Legal obligation |
| Consent records | 7 years | GDPR Art. 7(1) (demonstrability) + LGPD Art. 8 (consent regime) |

---

## 8. Your Rights (GDPR Art. 15-22 / CCPA §1798.100-125)

You have the following rights:

- **Right of access** (GDPR Art. 15 / CCPA §1798.110): confirm processing and access your data.
- **Right to rectification** (GDPR Art. 16): request correction of inaccurate data.
- **Right to erasure** (GDPR Art. 17 / CCPA §1798.105): request deletion of your data.
- **Right to portability** (GDPR Art. 20): receive your data in structured JSON format.
- **Right to object** (GDPR Art. 21): object to processing based on legitimate interests.
- **Right to restrict processing** (GDPR Art. 18): request restriction of processing.
- **Right to withdraw consent** (GDPR Art. 7.3): withdraw consent at any time.

To exercise your rights, use: **POST /v1/privacy/dsr/{right}** (self-service API).
Response time: up to 30 calendar days (access/portability); 5 business days (rectification); ≤ 5 minutes (consent revoke).

---

## 9. Security Measures

We implement the following security measures:

- Encryption in transit (TLS 1.2 minimum; TLS 1.3 negotiated where supported).
- Encryption at rest (R2 + Neon).
- Multi-factor authentication (WebAuthn FIDO2).
- Tamper-evident audit-chain source controls; production Object Lock immutability and a fixed retention duration are not established.
- Regular security testing (SOC 2 Type II in preparation).

---

## 10. Cookies and Tracking

We use strictly necessary functional cookies for service operation. We do not use third-party tracking cookies without your explicit consent.

---

## 11. Children

CoreLink is a B2B service for professional developers. We do not knowingly collect data from persons under 18 years of age.

---

## 12. Changes to This Notice

Any **material** change (new data category, new sub-processor, new purpose) will be communicated in advance and will require new consent (**major version bump**).

Clarification updates (typo corrections, contact updates) are published silently (**minor version bump**) with a diff available at `/privacy/changelog`.

---

## 13. Contact and Supervisory Authority

**Interim DPO:** privacy@hugr.dev
**Controller:** HuGR Labs Ltda.

**EU supervisory authority:** Irish Data Protection Commission (DPC) — [www.dataprotection.ie](https://www.dataprotection.ie)
**California:** California Privacy Protection Agency — [cppa.ca.gov](https://cppa.ca.gov)
