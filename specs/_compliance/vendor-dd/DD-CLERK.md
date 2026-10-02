---
id: "DD-CLERK-2026-05-15"
type: "vendor_due_diligence"
doc_status: "ACTIVE"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
sprint: "R5-3"
parent_wi: "WI-R5-3-GAP-14-VENDOR-RISK"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
inherits_from: ["VENDOR-RISK-REGISTER-2026-05-15", "VENDOR-RISK-METHODOLOGY-2026-05-15"]
tags: ["soc2", "cc9.2", "vendor-dd", "critical", "clerk", "auth", "gap-14"]
---

# Vendor DD — Clerk, Inc.

> **doc_status:** ACTIVE · Register row: 3 · Category: **Critical** · Residual risk: **4.0** (Inherent 16 × CEF 0.25).
>
> Clerk is the sole authentication provider for CoreLink (admin-ui + API JWT verification). Clerk outage prevents new logins; existing sessions degrade.

---

## 1. Vendor profile

| Field | Value |
|---|---|
| Legal entity | Clerk, Inc. |
| HQ | San Francisco, CA, USA |
| Plan | Pro (production app + JWT templates + organization-level roles) |
| Contract effective | Not recorded — standard online terms and DPA accepted at account signup (owner statement, #2593 re-charter); no acceptance record is held |
| Monthly run-rate | $25/mo Pro tier (current) — Enterprise tier negotiation deferred to post-GA |
| Account contacts | (recorded in `legal/vendor-contacts.md`) |

## 2. Service scope

- User account lifecycle (sign-up, sign-in, password reset, MFA, social logins)
- JWT issuance via `pat` template (consumed by `corelink-clerk` for API authentication)
- Session management (Clerk-hosted; CoreLink consumes via SDK middleware)
- Organization-level role assignments (admin / member / billing-admin → mapped to CoreLink scopes per `auth-event-taxonomy.md`)
- Webhook delivery of identity events (user.created, user.deleted → DSR-erasure pipeline)

## 3. Data sharing

| Data category | Direction | Encryption at rest | Encryption in transit | Key holder |
|---|---|---|---|---|
| User PII (email, name, phone, password hash) | CoreLink customer → Clerk | Clerk-managed (AES-256) | TLS 1.3 | Clerk |
| MFA secrets (TOTP, WebAuthn public keys) | Clerk-side only (we never see them) | Clerk-managed | TLS 1.3 | Clerk |
| Session tokens (JWT) | Clerk → CoreLink (verified via JWKS) | n/a (signed, not encrypted; short-lived) | TLS 1.3 | Clerk (private key) / CoreLink (public verify) |
| Organization membership graph | CoreLink ↔ Clerk | Clerk-managed | TLS 1.3 | Clerk |
| Webhook signing secret | Clerk → CoreLink | `cf-wrangler` | TLS 1.3 | CoreLink |

## 4. Regulatory and attestation scope

| Framework | Status | Evidence path |
|---|---|---|
| SOC 2 Type II | Attested | Clerk Trust Center + Drata vendor module |
| ISO 27001 | In progress (target 2026 Q4) | Clerk Trust Center |
| GDPR | Processor; SCCs Module 2 | Clerk DPA |
| LGPD | Processor (US-hosted; SCCs cover BR transfers) | Clerk DPA |
| HIPAA | Not in scope (no PHI) | — |

## 5. Contractual posture

| Document | Signed | Notes |
|---|---|---|
| Clerk Standard Terms | Not recorded (accepted online) | https://clerk.com/legal/standard-terms |
| DPA | Not recorded (accepted online with the terms) | https://clerk.com/legal/dpa |
| SLA | Pro plan baseline (99.9% monthly uptime) | Enterprise SLA TBD post-GA |
| BAA | Not signed | No PHI |

## 6. Control mapping

| CoreLink CTRL | Dependency on Clerk |
|---|---|
| CTRL-IDENT-001..004 | Clerk is the identity provider |
| CTRL-ACCESS-001..003 | Authorization scopes derived from Clerk org-roles + JWT claims |
| CTRL-AUDIT-002 | auth-event audit log feeds from Clerk webhooks |
| CTRL-PRIV-014 | DSR-erasure flow includes Clerk user.delete API call as terminal step |
| CTRL-PRIV-CONSENT-001..006 | Cookiebot consent records keyed by Clerk user_id |

## 7. Risk assessment narrative

**Inherent risk (16 = 4 × 4):** Impact 4 (no new logins, no admin-plane access — but existing JWTs remain valid until expiry; data plane survives via long-lived JWKS cache and read-only-mode toggle); Likelihood 4 (younger vendor than Cloudflare/Stripe — public incidents have occurred in 2024-2025 SaaS-auth class).

**Residual risk (4.0):** CEF 0.25 — Clerk has current SOC 2 Type II + signed DPA, CoreLink has compensating controls (long-lived JWKS cache, read-only-mode toggle, kill-Clerk chaos drill scheduled), but failover to a non-Clerk identity provider (e.g., WorkOS, Auth0) is not built-in — a vendor switch is a multi-week project. CEF capped at 0.25.

**Top risks monitored:**

1. Clerk control-plane outage > JWKS cache TTL → admin-plane locked out. Mitigation: extended cache + emergency JWT minting via Clerk-down break-glass per `RB-AUTH-EMERGENCY.md` (drafted under R5-A8).
2. Clerk webhook delivery failure → DSR-erasure pipeline stalled. Mitigation: idempotent Clerk-user-delete retry in `corelink-dsr-engine`; nightly reconcile job catches drift.
3. Clerk pricing-tier renegotiation at Enterprise upgrade → cost spike. Mitigation: Enterprise contract terms negotiation queued for post-GA.
4. Clerk acquired into incompatible terms. Mitigation: identity-provider abstraction layer in `corelink-auth-iface` lets us swap providers with effort, not rewrite.

## 8. Escalation contacts

| Role | Contact | SLA |
|---|---|---|
| Clerk support — P1 | Clerk Slack Connect + support@clerk.com `Subject: URGENT P1` | 4h business hours |
| Security | security@clerk.com | 24h |
| Privacy / DPA | privacy@clerk.com | 5 business days |
| Breach notification | privacy@clerk.com + security@hugr.dev | Per DPA |

## 9. Termination / exit plan

If Clerk exits the market or terminates CoreLink:

1. **Day 0..7:** snapshot all Clerk user objects via Clerk Backend API export (paginated; includes email, public_metadata, organization membership; password hashes are **non-exportable** by design — users will need to reset on migration).
2. **Day 7..30:** stand up replacement IdP (WorkOS preferred — same JWT-template shape; Auth0 fallback). Implement password-reset-mandatory flow at first login on new IdP.
3. **Day 30..60:** dual-IdP cutover (Clerk for existing sessions, new IdP for new sign-ups) → final cutover with mandatory re-auth.
4. **Day 60..90:** decommission Clerk.

**RTO:** ≤ 60 days; **RPO:** zero data loss but ≥ 1 user-visible password reset event for the entire user base.

## 10. Review history

| Review date | Reviewer | Type | Residual | Notes |
|---|---|---|---|---|
| 2026-05-15 | Gustavo Schneiter (VP-Sec) | Baseline | 4.0 | Initial DD; closes GAP-14. Kill-Clerk drill formal evidence is open action VR-2. |

Next quarterly review: **2026-08-15**.
