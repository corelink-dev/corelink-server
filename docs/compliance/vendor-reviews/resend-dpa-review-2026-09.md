# Vendor Contract-Basis Record — Resend, Inc.

> STATUS: RECORDED — owner re-charter of B-316, 2026-10-01 ([#2593](https://github.com/HuGR-dev/corelink-server/issues/2593#issuecomment-5941195884)).
> Resend is engaged on its own standard online terms and DPA, accepted online
> at account signup. No countersigned copy exists and no acceptance date is
> recorded.

| Field | Value |
|---|---|
| Vendor | Resend, Inc. |
| Sub-processor id | `resend` |
| Contract basis | Resend's standard online terms and data processing agreement, accepted online by the owner when the account was created (owner statement, #2593 re-charter). No countersigned copy. |
| Terms reference | <https://resend.com/legal/terms-of-service> |
| DPA reference | <https://resend.com/legal/dpa> |
| Online acceptance date | Not recorded. |
| Reviewer | The owner. CoreLink is a single-owner company with no separate Legal/Privacy reviewer (#2593 re-charter). |
| Owner disposition | In the approved launch sub-processor set; re-charter recorded 2026-10-01 in #2593. |
| SCC / transfer mechanism | As set out in Resend's DPA (linked above). |
| Schrems II TIA | None recorded. |
| Data categories processed | recipient_email_pii |
| Data residency / region | United States |
| Certifications verified | None verified for CoreLink; only Resend's own public statements exist. |
| Conditions / follow-ups | Record the acceptance date only if an acceptance record (vendor dashboard or acceptance email) is found. Re-read the linked terms and DPA when Resend announces a change. |
| Next review due | Not scheduled. |

## Repository-verified technical and data-flow scope

- **Role:** transactional email and newsletter-audience delivery.
- **Runtime flow:** `apps/admin-ui/src/app/api/newsletter/subscribe/route.ts`
  accepts a newsletter email, reads `RESEND_API_KEY` and
  `RESEND_NEWSLETTER_AUDIENCE_ID` only on the server, and sends an HTTPS
  `POST` to `api.resend.com/audiences/{audience}/contacts`. The payload contains
  the recipient email and `unsubscribed: false`; source and locale are bounded
  non-PII tags. The route never returns the upstream response or logs the email.
- **Additional flow:** `apps/analytics-worker/wrangler.toml` declares the same
  `RESEND_API_KEY` for the Monday digest email. The secret is not committed to
  the repository.
- **Repository sources:** `apps/admin-ui/src/app/api/newsletter/subscribe/route.ts`;
  `apps/analytics-worker/wrangler.toml`; registry row 16 in
  `specs/_compliance/VENDOR-RISK-REGISTER.md`.

## Notes

This record replaces the earlier `TEMPLATE` packet. VR-6 originally asked for a
dated Legal review and a signed-copy DPA; the owner's 2026-10-01 re-charter
closes it on the public sub-processor list, which names Resend and links its
standard online terms and DPA. Nothing here claims a signature, a countersigned
contract, a named Legal reviewer, a transfer impact assessment, a certification,
or an acceptance date. VR-6 is Closed in
`specs/_compliance/VENDOR-RISK-REGISTER.md` §5.

---

*Referenced by `legal/sub-processors.md`. Its contract basis and its agreement
with every public sub-processor list are enforced by the B-316 verifier
(`scripts/verify_b316_pending_vendor_reviews.py`).*
