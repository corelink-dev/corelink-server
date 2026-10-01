# Vendor Legal-Review Record — Functional Software, Inc. (Sentry)

> STATUS: TEMPLATE — pending the actual legal review record (owner/counsel to complete).

| Field | Value |
|---|---|
| Vendor | Functional Software, Inc. (Sentry) |
| Sub-processor id | `sentry` |
| Review date | `TBD (YYYY-MM-DD)` |
| Reviewer | `TBD (named Legal Counsel / Privacy Officer)` |
| DPA reference | <https://sentry.io/legal/dpa/> |
| DPA status | `TBD (signed copy pending — VR-7)` |
| SCC / transfer mechanism | `TBD` |
| Schrems II TIA | `TBD` |
| Data categories processed | telemetry |
| Data residency / region | `TBD (verify account-selected Sentry region)` |
| Sub-processor flow-down | `TBD (confirm flow-down per GDPR Art. 28(4))` |
| Certifications verified | `TBD (SOC 2 Type II report not yet pulled into Drata — VR-7)` |
| Review outcome | `TBD (approved / approved-with-conditions / rejected)` |
| Conditions / follow-ups | `VR-7 — Legal must obtain and record the signed-copy DPA and SOC 2 evidence.` |
| Next review due | `TBD (YYYY-MM-DD)` |

## Repository-verified technical and data-flow scope

- **Code-wired role:** conditional application error/transaction monitoring for
  the admin UI browser/server/edge, public docs browser, main Cloudflare Worker,
  and get-corelink/analytics/signup Workers. This does not establish which
  Sentry projects or environments are enabled in the account or deployment.
- **Conditional runtime flow:** admin browser initialisation requires
  `NEXT_PUBLIC_SENTRY_DSN`; admin server/edge require `SENTRY_DSN` or the public
  fallback. The docs build emits a browser Sentry loader only when
  `SENTRY_DSN_DOCS` is set. The four Workers use `Sentry.withSentry` with an
  optional `SENTRY_DSN` binding and an empty-string fallback. Admin and Worker
  configs set `sendDefaultPii: false` and use local `beforeSend` /
  `beforeSendTransaction` scrubbers; the docs loader sets `sendDefaultPii: false`
  and filters selected breadcrumb header keys. These enumerated controls do
  not establish the absence of personal data or customer content in live events.
- **Data boundary:** the repository classifies the resulting exception,
  breadcrumb, and diagnostic event stream as `telemetry`; no customer content
  flow is asserted by this packet.
- **Repository sources:** `apps/admin-ui/instrumentation-client.ts`,
  `apps/admin-ui/sentry.server.config.ts`, `apps/admin-ui/sentry.edge.config.ts`,
  `apps/docs/docusaurus.config.ts`, `worker/src/index.ts`,
  `apps/get-corelink-worker/src/index.ts`, `apps/analytics-worker/src/index.ts`,
  `apps/signup-worker/src/index.ts`, and their local Sentry scrubbers.

## Notes

No signature, named review, transfer assessment, certification, or approval is
claimed. Legal owns VR-7 in `specs/_compliance/VENDOR-RISK-REGISTER.md` §5,
due 2026-09-24.

---

*Referenced by `legal/sub-processors.md`. Existence and pending-state integrity
are enforced by the B-316 verifier.*
