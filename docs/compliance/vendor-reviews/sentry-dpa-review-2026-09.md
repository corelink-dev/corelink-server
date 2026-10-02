# Vendor Contract-Basis Record — Functional Software, Inc. (Sentry)

> STATUS: RECORDED — owner re-charter of B-316, 2026-10-01 ([#2593](https://github.com/HuGR-dev/corelink-server/issues/2593#issuecomment-5941195884)).
> Sentry is engaged on its own standard online terms and DPA, accepted online
> at account signup. No countersigned copy exists and no acceptance date is
> recorded.

| Field | Value |
|---|---|
| Vendor | Functional Software, Inc. (Sentry) |
| Sub-processor id | `sentry` |
| Contract basis | Sentry's standard online terms and data processing agreement, accepted online by the owner when the account was created (owner statement, #2593 re-charter). No countersigned copy. |
| Terms reference | <https://sentry.io/terms/> |
| DPA reference | <https://sentry.io/legal/dpa/> |
| Online acceptance date | Not recorded. |
| Reviewer | The owner. CoreLink is a single-owner company with no separate Legal/Privacy reviewer (#2593 re-charter). |
| Owner disposition | In the launch sub-processor set the owner chose; see the re-charter comment on #2593. |
| SCC / transfer mechanism | As set out in Sentry's DPA (linked above). |
| Schrems II TIA | None recorded. |
| Data categories processed | telemetry |
| Data residency / region | Not verified for the CoreLink account: the account-selected Sentry data region has not been read back. The registers record United States. |
| Certifications verified | None verified for CoreLink; only Sentry's own public statements exist. |
| Conditions / follow-ups | Record the acceptance date only if an acceptance record (vendor dashboard or acceptance email) is found. Re-read the linked terms and DPA when Sentry announces a change. |
| Next review due | Not scheduled. |

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

This record replaces the earlier `TEMPLATE` packet. VR-7 originally asked for a
dated Legal review and a signed-copy DPA; the owner's re-charter (#2593)
closes it on the public sub-processor list, which names Sentry and links its
standard online terms and DPA. This record claims no signature or other
execution evidence, no named Legal reviewer, no transfer impact assessment, no
certification and no acceptance date. VR-7 is Closed in
`specs/_compliance/VENDOR-RISK-REGISTER.md` §5.

---

*Referenced by `legal/sub-processors.md`. Its contract basis and its agreement
with every public sub-processor list are enforced by the B-316 verifier
(`scripts/verify_b316_pending_vendor_reviews.py`).*
