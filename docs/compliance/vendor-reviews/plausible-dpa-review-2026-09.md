# Vendor Contract-Basis Record — Plausible Insights OÜ (Plausible Analytics)

> STATUS: RECORDED — owner re-charter of B-316, 2026-10-01 ([#2593](https://github.com/HuGR-dev/corelink-server/issues/2593#issuecomment-5941195884)).
> Plausible is engaged on its own standard online terms and DPA, accepted online
> at account signup. No countersigned copy exists and no acceptance date is
> recorded.

| Field | Value |
|---|---|
| Vendor | Plausible Insights OÜ (Plausible Analytics) |
| Sub-processor id | `plausible` |
| Contract basis | Plausible's standard online terms and data processing agreement, accepted online by the owner when the account was created (owner statement, #2593 re-charter). No countersigned copy. |
| Terms reference | <https://plausible.io/terms> |
| DPA reference | <https://plausible.io/dpa> |
| Online acceptance date | Not recorded. |
| Reviewer | The owner. CoreLink is a single-owner company with no separate Legal/Privacy reviewer (#2593 re-charter). |
| Owner disposition | In the launch sub-processor set the owner chose; see the re-charter comment on #2593. |
| SCC / transfer mechanism | As set out in Plausible's DPA (linked above). |
| Schrems II TIA | None recorded. |
| Data categories processed | telemetry |
| Data residency / region | European Union |
| Certifications verified | None verified for CoreLink; only Plausible's own public statements exist. |
| Conditions / follow-ups | Record the acceptance date only if an acceptance record (vendor dashboard or acceptance email) is found. Re-read the linked terms and DPA when Plausible announces a change. |
| Next review due | Not scheduled. |

## Repository-verified technical and data-flow scope

- **Role:** cookieless web analytics for the docs-site marketing funnel.
- **Runtime flow:** `apps/docs/docusaurus.config.ts` injects the external
  `https://plausible.io/js/script.js` with `data-domain:
  corelink-docs.humangr.com`. The repository records this as aggregate page
  view telemetry and documents the no-cookie/no-fingerprinting configuration.
- **Optional server flow:** `apps/analytics-worker/wrangler.toml` declares
  `PLAUSIBLE_API_KEY` as an optional secret for the weekly digest; absence of
  that secret omits Plausible totals rather than failing the cron path.
- **Repository sources:** `apps/docs/docusaurus.config.ts`,
  `apps/analytics-worker/wrangler.toml`, and registry row 21 in
  `specs/_compliance/VENDOR-RISK-REGISTER.md`.

## Notes

This record replaces the earlier `TEMPLATE` packet. VR-8 originally asked for a
dated Legal review and a signed-copy DPA; the owner's re-charter (#2593)
closes it on the public sub-processor list, which names Plausible and links its
standard online terms and DPA. This record claims no signature or other
execution evidence, no named Legal reviewer, no transfer impact assessment, no
certification and no acceptance date. VR-8 is Closed in
`specs/_compliance/VENDOR-RISK-REGISTER.md` §5.

---

*Referenced by `legal/sub-processors.md`. Its contract basis and its agreement
with every public sub-processor list are enforced by the B-316 verifier
(`scripts/verify_b316_pending_vendor_reviews.py`).*
