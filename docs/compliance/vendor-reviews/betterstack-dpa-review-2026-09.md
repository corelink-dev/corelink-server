# Vendor Contract-Basis Record — Better Stack, Inc. (BetterStack / Statuspage)

> STATUS: RECORDED — owner re-charter of B-316, 2026-10-01 ([#2593](https://github.com/HuGR-dev/corelink-server/issues/2593#issuecomment-5941195884)).
> Better Stack is engaged on its own standard online terms and DPA, accepted online
> at account signup. No countersigned copy exists and no acceptance date is
> recorded.

| Field | Value |
|---|---|
| Vendor | Better Stack, Inc. (BetterStack / Statuspage) |
| Sub-processor id | `betterstack` |
| Contract basis | Better Stack's standard online terms and data processing agreement, accepted online by the owner when the account was created (owner statement, #2593 re-charter). No countersigned copy. |
| Terms reference | <https://betterstack.com/terms> |
| DPA reference | <https://betterstack.com/dpa> |
| Online acceptance date | Not recorded. |
| Reviewer | The owner. CoreLink is a single-owner company with no separate Legal/Privacy reviewer (#2593 re-charter). |
| Owner disposition | In the launch sub-processor set the owner chose; see the re-charter comment on #2593. |
| SCC / transfer mechanism | As set out in Better Stack's DPA (linked above). |
| Schrems II TIA | None recorded. |
| Data categories processed | telemetry |
| Data residency / region | European Union |
| Certifications verified | None verified for CoreLink; only Better Stack's own public statements exist. |
| Conditions / follow-ups | Record the acceptance date only if an acceptance record (vendor dashboard or acceptance email) is found. Re-read the linked terms and DPA when Better Stack announces a change. |
| Next review due | Not scheduled. |

## Repository-verified technical and data-flow scope

- **Role:** uptime/status monitoring, synthetic probes, and public status page
  hosting.
- **Runtime flow:** `monitoring/synthetic/probes.yml` defines seven HTTP health
  probes against CoreLink's own public endpoints. The docs StatusPill fetches
  the vendor status page's `index.json` with `GET` and `credentials: omit`,
  then renders status data; it does not send visitor data, cookies, or
  fingerprints to the vendor.
- **Data boundary:** probe results are HTTP status codes and JSON assertions;
  the repository classifies this stream as `telemetry` and records no customer
  PII or content transfer.
- **Repository sources:** `monitoring/synthetic/probes.yml`,
  `apps/docs/src/components/StatusPill/StatusPill.tsx`,
  `apps/docs/src/statuspage-url.ts`, and registry row 22 in
  `specs/_compliance/VENDOR-RISK-REGISTER.md`.

## Notes

This record replaces the earlier `TEMPLATE` packet. VR-9 originally asked for a
dated Legal review and a signed-copy DPA; the owner's re-charter (#2593)
closes it on the public sub-processor list, which names Better Stack and links its
standard online terms and DPA. This record claims no signature or other
execution evidence, no named Legal reviewer, no transfer impact assessment, no
certification and no acceptance date. VR-9 is Closed in
`specs/_compliance/VENDOR-RISK-REGISTER.md` §5.

---

*Referenced by `legal/sub-processors.md`. Its contract basis and its agreement
with every public sub-processor list are enforced by the B-316 verifier
(`scripts/verify_b316_pending_vendor_reviews.py`).*
