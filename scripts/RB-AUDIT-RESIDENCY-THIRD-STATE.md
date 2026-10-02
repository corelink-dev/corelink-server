# RB-AUDIT-RESIDENCY-THIRD-STATE — full-population audit residency check

Run the read-only control before a residency attestation or after an audit/DSR
incident. It does not alter D1, audit evidence, tenant rows, or erasure state.

```bash
python3 scripts/verify_audit_residency.py \
  --environment production \
  --database-id "$CORELINK_PROD_D1_DATABASE_ID"
```

`CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` must already be in the
environment. The command neither reads `.env.local` nor writes a secret. For a
reviewable rerun, save the raw API response in an approved restricted evidence
store and use `--input /restricted/path/d1-residency.json`; do not commit it.

## State and exit contract

| State | Exit | Meaning | Operator action |
| --- | ---: | --- | --- |
| `COMPLIANT` | 0 | Every customer row is `satisfied`; every reserved `_public` row has canonical `wnam` region and an allowed public event type. | Archive the JSON output with the change/attestation record. |
| `DOCUMENTED_EXCEPTION` | 0 | No `violated` and no `unevaluable` row, and no owner-attested reference is missing; the only non-satisfied customer rows are `erased_lineage_exception` (#1669 policy B) and/or `owner_attested_prelaunch_test_traffic` (owner attestation, 2026-10-02). | Never attest plain compliance. Attest compliance with the documented exceptions, citing both authorities and reporting `states.erased_lineage_exception`, `states.owner_attested_prelaunch_test_traffic` and `states.violated`. |
| `FAILED` | 1 | At least one known mismatch (`violated`) or unprovable row (`unevaluable`) exists. | Do not attest compliance. Preserve evidence and investigate the named buckets. |
| `INDETERMINATE` | 2 | Credentials, timeout, response shape, control, or full-population partition cannot be trusted. | Restore read access/query health and rerun; never interpret this as zero violations. |

The full denominator is exactly `customer_rows + public_rows`, where
`public_rows = reserved_public_rows + invalid_public_rows`. Customer rows
partition into three disjoint, exhaustive buckets. A customer row is
`satisfied` only when a joined tenant and both canonical regions exist and
are equal. A known unequal pair is `violated`. A missing
tenant, missing region, or malformed/unknown region is `unevaluable`.
Valid `_public` rows are reported separately as `reserved_public_rows`, never
as customer rows or as unexplained customer orphans. An unexpected `_public`
region or event type enters `invalid_public_rows` and `unevaluable_rows`, so it
fails the attestation. `total_rows` equals the three customer buckets plus
`reserved_public_rows` and `invalid_public_rows`; the full `unevaluable_rows`
includes both customer and invalid public rows.

## Mandatory controls

Inspect the JSON `counts` object. It includes the full denominator and each
partition, public-namespace checks, DSR-erasure evidence, unexplained customer
orphan denominator, and `weur` evidence. In production `erasure_log_rows=0`
is indeterminate: without the
control, the tool cannot distinguish retained Art. 5(2) DSR evidence from an
unexplained orphan. `weur_audit_rows > 0` with `weur_tenants=0` must remain
visible through `weur_orphan_rows`; it cannot become a green result.

Erased tenants remain legitimate retained audit evidence. Their residency
cannot be re-proven because their `primary_region` no longer exists. Under the
#1669 **policy B** owner decision (2026-10-01), a customer row whose tenant has
no `tenant` row but does have a `dsr_erasure_log` entry (`erased_orphan_rows`)
is a documented exception: the `states` object reports it as
`erased_lineage_exception`, separately from `unevaluable`. It is never
`satisfied` and never `COMPLIANT`, and it does not by itself fail the check. The
aggregate SQL is unchanged, so the raw `counts.unevaluable_rows` still includes
these rows; `states.unevaluable = unevaluable_rows - erased_orphan_rows` is the
failing bucket. The unexplained-orphan counts stay in `states.unevaluable`
specifically so they cannot disappear from the denominator. The exception
covers only rows with a recorded erasure; it never covers a missing tenant with
no erasure record.

## Owner-attested prelaunch test traffic (row-scoped)

On 2026-10-02 the owner attested that the 13 unexplained historical rows of
#1669 are their own prelaunch test traffic
(<https://github.com/HuGR-dev/corelink-server/issues/1669#issuecomment-5959812722>).
`scripts/i1669_owner_attested_rows.json` records that decision. It holds
exactly 13 row references, each
`sha256("corelink.issue-1669.audit-row-ref.v1" + NUL + audit_outbox.id)`, plus
the authority URL, the decision date and `log_confirmed: false`. No tenant id,
row id or payload is in the repository; the restricted crosswalk stays with
the data owner. The references are **unkeyed** hashes: they do not reveal an
id, but anyone who can guess a candidate id (the id embeds tenant, event type,
digest, principal and time) can confirm it. Treat them as confirmable, not
secret.

The ledger's canonical SHA-256
(`aa62625a9dc979442e356603512968d51e69e9fd61b03ef313cc1d3d24c13cae`) is pinned
in code as `OWNER_ATTESTED_LEDGER_SHA256`. A ledger that differs in any way is
rejected, including a swap of one reference for another valid-looking one;
changing it needs a reviewed code change. Record that digest on #1669 next to
the decision so the authority binds the exact content.

The attestation applies only in the `production` environment against the
production D1 (`d64742ea-e102-40b2-a844-ff02e3f94562`) the decision covers:

- a live `staging`/`test` run, or a `production` run against another database
  id, never reads the residual and never consults the ledger;
- `--residual-refs-input` is refused (exit 2) outside `--environment production`;
- a probe receipt from another database records `attestation: null`;
- the classifier rejects an attestation block on any receipt whose
  `database_id_sha256` is not the production D1's.

`RESIDUAL_REFS_SQL` reads the ids of the unexplained residual. The ids are
hashed in memory and never retained or printed, and a residual of more than 64
rows is indeterminate. The hashed references are matched against the ledger:

- a residual row whose reference is in the ledger is
  `owner_attested_prelaunch_test_traffic`: its own category, not
  log-confirmed, never `COMPLIANT`;
- any other residual row (for example a 14th unexplained row) stays
  `unevaluable` and the check fails;
- a ledger reference absent from the residual is reported as
  `attestation.attested_refs_missing` and the check fails with the reason
  "owner-attested row references are missing…". It is never silently passed.

The verifier applies the attestation only when given the residual read
(`--residual-refs-input` alongside `--input`, or a live `--database-id` read
of the production D1); without it the 13 rows stay `unevaluable`. Changing the
ledger needs a new recorded owner decision and a reviewed change of the pinned
digest; the count of 13 is also pinned in code.

## Offline classification of a retained hosted receipt

The manual #1669 workflow uploads aggregate counts and SHA-256 bindings only;
it does not retain tenant identifiers or row payloads. Classify a downloaded
redacted receipt without Cloudflare credentials:

```bash
python3 scripts/classify_i1669_receipt.py \
  /restricted/path/issue-1669-read-only-receipt.json \
  --sha256 /restricted/path/issue-1669-read-only-receipt.sha256
```

The command validates the artifact checksum, receipt digest, exact receipt and
query schemas, query hashes, tenant-to-row cardinalities, all three population
partitions, and the fail-closed verdict. Its disjoint classes give
every row an aggregate disposition: satisfied, violated, retained DSR orphan,
unexplained orphan, other unevaluable customer row, valid `_public`, or invalid
`_public`. Retained DSR orphans are marked
**`DOCUMENTED_EXCEPTION_ERASED_LINEAGE`** (policy B: preserved, own disposition,
not non-compliant). Unexplained orphans are marked **preserve and require
restricted owner reconciliation**. Neither class is treated as
residency-compliant, and the command cannot assign an individual tenant
identity from aggregate-only evidence. `overall_disposition` is `COMPLIANT`,
`DOCUMENTED_EXCEPTION` (exit 0 for both), or `KEEP_OPEN` (exit 1).

A schema-v2 receipt (`corelink.issue-1669.read-only-residency.v2`) adds the
`residual_refs` query, the hashed residual references and an `attestation`
block. The classifier recomputes the attestation from those references and
the current ledger, and rejects a receipt whose block differs. That covers a
forged count or a receipt bound to another ledger version. Attested rows are
classified `owner_attested_prelaunch_test_traffic` with the
**`DOCUMENTED_EXCEPTION_OWNER_ATTESTED_NOT_LOG_CONFIRMED`** disposition.
Schema-v1 receipts carry no references, so the attestation is never applied to
them.

Each receipt's recorded verdict is verified under the rule it was written
with. Schema v1 predates policy B, so a v1 verdict is checked against the
pre-policy-B rule (every unevaluable row, erased lineage included, is
`FAILED`) and reported exactly as recorded in `source_status`, with
`verdict_rule: pre_policy_b`. The policy-B reading of the same counts appears
separately as `current_policy_status` and never changes `overall_disposition`.
A historical receipt is never upgraded; closure needs a fresh schema-v2
receipt.

Keep the restricted crosswalk and any row-level evidence in the approved
restricted store. Do not rewrite or delete retained audit rows to make the
aggregate green. An unexplained residual remains open until the data owner
records a disposition for every affected tenant and row; any historical repair
requires a separate approved, auditable change.
