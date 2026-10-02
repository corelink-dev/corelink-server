### Added

- **B-127 / #1669: the 13 historical unexplained audit rows get a row-scoped `owner_attested_prelaunch_test_traffic` disposition under the owner's attestation of 2026-10-02 (issue comment 5959812722).**
  The bounded log correlation confirmed none of the 13 rows. The owner then attested that they are their own
  prelaunch test traffic. `scripts/i1669_owner_attested_rows.json` holds exactly 13 row references, each a
  domain-separated SHA-256 of `audit_outbox.id`, plus the authority URL, the decision date and
  `log_confirmed: false`. It holds no tenant id, row id or payload.
  - **Confirmable, not secret:** the references are unkeyed, so someone who can guess a candidate id can
    confirm it.
  - **Pinned:** the ledger's canonical SHA-256 is pinned in code, so any change to it, including a same-count
    reference swap, needs a reviewed code change.
  - **New read:** a bounded allowlisted read, `RESIDUAL_REFS_SQL` (at most 64 rows), returns the residual's
    row ids. The probe hashes them in memory and writes only the references, in receipt schema v2.
  - **Production only:** the attestation applies in the production environment against the production D1 the
    decision covers. Staging and test never read the residual, and `--residual-refs-input` is refused outside
    production. A receipt from another database must carry `attestation: null`.
  - **Exact scope:** a referenced row moves out of `unevaluable` into its own category, never `COMPLIANT`. A
    14th unexplained row still fails. An attested reference that disappeared is reported (`attested_refs_missing`)
    and fails the check.
  - **Classifier:** it recomputes the attestation from the receipt's references and the current ledger instead
    of trusting the probe. v1 receipts never get the attestation.
  - **Evidence:** a one-off read-only check against production on 2026-10-02 matched all 13 references, with 0
    unattested and 0 missing. 138 focal tests pass. All 44 content-matched mutations turn them red: the
    policy-B and attestation logic, each review fix reverted on its own, and each fail-closed residual check.
