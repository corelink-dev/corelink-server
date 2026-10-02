### Added

- **B-127 / #1669: the 13 historical unexplained audit rows get a row-scoped `owner_attested_prelaunch_test_traffic` disposition under the owner's attestation of 2026-10-02 (issue comment 5959812722).**
  The bounded log correlation confirmed none of the 13 rows. The owner then attested that they are their own
  prelaunch test traffic. `scripts/i1669_owner_attested_rows.json` holds exactly 13 opaque references, each a
  domain-separated SHA-256 of `audit_outbox.id`, plus the authority URL and `log_confirmed: false`. It holds no
  tenant id, row id or payload. A new bounded allowlisted read, `RESIDUAL_REFS_SQL` (at most 64 rows), returns
  the residual's row ids. The probe hashes them in memory and writes only the references, in receipt schema v2.
  A referenced row moves out of `unevaluable` into its own category, never `COMPLIANT`. A 14th unexplained row
  still fails. An attested reference that disappeared is reported (`attested_refs_missing`) and fails the check.
  The classifier recomputes the attestation from the receipt's references and the current ledger instead of
  trusting the probe. v1 receipts never get the attestation. A one-off read-only check against production
  today matched all 13 references, with 0 unattested and 0 missing. 117 focal tests pass, and all 28
  content-matched mutations of the policy-B and attestation logic turn them red.
