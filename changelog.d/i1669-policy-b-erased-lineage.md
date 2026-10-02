### Changed

- **B-127 / #1669: rows orphaned by a completed DSR erasure are now classified as their own documented exception (`erased_lineage_exception`) instead of `unevaluable`, under the owner's policy B decision of 2026-10-01.**
  Before this change, the residency verifier failed every population that held one of the 3,526 retained
  Art. 5(2) audit rows of erased tenants. Those rows can never become evaluable, so #1669 could not close
  under any data. `scripts/verify_audit_residency.py` now partitions the full population into `satisfied`,
  `violated`, `erased_lineage_exception`, `unevaluable` and `reserved_public`. A population whose only
  non-satisfied rows are erased lineage reports the distinct status `DOCUMENTED_EXCEPTION` (exit 0), never
  `COMPLIANT`.
  - **Narrowed definition:** a row counts as erased lineage only when its tenant's D1 erasure completed, that
    is a `dsr_erasure_log` entry with `backend = 'd1' AND outcome = 'erased'`. Before, any erasure-log entry
    counted.
  - **Excluded:** `partial_failure`, `failed`, `pseudonymized`, an unknown value, NULL and other backends' outcomes never
    qualify. Neither does `d1`'s `not_applicable`, which means a legal hold preserved the data. Those rows
    stay `unevaluable`.
  - **No row lost:** a read-only production check on 2026-10-02 found all 3,526 rows covered.
  - **Still failing:** unexplained orphans, violations and invalid `_public` rows.
  - **Receipts:** query hashes are pinned per receipt schema. Schema-v1 receipts are verified against the v1
    queries and the pre-policy-B rule (`assess_pre_policy_b`), so the retained production receipt 35697251287
    still verifies exactly as recorded: `FAILED` / `KEEP_OPEN`. It is not re-judged under the narrowed
    policy. Probe receipts are schema v2.
  - **Classifier:** gives the v2 erased class the `DOCUMENTED_EXCEPTION_ERASED_LINEAGE` disposition, and the
    probe exits 0 for the exception.
