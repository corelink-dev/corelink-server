### Changed

- **B-127 / #1669: rows orphaned by a recorded DSR erasure are now classified as their own documented exception (`erased_lineage_exception`) instead of `unevaluable`, under the owner's policy B decision of 2026-10-01.**
  Before this change, the residency verifier failed every population that held one of the 3,526 retained
  Art. 5(2) audit rows of erased tenants. Those rows can never become evaluable, so #1669 could not close
  under any data. `scripts/verify_audit_residency.py` now partitions the full population into `satisfied`,
  `violated`, `erased_lineage_exception`, `unevaluable` and `reserved_public`. A population whose only
  non-satisfied rows are erased lineage reports the distinct status `DOCUMENTED_EXCEPTION` (exit 0), never
  `COMPLIANT`. Unexplained orphans (no tenant row and no erasure record), violations and invalid `_public`
  rows still fail. The three aggregate SQL statements and their query hashes are unchanged. Receipts the
  probe writes move to schema v2, which adds the owner-attestation fields (see the companion fragment).
  Schema-v1 receipts are verified against the rule they were written under (`assess_pre_policy_b`), so
  the retained production receipt 35697251287 still verifies exactly as recorded: `FAILED` / `KEEP_OPEN`.
  The policy-B reading is reported separately as `current_policy_status`. The receipt classifier gives the
  erased class the `DOCUMENTED_EXCEPTION_ERASED_LINEAGE` disposition (report schema v2), and the probe
  exits 0 for the exception.
