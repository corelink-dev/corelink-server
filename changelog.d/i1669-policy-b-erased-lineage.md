### Changed

- **B-127 / #1669: rows orphaned by a recorded DSR erasure are now classified as their own documented exception (`erased_lineage_exception`) instead of `unevaluable`, under the owner's policy B decision of 2026-10-01.**
  Before this change, the residency verifier failed every population that held one of the 3,526 retained
  Art. 5(2) audit rows of erased tenants. Those rows can never become evaluable, so #1669 could not close
  under any data. `scripts/verify_audit_residency.py` now partitions the full population into `satisfied`,
  `violated`, `erased_lineage_exception`, `unevaluable` and `reserved_public`. A population whose only
  non-satisfied rows are erased lineage reports the distinct status `DOCUMENTED_EXCEPTION` (exit 0), never
  `COMPLIANT`. Unexplained orphans (no tenant row and no erasure record), violations and invalid `_public`
  rows still fail. The read-only aggregate SQL, its query hashes and the receipt schema are byte-identical,
  so the retained production receipt 35697251287 still verifies. It still classifies as `FAILED` /
  `KEEP_OPEN` on its 13 unexplained rows. The receipt classifier gives the erased class the
  `DOCUMENTED_EXCEPTION_ERASED_LINEAGE` disposition (report schema v2), and the probe exits 0 for the
  exception. Eleven content-matched mutations of the new logic each turn the focused suites red.
