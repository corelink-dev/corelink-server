### Fixed

- **#2165 image-build spend admission no longer requires a fabricated actual.** One
  validator now admits on either a receipt-backed actual (unchanged arithmetic) or a
  complete, itemised, receipt-bound upper bound with `actual_usd` left null, under the
  $20 cap and $5 reserve counted once. Unknown units, open-ended lifetimes, missing
  cleanup, duplicate or ambiguous operations, a zero actual, and bound/sum or
  units-times-price mismatches each deny with a named reason.
