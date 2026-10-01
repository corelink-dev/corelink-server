### Fixed

- **The read-only staging preflight failed with an empty receipt whenever the
  staging Workers already existed (#2167, #1700, run 36912429001).** The
  read-only workflow now passes `--existing-worker-plan`. When all three
  canonical Workers exist, the preflight reads only their secret names and
  reports, for each Worker, the names already set and the names still missing.
  It points to `update-existing-secrets` as the next step, never reads or
  prints a secret value, and does not recreate any Worker. It still refuses
  ambiguous states: only some of the Workers present, unapproved secret names,
  a partial B-216 pair, a shared secret set on only one Worker, or a malformed,
  duplicate or unreadable inventory. A malformed Worker listing no longer
  counts as "no Workers exist". The quarantine-apply create gate runs without
  the flag and still refuses existing Workers.
