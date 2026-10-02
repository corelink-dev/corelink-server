### Fixed

- **A committed clippy-debt baseline can no longer admit a new diagnostic.** The
  `rust-affected-tests` baseline step used to trust the baseline in the change under
  test, so a change that added a clippy warning to a ledger package passed once it
  also committed the regenerated baseline. `scripts/rust_clippy_debt.py` now also
  receives the same baseline file as committed at the base revision. The committed
  baseline must be a sub-multiset of it: an entry the base does not list, or lists
  fewer times, is red. The one exception is a declared bootstrap, when the base
  revision has no baseline for the package at all, and that run prints a warning.
  The ratchet also runs for a ledger package the change did not select.
