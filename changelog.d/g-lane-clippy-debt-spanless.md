### Fixed

- **The clippy-debt comparison no longer drops a warning that has no primary span.**
  `scripts/rust_clippy_debt.py` skipped every diagnostic without one as if it were
  rustc's "N warnings emitted" summary, so a crate-level lint such as
  `clippy::multiple_crate_versions` passed beside unchanged debt. Now it drops only
  rustc's exact end-of-crate summaries, and only when they have no span and no lint
  code. Any other diagnostic without a primary span is compared by its lint code and
  message, like every other entry.
