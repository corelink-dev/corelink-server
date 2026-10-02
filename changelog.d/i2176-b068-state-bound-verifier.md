### Fixed

- **The #2176 trusted gRPC gate admitted a mixed #2565 BASE.** The gate
  checked the B068 verifier (`scripts/verify_real_ignored_harnesses.py`)
  against the union of every era's digest. Its #2565 endpoint classifier
  skips the wallet-route paths. A BASE with successor endpoints and the
  stale #2792 verifier (294ea6c1) was therefore labelled "successor", and
  `validate_wave(base, base, set())` returned True. The full-group
  classifier calls the same tree partial. The admitted verifier digests are
  now bound to the classified #2565 state:
  - "new" admits only the delivered verifier and its exact #2792 transform;
  - "successor" admits only the reviewed successor.

  A production-path test runs the real `validate_wave` on a hardlinked copy
  of the real tree with two mixed BASEs. It refuses both, and it fails on
  the previous verifier.
