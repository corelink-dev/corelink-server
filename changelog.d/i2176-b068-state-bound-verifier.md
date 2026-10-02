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

- **The trusted gates now carry and pin #2889's D1 request-forgery fix
  (Refs #1674).** `crates/corelink-container/src/storage/d1_http.rs` is a
  transport control, so no PR can change it alone without leaving main's
  BASE unrecognised. This change carries the exact head bytes of #2889
  (`a4f53cf`, `8db50a72`) and moves every current pin with them:
  - `WAVE_BASE_CONTROLS`;
  - the B068 `SOURCE_SHA256`;
  - a new `STAGING_D1_PROXY_SOURCE_I1674_SHA256`, which the hosted-runner
    topology now binds. Reverting only the Rust file therefore fails;
  - the i2565 successor pin of the B068 verifier;
  - the literal in `tests/test_backlog_verify_trust_boundary.py`.

  The historical transition maps keep their bytes: the #1700 proxy target,
  the #1678 base-control snapshots in `backlog_verify.py`, and the #2574
  verifier. The ledger row now classes `d1_http.rs` as transport-reviewed
  (credential flow): the new URL builder decides where the
  `CF_API_TOKEN` bearer is sent.
