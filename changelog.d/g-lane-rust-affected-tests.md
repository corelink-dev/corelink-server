### Added

- **A general Rust PR lane runs again, on GitHub-hosted runners.** `rust-affected-tests`
  runs `cargo clippy --all-targets -D warnings` and `cargo test --tests --bins --examples` on
  `ubuntu-24.04` for the packages a change can break. Selection comes from `cargo metadata`:
  each changed path's owning package, its reverse-dependency closure, packages whose tests
  dev-depend on that closure, and an entry-by-entry `Cargo.lock` diff. Toolchain, cargo
  configuration and lane changes select the whole workspace; the lane's own files include
  its teeth file and any clippy-debt baseline. The test job is split into three matrix shards,
  and the job timeouts bound the critical path at 22 minutes, under the lane's 25-minute
  budget. A single verdict job fails when a selection error or a skipped job could
  otherwise read as a pass. The test job's `SKIP_TESTS` ledger holds tests that cannot pass
  under the lane's `PROPTEST_CASES`; every other test must pass. `-D warnings` applies to
  every selected package. The clippy job's `CLIPPY_DEBT` ledger, which would hold a
  package to a reviewed baseline diagnostic by diagnostic instead, is empty: an entry
  narrows the gate and needs the owner's explicit scope amendment. `corelink-server`
  fails both jobs today, so the lane is red whenever it is selected until those failures
  are fixed or the scope is amended. Its strict clippy run fails in nine source files that
  other gates pin, freeze or bind to reviewed CodeQL alerts, and on one production slice
  in a tenth file, whose fix would change behavior. Its B-126 test fails because `main.rs` has 1047 lines
  against a 1000-line ceiling. The workflow header lists each failure and why this lane
  leaves it unfixed.
