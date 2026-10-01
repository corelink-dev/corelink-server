### Added

- **A general Rust PR lane runs again, on GitHub-hosted runners.** `rust-affected-tests`
  runs `cargo clippy --all-targets -D warnings` and `cargo test --tests --bins --examples` on
  `ubuntu-24.04` for the packages a change can break. Selection comes from `cargo metadata`:
  each changed path's owning package, its reverse-dependency closure, packages whose tests
  dev-depend on that closure, and an entry-by-entry `Cargo.lock` diff. Toolchain, cargo
  configuration and lane changes select the whole workspace. A single verdict job fails
  when a selection error or a skipped job could otherwise read as a pass. Two declared
  ledgers sit in the test job: `SKIP_TESTS` for tests that cannot pass under the lane's
  `PROPTEST_CASES`, and `KNOWN_FAILING` for real failures on `main`. Each `KNOWN_FAILING`
  entry is run on its own and must still fail, so a fix turns the lane red until its entry
  is deleted. A third ledger, `CLIPPY_DEBT` in the clippy job, takes `corelink-server`
  out of the `-D warnings` run, because its lint backlog on `main` is too large to fix in
  this change. A ratchet counts the package's distinct diagnostics with lints capped at
  warn. Any new diagnostic turns the lane red, and so does a fix until the declared count
  is lowered.
