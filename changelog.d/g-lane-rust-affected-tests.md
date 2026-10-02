### Added

- **A general Rust PR lane runs again, on GitHub-hosted runners.** `rust-affected-tests`
  runs `cargo clippy --all-targets -D warnings` and `cargo test --tests --bins --examples` on
  `ubuntu-24.04` for the packages a change can break. Selection comes from `cargo metadata`:
  each changed path's owning package, its reverse-dependency closure, packages whose tests
  dev-depend on that closure, and an entry-by-entry `Cargo.lock` diff. Toolchain, cargo
  configuration and lane changes select the whole workspace; the lane's own files include
  its teeth file and its clippy baselines. The test job is split into three matrix shards,
  and the job timeouts bound the critical path at 22 minutes, under the lane's 25-minute
  budget. A single verdict job fails when a selection error or a skipped job could
  otherwise read as a pass. The test job's `SKIP_TESTS` ledger holds tests that cannot pass
  under the lane's `PROPTEST_CASES`; every other test must pass. The clippy job's
  `CLIPPY_DEBT` ledger takes `corelink-server` out of the `-D warnings` run, because its
  lint backlog on `main` touches files whose hashes other gates pin. Instead its
  diagnostics are compared one by one with a reviewed baseline in
  `.github/rust-affected-tests/clippy-debt/`. A diagnostic the baseline does not list turns
  the lane red, even when a listed one was fixed in the same change, and a fixed one stays
  red until the baseline drops it.
