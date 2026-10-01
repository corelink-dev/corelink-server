### Added

- **A general Rust PR lane runs again, on GitHub-hosted runners.** `rust-affected-tests`
  runs `cargo clippy --all-targets -D warnings` and `cargo test --all-targets` on
  `ubuntu-24.04` for the packages a change can break. Selection comes from `cargo metadata`:
  each changed path's owning package, its reverse-dependency closure, packages whose tests
  dev-depend on that closure, and an entry-by-entry `Cargo.lock` diff. Toolchain, cargo
  configuration and lane changes select the whole workspace. A single verdict job fails
  when a selection error or a skipped job could otherwise read as a pass.
