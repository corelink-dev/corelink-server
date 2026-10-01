### Fixed

- **`clippy -D warnings` is clean again in six packages.** The new `rust-affected-tests`
  lane's first whole-workspace run found lint failures that had merged while every lint lane
  was off. These were fixed without behavior changes: `corelink-billing-stripe-traits`,
  `corelink-clerk`, `corelink-dpa-acceptance`, `sbom-publish`, `corelink-audit-chain` (test)
  and `corelink-cli` (test). Also removed: `corelink-cli`'s Rekor helper assertion, which has
  had no caller since the Rekor lane was retired.
