### Fixed

- **Fixed the `clippy --all-targets -D warnings` failures that merged while every lint
  lane was off.** The new `rust-affected-tests` lane found them one dependency layer at a
  time. None of the fixes changes behavior:
  `corelink-billing-stripe-traits`, `corelink-billing-stripe-materializer` and
  `corelink-clerk` (signature lints), `corelink-stripe-real` (a private wrapper with no
  caller removed), `sbom-publish` (item order), and the test targets of
  `corelink-dpa-acceptance`, `corelink-audit-chain`, `corelink-cli` and `corelink-billing`.
  Two exceptions are scoped `#[expect]`s with a written reason, because the exact source is
  pinned elsewhere. The first is `corelink-cli`'s unused Rekor helper, which only a
  closed-world gate's own PR may delete. The second is the B-251 nearest-rank p99
  expression that `verify_b251_quota_cas_budget.py` checks verbatim. Each `#[expect]`
  fails the lint run once its reason is gone.
