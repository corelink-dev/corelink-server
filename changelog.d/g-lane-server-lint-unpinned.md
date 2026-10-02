### Fixed

- **Fixed the `corelink-server` clippy failures in files that no other gate pins.** The
  fixes touch 16 files and change no behavior. Test modules that index, unwrap or panic
  now carry the crate's usual test `allow`. Three `rows.len() != 1` guards followed by
  `rows[0]`, in the staging BYOK teardown and tenant lookup, are now one `let [row]`
  pattern returning the same error. `is_none_or`, stable only since Rust 1.82 against the
  workspace's 1.80 MSRV, became `map_or(true, …)`. An import only a test used moved into
  that test, two needless borrows went, and three unused test-only accessors were
  deleted. The `CAS_LOCK_SHARDS` lower bound in its test is now checked at compile time.
  Five exceptions are scoped `#[expect]`s with a written reason, so each fails the lint
  run once its reason is gone. Two cover `too_many_arguments` signatures. Two cover the
  `ActionCache` validator and its test fixture, which read and fill REAPI's deprecated
  symlink lists that v2.0 clients still send. The fifth is `dead_code` on the staging
  BYOK activation path, which only tests call. The files still red are listed under
  EXPOSED FAILURES in `rust-affected-tests.yml`.
