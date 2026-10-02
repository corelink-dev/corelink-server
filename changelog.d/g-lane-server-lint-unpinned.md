### Fixed

- **Fixed the `corelink-server` clippy failures in files that no other gate pins or
  scopes.** The fixes touch 14 files and change no behavior. Test modules that index,
  unwrap or panic now carry the crate's usual test `allow`. `is_none_or`, stable only
  since Rust 1.82 against the workspace's 1.80 MSRV, became `map_or(true, …)`. An import
  only a test used moved into that test, a needless borrow went, a test helper's return
  type got an alias, and three unused test-only accessors were deleted. The
  `CAS_LOCK_SHARDS` lower bound in its test is now checked at compile time. Three
  exceptions are scoped `#[expect]`s with a written reason, so each fails the lint run
  once its reason is gone: one `too_many_arguments` signature, and the `ActionCache`
  validator and its test fixture, which read and fill REAPI's deprecated symlink lists
  that v2.0 clients still send. The files still red are listed under EXPOSED FAILURES in
  `rust-affected-tests.yml`.
