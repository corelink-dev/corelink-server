### Fixed

- **B-126's line-ceiling test passes on `main` again without hiding new breaches.**
  `crates/corelink-container/src/main.rs` is 1047 lines against the 1000-line ceiling,
  and other gates pin its hash, so it carries a declared bound of 1047 inside the test
  instead. It may not grow, and the bound must come down when it shrinks. Every other file
  in the list is still held under 1000 lines, and the test now reports every breach, not
  only the first it meets. The `rust-affected-tests` lane no longer needs to keep the test
  in an expected-failure ledger, where any new breach would have passed as the old one.
