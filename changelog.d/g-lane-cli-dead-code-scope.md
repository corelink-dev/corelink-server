### Fixed

- **`dead_code` is strict again across `corelink-cli`'s release-contract assertions.**
  The `#[expect(dead_code)]` on the whole `assertions` module also covered any future
  unused helper. It now sits on a never-called wrapper that is the only reference to
  the one retired Rekor helper, so every other item in the module is checked again.
