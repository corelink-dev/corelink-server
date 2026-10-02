### Fixed

- **Two `corelink-server` tests that failed on `main` pass again.** The second
  `rust-affected-tests` run found both. Both fixes are test-only:
  - `gc_binary_wiring` now looks for the `sudo test -x … || { …; exit 1; }` probe that #2762
    put in place of `[ -x … ]`.
  - `money_path_auth_wiring` now provisions the `DPA_ACCEPT_IP_HASH_SALT` that #2852 made
    mandatory for mounting `dpa-accept`.
