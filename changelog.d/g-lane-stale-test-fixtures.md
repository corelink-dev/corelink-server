### Fixed

- **Two `corelink-server` tests that failed on `main` pass again; `corelink-stripe-real`
  is clippy-clean.** The fixes come from the second `rust-affected-tests` run, and all three
  are behavior-free:
  - `gc_binary_wiring` now looks for the `sudo test -x … || { …; exit 1; }` probe that #2762
    put in place of `[ -x … ]`.
  - `money_path_auth_wiring` now provisions the `DPA_ACCEPT_IP_HASH_SALT` that #2852 made
    mandatory for mounting `dpa-accept`.
  - `WebhookDispatcher::emit_audit_and_sli`, a private wrapper with no caller, is removed.
