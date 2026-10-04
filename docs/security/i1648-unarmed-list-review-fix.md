# #1648 cold-review correction: unarmed list refusal

## Expected result (recorded before implementation)

The major finding is valid: CAS and AC list enter `acquire_byok_data`, but
the no-runtime-gate return bypasses the unarmed config snapshot.

Every private CAS/AC operation must check the attached unarmed config view
before a context or absent-runtime-gate return can permit storage access.
An active (convergent or random), partial, pending or shredded tenant must
receive an internal/fail-closed error. Parse and transport failures must also
refuse access. Both list implementations must dispatch zero R2 calls on these
errors, including requests with a pagination cursor. Missing and inactive
configurations retain successful plaintext listing. Public listing must remain
available even when the config source fails. Armed handlers keep their existing
runtime gate and catalog behavior.

## Validation plan

- Add Rust regressions calling the production CAS/AC attachment helpers and
  list traits, with the existing storage dispatch recorder. Assert the refusal
  reason and zero calls; assert successful dispatch for permitted configurations.
- Run a focused Python source-wiring regression locally: both list paths must
  propagate the unarmed check before storage dispatch. Revert each handler's
  fix independently in a temporary copy and require a nonzero test exit.
- Run `cargo fmt --all --check` only. Rust behavioral execution and compilation
  belong to the hosted PR lane; no local Rust build is permitted for this fix.

The source-wiring mutation is evidence of wiring coverage, not a claim that
the Rust behavioral tests ran locally.

## Results

- Finding: **fixed**. Both handlers now consult the shared unarmed config
  cache at entry to `acquire_byok_data`, before context or missing-gate exits.
  Both existing list paths propagate that refusal before R2 enumeration.
- Initial local regression before the fix: four tests, three failures (CAS
  entry, AC entry and the missing shared check); list-entry wiring passed.
- `python3 tests/test_i1648_unarmed_storage_gate.py -v`: five tests passed.
  Temporary-copy mutations independently reverted the CAS and AC entry checks,
  swallowed config-source errors, and allowed engaged tenants. All four were
  killed: each child run failed exactly one of the four wiring checks.
- `cargo fmt --all --check`: passed. `git diff --check`: passed. The new
  included Rust test block was also formatted with rustfmt in a temporary file.
- Rust regressions added: `unarmed_lists_refuse_engaged_and_unreadable_config_before_r2`
  covers 40 CAS/AC refusals across both crypto modes, every engaged state,
  parse/transport errors, and first/continuation pages, with zero R2 dispatch.
  `unarmed_lists_allow_missing_inactive_and_public_config` covers six permitted
  CAS/AC listings. These tests await the hosted PR lane; no local Rust build ran.
- Additional regression command:
  `python3 -m pytest -q tests/test_i1648_unarmed_storage_gate.py tests/test_verify_b083_byok.py tests/test_verify_b087_questionnaires.py tests/test_verify_b154_instrument_claims.py`.
  Result: 64 passed, four failed, six subtests passed. The four existing failures
  are B-083's fixture omitting the imported `verify_b086_d1_residency` module;
  B-087's live population mismatch (BYOK receipt, active fuzz schedule and SIG
  K.10 copy); B-087's missing parked-schedule mutation anchor; and B-154's stale
  B-086 provider readback (24-hour limit). The 25 relevant guard, fixture and
  source-control files were checked byte-for-byte against pre-fix HEAD and are
  unchanged. No verifier pins or external evidence were changed.
- Commit blocked by the session filesystem sandbox: `git add` could not create
  `.git/worktrees/agent-af21108c5957bdd21/index.lock` (`Operation not permitted`).
  No files were staged and no commit was created. HEAD remains
  `fd8c4a4c8cdc12729104bb2607eb2bc41dab4a4e`; changes are preserved in the worktree.
