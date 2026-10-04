# PR #9 refusal coverage repair

Baseline: `027a6347c18523d51d1688dd5b1973915c1ba38f`.

## Expected result (recorded before implementation)

The major finding at `live_integration.rs:689` is valid. For every refused
credential, each guarded harness entry point must return an authentication
error without sending even a read request. In particular, Starter product and
price creation and both archive methods must be exercised with valid fixture
arguments, so argument validation cannot hide a missing credential guard.

The behavioral test must assert zero captured requests immediately after each
call. Removing any one pre-request guard in a temporary source copy must fail
that assertion. The source verifier must also reject each independently removed
guard and missing behavioral call, without relying on source digest mismatches.

Local validation uses Python, shell checks and `cargo fmt --all --check` only.
Rust behavior and Rust guard-removal mutations run in the credentialless hosted
PR lane. No local Cargo build, network operation, push or shared stash is used.

## Result and evidence

Fixed: all eight guarded entry points are now called for each of the eight
refused keys, using valid fixture arguments. Each call asserts zero received
requests before checking the authentication error. A 400 mock response bounds
a missing-guard regression without retry backoff. No production method needed
changing: its guard already existed; the defect was missing regression coverage.

The source verifier checks each method's first statement and its assertion in
the refused-key loop independently. Its Stripe mutation suite now includes
eight individual guard removals and eight individual behavioral-call removals,
in addition to the ten existing mutations. Only the Stripe source digest already
owned by this PR was updated; unrelated verifier pins were untouched.

Local results:

- The new source regression tests initially failed with 16 missed mutations.
- `python3 -S -m unittest tests/test_stripe_pre_request_guards.py tests/test_stripe_harness_cleanup_receipt.py`: 9 tests passed, including all 16 source mutations and rejection of compilation errors, zero-test controls and wrong failures as behavioral proof.
- `python3 -S scripts/verify_real_ignored_harnesses.py`: passed the full executor contract and negative mutations, including all 26 Stripe source mutations.
- Removing the verifier fix in a temporary copy reproduced exactly 16 test failures; restoring the original refusal test body in another temporary copy was rejected for missing refusal coverage.
- `cargo fmt --all --check`: passed. No Rust compilation was run locally.
- `python3 -S scripts/assemble_changelog.py --lint changelog.d/i2565-direct-stripe-test-profile.md`: passed. Whole-directory lint found pre-existing malformed fragments outside this change.
- `python3 -S scripts/verify_i1650_real_integration_readiness.py`: valid contract, exit 0; expected `BLOCKED` state for external credentials/resources/cleanup evidence.
- Python syntax validation and `git diff --check`: passed.

Hosted Rust results remain pending. The existing credentialless PR lane now
runs the focused Python suite and a temporary-workspace Rust mutation runner.
The runner requires an unmutated pass, then the exact zero-request behavioral
failure for each removed guard, then a restored pass. It reuses dependency
artifacts and runs Cargo offline. Compilation errors and unrelated test failures
cannot satisfy a mutation. No hosted run was started or observed in this session.

## Commit limitation

The requested named-file staging and `git commit -s` were attempted. Both were
blocked by the sandbox refusing creation of
`/Users/gustavoschneiter/Documents/HuGR/corelink-server/.git/worktrees/agent-a7b4fe7a1ee02900b/index.lock`
with `Operation not permitted`. No commit was created and HEAD remains at the
baseline. The modifications remain in the worktree; a complete patch, commit
message with the requested contiguous trailers, and a named-file commit script
are saved under the authorized campaign directory
`/Users/gustavoschneiter/Documents/HuGR/2026-10-corelink-esteira/gpt/fix/2565-2234/`.
