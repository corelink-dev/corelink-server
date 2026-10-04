# PR #3 cold-review acceptance criteria

Written before implementation on 2026-10-03.

- Delayed RPC: a POST accepted by the HTTP handler in its scheduled two-minute
  bucket must be rejected at DO entry if delivery crosses that bucket. Rejection
  must precede durable claim, lifetime alarm, cleanup and native execution.
  Admission at the last millisecond of the bucket remains valid, with its kill
  deadline before the broker's scheduled + 23-minute cutoff. A delayed-RPC test
  must exercise the real handler, DO, broker cleanup and Python rollback gate.
- Failure custody: runtime rollback must install its EXIT/TERM custody handler
  before any preliminary read. A route, deployment, ownership or first-quiescence
  failure must preserve the failure outcome, attempt only broker-owned workers.dev
  cleanup, withhold Worker/Container restoration and emit a sanitized residual.
  Cleanup refusal must also emit a residual. Restoration remains gated on route,
  ownership, quiescence and cleanup success; a failed second gate withholds it.

Verification requires focused tests and reverting each production fix in a
separate temporary copy to demonstrate that its regression test fails. No shared
stash, provider calls, cargo builds, network, push or pinned-verifier edits.

## Results

Both major findings are fixed; neither was rejected. Independent cold diff review
returned APPROVE with no remaining major or blocker findings.

- Worker: `durable_object`, `staging_d1_http`, `staging_d1_http_lifetime` and
  `staging_d1_http_lifecycle` focused suites: 172 tests passed.
- Node: HTTP bootstrap, HTTP probe, runtime probe and probe-window suites:
  180 tests passed with six socket/process-dependent cases excluded.
- Python: rollback quiescence and executable workflow failure-injection tests:
  23 tests passed with one Unix-socket case excluded.
- Worker `tsc --noEmit`, `cargo fmt --all --check`, runtime rollback `bash -n`
  and `git diff --check`: passed. No Rust compilation was run.
- Admission mutation: restored the pre-fix DO file in a temporary copy. All
  three delayed-RPC cases failed (HTTP 200 instead of 503); the last-millisecond
  positive boundary test passed.
- Custody mutation: restored the pre-fix workflow in a separate temporary copy.
  Three regression tests failed with seven failure assertions: early cleanup
  was skipped or the residual receipt was absent.

The initial unrestricted suites encountered sandbox EPERM on local sockets and
process inspection; the selected suites exclude those cases without changing
or disabling tests in source. Mutation copies used no stash. Validation logs
are retained locally under `/tmp/i1700-review-validation/`.
