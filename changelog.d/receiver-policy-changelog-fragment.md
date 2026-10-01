### Fixed

- **DSR-receiver PRs could not satisfy `changelog-validate` and the receiver
  path boundary at the same time (#2574 policy, seen on #2861).**
  `changelog-validate` requires every `feat:`/`fix:` PR to ADD a
  `changelog.d/` fragment, while `verify_i2574_grpc_diagnostic_policy.py
  --check-receiver-path-boundary` refused every path outside the receiver set,
  so a receiver fix failed one gate whichever way it was written. The boundary
  now admits exactly one more shape: an ADDED, flat fragment matching
  `^changelog\.d/[a-z0-9][a-z0-9._-]*\.md$`, never `changelog.d/README.md`.
  Added-ness is read from `git diff --diff-filter=A`; a modified or deleted
  fragment, a nested or dotted path, and `CHANGELOG.md` stay foreign. Two new
  tests (one of them end-to-end against a real git history) cover the shape,
  and the SHA-256 pins on the verifier and its test in `campaign-ci.yml` and
  `verify_i2176_grpc_deny_gate.py` move to the new bytes.
