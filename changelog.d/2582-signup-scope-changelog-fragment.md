### Fixed

- **The #2582 signup-ownership change-scope gate refused the changelog fragment
  that `changelog-validate` requires.** `verify_issue_2582_signup_ownership.py`
  failed every path outside its fixed signup set, so a `fix:`/`feat:` signup
  writer PR could not pass both gates. The scope check now admits exactly one
  more shape, the same rule #2862 gave the DSR receiver: an ADDED, flat
  fragment matching `^changelog\.d/[a-z0-9][a-z0-9._-]*\.md$`, never
  `changelog.d/README.md`, with added-ness read from `git diff
  --diff-filter=A`. Modified or deleted fragments, nested paths, `CHANGELOG.md`
  and every other path stay out of scope. An empty changed-path list is now a
  named failure instead of a silent pass. The new teeth tests (9, four of them
  against a real git history) run in the workflow before the scope check.
