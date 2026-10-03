### Fixed

- **B-154 is done: its prelaunch Object Lock and BYOK claims now match proven capability (#1676).**
  Both provider rows reached a terminal outcome, and both end in a narrowed launch claim, not
  in a promoted capability. #1646 closed on 2026-09-30 through #2808, with one accepted
  nonproduction synthetic AWS S3 version (`accepted-aws-target.json`, sha256 `0bec97b7…`). On
  2026-10-01 the owner accepted the BYOK fail-closed limitation that #2807 shipped.
  `prelaunch-claim-resolution.json` now records `DONE_PRELAUNCH_CLAIMS_MATCH_PROVEN_CAPABILITY`
  and pins both outcomes. `provider_chains_closed` stays `false`, because #1653/#2165 continue
  as product hardening. B-154 moves to `done`/`tl` in `BACKLOG.md` and in the owner-action
  packet, and both verifiers now enforce that terminal record.
  The `verify` joins its two commands with `&&`. Before this change, a failing packet check was
  masked by the exit status of the claims check that ran after it.
- **The B-154 guard no longer decays on the wall clock.** Before this change it ran B-086's
  24-hour D1 readback freshness window, so it failed on `main` 24 hours after the
  2026-09-30 readback, with no byte changed. B-154 now binds that exact receipt by hash
  (`max_age=None`), while every content check still runs and naive or future timestamps are
  still rejected. B-086 keeps its own 24-hour freshness gate.
