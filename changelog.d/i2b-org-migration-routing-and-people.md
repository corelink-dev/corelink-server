### Fixed

- **Org migration I2b: cross-repo fetches, bot-token owner and review routing
  now point at `corelink-dev`.** The server was recreated in `corelink-dev`
  after `HuGR-dev` became unreachable. Two workflows fetched code by an old
  owner name, which anyone could register if the name were ever freed.
  `b251-d03-read-only-probe` now fetches the SHA-pinned D02 producer from the
  repository that runs it, and `pr-601-hosted-spawn-worker-consumer` fetches
  from `corelink-dev/corelink-runners`. That lane fails closed when its URL and
  the repository in its receipt disagree. The five bot-PR creators mint App
  tokens for `owner: corelink-dev`. `verify_bot_pr_auth.py` now reads the owner
  of each mint step and ignores comments. The old substring check accepted a
  live wrong owner hidden behind a commented correct one. `verify_b251_provenance_contract.py`
  now rejects a D02 checkout that names any owner. Each new check has mutation
  tests, and disabling either check turns those tests red. `CODEOWNERS` routes
  its 66 rules to `@gusmhs` instead of the suspended `@gmhelmold`. The dated
  header is kept as history. `dependabot.yml` drops the 12 reviewer entries for
  the `HumanGuardrail/security` team, which never existed. Its PR limit was
  already 0 on all 12 ecosystems, the lowest value. The issue picker's
  advisory and Discussions links, and the subprocessors-sync reviewer request,
  now point at the recreated repository and account.
