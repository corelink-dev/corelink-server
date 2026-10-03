### Fixed

- **Workflow guards no longer bind to the suspended `HuGR-dev` repository (org migration I2a).**
  The move to `corelink-dev` recreates the server repository under a new numeric ID. Every
  job gated on `github.repository == 'HuGR-dev/corelink-server'` or
  `github.repository_id == '1232040291'` would therefore have skipped forever, and a skipped
  job looks green.
  - **Two guard forms (migration PLAN section 4.1).** The 73 unpinned guarded workflows now use one of them:
    - routine lanes (52) use `github.repository_id == vars.CORELINK_SERVER_REPO_ID`. An unset
      variable makes the guard false.
    - privileged lanes (24: a job with `environment:` or `id-token: write`) carry a literal
      ID. The new `scripts/sync_workflow_repository_guards.py --write` renders it from
      `config/github-identity.json`. Until the ID is read back the literal is `'0'`, which
      matches no repository, and `--check` refuses it.
  - **Name guards and shell repository comparisons are gone.**
  - **Production deploy lanes.** `admin-ui-deploy`, `docs-deploy` and `signup-worker-deploy`
    deployed production on every push to `main` with no guard. They now require the server
    repository, protected `main` and the `production` environment.
  - **Clone-only lanes.** `sbom-clone-bundle` and `i1629-effect-ledger-sql` were pinned to the
    clone-only ID `1380335483` and could never run on the canonical repository. Both are
    repointed. The SBOM lane also drops a step that ran a script that was never committed.
  - **Lockstep verifiers and tests** move in the same change.
  - **Not in this change.** Workflows whose guard text is sha256-pinned or blob-pinned stay in
    the checker's ledger for the coupled re-pin (I3 and I6).
