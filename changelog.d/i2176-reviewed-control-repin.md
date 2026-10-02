### Fixed

- **The #2176 trusted gRPC gate and the #2574 policy refused every BASE,
  because main no longer matched their pins (gate health F1/F6, #2868).**
  Main had moved 19 of the 54 transport-control pins and the P0
  secrets-matrix pin. It had also moved paths in all four delivery groups,
  so each group matched neither its old nor its new pin. Four #2574 surface
  paths had moved too. The pins are now re-baselined to the bytes of main
  `da2d3f8db`, then re-checked against main `e845feb68`. By then three more
  PRs had moved pinned paths. #2876 moved two #2565 paths: its issue-1650
  path filter and the B068 verifier. #2882 moved eight i1700 paths with its
  V15 probe window, including `durable_object.ts`. #2884 moved the i1700
  deploy workflow again, to swap its deploy token. #2885 and #2886 (main
  `3e7080062`) moved no pinned path. Both verifiers accept that tree,
  merged with this PR, as their own BASE.

  Every moved pin was reviewed first. The per-file ledger is
  `REBASELINE_LEDGER` in `scripts/verify_i2176_grpc_deny_gate.py`: 47 rows,
  one per moved pin. Each row records four things:
  - the PRs that moved the file, from main's first-parent history;
  - its class: 15 rows are transport-reviewed and 32 are not-transport;
  - its disposition, meaning the pin maps re-pinned to the reviewed bytes;
  - the reason the bytes are admitted.

  A row is transport-reviewed when its change runs on a request path into a
  deployed Worker or Container, or decides admission there. It also counts
  when it changes how a credential reaches such a process, including the
  authority that writes it, or when it touches TLS or the gRPC deny. A
  credential that reaches only a CI, test or operator process, or only the
  Cloudflare API, is not-transport, and its reason says so.

  All 47 rows were re-pinned and none was restored, because none adds a gRPC
  admission. Unit tests require the ledger keys to equal the moved pins and
  each disposition to name exactly the maps that moved. A cold review
  (FIX_FIRST) found that credential flow and the authenticated probe path
  had been classed as not-transport. Seven rows moved to transport-reviewed,
  and a unit test pins them with their review records:
  - credential flow, naming source, destination, scope and guards:
    - the i1700 deploy workflow: since #2853 its broker PUTs a temporary
      `CORELINK_ADMIN_AUTH_KEY` into corelink-staging and opens workers.dev;
      #2884 swaps the authority to `CF_API_TOKEN`, which never enters the
      Worker or the Container;
    - `storage.rs`: the Container reads an optional `R2_S3_SESSION_TOKEN`
      into its R2 signer, but the DO's env allowlist never forwards it, so a
      deployed Container keeps static keys;
    - `staging_bootstrap_provider.py` and `staging-quarantine-apply.yml`:
      the B-216 alert bearer goes to the signup Worker only, behind opt-in
      and authority receipts, and the #2176 Worker gains no secret name;
  - probe path, naming path, effect and guards: the probe window JSON,
    `staging_runtime_d1_probe.ts` and `staging_d1_probe_retirement.ts`.
    They run on, or decide admission for, the authenticated
    HTTP -> DO -> Container proof. The V15 window admits a POST only from
    18:00 to 20:00Z on 2026-10-02, and the lifetime ends by 21:15Z.

  Part of that review was kept as not-transport. The harness workflow,
  runner and manifest hand temporary R2 credentials only to a CI cargo-test
  process, never to a deployed Worker or Container. `index_schedule.ts` is
  a cron handler that, since #2853, can only read a receipt.

  The original eight transport-reviewed rows were read against the #2176
  contract:
  - `index_fetch.ts` (#2853) runs the staging D1 proof handler before the
    gRPC deny. The handler answers JSON and never proxies. On the proof path
    it needs staging and admin auth. A gRPC POST gets 400, and an
    authenticated GET reads the proof status. Any other request falls
    through to the unchanged deny. One contract deviation is recorded: on
    `*.workers.dev`, every request except the proof literal gets 404. A
    gRPC request there is therefore denied with 404, not the 503 that the
    contract text names.
  - `Dockerfile` and `durable_object_start.ts` (#2749, #2853, #2858) add a
    staging-only PID-1 supervisor. The final image keeps `USER corelink`,
    port 50051 and the `corelink-server` ENTRYPOINT.
  - `durable_object.ts` adds only early 404/410 denials. #2749, #2773 and
    #2788 reach states that were already pinned.
  - The two `staging_d1_binding_proxy` sources (#2858) add only deadline
    rejections (502).
  - The probe route returns 404 without its validated lifetime.
  - The #2574 checker gains its reviewed surface.

  The historical maps stay unchanged: `WAVE_GROUPS` (old/new), the B068 pair
  `377bcacb`/`294ea6c1`, and the #2574 `EXPECTED` delivery bytes that the
  fixtures prove. The new bytes sit beside them, in
  `WAVE_GROUP_SUCCESSOR_PINS` and `REVIEWED_SURFACE`. The successor bytes
  are a BASE state only. No candidate can move a group into or out of that
  state, and old -> new is still the only admitted transition. New tests run
  on hardlinked copies of the real tree:
  - the baseline accepts itself and ordinary Stripe client maintenance;
  - it refuses an edit to a control, a successor, the matrix, the B068
    verifier, or a new container path;
  - moving any one pin makes the BASE unrecognised.

  Merge note, for a one-time exception to the stale BASE check:
  - Why the exception is needed: the `pull_request_target` check runs the
    BASE verifier, and that verifier is stale. It refuses its own BASE
    ("trusted BASE transport controls do not match actual d2f1 snapshot",
    run 36974457526). By design, it also requires a candidate's verifier
    and tests to equal the BASE bytes. No gate repair can pass that check.
  - Which head to merge: only the reviewed PR head. A commit cannot name
    its own SHA, so the PR comment that records the exception must quote
    it.
  - Evidence required on that head: the `issue 2574 staging gRPC
    diagnostic` run must be green, since it executes this PR's suites.
    Locally, these must pass: both `unittest` suites,
    `verify_i2176_grpc_deny_gate.py --self-test` and
    `verify_i2574_grpc_diagnostic_policy.py --self-test`.
  - Route: while B-315 is open, `--merge` and `--admin` are not used
    (CLAUDE.md). Run the report-only `bash scripts/pre-merge-gate-check.sh
    2868`, record the stale-BASE reason and head SHA in a PR comment, then
    run `gh pr merge 2868 --squash --match-head-commit <head SHA>`. The
    owner or lead decides whether to proceed.
  - If main moves a pinned path first, re-baseline and review it before
    merging. An i1700 probe-window move does this, because the window
    constants live in pinned i1700 paths (the V15 move touched eight).
