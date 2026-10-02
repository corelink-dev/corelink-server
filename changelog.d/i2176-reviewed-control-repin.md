### Fixed

- **The #2176 trusted gRPC gate and the #2574 policy refused every BASE,
  because main no longer matched their pins (gate health F1/F6, #2868).**
  Main had moved 19 of the 54 transport-control pins and the P0
  secrets-matrix pin. It had also moved paths in all four delivery groups,
  so each group matched neither its old nor its new pin. Four #2574 surface
  paths had moved too. The pins are now re-baselined to the bytes of main
  `da2d3f8db`, and both verifiers accept that tree as its own BASE. Every
  moved pin was reviewed first: 47 rows in `REBASELINE_LEDGER`
  (`scripts/verify_i2176_grpc_deny_gate.py`), each naming the PRs that
  moved the file, a transport class and the reason. Eight rows touch the
  request path and were read against the #2176 contract:
  - `index_fetch.ts` (#2853) runs the staging D1 proof handler before the
    gRPC deny. It returns JSON only and never proxies. It does not admit a
    gRPC POST (400), and every other request falls through to the
    unchanged deny.
  - `Dockerfile`, `durable_object_start.ts` (#2853, #2858) add a
    staging-only PID-1 supervisor. ENTRYPOINT, USER and port 50051 are
    unchanged.
  - `durable_object.ts` adds only early 404/410 denials.
  - The two `staging_d1_binding_proxy` sources (#2858) add only deadline
    rejections.
  - The probe route adds a lifetime check that returns 404.
  - The #2574 checker gains its reviewed surface.

  None adds a gRPC admission. The historical maps stay unchanged:
  `WAVE_GROUPS` (old/new), the B068 pair `377bcacb`/`294ea6c1`, and the
  #2574 `EXPECTED` delivery bytes that the fixtures prove. The new bytes
  live alongside them, as `WAVE_GROUP_SUCCESSOR_PINS` and
  `REVIEWED_SURFACE`. The successor bytes are a BASE state only. No
  candidate can move a group into or out of that state, and old -> new is
  still the only admitted transition. New tests, on hardlinked copies of the
  real tree, show three things. The baseline accepts itself and ordinary
  Stripe client maintenance. It refuses an edit to a control, a successor,
  the matrix, the B068 verifier, or a new container path. Moving any one
  pin makes the BASE unrecognised. The ledger must name exactly the moved
  pins.

  Merge note: this change has to be merged once with
  `scripts/pre-merge-gate-check.sh --merge 2868 --admin-reason`. Its
  `pull_request_target` check runs the stale BASE verifier. That verifier
  refuses its own BASE and, by design, requires a candidate's verifier and
  tests to equal the BASE bytes. So no gate repair can pass it. Use this
  exception only on the reviewed head, after that head's `issue 2574
  staging gRPC diagnostic` run, which executes the candidate's suites, is
  green. The merge script records the gated head SHA. Re-baseline if main
  moves a pinned path first.
