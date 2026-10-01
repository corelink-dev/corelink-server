### Fixed

- **The #2176 trusted gRPC gate and the #2574 diagnostic were red on main
  because their frozen pins no longer matched main (gate health F1/F6).**
  19 of the 54 d2f1 transport-control pins, the P0 secrets-matrix pin and the
  B068 verifier pin pair in `verify_i2176_grpc_deny_gate.py` had drifted.
  Each changed file was reviewed against its post-snapshot commits. 14 controls,
  the matrix and the B068 pair carried no transport change (CI, docs, tests,
  CLI version, outbound R2 session token, signup-only B-216 secret opt-in) and
  are re-pinned to main `b60f5ee8c`. `Dockerfile`, `durable_object_start.ts`,
  `index_fetch.ts` and both `staging_d1_binding_proxy` sources keep their d2f1
  pins: #2853 put a staging handler before the public gRPC deny and swapped the
  Container entrypoint, and #2858 changed the image and a Worker entrypoint.
  They need a human transport review, so the trusted gate stays red on main.
  The 6 failing unit tests now pass. A new test fails on any unreviewed
  control drift and on any stale pending entry.
