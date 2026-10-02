### Fixed

- **B-068 (#1650): the credentialless real integration pack accepts the reviewed
  #2846 staging topology state.** #2846 changed only
  `validated_inputs.runner_label` in `infra/staging/topology.json`, which the
  B-068 executor contract binds to the D1 proxy source, so the pack failed on
  `main`. The new state is now a reviewed pair bound to the D1 proxy source
  target, the stale `d1_http.rs` manifest pin is corrected and guarded against
  drift, and topology changes now trigger the pack on their own pull request.
