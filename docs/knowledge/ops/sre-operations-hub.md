---
type: "CrateCluster"
title: "SRE operations hub (corelink-ops + satellites)"
description: "How corelink-ops aggregates the SRE/ops primitives (chaos, secret-rotation, drift, runbook, statuspage, slack) into one import surface, and which satellites are live external transports vs. pure-logic skeletons whose production wiring is deferred."
source_files:
  - "crates/corelink-ops/src/lib.rs"
  - "crates/corelink-ops/src/chaos.rs"
  - "crates/corelink-ops/src/rotation.rs"
  - "crates/corelink-ops/src/rotation/worker.rs"
  - "crates/corelink-ops/src/rotation/worker/rollback.rs"
  - "crates/corelink-ops/src/statuspage.rs"
  - "crates/corelink-ops/src/slack.rs"
  - "crates/corelink-ops/src/terraform.rs"
  - "crates/corelink-ops/src/runbook.rs"
  - "crates/corelink-ops/src/dt.rs"
  - "crates/corelink-chaos-scheduler/src/runner.rs"
  - "crates/corelink-chaos-scheduler/src/catalog.rs"
  - "crates/corelink-rotation-adapters/src/adapter.rs"
  - "crates/corelink-slack-real/src/http.rs"
  - "crates/corelink-statuspage-real/src/http.rs"
  - "crates/corelink-statuspage-real/src/lib.rs"
  - "crates/corelink-dt-webhook/src/handler.rs"
  - "crates/corelink-terraform-drift-consumer/src/consumer.rs"
  - "crates/corelink-runbook-tracker/src/lib.rs"
  - "crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs"
  - "crates/corelink-clerk-cf/src/dsr_statuspage_cron.rs"
  - "crates/corelink-clerk-cf/wrangler.toml"
source_blobs:
  - "crates/corelink-ops/src/lib.rs@440470d297248bab67ce6cf7da370f28c7e8b771"
  - "crates/corelink-ops/src/chaos.rs@470b192abd69cbdce1e5da278bd4ddfa767b47b1"
  - "crates/corelink-ops/src/rotation.rs@78227b795e1f1825ff08513e29880327870ec390"
  - "crates/corelink-ops/src/rotation/worker.rs@4477879c9b33b3196e5b6a700438e4d4702f5c5e"
  - "crates/corelink-ops/src/rotation/worker/rollback.rs@bb92d8caf77ffeeeb562ab706ef89f45042111dd"
  - "crates/corelink-ops/src/statuspage.rs@89c2f4ac7232d1e82f265e6bb808771063d8d793"
  - "crates/corelink-ops/src/slack.rs@a95953329ccf0ba49e86f8f278afbf510b9500fe"
  - "crates/corelink-ops/src/terraform.rs@f4528ede400f0c7df4f26c7317655a578560a2bb"
  - "crates/corelink-ops/src/runbook.rs@75274eea7c5c238e5a3181b25a7ae2808ace7508"
  - "crates/corelink-ops/src/dt.rs@87e797e0881b878e50ec175f837066bde20dc320"
  - "crates/corelink-chaos-scheduler/src/runner.rs@d5fb6cac4f40c73cd54d3c3206b047d545727c5e"
  - "crates/corelink-chaos-scheduler/src/catalog.rs@0f8afa5d8c29243fcdbca69848f06ce40387aaf4"
  - "crates/corelink-rotation-adapters/src/adapter.rs@9b6d65475731e4fec5b9371afba3534b7324244a"
  - "crates/corelink-slack-real/src/http.rs@db2683fc141c34e2a39fa353f1e5ff423603abb4"
  - "crates/corelink-statuspage-real/src/http.rs@be4475b1f217211050f0f99c06690ba67556e375"
  - "crates/corelink-statuspage-real/src/lib.rs@b294a82298c3713dda726e823e3e111fa553471b"
  - "crates/corelink-dt-webhook/src/handler.rs@3aa0cba9ea6f44f190365c8a9e6684c6639d67dc"
  - "crates/corelink-terraform-drift-consumer/src/consumer.rs@c62022ee9b81fe4fa54472c0957459f4f5b7acb5"
  - "crates/corelink-runbook-tracker/src/lib.rs@c3c770e37961eef6451c51f047a28c669dc017c0"
  - "crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs@bd62eac30c7c531e3ba9a4054cace111a7d633ed"
  - "crates/corelink-clerk-cf/src/dsr_statuspage_cron.rs@25fc5359f7579ace71a51868d92a8e88c9a07688"
  - "crates/corelink-clerk-cf/wrangler.toml@38f5cf283ac07ebf36aab47d00c19cca621cd31f"
checkpoint_sha: "a65c7d7caed03adf00acd3a227dc20c4e857f7f0"
provenance: "AUTHORED"
tags: ["sre", "operations", "alerting", "chaos", "rotation"]
timestamp: "2026-06-28T00:00:00Z"

---
# SRE operations hub (corelink-ops + satellites)

`corelink-ops` is the **single import target** for every ops/SRE primitive in the
workspace — it is an *aggregator*, not an owner. Per the Wave-33 "Option-A aggregator"
strategy it re-exports (and, in Wave-35 Phase 2, physically absorbs a subset of)
formerly-standalone crates at canonical submodule paths so consumers say
`use corelink_ops::chaos::*` instead of tracking ~28 crate names. The hard thing this
concept records — the thing the rustdoc will NOT tell you bluntly — is the **live-vs-skeleton
split**: some satellites are real external transports that hit Slack / Atlassian over the wire,
while others ship only pure-logic state machines whose production Cloudflare wiring is *deferred*,
and the only implementation in the crate is an in-memory fake. Read the per-satellite verdict
below before assuming any of these "fires" in production.

# Role
- The ops/SRE umbrella: one library surface re-exporting chaos, rotation, drift, runbook,
  statuspage, slack, oncall, drata, admin-dual-approval, etc. (`crates/corelink-ops/src/lib.rs:211-229`).
- A pure pass-through for the still-external satellites — e.g. `chaos`, `statuspage`, `slack`,
  `terraform`, `runbook`, and `dt::webhook` are `pub use`/`pub mod` re-exports with NO logic of
  their own (`crates/corelink-ops/src/chaos.rs:10`; `crates/corelink-ops/src/statuspage.rs:11`;
  `crates/corelink-ops/src/slack.rs:11`; `crates/corelink-ops/src/dt.rs:22-24`).
- The boundary between the two alerting egress transports that are REAL (`slack-real`,
  `statuspage-real` — reqwest::blocking to live APIs) and the orchestrators that only describe
  what *would* be emitted.

# How it works
- The umbrella declares one `pub mod` per thematic area; the absorbed-vs-external split is purely
  whether the module body is inline or a `pub use` of an external crate
  (`crates/corelink-ops/src/lib.rs:211-229`). `rotation` keeps `adapters` external but absorbs
  `worker` inline (`crates/corelink-ops/src/rotation.rs:11-15`).
- **Chaos (`corelink-chaos-scheduler`) — real logic, wiring external.** `run_experiment` is a pure
  state machine: it runs a HARD safe-mode gate (auto-aborts unless target is Staging) BEFORE any
  experiment, then emits a 3-event audit lifecycle
  (`crates/corelink-chaos-scheduler/src/runner.rs:137-147`,
  `crates/corelink-chaos-scheduler/src/runner.rs:158-185`). Real I/O (state capture, R2 7y archive,
  SLO measurement) is delegated to the injected `Telemetry` trait — the production adapter wiring
  "lives outside the src/" (`crates/corelink-chaos-scheduler/src/runner.rs:61-71`). The canonical
  catalog is 8 experiments covering 8 distinct FM-IDs
  (`crates/corelink-chaos-scheduler/src/catalog.rs:26-112`).
- **Slack alerting (`corelink-slack-real`) — LIVE external transport.** `SlackHttpClient::send`
  POSTs the Block-Kit JSON to the real incoming-webhook URL via `reqwest::blocking`, with a retry
  loop and an audit emit on both Sent and Failed
  (`crates/corelink-slack-real/src/http.rs:124-194`).
- **Statuspage (`corelink-statuspage-real`) — LIVE external transport, dual-target.**
  `StatuspageHttpClient::publish_dsr_metric` gates on a local 1-per-5-min rate limiter, then POSTs
  the DSR metric to `api.statuspage.io` with the `OAuth` header, retrying 429/5xx and emitting
  audit on every arm (`crates/corelink-statuspage-real/src/http.rs:166-275`). The native
  `http.rs` is `reqwest::blocking`; a separate `wasm32_backend.rs` (worker::Fetch) exists because
  blocking reqwest does not link on wasm32 (`crates/corelink-statuspage-real/src/lib.rs:55-76`).
- **DSR statuspage scheduler (`corelink-dsr-statuspage-scheduler`) — the most fully WIRED path.**
  `run_once` composes D1 row-source → 24h aggregate → bridge → real `StatuspageBackend::publish`,
  with a cron dedupe ledger and fail-CLOSED audit at every transition
  (`crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:187-202`,
  `crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:296-365`). It is genuinely live: the
  worker `#[event(scheduled)]` handler resolves real bindings + D1 + the Statuspage API-key secret
  and invokes it (`crates/corelink-clerk-cf/src/dsr_statuspage_cron.rs:128-214`), pinned to the
  cron trigger in `wrangler.toml` (`crates/corelink-clerk-cf/wrangler.toml:142-143`).
- **Terraform drift (`corelink-terraform-drift-consumer`) — real orchestrator, NO apply surface.**
  `process_plan_event` classifies → audit-emits BEFORE the store insert → inserts → records metrics,
  all generic over `DriftClassifier`/`DriftAuditSink`/`DriftFindingStore` traits
  (`crates/corelink-terraform-drift-consumer/src/consumer.rs:58-96`). The crate deliberately has no
  `terraform apply` (`crates/corelink-terraform-drift-consumer/src/consumer.rs:124-128`).
- **Runbook tracker (`corelink-runbook-tracker`) — pure-logic library, no I/O.** Cadence
  (`is_overdue` ≥ 30d) and drift (`compute_drift`, ratio > 2.0 → flagged) are standalone helpers;
  host adapters (D1, Cron, CLI) bind via the `DrillRecorder` trait
  (`crates/corelink-runbook-tracker/src/lib.rs:256-272`,
  `crates/corelink-runbook-tracker/src/lib.rs:284-286`).
- **Secret rotation (`corelink-rotation-adapters` + the absorbed `rotation::worker`) — pure-logic
  SKELETON.** The adapter trait enforces the read/write key-state invariants and the rollback
  driver accumulates consecutive above-threshold probes (1% sustained 5 probes → trigger), but the
  worker module's own header states all Cron bindings + D1 atomic batches + KMS calls are deferred
  (`crates/corelink-ops/src/rotation/worker.rs:1-11`,
  `crates/corelink-rotation-adapters/src/adapter.rs:14-27`,
  `crates/corelink-ops/src/rotation/worker/rollback.rs:150-171`).

# Invariants
- A still-external satellite module in the umbrella adds NO behaviour — it is exactly a re-export,
  so its semantics are whatever the owning crate ships (`crates/corelink-ops/src/chaos.rs:10`;
  `crates/corelink-ops/src/statuspage.rs:11`).
- Chaos NEVER runs outside Staging: a non-Staging target short-circuits to an `Aborted` audit
  before any experiment side-effect (`crates/corelink-chaos-scheduler/src/runner.rs:137-147`).
- Every real alerting transport is audit-emit-fail-CLOSED: Slack/Statuspage emit an audit envelope
  on BOTH success and failure before returning (`crates/corelink-slack-real/src/http.rs:149-190`;
  `crates/corelink-statuspage-real/src/http.rs:218-272`).
- The drift consumer emits the audit record BEFORE the store mutation, so an audit-sink failure
  blocks the write (`crates/corelink-terraform-drift-consumer/src/consumer.rs:75-82`).
- The drift consumer exposes no apply path by construction
  (`crates/corelink-terraform-drift-consumer/src/consumer.rs:124-128`).
- The DSR scheduler dedupes per `(date, metric_id)` and seizes the ledger slot even on failure
  (fail-once-per-day), so the cron runtime cannot re-publish the same UTC day
  (`crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:207-221`,
  `crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:347-362`).

# Gotchas
- **Two satellites are NOT production-wired.** `dt::webhook`'s only handler impl is
  `InMemoryDtWebhookHandler` — it does real HMAC verify + severity routing + DLQ, but
  `deliver_to_channel` is an explicit in-memory simulation and the header says production CF Worker
  wiring is deferred (`crates/corelink-dt-webhook/src/handler.rs:7-9`,
  `crates/corelink-dt-webhook/src/handler.rs:197-213`). The `rotation::worker` is likewise a
  pure-logic skeleton with Cron/D1/KMS deferred to WI-S13-006
  (`crates/corelink-ops/src/rotation/worker.rs:7-11`). Do not claim either "alerts" or "rotates"
  in prod from this crate alone.
- The aggregator is NOT a single source of truth for the externals: their `src/`, tests, and benches
  stay in the owning crate; the umbrella only re-exports symbols
  (`crates/corelink-ops/src/lib.rs:46-48`). To change chaos/slack/statuspage behaviour you edit the
  satellite crate, not `corelink-ops`.
- The Statuspage HTTPS client is target-split: `http.rs` (native reqwest::blocking) vs
  `wasm32_backend.rs` (worker::Fetch). The live cron path runs the *wasm32* backend; the native
  client is the one consumed via the umbrella on host/CI
  (`crates/corelink-statuspage-real/src/lib.rs:55-76`).
- `slack`/`statuspage` are ALSO re-exported by `corelink-adapters-cloud` (the pure-logic vs binding
  split is deferred), so the same symbols are reachable by two paths
  (`crates/corelink-ops/src/slack.rs:7-9`; `crates/corelink-ops/src/statuspage.rs:7-9`).

# Citations
1. `crates/corelink-ops/src/lib.rs:211-229` — the umbrella's `pub mod` surface (one module per ops area).
2. `crates/corelink-ops/src/lib.rs:46-48` — absorbed crates remain canonical sources; umbrella only re-exports.
3. `crates/corelink-ops/src/chaos.rs:10` — chaos is a bare `pub use corelink_chaos_scheduler::*`.
4. `crates/corelink-ops/src/rotation.rs:11-15` — rotation keeps `adapters` external, absorbs `worker`.
5. `crates/corelink-ops/src/statuspage.rs:7-9` / `:11` — statuspage re-export + dual-path note.
6. `crates/corelink-ops/src/slack.rs:7-9` / `:11` — slack re-export + dual-path note.
7. `crates/corelink-ops/src/terraform.rs:8` — terraform-drift re-export.
8. `crates/corelink-ops/src/runbook.rs:9` — runbook-tracker re-export.
9. `crates/corelink-ops/src/dt.rs:22-24` — `dt::webhook` re-export (CLI/reconcile are binary-only).
10. `crates/corelink-chaos-scheduler/src/runner.rs:137-147` — HARD safe-mode abort before any experiment.
11. `crates/corelink-chaos-scheduler/src/runner.rs:158-185` — Started/capture/measure/Completed lifecycle.
12. `crates/corelink-chaos-scheduler/src/runner.rs:61-71` — real I/O delegated to injected `Telemetry`.
13. `crates/corelink-chaos-scheduler/src/catalog.rs:26-112` — canonical 8-experiment catalog.
14. `crates/corelink-rotation-adapters/src/adapter.rs:14-27` — read/write key-state invariants.
15. `crates/corelink-slack-real/src/http.rs:124-194` — real webhook POST + retry + audit (LIVE transport).
16. `crates/corelink-statuspage-real/src/http.rs:166-275` — real `api.statuspage.io` POST + rate-limit + retry + audit.
17. `crates/corelink-statuspage-real/src/lib.rs:55-76` — native http vs wasm32 backend target split.
18. `crates/corelink-dt-webhook/src/handler.rs:7-9` — production CF Worker wiring deferred.
19. `crates/corelink-dt-webhook/src/handler.rs:197-213` — `deliver_to_channel` is an in-memory simulation.
20. `crates/corelink-terraform-drift-consumer/src/consumer.rs:58-96` — classify→audit-before-store→insert→metrics.
21. `crates/corelink-terraform-drift-consumer/src/consumer.rs:124-128` — no `terraform apply` surface by construction.
22. `crates/corelink-runbook-tracker/src/lib.rs:256-272` — `compute_drift` (ratio > 2.0 → flagged).
23. `crates/corelink-runbook-tracker/src/lib.rs:284-286` — `is_overdue` (≥ 30-day cadence).
24. `crates/corelink-ops/src/rotation/worker.rs:1-11` — rotation worker ships pure-logic skeleton; Cron/D1/KMS deferred.
25. `crates/corelink-ops/src/rotation/worker/rollback.rs:150-171` — PAT-ROLL-FORWARD-001 sustained-breach rollback trigger.
26. `crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:187-202` — `run_once` scheduled-audit-first.
27. `crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:207-221` — dedupe pre-flight (already-published-today).
28. `crates/corelink-dsr-statuspage-scheduler/src/scheduler.rs:296-365` — publish + fail-once-per-day ledger seize.
29. `crates/corelink-clerk-cf/src/dsr_statuspage_cron.rs:128-214` — live `#[event(scheduled)]` handler wiring real bindings.
30. `crates/corelink-clerk-cf/wrangler.toml:142-143` — `[triggers] crons = ["0 6 * * *"]` pins the cron.
