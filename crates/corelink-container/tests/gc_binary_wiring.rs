//! B-071 artifact wiring contract.
//!
//! These checks intentionally inspect the declared build and CI interfaces
//! rather than requiring a container build in the Rust test process. The
//! production build workflow independently extracts the OCI rootfs and runs
//! this same executable in forced dry-run mode.

const DOCKERFILE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Dockerfile"));
const BUILD_WORKFLOW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/workflows/container-build-push-prod.yml"
));
const DRY_RUN_WORKFLOW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/workflows/gc-sweep-dry-run.yml"
));
const PRODUCTION_SWEEP_BIN: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/gc_sweep.rs"));
const OWNER_PACKETS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/handoff/2026-09-05-owner-action-packets-b008-b154.json"
));

fn gate_4b_source(workflow: &str) -> Option<&str> {
    let start_marker =
        "      - name: Gate 4b — native production GC binary is present and fail-closed";
    let end_marker = "      - name: ADR-0015 reproducibility attestation (reminder)";
    let start = workflow.find(start_marker)?;
    let body_start = start + start_marker.len();
    let end = workflow[body_start..].find(end_marker)? + body_start;
    Some(&workflow[start..end])
}

fn gate_4b_has_required_contract(gate: &str) -> bool {
    gate.contains("GC_OBSERVATION_ONLY=true")
        && gate.contains("GC_LIVE_DELETE=false")
        && gate.contains("gc_sweep FAILED (fail-closed)")
}

fn normalize_shell_continuations(source: &str) -> String {
    let mut normalized = String::with_capacity(source.len());
    let mut continuing = false;

    for line in source.lines() {
        let line = if continuing { line.trim_start() } else { line };
        if let Some(prefix) = line.strip_suffix('\\') {
            normalized.push_str(prefix);
            continuing = true;
        } else {
            normalized.push_str(line);
            normalized.push('\n');
            continuing = false;
        }
    }

    normalized
}

#[test]
fn runtime_image_contains_a_separately_invoked_gc_binary() {
    let build = "cargo build --release --locked -p corelink-gc --bin gc_sweep;";
    let stage = "cp /build/target/release/gc_sweep /out/gc_sweep";
    let runtime = "COPY --from=builder /out/gc_sweep /usr/local/bin/gc_sweep";
    let production_build =
        "cargo build --release --locked -p corelink-server --bin corelink-gc-sweep-production";
    let production_stage =
        "cp /build/target/release/corelink-gc-sweep-production /out/corelink-gc-sweep-production";
    let production_runtime =
        "COPY --from=builder /out/corelink-gc-sweep-production /usr/local/bin/corelink-gc-sweep-production";

    assert!(
        DOCKERFILE.contains(build),
        "gc_sweep must be built in builder"
    );
    assert!(
        DOCKERFILE.contains(stage),
        "gc_sweep must leave the cache mount"
    );
    assert!(
        DOCKERFILE.contains(runtime),
        "gc_sweep must enter the runtime image"
    );
    assert!(
        DOCKERFILE.contains(production_build),
        "native production sweep must be built under its distinct name"
    );
    assert!(
        DOCKERFILE.contains(production_stage),
        "native production sweep must leave the cache mount"
    );
    assert!(
        DOCKERFILE.contains(production_runtime),
        "native production sweep must enter the runtime image"
    );
    assert!(
        !DOCKERFILE.contains("ENV GC_LIVE_DELETE=true"),
        "the image must never default to live deletion"
    );
    assert!(
        DOCKERFILE.contains("ENTRYPOINT [\"/usr/local/bin/corelink-server\"]"),
        "shipping gc_sweep must not replace the server entrypoint"
    );
}

#[test]
fn native_sweep_observation_requires_explicit_false_delete_gate() {
    let source = include_str!("../src/gc_sweep.rs");
    for required in [
        "GC_OBSERVATION_ONLY",
        "GC_OBSERVATION_ONLY=true requires GC_LIVE_DELETE=false",
        "pub observation_only: bool",
    ] {
        assert!(
            source.contains(required),
            "observation contract must contain {required:?}"
        );
    }
    assert!(
        PRODUCTION_SWEEP_BIN.contains("observation_only={}"),
        "the native sweep binary must report the observation-only contract"
    );
    for evidence_field in [
        "\"schema_version\": 1",
        "\"candidates_scanned\"",
        "\"reclaimable_count\"",
        "\"reclaimable_bytes\"",
        "\"delete_count\"",
        "\"phase_budget_ms\"",
        "\"max_candidates\"",
    ] {
        assert!(
            PRODUCTION_SWEEP_BIN.contains(evidence_field),
            "native observation output must contain {evidence_field:?}"
        );
    }
    let adapter = include_str!("../src/gc_sweep.rs");
    for required in [
        "D1HttpClient::from_d1_env()",
        "config.max_candidates",
        "validate_observation_region(config.region)?",
        "GC_REGION=syd has no provisioned macro-residency mapping",
        "ObservationOnlyR2Delete",
        "R2 delete is disabled for production GC observation",
        "ObservationOnlyAuditSink",
        "GC mutation audit is disabled for production observation",
        "InMemoryGcSweepReportSink::new()",
    ] {
        assert!(
            adapter.contains(required),
            "the native observation path must contain {required:?}"
        );
    }
    assert!(
        !PRODUCTION_SWEEP_BIN.contains("StorageEnv::from_env"),
        "read-only GC observation must not require R2 credentials"
    );
    let d1 = include_str!("../src/storage/d1_http.rs");
    assert!(d1.contains("self.read_only && !is_select_statement(sql)"));
    assert!(d1.contains("D1 read-only client rejected a batch request"));
    assert!(d1.contains("parsed.result.len() != 1"));
    assert!(d1.contains("result.success != Some(true)"));
}

#[test]
fn b071_owner_packet_names_truthful_observation_metrics() {
    let b071 = OWNER_PACKETS
        .split("\"id\": \"B-071\"")
        .nth(1)
        .and_then(|tail| tail.split("\"id\": \"B-072\"").next());
    assert!(b071.is_some(), "B-071 packet must precede B-072");
    let b071 = b071.unwrap_or("");
    for required in [
        "\"candidates_scanned\"",
        "\"reclaimable_count\"",
        "\"reclaimable_bytes\"",
    ] {
        assert!(
            b071.contains(required),
            "B-071 packet must contain {required}"
        );
    }
    assert!(
        !b071.contains("\"candidate_bytes\""),
        "B-071 packet must not retain the ambiguous candidate_bytes field"
    );
}

#[test]
fn image_inspection_runs_gc_as_a_measurable_dry_run() {
    for required in [
        "Gate 4 — embedded GC binary is forced dry-run",
        // #2762 moved the probe under sudo: the exported rootfs is root-owned.
        "sudo test -x \"$B/rootfs/usr/local/bin/gc_sweep\" || { echo \"::error::gc_sweep is absent or not executable in the runtime image\"; exit 1; }",
        "GC_LIVE_DELETE=false",
        "reclaimable_count         = 1",
        "reclaimable_bytes         = 4096",
        "deleted_count             = 0",
        "deleted_bytes             = 0",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(required),
            "image inspection must contain {required:?}"
        );
    }
}

#[test]
fn native_production_gate_scopes_explicit_false_delete_guard() {
    let gate = gate_4b_source(BUILD_WORKFLOW);
    assert!(gate.is_some(), "Gate 4b must be present");
    let Some(gate) = gate else { return };
    assert!(gate_4b_has_required_contract(gate));

    // A mutation that removes the explicit false delete guard from Gate 4b
    // must not be rescued by the identical dry-run setting in Gate 4.
    let mutated = gate.replacen("GC_LIVE_DELETE=false", "GC_LIVE_DELETE", 1);
    assert!(!gate_4b_has_required_contract(&mutated));
}

#[test]
fn scheduled_sweep_is_credentialless_and_cannot_arm_delete() {
    let normalized_workflow = normalize_shell_continuations(DRY_RUN_WORKFLOW);
    for required in [
        "GC_LIVE_DELETE: \"false\"",
        "env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID cargo run -p corelink-gc --bin gc_sweep",
        "reclaimable_count         = 1",
        "reclaimable_bytes         = 4096",
        "deleted_count             = 0",
        "deleted_bytes             = 0",
    ] {
        assert!(
            normalized_workflow.contains(required),
            "scheduled dry-run must contain {required:?}"
        );
    }
    assert!(
        !DRY_RUN_WORKFLOW.contains("live_delete:"),
        "the scheduled dry-run workflow must not expose a live-delete input"
    );
}

#[test]
fn owner_package_has_a_fail_closed_collector_and_verifier() {
    let collector = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/collect_b071_gc_observation.py"
    ));
    for required in [
        "GC_OBSERVATION_ONLY\": \"true\"",
        "GC_LIVE_DELETE\": \"false\"",
        "GC_LIVE_DELETE_CONFIRM",
        "R2_S3_SECRET_ACCESS_KEY",
        "tenant_region_population",
        "PENDING_OWNER_REVIEW",
        "live_delete_authorized",
        "native dry-run reported a deletion",
    ] {
        assert!(
            collector.contains(required),
            "B-071 collector must retain {required:?}"
        );
    }
}
