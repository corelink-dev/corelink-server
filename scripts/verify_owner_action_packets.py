#!/usr/bin/env python3
"""Fail-closed verifier for the bounded owner-action packet population.

This guard validates the packet's portable engineering contract only. It never
contacts GitHub, PagerDuty, Stripe, Drata, Cloudflare, Apple, Windows, or a
customer, and it never independently treats an owner action as completed merely
because a packet field is present. Missing, duplicate,
ambiguous, or mutated packet fields are errors rather than an empty result.
It does not perform or independently reproduce an owner action; a closed row is
accepted only when its packet metadata and canonical BACKLOG contract record the
corresponding repository/evidence closure.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json"
sys.path.insert(0, str(ROOT / "scripts"))
from verify_b083_kms_lifecycle_evidence import EvidenceError as B083EvidenceError
from verify_b083_kms_lifecycle_evidence import validate_record as validate_b083_evidence
EXPECTED_IDS = (
    "B-008", "B-012", "B-013", "B-032", "B-035", "B-065",
    "B-086", "B-089", "B-097", "B-110", "B-111", "B-154",
    "B-029", "B-044", "B-046", "B-054", "B-063", "B-068", "B-071",
    "B-072", "B-083", "B-102", "B-106", "B-113", "B-125", "B-128",
    "B-134", "B-142", "B-165",
)
# Terminal owner decisions move to the repository-side ``tl`` owner only after
# their source-bound closure evidence receives a strict focal verifier. Other
# legacy rows remain owner-controlled until their actions are evidenced.
LEGACY_OWNER_IDS = frozenset(EXPECTED_IDS[:12]) - {"B-012", "B-013", "B-035", "B-110"}
CLOSED_PACKET_IDS = frozenset({"B-012", "B-013", "B-035", "B-110", "B-165"})
B089_SURFACES = (
    "legal/sla/v1.0.0.md",
    "apps/docs/src/pages/legal/terms.tsx",
    "apps/docs/src/lib/pricing.ts",
)
B089_HISTORICAL_V1_SHA256 = "4b6e39a0891eecf32640e9815386436e155e3334cd655ea180ca6f3bc1af6d09"
ITEM_FIELDS = {
    "id", "owner", "status", "action_type", "procedure",
    "inputs_and_credentials_boundary", "evidence", "expected_postcondition",
    "retry_and_rollback", "references",
}
BOUNDARY_FIELDS = {"inputs", "credentials"}
EVIDENCE_FIELDS = {"path", "format", "required_fields", "item_schema"}
FORBIDDEN_MARKERS = ("<", ">", "TBD", "TODO", "FIXME", "SECRET_VALUE")
SECRET_SHAPES = (
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|sk_live_|whsec_)\S+", re.IGNORECASE),
)

# B-111 is an owner acquisition item, not a claim that any certificate exists.
# Keep its contract synchronized with the executable workflow_call interfaces;
# comments and stale prose must not be allowed to satisfy this guard.
B111_WORKFLOW_SECRETS = {
    ".github/workflows/notarize-macos.yml": frozenset({
        "CORELINK_CLI_RELEASE_TOKEN",
        "APPLE_DEVELOPER_ID",
        "APPLE_DEVELOPER_ID_PASSWORD",
        "APPLE_TEAM_ID",
        "APPLE_NOTARIZATION_API_KEY",
        "APPLE_NOTARIZATION_KEY_ID",
        "APPLE_NOTARIZATION_ISSUER",
        "APPLE_DEVELOPER_ID_FINGERPRINT",
    }),
    ".github/workflows/sign-windows.yml": frozenset({
        "CORELINK_CLI_RELEASE_TOKEN",
        "WINDOWS_CODE_SIGNING_CERT",
        "WINDOWS_CODE_SIGNING_PASSWORD",
        "WINDOWS_CODE_SIGNING_FINGERPRINT",
        "WINDOWS_CODE_SIGNING_SUBJECT",
    }),
}
B111_ACQUISITION_SECRETS = frozenset().union(
    B111_WORKFLOW_SECRETS[".github/workflows/notarize-macos.yml"]
    - {"CORELINK_CLI_RELEASE_TOKEN"},
    B111_WORKFLOW_SECRETS[".github/workflows/sign-windows.yml"]
    - {"CORELINK_CLI_RELEASE_TOKEN"},
)
B111_RELEASE_CHAIN = {
    "release": {"build"},
    "sign-linux": {"release"},
    "sign-windows": {"sign-linux", "release"},
    "notarize-macos": {"sign-windows", "release"},
}
B110_EVIDENCE_PATH = "evidence/owner-actions/B-110/ci-capacity-decision.json"
B008_EVIDENCE_PATH = "evidence/owner-actions/B-008/pagerduty-incident-review.json"
B008_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "admission", "drill", "pagerduty_timeline",
    "webhook_receipt", "d1_receipt", "human_delivery_verdict", "reviewer",
]
B008_PROCEDURE = [
    "UI: In PagerDuty, create a separate read-only API key named corelink-incident-review-UTC; do not reuse or rotate PAGERDUTY_ROUTING_KEY.",
    "UI: With a repository administrator, establish required approval protection for synthetic-drill-staging and provision the staging root worker with SCHEDULED_DRILL_DELIVERY bound to corelink-synthetic-pager-staging; verify the receiver, migrated D1 schema, and dedicated synthetic-service routing/webhook secrets, leaving activation false.",
    "UI: After those prerequisites are verified, the SRE Lead explicitly authorizes one non-production root-worker scheduled tick in immediate-delivery mode; remove/disable the staging trigger after that tick and never activate the production receiver.",
    "RUN: Capture that single scheduler acceptance, receiver D1 triggered row, PagerDuty incident ID/timestamp, and signed acknowledgement or escalation webhook; do not retry or dispatch a duplicate.",
    "RUN: With the read-only key supplied through a password manager or stdin (never argv/logs), export the PagerDuty incident timeline and correlate it to the staging D1 row and webhook receipt at the canonical evidence path.",
    "UI: Record the human-delivery verdict and D1 outcome/mtta_ms, then disable staging activation and revoke the read-only review key; if any receipt is missing or ambiguous, keep B-008 open and escalate.",
]
B008_INPUTS = [
    "PagerDuty account/service identifier",
    "read-only review interval",
    "repository-admin-protected synthetic-drill-staging environment",
    "staging root worker and SCHEDULED_DRILL_DELIVERY binding",
    "staging receiver and migrated D1 schema",
    "dedicated synthetic-drill routing/webhook secrets",
    "explicit SRE Lead authorization for one immediate-mode scheduled tick",
]
B008_CREDENTIAL_BOUNDARY = (
    "The owner creates and holds a separate read-only PagerDuty API key for incident review. The synthetic-drill "
    "routing key and webhook secret are staging-only platform secrets; never reuse PAGERDUTY_ROUTING_KEY, commit "
    "credentials, or include them in evidence."
)
B008_EVIDENCE_ITEM_SCHEMA = (
    "admission records read_only_key_scope=read_only, protected_environment=synthetic-drill-staging, "
    "required_approvals, staging_root_worker, service_binding, staging_receiver, d1_schema, "
    "dedicated_secret_names, and owner_authorized_at; drill records drill_id, correlation_id, delivery_mode=immediate, "
    "scheduled_tick_count=1, scheduled_at, scheduled_tick_disabled_at, and scheduler_acceptance; "
    "pagerduty_timeline records incident_id, dedup_key=drill_id, correlation_id=drill.correlation_id, "
    "created_at, trigger_status, escalation_policy_id, acknowledgement_at, escalation_at, and redacted source_url; "
    "webhook_receipt records event_id, drill_id, correlation_id=drill.correlation_id, kind, occurred_at, "
    "signature_verified, and redacted source_reference; "
    "d1_receipt records drill_id, correlation_id=drill.correlation_id, delivery_mode=immediate, "
    "triggered_at_ms, delivered_at_ms, outcome, ack_ts_ms, mtta_ms, "
    "ack_vector, and redacted source_reference; human_delivery_verdict is delivered, not_delivered, or inconclusive."
)
B008_EXPECTED_POSTCONDITION = (
    "The redacted receipt correlates one explicitly authorized protected staging drill through scheduler, D1, "
    "PagerDuty, and signed human acknowledgement/escalation. B-008 remains open unless the evidence proves "
    "human delivery and all issue closure gates are met."
)
B008_RETRY_AND_ROLLBACK = (
    "Before prerequisites and explicit SRE Lead authorization, dispatch nothing. After authorization, permit one "
    "staging drill only; do not retry or duplicate. If any receipt is missing/ambiguous or delivery is not proven, "
    "disable staging activation, retain the evidence, escalate, and keep B-008 open. Revoke only the new read-only "
    "review key; never revoke or repurpose PAGERDUTY_ROUTING_KEY."
)
B008_REQUIRED_REFERENCES = frozenset({
    "BACKLOG.md#B-008",
    "BACKLOG.md#B-072",
    "docs/internal/2026-08-24-owner-decision-brief.md",
    "evidence/i1641/pagerduty-contract-manifest.json",
})
B008_STAGING_TOPOLOGY_PATH = "infra/staging/topology.json"
B008_STAGING_ROOT_WORKER = "corelink-staging"
B008_STAGING_SERVICE_BINDING = "SCHEDULED_DRILL_DELIVERY"
B008_STAGING_RECEIVER = "corelink-synthetic-pager-staging"
B065_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "account", "destination_inventory",
    "retained_endpoint_ids", "resolution", "billing_health_runs",
    "duplicate_events_resolved", "operator",
]
B065_SCHEMA_REQUIRED_TERMS = (
    "v1 or v2", "signup_worker", "corelink_prd_container",
    "observed_disabled", "disabled_now", "mutation_performed",
    "disabled_at is required only for disabled_now", "Legacy retired_endpoint_id",
    "never replace the typed resolution or either retained ID",
)
B083_PROCEDURE_MARKERS = (
    ("protected, isolated nonproduction AWS runtime", "exact shipped byok-aws-real image", "sha256 image digest"),
    ("distinct isolated test tenant", "customer-controlled CMK", "deletion scheduling"),
    ("wrap, unwrap, and check_access", "durable audit receipt sink", "outside git and issue comments"),
    ("customer create/import", "activation before the first D1 mutation", "provider failure with bounded retry", "residency"),
    ("production binary's run_loop p99", "no more than five minutes", "AWS CLI-only result is insufficient"),
    ("evidence_state to VERIFIED", "all five external prerequisites PROVISIONED", "ten lifecycle keys", "UTC completion timestamp"),
    ("exact-head GitHub Actions contract", "#2165", "#1653", "keep #1653 open"),
)
B083_BOUNDARY_MARKERS = (
    "two disposable isolated test tenants", "customer-controlled CMK", "durable audit receipt sink",
    "repository action never creates, imports, rotates, disables, schedules deletion for, or cleans up a provider resource",
)
B083_POSTCONDITION_MARKERS = (
    "five prerequisites", "all ten lifecycle steps", "run_loop revoke/restore p99 is at most five minutes",
)
B083_RETRY_MARKERS = (
    "fail closed", "provider mutation, rollback, or cleanup is separately authorized", "do not retry with plaintext",
)
B083_REFERENCES = frozenset({
    "#2165", "#1653", "scripts/verify_b083_kms_lifecycle_evidence.py",
    ".github/workflows/issue-1653-byok-kms-contract.yml",
    "evidence/owner-actions/B-083/byok-real-kms-lifecycle.json",
})
B071_PROCEDURE_MARKERS = (
    ("source-backed retention and eviction decision", "already-running production physical_delete run", "workspace pins", "active references", "legal and audit holds", "grace period", "stop/rollback condition", "observation only"),
    ("SRE/provider provisions and verifies isolated staging", "D1 binding", "region-matched R2 bucket", "DNS", "evidence/staging/readiness.json", "deployment_state=ready", "protected secret names only"),
    ("Environment owner verifies the seven required staging names", "protected and reviewer-gated", "K6_STAGING_BYOK_CMK_ID", "K6_STAGING_MFA_STUB", "K6_STAGING_PAT", "K6_STAGING_STRIPE_WHSEC", "K6_STAGING_TEARDOWN_TOKEN", "K6_TARGET_IDENTITY_RECEIPT", "K6_TARGET_HOST"),
    ("immutable image@sha256 digest", "verified staging target", "tag or build result does not identify"),
    ("immutable digest of the exact production container or extracted image", "same digest as the staging deployment", "source-backed artifact equivalence", "staging readiness alone does not prove"),
    ("Only after the owner, staging/provider, protected-input", "production-runtime identity/equivalence receipts exist", "CLOUDFLARE_ACCOUNT_ID", "D1_DATABASE_ID", "CF_API_TOKEN", "R2_TDK_HEX", "already-running production physical_delete run", "production artifact digest"),
    ("verify --expect-approval pending", "balanced classifications", "at most 250 candidates per run", "phase duration within budget", "delete_count=0", "deleted_bytes=0", "live_delete_flag=false", "PENDING_OWNER_REVIEW", "reviewer and decision time unset", "live_delete_authorized=false"),
    ("separate source-backed owner record", "Keep the observation JSON unchanged at PENDING_OWNER_REVIEW", "reviewer/time unset", "never authorizes a first destructive run", "link accepted evidence from #1651", "keep #1651 open"),
)
B071_BOUNDARY_MARKERS = (
    "owner-approved tenant", "retention/eviction terms", "already-running production physical_delete run identifier",
    "verified staging target", "region-matched R2 bucket", "reviewer-gated names",
    "production observation runtime relationship", "bounded phase budget",
)
B071_CREDENTIAL_MARKERS = (
    "CLOUDFLARE_ACCOUNT_ID", "D1_DATABASE_ID", "CF_API_TOKEN", "R2_TDK_HEX",
    "CF_API_TOKEN must be a D1 read-only Cloudflare token",
    "Never place secret values", "GC_OBSERVATION_ONLY=true", "GC_LIVE_DELETE=false",
    "strips live-delete confirmation and R2 write credentials",
)
B071_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "image_digest", "runs", "tenant_region_population",
    "candidates_scanned", "reclaimable_count", "reclaimable_bytes", "delete_count",
    "deleted_bytes", "live_delete_flag", "approval", "operator",
]
B071_SCHEMA_REQUIRED_TERMS = (
    "run_id", "tenant_id", "region", "started_at", "completed_at", "candidates_scanned",
    "reclaimable_count", "reclaimable_bytes", "delete_count", "deleted_bytes",
    "skipped_grace_pending", "skipped_refcount_non_zero", "already_resolved",
    "phase_budget:{budget_ms,duration_ms}", "max_candidates", "verdict",
    "max_candidates is at most 250", "duration_ms does not exceed budget_ms", "PENDING_OWNER_REVIEW",
    "reviewer and decision time unset", "live_delete_authorized=false",
    "Legal-hold and accounting outcomes are not fields",
)
B071_POSTCONDITION_MARKERS = (
    "source-backed owner retention/stop decision", "verified staging/provider readiness",
    "production observation image identity/equivalence", "bounded zero-delete receipt",
    "PENDING_OWNER_REVIEW", "reviewer and decision time unset", "B-071 stays open",
)
B071_RETRY_MARKERS = (
    "Stop on missing or contradictory authority", "production/runtime relationship",
    "Do not broaden scope", "do not create or advance a run through this collector",
    "without fresh owner/provider authorization", "leave B-071 open",
)
B071_REFERENCES = frozenset({
    "#2167", "#1651", "infra/staging/topology.json", "evidence/staging/readiness.json",
    "scripts/verify_staging_target.py", "scripts/collect_b071_gc_observation.py",
    "docs/operator/gc-production-observation.md",
    ".github/workflows/issue-1651-gc-live-readiness.yml",
})
B110_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version",
    "captured_at",
    "selected_option",
    "workflows",
    "capacity_or_billing_reference",
    "coverage_impact",
    "runner_labels",
    "rollback_owner",
    "operator",
]
B110_EVIDENCE_ITEM_SCHEMA = (
    "workflows[] contains workflow, current_runner, selected_runner, and action; "
    "selected_option is hosted_billing, linux_self_hosted, or owner_authorized_park."
)
B110_EVIDENCE_WORKFLOWS = [
    {
        "workflow": ".github/workflows/cas_foundation.yml",
        "current_runner": "ubuntu-latest / ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/coverage.yml",
        "current_runner": "ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/ffi-matrix-ci.yml",
        "current_runner": "ubuntu-latest",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/mutation-nightly.yml",
        "current_runner": "ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
]
B110_EXPECTED_POSTCONDITION = (
    "The owner-approved Linux self-hosted capacity decision is recorded and the four lanes use viable "
    "CoreLink capacity without deletion; B-110 is closed only after the workflow and verifier changes are present."
)
B110_PROCEDURE = [
    "UI: Choose one authorized capacity path for cas_foundation, coverage, ffi-matrix-ci, and mutation-nightly: restore hosted billing, provision an adequate Linux self-hosted box, or authorize deletion/parking of the named lanes.",
    "RUN: For a self-hosted path, register a dedicated runner label with documented CPU/RAM/disk limits and verify the four workflows’ `runs-on` and toolchain assumptions before enabling it.",
    "UI: For hosted billing, confirm the GitHub account spending limit and payment state; for deletion/parking, obtain explicit owner approval describing the coverage loss. Record the selected option before any workflow mutation.",
]

# These three receipts are repository-side observations of owner-gated work.
# Their presence is deliberately required even when the external action was
# NOT_EXECUTED/BLOCKED: an absent artifact is ambiguous, while a typed blocker
# cannot be mistaken for a production success.
B054_EVIDENCE_PATH = "evidence/owner-actions/B-054/keyed-audit-epoch-rollout.json"
B054_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "evidence_mode", "authority_roles",
    "non_material_references", "legacy_epoch", "keyed_epoch",
    "two_person_administration", "migration_receipts", "witness_receipt", "archive_verification",
    "rotation_receipt", "revocation_recovery", "retention", "audit_linkage",
    "rollback_plan", "operator", "repository_checks",
]
B083_EVIDENCE_PATH = "evidence/owner-actions/B-083/byok-real-kms-lifecycle.json"
B083_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "evidence_state", "tenant_redacted",
    "runtime", "external_prerequisites", "custody_policy", "lifecycle",
    "operator", "repository_checks",
]
B097_EVIDENCE_PATH = "evidence/owner-actions/B-097/cloudflare-vcpu-quota-case.json"
B097_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "account_id_redacted", "case_id",
    "requested_total_vcpu", "current_total_vcpu", "declared_reservation_vcpu",
    "active_tenants_concurrent", "provider_decision", "effective_at", "operator",
    "read_only_capture",
]
B086_EVIDENCE_PATH = "evidence/owner-actions/B-086/d1-residency-resolution.json"
B086_PACKET_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "decision", "production_bindings",
    "distinct_database_ids", "dpa_status", "effective_at",
    "signed_document_sha256_or_provider_case", "reviewer",
]
B086_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "capture_commit", "captured_at", "decision", "production_bindings",
    "distinct_database_ids", "dpa_status", "related_legal_surfaces",
    "effective_at", "signed_document_sha256_or_provider_case", "reviewer",
    "unresolved_reason", "cloudflare_observations", "capability_observation",
    "verification", "source_sha256", "commands", "mutations_performed",
]
B154_EVIDENCE_PATH = "evidence/owner-actions/B-154/executed-instrument-resolution.json"
B154_EVIDENCE_REQUIRED_FIELDS = [
    "schema_version", "captured_at", "surfaces", "decisions",
    "signed_documents", "notices", "capability_evidence", "operator",
]
RECEIPT_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT_EXECUTED"})
PACKET_BASE_SHA = "908d3bdc86f17a8b41a280baaea9352d7ed450ab"
BASE_SHA_PROVENANCE_DISCLAIMER = (
    "The base_sha is an immutable D03 packet reference for provenance, not a claim that the reference "
    "is an ancestor of every checkout carrying this packet."
)
B054_REPOSITORY_CHECKS = [
    {
        "command": "python3 scripts/verify_b054_audit_chain_contract.py",
        "status": "PASS",
        "detail": "Unknown, partial, and downgrade epoch metadata fail closed; mutation fixtures are rejected.",
    },
    {
        "command": "python3 scripts/test_audit_chain_epoch_schema.py",
        "status": "PASS",
        "detail": "Additive schema constraints and no-replace guards pass with recursive_triggers=OFF.",
    },
]
B083_REPOSITORY_CHECKS = [
    {
        "command": "python3 scripts/verify_b083_revocation_wiring.py",
        "status": "PASS",
        "detail": "Durable source, pre-bind run_loop wiring, focal behavior, and mutation checks pass.",
    },
    {
        "command": "python3 tests/test_verify_b083_byok.py",
        "status": "PASS",
        "detail": "B083 verifier mutation: green baseline and named red mutant.",
    },
]


class PacketError(ValueError):
    pass


def _read_packet(path: Path = PACKET) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise PacketError(f"missing/non-regular packet: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"packet is not valid UTF-8 JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PacketError("packet root must be an object")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PacketError(f"{label} must be a non-empty string")
    if any(marker in value for marker in FORBIDDEN_MARKERS):
        raise PacketError(f"{label} contains an unresolved/ambiguous marker")
    if any(pattern.search(value) for pattern in SECRET_SHAPES):
        raise PacketError(f"{label} contains credential material")
    return value


def _string_list(value: object, label: str, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise PacketError(f"{label} must be a non-empty list")
    result = []
    for index, entry in enumerate(value):
        result.append(_text(entry, f"{label}[{index}]"))
    return result


def _read_backlog_contracts() -> dict[str, tuple[str, str]]:
    """Read the canonical owner/status contract for the closed packet IDs."""
    path = ROOT / "BACKLOG.md"
    if not path.is_file() or path.is_symlink():
        raise PacketError(f"missing/non-regular backlog: {path}")
    text = path.read_text(encoding="utf-8")
    blocks = re.findall(r"```backlog\n(.*?)```", text, flags=re.DOTALL)
    contracts: dict[str, tuple[str, str]] = {}
    for block in blocks:
        id_match = re.search(r"^id:\s*(B-\d+)\s*$", block, flags=re.MULTILINE)
        if not id_match:
            continue
        item_id = id_match.group(1)
        owner_match = re.search(r"^owner:\s*([^\s]+)\s*$", block, flags=re.MULTILINE)
        status_match = re.search(r"^status:\s*([^\s]+)\s*$", block, flags=re.MULTILINE)
        if not owner_match or not status_match:
            raise PacketError(f"BACKLOG contract is missing owner/status for {item_id}")
        if item_id in contracts:
            raise PacketError(f"BACKLOG contract is duplicated for {item_id}")
        contracts[item_id] = (owner_match.group(1), status_match.group(1))
    missing = sorted(set(EXPECTED_IDS) - set(contracts))
    if missing:
        raise PacketError(f"BACKLOG contract missing packet IDs: {missing}")
    return {item_id: contracts[item_id] for item_id in EXPECTED_IDS}


_SECRET_EXPRESSION = re.compile(r"\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}")


def _strip_yaml_comment(line: str) -> str:
    """Strip YAML comments without treating quoted/string content as syntax."""
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = None
        elif quote == "'":
            if character == "'":
                if index + 1 < len(line) and line[index + 1] == "'":
                    index += 1
                else:
                    quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
        index += 1
    return line.rstrip()


def _workflow_lines(path: Path) -> list[tuple[int, str, int]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PacketError(f"workflow is not valid UTF-8: {path}: {exc}") from exc
    result: list[tuple[int, str, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_yaml_comment(raw_line)
        if not line.strip() or line.strip() == "---":
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indentation]:
            raise PacketError(f"workflow uses tab indentation: {path}:{line_number}")
        result.append((indentation, line[indentation:], line_number))
    return result


def _mapping_entry(content: str) -> tuple[str, str] | None:
    if ":" not in content:
        return None
    key, value = content.split(":", 1)
    key = key.strip()
    if not key:
        return None
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {'"', "'"}:
        key = key[1:-1]
    return key, value.strip()


def _inline_needs(value: str) -> set[str]:
    value = value.strip()
    if not value:
        return set()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    entries = value.split(",")
    result: set[str] = set()
    for entry in entries:
        entry = entry.strip()
        if len(entry) >= 2 and entry[0] == entry[-1] and entry[0] in {'"', "'"}:
            entry = entry[1:-1]
        if entry:
            result.add(entry)
    return result


def _read_yaml_workflow(path: Path, require_workflow_call: bool = True) -> dict[str, object]:
    """Read only the workflow semantics required by the B-111 guard.

    This deliberately avoids a YAML library: the canonical verifier is run
    with ``python3 -S``.  Comments are removed with quote awareness, and secret
    expressions are accepted only from actual ``env:`` mappings, so prose,
    comments, and arbitrary run-string bait cannot satisfy the contract.
    """
    if not path.is_file() or path.is_symlink():
        raise PacketError(f"missing/non-regular workflow: {path}")
    lines = _workflow_lines(path)

    top_keys: dict[str, int] = {}
    for index, (indent, content, _line_number) in enumerate(lines):
        if indent != 0:
            continue
        entry = _mapping_entry(content)
        if entry:
            top_keys[entry[0]] = index
    on_index = top_keys.get("on")
    jobs_index = top_keys.get("jobs")
    if on_index is None and require_workflow_call:
        raise PacketError(f"workflow on contract missing: {path}")
    if jobs_index is None:
        raise PacketError(f"workflow jobs contract missing: {path}")

    declared: set[str] = set()
    if require_workflow_call:
        assert on_index is not None
        workflow_call_index = None
        for index in range(on_index + 1, len(lines)):
            indent, content, _line_number = lines[index]
            if indent <= 0:
                break
            entry = _mapping_entry(content)
            if indent == 2 and entry and entry[0] == "workflow_call" and not entry[1]:
                workflow_call_index = index
                break
        if workflow_call_index is None:
            raise PacketError(f"workflow_call contract missing: {path}")
        secrets_index = None
        for index in range(workflow_call_index + 1, len(lines)):
            indent, content, _line_number = lines[index]
            if indent <= 2:
                break
            entry = _mapping_entry(content)
            if indent == 4 and entry and entry[0] == "secrets" and not entry[1]:
                secrets_index = index
                break
        if secrets_index is None:
            raise PacketError(f"workflow_call.secrets contract missing: {path}")
        for indent, content, _line_number in lines[secrets_index + 1:]:
            if indent <= 4:
                break
            entry = _mapping_entry(content)
            if indent == 6 and entry:
                declared.add(entry[0])

    referenced: set[str] = set()
    known_secrets = B111_ACQUISITION_SECRETS | {"CORELINK_CLI_RELEASE_TOKEN"}
    env_indent: int | None = None
    for indent, content, _line_number in lines:
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        entry = _mapping_entry(content)
        if entry and entry[0] == "env" and not entry[1]:
            env_indent = indent
            continue
        if env_indent is not None and indent == env_indent + 2:
            referenced.update(
                name for name in _SECRET_EXPRESSION.findall(content) if name in known_secrets
            )

    jobs: dict[str, dict[str, object]] = {}
    for index in range(jobs_index + 1, len(lines)):
        indent, content, _line_number = lines[index]
        if indent == 0:
            break
        entry = _mapping_entry(content)
        if indent == 2 and entry and not entry[1]:
            if entry[0] in jobs:
                raise PacketError(f"duplicate workflow job: {path}: {entry[0]}")
            jobs[entry[0]] = {}
        elif indent == 4 and entry and entry[0] == "needs" and jobs:
            current_job = next(reversed(jobs))
            if "needs" in jobs[current_job]:
                raise PacketError(f"duplicate workflow needs: {path}: {current_job}")
            jobs[current_job]["needs"] = _inline_needs(entry[1])
    return {
        "declared": frozenset(declared),
        "referenced": frozenset(referenced),
        "jobs": jobs,
    }


def _read_b111_workflow_contracts(root: Path = ROOT) -> dict[str, object]:
    contracts = {
        path: _read_yaml_workflow(root / path)
        for path in B111_WORKFLOW_SECRETS
    }
    release = _read_yaml_workflow(root / ".github/workflows/release-cli.yml", require_workflow_call=False)
    contracts["release-chain"] = release
    return contracts


def _needs_set(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, set) and all(isinstance(entry, str) for entry in value):
        return set(value)
    if isinstance(value, list) and all(isinstance(entry, str) for entry in value):
        return set(value)
    return set()


def _check_b111_workflow_contract(workflow_contracts: dict[str, object]) -> None:
    for path, expected in B111_WORKFLOW_SECRETS.items():
        contract = workflow_contracts.get(path)
        if not isinstance(contract, dict):
            raise PacketError(f"B-111 workflow contract missing: {path}")
        declared = contract.get("declared")
        if declared != expected:
            raise PacketError(
                f"B-111 {path} workflow_call secrets drifted: "
                f"expected={sorted(expected)}, got={sorted(declared or ())}"
            )
        referenced = contract.get("referenced")
        if referenced != expected:
            raise PacketError(
                f"B-111 {path} executable secret references drifted: "
                f"expected={sorted(expected)}, got={sorted(referenced or ())}"
            )

    release = workflow_contracts.get("release-chain")
    if not isinstance(release, dict) or not isinstance(release.get("jobs"), dict):
        raise PacketError("B-111 B-112 release chain contract missing")
    jobs = release["jobs"]
    for job, expected_needs in B111_RELEASE_CHAIN.items():
        node = jobs.get(job)
        if not isinstance(node, dict):
            raise PacketError(f"B-111 B-112 release chain job missing: {job}")
        actual_needs = _needs_set(node.get("needs"))
        if not expected_needs.issubset(actual_needs):
            raise PacketError(
                f"B-111 B-112 release chain ordering drifted for {job}: "
                f"requires={sorted(expected_needs)}, got={sorted(actual_needs)}"
            )


def _read_b110_evidence() -> dict[str, object]:
    path = ROOT / B110_EVIDENCE_PATH
    if not path.is_file() or path.is_symlink():
        raise PacketError(f"B-110 evidence is missing/non-regular: {B110_EVIDENCE_PATH}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"B-110 evidence is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise PacketError("B-110 evidence root must be an object")
    return record


def _check_b110_evidence(item: dict[str, object]) -> None:
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B110_EVIDENCE_PATH:
        raise PacketError("B-110 evidence path is not the canonical capacity decision")
    if evidence["format"] != "json":
        raise PacketError("B-110 evidence format is not JSON")
    if evidence["required_fields"] != B110_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-110 evidence required fields drifted")
    if evidence["item_schema"] != B110_EVIDENCE_ITEM_SCHEMA:
        raise PacketError("B-110 evidence item schema drifted")
    if item["action_type"] != "ci_capacity_decision":
        raise PacketError("B-110 action type drifted")
    if item["procedure"] != B110_PROCEDURE:
        raise PacketError("B-110 procedure drifted")
    if item["expected_postcondition"] != B110_EXPECTED_POSTCONDITION:
        raise PacketError("B-110 expected postcondition drifted")

    record = _read_b110_evidence()
    if set(record) != set(B110_EVIDENCE_REQUIRED_FIELDS):
        raise PacketError("B-110 evidence fields drifted")
    if record["schema_version"] != 1 or not isinstance(record["captured_at"], str) or not record["captured_at"].strip():
        raise PacketError("B-110 evidence capture metadata drifted")
    if record["selected_option"] != "linux_self_hosted":
        raise PacketError("B-110 capacity decision is not linux_self_hosted")
    if record["workflows"] != B110_EVIDENCE_WORKFLOWS:
        raise PacketError("B-110 workflow evidence drifted")
    if record["capacity_or_billing_reference"] != (
        "CoreLink runner image documentation: Linux x86_64, 4 vCPU, 12.5 GB; migration commit 41c47f236"
    ):
        raise PacketError("B-110 capacity reference drifted")
    if record["coverage_impact"] != (
        "No lane was deleted or parked. The FFI Python/Go/Node matrices remain intact; cache guards remain "
        "self-hosted-safe; workflow assertions are unchanged."
    ):
        raise PacketError("B-110 coverage impact drifted")
    if record["runner_labels"] != ["corelink"]:
        raise PacketError("B-110 runner labels drifted")
    if record["rollback_owner"] != "owner" or record["operator"] != "owner-authorized automation":
        raise PacketError("B-110 evidence ownership metadata drifted")


def _check_b089_surface_contract(item: dict[str, object], root: Path = ROOT) -> None:
    """Pin the approved but inactive Enterprise-only prelaunch posture."""
    expected_references = ["BACKLOG.md#B-089", *B089_SURFACES]
    if item["references"] != expected_references:
        raise PacketError("B-089 source references drifted")
    procedure = item["procedure"]
    if not isinstance(procedure, list) or not any(
        all(path in step for path in B089_SURFACES)
        for step in procedure if isinstance(step, str)
    ):
        raise PacketError("B-089 procedure must name all live source paths")

    sources: dict[str, str] = {}
    for path_text in B089_SURFACES:
        path = root / path_text
        if path.is_symlink() or not path.is_file():
            raise PacketError(f"B-089 source missing or non-regular: {path_text}")
        try:
            sources[path_text] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PacketError(f"B-089 source unreadable: {path_text}") from exc

    historical_path = root / B089_SURFACES[0]
    if hashlib.sha256(historical_path.read_bytes()).hexdigest() != B089_HISTORICAL_V1_SHA256:
        raise PacketError("B-089 historical v1.0.0 SHA-256 differs from the approved base bytes")
    draft_path = root / "legal/sla/v1.1.0.md"
    if draft_path.is_symlink() or not draft_path.is_file():
        raise PacketError("B-089 v1.1.0 prelaunch draft missing or non-regular")
    draft_raw = draft_path.read_text(encoding="utf-8")
    draft = re.sub(r"\s+", " ", draft_raw)
    for marker in (
        "DRAFT — NOT EFFECTIVE", "not a customer agreement", "No SLA service-credit program is currently active",
        "SLA_CREDITS_ENABLED", "#2568", "Counsel approval", "Free", "Solo", "Starter", "Pro", "Max", "Enterprise",
        "0 < shortfall < 0.5 pp", "0.5 pp ≤ shortfall < 1.0 pp", "1.0 pp ≤ shortfall < 2.5 pp",
        "2.5 pp ≤ shortfall ≤ 5.0 pp", "shortfall > 5.0 pp", "absolute uptime `< 95%`",
        "0 < excess ≤ 25%", "25% < excess ≤ 50%", "excess > 50%",
        "DSR erasure `30 days ≤ duration < 45 days`", "DSR erasure `duration ≥ 45 days`",
        "Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours`",
        "Credits stack only across distinct SLOs in the same Service Period.",
        "aggregate is capped at 100% of the Monthly Service Fee.",
        "Catastrophic uptime takes priority over every lower band.",
        "No separate refund is added for the same ordinary SLA breach.",
        "A signed Enterprise Order Form may change only the metrics, rates, or remedies that it expressly identifies.",
        "three consecutive months of uptime breach against an applicable §2 SLO",
        "one catastrophic uptime breach", "repeated DSR erasure breach in two consecutive months",
        "A pro-rata refund of prepaid fees applies only after a valid termination under this section",
        "is not a second recovery for the same SLA breach.",
        "no promise of automatic or manual issuance", "separate controlled release acceptance is recorded",
    ):
        if marker.lower() not in draft.lower():
            raise PacketError(f"B-089 v1.1.0 draft missing policy marker: {marker}")
    if "issued automatically against the next invoice" in draft.lower():
        raise PacketError("B-089 v1.1.0 draft reintroduced active issuance promise")
    expected_tiers = ("Free", "Solo", "Starter", "Pro", "Max", "Enterprise")
    tier_rows = re.findall(r"^\| (Free|Solo|Starter|Pro|Max|Enterprise) \|([^\n]*)$", draft_raw, flags=re.M)
    if [tier for tier, _ in tier_rows] != list(expected_tiers):
        raise PacketError("B-089 v1.1.0 six-tier credit matrix drifted")
    for tier, row in tier_rows:
        values = [value.strip() for value in row.split("|") if value.strip()]
        if tier != "Enterprise" and any(value.strip().lower() != "no" for value in values):
            raise PacketError(f"B-089 non-Enterprise credits are not disabled: {tier}")
        if tier == "Enterprise" and any("proposed" not in value.lower() for value in values):
            raise PacketError("B-089 Enterprise eligibility must remain proposed")

    def require_credit_table(start: str, end: str, header: str, separator: str, expected: tuple[str, ...]) -> None:
        section = draft_raw.split(start, 1)
        if len(section) != 2:
            raise PacketError(f"B-089 v1.1.0 schedule section missing: {start}")
        table = section[1].split(end, 1)[0]
        rows = [line.strip() for line in table.splitlines() if line.strip().startswith("|")]
        if rows[:2] != [header, separator] or rows[2:] != list(expected):
            raise PacketError(f"B-089 v1.1.0 exact schedule rows drifted: {start}")

    require_credit_table(
        "### 2.1 Uptime / availability", "### 2.2 p99 GET latency",
        "| Measured result | Credit as % of Monthly Service Fee |", "|---|---:|",
        (
            "| Target met or exceeded | 0% |",
            "| `0 < shortfall < 0.5 pp` | 5% |",
            "| `0.5 pp ≤ shortfall < 1.0 pp` | 10% |",
            "| `1.0 pp ≤ shortfall < 2.5 pp` | 25% |",
            "| `2.5 pp ≤ shortfall ≤ 5.0 pp` | 50% |",
            "| `shortfall > 5.0 pp` or absolute uptime `< 95%` | 100% plus the §4 termination right |",
        ),
    )
    require_credit_table(
        "### 2.2 p99 GET latency", "### 2.3 Freshness",
        "| Excess over target | Credit as % of Monthly Service Fee |", "|---|---:|",
        (
            "| `0 < excess ≤ 25%` | 5% |",
            "| `25% < excess ≤ 50%` | 10% |",
            "| `excess > 50%` | 25% |",
        ),
    )
    require_credit_table(
        "### 2.3 Freshness", "## 3. Stacking, cap, and remedy",
        "| Breach | Credit |", "|---|---|",
        (
            "| DSR erasure `30 days ≤ duration < 45 days` | 5% |",
            "| DSR erasure `duration ≥ 45 days` | 25% plus DPO incident review |",
            "| Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours` | 10% |",
        ),
    )

    pricing = sources[B089_SURFACES[2]]
    canonical = re.search(r"CANONICAL_TIERS:\s*readonly TierId\[\]\s*=\s*\[([^]]+)\]", pricing, re.S)
    if canonical is None:
        raise PacketError("B-089 sold-tier census missing")
    sold_tiers = re.findall(r'"([a-z]+)"', canonical.group(1))
    if sold_tiers != ["free", "solo", "starter", "pro", "max", "enterprise"]:
        raise PacketError(f"B-089 sold-tier census drifted: {sold_tiers}")
    # Pricing keeps a future Enterprise eligibility flag; activation is separately gated.
    expected_flags = ("false", "false", "false", "false", "false", "true")
    for tier, expected_flag in zip(sold_tiers, expected_flags, strict=True):
        blocks = re.findall(rf"(?ms)^  {tier}: \{{(.*?)^  \}},", pricing)
        if len(blocks) != 1 or re.findall(r"\bslaCredits:\s*(true|false)\b", blocks[0]) != [expected_flag]:
            raise PacketError(f"B-089 published pricing credit posture drifted: {tier}")

    terms = sources[B089_SURFACES[1]]
    section = terms.split("14. Service availability and credits", 1)
    if len(section) != 2:
        raise PacketError("B-089 published Terms credit section missing")
    section_body = section[1].split("</section>", 1)[0]
    if "No SLA service-credit program is currently active" not in section_body:
        raise PacketError("B-089 Terms must keep SLA credits inactive")
    if "Pro-tier customers are entitled to a" in section_body or "applied automatically to the next invoice" in section_body:
        raise PacketError("B-089 Terms reintroduced a Pro/automatic active credit claim")
    faq = root / "marketing/sales/FAQ-MASTER.md"
    pricing_page = root / "apps/docs/src/pages/pricing.tsx"
    for path in (faq, pricing_page):
        if path.is_symlink() or not path.is_file():
            raise PacketError(f"B-089 public surface missing or non-regular: {path.relative_to(root)}")
    faq_text = faq.read_text(encoding="utf-8").lower()
    if "sla service credits are not active for any tier today" not in faq_text or "valid termination under that sla" not in faq_text:
        raise PacketError("B-089 FAQ active-credit/refund posture drifted")
    if "99.9% sla + credits" in pricing_page.read_text(encoding="utf-8").lower():
        raise PacketError("B-089 public pricing page reintroduced inactive SLA-credit claim")


def _read_json_evidence(path_text: str, expected_fields: list[str], label: str) -> dict[str, object]:
    """Load one canonical receipt and reject missing/extra root fields and secrets."""
    path = ROOT / path_text
    if not path.is_file() or path.is_symlink():
        raise PacketError(f"{label} evidence is missing/non-regular: {path_text}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"{label} evidence is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise PacketError(f"{label} evidence root must be an object")
    if set(record) != set(expected_fields):
        raise PacketError(
            f"{label} evidence fields drifted; expected={expected_fields}, got={sorted(record)}"
        )
    serialized = json.dumps(record, ensure_ascii=False)
    if any(pattern.search(serialized) for pattern in SECRET_SHAPES):
        raise PacketError(f"{label} evidence contains credential material")
    return record


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise PacketError(f"{label} fields drifted; expected={sorted(expected)}, got={got}")
    return value


def _receipt_status(value: object, label: str) -> str:
    if value not in RECEIPT_STATUSES:
        raise PacketError(f"{label} has invalid status: {value!r}")
    return str(value)


def _receipt_blocker(value: object, status: str, label: str) -> None:
    if status != "PASS":
        if not isinstance(value, str) or not value.strip():
            raise PacketError(f"{label} must name an exact blocker for {status}")


def _check_b054_evidence(item: dict[str, object]) -> None:
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B054_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-054 evidence binding drifted")
    if evidence["required_fields"] != B054_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-054 evidence required fields drifted")
    record = _read_json_evidence(B054_EVIDENCE_PATH, B054_EVIDENCE_REQUIRED_FIELDS, "B-054")
    if record["schema_version"] != 1 or not isinstance(record["captured_at"], str) or not record["captured_at"].strip():
        raise PacketError("B-054 evidence capture metadata drifted")
    if record["evidence_mode"] != "FIXTURE_READINESS_ONLY":
        raise PacketError("B-054 evidence must identify fixture/readiness scope")
    if record["authority_roles"] != ["SRE executor", "Security approver"]:
        raise PacketError("B-054 authority roles drifted")
    if record["non_material_references"] != [
        "docs/internal/secrets-checklist.md#245-audit-chain-link-key-keyring",
        "docs/internal/secrets-checklist.md#257-audit-chain-signing-trust-root-public-keys",
        "specs/04_sprints/S09/work_items/WI-S09-007-keyed-audit-chain-epoch.md#required-implementation-proof-and-residual-blockers",
    ]:
        raise PacketError("B-054 non-material references drifted")
    expected_epochs = {
        "legacy_epoch": ("E0/unkeyed", "NOT_EXECUTED"),
        "keyed_epoch": ("E1/keyed", "BLOCKED"),
    }
    for name in ("legacy_epoch", "keyed_epoch"):
        epoch = _exact_keys(record[name], {"algorithm_version", "row_count", "verification", "status", "blocker"}, f"B-054 {name}")
        status = _receipt_status(epoch["status"], f"B-054 {name}")
        expected_algorithm, expected_status = expected_epochs[name]
        if epoch["algorithm_version"] != expected_algorithm:
            raise PacketError(f"B-054 {name} algorithm version drifted")
        if epoch["row_count"] is not None:
            raise PacketError(f"B-054 {name} row count would overstate an unexecuted probe")
        if epoch["verification"] != expected_status or status != expected_status or status != epoch["verification"]:
            raise PacketError(f"B-054 {name} status/verification coherence drifted")
        _receipt_blocker(epoch["blocker"], status, f"B-054 {name}")
    custody = _exact_keys(
        record["two_person_administration"],
        {"status", "executor_role", "approver_role", "access_review", "authorization_receipt", "blocker"},
        "B-054 two_person_administration",
    )
    custody_status = _receipt_status(custody["status"], "B-054 two_person_administration")
    if custody_status != "BLOCKED":
        raise PacketError("B-054 two-person administration status would overstate custody evidence")
    if custody["executor_role"] != "SRE executor" or custody["approver_role"] != "Security approver":
        raise PacketError("B-054 two-person administration roles drifted")
    access_review = _exact_keys(
        custody["access_review"],
        {"status", "owner", "review_date", "blocker"},
        "B-054 two_person_administration.access_review",
    )
    if _receipt_status(access_review["status"], "B-054 access review") != "BLOCKED":
        raise PacketError("B-054 access review status would overstate custody evidence")
    if access_review["owner"] is not None or access_review["review_date"] is not None:
        raise PacketError("B-054 access review cannot invent owner or review-date evidence")
    _receipt_blocker(access_review["blocker"], "BLOCKED", "B-054 access review")
    authorization = _exact_keys(
        custody["authorization_receipt"],
        {"status", "reference", "blocker"},
        "B-054 two_person_administration.authorization_receipt",
    )
    if _receipt_status(authorization["status"], "B-054 authorization receipt") != "NOT_EXECUTED":
        raise PacketError("B-054 authorization receipt status would overstate witnessed custody")
    if authorization["reference"] is not None:
        raise PacketError("B-054 authorization receipt has a reference despite not being executed")
    _receipt_blocker(authorization["blocker"], "NOT_EXECUTED", "B-054 authorization receipt")
    _receipt_blocker(custody["blocker"], custody_status, "B-054 two_person_administration")
    migration = _exact_keys(record["migration_receipts"], {"status", "migrations", "references", "blocker"}, "B-054 migration_receipts")
    migration_status = _receipt_status(migration["status"], "B-054 migration_receipts")
    if migration_status != "NOT_EXECUTED":
        raise PacketError("B-054 migration status would overstate an unexecuted rollout")
    if migration["migrations"] != ["0109_audit_chain_epoch_contract.sql", "0110_audit_chain_epoch_row_metadata.sql"]:
        raise PacketError("B-054 migration list drifted")
    if migration["references"] != []:
        raise PacketError("B-054 migration references would overstate an applied migration")
    _receipt_blocker(migration["blocker"], migration_status, "B-054 migration_receipts")
    expected_receipt_statuses = {
        "witness_receipt": "BLOCKED",
        "archive_verification": "NOT_EXECUTED",
        "rotation_receipt": "BLOCKED",
        "revocation_recovery": "NOT_EXECUTED",
        "retention": "NOT_EXECUTED",
        "audit_linkage": "NOT_EXECUTED",
    }
    for name, fields in {
        "witness_receipt": {"status", "reference", "blocker"},
        "archive_verification": {"status", "proof_reference", "blocker"},
        "rotation_receipt": {"status", "reference", "blocker"},
        "revocation_recovery": {"status", "reference", "blocker"},
        "retention": {"status", "reference", "blocker"},
        "audit_linkage": {"status", "reference", "blocker"},
    }.items():
        nested = _exact_keys(record[name], fields, f"B-054 {name}")
        status = _receipt_status(nested["status"], f"B-054 {name}")
        if status != expected_receipt_statuses[name]:
            raise PacketError(f"B-054 {name} status would overstate the current rollout state")
        reference_key = "proof_reference" if name == "archive_verification" else "reference"
        if status != "PASS" and nested[reference_key] is not None:
            raise PacketError(f"B-054 {name} has a reference despite status {status}")
        _receipt_blocker(nested["blocker"], status, f"B-054 {name}")
    rollback = _exact_keys(record["rollback_plan"], {"status", "decision", "blocker"}, "B-054 rollback_plan")
    rollback_status = _receipt_status(rollback["status"], "B-054 rollback_plan")
    if rollback_status != "NOT_EXECUTED" or rollback["decision"] != "preserve E0 and do not cut over":
        raise PacketError("B-054 rollback decision/status drifted")
    _receipt_blocker(rollback["blocker"], rollback_status, "B-054 rollback_plan")
    if not isinstance(record["operator"], str) or not record["operator"].strip():
        raise PacketError("B-054 operator missing")
    _check_repository_checks(record["repository_checks"], "B-054", B054_REPOSITORY_CHECKS)


def _check_repository_checks(value: object, label: str, expected: list[dict[str, str]] | None = None) -> None:
    if not isinstance(value, list) or not value:
        raise PacketError(f"{label} repository_checks must be a non-empty list")
    for index, entry in enumerate(value):
        check = _exact_keys(entry, {"command", "status", "detail"}, f"{label} repository_checks[{index}]")
        if not isinstance(check["command"], str) or not check["command"].strip():
            raise PacketError(f"{label} repository_checks[{index}] command missing")
        if check["status"] not in {"PASS", "FAIL", "NOT_EXECUTED", "BLOCKED"}:
            raise PacketError(f"{label} repository_checks[{index}] status invalid")
        if not isinstance(check["detail"], str) or not check["detail"].strip():
            raise PacketError(f"{label} repository_checks[{index}] detail missing")
    if expected is not None and value != expected:
        raise PacketError(f"{label} repository_checks commands/details drifted")


def _check_b071_owner_packet(item: dict[str, object]) -> None:
    if item["action_type"] != "owner_authorized_bounded_gc_observation_evidence":
        raise PacketError("B-071 action type must preserve the owner-authorized observation boundary")
    procedure = item["procedure"]
    assert isinstance(procedure, list)
    if len(procedure) != len(B071_PROCEDURE_MARKERS):
        raise PacketError("B-071 procedure must retain all eight ordered owner/provider actions")
    for index, markers in enumerate(B071_PROCEDURE_MARKERS):
        if any(marker not in procedure[index] for marker in markers):
            raise PacketError(f"B-071 procedure[{index}] lost a scope, evidence, or zero-delete boundary")

    boundary = item["inputs_and_credentials_boundary"]
    assert isinstance(boundary, dict)
    inputs = boundary["inputs"]
    credentials = boundary["credentials"]
    assert isinstance(inputs, list) and isinstance(credentials, str)
    boundary_text = " ".join(inputs) + " " + credentials
    if any(marker not in boundary_text for marker in B071_BOUNDARY_MARKERS):
        raise PacketError("B-071 inputs lost retention, readiness, runtime, or bounded-scope evidence")
    if any(marker not in credentials for marker in B071_CREDENTIAL_MARKERS):
        raise PacketError("B-071 credential boundary lost secret or no-delete controls")

    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != "evidence/owner-actions/B-071/gc-production-dry-run.json" or evidence["format"] != "json":
        raise PacketError("B-071 evidence must retain the canonical GC observation receipt path")
    if evidence["required_fields"] != B071_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-071 evidence must match the collector's exact root schema")
    schema = evidence["item_schema"]
    assert isinstance(schema, str)
    if any(marker not in schema for marker in B071_SCHEMA_REQUIRED_TERMS):
        raise PacketError("B-071 evidence schema lost a required field, bound, or pending-review rule")

    postcondition = item["expected_postcondition"]
    retry = item["retry_and_rollback"]
    assert isinstance(postcondition, str) and isinstance(retry, str)
    if any(marker not in postcondition for marker in B071_POSTCONDITION_MARKERS):
        raise PacketError("B-071 postcondition lost required external evidence or zero-delete boundary")
    if any(marker not in retry for marker in B071_RETRY_MARKERS):
        raise PacketError("B-071 retry path lost its fail-closed owner/provider boundary")

    references = item["references"]
    assert isinstance(references, list)
    if not B071_REFERENCES.issubset(references):
        raise PacketError("B-071 references lost its issue, readiness, collector, or procedure anchor")


def _check_b083_evidence(item: dict[str, object]) -> None:
    if item["action_type"] != "owner_authorized_real_kms_lifecycle_evidence":
        raise PacketError("B-083 action type must name the owner-authorized lifecycle evidence boundary")
    procedure = item["procedure"]
    assert isinstance(procedure, list)
    if len(procedure) != len(B083_PROCEDURE_MARKERS):
        raise PacketError("B-083 procedure must retain the complete seven-step owner packet")
    for index, markers in enumerate(B083_PROCEDURE_MARKERS):
        if any(marker not in procedure[index] for marker in markers):
            raise PacketError(f"B-083 procedure[{index}] lost a lifecycle, custody, or evidence boundary")
    boundary = item["inputs_and_credentials_boundary"]
    assert isinstance(boundary, dict)
    inputs = boundary["inputs"]
    credentials = boundary["credentials"]
    assert isinstance(inputs, list) and isinstance(credentials, str)
    boundary_text = " ".join(inputs) + " " + credentials
    if any(marker not in boundary_text for marker in B083_BOUNDARY_MARKERS):
        raise PacketError("B-083 credential boundary lost tenant, custody, audit, or no-mutation protection")
    postcondition = item["expected_postcondition"]
    retry = item["retry_and_rollback"]
    assert isinstance(postcondition, str) and isinstance(retry, str)
    if any(marker not in postcondition for marker in B083_POSTCONDITION_MARKERS):
        raise PacketError("B-083 postcondition lost lifecycle completeness or p99 boundary")
    if any(marker not in retry for marker in B083_RETRY_MARKERS):
        raise PacketError("B-083 retry path lost fail-closed or owner-authorization boundary")
    references = item["references"]
    assert isinstance(references, list)
    if not B083_REFERENCES.issubset(references):
        raise PacketError("B-083 references lost its issue, verifier, workflow, or evidence anchor")
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B083_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-083 evidence binding drifted")
    if evidence["required_fields"] != B083_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-083 evidence required fields drifted")
    record = _read_json_evidence(B083_EVIDENCE_PATH, B083_EVIDENCE_REQUIRED_FIELDS, "B-083")
    try:
        validate_b083_evidence(record)
    except B083EvidenceError as exc:
        raise PacketError(f"B-083 lifecycle evidence invalid: {exc}") from exc
    _check_repository_checks(record["repository_checks"], "B-083", B083_REPOSITORY_CHECKS)


def _check_b008_action_contract(item: dict[str, object]) -> None:
    """Keep B-008's owner procedure aligned with the protected staging receipt gate."""
    if item["action_type"] != "external_read_credential_and_single_staging_drill":
        raise PacketError("B-008 action type must require read-only review and one staging drill")
    if item["procedure"] != B008_PROCEDURE:
        raise PacketError("B-008 procedure lost its read-only key, protected admission, or one-drill boundary")

    boundary = item["inputs_and_credentials_boundary"]
    assert isinstance(boundary, dict)
    if boundary["inputs"] != B008_INPUTS or boundary["credentials"] != B008_CREDENTIAL_BOUNDARY:
        raise PacketError("B-008 admission inputs or credential separation drifted")

    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B008_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-008 evidence binding drifted")
    if evidence["required_fields"] != B008_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-008 receipt fields must capture admission, drill, PagerDuty, webhook, and D1 evidence")
    if evidence["item_schema"] != B008_EVIDENCE_ITEM_SCHEMA:
        raise PacketError("B-008 nested receipt schema drifted")
    if item["expected_postcondition"] != B008_EXPECTED_POSTCONDITION:
        raise PacketError("B-008 postcondition must require correlated proof of human delivery")
    if item["retry_and_rollback"] != B008_RETRY_AND_ROLLBACK:
        raise PacketError("B-008 retry path must prohibit duplicates and require owner authorization")
    references = item["references"]
    assert isinstance(references, list)
    if not B008_REQUIRED_REFERENCES.issubset(references):
        raise PacketError("B-008 references lost its backlog, staging dependency, or receipt contract")
    try:
        topology = json.loads((ROOT / B008_STAGING_TOPOLOGY_PATH).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"B-008 staging topology is unavailable or invalid: {exc}") from exc
    _check_b008_staging_binding(topology)


def _check_b008_staging_binding(topology: object) -> None:
    """Bind the owner packet to the checked-in protected staging service route."""
    if not isinstance(topology, dict):
        raise PacketError("B-008 staging topology must be an object")
    cloudflare = topology.get("cloudflare")
    if not isinstance(cloudflare, dict):
        raise PacketError("B-008 staging topology has no Cloudflare contract")
    if cloudflare.get("root_worker") != B008_STAGING_ROOT_WORKER:
        raise PacketError("B-008 staging root worker binding drifted")
    if cloudflare.get("synthetic_receiver_worker") != B008_STAGING_RECEIVER:
        raise PacketError("B-008 staging receiver binding drifted")
    service_bindings = cloudflare.get("service_bindings")
    expected_binding = {
        "worker": B008_STAGING_ROOT_WORKER,
        "binding": B008_STAGING_SERVICE_BINDING,
        "service": B008_STAGING_RECEIVER,
    }
    if not isinstance(service_bindings, list) or expected_binding not in service_bindings:
        raise PacketError("B-008 scheduled drill service binding is not source-bound to staging")


def _check_b097_evidence(item: dict[str, object]) -> None:
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B097_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-097 evidence binding drifted")
    if evidence["required_fields"] != B097_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-097 evidence required fields drifted")
    record = _read_json_evidence(B097_EVIDENCE_PATH, B097_EVIDENCE_REQUIRED_FIELDS, "B-097")
    if record["schema_version"] != 1 or record["captured_at"] != "2026-09-13T00:44:49Z":
        raise PacketError("B-097 evidence capture metadata drifted")
    if not isinstance(record["account_id_redacted"], str) or not re.fullmatch(r"[0-9a-f]{4}\.\.\.[0-9a-f]{4}", record["account_id_redacted"]):
        raise PacketError("B-097 account identifier must remain redacted")
    if record["case_id"] is not None or record["requested_total_vcpu"] is not None or record["effective_at"] is not None:
        raise PacketError("B-097 receipt must not invent an unevidenced support case or requested/effective quota")
    if record["current_total_vcpu"] != 1500 or record["declared_reservation_vcpu"] != 1295 or record["active_tenants_concurrent"] is not None:
        raise PacketError("B-097 quota/active-tenant capture is not the measured truthful state")
    if record["provider_decision"] != "pending":
        raise PacketError("B-097 provider decision must remain pending without a case/decision receipt")
    capture = _exact_keys(record["read_only_capture"], {"cloudchamber_account_endpoint", "provider_limit_confirmed", "provider_response", "application_readback", "instance_census", "active_tenant_metric", "tenant_population_readback", "activity_readback", "support_case"}, "B-097 read_only_capture")
    if capture["cloudchamber_account_endpoint"] != "GET /accounts/{account}/containers/me":
        raise PacketError("B-097 read_only_capture endpoint drifted")
    if capture["provider_limit_confirmed"] is not True or capture["support_case"] != "not evidenced in this capture; no case ID or provider decision was supplied":
        raise PacketError("B-097 read_only_capture support/limit boundary drifted")
    response = _exact_keys(capture["provider_response"], {"http_success", "total_vcpu", "vcpu_per_deployment", "total_memory_mib", "usage"}, "B-097 provider_response")
    if response != {"http_success": True, "total_vcpu": 1500, "vcpu_per_deployment": 4, "total_memory_mib": 6291456, "usage": None}:
        raise PacketError("B-097 provider response drifted")
    apps = _exact_keys(capture["application_readback"], {"source", "listed_applications", "cache_main_runner_subtotal_vcpu", "other_applications_reservation_vcpu", "applications", "interpretation"}, "B-097 application_readback")
    if apps["source"] != "Cloudflare Containers application info API via Wrangler OAuth, read-only" or apps["listed_applications"] != 11:
        raise PacketError("B-097 application census source/count drifted")
    expected_apps = {
        "corelink-prod-corelinkserver-prod": (200, 0.25, 16, 1),
        "corelink-prod-sam-corelinkserver-prod-sam": (200, 0.25, 15, 0),
        "corelink-prod-lhr-corelinkserver-prod-lhr": (200, 0.25, 15, 0),
        "corelink-prod-nrt-corelinkserver-prod-nrt": (200, 0.25, 15, 0),
        "corelink-prod-syd-corelinkserver-prod-syd": (200, 0.25, 15, 0),
        "corelink-spawn-worker-runnercontainer": (250, 4, 18, 0),
        "corelink-spawn-worker-runnerdevenvdo": (10, 4, 7, 0),
        "corelink-spawn-worker-checkhostcontainer": (1, 4, 1, 0),
        "corelink-fabricd-fabricdcontainer": (1, 1, 1, 0),
        "githugr-engine-enginecontainer": (0, 0.25, 0, 0),
        "githugr-githugrcontainer": (0, 0.25, 0, 0),
    }
    rows = apps["applications"]
    if not isinstance(rows, list) or len(rows) != len(expected_apps):
        raise PacketError("B-097 application census incomplete")
    observed = {}
    for index, raw in enumerate(rows):
        app = _exact_keys(raw, {"name", "max_instances", "vcpu", "instances", "active_instances"}, f"B-097 application[{index}]")
        name = app["name"]
        if not isinstance(name, str) or name in observed:
            raise PacketError("B-097 duplicate/invalid application")
        observed[name] = (app["max_instances"], app["vcpu"], app["instances"], app["active_instances"])
    if observed != expected_apps:
        raise PacketError("B-097 application snapshot drifted")
    subtotal = sum(row[0] * row[1] for name, row in observed.items() if name.startswith("corelink-prod-") or name == "corelink-spawn-worker-runnercontainer")
    total = sum(row[0] * row[1] for row in observed.values())
    if (apps["cache_main_runner_subtotal_vcpu"], apps["other_applications_reservation_vcpu"], total) != (subtotal, total - subtotal, record["declared_reservation_vcpu"]):
        raise PacketError("B-097 declared reservation arithmetic drifted")
    if apps["interpretation"] != "max_instances times vCPU is declared application ceiling, not provider usage, billable CPU, or tenant concurrency; application instances include healthy/prewarmed capacity":
        raise PacketError("B-097 application ceiling disclaimer drifted")
    census = _exact_keys(capture["instance_census"], {"source", "window_start_utc", "captured_at", "by_region", "listed_named_instances", "inactive", "running_tenant_named", "running_reserved_system", "interpretation"}, "B-097 instance_census")
    if census["source"] != "Cloudflare Containers instances API via Wrangler OAuth, read-only":
        raise PacketError("B-097 instance census source drifted")
    if (census["window_start_utc"], census["captured_at"]) != ("2026-09-13T14:28:08Z", "2026-09-13T14:28:56Z"):
        raise PacketError("B-097 instance census capture window drifted")
    expected_regions = {
        "prod": {"listed": 4, "inactive": 3, "running_tenant_named": 0, "running_reserved_system": 1},
        "prod-sam": {"listed": 2, "inactive": 2, "running_tenant_named": 0, "running_reserved_system": 0},
        "prod-lhr": {"listed": 2, "inactive": 2, "running_tenant_named": 0, "running_reserved_system": 0},
        "prod-nrt": {"listed": 2, "inactive": 2, "running_tenant_named": 0, "running_reserved_system": 0},
        "prod-syd": {"listed": 2, "inactive": 2, "running_tenant_named": 0, "running_reserved_system": 0},
    }
    if census["by_region"] != expected_regions:
        raise PacketError("B-097 instance census regional state drifted")
    for region, observed_region in census["by_region"].items():
        if any(type(observed_region[field]) is not int for field in expected_regions[region]):
            raise PacketError("B-097 instance census regional count must be an integer")
    for field, row_field in (("listed_named_instances", "listed"), ("inactive", "inactive"), ("running_tenant_named", "running_tenant_named"), ("running_reserved_system", "running_reserved_system")):
        if type(census[field]) is not int or census[field] != sum(row[row_field] for row in expected_regions.values()):
            raise PacketError(f"B-097 instance census {field} arithmetic drifted")
    if census["interpretation"] != "later point-in-time named-instance supplement (2026-09-13T14:28:08Z..14:28:56Z) to the top-level 2026-09-13T00:44:49Z quota/application-cap/D1 capture, not one simultaneous snapshot; zero running tenant-named containers is not peak tenant concurrency, customer activity, or account vCPU usage":
        raise PacketError("B-097 instance census point-in-time disclaimer drifted")
    if capture["active_tenant_metric"] != "unavailable: tenant registration/state, stale audit activity, and application instance health are not a concurrent-active-tenant metric":
        raise PacketError("B-097 active-tenant metric disclaimer drifted")
    tenants = _exact_keys(capture["tenant_population_readback"], {"database", "access", "query", "rows", "total_registered_tenants", "changed_db", "rows_written", "interpretation"}, "B-097 tenant_population_readback")
    if tenants["database"] != "CONFIG_DB/prod" or tenants["access"] != "remote-read-only" or tenants["query"] != "SELECT primary_region, COALESCE(tenant_state,'NULL') AS tenant_state, COUNT(*) AS tenant_count FROM tenant GROUP BY primary_region,tenant_state ORDER BY primary_region,tenant_state":
        raise PacketError("B-097 tenant census source drifted")
    if tenants["rows"] != [
        {"primary_region": "apac", "tenant_state": "active", "tenant_count": 1},
        {"primary_region": "enam", "tenant_state": "active", "tenant_count": 62},
        {"primary_region": "enam", "tenant_state": "dpa_pending", "tenant_count": 93},
        {"primary_region": "wnam", "tenant_state": "dpa_pending", "tenant_count": 108},
    ] or tenants["total_registered_tenants"] != sum(row["tenant_count"] for row in tenants["rows"]):
        raise PacketError("B-097 tenant census population drifted")
    if tenants["changed_db"] is not False or type(tenants["rows_written"]) is not int or tenants["rows_written"] != 0 or tenants["interpretation"] != "tenant_state=active means registered state, not a concurrent workload or container assignment":
        raise PacketError("B-097 tenant census read-only/disclaimer drifted")
    activity = _exact_keys(capture["activity_readback"], {"database", "access", "customer_audit_rows", "distinct_tenants_all_time", "last_customer_audit_ts_ms", "distinct_tenants_last_15m", "distinct_tenants_last_1h", "distinct_tenants_last_24h", "interpretation"}, "B-097 activity_readback")
    if activity["database"] != "CONFIG_DB/prod" or activity["access"] != "remote-read-only" or any(activity[name] != expected for name, expected in {"customer_audit_rows": 71, "distinct_tenants_all_time": 16, "last_customer_audit_ts_ms": 1784669020765, "distinct_tenants_last_15m": 0, "distinct_tenants_last_1h": 0, "distinct_tenants_last_24h": 0}.items()):
        raise PacketError("B-097 activity readback drifted")
    if activity["interpretation"] != "retained audit activity is stale; these aggregates are not a concurrent-active-tenant measurement":
        raise PacketError("B-097 activity readback disclaimer drifted")


def _check_b086_evidence(item: dict[str, object]) -> None:
    procedure = " ".join(item["procedure"])
    if "pending legal-review template, not an executed instrument" not in procedure:
        raise PacketError("B-086 packet must distinguish the pending residency template from an executed instrument")
    if "any subsequently executed residency claim" not in item["expected_postcondition"]:
        raise PacketError("B-086 packet must not assert a current executed residency claim")
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B086_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-086 evidence binding drifted")
    if evidence["required_fields"] != B086_PACKET_REQUIRED_FIELDS:
        raise PacketError("B-086 evidence required fields drifted")
    record = _read_json_evidence(B086_EVIDENCE_PATH, B086_EVIDENCE_REQUIRED_FIELDS, "B-086")
    if record["schema_version"] != "1.0" or not isinstance(record["captured_at"], str) or not record["captured_at"].strip():
        raise PacketError("B-086 evidence capture metadata drifted")
    capture_commit = record["capture_commit"]
    if not isinstance(capture_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", capture_commit):
        raise PacketError("B-086 source hashes need an explicit full capture commit")
    expected_sources = {
        "wrangler.toml",
        "legal/dpa-residency-amendment.md",
        "scripts/verify_b086_d1_residency.py",
        "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json",
    }
    source_hashes = _exact_keys(record["source_sha256"], expected_sources, "B-086 source_sha256")
    for source_path, expected_hash in source_hashes.items():
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise PacketError(f"B-086 source hash is malformed: {source_path}")
        try:
            captured = subprocess.run(
                ["git", "show", f"{capture_commit}:{source_path}"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise PacketError(f"B-086 capture commit cannot read {source_path}") from exc
        actual_hash = hashlib.sha256(captured).hexdigest()
        if expected_hash != actual_hash:
            raise PacketError(f"B-086 source hash does not match capture commit: {source_path}")
    if record["decision"] != "unresolved" or record["effective_at"] is not None:
        raise PacketError("B-086 evidence must retain the unresolved decision boundary")
    bindings = record["production_bindings"]
    if not isinstance(bindings, list) or len(bindings) != 5:
        raise PacketError("B-086 production binding population drifted")
    expected_envs = {"prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd"}
    actual_envs: set[str] = set()
    database_ids: set[str] = set()
    for index, binding in enumerate(bindings):
        row = _exact_keys(
            binding,
            {"env", "binding", "database_name", "database_id", "residency_claim"},
            f"B-086 production_bindings[{index}]",
        )
        if not all(isinstance(row[field], str) and row[field].strip() for field in row):
            raise PacketError(f"B-086 production_bindings[{index}] contains an empty field")
        actual_envs.add(row["env"])
        database_ids.add(row["database_id"])
        if row["binding"] != "CONFIG_DB":
            raise PacketError("B-086 production binding is not CONFIG_DB")
    if actual_envs != expected_envs or len(database_ids) != 1 or record["distinct_database_ids"] != 1:
        raise PacketError("B-086 D1 identity census drifted")
    if not isinstance(record["dpa_status"], str) or "PENDING_LEGAL_REVIEW" not in record["dpa_status"]:
        raise PacketError("B-086 DPA status must remain pending legal review")
    if not isinstance(record["signed_document_sha256_or_provider_case"], (str, type(None))):
        raise PacketError("B-086 signed/provider reference shape drifted")
    if record["signed_document_sha256_or_provider_case"] is not None:
        raise PacketError("B-086 unresolved evidence must not invent a signed/provider reference")
    if not isinstance(record["unresolved_reason"], str) or "Owner/counsel" not in record["unresolved_reason"]:
        raise PacketError("B-086 unresolved reason is missing the owner/counsel boundary")
    verification = _exact_keys(record["verification"], {"b086_self_test", "owner_action_packet", "status"}, "B-086 verification")
    if verification != {"b086_self_test": "pass", "owner_action_packet": "pass (29 items)", "status": "open"}:
        raise PacketError("B-086 verification receipt drifted")
    if record["mutations_performed"] != []:
        raise PacketError("B-086 evidence must remain read-only")


def _check_b154_evidence(item: dict[str, object]) -> None:
    evidence = item["evidence"]
    assert isinstance(evidence, dict)
    if evidence["path"] != B154_EVIDENCE_PATH or evidence["format"] != "json":
        raise PacketError("B-154 evidence binding drifted")
    if evidence["required_fields"] != B154_EVIDENCE_REQUIRED_FIELDS:
        raise PacketError("B-154 evidence required fields drifted")
    record = _read_json_evidence(B154_EVIDENCE_PATH, B154_EVIDENCE_REQUIRED_FIELDS, "B-154")
    if record["schema_version"] != 1 or not isinstance(record["captured_at"], str) or not record["captured_at"].strip():
        raise PacketError("B-154 evidence capture metadata drifted")
    expected_surfaces = {
        "legal/dpa/v1.0.0.en-US.md": "dpa_object_lock",
        "legal/sla/v1.0.0.md": "sla_byok_kill_switch",
        "marketing/launch/CASE-STUDIES/enterprise-byok.md": "case_study_attribution",
    }
    surfaces = record["surfaces"]
    if not isinstance(surfaces, list) or len(surfaces) != len(expected_surfaces):
        raise PacketError("B-154 surface population drifted")
    seen_surfaces: set[str] = set()
    for index, surface in enumerate(surfaces):
        row = _exact_keys(surface, {"surface", "original_claim", "decision", "effective_at", "evidence_reference"}, f"B-154 surfaces[{index}]")
        path = row["surface"]
        if path not in expected_surfaces or path in seen_surfaces:
            raise PacketError("B-154 surface identity drifted")
        seen_surfaces.add(path)
        if not isinstance(row["original_claim"], str) or not row["original_claim"].strip():
            raise PacketError("B-154 original claim is missing")
        if row["decision"] != "unresolved" or row["effective_at"] is not None:
            raise PacketError("B-154 receipt must not imply an executed remedy")
        reference = row["evidence_reference"]
        if not isinstance(reference, str) or not reference.strip():
            raise PacketError("B-154 evidence reference is missing")
        reference_match = re.fullmatch(
            re.escape(path) + r":[^;]+; sha256 ([0-9a-f]{64})", reference
        )
        if reference_match is None:
            raise PacketError(f"B-154 evidence reference is not source-bound: {path}")
        source_path = ROOT / path
        if not source_path.is_file() or source_path.is_symlink():
            raise PacketError(f"B-154 evidence source is missing/non-regular: {path}")
        actual_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if reference_match.group(1) != actual_hash:
            raise PacketError(f"B-154 evidence reference hash does not match source: {path}")
    decisions = _exact_keys(record["decisions"], set(expected_surfaces.values()), "B-154 decisions")
    if any(not isinstance(value, str) or not value.startswith("unresolved:") for value in decisions.values()):
        raise PacketError("B-154 decisions must retain explicit unresolved boundaries")
    signed_documents = record["signed_documents"]
    if not isinstance(signed_documents, list) or len(signed_documents) != 2:
        raise PacketError("B-154 signed-document population drifted")
    seen_documents: set[str] = set()
    for index, document in enumerate(signed_documents):
        row = _exact_keys(document, {"path", "version", "sha256"}, f"B-154 signed_documents[{index}]")
        if row["path"] not in {"legal/dpa/v1.0.0.en-US.md", "legal/sla/v1.0.0.md"} or row["path"] in seen_documents:
            raise PacketError("B-154 signed-document identity drifted")
        seen_documents.add(row["path"])
        if row["version"] != "1.0.0" or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise PacketError("B-154 signed-document hash/version drifted")
        source_path = ROOT / row["path"]
        try:
            actual_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise PacketError(f"B-154 signed-document source is unreadable: {row['path']}") from exc
        if row["sha256"] != actual_sha256:
            raise PacketError(f"B-154 signed-document hash does not match source: {row['path']}")
    notices = record["notices"]
    if not isinstance(notices, list) or len(notices) != 3:
        raise PacketError("B-154 notice population drifted")
    for index, notice in enumerate(notices):
        row = _exact_keys(notice, {"surface", "status", "effective_at", "reference", "blocker"}, f"B-154 notices[{index}]")
        if row["status"] != "NOT_EXECUTED" or row["effective_at"] is not None or row["reference"] is not None:
            raise PacketError("B-154 notice receipt would overstate external execution")
        if not isinstance(row["blocker"], str) or not row["blocker"].strip():
            raise PacketError("B-154 notice blocker is missing")
    capability = _exact_keys(record["capability_evidence"], {"object_lock", "byok_kill_switch", "case_study"}, "B-154 capability_evidence")
    object_lock = _exact_keys(
        capability["object_lock"], {"status", "reference", "historical_report"},
        "B-154 capability_evidence.object_lock",
    )
    probe_path = "evidence/owner-actions/B-046/object-lock-probe.json"
    if object_lock["status"] != "INDETERMINATE" or object_lock["reference"] != probe_path:
        raise PacketError("B-154 latest Object Lock classification must remain indeterminate")
    probe_file = ROOT / probe_path
    if not probe_file.is_file() or probe_file.is_symlink():
        raise PacketError("B-154 latest Object Lock probe is missing/non-regular")
    try:
        probe = json.loads(probe_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"B-154 latest Object Lock probe is unreadable: {exc}") from exc
    if probe.get("classification") != "INDETERMINATE":
        raise PacketError("B-154 Object Lock receipt disagrees with latest probe")
    history = _exact_keys(
        object_lock["historical_report"],
        {"date", "classification", "reference", "raw_probe_artifact"},
        "B-154 capability_evidence.object_lock.historical_report",
    )
    if history != {
        "date": "2026-08-25",
        "classification": "REPORTED_NOT_IMPLEMENTED",
        "reference": "BACKLOG.md#B-046",
        "raw_probe_artifact": "NOT_LINKED_IN_B046",
    }:
        raise PacketError("B-154 historical Object Lock report is not source-bound")
    expected_capabilities = {
        "byok_kill_switch": "UNVERIFIED_RUNTIME_P99",
        "case_study": "NOT_PUBLISHED",
    }
    for name, expected_status in expected_capabilities.items():
        row = _exact_keys(capability[name], {"status", "reference"}, f"B-154 capability_evidence.{name}")
        if row["status"] != expected_status or not isinstance(row["reference"], str) or not row["reference"].strip():
            raise PacketError(f"B-154 capability evidence drifted for {name}")
    if not isinstance(record["operator"], str) or "read-only" not in record["operator"]:
        raise PacketError("B-154 operator boundary drifted")



B035_EVIDENCE_PATH = "evidence/owner-actions/B-035/tls-legal-remediation.json"
B035_SOURCE_SHA = "ff232e5c53f69872ed8108e5f5defb185655b0ae"
B035_ARTIFACT_SHA256 = "060de7b927cc46a3035f646b03348ccc92f4b60673d1edee44a4d9a04c0d3761"


def _check_b035_record(record: object) -> None:
    if not isinstance(record, dict):
        raise PacketError("B-035 closure evidence must be a JSON object")
    required = {
        "schema_version", "captured_at", "decision", "source_sha", "source_pr",
        "source_receipt", "workflow_run", "artifact_id", "artifact_sha256",
        "observed_floor", "handshakes", "prelaunch_disposition", "limitations",
    }
    if set(record) != required:
        raise PacketError("B-035 closure evidence fields drifted")
    expected = {
        "schema_version": 1,
        "decision": "truthful_tls_1_2_prelaunch",
        "source_sha": B035_SOURCE_SHA,
        "source_pr": "https://github.com/HuGR-dev/corelink-server/pull/2691",
        "source_receipt": "https://github.com/HuGR-dev/corelink-server/issues/2163#issuecomment-5851309900",
        "workflow_run": "https://github.com/HuGR-dev/corelink-server/actions/runs/36282709392",
        "artifact_id": 10918909501,
        "artifact_sha256": B035_ARTIFACT_SHA256,
        "observed_floor": "TLS 1.2",
        "handshakes": {"passed": 24, "total": 24, "host_count": 12},
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise PacketError("B-035 closure evidence source/run/artifact contract drifted")
    stamp = record["captured_at"]
    if not isinstance(stamp, str) or not re.fullmatch(r"2026-09-27T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z", stamp):
        raise PacketError("B-035 closure evidence UTC capture time missing")
    disposition = record["prelaunch_disposition"]
    if not isinstance(disposition, dict) or set(disposition) != {
        "customer_terms_executed", "external_recipients", "basis",
        "counsel_approval_claimed", "customer_notice_claimed",
    }:
        raise PacketError("B-035 prelaunch disposition fields drifted")
    if any(disposition[key] is not False for key in (
        "customer_terms_executed", "external_recipients",
        "counsel_approval_claimed", "customer_notice_claimed",
    )) or not isinstance(disposition["basis"], str) or "#1645" not in disposition["basis"]:
        raise PacketError("B-035 prelaunch disposition is not source-bound")
    limitations = record["limitations"]
    if not isinstance(limitations, str) or "Bazel returned HTTP 500" not in limitations or "does not establish Bazel application health" not in limitations:
        raise PacketError("B-035 TLS-only limitation missing")


def _check_b035_evidence(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise PacketError("B-035 closure evidence file missing or non-regular")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PacketError("B-035 closure evidence unreadable or malformed") from exc
    _check_b035_record(record)


def _check_item(
    item: object,
    expected_id: str,
    backlog_contracts: dict[str, tuple[str, str]],
    workflow_contracts: dict[str, object],
) -> None:
    if not isinstance(item, dict):
        raise PacketError(f"{expected_id}: item must be an object")
    if set(item) != ITEM_FIELDS:
        missing = sorted(ITEM_FIELDS - set(item))
        extra = sorted(set(item) - ITEM_FIELDS)
        raise PacketError(f"{expected_id}: item fields mismatch; missing={missing}, extra={extra}")
    if item.get("id") != expected_id:
        raise PacketError(f"item id mismatch: expected {expected_id!r}, got {item.get('id')!r}")
    canonical_owner, canonical_status = backlog_contracts[expected_id]
    expected_owner = "owner" if expected_id in LEGACY_OWNER_IDS else "tl"
    allowed_statuses = {"open", "parked"}
    # B-012 closes on its verified hosted DCO/rustfmt receipt; B-013 closes on
    # its owner-authorized redacted deletion record; B-110 closes after the
    # owner selects the already-provisioned CoreLink Linux substrate and the
    # four workflow migrations are evidenced. B-035 closes on the owner-selected
    # prelaunch wording and exact live TLS receipt. Other legacy items remain pending.
    if expected_id in CLOSED_PACKET_IDS:
        allowed_statuses.add("done")
    if canonical_owner != expected_owner or canonical_status not in allowed_statuses:
        raise PacketError(
            f"{expected_id}: BACKLOG canonical contract drifted from "
            f"{expected_owner}/allowed-status ({canonical_owner}/{canonical_status})"
        )
    # The packet remains status-aligned with BACKLOG; parked legacy items may
    # retain an open packet while external action is pending.
    packet_status_ok = item.get("status") == canonical_status or (
        canonical_status == "parked" and item.get("status") == "open"
    )
    if item.get("owner") != canonical_owner or not packet_status_ok:
        raise PacketError(
            f"{expected_id}: packet owner/status disagrees with BACKLOG "
            f"({canonical_owner}/{canonical_status})"
        )
    _text(item["action_type"], f"{expected_id}.action_type")

    procedure = _string_list(item["procedure"], f"{expected_id}.procedure", minimum=2)
    if not all(step.startswith(("RUN:", "UI:")) for step in procedure):
        raise PacketError(f"{expected_id}.procedure: every step must be an explicit RUN: or UI: procedure")

    boundary = item["inputs_and_credentials_boundary"]
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        raise PacketError(f"{expected_id}.inputs_and_credentials_boundary fields are ambiguous")
    _string_list(boundary["inputs"], f"{expected_id}.inputs_and_credentials_boundary.inputs")
    _text(boundary["credentials"], f"{expected_id}.inputs_and_credentials_boundary.credentials")

    evidence = item["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
        raise PacketError(f"{expected_id}.evidence fields are ambiguous")
    path = _text(evidence["path"], f"{expected_id}.evidence.path")
    if not path.startswith("evidence/owner-actions/") and not path.startswith("docs/compliance/vendor-reviews/"):
        raise PacketError(f"{expected_id}.evidence.path is outside the canonical owner-evidence roots")
    if Path(path).is_absolute() or ".." in Path(path).parts:
        raise PacketError(f"{expected_id}.evidence.path must be repository-relative")
    if evidence["format"] not in ("json", "markdown"):
        raise PacketError(f"{expected_id}.evidence.format is unsupported")
    _string_list(evidence["required_fields"], f"{expected_id}.evidence.required_fields")
    _text(evidence["item_schema"], f"{expected_id}.evidence.item_schema")

    _text(item["expected_postcondition"], f"{expected_id}.expected_postcondition")
    _text(item["retry_and_rollback"], f"{expected_id}.retry_and_rollback")
    references = _string_list(item["references"], f"{expected_id}.references", minimum=1)
    if not any(reference.startswith("BACKLOG.md#") for reference in references):
        raise PacketError(f"{expected_id}.references must include its BACKLOG anchor")
    if expected_id == "B-035":
        if path != B035_EVIDENCE_PATH:
            raise PacketError("B-035 evidence locator drifted")
        _check_b035_evidence(ROOT / path)
    if expected_id == "B-008":
        _check_b008_action_contract(item)
    if expected_id == "B-089":
        _check_b089_surface_contract(item)
    if expected_id == "B-065":
        if evidence["required_fields"] != B065_EVIDENCE_REQUIRED_FIELDS:
            raise PacketError("B-065 evidence must retain the two destination IDs and typed resolution")
        schema = evidence["item_schema"]
        if any(term not in schema for term in B065_SCHEMA_REQUIRED_TERMS):
            raise PacketError("B-065 evidence schema omits a resolution or destination invariant")
        procedure_text = " ".join(procedure)
        if not all(term in procedure_text for term in ("v1", "v2", "explicit decision", "if already disabled")):
            raise PacketError("B-065 procedure must distinguish readback, mutation, and no-op")
    if expected_id == "B-012":
        # A token can make bot-PR CI unattended, but a missing runner or a
        # zero-job startup failure is a different boundary. Keep the owner
        # packet from regressing to "all bot PR events are suppressed".
        if item["action_type"] != "github_app_installation_token" or len(procedure) != 5:
            raise PacketError("B-012 credential procedure drifted")
        required_by_step = (
            ("GitHub App", "contents:write", "pull_requests:write", "repository-scoped"),
            ("CORELINK_BOT_APP_ID", "CORELINK_BOT_APP_PRIVATE_KEY", "--body-stdin", "five creators"),
            ("startup_failure", "online runner labelled corelink", "hosted-billing", "ubuntu-latest"),
            ("approval-required", "GITHUB_TOKEN", "Dependabot"),
            ("job_urls", "job_count", "zero-job run", "dco-check", "rustfmt"),
        )
        for index, required in enumerate(required_by_step):
            if any(marker not in procedure[index] for marker in required):
                raise PacketError(f"B-012 procedure[{index}] lost a token/runner/approval boundary")
        credentials = boundary["credentials"]
        assert isinstance(credentials, str)
        if not all(marker in credentials for marker in ("administration:read", "actions:read", "separate")):
            raise PacketError("B-012 bot-PR and runner-census credential scopes were conflated")
        schema = evidence["item_schema"]
        assert isinstance(schema, str)
        if not all(
            marker in schema
            for marker in (
                "run_id", "workflow", "url", "approval_state", "job_count", "job_urls",
                "runner_names", "runner_group", "runner_labels", "ubuntu-latest",
                "conclusion", "started_at", "completed_at",
            )
        ):
            raise PacketError("B-012 evidence no longer requires job-level execution")
        if not all(
            marker in item["expected_postcondition"]
            for marker in ("actual jobs completed", "no approval pending", "DCO", "rustfmt")
        ):
            raise PacketError("B-012 closure no longer requires completed jobs")
    if expected_id == "B-110":
        _check_b110_evidence(item)
    if expected_id == "B-054":
        _check_b054_evidence(item)
    if expected_id == "B-071":
        _check_b071_owner_packet(item)
    if expected_id == "B-083":
        _check_b083_evidence(item)
    if expected_id == "B-097":
        _check_b097_evidence(item)
    if expected_id == "B-086":
        _check_b086_evidence(item)
    if expected_id == "B-154":
        _check_b154_evidence(item)
    if expected_id == "B-111":
        procedure_text = " ".join(item["procedure"])
        schema_text = item["evidence"]["item_schema"]
        missing = sorted(
            name for name in B111_ACQUISITION_SECRETS
            if name not in procedure_text or name not in schema_text
        )
        if missing:
            raise PacketError(f"B-111 procedure/evidence omits executable secret names: {missing}")
        if "B-112" not in procedure_text:
            raise PacketError("B-111 procedure must name B-112 as the upstream release prerequisite")
        evidence_fields = set(item["evidence"]["required_fields"])
        if "release_prerequisite" not in evidence_fields:
            raise PacketError("B-111 evidence must retain the B-112 release prerequisite")
        _check_b111_workflow_contract(workflow_contracts)


def check_data(
    data: object,
    identifier: str | None = None,
    backlog_contracts: dict[str, tuple[str, str]] | None = None,
    workflow_contracts: dict[str, object] | None = None,
) -> dict[str, int]:
    if not isinstance(data, dict):
        raise PacketError("packet root must be an object")
    required_root = {"schema_version", "packet_id", "repository", "base_sha", "status", "non_claim", "population", "items"}
    if set(data) != required_root:
        raise PacketError(f"packet root fields mismatch; expected {sorted(required_root)}")
    if data["schema_version"] != 1 or data["repository"] != "HuGR-Labs/corelink-server":
        raise PacketError("packet schema or repository identity changed")
    # This packet was authored against the D03 reconciliation snapshot.  The
    # field is a provenance reference, not a merge-base assertion: recovery
    # restacks may legitimately carry the packet on a branch that does not
    # descend from that snapshot.  Keep the exact immutable reference while
    # avoiding the false claim that it is an ancestor of every checkout.
    if data["base_sha"] != PACKET_BASE_SHA:
        raise PacketError("packet base SHA is not the requested exact D03 provenance reference")
    if backlog_contracts is None:
        backlog_contracts = _read_backlog_contracts()
    if workflow_contracts is None:
        workflow_contracts = _read_b111_workflow_contracts()
    if set(backlog_contracts) != set(EXPECTED_IDS):
        raise PacketError("BACKLOG owner/status reconciliation population is not closed")
    _text(data["packet_id"], "packet_id")
    _text(data["status"], "status")
    non_claim = _text(data["non_claim"], "non_claim")
    if BASE_SHA_PROVENANCE_DISCLAIMER not in non_claim:
        raise PacketError("non_claim must include the base_sha provenance disclaimer")

    population = data["population"]
    if population != list(EXPECTED_IDS):
        raise PacketError(f"closed population mismatch: expected {list(EXPECTED_IDS)}, got {population!r}")
    items = data["items"]
    if not isinstance(items, list) or len(items) != len(EXPECTED_IDS):
        raise PacketError("items must contain exactly the closed population")
    seen: set[str] = set()
    evidence_paths: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise PacketError("items contains a non-object entry")
        item_id = item.get("id")
        if item_id in seen:
            raise PacketError(f"duplicate item: {item_id}")
        seen.add(str(item_id))
        if identifier is None or str(item_id) == identifier:
            _check_item(item, str(item_id), backlog_contracts, workflow_contracts)
        evidence_path = str(item["evidence"]["path"])
        if evidence_path in evidence_paths:
            raise PacketError(f"duplicate canonical evidence path: {evidence_path}")
        evidence_paths.add(evidence_path)
    if seen != set(EXPECTED_IDS):
        raise PacketError(f"item population mismatch: expected {list(EXPECTED_IDS)}, got {sorted(seen)}")
    if identifier is not None and identifier not in EXPECTED_IDS:
        raise PacketError(f"unknown packet id: {identifier}")
    return {"items": len(items), "population": len(population)}


def mutation_self_test(data: dict[str, object]) -> int:
    """Remove/mangle every load-bearing packet boundary in memory."""
    mutations = 0
    backlog_contracts = _read_backlog_contracts()
    workflow_contracts = _read_b111_workflow_contracts()
    for index, item in enumerate(data["items"]):
        assert isinstance(item, dict)
        for field in ITEM_FIELDS:
            mutated = copy.deepcopy(data)
            del mutated["items"][index][field]
            try:
                check_data(
                    mutated,
                    backlog_contracts=backlog_contracts,
                    workflow_contracts=workflow_contracts,
                )
            except PacketError:
                mutations += 1
            else:
                raise PacketError(f"mutation was accepted: {item['id']}.{field}")
        for field, mutated_value in (("owner", "owner" if item["owner"] == "tl" else "tl"), ("status", "closed")):
            mutated = copy.deepcopy(data)
            mutated["items"][index][field] = mutated_value
            try:
                check_data(
                    mutated,
                    backlog_contracts=backlog_contracts,
                    workflow_contracts=workflow_contracts,
                )
            except PacketError:
                mutations += 1
            else:
                raise PacketError(f"cross-file {field} mutation was accepted: {item['id']}")
    mutated_population = copy.deepcopy(data)
    mutated_population["population"] = list(EXPECTED_IDS[:-1])
    try:
        check_data(
            mutated_population,
            backlog_contracts=backlog_contracts,
            workflow_contracts=workflow_contracts,
        )
    except PacketError:
        mutations += 1
    else:
        raise PacketError("population mutation was accepted")
    mutated_path = copy.deepcopy(data)
    mutated_path["items"][1]["evidence"]["path"] = mutated_path["items"][0]["evidence"]["path"]
    try:
        check_data(
            mutated_path,
            backlog_contracts=backlog_contracts,
            workflow_contracts=workflow_contracts,
        )
    except PacketError:
        mutations += 1
    else:
        raise PacketError("duplicate evidence-path mutation was accepted")
    # B-035: a metadata-only done claim must fail if the source-bound receipt
    # is absent or its immutable artifact digest changes.
    try:
        _check_b035_evidence(ROOT / "evidence/owner-actions/B-035/missing.json")
    except PacketError:
        mutations += 1
    else:
        raise PacketError("B-035 missing-file mutation was accepted")
    b035 = json.loads((ROOT / B035_EVIDENCE_PATH).read_text(encoding="utf-8"))
    b035["artifact_sha256"] = "0" * 64
    try:
        _check_b035_record(b035)
    except PacketError:
        mutations += 1
    else:
        raise PacketError("B-035 artifact-digest mutation was accepted")
    return mutations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", choices=EXPECTED_IDS)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        data = _read_packet()
        result = check_data(data, args.id)
        mutations = mutation_self_test(data) if args.self_test else 0
    except (OSError, PacketError) as exc:
        print(f"owner-action packet: FAIL: {exc}", file=sys.stderr)
        return 1
    suffix = f", {mutations} mutation(s) rejected" if args.self_test else ""
    print(f"owner-action packet: PASS: {result['items']} item(s), closed population verified{suffix}")
    if args.id == "B-054":
        evidence = _read_json_evidence(B054_EVIDENCE_PATH, B054_EVIDENCE_REQUIRED_FIELDS, "B-054")
        print(
            "B-054 evidence: "
            f"{evidence['evidence_mode']}; "
            f"rotation={evidence['rotation_receipt']['status']}; "
            f"revocation_recovery={evidence['revocation_recovery']['status']}; "
            f"retention={evidence['retention']['status']}; "
            f"audit_linkage={evidence['audit_linkage']['status']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
