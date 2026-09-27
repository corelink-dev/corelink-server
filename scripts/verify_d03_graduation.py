#!/usr/bin/env python3
"""Closed-population graduation gate for the D03 TL backlog lane.

This is intentionally a bounded register check.  It does not dispatch CI,
contact GitHub, or pretend that production evidence is present.  It proves
that the one DCO candidate accounts for the exact original population, that
every parked item has an executable owner packet, that every post-graduation
retired item has a local retirement gate, and that the six DONE items still
pass their local inverted guards. A reopened item must retain a fail-closed
evidence receipt.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.backlog_verify import parse
from scripts.verify_b006_evidence import EvidenceError as B006EvidenceError
from scripts.verify_b006_evidence import validate_closure as validate_b006_closure
from scripts.verify_b006_evidence import validate_receipt as validate_b006_receipt
from scripts.verify_b006_provider_binding import ProviderBindingError, validate_provider_binding
from scripts.verify_b229_clerk_webhook import VerificationError as B229VerificationError
from scripts.verify_b229_clerk_webhook import verify_repo as verify_b229_receipt


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "docs/handoff/2026-09-06-d03-graduation-packets.json"
OWNER_POPULATION = ("B-039",)
POST_GRADUATION_RETIRED = ("B-210",)
OWNER_PACKET_FIELDS = {"owner", "status", "dependency", "action", "artifact", "command"}
OWNER_MIRROR_URL = "https://corelink-artifacts.humangr.com/tlaplus/v1.8.0/eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a/tla2tools.jar"
OWNER_MIRROR_SHA256 = "eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a"

# The compact D03 register is only a handoff index.  Its command must still
# preserve the load-bearing parts of the detailed owner packet.  Keep this
# map closed: accepting a self-declared profile/sample count would let a
# command redirect arbitrary output while claiming to run the right proof.
COMMAND_CONTRACTS: dict[str, dict[str, Any]] = {
    "B-044": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-044",
        "profiles": [], "sample_count": 1,
        "required": ["orphan_reconcile_scan", "sbox", "observe", "type-1", "type-2", "tail_rc", "124"],
        "safety": ["RECONCILE_ORPHAN_TEARDOWN=0"],
        "forbidden": ["RECONCILE_ORPHAN_TEARDOWN=1", "wrangler delete", "wrangler destroy"],
    },
    "B-046": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-046",
        "profiles": [], "sample_count": 2,
        "required": ["--probe", "object-lock", "COMPLIANCE"],
        "safety": ["B046_PROBE_ALLOW_MUTATION=1", "corelink-b046-probe-"],
        "forbidden": ["corelink-prod", "0102_cas_retention", "compliance database"],
    },
    "B-063": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-063",
        "profiles": ["93da3f7a", "enam"], "sample_count": 3,
        "required": ["audit_outbox", "GROUP BY", "part_last_archived", "audit-archive-lag", "PagerDuty", "workflow_dispatch", "corelink-config-prod"],
        "safety": ["--remote", "--ref main", "SELECT", "B063_REPAIR_APPROVED=1"],
        "forbidden": ["DELETE FROM", "UPDATE ", "INSERT INTO"],
    },
    "B-068": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-068",
        "profiles": ["d1", "r2", "stripe", "neon"], "sample_count": 4,
        "required": ["real-ignored-harnesses.yml", "workflow_dispatch", "seed", "active_yaml", "awk"],
        "safety": ["--ref main", "profile=", "OWNER_APPROVED_REAL_INTEGRATION=1"],
        "forbidden": ["emit_e2e_seed", "PAT signing seed"],
    },
    "B-071": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-071",
        "profiles": [], "sample_count": 1,
        "required": ["gc-sweep-dry-run.yml", "GC_LIVE_DELETE=false", "deleted_count", "0"],
        "safety": ["credentialless", "dry-run"],
        "forbidden": ["GC_LIVE_DELETE=true", "container-build-push-prod.yml", "DELETE "],
    },
    "B-072": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-072",
        "profiles": ["0 14 * * 1", "59 23 * * 1"], "sample_count": 1,
        "required": ["SCHEDULED_DRILL_DELIVERY", "corelink-synthetic-pager-staging", "correlation", "PagerDuty", "synthetic_page_drills"],
        "safety": ["receiver", "202", "SCHEDULED_DRILL_RECEIVER_DEPLOYED"],
        "forbidden": ["PAGERDUTY_ROUTING_KEY=", "Authorization: Bearer"],
    },
    "B-083": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-083",
        "profiles": ["byok-aws-real"], "sample_count": 1,
        "required": ["/v1/admin/byok/activate", "/v1/admin/byok/deactivate", "check_access", "cas", "run_loop"],
        "safety": ["test-tenant", "fail-closed", "OWNER_APPROVED_BYOK_TEST=1"],
        "forbidden": ["production tenant", "plaintext Tcs", "customer CMK"],
    },
    "B-098": {
        "owner_packet": "docs/handoff/2026-09-05-b098-owner-action-packet.md",
        "profiles": [], "sample_count": 1,
        "required": ["verify_b098_repo_hygiene.py", "--dry-run", "--expected-main-sha"],
        "safety": ["no semver release tag", "--dry-run"],
        "forbidden": ["git tag -a", "git push", "--force"],
    },
    "B-102": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-102",
        "profiles": ["cas:rw"], "sample_count": 3,
        "required": ["/cargo", "1 KiB", "Server-Timing", "third_request_hot"],
        "safety": ["-le 60", "cas:rw", "OWNER_APPROVED_PROBE=1"],
        "forbidden": ["/v1/customer/cas/probe"],
    },
    "B-107": {
        "owner_packet": "docs/handoff/2026-09-05-b103-b129-attribution-owner-packet.md#B-107",
        "profiles": ["ostore", "oaccounting"], "sample_count": 3,
        "required": ["/cargo/", "1 KiB", "Server-Timing", "three sequential", "phase sum", "deployed commit"],
        "safety": ["-le 60", "timeout 25s", "--max-time 20", "Authorization: Bearer", "OWNER_APPROVED_PROBE=1", "CORELINK_DEPLOYED_COMMIT"],
        "forbidden": ["/v1/customer/cas/probe", "X-Server-Timing-Wdb-Detail", "sqlite_master", "DROP ", "DELETE FROM"],
    },
    "B-104": {
        "owner_packet": "docs/handoff/2026-09-05-b103-b129-attribution-owner-packet.md#B-104",
        "profiles": ["authenticated"], "sample_count": 10,
        "required": ["missing", "median", "p90", "version"],
        "safety": ["Authorization: Bearer", "HTTP status", "OWNER_APPROVED_PROBE=1"],
        "forbidden": ["--fail", "maximum"],
    },
    "B-105": {
        "owner_packet": "docs/campaigns/remediation/work-packages/B091-B130.md#WP-B105",
        "profiles": [], "sample_count": 6,
        "required": [
            "perf-production-evidence.yml",
            "collect_b105_same_lane.py", "expected_sha", "gh api repos/HuGR-Labs/corelink-server/commits/main", "run_id", "gh run view", "gh run download",
            "b102-b108-owner-evidence-", "corelink-performance-evidence.v2.json",
            "cache_mode", "disabled", "enabled", "B105-cache-comparison.json", "createdAt", "dispatch_started_at", "headSha", ".headSha == $expected_sha",
            "verify_b102_b108_evidence.py --packet", "--expect open",
        ],
        "safety": ["--ref main", "OWNER_APPROVED_LANE_DISPATCH=1", "status", "completed"],
        "forbidden": ["release-slsa3.yml", "--force"],
    },
    "B-106": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-106",
        "profiles": ["d1", "kv", "l1"], "sample_count": 2,
        "required": ["cold", "sleep 61", "Server-Timing", "30-second KV revocation backstop", "at least 61 seconds", "minted_at_epoch", "unused_since_epoch", "observed_at_epoch"],
        "safety": ["CORELINK_COLD_PAT", "revocation", "OWNER_APPROVED_PROBE=1"],
        "forbidden": ["TTL", "KV_TTL", "--fail"],
    },
    "B-112": {
        "owner_packet": "docs/campaigns/remediation/work-packages/B091-B130.md#WP-B112",
        "profiles": ["linux", "windows"], "sample_count": 1,
        "required": ["release-cli.yml", "release-slsa3.yml", "cargo-zigbuild", "checksums", "SLSA", "gh run rerun", "B112_RUN_ID", "B112_EXPECTED_REF", "B112_EXPECTED_SHA", "B112_EXPECTED_ATTEMPT", "workflowName", "headBranch", "headSha", "head_sha", "event", "push", "cli-v", "cli-vMAJOR.MINOR.PATCH", "status == \"completed\"", "conclusion", "--failed", "--attempt", "workflow_call", "gh api", "referenced_workflows", "run_attempt", "slsa_workflow", "slsa_ref", "slsa_event", "slsa_meta", "slsa_run_id", "artifact"],
        "safety": ["--root", "OWNER_APPROVED_RELEASE_RERUN=1"],
        "forbidden": ["git tag", "cosign-sign.yml", "--force", "workflow_dispatch", "--all", "gh run list --workflow release-slsa3.yml"],
    },
    "B-113": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-113",
        "profiles": ["nightly.yml", "sbom.yml", "buck2-starter-ci.yml", "fuzz-nightly.yml", "endurance-2h-nightly.yml", "load-test-nightly.yml", "billing-health-daily.yml"],
        "sample_count": 7,
        "required": ["runner", "conclusion", "terraform-drift.yml"],
        "safety": ["--ref main", "B-111", "OWNER_APPROVED_LANE_DISPATCH=1"],
        "forbidden": ["terraform-drift.yml --dispatch"],
    },
    "B-122": {
        "owner_packet": "docs/handoff/2026-09-05-b103-b129-attribution-owner-packet.md#B-122",
        "profiles": ["B-102", "B-107"], "sample_count": 3,
        "required": ["deployed commit", "ostore", "oaccounting", "phase sum"],
        "safety": ["1 KiB", "-le 60", "timeout 25s", "--max-time 20", "Authorization: Bearer", "OWNER_APPROVED_PROBE=1"],
        "forbidden": ["sqlite_master", "DROP ", "DELETE FROM", "X-Server-Timing-Wdb-Detail", "/v1/customer/cas/probe"],
    },
    "B-125": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-125",
        "profiles": ["audit_outbox"], "sample_count": 1,
        "required": ["D-1-audit-trail", "arrivals", "sealed_rows", "oldest_unsealed", "seal_latency", "512"],
        "safety": ["--remote", "SELECT", "OWNER_APPROVED_READONLY=1"],
        "forbidden": ["AUDIT_DRAIN", "DELETE ", "UPDATE ", "drain --run"],
    },
    "B-127": {
        "owner_packet": "docs/campaigns/remediation/work-packages/B091-B130.md#WP-B127",
        "profiles": ["satisfied", "violated", "unevaluable", "weur"], "sample_count": 1,
        "required": ["LEFT JOIN", "audit_outbox", "tenants", "total_rows", "denominator", "corelink-config-prod"],
        "safety": ["--remote", "SELECT", "OWNER_APPROVED_READONLY=1"],
        "forbidden": ["sqlite_master", "DELETE ", "UPDATE ", "DROP "],
    },
    "B-129": {
        "owner_packet": "docs/handoff/2026-09-05-b103-b129-attribution-owner-packet.md#B-129",
        "profiles": ["qtier", "qdo", "qbatch", "qresid", "qcontrol"], "sample_count": 10,
        "required": ["SERVER_TIMING_WDB_DETAIL=on", "deployed commit", "timestamp", "region", "sample", "residual", "<10%", "phase sum", "ohop", "wdb", "origin", "/cargo/"],
        "safety": ["diagnostic", "Authorization: Bearer", "OWNER_APPROVED_PROBE=1", "DEPLOYED_SERVER_TIMING_WDB_DETAIL", "timeout 25s", "--max-time 20", "deadline"],
        "forbidden": ["--fail", "production config", "X-Server-Timing-Wdb-Detail", "/v1/customer/cas/probe"],
    },
    "B-134": {
        "owner_packet": "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json#B-134",
        "profiles": ["smoke-install.yml", "cosign-sign.yml"], "sample_count": 2,
        "required": ["docker info", "image_digest", "Rekor", "webhook", "UNMEASURED", "headBranch", "headSha", "event", "expected_sha"],
        "safety": ["workflow_dispatch", "corelink", "OWNER_APPROVED_B134=1"],
        "forbidden": ["codeql.yml", "secrets-drift.yml", "--force"],
    },
    "B-216": {
        "owner_packet": "docs/internal/b215-b230-runtime-owner-actions.md#B-216",
        "profiles": ["corelink-signup-worker", "corelink-dsr-erasure-dlq"], "sample_count": 1,
        "required": ["dsr.erasure.dead_letter", "requeue_once", "paging", "revision", "priorRequeues < MAX_DLQ_REQUEUES", "normalizedDlqRequeueCount", "return MAX_DLQ_REQUEUES;", "B216_EXPECTED_REVISION", "B216_EVENT_ID", "event_id", "exhausted", "requeue_count", "delivery_status", "receipt_id"],
        "safety": ["OWNER_APPROVED_B216=1", "timeout 30s"],
        "forbidden": ["wrangler queue send", "wrangler queues delete", "DELETE FROM", "--force"],
    },
    "B-251": {
        "owner_packet": "docs/campaigns/remediation/work-packages/B131-B167.md#WP-B251",
        "profiles": ["b251-d02", "b251-d03-observed", "InMemoryAtomicQuotaChecker"], "sample_count": 1000,
        "required": ["verify_b251_quota_cas_budget.py", "run_b251_latency_probe.py", "--allow-run", "--d02-identity", "--observed-identity", "--output", "b251-d02-identity.json", "b251-d03-observed-identity.json", "corelink.b251.latency-probe.v1", "identity.match", "fields_compared", "seed", "failure", "blob", "measurement.sample_count", "measurement.p99_us", "measurement.limit_us", "production_latency_measured", "InMemoryAtomicQuotaChecker"],
        "safety": ["set -euo pipefail", "p99_us < .measurement.limit_us", "production_latency_measured == false"],
        "forbidden": ["--force", "production quota redesign", "B251_OBSERVED_", "jq -n", "cargo test -p corelink-billing", "B251-latency-probe.log"],
    },
}
SEMANTIC_PACKET_FIELDS = {"owner_packet", "profiles", "sample_count", "required", "safety", "forbidden"}

# Each operation is deliberately unique within its command.  A token-only
# contract could survive removal of the actual probe while retaining a quoted
# profile name or artifact path, so the verifier also requires these concrete
# owner-packet operations.
COMMAND_OPERATIONS: dict[str, tuple[str, ...]] = {
    "B-044": ("timeout 30s", "tail_rc=0"),
    "B-046": ("verify_b046_object_lock_probe.py --probe",),
    "B-063": ("audit-archive-lag.yml --ref main", "wrangler d1 execute corelink-config-prod"),
    "B-068": ("gh workflow run real-ignored-harnesses.yml", "active_yaml=\"$(awk"),
    "B-071": ("gh workflow run gc-sweep-dry-run.yml",),
    "B-072": ("verify_b072_scheduled_drills.py", "service = \"corelink-synthetic-pager-staging\""),
    "B-083": ("verify_b083_revocation_wiring.py",),
    "B-098": ("verify_b098_repo_hygiene.py",),
    "B-102": ("$CORELINK_PROD_BASE/cargo",),
    "B-107": ("$CORELINK_PROD_BASE/cargo/${CORELINK_DOGFOOD_TENANT:?}/b107-${ordinal}",),
    "B-104": ("does-not-exist-$ordinal",),
    "B-105": (
        "gh workflow run perf-production-evidence.yml --ref main",
        "expected_sha=\"$(gh api repos/HuGR-Labs/corelink-server/commits/main --jq .sha)\"", "run_id=\"\"", "gh run view \"$run_id\"", "gh run download \"$run_id\"",
        ".headSha == $expected_sha",
        "tee artifacts/d03/B105-cache-comparison.json", "verify_b102_b108_evidence.py --packet",
    ),
    "B-106": ("$CORELINK_PROD_BASE/v1/customer/keys",),
    "B-112": (
        "gh run rerun",
        "run_meta=\"$(gh run view",
        "expected_sha=\"${B112_EXPECTED_SHA",
        ".workflowName == \"release-cli\" and .event == \"push\"",
        ".conclusion == \"failure\" and ($ref | test(\"^refs/tags/cli-v[0-9]+\\.[0-9]+\\.[0-9]+$\")) and .headBranch == ($ref | sub(\"^refs/tags/\";\"\")) and (.headBranch | test(\"^cli-v[0-9]+\\.[0-9]+\\.[0-9]+$\"))",
        "all(.jobs[]; ((.name | ascii_downcase | startswith(\"create release\")) | not) or .conclusion == \"skipped\")",
        "all(.jobs[]; ((.name | ascii_downcase | startswith(\"publish verified signed release\")) | not) or .conclusion == \"skipped\")",
        "gh run rerun \"$run_id\" --failed",
        "lock_dir=\"${artifact}.lock\"",
        ".databaseId == $expected_run_id",
        ".attempt == ($expected_attempt + 1) and (.databaseId | type == \"number\") and .status == \"completed\"",
        "all(.jobs[]; ((.name | ascii_downcase | startswith(\"create release\")) | not) or (.status == \"completed\" and .conclusion == \"success\"))",
        "all(.jobs[]; ((.name | ascii_downcase | startswith(\"publish verified signed release\")) | not) or (.status == \"completed\" and .conclusion == \"success\"))",
        "gh run view \"$run_id\" --attempt \"$attempt_after\" --log",
        "caller_attempt=\"$(gh api",
        ".referenced_workflows = (.referenced_workflows // [])",
        ".head_sha == $sha",
        ".head_sha == ($sha | tostring)",
        "(.run_attempt | type) == \"number\"",
        ".run_attempt == $expected_attempt",
        "(.slsa_attempt | type) == \"number\"",
        ".id == ($run_id | tonumber)",
        ".slsa_run_id == ($run_id | tonumber)",
        ".slsa_workflow = (.referenced_workflows |",
        ".slsa_workflow.ref == $ref",
        ".slsa_workflow.ref == ($ref | tostring)",
        ".slsa_workflow.sha == $sha",
        ".slsa_workflow.sha == ($sha | tostring)",
        ".slsa_ref = (.slsa_workflow.ref // $ref)",
        ".slsa_ref == $ref",
        "slsa_event=\"workflow_call\"",
        "slsa_run_id=\"$(jq -r",
    ),
    "B-113": ("gh workflow run \"$workflow\"",),
    "B-125": ("wrangler d1 execute corelink-prod",),
    "B-127": ("wrangler d1 execute corelink-config-prod",),
    "B-122": ("$CORELINK_PROD_BASE/cargo/${CORELINK_DOGFOOD_TENANT:?}/b122-${ordinal}",),
    "B-129": ("$CORELINK_PROD_BASE/cargo/${CORELINK_DOGFOOD_TENANT:?}/${CORELINK_DOGFOOD_CARGO_KEY:?}",),
    "B-134": ("check_b134_observability.py", "expected_sha=\"$(gh api", ".headSha == $sha"),
    "B-216": ("wrangler tail corelink-signup-worker", "jq -e --arg worker \"corelink-signup-worker\" --arg queue \"corelink-dsr-erasure-dlq\"", "jq -e --arg worker \"corelink-signup-worker\" --arg revision \"$B216_EXPECTED_REVISION\" --arg event_id \"$B216_EVENT_ID\"", "test -s reports/owner-actions/b216-alert-delivery.json", "test -s reports/owner-actions/b216-exhausted-observation.md"),
    "B-251": (
        "python3 scripts/verify_b251_quota_cas_budget.py",
        "python3 scripts/run_b251_latency_probe.py --allow-run",
        "jq -e",
    ),
}

# Frozen from the 42 TL/open records at the D03 starting head.  Do not derive
# this set from the candidate: doing so would make deletion look like closure.
ORIGINAL_TL_OPEN = (
    "B-044", "B-046", "B-216", "B-229", "B-028", "B-029", "B-054", "B-112",
    "B-113", "B-061", "B-063", "B-068", "B-071", "B-072", "B-074", "B-083",
    "B-098", "B-102", "B-103", "B-104", "B-105", "B-106", "B-107", "B-114",
    "B-118", "B-122", "B-125", "B-126", "B-127", "B-128", "B-129", "B-134",
    "B-135", "B-138", "B-139", "B-142", "B-152", "B-250", "B-251", "B-155",
    "B-165", "B-253",
)
EXCLUDED = frozenset(("B-061", "B-126", "B-155"))
GRADUATED = tuple(item for item in ORIGINAL_TL_OPEN if item not in EXCLUDED) + ("B-006",)
GRADUATED_SET = frozenset(GRADUATED)
ORIGINAL_SET = frozenset(ORIGINAL_TL_OPEN)
DONE_SET = frozenset(("B-006", "B-028", "B-074", "B-118", "B-135", "B-165", "B-229", "B-253"))
B118_ARTIFACT = "scripts/verify_b118_retirement.py"
B118_COMMAND = "python3 scripts/verify_b118_retirement.py"
B118_EVIDENCE = (
    "BACKLOG.md B-118 retirement record; changelog.d/1490-remove-cosign-sign.md; "
    "docs/campaigns/remediation/B-134-docker-shim-experiment.md RETIRED (B-118) row; "
    "release-slsa3.yml and cas_foundation.yml executable cosign sign-blob/verify-blob paths; "
    ".github/workflows/cosign-sign.yml absent"
)
B006_ARTIFACT = "artifacts/d03/B006-capability-metrics.json"
B006_PROVIDER_ARTIFACT = "artifacts/d03/B006-provider-binding.json"
B165_ARTIFACT = "evidence/owner-actions/B-165/rejection-served-latency.json"
B165_COMPLETE_ARTIFACT = "evidence/owner-actions/B-165/complete-latency-2026-09-09.tsv"
B165_SERVER_TIMING_ARTIFACT = "evidence/owner-actions/B-165/served-server-timing-2026-09-09.tsv"
B165_TENANT_A = "8a6b4e4e-5d66-4ab7-9388-85ea5ed45c4c"
B165_TENANT_B = "ee30f7ba-fc25-4d71-939e-ebe130b4c6a3"
B165_PAT_FINGERPRINT_A = "sha256:dbc983ada203f4ca87e023ea9dd40a6c3367c3843e49a774849bf8078799fac8"
B165_PAT_FINGERPRINT_B = "sha256:25e409be70b0633d1f0a2179e23de7b254eef69cff253e105b36cde1f18176d1"
B165_COMMAND = (
    "python3 scripts/verify_b165_latency.py "
    f"{B165_COMPLETE_ARTIFACT} --samples 10 --require-served "
    f"--tenant-a {B165_TENANT_A} --tenant-b {B165_TENANT_B} "
    f"--pat-fingerprint-a {B165_PAT_FINGERPRINT_A} "
    f"--pat-fingerprint-b {B165_PAT_FINGERPRINT_B} "
    f"--server-timing-tsv {B165_SERVER_TIMING_ARTIFACT}"
)
B165_EVIDENCE = (
    f"{B165_ARTIFACT} and docs/perf/2026-09-09-wp-b165-complete.md preserve the complete "
    "four-route 401 refusal, health 200 control, and two distinct tenant-bound served "
    "200 populations. The canonical B-165 verifier requires ten samples, redacted "
    "distinct PAT fingerprints, and one-to-one Server-Timing/transport residual checks; "
    "its source guard proves 404-only/never-401 padding. This is diagnostic evidence "
    "only; no deployment was performed."
)
EXCLUDED_FINGERPRINTS = {
    "B-061": "d759a0591e6f867b4245f09512963f2ae10924c7b25cfad02754dc1b323657dc",
    "B-126": "88e2fe5082ad1ad9c393c633c862f947043b378c1fd36393a949b64eab34b089",
    "B-155": "b675f68b3f5c81c0b0cf4bdd48403dbb05f0cb13c865efb295ace6eab829c58c",
}


class GraduationError(ValueError):
    pass


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GraduationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_packets(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_json_no_duplicates)
    except (json.JSONDecodeError, GraduationError) as exc:
        raise GraduationError(f"invalid graduation packet JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GraduationError("graduation packet root must be an object")
    return value


def _read(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise GraduationError(f"missing/non-regular graduation input: {path}")
    return path.read_text(encoding="utf-8")


def _require_string(mapping: dict[str, Any], key: str, item: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GraduationError(f"{item}: packet field {key!r} is missing or empty")
    return value


def _check_bounded_shell(item: str, command: str, artifact: str) -> None:
    """Reject shell features outside the two bounded owner-command grammars.

    This is deliberately a small allowlist rather than a general shell parser:
    the packet commands are reviewable evidence collectors, not an escape hatch
    for arbitrary owner-provided scripts.  Bash still performs syntax checking,
    while this layer rejects command substitution, unsafe separators/redirects,
    and commands which only smuggle a required token through an inert branch.
    """
    if "\n" in command or "$ (" in command:
        raise GraduationError(f"{item}: command contains an unbounded shell construct")
    if "$(__" in command or "$(" in command or "`" in command:
        raise GraduationError(f"{item}: command substitution is not allowed")
    syntax = subprocess.run(
        ["bash", "-n"], input=command, text=True, capture_output=True, check=False
    )
    if syntax.returncode != 0:
        raise GraduationError(f"{item}: command is not valid bash syntax")
    if command.rstrip().endswith((";", "|", "||", "&&")):
        raise GraduationError(f"{item}: command has a trailing separator")

    try:
        tokens = list(shlex.shlex(command, posix=True, punctuation_chars=";&|><()"))
    except ValueError as exc:
        raise GraduationError(f"{item}: command cannot be tokenized safely") from exc
    forbidden_operators = {"&&", "&", "<<", "<<<", ">>", "<", "&>"}
    if any(token in forbidden_operators for token in tokens):
        raise GraduationError(f"{item}: command contains an unapproved shell operator")
    expected_operators = {
        "B-216": {";": 24, ">": 6, ";;": 2, "||": 1, "|": 1},
        "B-251": {";": 4, ">": 1},
    }[item]
    operators = Counter(
        token for token in tokens if token in {";", ";;", "||", "|", ">", "<", ">>", ">&", "&&", "&"}
    )
    if dict(operators) != expected_operators:
        raise GraduationError(f"{item}: command separator/redirect shape is not the reviewed bounded form")
    if item == "B-251" and ">" in tokens:
        # The runner owns atomic evidence creation. The shell only discards
        # jq's boolean output after validating the completed artifact.
        redirect_targets = [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == ">"]
        if redirect_targets != ["/dev/null"]:
            raise GraduationError(f"{item}: redirect is outside the reviewed validation sink")
    if item == "B-216" and ">" in tokens:
        redirect_targets = [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == ">"]
        if redirect_targets != [artifact, "/dev/null", "/dev/null", artifact, "/dev/null", "/dev/null"]:
            raise GraduationError(f"{item}: redirects must only capture the declared event artifact")
    if item == "B-251" and tokens.count(">&") != 0:
        raise GraduationError(f"{item}: runner output must not be redirected into side evidence")
    if item == "B-216" and tokens.count(";;") != 2:
        raise GraduationError(f"{item}: timeout status case must remain structurally bounded")

    allowed = {
        "B-216": {"set", "export", "test", ":", "grep", "tail_rc=0", "timeout", "wrangler", "jq", "case", "exit"},
        "B-251": {"set", "export", "jq", "python3"},
    }[item]
    control = {";", "||", "|", ")", "(", ";;", "in", "esac", "*"}
    at_command_start = True
    in_case = False
    in_case_pattern = False
    for token in tokens:
        if token == "case":
            in_case = True
            in_case_pattern = True
            at_command_start = False
            continue
        if in_case:
            if token == "esac":
                in_case = False
                in_case_pattern = False
                at_command_start = True
            elif token == ";;":
                in_case_pattern = True
                at_command_start = True
            elif token == ")":
                in_case_pattern = False
                at_command_start = True
            elif in_case_pattern or token in {"in", "|", "*"}:
                continue
            elif at_command_start:
                if token not in allowed:
                    raise GraduationError(f"{item}: unapproved shell command {token!r}")
                at_command_start = False
            continue
        if token in control:
            at_command_start = token not in {")", "(", "in", "*"}
            continue
        if token in {">", ">&"}:
            at_command_start = False
            continue
        if at_command_start:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                at_command_start = False
                continue
            if token not in allowed:
                raise GraduationError(f"{item}: unapproved shell command {token!r}")
            at_command_start = False


def _extract_jq_filters(command: str) -> list[tuple[str, bool, dict[str, str]]]:
    """Extract bounded jq filters and their ``-n`` mode from shell tokens."""

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise GraduationError("jq filter command cannot be tokenized") from exc
    entries: list[tuple[str, bool, dict[str, str]]] = []
    index = 0
    while index < len(tokens):
        if tokens[index] != "jq":
            index += 1
            continue
        index += 1
        null_input = False
        args: dict[str, str] = {}
        while index < len(tokens):
            token = tokens[index]
            if token in {"-e", "--exit-status"}:
                index += 1
            elif token in {"-n", "--null-input"}:
                null_input = True
                index += 1
            elif token in {"--arg", "--argjson"} and index + 2 < len(tokens):
                args[tokens[index + 1]] = tokens[index + 2]
                index += 3
            elif token.startswith("-"):
                index += 1
            else:
                entries.append((token, null_input, args))
                index += 1
                break
        else:
            raise GraduationError("jq invocation has no executable filter")
    return entries


def _run_jq_filter(
    filter_text: str,
    payload: object | None,
    args: dict[str, str],
    null_input: bool = False,
) -> tuple[int, str]:
    argv = ["jq", "-e"]
    if null_input:
        argv.append("-n")
    for name, value in args.items():
        argv.extend(("--arg", name, value))
    argv.append(filter_text)
    completed = subprocess.run(
        argv,
        input=None if null_input else json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    return completed.returncode, completed.stdout


def _assert_jq_filter_active(
    label: str,
    filter_text: str,
    positive: dict[str, object],
    all_wrong: dict[str, object],
    args: dict[str, str],
) -> None:
    status, _ = _run_jq_filter(filter_text, positive, args)
    if status != 0:
        raise GraduationError(f"{label}: positive jq fixture did not match")
    for key, value in all_wrong.items():
        negative = dict(positive)
        negative[key] = value
        status, _ = _run_jq_filter(filter_text, negative, args)
        if status == 0:
            raise GraduationError(f"{label}: jq predicate is inert for field {key!r}")


def _check_b216_semantics(command: str) -> None:
    required_fragments = (
        "test -n \"${B216_EXPECTED_REVISION:?provide deployed revision}\"",
        "test -n \"${B216_EVENT_ID:?provide exhausted event ID}\"",
        "test -s reports/owner-actions/b216-deployed-signup-worker.json",
        "test -s reports/owner-actions/b216-alert-delivery.json",
        "test -s reports/owner-actions/b216-exhausted-observation.md",
        "timeout 30s wrangler tail corelink-signup-worker --format json --search dsr.erasure.dead_letter > artifacts/d03/B216-dlq-incident.json",
        "event_id == $event_id",
        "revision == $revision",
        ".channel == \"paging\"",
        ".event == \"dsr.erasure.dead_letter\"",
        "exhausted == true",
        "action == \"requeue_once\"",
        "requeue_count == 1",
        "delivery_status == \"delivered\"",
        "receipt_id|type==\"string\"",
        "event_id=$B216_EVENT_ID revision=$B216_EXPECTED_REVISION exhausted=true action=requeue_once requeue_count=1 operator_disposition=manual_followup",
    )
    for fragment in required_fragments:
        if fragment not in command:
            raise GraduationError(f"B-216: command lacks correlated evidence assertion {fragment!r}")
    if "grep -Eiq" in command or "|" not in command:
        raise GraduationError("B-216: evidence must use structured all-fields correlation, not OR greps")

    filters = _extract_jq_filters(command)
    if len(filters) != 4 or any(entry[1] for entry in filters):
        raise GraduationError("B-216: expected four input-backed jq filters")
    _assert_jq_filter_active(
        "B-216 deployed worker correlation",
        filters[0][0],
        {"worker": "corelink-signup-worker", "queue": "corelink-dsr-erasure-dlq", "revision": "rev-216"},
        {"worker": "wrong-worker", "queue": "wrong-queue", "revision": "wrong-revision"},
        {"worker": "corelink-signup-worker", "queue": "corelink-dsr-erasure-dlq", "revision": "rev-216"},
    )
    _assert_jq_filter_active(
        "B-216 alert correlation",
        filters[1][0],
        {"event_id": "evt-216", "revision": "rev-216", "channel": "paging", "delivery_status": "delivered", "receipt_id": "receipt-216"},
        {"event_id": "wrong-event", "revision": "wrong-revision", "channel": "other", "delivery_status": "failed", "receipt_id": ""},
        {"event_id": "evt-216", "revision": "rev-216"},
    )
    _assert_jq_filter_active(
        "B-216 tail event correlation",
        filters[2][0],
        {"worker": "corelink-signup-worker", "revision": "rev-216", "event": "dsr.erasure.dead_letter", "event_id": "evt-216", "exhausted": True, "action": "requeue_once", "requeue_count": 1},
        {"worker": "wrong-worker", "revision": "wrong-revision", "event": "wrong-event", "event_id": "wrong-id", "exhausted": False, "action": "drop", "requeue_count": 2},
        {"worker": "corelink-signup-worker", "revision": "rev-216", "event_id": "evt-216"},
    )
    _assert_jq_filter_active(
        "B-216 repeated alert correlation",
        filters[3][0],
        {"event_id": "evt-216", "revision": "rev-216", "channel": "paging", "delivery_status": "delivered", "receipt_id": "receipt-216"},
        {"event_id": "wrong-event", "revision": "wrong-revision", "channel": "other", "delivery_status": "failed", "receipt_id": ""},
        {"event_id": "evt-216", "revision": "rev-216", "channel": "paging", "delivery_status": "delivered", "receipt_id": "receipt-216"},
    )


def _check_b251_semantics(command: str, artifact: str) -> None:
    required_fragments = (
        "python3 scripts/verify_b251_quota_cas_budget.py",
        "python3 scripts/run_b251_latency_probe.py --allow-run",
        "--d02-identity reports/owner-actions/b251-d02-identity.json",
        "--observed-identity reports/owner-actions/b251-d03-observed-identity.json",
        "--output " + artifact,
        '.schema == "corelink.b251.latency-probe.v1"',
        ".identity.match == true",
        '.identity.fields_compared == ["seed","failure","blob"]',
        ".measurement.sample_count == 1000",
        ".measurement.limit_us == 5000",
        ".measurement.p99_us <= .measurement.limit_us",
        '.measurement.fixture == "InMemoryAtomicQuotaChecker"',
        ".measurement.production_latency_measured == false",
        artifact + " >/dev/null",
    )
    for fragment in required_fragments:
        if fragment not in command:
            raise GraduationError(f"B-251: command lacks structural identity/measurement assertion {fragment!r}")
    forbidden_old_path = (
        "B251_OBSERVED_",
        "B251_ALLOW_IGNORED_PROBE",
        "jq -n",
        "measurement_mode",
        "cargo test -p corelink-billing",
        "B251-latency-probe.log",
    )
    if any(fragment in command for fragment in forbidden_old_path):
        raise GraduationError("B-251: obsolete split evidence path remains")
    if command.count("python3 scripts/run_b251_latency_probe.py") != 1:
        raise GraduationError("B-251: canonical runner must execute exactly once")

    filters = _extract_jq_filters(command)
    if len(filters) != 1 or filters[0][1] or filters[0][2]:
        raise GraduationError("B-251: expected one input-backed evidence jq filter")
    filter_text = filters[0][0]
    positive = {
        "schema": "corelink.b251.latency-probe.v1",
        "revision": "a" * 40,
        "test_blob": "b" * 40,
        "identity": {"match": True, "fields_compared": ["seed", "failure", "blob"]},
        "measurement": {
            "sample_count": 1000,
            "p99_us": 5000,
            "limit_us": 5000,
            "fixture": "InMemoryAtomicQuotaChecker",
            "production_latency_measured": False,
        },
    }
    status, _ = _run_jq_filter(filter_text, positive, {})
    if status != 0:
        raise GraduationError("B-251: canonical evidence fixture did not match")
    negatives = (
        {**positive, "schema": "fixture-only"},
        {**positive, "identity": {"match": False, "fields_compared": ["seed", "failure", "blob"]}},
        {**positive, "identity": {"match": True, "fields_compared": ["seed", "blob"]}},
        {**positive, "measurement": {**positive["measurement"], "sample_count": 999}},
        {**positive, "measurement": {**positive["measurement"], "p99_us": 5001}},
        {**positive, "measurement": {**positive["measurement"], "limit_us": 5001}},
        {**positive, "measurement": {**positive["measurement"], "fixture": "production"}},
        {
            **positive,
            "measurement": {**positive["measurement"], "production_latency_measured": True},
        },
    )
    for index, negative in enumerate(negatives):
        status, _ = _run_jq_filter(filter_text, negative, {})
        if status == 0:
            raise GraduationError(f"B-251: evidence predicate is inert for negative {index}")



def _active_shell_segments(command: str) -> list[list[str]]:
    """Tokenize executable shell words, dropping comments and quoted bait."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    separators = {";", "&&", "||", "|", "&", "\n"}
    segments: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token in separators:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _check_d1_read_command(item: str, packet: dict[str, Any], command: str) -> None:
    """Require the packet's D1 read to use one closed-world shell invocation.

    The surrounding owner procedures intentionally use shell control flow, but
    the remote D1 operation itself is a narrow grammar boundary.  Parse that
    boundary instead of accepting a substring: this keeps command injection
    operators, substitutions, redirects, duplicate invocations, and the old
    Worker name out of the load-bearing read.
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n")
    lexer.whitespace_split = True
    # Keep comments as tokens.  A trailing ``#`` is not inert evidence: it is
    # an unreviewed shell construct and must fail the closed-world grammar.
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise GraduationError(f"{item}: D1 command has invalid shell quoting") from exc

    invocation = ("wrangler", "d1", "execute")
    starts = [
        index
        for index in range(len(tokens) - len(invocation) + 1)
        if tuple(tokens[index : index + len(invocation)]) == invocation
    ]
    if len(starts) != 1:
        raise GraduationError(f"{item}: D1 command must contain exactly one wrangler d1 execute invocation")

    start = starts[0]
    if item == "B-063":
        expected_start = 120
        expected_prefix = [
            "set", "-euo", "pipefail", ";", "test",
            "${B063_REPAIR_APPROVED:?set B063_REPAIR_APPROVED=1 only after the authorized repair}",
            "=", "1", ";", "export", "D03_SAMPLE_COUNT=3", ";", ":", ">",
            "artifacts/d03/B063-archive-lag-pagerduty.json", ";", "grep", "-Fq",
            "workflow_dispatch", ".github/workflows/audit-archive-lag.yml", ";",
        ]
        expected_loop_prefix = ["for", "sample", "in", "1", "2", "3", ";", "do"]
        expected_length = 144
    else:
        expected_start = 12
        expected_prefix = [
            "set", "-euo", "pipefail", ";", "test",
            "${OWNER_APPROVED_READONLY:?set OWNER_APPROVED_READONLY=1 for ephemeral read-only D1 access}",
            "=", "1", ";", "export", "D03_SAMPLE_COUNT=1", ";",
        ]
        expected_loop_prefix = []
        expected_length = 36
    if start != expected_start or tokens[: len(expected_prefix)] != expected_prefix:
        raise GraduationError(f"{item}: command prefix is outside the reviewed shell grammar")
    if expected_loop_prefix and tokens[start - len(expected_loop_prefix) : start] != expected_loop_prefix:
        raise GraduationError(f"{item}: command loop prefix is outside the reviewed shell grammar")
    if len(tokens) != expected_length:
        raise GraduationError(f"{item}: command contains unrecognized shell tokens")

    prefix = tokens[start : start + 7]
    if len(prefix) != 7 or prefix[3] != "corelink-config-prod" or prefix[4:6] != ["--remote", "--command"]:
        raise GraduationError(f"{item}: D1 command target/options are outside the closed-world grammar")
    query = prefix[6]
    # ``<`` is a legitimate SQL comparison in the B-063 read.  Redirects are
    # shell tokens outside this quoted argument and are rejected by the exact
    # pipeline grammar below.
    if any(marker in query for marker in (";", "&&", "||", "|", "$(", "${", "`")):
        raise GraduationError(f"{item}: D1 query contains a shell operator or substitution")

    artifact = packet["artifact"]
    if item == "B-063":
        tail = ["|", "tee", "-a", artifact]
    else:
        tail = ["|", "tee", artifact]
    tail_start = start + len(prefix)
    if tokens[tail_start : tail_start + len(tail)] != tail:
        raise GraduationError(f"{item}: D1 command pipeline is outside the closed-world grammar")
    after_tail = tail_start + len(tail)
    if item == "B-063":
        expected_suffix = [
            ";", "grep", "-Eiq", "pending_old|part_last_archived", artifact,
            ";", "dispatch_and_wait", ";", "done", ";", "test", "-n",
            "${PAGERDUTY_REFERENCE:?redacted PagerDuty reference required}",
        ]
    else:
        expected_suffix = [
            ";", "test", "-s", artifact, ";", "grep", "-Eiq",
            "satisfied|violated|unevaluable|weur|tenants|total_rows|denominator", artifact,
            ";", "grep", "-Fq", "LEFT JOIN",
            "docs/campaigns/remediation/work-packages/B091-B130.md",
        ]
    if tokens[after_tail:] != expected_suffix:
        raise GraduationError(f"{item}: command has unrecognized post-processing tokens")


def _require_b105_active_commands(command: str) -> None:
    """Require B-105's load-bearing operations as executable shell commands."""
    segments = _active_shell_segments(command)

    def has_prefix(words: tuple[str, ...]) -> bool:
        return any(tuple(segment[: len(words)]) == words for segment in segments)

    def has_sequence(words: tuple[str, ...]) -> bool:
        return any(
            any(tuple(segment[i : i + len(words)]) == words for i in range(len(segment) - len(words) + 1))
            for segment in segments
        )

    def has_nested_prefix(prefix: str) -> bool:
        return any(
            segment and segment[0] not in {"echo", "printf", ":"} and token.startswith(prefix)
            for segment in segments
            for token in segment
        )

    if not has_sequence(("set", "-euo", "pipefail")):
        raise GraduationError("B-105: strict shell options are not executable")
    if not has_prefix(("gh", "workflow", "run", "perf-production-evidence.yml", "--ref", "main")):
        raise GraduationError("B-105: workflow dispatch is not executable")
    if not has_sequence(("gh", "run", "watch")) or not (
        has_sequence(("gh", "run", "view")) or has_nested_prefix("run_meta=$(gh run view ")
    ):
        raise GraduationError("B-105: correlated run wait/view is not executable")
    if not has_prefix(("gh", "run", "download")):
        raise GraduationError("B-105: artifact download is not executable")
    if not has_prefix(("jq", "-e")):
        raise GraduationError("B-105: jq assertion is not executable")
    if not has_prefix(("python3", "scripts/verify_b102_b108_evidence.py", "--packet")):
        raise GraduationError("B-105: packet verification is not executable")

def _check_command_contract(item: str, packet: dict[str, Any], root: Path) -> None:
    expected = COMMAND_CONTRACTS.get(item)
    if expected is None:
        return
    contract = packet.get("command_contract")
    if not isinstance(contract, dict) or set(contract) != SEMANTIC_PACKET_FIELDS:
        raise GraduationError(f"{item}: command_contract fields are missing or ambiguous")
    if contract != expected:
        raise GraduationError(f"{item}: command_contract disagrees with the authoritative owner packet")
    command = packet["command"]
    if item in {"B-063", "B-127"}:
        _check_d1_read_command(item, packet, command)
    if item in {"B-216", "B-251"}:
        _check_bounded_shell(item, command, packet["artifact"])
        if item == "B-216":
            _check_b216_semantics(command)
        else:
            _check_b251_semantics(command, packet["artifact"])
    if item == "B-112" and "#" in command:
        raise GraduationError("B-112 command must not contain shell-comment predicate bait")
    if item == "B-112":
        head_sha = ".headSha == $sha"
        lock_marker = '; lock_dir="${artifact}.lock";'
        rerun_marker = '; gh run rerun "$run_id" --failed;'
        slsa_marker = '; caller_attempt="$(gh api'
        if lock_marker not in command or rerun_marker not in command or slsa_marker not in command:
            raise GraduationError("B-112 command is missing release rerun structural anchors")
        initial = command.split(lock_marker, 1)[0]
        terminal = command.split(rerun_marker, 1)[1].split(slsa_marker, 1)[0]
        if initial.count(head_sha) != 1:
            raise GraduationError("B-112 initial release headSha predicate must occur exactly once")
        if terminal.count(head_sha) != 2:
            raise GraduationError("B-112 terminal release headSha predicates must occur exactly twice")
        if '.headSha == $sha and (all(.jobs[]; ((.name | ascii_downcase | startswith("create release")) | not) or .conclusion == "skipped"))' not in initial:
            raise GraduationError("B-112 initial headSha predicate is not bound to skipped-release guard")
        if terminal.count('.status == "completed" and .conclusion == "success"') != 6:
            raise GraduationError("B-112 terminal predicates do not require a successful rerun and release jobs")
        if "saw_active" in terminal:
            raise GraduationError("B-112 must accept an attempt that completed before its first poll")
    if item == "B-105":
        expected_sha_assignment = 'expected_sha="$(gh api repos/HuGR-Labs/corelink-server/commits/main --jq .sha)"'
        if command.count(expected_sha_assignment) != 1:
            raise GraduationError("B-105: expected SHA must come from the main-branch commit API")
        if command.count('[[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]]') != 1:
            raise GraduationError("B-105: expected SHA must be validated as a full commit SHA")
        if command.count('.headSha == $expected_sha') != 2:
            raise GraduationError("B-105: run selection and terminal metadata must bind exact headSha")
    if "set -euo pipefail" not in command:
        raise GraduationError(f"{item}: command must enable fail-closed shell options")
    if "printf" in command:
        raise GraduationError(f"{item}: assertions must come from tool output, not printf token bait")
    if not re.search(r"\b(?:grep|jq\s+-e|awk|test|case)\b", command):
        raise GraduationError(f"{item}: command has no executable assertion over captured tool output")
    for curl_fragment in re.findall(r"\bcurl\b([^;]*)", command):
        if "--output /dev/null" not in curl_fragment:
            raise GraduationError(f"{item}: curl response body must be discarded from evidence")
    if "wrangler tail" in command and not re.search(r"\btimeout\s+[0-9]+s\s+wrangler tail\b", command):
        raise GraduationError(f"{item}: wrangler tail must have a finite timeout")
    if "gh workflow run" in command:
        if not all(token in command for token in ("run_id", "gh run view", "status", "completed")):
            raise GraduationError(f"{item}: dispatched workflow must correlate its run ID and wait terminal")
    if "gh run rerun" in command and not all(token in command for token in ("run_id", "gh run view", "completed")):
        raise GraduationError(f"{item}: rerun must correlate its run ID and wait terminal")
    marker = f"D03_SAMPLE_COUNT={expected['sample_count']}"
    if marker not in command:
        raise GraduationError(f"{item}: command must carry the explicit {marker} population marker")
    token_aliases = {
        # YAML env syntax is the authoritative workflow operation; accepting
        # the equivalent shell spelling here avoids requiring a second, local
        # flag that could be mistaken for proof about the remote run.
        "GC_LIVE_DELETE=false": ('GC_LIVE_DELETE: "false"',),
        "sleep 61": ("sleep_interval_seconds=61",),
    }
    for token in (*expected["required"], *expected["safety"]):
        if token not in command and not any(alias in command for alias in token_aliases.get(token, ())):
            raise GraduationError(f"{item}: command is missing semantic token {token!r}")
    for operation in COMMAND_OPERATIONS.get(item, ()):
        if operation not in command:
            raise GraduationError(f"{item}: command omits load-bearing owner operation {operation!r}")
    for profile in expected["profiles"]:
        if profile not in command:
            raise GraduationError(f"{item}: command omits required profile/population {profile!r}")
    for token in expected["forbidden"]:
        if token in command:
            raise GraduationError(f"{item}: command contains forbidden unsafe token {token!r}")
    reference = expected["owner_packet"].split("#", 1)[0]
    source = root / reference
    if not source.is_file() or source.is_symlink():
        raise GraduationError(f"{item}: authoritative owner packet is missing/non-regular: {reference}")
    source_text = source.read_text(encoding="utf-8")
    if item not in source_text:
        raise GraduationError(f"{item}: authoritative owner packet does not mention the item")


def _check_b165_done_evidence(packet: dict[str, Any], root: Path) -> None:
    """Bind the DONE packet to the committed, complete B-165 receipt.

    B-165's acceptance is a local verifier over retained production evidence;
    the D03 packet must not silently fall back to the older parked curl probe or
    to a self-described JSON receipt. Check the receipt's hashes and then run
    the same verifier arguments recorded in the packet.
    """
    if packet.get("artifact") != B165_ARTIFACT:
        raise GraduationError("B-165: DONE packet must name the committed receipt artifact")
    if packet.get("command") != B165_COMMAND:
        raise GraduationError("B-165: DONE packet must use the canonical complete verifier command")
    if packet.get("verify_means") != "done":
        raise GraduationError("B-165: DONE packet must declare verify_means=done")
    if packet.get("evidence") != B165_EVIDENCE:
        raise GraduationError("B-165: DONE evidence description is not the closed-world receipt statement")

    receipt_path = root / B165_ARTIFACT
    try:
        receipt = json.loads(_read(receipt_path))
    except json.JSONDecodeError as exc:
        raise GraduationError(f"B-165: receipt is not valid JSON: {exc}") from exc
    if receipt.get("schema_version") != 1:
        raise GraduationError("B-165: receipt schema_version is not 1")
    if receipt.get("verdict") != "complete_two_tenant_measurement;_padding_policy_recorded;_measurement_contract_repaired":
        raise GraduationError("B-165: receipt does not declare the complete two-tenant verdict")
    if receipt.get("padding_decision", {}).get("decision") != "retain_padding_for_404_misses_including_unmatched_routes;_never_pad_401":
        raise GraduationError("B-165: receipt padding decision is not the ratified 404-only boundary")

    try:
        served = receipt["served_samples"]
        populations = served["populations"]
        if served["complete_artifact"] != B165_COMPLETE_ARTIFACT:
            raise GraduationError("B-165: receipt complete artifact path drifted")
        if served["server_timing_artifact"] != B165_SERVER_TIMING_ARTIFACT:
            raise GraduationError("B-165: receipt Server-Timing artifact path drifted")
        by_surface = {entry["surface"]: entry for entry in populations}
        if set(by_surface) != {"served_a", "served_b"}:
            raise GraduationError("B-165: receipt served population set is incomplete")
        expected_identity = {
            "served_a": (B165_TENANT_A, B165_PAT_FINGERPRINT_A),
            "served_b": (B165_TENANT_B, B165_PAT_FINGERPRINT_B),
        }
        for surface, (tenant, fingerprint) in expected_identity.items():
            if by_surface[surface].get("tenant") != tenant or by_surface[surface].get("pat_fingerprint") != fingerprint:
                raise GraduationError(f"B-165: receipt {surface} identity is not bound to the canonical population")
        references = (
            (receipt["rejection_samples"], "artifact", "sha256"),
            (receipt["rejection_samples"], "recovery_artifact", "recovery_sha256"),
            (receipt["served_samples"], "artifact", "sha256"),
            (receipt["served_samples"], "complete_artifact", "complete_sha256"),
            (receipt["served_samples"], "server_timing_artifact", "server_timing_sha256"),
        )
        for section, path_key, hash_key in references:
            referenced = section[path_key]
            target = root / referenced
            if target.is_symlink() or not target.is_file():
                raise GraduationError(f"B-165: receipt artifact is missing/non-regular: {referenced}")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest != section[hash_key]:
                raise GraduationError(f"B-165: receipt hash disagrees with {referenced}")
    except (KeyError, TypeError, ValueError) as exc:
        raise GraduationError(f"B-165: receipt is missing a required committed-evidence field: {exc}") from exc

    verify_args = (
        sys.executable,
        "scripts/verify_b165_latency.py",
        B165_COMPLETE_ARTIFACT,
        "--samples", "10",
        "--require-served",
        "--tenant-a", B165_TENANT_A,
        "--tenant-b", B165_TENANT_B,
        "--pat-fingerprint-a", B165_PAT_FINGERPRINT_A,
        "--pat-fingerprint-b", B165_PAT_FINGERPRINT_B,
        "--server-timing-tsv", B165_SERVER_TIMING_ARTIFACT,
    )
    result = subprocess.run(verify_args, cwd=root, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise GraduationError(f"B-165: canonical verifier did not establish complete evidence: {result.stdout}{result.stderr}")


def _validate_b006_committed_evidence(root: Path, *, require_closure: bool) -> None:
    """Validate B-006 receipts in the static D03 packet, independent of age."""

    try:
        metrics = json.loads(_read(root / B006_ARTIFACT))
        provider = json.loads(_read(root / B006_PROVIDER_ARTIFACT))
        if require_closure:
            validate_b006_closure(metrics, provider, mode="historical")
        else:
            validate_b006_receipt(metrics, mode="historical")
            validate_provider_binding(provider, mode="historical")
    except (json.JSONDecodeError, B006EvidenceError, ProviderBindingError) as exc:
        if require_closure:
            message = "DONE disposition lacks valid zero metrics plus valid provider binding"
        else:
            message = "reopened evidence is not fail-closed"
        raise GraduationError(f"B-006: {message}: {exc}") from exc


def _check_b006_done_population(packets: dict[str, dict[str, Any]]) -> None:
    """Keep B-006 in the closed D03 DONE population."""

    b006 = packets.get("B-006")
    if not isinstance(b006, dict) or b006.get("disposition") != "DONE":
        raise GraduationError("B-006 must remain in the DONE population")


def _check_packets(packets: dict[str, Any], root: Path = ROOT) -> dict[str, dict[str, Any]]:
    if packets.get("schema_version") != 2:
        raise GraduationError("packet schema_version must be 2")
    if tuple(packets.get("original_tl_open", ())) != ORIGINAL_TL_OPEN:
        raise GraduationError("packet original population is not the frozen 42-item order")
    if tuple(packets.get("graduated_scope", ())) != GRADUATED:
        raise GraduationError("packet graduated scope is not exactly the 39-item lane plus B-006")
    entries = packets.get("packets")
    if not isinstance(entries, dict):
        raise GraduationError("packets must be an object")
    if set(entries) != GRADUATED_SET:
        missing = sorted(GRADUATED_SET - set(entries))
        extra = sorted(set(entries) - GRADUATED_SET)
        raise GraduationError(f"packet population mismatch: missing={missing}, extra={extra}")
    for item in GRADUATED:
        packet = entries[item]
        if not isinstance(packet, dict):
            raise GraduationError(f"{item}: packet must be an object")
        disposition = _require_string(packet, "disposition", item)
        allowed_dispositions = ("DONE", "PARKED", "REOPENED") if item == "B-006" else ("DONE", "PARKED")
        if disposition not in allowed_dispositions:
            raise GraduationError(f"{item}: unclassified disposition {disposition!r}")
        _require_string(packet, "artifact", item)
        _require_string(packet, "command", item)
        _require_string(packet, "owner", item)
        _require_string(packet, "dependency", item)
        _require_string(packet, "action", item)
        if item == "B-006" and packet.get("provider_artifact") != B006_PROVIDER_ARTIFACT:
            raise GraduationError("B-006: provider binding artifact must be declared")
        _check_command_contract(item, packet, root)
        if item == "B-105":
            command = packet["command"]
            _require_b105_active_commands(command)
            exact_dispatch = "gh workflow run perf-production-evidence.yml --ref main"
            if command.count(exact_dispatch) != 1:
                raise GraduationError("B-105: gate must dispatch exactly perf-production-evidence.yml from main")
            if "release-slsa3.yml" in command:
                raise GraduationError("B-105: stale release-slsa3.yml dispatch remains in the owner packet")
            workflow = root / ".github/workflows/perf-production-evidence.yml"
            workflow_text = _read(workflow)
            if "python3 scripts/collect_b105_same_lane.py" not in workflow_text:
                raise GraduationError("B-105: perf-production-evidence.yml does not collect the paired lane")
        if item == "B-104":
            command = packet["command"]
            even_median = "v[int((n+1)/2)] + v[int((n+2)/2)]"
            if even_median not in command:
                raise GraduationError("B-104: median must average the two middle samples for even populations")
            if "rank=0.9*(n-1)+1; lo=int(rank); frac=rank-lo" not in command:
                raise GraduationError("B-104: p90 must use the inclusive linear interpolation formula")
        if item == "B-229":
            command = packet["command"]
            artifact = "evidence/production/B-229-clerk-webhook-2026-09-08.md"
            expected_command = (
                "set -euo pipefail; python3 scripts/verify_b229_clerk_webhook.py --evidence "
                f"{artifact}; python3 scripts/verify_b229_clerk_webhook.py --evidence {artifact} --self-test"
            )
            if packet["artifact"] != artifact or command != expected_command:
                raise GraduationError("B-229: packet artifact and standalone verifier command are not exact")
            expected_evidence = (
                "B-229 production receipt evidence/production/B-229-clerk-webhook-2026-09-08.md is verified by "
                "scripts/verify_b229_clerk_webhook.py: exact source SHA, Cloudflare version, 100% traffic, "
                "health 200, signed probe 200 ignored, and omitted payload/credential values."
            )
            if packet.get("evidence") != expected_evidence:
                raise GraduationError("B-229: DONE evidence description is not the exact closed-world receipt statement")
            if not (root / "scripts/verify_b229_clerk_webhook.py").is_file():
                raise GraduationError("B-229: standalone production receipt verifier is missing")
            try:
                verify_b229_receipt(root / artifact)
            except (OSError, B229VerificationError) as exc:
                raise GraduationError(f"B-229: standalone receipt verification failed: {exc}") from exc
        if item == "B-118":
            if disposition != "DONE":
                raise GraduationError("B-118: retired lane must remain DONE, never PARKED")
            if packet.get("artifact") != B118_ARTIFACT or packet.get("command") != B118_COMMAND:
                raise GraduationError("B-118: packet must use the local retirement gate exactly")
            if packet.get("verify_means") != "done" or packet.get("evidence") != B118_EVIDENCE:
                raise GraduationError("B-118: DONE evidence must name the exact retired controls")
            gate = root / B118_ARTIFACT
            if gate.is_symlink() or not gate.is_file():
                raise GraduationError("B-118: local retirement gate is missing/non-regular")
        if item == "B-165" and disposition == "DONE":
            _check_b165_done_evidence(packet, root)
        if disposition == "PARKED":
            artifact = _require_string(packet, "artifact", item)
            command = _require_string(packet, "command", item)
            if artifact not in command:
                raise GraduationError(f"{item}: gate command does not create declared artifact {artifact}")
            if item == "B-251":
                if command.count(f"--output {artifact}") != 1:
                    raise GraduationError(f"{item}: canonical runner must own declared artifact output")
            elif not re.search(r"(?:>|tee)\s*[^\n;]*" + re.escape(artifact), command):
                raise GraduationError(f"{item}: gate command has no stdout/tee capture for {artifact}")
        if disposition == "DONE":
            _require_string(packet, "evidence", item)
            if item == "B-006":
                _validate_b006_committed_evidence(root, require_closure=True)
        elif disposition == "PARKED":
            if packet.get("verify_means") != "parked":
                raise GraduationError(f"{item}: parked packet must declare verify_means=parked")
        else:
            if item != "B-006" or packet.get("verify_means") != "reopened":
                raise GraduationError(f"{item}: reopened packet must declare verify_means=reopened")
            if packet.get("artifact") != B006_ARTIFACT:
                raise GraduationError("B-006: reopened packet artifact drifted")
            if packet.get("provider_artifact") != B006_PROVIDER_ARTIFACT:
                raise GraduationError("B-006: provider binding artifact drifted")
            command = packet["command"]
            for token in (
                "scripts/collect_b006_metrics.py",
                "scripts/collect_b006_provider_binding.py",
                "scripts/verify_b006_evidence.py",
                "scripts/verify_b006_provider_binding.py",
                B006_PROVIDER_ARTIFACT,
                "--keychain-service 'CoreLink/METRICS_OBSERVABILITY_KEY'",
                "--keychain-account corelink-ops",
                "X-Corelink-Internal-Auth",
                "--timeout 10",
                "--max-bytes 1048576",
            ):
                if token not in command:
                    raise GraduationError(f"B-006: reopened command is missing {token!r}")
            for forbidden in ("Authorization: Bearer", "CORELINK_PROD_TOKEN", "curl --fail", "--source-sha", "source_sha"):
                if forbidden in command:
                    raise GraduationError(f"B-006: reopened command contains forbidden credential form {forbidden!r}")
            _validate_b006_committed_evidence(root, require_closure=False)
    return entries


def _check_owner_packets(
    packets: dict[str, Any], records: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Validate owner-owned records without changing the frozen TL lane."""
    population = packets.get("owner_population")
    if tuple(population or ()) != OWNER_POPULATION:
        raise GraduationError("packet owner population is not the closed B-039 scope")
    entries = packets.get("owner_packets")
    if not isinstance(entries, dict) or set(entries) != set(OWNER_POPULATION):
        raise GraduationError("owner packet population is missing or not closed")
    for item in OWNER_POPULATION:
        packet = entries[item]
        if not isinstance(packet, dict) or set(packet) != OWNER_PACKET_FIELDS:
            raise GraduationError(f"{item}: owner packet fields are missing or ambiguous")
        record = records.get(item)
        if record is None:
            raise GraduationError(f"{item}: owner packet has no BACKLOG record")
        raw = record.raw
        if raw.get("owner") != packet["owner"] or raw.get("status") != packet["status"]:
            raise GraduationError(f"{item}: owner packet status disagrees with BACKLOG")
        for field in OWNER_PACKET_FIELDS:
            _require_string(packet, field, item)
        artifact = packet["artifact"]
        command = packet["command"]
        if artifact not in command or not re.search(r">\s*" + re.escape(artifact), command):
            raise GraduationError(f"{item}: owner command does not capture declared artifact")
        if "--offline" in command or OWNER_MIRROR_URL not in command:
            raise GraduationError(f"{item}: owner command must probe the immutable mirror URL")
        if OWNER_MIRROR_SHA256 not in command or "sha256sum" not in command:
            raise GraduationError(f"{item}: owner command must verify the pinned SHA-256")
        if raw.get("action-packet") != str(PACKET_PATH.relative_to(ROOT)):
            raise GraduationError(f"{item}: BACKLOG action-packet wiring is missing")
    return entries


def verify_document(
    root: Path = ROOT,
    *,
    backlog_text: str | None = None,
    packet_text: str | None = None,
    run_guards: bool = True,
    run_gates: bool = True,
) -> dict[str, int]:
    backlog_text = _read(root / "BACKLOG.md") if backlog_text is None else backlog_text
    packet_text = _read(root / PACKET_PATH.relative_to(ROOT)) if packet_text is None else packet_text
    records = parse(backlog_text)
    ids = [record.id for record in records]
    if len(ids) != len(set(ids)):
        raise GraduationError("BACKLOG contains duplicate ids")
    by_id = {record.id: record for record in records}
    if not ORIGINAL_SET.issubset(by_id) or "B-006" not in by_id:
        raise GraduationError("BACKLOG is missing an original TL/open item or B-006")
    # This is a historical D03 graduation gate.  New post-graduation backlog
    # findings are checked by their own records and must not invalidate the
    # closed 42-item D03 population merely because they are engineering-owned.
    remaining_open = sorted(
        record.id for record in records
        if record.id in ORIGINAL_SET
        and record.raw.get("owner") == "tl"
        and record.raw.get("status") == "open"
    )
    if remaining_open:
        raise GraduationError(f"repository still has owner tl/status open: {remaining_open}")
    packet_data = _load_packets(packet_text)
    if tuple(packet_data.get("post_graduation_retired", ())) != POST_GRADUATION_RETIRED:
        raise GraduationError("post-graduation retired population is missing or not closed")
    for item in POST_GRADUATION_RETIRED:
        record = by_id.get(item)
        if record is None or record.raw.get("owner") != "tl" or record.raw.get("status") != "done":
            raise GraduationError(f"{item}: post-graduation disposition must remain tl/done")
        means = str(record.raw.get("verify-means", ""))
        if not means.lstrip().lower().startswith("done —"):
            raise GraduationError(f"{item}: retired disposition must use done verify-means")
        if "B-119" not in means or "retir" not in means.lower():
            raise GraduationError(f"{item}: retired disposition must name the B-119 decision")
    _check_owner_packets(packet_data, by_id)
    packets = _check_packets(packet_data, root)
    _check_b006_done_population(packets)
    packet_done = frozenset(item for item, packet in packets.items() if packet["disposition"] == "DONE")
    if packet_done != DONE_SET:
        raise GraduationError(f"DONE population is not exactly {sorted(DONE_SET)}: {sorted(packet_done)}")

    for item in ORIGINAL_TL_OPEN:
        record = by_id[item]
        data = record.raw
        if data.get("owner") != "tl":
            raise GraduationError(f"{item}: owner changed from tl")
        if item in EXCLUDED:
            if data.get("status") != "done":
                raise GraduationError(f"{item}: excluded lane must be done on the integrated head")
            load_bearing = "\0".join(str(data.get(key, "")) for key in ("status", "verify", "verify-means"))
            fingerprint = hashlib.sha256(load_bearing.encode()).hexdigest()
            if fingerprint != EXCLUDED_FINGERPRINTS[item]:
                raise GraduationError(f"{item}: parent load-bearing fingerprint changed")
            continue
        packet = packets[item]
        status = data.get("status")
        expected = packet["disposition"].lower()
        if status != expected:
            raise GraduationError(f"{item}: BACKLOG status {status!r} disagrees with packet {expected!r}")
        means = str(data.get("verify-means", ""))
        if expected == "done":
            done_prefixes = ("done —", "inverted —") if item == "B-165" else ("done —",)
            if not means.lstrip().lower().startswith(done_prefixes):
                raise GraduationError(f"{item}: DONE verify-means is not inverted to done")
            if re.search(r"(?im)^\s*(?:open|manual|parked)\b", means):
                raise GraduationError(f"{item}: DONE verify-means contains stale status language")
        else:
            if not means.lstrip().lower().startswith("parked —"):
                raise GraduationError(f"{item}: PARKED verify-means must start with parked —")
            if re.search(r"(?im)^\s*(?:open|manual)\b", means):
                raise GraduationError(f"{item}: PARKED verify-means contains stale open/manual language")

    b006 = by_id["B-006"]
    if b006.raw.get("owner") != "tl":
        raise GraduationError("B-006 owner changed from tl")
    b006_status = b006.raw.get("status")
    b006_means = str(b006.raw.get("verify-means", "")).lstrip().lower()
    if b006_status == "open":
        if packets["B-006"]["disposition"] != "REOPENED" or not b006_means.startswith("open —"):
            raise GraduationError("B-006 open status must use a truthful reopened packet")
    elif b006_status == "done":
        if packets["B-006"]["disposition"] != "DONE" or not b006_means.startswith("done —"):
            raise GraduationError("B-006 done status must use a DONE packet and inverted means")
    else:
        raise GraduationError("B-006 must be open until authenticated zero evidence proves done")
    if packets["B-129"]["disposition"] != "PARKED" or "<10%" not in packets["B-129"]["evidence"]:
        raise GraduationError("B-129 must remain parked until production residual is <10%")

    if run_guards:
        commands = (
            ("B-028", (sys.executable, "scripts/verify_b028_dependabot.py")),
            ("B-074", (sys.executable, "scripts/verify_b074_money_path_auth.py", "--self-test")),
            ("B-118", (sys.executable, B118_ARTIFACT)),
            ("B-165", (
                sys.executable, "scripts/verify_b165_latency.py", B165_COMPLETE_ARTIFACT,
                "--samples", "10", "--require-served", "--tenant-a", B165_TENANT_A,
                "--tenant-b", B165_TENANT_B, "--pat-fingerprint-a", B165_PAT_FINGERPRINT_A,
                "--pat-fingerprint-b", B165_PAT_FINGERPRINT_B,
                "--server-timing-tsv", B165_SERVER_TIMING_ARTIFACT,
            )),
            ("B-253", (sys.executable, "-m", "pytest", "-q", "tests/test_b253_openapi_version.py")),
        )
        for item, command in commands:
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                raise GraduationError(f"{item}: inverted guard failed: {result.stdout}{result.stderr}")
    if run_gates:
        _run_parked_gates(root, by_id)
        _run_retired_gates(root, by_id)
    return {
        "original": len(ORIGINAL_TL_OPEN),
        "graduated": len(GRADUATED),
        "done": sum(packet["disposition"] == "DONE" for packet in packets.values()),
        "parked": sum(packet["disposition"] == "PARKED" for packet in packets.values()),
        "reopened": sum(packet["disposition"] == "REOPENED" for packet in packets.values()),
    }


_OFFLINE_ONLY_MARKERS = ("manual", "gh ", "gh\\n", "wrangler", "cargo ")
_OFFLINE_ONLY_IDS = frozenset((
    "B-028", "B-083", "B-098", "B-112", "B-129", "B-216", "B-229", "B-250",
))


def _run_parked_gates(root: Path, records: dict[str, Any]) -> None:
    """Run each parked gate once, replacing external actions with its offline guard."""
    for item in GRADUATED:
        if records[item].raw.get("status") != "parked":
            continue
        declared = str(records[item].raw.get("verify", ""))
        if item in _OFFLINE_ONLY_IDS or any(marker in declared for marker in _OFFLINE_ONLY_MARKERS):
            command = (sys.executable, "scripts/verify_d03_parked_gate.py", "--id", item)
        else:
            command = (sys.executable, "scripts/backlog_verify.py", "--id", item, "--format", "json")
        environment = dict(os.environ)
        environment["D03_GRADUATION_NESTED"] = "1"
        environment["D03_GRADUATION_OFFLINE"] = "1"
        try:
            result = subprocess.run(
                command, cwd=root, env=environment, capture_output=True, text=True, timeout=120
            )
        except subprocess.TimeoutExpired as exc:
            raise GraduationError(f"{item}: parked gate exceeded 120s") from exc
        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip()[-1000:]
            raise GraduationError(f"{item}: parked gate failed rc={result.returncode}: {output}")


def _run_retired_gates(root: Path, records: dict[str, Any]) -> None:
    """Run the local gate for each post-graduation retired item."""
    for item in POST_GRADUATION_RETIRED:
        if records[item].raw.get("status") != "done":
            continue
        command = (sys.executable, "scripts/verify_b210_retirement.py")
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip()[-1000:]
            raise GraduationError(f"{item}: retired gate failed rc={result.returncode}: {output}")


def self_test(root: Path = ROOT) -> None:
    backlog = _read(root / "BACKLOG.md")
    packets = _read(root / PACKET_PATH.relative_to(ROOT))
    command_removed = packets.replace('"command": "', '"command_removed": "', 1)
    if command_removed == packets:
        raise GraduationError("self-test fixture failed to locate a packet command field")
    retired_population = '  "post_graduation_retired": [\n    "B-210"\n  ],\n'
    if retired_population not in packets:
        raise GraduationError("self-test fixture failed to locate the retired population")
    cases = (
        ("status-open", backlog.replace("id: B-044\nrepo: corelink-runners\nowner: tl\nstatus: parked", "id: B-044\nrepo: corelink-runners\nowner: tl\nstatus: open", 1), packets),
        ("stale-means", backlog.replace("verify-means: |\n  parked —", "verify-means: |\n  open —", 1), packets),
        ("packet-command-removed", backlog, command_removed),
        ("packet-unclassified", backlog, packets.replace('"disposition": "PARKED"', '"disposition": "UNKNOWN"', 1)),
        ("post-graduation-omitted", backlog, packets.replace(retired_population, "", 1)),
        (
            "post-graduation-parked",
            backlog,
            packets.replace(retired_population, '  "post_graduation_parked": [\n    "B-210"\n  ],\n', 1),
        ),
        (
            "retired-status-parked",
            backlog.replace("id: B-210\nrepo: corelink-server\nowner: tl\nstatus: done", "id: B-210\nrepo: corelink-server\nowner: tl\nstatus: parked", 1),
            packets,
        ),
        (
            "retired-means-parked",
            backlog.replace("verify-means: |\n  done — B-210", "verify-means: |\n  parked — B-210", 1),
            packets,
        ),
        (
            "b118-reintroduced-parked",
            backlog,
            packets.replace(
                '"B-118": {\n      "disposition": "DONE"',
                '"B-118": {\n      "disposition": "PARKED"',
                1,
            ),
        ),
        (
            "b118-dispatch-command",
            backlog,
            packets.replace(B118_COMMAND, "gh run list --workflow cosign-sign.yml", 1),
        ),
        (
            "fake-done",
            backlog.replace("id: B-044\nrepo: corelink-runners\nowner: tl\nstatus: parked", "id: B-044\nrepo: corelink-runners\nowner: tl\nstatus: done", 1),
            packets.replace(
                '"B-044": {\n      "disposition": "PARKED"',
                '"B-044": {\n      "disposition": "DONE"',
                1,
            ),
        ),
        (
            "artifact-capture-removed",
            backlog,
            packets.replace(" : > artifacts/d03/B102-server-timing.json", "", 1).replace(
                " | tee -a artifacts/d03/B102-server-timing.json", "", 3
            ).replace(" >> artifacts/d03/B102-server-timing.json", "", 1),
        ),
    )
    for name, mutated_backlog, mutated_packets in cases:
        try:
            verify_document(root, backlog_text=mutated_backlog, packet_text=mutated_packets, run_guards=False, run_gates=False)
        except GraduationError:
            continue
        raise GraduationError(f"mutation unexpectedly passed: {name}")
    for item in EXCLUDED:
        marker = f"id: {item}"
        start = backlog.index(marker)
        end = backlog.index("```", start)
        original = backlog[start:end]
        mutated = backlog[:start] + original.replace("verify-means:", "verify-means: MUTATED ", 1) + backlog[end:]
        try:
            verify_document(root, backlog_text=mutated, packet_text=packets, run_guards=False, run_gates=False)
        except GraduationError:
            continue
        raise GraduationError(f"mutation unexpectedly passed: {item} verify-means")
    owner_data = _load_packets(packets)
    for name, mutation in (
        ("owner-packet-missing", lambda data: data["owner_packets"].pop("B-039")),
        ("owner-status-missing", lambda data: data["owner_packets"]["B-039"].pop("status")),
        (
            "owner-offline-command",
            lambda data: data["owner_packets"]["B-039"].update(
                command="python3 scripts/verify_b155_owned.py --id B-039 --expect open --offline > artifacts/d03/B039-mirror-availability.json"
            ),
        ),
    ):
        mutated = copy.deepcopy(owner_data)
        mutation(mutated)
        try:
            verify_document(
                root,
                packet_text=json.dumps(mutated),
                run_guards=False,
                run_gates=False,
            )
        except GraduationError:
            continue
        raise GraduationError(f"mutation unexpectedly passed: {name}")

    # Every flagged parked command has a population/safety contract.  Kill one
    # load-bearing safety token, declared count, and concrete owner operation
    # per item; a verifier that checks only artifact redirection must not accept
    # any of these mutants.
    for item, contract in COMMAND_CONTRACTS.items():
        mutations = [
            ("semantic-token-removed", lambda data, token=contract["safety"][0]: data["packets"][item].update(command=data["packets"][item]["command"].replace(token, ""))),
            ("semantic-count-mutated", lambda data: data["packets"][item]["command_contract"].update(sample_count=contract["sample_count"] + 1)),
        ]
        mutations.extend(
            (f"load-bearing-operation-removed:{operation}", lambda data, operation=operation: data["packets"][item].update(command=data["packets"][item]["command"].replace(operation, "", 1)))
            for operation in COMMAND_OPERATIONS[item]
        )
        for name, mutation in mutations:
            mutated = copy.deepcopy(owner_data)
            # Start from the full graduation document, not only owner packets.
            full = _load_packets(packets)
            mutation(full)
            try:
                verify_document(
                    root,
                    packet_text=json.dumps(full),
                    run_guards=False,
                    run_gates=False,
                )
            except GraduationError:
                continue
            raise GraduationError(f"mutation unexpectedly passed: {item} {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-guards", action="store_true")
    parser.add_argument("--schema-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        nested = bool(os.environ.get("D03_GRADUATION_NESTED"))
        result = verify_document(
            run_guards=not args.no_guards and not args.schema_only and not nested,
            run_gates=not args.schema_only and not nested,
        )
        if args.self_test:
            self_test()
        print(f"D03 graduation: PASS; original={result['original']} graduated={result['graduated']} done={result['done']} parked={result['parked']} reopened={result['reopened']}")
        return 0
    except (GraduationError, OSError, subprocess.SubprocessError) as exc:
        print(f"D03 graduation FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
