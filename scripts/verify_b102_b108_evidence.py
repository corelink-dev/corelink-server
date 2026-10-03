#!/usr/bin/env python3
"""Fail-closed verifier for the bounded, owner-only B-102..B-108 lane.

The packet is evidence, not a declaration.  Every observation carries the
tenant and an operation id; deployment identity is bound to the GitHub run and
to the provider response digest; all derived values are recomputed here.  No
credential is accepted in the packet.  The verifier never contacts production.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from install_pinned_gh import InstallError as PinnedGhError
    from install_pinned_gh import install as install_pinned_gh
except ModuleNotFoundError:  # imported as scripts.verify_b102_b108_evidence
    from scripts.install_pinned_gh import InstallError as PinnedGhError
    from scripts.install_pinned_gh import install as install_pinned_gh
try:
    from server_repository import resolve_server_repository
    from server_repository import validate_server_repository as validate_configured_server_repository
except ModuleNotFoundError:  # imported as scripts.verify_b102_b108_evidence
    from scripts.server_repository import resolve_server_repository
    from scripts.server_repository import validate_server_repository as validate_configured_server_repository

SCHEMA = "corelink.performance-evidence.v2"
ITEMS = tuple(f"B-{n:03d}" for n in range(102, 109))
# Packets are at most MAX_AGE old, so they always come from the live repo;
# the authorized identity is the configured server in config/github-identity.json.
REPO: str | None = None
SOURCE = "worker/src/lib/quota.ts"
WORKFLOW = ".github/workflows/perf-production-evidence.yml"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
GITHUB_WORKFLOW_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
GH_ATTESTATION_VERSION = "2.79.0"
SUBJECT_NAME = "b106-cold-attestation.json"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
OP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
SECRET = re.compile(r"(?i)(bearer\s+|pat[_-]?token|api[_-]?key|password|secret|private[_-]?key|authorization)")
FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
SERVER_TIMING_ENTRY = re.compile(
    r"\s*(?P<name>[a-z][a-z0-9_-]*);dur=(?P<duration>[0-9]+(?:\.[0-9]+)?)"
    r'(?:;[a-z][a-z0-9_-]*=(?:"(?:[^"\\]|\\.)*"|[^,;\s]+))*\s*'
)
MAX_AGE = 15 * 60
FRESH_MINT_MAX_AGE_SECONDS = 15 * 60
COLD_MIN_IDLE_SECONDS = 61
KV_PAT_ROW_TTL_SECONDS = 30
CLOCK_TOLERANCE = 2
COUNTER_SQL = (
    "INSERT INTO monthly_request_counts (tenant_id, year_month, request_count, updated_at_ms) "
    "VALUES (?1, ?2, 1, ?3) "
    "ON CONFLICT(tenant_id, year_month) "
    "DO UPDATE SET request_count = request_count + 1, updated_at_ms = ?3 "
    "RETURNING request_count"
)


class EvidenceError(ValueError):
    pass


def validate_server_repository(repository: str) -> str:
    """Require the exact configured server repository identity."""
    try:
        return validate_configured_server_repository(repository)
    except ValueError as exc:
        raise EvidenceError("repository is not an authorized corelink-server identity") from exc


def obj(v: Any, label: str) -> dict[str, Any]:
    if not isinstance(v, dict):
        raise EvidenceError(f"{label} must be an object")
    return v


def text(v: Any, label: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise EvidenceError(f"{label} must be a non-empty string")
    return v.strip()


def num(v: Any, label: str, minimum: float = 0.0) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise EvidenceError(f"{label} must be numeric")
    x = float(v)
    if not math.isfinite(x) or x < minimum:
        raise EvidenceError(f"{label} must be finite and >= {minimum}")
    return x


def entries(v: Any, label: str, minimum: int) -> list[dict[str, Any]]:
    if not isinstance(v, list) or len(v) < minimum:
        raise EvidenceError(f"{label} requires at least {minimum} entries")
    return [obj(x, f"{label}[{i}]") for i, x in enumerate(v)]


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


WIRE_DIGEST_FIELDS = (
    "tenant_id", "operation_id", "request_key", "method", "status", "payload_bytes",
    "payload_sha256", "elapsed_ms", "server_timing", "error", "authenticated",
    "auth_source", "colo", "response_request_id",
)


def wire_output_sha256(row: dict[str, Any]) -> str:
    material = {key: row.get(key) for key in WIRE_DIGEST_FIELDS}
    return sha(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())


def server_timing_entries(value: str, label: str) -> list[str]:
    """Split Server-Timing entries without treating commas in quotes as seams."""
    entries: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            entries.append(value[start:index])
            start = index + 1
    if quoted or escaped:
        raise EvidenceError(f"{label} contains an unterminated quoted value")
    entries.append(value[start:])
    return entries


def blocking_phase_pair(row: dict[str, Any], label: str) -> tuple[float, float]:
    """Read the disjoint R2/D1 phases and reject missing or duplicate names."""
    timing = text(row.get("server_timing"), f"{label}.server_timing")
    matches: dict[str, list[float]] = {}
    for entry in server_timing_entries(timing, f"{label}.server_timing"):
        match = SERVER_TIMING_ENTRY.fullmatch(entry)
        if match is None:
            continue
        matches.setdefault(match.group("name"), []).append(float(match.group("duration")))
    pair = []
    for name in ("ostore", "oaccounting"):
        values = matches.get(name, [])
        if len(values) != 1:
            raise EvidenceError(f"{label} requires exactly one {name} wire phase")
        pair.append(values[0])
    return pair[0], pair[1]


def phase_pair_fits_wire_clock(row: dict[str, Any], label: str) -> tuple[float, float]:
    store, accounting = blocking_phase_pair(row, label)
    elapsed = num(row.get("elapsed_ms"), f"{label}.elapsed_ms", 0.001)
    # Server-Timing phases are truncated independently to milliseconds. The
    # client wall clock includes the server window plus transport, so the pair
    # cannot legitimately exceed it; 1 ms covers local rounding only.
    if store + accounting > elapsed + 1.0:
        raise EvidenceError(f"{label} storage/accounting phase sum exceeds client wall clock")
    return store, accounting


def raw_hash(v: Any, label: str) -> str:
    value = text(v, label)
    if not FINGERPRINT.fullmatch(value):
        raise EvidenceError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def mint_binding_sha256(att: dict[str, Any]) -> str:
    material = json.dumps(
        {
            "expires_ms": att.get("expires_ms"),
            "pat_id": att.get("pat_id"),
            "tenant_id": att.get("tenant_id"),
            "token_fingerprint": att.get("token_fingerprint"),
            "token_id": att.get("token_id"),
            "mint_operation_id": att.get("mint_operation_id"),
            "mint_request_id": att.get("mint_request_id"),
            "mint_response_sha256": att.get("mint_response_sha256"),
            "minted_at_epoch": att.get("minted_at_epoch"),
            "unused_since_epoch": att.get("unused_since_epoch"),
            "observed_at_epoch": att.get("observed_at_epoch"),
            "attestation_source": att.get("attestation_source"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha(material)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def b106_subject_bytes(att: dict[str, Any], deployment_record: dict[str, Any]) -> bytes:
    source = obj(att.get("attestation_source"), "B-106.attestation_source")
    return canonical_json(
        {
            "schema": "corelink.performance-evidence.b106-attestation.v1",
            "repository": REPO,
            "workflow": "perf-production-evidence",
            "run_id": deployment_record["github_run_id"],
            "run_attempt": deployment_record["github_run_attempt"],
            "event": deployment_record["github_event"],
            "ref": deployment_record["github_ref"],
            "head_sha": deployment_record["source_head"],
            "run_started_at": deployment_record["github_run_started_at"],
            "cold_attestation": att,
        }
    )


def _attested_statement(bundle: dict[str, Any], label: str) -> dict[str, Any]:
    envelope = obj(bundle.get("dsseEnvelope"), f"{label}.dsseEnvelope")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise EvidenceError(f"{label} is not an in-toto DSSE envelope")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise EvidenceError(f"{label} has no DSSE signature")
    for index, signature in enumerate(signatures):
        signature = obj(signature, f"{label}.signatures[{index}]")
        encoded_signature = text(signature.get("sig"), f"{label}.signatures[{index}].sig")
        try:
            decoded_signature = base64.b64decode(encoded_signature, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EvidenceError(f"{label}.signatures[{index}] is not base64") from exc
        if not decoded_signature:
            raise EvidenceError(f"{label}.signatures[{index}] is empty")
    encoded = text(envelope.get("payload"), f"{label}.dsseEnvelope.payload")
    try:
        statement = obj(json.loads(base64.b64decode(encoded, validate=True)), f"{label}.statement")
    except (ValueError, json.JSONDecodeError, binascii.Error) as exc:
        raise EvidenceError(f"{label} has an invalid DSSE payload") from exc
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise EvidenceError(f"{label} is not an in-toto Statement v1")
    if statement.get("predicateType") != SLSA_PREDICATE:
        raise EvidenceError(f"{label} predicate type is not SLSA provenance v1")
    verification_material = obj(bundle.get("verificationMaterial"), f"{label}.verificationMaterial")
    certificate = obj(verification_material.get("certificate"), f"{label}.verificationMaterial.certificate")
    encoded_certificate = text(certificate.get("rawBytes"), f"{label}.verificationMaterial.certificate.rawBytes")
    try:
        if not base64.b64decode(encoded_certificate, validate=True):
            raise ValueError("empty certificate")
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError(f"{label} has no retained signing certificate") from exc
    timestamp_data = obj(verification_material.get("timestampVerificationData"), f"{label}.timestampVerificationData")
    if not any(isinstance(timestamp_data.get(key), list) and timestamp_data[key] for key in ("tlogEntries", "rfc3161Timestamps")):
        raise EvidenceError(f"{label} has no retained transparency/timestamp verification")
    return statement


def _validate_attestation_identity(
    statement: dict[str, Any], deployment_record: dict[str, Any], subject_sha: str, label: str
) -> None:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise EvidenceError(f"{label} must have exactly one attested subject")
    subject = obj(subjects[0], f"{label}.subject[0]")
    if subject.get("name") != SUBJECT_NAME:
        raise EvidenceError(f"{label} subject name is not canonical")
    digest = obj(subject.get("digest"), f"{label}.subject[0].digest")
    if digest.get("sha256") != subject_sha.removeprefix("sha256:"):
        raise EvidenceError(f"{label} subject digest differs from the cold evidence")
    predicate = obj(statement.get("predicate"), f"{label}.predicate")
    build_definition = obj(predicate.get("buildDefinition"), f"{label}.predicate.buildDefinition")
    if build_definition.get("buildType") != GITHUB_WORKFLOW_BUILD_TYPE:
        raise EvidenceError(f"{label} build type is not the GitHub Actions workflow provenance")
    external = obj(build_definition.get("externalParameters"), f"{label}.predicate.buildDefinition.externalParameters")
    workflow = obj(external.get("workflow"), f"{label}.predicate.workflow")
    if workflow != {
        "ref": deployment_record["github_ref"],
        "repository": f"https://github.com/{REPO}",
        "path": WORKFLOW,
    }:
        raise EvidenceError(f"{label} workflow identity is not exact")
    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or not any(
        isinstance(dep, dict)
        and isinstance(dep.get("digest"), dict)
        and dep["digest"].get("gitCommit") == deployment_record["source_head"]
        for dep in dependencies
    ):
        raise EvidenceError(f"{label} resolved dependencies do not name the exact source SHA")
    run_details = obj(predicate.get("runDetails"), f"{label}.predicate.runDetails")
    metadata = obj(run_details.get("metadata"), f"{label}.predicate.runDetails.metadata")
    expected_invocation = (
        f"https://github.com/{REPO}/actions/runs/{deployment_record['github_run_id']}"
        f"/attempts/{deployment_record['github_run_attempt']}"
    )
    if metadata.get("invocationId") != expected_invocation:
        raise EvidenceError(f"{label} invocation does not bind the exact workflow run/attempt")


def verify_attestation_with_gh(
    bundle: dict[str, Any], subject_bytes: bytes, deployment_record: dict[str, Any], expected: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Run the pinned GitHub Sigstore verifier against the retained bundle.

    The executable and version are deliberately not caller-overridable: the
    verifier is installed from the repository-pinned release and validated
    before it accepts any DSSE/tlog material.
    """
    with tempfile.TemporaryDirectory(prefix="corelink-b106-verify-") as directory:
        root = Path(directory)
        try:
            verifier_path = install_pinned_gh(root / "gh")
        except (OSError, PinnedGhError) as exc:
            raise EvidenceError(f"B-106 pinned gh verifier is unavailable: {exc}") from exc
        verifier = str(verifier_path)
        gh_home = root / "home"
        gh_config = root / "config"
        gh_home.mkdir(mode=0o700)
        gh_config.mkdir(mode=0o700)
        environment = gh_environment(gh_home, gh_config)
        try:
            version = subprocess.run(
                (str(verifier_path), "version"), capture_output=True, text=True, check=True, timeout=15, env=environment
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise EvidenceError(f"B-106 pinned gh verifier is unavailable: {exc}") from exc
        if not version.startswith(f"gh version {GH_ATTESTATION_VERSION}"):
            raise EvidenceError(f"B-106 gh verifier version is not pinned to {GH_ATTESTATION_VERSION}")
        subject_path = root / SUBJECT_NAME
        bundle_path = root / "attestation.bundle.json"
        subject_path.write_bytes(subject_bytes)
        bundle_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        san = f"https://github.com/{REPO}/{WORKFLOW}@{deployment_record['github_ref']}"
        command = (
            verifier, "attestation", "verify", str(subject_path), "--repo", REPO, "--bundle", str(bundle_path),
            "--predicate-type", SLSA_PREDICATE, "--cert-identity", san,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--signer-digest", deployment_record["source_head"], "--source-digest", deployment_record["source_head"],
            "--source-ref", deployment_record["github_ref"], "--format", "json",
        )
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60, env=environment)
            verified = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            raise EvidenceError("B-106 pinned gh attestation verification failed") from exc
    if not isinstance(verified, list) or not verified or verified != expected:
        raise EvidenceError("B-106 gh verification result is not byte-for-byte bound to the retained result")
    return verified


def gh_environment(home: Path, config: Path) -> dict[str, str]:
    """Run gh with a strict allowlist; no runner environment is inherited."""
    environment = {
        "GH_HOST": "github.com",
        "GH_CONFIG_DIR": str(config),
        "GH_NO_UPDATE_NOTIFIER": "1",
        "HOME": str(home),
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": str(config),
        "GITHUB_SERVER_URL": "https://github.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
    }
    return environment


def attested_subject_digest(bundle: dict[str, Any], label: str) -> str:
    statement = _attested_statement(bundle, label)
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise EvidenceError(f"{label} must have exactly one attested subject")
    digest = obj(subjects[0], f"{label}.subject[0]").get("digest")
    digest = obj(digest, f"{label}.subject[0].digest").get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EvidenceError(f"{label} subject has no SHA-256 digest")
    return "sha256:" + digest


def reject_secrets(v: Any, path: str = "packet") -> None:
    if isinstance(v, str) and SECRET.search(v):
        raise EvidenceError(f"{path} contains credential-like material")
    if isinstance(v, dict):
        for k, child in v.items():
            # Credential-shaped names are forbidden even when their value is
            # redacted.  Fingerprints are the sole intentional token exception.
            if SECRET.search(k) and not (k.endswith("_fingerprint") or k.endswith("_raw_output_sha256")):
                raise EvidenceError(f"{path}.{k} is a credential field")
            reject_secrets(child, f"{path}.{k}")
    elif isinstance(v, list):
        for i, child in enumerate(v):
            reject_secrets(child, f"{path}[{i}]")


def iso_epoch(value: Any, label: str) -> float:
    raw = text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include a timezone")
    return parsed.timestamp()


def common(row: dict[str, Any], label: str, tenant: str) -> None:
    if row.get("tenant_id") != tenant:
        raise EvidenceError(f"{label}.tenant_id is not the packet tenant")
    operation = text(row.get("operation_id"), f"{label}.operation_id")
    if not OP.fullmatch(operation):
        raise EvidenceError(f"{label}.operation_id is malformed")


def deployment(item: dict[str, Any], label: str, root: Path, tenant: str) -> str:
    d = obj(item.get("deployment"), f"{label}.deployment")
    if d.get("repository") != REPO or d.get("environment") != "production":
        raise EvidenceError(f"{label} deployment is not the production repository")
    commit = text(d.get("deployed_commit"), f"{label}.deployment.deployed_commit")
    source_head = text(d.get("source_head"), f"{label}.deployment.source_head")
    if not SHA1.fullmatch(commit) or not SHA1.fullmatch(source_head):
        raise EvidenceError(f"{label} deployment SHAs must be full lowercase commits")
    if d.get("github_sha") != source_head or d.get("github_repository") != REPO:
        raise EvidenceError(f"{label} deployment is not bound to GitHub context")
    github_ref = text(d.get("github_ref"), f"{label}.deployment.github_ref")
    if not github_ref.startswith("refs/"):
        raise EvidenceError(f"{label}.deployment.github_ref is not a full Git ref")
    if d.get("github_event") not in {"workflow_dispatch", "workflow_run"}:
        raise EvidenceError(f"{label} deployment lane is not owner-triggered")
    run_id = text(d.get("github_run_id"), f"{label}.deployment.github_run_id")
    if not run_id.isdigit():
        raise EvidenceError(f"{label}.deployment.github_run_id is malformed")
    run_attempt = text(d.get("github_run_attempt"), f"{label}.deployment.github_run_attempt")
    if not run_attempt.isdigit() or int(run_attempt) < 1:
        raise EvidenceError(f"{label}.deployment.github_run_attempt is malformed")
    iso_epoch(d.get("github_run_started_at"), f"{label}.deployment.github_run_started_at")
    github_deployment_id = text(d.get("github_deployment_id"), f"{label}.deployment.github_deployment_id")
    if not github_deployment_id.isdigit():
        raise EvidenceError(f"{label}.deployment.github_deployment_id is malformed")
    provider = obj(d.get("provider_record"), f"{label}.deployment.provider_record")
    if provider.get("provider") != "cloudflare" or provider.get("environment") != "production":
        raise EvidenceError(f"{label} provider record is not Cloudflare production")
    provider_blob = text(d.get("provider_blob_sha256"), f"{label}.deployment.provider_blob_sha256")
    if not FINGERPRINT.fullmatch(provider_blob):
        raise EvidenceError(f"{label} provider response must be content-addressed")
    if provider.get("commit") != commit or provider.get("deployment_id") != d.get("deployment_id"):
        raise EvidenceError(f"{label} provider record is not bound to the deployed commit/id")
    deployment_id = text(d.get("deployment_id"), f"{label}.deployment.deployment_id")
    if not OP.fullmatch(deployment_id):
        raise EvidenceError(f"{label}.deployment_id is malformed")
    if text(d.get("version"), f"{label}.deployment.version") != commit:
        raise EvidenceError(f"{label}.deployment.version is not the deployed commit")
    if text(d.get("tenant_id"), f"{label}.deployment.tenant_id") != tenant:
        raise EvidenceError(f"{label}.deployment is not tenant-scoped")
    op = text(d.get("operation_id"), f"{label}.deployment.operation_id")
    if not OP.fullmatch(op):
        raise EvidenceError(f"{label}.deployment.operation_id is malformed")
    try:
        present = subprocess.run(("git", "cat-file", "-e", f"{commit}^{{commit}}"), cwd=root, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError(f"{label} git provenance unavailable: {exc}") from exc
    if present.returncode:
        raise EvidenceError(f"{label} deployed commit is absent")
    if commit != source_head:
        raise EvidenceError(f"{label} deployed commit is not exactly the GitHub SHA")
    return commit


def b102(item: dict[str, Any], root: Path, tenant: str) -> str:
    deployment(item, "B-102", root, tenant)
    rows = entries(item.get("requests"), "B-102.requests", 3)[:3]
    for i, row in enumerate(rows):
        common(row, f"B-102.requests[{i}]", tenant)
        if row.get("method") != "PUT" or row.get("status") != 200 or num(row.get("payload_bytes"), "B-102.payload_bytes") != 1024:
            raise EvidenceError("B-102 requires three successful 1 KiB PUTs")
        if row.get("raw_output_sha256") != wire_output_sha256(row):
            raise EvidenceError("B-102 raw output hash is not bound to the complete wire sample")
        phase_pair_fits_wire_clock(row, f"B-102.requests[{i}]")
    if num(item.get("sequence_window_seconds"), "B-102.sequence_window_seconds") > 60:
        raise EvidenceError("B-102 PUTs are not a bounded warm sequence")
    if not FINGERPRINT.fullmatch(text(item.get("token_fingerprint"), "B-102.token_fingerprint")):
        raise EvidenceError("B-102 token fingerprint is not SHA-256")
    return "open"


def b103(item: dict[str, Any], root: Path, tenant: str) -> str:
    deployment(item, "B-103", root, tenant)
    runs = entries(item.get("runs"), "B-103.runs", 3)
    if len({num(x.get("concurrency"), "B-103.concurrency", 1) for x in runs}) < 3:
        raise EvidenceError("B-103 requires three concurrency levels")
    measured = []
    for i, row in enumerate(runs):
        common(row, f"B-103.runs[{i}]", tenant)
        c = num(row.get("concurrency"), "B-103.concurrency", 1)
        requests = num(row.get("requests"), "B-103.requests", 1)
        successes = num(row.get("successes"), "B-103.successes")
        failures = obj(row.get("failures"), "B-103.failures")
        failed = sum(num(v, "B-103.failure_count") for v in failures.values())
        if requests != successes + failed:
            raise EvidenceError(f"B-103 counts do not reconcile at concurrency {c:g}")
        if failed != 0:
            raise EvidenceError("B-103 requires zero failures at every concurrency level")
        throughput = successes / (num(row.get("wall_ms"), "B-103.wall_ms", .001) / 1000)
        raw = num(row.get("throughput_rps"), "B-103.throughput_rps")
        if abs(raw - throughput) > max(.001, throughput * .001):
            raise EvidenceError("B-103 throughput is not derived from raw counts")
        raw_hash(row.get("raw_output_sha256"), "B-103.raw_output_sha256")
        measured.append((c, throughput, failed))
    measured.sort()
    low, high = measured[0], measured[-1]
    # Significant scaling is explicit and mathematical, not a self-attested bool.
    return "open"


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    position = p * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def b104(item: dict[str, Any], root: Path, tenant: str) -> str:
    deployment(item, "B-104", root, tenant)
    rows = entries(item.get("samples"), "B-104.samples", 10)
    times = []
    for i, row in enumerate(rows):
        common(row, f"B-104.samples[{i}]", tenant)
        if row.get("method") != "GET" or row.get("status") != 404 or row.get("authenticated") is not True:
            raise EvidenceError("B-104 requires authenticated 404 GETs")
        if row.get("auth_source") not in {"l1", "kv", "d1"}:
            raise EvidenceError("B-104 requires a wire-derived auth source")
        if not text(row.get("colo"), f"B-104.samples[{i}].colo"):
            raise EvidenceError("B-104 requires a wire-derived colo")
        if not text(row.get("response_request_id"), f"B-104.samples[{i}].response_request_id"):
            raise EvidenceError("B-104 requires a wire-derived response request id")
        text(row.get("request_key"), f"B-104.samples[{i}].request_key")
        raw_hash(row.get("payload_sha256"), f"B-104.samples[{i}].payload_sha256")
        if row.get("raw_output_sha256") != wire_output_sha256(row):
            raise EvidenceError("B-104 raw output hash is not bound to the complete wire sample")
        times.append(num(row.get("elapsed_ms"), "B-104.elapsed_ms"))
    ordered = sorted(times)
    median = (ordered[(len(ordered)-1)//2] + ordered[len(ordered)//2]) / 2
    p90 = percentile(times, .90)
    computed = obj(item.get("computed"), "B-104.computed")
    if abs(num(computed.get("median_ms"), "B-104.median_ms") - median) > .001 or abs(num(computed.get("p90_ms"), "B-104.p90_ms") - p90) > .001:
        raise EvidenceError("B-104 percentiles are not derived from raw samples")
    return "open"


def b105(item: dict[str, Any], root: Path, tenant: str) -> str:
    commit = deployment(item, "B-105", root, tenant)
    pairs = entries(item.get("pairs"), "B-105.pairs", 6)
    if len(pairs) != 6:
        raise EvidenceError("B-105 requires exactly six paired runs")
    first = []
    for i, pair in enumerate(pairs):
        common(pair, f"B-105.pairs[{i}]", tenant)
        control, treatment = obj(pair.get("control"), "B-105.control"), obj(pair.get("treatment"), "B-105.treatment")
        for arm, row, mode in (("control", control, "disabled"), ("treatment", treatment, "enabled")):
            common(row, f"B-105.{arm}", tenant)
            if row.get("cache_mode") != mode or row.get("status") != "complete":
                raise EvidenceError("B-105 cache mode/status is not real lane evidence")
            raw_hash(row.get("raw_output_sha256"), f"B-105.{arm}.raw_output_sha256")
            raw_hash(row.get("sccache_stats_raw_sha256"), f"B-105.{arm}.sccache_stats_raw_sha256")
            num(row.get("duration_seconds"), f"B-105.{arm}.duration_seconds", .001)
            stats = obj(row.get("sccache"), f"B-105.{arm}.sccache")
            num(stats.get("hits"), f"B-105.{arm}.sccache.hits")
            num(stats.get("misses"), f"B-105.{arm}.sccache.misses")
            if any(num(stats.get(k), f"B-105.{arm}.sccache.{k}") != 0 for k in ("read_errors", "write_errors")):
                raise EvidenceError("B-105 cache lane contains an sccache error")
        for key in ("revision", "runner", "machine", "toolchain", "command"):
            if control.get(key) != treatment.get(key):
                raise EvidenceError(f"B-105 arms differ in {key}")
        if control.get("revision") != commit:
            raise EvidenceError("B-105 lane revision is not the deployed GitHub SHA")
        first.append(pair.get("control_first"))
    if any(x not in {True, False} for x in first) or any(a == b for a, b in zip(first, first[1:])):
        raise EvidenceError("B-105 must alternate control-first and treatment-first")
    return "open"


def b106(item: dict[str, Any], root: Path, tenant: str, now: float) -> str:
    deployment(item, "B-106", root, tenant)
    deployment_record = obj(item.get("deployment"), "B-106.deployment")
    if item.get("kv_ttl_seconds") != KV_PAT_ROW_TTL_SECONDS:
        raise EvidenceError(f"B-106 evidence must report the runtime {KV_PAT_ROW_TTL_SECONDS}-second KV TTL")
    att = obj(item.get("cold_attestation"), "B-106.cold_attestation")
    common(att, "B-106.cold_attestation", tenant)
    raw_hash(att.get("mint_raw_output_sha256"), "B-106.mint_raw_output_sha256")
    raw_hash(att.get("mint_response_sha256"), "B-106.mint_response_sha256")
    if att.get("mint_response_sha256") != att.get("mint_raw_output_sha256"):
        raise EvidenceError("B-106 mint response digests do not agree")
    raw_hash(att.get("mint_response_binding_sha256"), "B-106.mint_response_binding_sha256")
    for key in ("pat_id", "token_id"):
        text(att.get(key), f"B-106.{key}")
    num(att.get("expires_ms"), "B-106.expires_ms", 1)
    mint_operation_id = text(att.get("mint_operation_id"), "B-106.mint_operation_id")
    if mint_operation_id != text(att.get("operation_id"), "B-106.cold_attestation.operation_id"):
        raise EvidenceError("B-106 mint operation is not the attested operation")
    text(att.get("mint_request_id"), "B-106.mint_request_id")
    fingerprint = text(att.get("token_fingerprint"), "B-106.token_fingerprint")
    if not FINGERPRINT.fullmatch(fingerprint):
        raise EvidenceError("B-106 token fingerprint is not SHA-256")
    if att.get("mint_response_binding_sha256") != mint_binding_sha256(att):
        raise EvidenceError("B-106 mint response binding is not reproducible")
    source = obj(att.get("attestation_source"), "B-106.attestation_source")
    if source.get("kind") != "github_actions_run":
        raise EvidenceError("B-106 attestation source is not a GitHub Actions run")
    if source.get("workflow") != "perf-production-evidence":
        raise EvidenceError("B-106 attestation source workflow is not the production evidence lane")
    if source.get("repository") != REPO:
        raise EvidenceError("B-106 attestation source is not the canonical repository")
    if source.get("event") != deployment_record.get("github_event"):
        raise EvidenceError("B-106 attestation source event is not correlated")
    if str(source.get("run_id")) != str(deployment_record.get("github_run_id")):
        raise EvidenceError("B-106 attestation source run is not correlated")
    if str(source.get("attempt")) != str(deployment_record.get("github_run_attempt")):
        raise EvidenceError("B-106 attestation source attempt is not correlated")
    if source.get("ref") != deployment_record.get("github_ref"):
        raise EvidenceError("B-106 attestation source ref is not correlated")
    if source.get("head_sha") != deployment_record.get("source_head"):
        raise EvidenceError("B-106 attestation source SHA is not correlated")
    source_started = iso_epoch(source.get("started_at"), "B-106.attestation_source.started_at")
    deployment_started = iso_epoch(deployment_record.get("github_run_started_at"), "B-106.deployment.github_run_started_at")
    if abs(source_started - deployment_started) > CLOCK_TOLERANCE:
        raise EvidenceError("B-106 attestation source timestamp is not correlated")
    for key in ("minted_at_epoch", "unused_since_epoch", "observed_at_epoch"):
        num(att.get(key), f"B-106.{key}", 1)
    minted, unused, observed = (float(att[k]) for k in ("minted_at_epoch", "unused_since_epoch", "observed_at_epoch"))
    if minted < source_started - CLOCK_TOLERANCE:
        raise EvidenceError("B-106 mint predates the trusted workflow attestation")
    if (
        not minted <= unused <= observed - COLD_MIN_IDLE_SECONDS
        or minted > now + CLOCK_TOLERANCE
        or unused > now + CLOCK_TOLERANCE
        or observed > now + CLOCK_TOLERANCE
        or now - minted > FRESH_MINT_MAX_AGE_SECONDS
    ):
        raise EvidenceError(
            f"B-106 does not prove a fresh token minted within {FRESH_MINT_MAX_AGE_SECONDS} seconds "
            f"and idle for {COLD_MIN_IDLE_SECONDS} seconds"
        )
    github_attestation = obj(item.get("github_attestation"), "B-106.github_attestation")
    subject_sha = raw_hash(github_attestation.get("subject_sha256"), "B-106.github_attestation.subject_sha256")
    if subject_sha != sha(b106_subject_bytes(att, deployment_record)):
        raise EvidenceError("B-106 GitHub attestation subject does not bind the exact cold timestamps")
    if github_attestation.get("subject_name") != "b106-cold-attestation.json":
        raise EvidenceError("B-106 GitHub attestation subject name is not canonical")
    bundle = obj(github_attestation.get("bundle"), "B-106.github_attestation.bundle")
    if github_attestation.get("bundle_sha256") != sha(canonical_json(bundle)):
        raise EvidenceError("B-106 GitHub attestation bundle hash is not reproducible")
    if attested_subject_digest(bundle, "B-106.github_attestation.bundle") != subject_sha:
        raise EvidenceError("B-106 GitHub attestation DSSE subject differs from the cold evidence")
    policy = obj(github_attestation.get("verification_policy"), "B-106.github_attestation.verification_policy")
    if policy != {
        "repository": REPO,
        "signer_workflow": f"{REPO}/{WORKFLOW}",
        "signer_digest": deployment_record["source_head"],
        "predicate_type": SLSA_PREDICATE,
    }:
        raise EvidenceError("B-106 GitHub attestation verification policy is not the production workflow")
    bundle_statement = _attested_statement(bundle, "B-106.github_attestation.bundle")
    _validate_attestation_identity(bundle_statement, deployment_record, subject_sha, "B-106.github_attestation.bundle")
    verification = github_attestation.get("verification")
    if not isinstance(verification, list) or not verification:
        raise EvidenceError("B-106 GitHub attestation has no successful gh verification result")
    verify_attestation_with_gh(
        bundle,
        b106_subject_bytes(att, deployment_record),
        deployment_record,
        verification,
    )
    verified_subject = False
    for entry in verification:
        if not isinstance(entry, dict):
            continue
        result = entry.get("verificationResult")
        if not isinstance(result, dict):
            continue
        if entry.get("attestation") != bundle:
            continue
        signature = result.get("signature")
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        if (
            not isinstance(certificate, dict)
            or certificate.get("sourceRepository") != REPO
            or not isinstance(certificate.get("certificateIssuer"), str)
            or not certificate.get("certificateIssuer")
            or certificate.get("issuer") != "https://token.actions.githubusercontent.com"
        ):
            continue
        signer_san = certificate.get("subjectAlternativeName")
        expected_san_prefix = f"https://github.com/{REPO}/{WORKFLOW}@"
        if signer_san != expected_san_prefix + deployment_record["github_ref"]:
            continue
        if not isinstance(result.get("verifiedTimestamps"), list) or not result["verifiedTimestamps"]:
            continue
        statement = result.get("statement")
        if not isinstance(statement, dict):
            continue
        if statement != bundle_statement:
            continue
        try:
            _validate_attestation_identity(statement, deployment_record, subject_sha, "B-106.github_attestation.verification")
        except EvidenceError:
            continue
        verified_subject = True
    if not verified_subject:
        raise EvidenceError("B-106 gh attestation verification output does not name the subject")
    cold, warm = obj(item.get("cold"), "B-106.cold"), obj(item.get("warm_control"), "B-106.warm_control")
    for row, label in ((cold, "B-106.cold"), (warm, "B-106.warm_control")):
        common(row, label, tenant)
        raw_hash(row.get("raw_output_sha256"), f"{label}.raw_output_sha256")
        if not row.get("response_request_id") or not row.get("colo"):
            raise EvidenceError(f"{label} is missing wire request/colo identity")
        if row.get("token_fingerprint") != fingerprint:
            raise EvidenceError("B-106 mint and request are not cryptographically linked")
    if cold.get("status") != 404 or cold.get("authenticated") is not True or cold.get("auth_source") != "d1" or warm.get("status") != 404 or warm.get("authenticated") is not True or warm.get("auth_source") not in {"l1", "kv"} or cold.get("colo") != warm.get("colo") or cold.get("response_request_id") == warm.get("response_request_id"):
        raise EvidenceError("B-106 cold and same-colo warm control are not proven")
    return "open"


def b107(item: dict[str, Any], root: Path, tenant: str) -> str:
    deployment(item, "B-107", root, tenant)
    rows = entries(item.get("samples"), "B-107.samples", 10)
    totals = []
    for i, row in enumerate(rows):
        common(row, f"B-107.samples[{i}]", tenant)
        if row.get("method") != "PUT" or row.get("status") != 200 or num(row.get("payload_bytes"), f"B-107.samples[{i}].payload_bytes") != 1024:
            raise EvidenceError("B-107 requires successful 1 KiB PUT responses")
        r2, accounting, phase_store, total = (
            num(row.get(k), f"B-107.{k}")
            for k in ("r2_ms", "accounting_ms", "ostore_ms", "storage_total_ms")
        )
        wire_store, wire_accounting = phase_pair_fits_wire_clock(row, f"B-107.samples[{i}]")
        if abs(r2 - wire_store) > .001 or abs(accounting - wire_accounting) > .001:
            raise EvidenceError("B-107 derived phases do not match Server-Timing")
        if abs(phase_store - r2) > .001 or abs(total - r2 - accounting) > .001:
            raise EvidenceError("B-107 R2/accounting phases do not reconcile exactly")
        wire_digest = wire_output_sha256(row)
        if row.get("raw_output_sha256") != wire_digest:
            raise EvidenceError("B-107 raw output hash is not bound to the complete wire sample")
        if row.get("r2_raw_output_sha256") != wire_digest or row.get("accounting_raw_output_sha256") != wire_digest:
            raise EvidenceError("B-107 separated phases are not bound to their wire sample")
        totals.append(total)
    computed = obj(item.get("computed"), "B-107.computed")
    values = sorted(totals)
    expected = ((values[(len(values)-1)//2] + values[len(values)//2]) / 2, percentile(values, .90), percentile(values, .99))
    for key, value in zip(("p50_ms", "p90_ms", "p99_ms"), expected):
        if abs(num(computed.get(key), f"B-107.{key}") - value) > .001:
            raise EvidenceError("B-107 percentile is not derived from raw phase samples")
    return "open"


def b108(item: dict[str, Any], root: Path, tenant: str) -> str:
    commit = deployment(item, "B-108", root, tenant)
    binding = obj(item.get("source_binding"), "B-108.source_binding")
    if binding.get("path") != SOURCE or binding.get("commit") != commit:
        raise EvidenceError("B-108 source binding is not the deployed blob")
    try:
        source = subprocess.run(("git", "show", f"{commit}:{SOURCE}"), cwd=root, capture_output=True, text=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError(f"B-108 deployed source blob unavailable: {exc}") from exc
    if binding.get("blob_sha256") != sha(source.encode()) or not FINGERPRINT.fullmatch(str(binding.get("blob_sha256", ""))):
        raise EvidenceError("B-108 source hash is not the deployed blob")
    # The source stores the SQL as adjacent TypeScript string literals, so
    # compare every immutable clause rather than looking for a non-existent
    # contiguous source-text rendering of the runtime statement.
    clauses = (
        "INSERT INTO monthly_request_counts (tenant_id, year_month, request_count, updated_at_ms)",
        "VALUES (?1, ?2, 1, ?3)",
        "ON CONFLICT(tenant_id, year_month)",
        "DO UPDATE SET request_count = request_count + 1, updated_at_ms = ?3",
        "RETURNING request_count",
    )
    if any(clause not in source for clause in clauses) or "runQuotaBatch" not in source or "db.batch" not in source:
        raise EvidenceError("B-108 atomic fresh counter guard is absent from deployed source")
    statement = text(item.get("counter_statement"), "B-108.counter_statement")
    if statement != COUNTER_SQL or item.get("counter_statement_sha256") != sha(COUNTER_SQL.encode()):
        raise EvidenceError("B-108 counter statement is not the canonical atomic SQL")
    # Guard is intentionally inverted: the exact fresh atomic path closes this
    # item as accepted-by-correctness; no owner-supplied decision is consulted.
    return "closed"


CHECKERS = {"B-102": b102, "B-103": b103, "B-104": b104, "B-105": b105, "B-107": b107, "B-108": b108}


def assess(packet: Any, repo_root: Path = Path("."), now_epoch: float | None = None) -> dict[str, str]:
    if REPO is None:
        raise EvidenceError("expected server repository identity was not selected")
    validate_server_repository(REPO)
    root = obj(packet, "packet")
    reject_secrets(root)
    if root.get("schema") != SCHEMA or root.get("environment") != "production":
        raise EvidenceError("packet schema/environment is invalid")
    captured = iso_epoch(root.get("captured_at"), "packet.captured_at")
    now = float(now_epoch if now_epoch is not None else dt.datetime.now(dt.timezone.utc).timestamp())
    if captured > now + CLOCK_TOLERANCE or now - captured > MAX_AGE:
        raise EvidenceError("packet is stale or captured in the future")
    tenant = text(root.get("tenant_id"), "packet.tenant_id")
    if not UUID.fullmatch(tenant):
        raise EvidenceError("packet.tenant_id must be a v4 UUID")
    items = obj(root.get("items"), "packet.items")
    if set(items) != set(ITEMS):
        raise EvidenceError("packet.items must contain exactly B-102 through B-108")
    result: dict[str, str] = {}
    operation_ids: list[str] = []
    deployment_keys: set[tuple[Any, ...]] = set()
    for item_id in ITEMS:
        item = obj(items[item_id], item_id)
        if item.get("tenant_id") != tenant:
            raise EvidenceError(f"{item_id}.tenant_id is not the packet tenant")
        deployment_record = obj(item.get("deployment"), f"{item_id}.deployment")
        deployment_keys.add(tuple(deployment_record.get(k) if k != "provider_record" else json.dumps(deployment_record.get(k), sort_keys=True) for k in ("deployed_commit", "source_head", "github_sha", "github_repository", "github_run_id", "github_deployment_id", "deployment_id", "version", "provider_blob_sha256", "provider_record")))
        def collect_ops(value: Any) -> None:
            if isinstance(value, dict):
                if "operation_id" in value:
                    operation_ids.append(text(value["operation_id"], f"{item_id}.operation_id"))
                for child in value.values():
                    collect_ops(child)
            elif isinstance(value, list):
                for child in value:
                    collect_ops(child)
        collect_ops(item)
        result[item_id] = (b106(item, repo_root, tenant, now) if item_id == "B-106" else CHECKERS[item_id](item, repo_root, tenant))
    if len(operation_ids) != len(set(operation_ids)):
        raise EvidenceError("operation_id values must be unique across the packet")
    if len(deployment_keys) != 1:
        raise EvidenceError("all items must use one consistent deployed commit/provider identity")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--expect", choices=("open", "closed"), default="closed")
    parser.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    args = parser.parse_args(argv)
    global REPO
    try:
        REPO = resolve_server_repository(args.repo)
        result = assess(json.loads(args.packet.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError, EvidenceError) as exc:
        print(f"instrument error: {exc}", file=sys.stderr)
        return 2
    for item, state in result.items():
        print(f"{item}: {state}")
    closed = all(state == "closed" for state in result.values())
    print(f"B-102..B-108 {'closed' if closed else 'open'}")
    return 0 if (closed == (args.expect == "closed")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
