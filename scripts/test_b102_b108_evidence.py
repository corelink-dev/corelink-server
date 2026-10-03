#!/usr/bin/env python3
"""Focused stdlib tests for every B-102..B-108 evidence contract and mutation."""

from __future__ import annotations

import copy
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import verify_b102_b108_evidence as verifier
import collect_b102_b107_measurements as collector
import collect_b102_b108_context as context_collector
verifier.REPO = verifier.SOURCE_REPO

ROOT = Path(__file__).parents[1]
NOW = 1_800_000_000.0
TENANT = "123e4567-e89b-42d3-a456-426614174000"
SHA = subprocess.run(("git", "rev-parse", "HEAD"), cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
ZERO64 = "a" * 64
RAW64 = "sha256:" + ZERO64


def deployment(op: str) -> dict:
    run_started_at = datetime.fromtimestamp(NOW - 300, timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "repository": verifier.REPO,
        "environment": "production",
        "deployed_commit": SHA,
        "source_head": SHA,
        "github_sha": SHA,
        "github_repository": verifier.REPO,
        "github_event": "workflow_dispatch",
        "github_run_id": "123456789",
        "github_run_attempt": "1",
        "github_run_started_at": run_started_at,
        "github_ref": "refs/heads/main",
        "github_deployment_id": "987654321",
        "provider_record": {"provider": "cloudflare", "environment": "production", "commit": SHA, "deployment_id": "deploy-123456"},
        "provider_blob_sha256": RAW64,
        "deployment_id": "deploy-123456",
        "version": SHA,
        "tenant_id": TENANT,
        "operation_id": op,
    }


def row(op: str, **kwargs) -> dict:
    return {"tenant_id": TENANT, "operation_id": op, **kwargs}


def github_attestation(attestation: dict, deployment_record: dict) -> dict:
    predicate = {
        "buildDefinition": {
            "buildType": verifier.GITHUB_WORKFLOW_BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "ref": deployment_record["github_ref"],
                    "repository": f"https://github.com/{verifier.REPO}",
                    "path": ".github/workflows/perf-production-evidence.yml",
                }
            },
            "resolvedDependencies": [{"digest": {"gitCommit": deployment_record["source_head"]}}],
        },
        "runDetails": {
            "metadata": {
                "invocationId": (
                    f"https://github.com/{verifier.REPO}/actions/runs/{deployment_record['github_run_id']}"
                    f"/attempts/{deployment_record['github_run_attempt']}"
                )
            }
        },
    }
    subject = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "b106-cold-attestation.json", "digest": {"sha256": verifier.sha(verifier.b106_subject_bytes(attestation, deployment_record))[len("sha256:") : ]}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }
    payload_bytes = json.dumps(subject, sort_keys=True, separators=(",", ":")).encode()
    payload = base64.b64encode(payload_bytes).decode()
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        # Deliberately non-verifying fixture: the real pinned gh verifier must
        # reject this fake signature/certificate/tlog material before the
        # structural mutation suite uses its monkeypatched verifier.
        "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": [{"sig": "ZmFrZQ=="}]},
        "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(b"fixture-certificate").decode()}, "timestampVerificationData": {"tlogEntries": [{"fixture": True}]}},
    }
    return {
        "subject_sha256": verifier.sha(verifier.b106_subject_bytes(attestation, deployment_record)),
        "subject_name": "b106-cold-attestation.json",
        "bundle_sha256": verifier.sha(verifier.canonical_json(bundle)),
        "bundle": bundle,
        "verification": [{"attestation": copy.deepcopy(bundle), "verificationResult": {"signature": {"certificate": {"sourceRepository": verifier.REPO, "certificateIssuer": "CN=fixture", "issuer": "https://token.actions.githubusercontent.com", "subjectAlternativeName": f"https://github.com/{verifier.REPO}/.github/workflows/perf-production-evidence.yml@refs/heads/main"}}, "verifiedTimestamps": [{"type": "tlog"}], "statement": subject}}],
        "verification_policy": {
            "repository": verifier.REPO,
            "signer_workflow": f"{verifier.REPO}/.github/workflows/perf-production-evidence.yml",
            "signer_digest": deployment_record["source_head"],
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
    }


def packet() -> dict:
    stamp = datetime.fromtimestamp(NOW - 10, timezone.utc).isoformat().replace("+00:00", "Z")
    deployments = {item: deployment(f"op-deploy-{item.lower()}") for item in verifier.ITEMS}
    req = [row(f"op-b102-{i:02d}", method="PUT", status=200, payload_bytes=1024, server_timing="auth;dur=1, ostore;dur=20, oaccounting;dur=10", elapsed_ms=40) for i in range(3)]
    for sample in req:
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
    runs = [row(f"op-b103-{i:02d}", concurrency=c, requests=c, successes=c, failures={}, wall_ms=1000 / (c / 4), throughput_rps=c / (1000 / (c / 4) / 1000), raw_output_sha256=RAW64) for i, c in enumerate((4, 16, 64))]
    samples104 = [row(f"op-b104-{i:02d}", method="GET", status=404, authenticated=True, auth_source="d1", colo="GRU", response_request_id=f"req-b104-{i:02d}", request_key=f"missing-{i}", elapsed_ms=20 + i, payload_sha256=RAW64) for i in range(10)]
    for sample in samples104:
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
    pairs = []
    for i in range(6):
        pairs.append({"tenant_id": TENANT, "operation_id": f"op-b105-{i:02d}", "control_first": i % 2 == 0,
                      "control": row(f"op-b105-c-{i:02d}", cache_mode="disabled", status="complete", revision=SHA, runner="corelink", machine="m1", toolchain="t1", command=["cargo", "test"], raw_output_sha256=RAW64, sccache_stats_raw_sha256=RAW64, duration_seconds=10, sccache={"hits": 0, "misses": 0, "read_errors": 0, "write_errors": 0}),
                      "treatment": row(f"op-b105-t-{i:02d}", cache_mode="enabled", status="complete", revision=SHA, runner="corelink", machine="m1", toolchain="t1", command=["cargo", "test"], raw_output_sha256=RAW64, sccache_stats_raw_sha256=RAW64, duration_seconds=5, sccache={"hits": 1, "misses": 0, "read_errors": 0, "write_errors": 0})})
    samples107 = [row(f"op-b107-{i:02d}", method="PUT", status=200, payload_bytes=1024, elapsed_ms=40, server_timing="ostore;dur=20, oaccounting;dur=10", r2_ms=20, accounting_ms=10, ostore_ms=20, storage_total_ms=30) for i in range(10)]
    for sample in samples107:
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
        sample["r2_raw_output_sha256"] = sample["raw_output_sha256"]
        sample["accounting_raw_output_sha256"] = sample["raw_output_sha256"]
    source = subprocess.run(("git", "show", f"{SHA}:{verifier.SOURCE}"), cwd=ROOT, capture_output=True, check=True).stdout
    blob = "sha256:" + hashlib.sha256(source).hexdigest()
    b108 = {"tenant_id": TENANT, "deployment": deployments["B-108"], "source_binding": {"path": verifier.SOURCE, "commit": SHA, "blob_sha256": blob}, "counter_statement": verifier.COUNTER_SQL, "counter_statement_sha256": "sha256:" + hashlib.sha256(verifier.COUNTER_SQL.encode()).hexdigest()}
    result = {"schema": verifier.SCHEMA, "environment": "production", "captured_at": stamp, "tenant_id": TENANT,
            "items": {
                "B-102": {"tenant_id": TENANT, "deployment": deployments["B-102"], "requests": req, "sequence_window_seconds": 10, "token_fingerprint": "sha256:" + ZERO64},
                "B-103": {"tenant_id": TENANT, "deployment": deployments["B-103"], "runs": runs},
                "B-104": {"tenant_id": TENANT, "deployment": deployments["B-104"], "samples": samples104, "computed": {"median_ms": 24.5, "p90_ms": 28.1}},
                "B-105": {"tenant_id": TENANT, "deployment": deployments["B-105"], "pairs": pairs},
                "B-106": {"tenant_id": TENANT, "deployment": deployments["B-106"], "kv_ttl_seconds": verifier.KV_PAT_ROW_TTL_SECONDS, "cold_attestation": row("op-b106-mint", mint_operation_id="op-b106-mint", minted_at_epoch=NOW - 130, unused_since_epoch=NOW - 120, observed_at_epoch=NOW - 59, mint_raw_output_sha256=RAW64, mint_response_sha256=RAW64, mint_response_binding_sha256=RAW64, mint_request_id="req-b106-mint", pat_id="pat-b106", token_id="tok-b106", expires_ms=(NOW + 300) * 1000, token_fingerprint="sha256:" + ZERO64, attestation_source={"kind": "github_actions_run", "workflow": "perf-production-evidence", "repository": verifier.REPO, "run_id": "123456789", "attempt": "1", "event": "workflow_dispatch", "ref": "refs/heads/main", "head_sha": SHA, "started_at": deployments["B-106"]["github_run_started_at"]}), "cold": row("op-b106-cold", status=404, authenticated=True, auth_source="d1", colo="GRU", response_request_id="req-b106-cold", auth_ms=40, raw_output_sha256=RAW64, token_fingerprint="sha256:" + ZERO64), "warm_control": row("op-b106-warm", status=404, authenticated=True, auth_source="kv", colo="GRU", response_request_id="req-b106-warm", auth_ms=40, raw_output_sha256=RAW64, token_fingerprint="sha256:" + ZERO64)},
                "B-107": {"tenant_id": TENANT, "deployment": deployments["B-107"], "samples": samples107, "computed": {"p50_ms": 30, "p90_ms": 30, "p99_ms": 30}},
                "B-108": b108,
            }}
    # Keep the fixture bound to the deployed runtime contract rather than a
    # duplicated TTL literal; the cold attestation remains independently
    # required to prove a 61-second idle interval below.
    result["items"]["B-106"]["kv_ttl_seconds"] = verifier.KV_PAT_ROW_TTL_SECONDS
    result["items"]["B-106"]["cold_attestation"]["mint_response_binding_sha256"] = verifier.mint_binding_sha256(result["items"]["B-106"]["cold_attestation"])
    result["items"]["B-106"]["github_attestation"] = github_attestation(
        result["items"]["B-106"]["cold_attestation"], result["items"]["B-106"]["deployment"]
    )
    return result


def expect_error(mutator, label: str) -> None:
    candidate = packet()
    mutator(candidate)
    try:
        verifier.assess(candidate, ROOT, NOW)
    except verifier.EvidenceError:
        return
    raise AssertionError(f"mutation was accepted: {label}")


class FakeResponse:
    def __init__(self, payload: bytes, status: int, headers: dict[str, str]):
        self._payload, self.status, self.headers = payload, status, headers

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._payload


def collector_wire_and_join_round_trip() -> None:
    """Exercise collector wire fields and the real collector→join→verifier path."""
    original_urlopen = collector.urlopen
    try:
        def fake_404(_request, **_kwargs):
            return FakeResponse(b"{}", 404, {"Server-Timing": 'auth;dur=3;desc="d1", total;dur=3', "X-Request-Id": "wire-404", "CF-Ray": "ray-GRU"})

        collector.urlopen = fake_404
        samples = [collector.call("https://example.invalid", TENANT, "pat", "GET", f"op-wire-b104-{i:02d}", f"missing-{i}") for i in range(10)]
        assert all(row["authenticated"] is True and row["auth_source"] == "d1" and row["colo"] == "GRU" for row in samples)
        values = sorted(row["elapsed_ms"] for row in samples)
        median = (values[4] + values[5]) / 2
        p90 = collector.percentile(values, .90)
        assert p90 == verifier.percentile(values, .90)
        evidence = packet()
        evidence["items"]["B-104"]["samples"] = samples
        evidence["items"]["B-104"]["computed"] = {"median_ms": median, "p90_ms": p90}
        live_now = time.time()
        trusted_started = datetime.fromtimestamp(live_now - 300, timezone.utc).isoformat().replace("+00:00", "Z")
        for evidence_item in evidence["items"].values():
            if isinstance(evidence_item, dict) and isinstance(evidence_item.get("deployment"), dict):
                evidence_item["deployment"]["github_run_started_at"] = trusted_started
        attestation = evidence["items"]["B-106"]["cold_attestation"]
        attestation.update(minted_at_epoch=live_now - 130, unused_since_epoch=live_now - 120, observed_at_epoch=live_now - 59)
        attestation["mint_response_binding_sha256"] = verifier.mint_binding_sha256(attestation)

        deployment_record = evidence["items"]["B-108"]["deployment"]
        context = {"schema": "corelink.performance-evidence.context.v1", "repository": verifier.REPO,
                   "environment": "production", "source_head": SHA, "github_event": "workflow_dispatch",
                   "github_run_id": "123456789", "github_run_attempt": "1", "github_run_started_at": deployment_record["github_run_started_at"], "github_ref": "refs/heads/main", "github_deployment_id": "987654321", "deployment_id": deployment_record["deployment_id"],
                   "provider": "cloudflare", "provider_commit": SHA, "provider_record": deployment_record["provider_record"],
                   "provider_blob_sha256": RAW64}
        measurements = {"tenant_id": TENANT, "items": {item: evidence["items"][item] for item in ("B-102", "B-103", "B-104", "B-106", "B-107")}}
        lane = {"schema": "corelink.b105-lane.v2", "pairs": evidence["items"]["B-105"]["pairs"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("context", context), ("measurements", measurements), ("b105", lane)):
                (root / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
            subject_path = root / "b106-cold-attestation.json"
            subprocess.run((sys.executable, str(ROOT / "scripts/build_b106_attestation_subject.py"), "--context", str(root / "context.json"), "--measurements", str(root / "measurements.json"), "--output", str(subject_path)), check=True, capture_output=True, text=True)
            subject = json.loads(subject_path.read_text(encoding="utf-8"))
            attestation_bundle = github_attestation(subject["cold_attestation"], deployment_record)
            bundle_path = root / "b106-attestation-bundle.json"
            bundle_path.write_text(json.dumps(attestation_bundle["bundle"], sort_keys=True, indent=2) + "\n", encoding="utf-8")
            verification_path = root / "b106-attestation-verification.json"
            verification_path.write_text(json.dumps(attestation_bundle["verification"], sort_keys=True, indent=2) + "\n", encoding="utf-8")
            output = root / "packet.json"
            subprocess.run((sys.executable, str(ROOT / "scripts/join_b102_b108_evidence.py"), "--context", str(root / "context.json"),
                            "--measurements", str(root / "measurements.json"), "--b105", str(root / "b105.json"),
                            "--b106-attestation-subject", str(subject_path), "--b106-attestation-bundle", str(bundle_path),
                            "--b106-attestation-verification", str(verification_path), "--root", str(ROOT), "--output", str(output)),
                           check=True, capture_output=True, text=True)
            joined = json.loads(output.read_text(encoding="utf-8"))
            result = verifier.assess(joined, ROOT)
            assert result["B-108"] == "closed" and all(result[item] == "open" for item in verifier.ITEMS[:-1])
    finally:
        collector.urlopen = original_urlopen


def mint_wire_binding_round_trip() -> None:
    original_urlopen = collector.urlopen
    try:
        payload = json.dumps({"token_plaintext": "opaque-token", "tenant": TENANT, "pat_id": "pat-b106", "token_id": "tok-b106", "expires_ms": (NOW + 300) * 1000}).encode()
        observed = {}

        def fake_mint(request, **_kwargs):
            observed["url"] = request.full_url
            observed["operation"] = request.headers["X-corelink-operation"]
            return FakeResponse(payload, 200, {"X-Request-Id": "mint-response-1"})

        collector.urlopen = fake_mint
        minted = collector.mint_fresh("https://example.invalid", TENANT, "session", "internal", "op-b106-mint")
        assert observed["url"].endswith("/v1/session/exchange") and observed["operation"] == "op-b106-mint"
        assert minted["mint_operation_id"] == "op-b106-mint" and minted["mint_request_id"] == "mint-response-1"
        assert minted["mint_response_sha256"].startswith("sha256:") and minted["mint_response_binding_sha256"].startswith("sha256:")
    finally:
        collector.urlopen = original_urlopen


def provider_record_boundary() -> None:
    records = list(context_collector.provider_records({"result": [{"id": "wrong-id", "commit": "other"}, {"id": "right-id", "commit": SHA}]}))
    assert (SHA, "right-id") in records and (SHA, "wrong-id") not in records


def workflow_run_timestamp_contract() -> None:
    """The authoritative run timestamp must use the pinned, isolated CLI."""
    workflow = (ROOT / ".github/workflows/perf-production-evidence.yml").read_text(encoding="utf-8")
    assert re.search(r"if: github\.repository_id == '[0-9]+' && github\.event_name == 'workflow_dispatch' && github\.ref == 'refs/heads/main' && github\.ref_protected", workflow)
    assert "${{ github.run_started_at }}" not in workflow
    assert "actions: read" in workflow
    assert "GITHUB_RUN_STARTED_AT: ${{ steps.github-run.outputs.started_at }}" in workflow
    start = workflow.index("      - name: Resolve GitHub run start timestamp")
    end = workflow.index("      - name: Build immutable run context", start)
    timestamp_step = workflow[start:end]
    assert "/usr/bin/env -i" in timestamp_step
    assert "GH_HOST=github.com" in timestamp_step
    assert "run_pinned_gh api" in timestamp_step
    assert 'repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}' in timestamp_step
    assert '--repo "${GITHUB_REPOSITORY}"' in workflow
    assert 'https://github.com/${GITHUB_REPOSITORY}/.github/workflows/perf-production-evidence.yml@${GITHUB_REF}' in workflow
    assert "\n          gh api" not in timestamp_step
    assert "HTTP_PROXY" not in timestamp_step and "SSL_CERT_FILE" not in timestamp_step
    verify_step = workflow[workflow.index("      - name: Verify canonical packet"):workflow.index("      - name: Publish verifier-backed owner handoff")]
    assert "CORELINK_EXPECTED_REPOSITORY: ${{ github.repository }}" in verify_step
    assert "GH_TOKEN" not in verify_step
    assert "CORELINK_GH_BIN" not in verify_step
    assert "GH_HOST" not in verify_step


def repository_identity_scope() -> None:
    """Source and destination are exact server identities; CLI/attacker names fail."""
    source = "HuGR-Labs/corelink-server"
    destination = "HuGR-dev/corelink-server"
    assert context_collector.is_server_repository(source)
    assert context_collector.is_server_repository(destination)
    assert not context_collector.is_server_repository("HuGR-Labs/corelink-cli")
    assert not context_collector.is_server_repository("attacker/corelink-server")
    try:
        verifier.validate_server_repository("attacker/corelink-server")
    except verifier.EvidenceError:
        pass
    else:
        raise AssertionError("attacker repository unexpectedly passed the evidence verifier")

    original_repo = verifier.REPO
    original_gh_verifier = verifier.verify_attestation_with_gh
    try:
        verifier.verify_attestation_with_gh = lambda _bundle, _subject, _deployment, expected: expected
        for expected_repo in (source, destination):
            verifier.REPO = expected_repo
            assert verifier.validate_server_repository(expected_repo) == expected_repo
            result = verifier.assess(packet(), ROOT, NOW)
            assert result["B-108"] == "closed"
            assert all(result[item] == "open" for item in verifier.ITEMS[:-1])

        verifier.REPO = "HuGR-Labs/corelink-cli"
        try:
            verifier.assess(packet(), ROOT, NOW)
        except verifier.EvidenceError:
            pass
        else:
            raise AssertionError("CLI identity unexpectedly passed the server evidence verifier")
    finally:
        verifier.REPO = original_repo
        verifier.verify_attestation_with_gh = original_gh_verifier


def main() -> int:
    try:
        verifier.assess(packet(), ROOT, NOW)
    except verifier.EvidenceError:
        pass
    else:
        raise AssertionError("fake fixture unexpectedly passed the pinned gh verifier")
    original_gh_verifier = verifier.verify_attestation_with_gh
    real_gh_root = tempfile.TemporaryDirectory(prefix="corelink-real-gh-test-")
    real_verifier = verifier.install_pinned_gh(Path(real_gh_root.name) / "gh")

    def expect_real_gh_error(mutator, label: str) -> None:
        candidate = packet()
        mutator(candidate)
        item = candidate["items"]["B-106"]
        attestation = item["github_attestation"]
        installer_calls = []

        def use_real_verifier(path: Path) -> Path:
            installer_calls.append(path)
            return real_verifier

        try:
            with patch.dict(os.environ, {"CORELINK_GH_BIN": str(Path(real_gh_root.name) / "attacker"), "PATH": str(Path(real_gh_root.name) / "attacker")}):
                with patch.object(verifier, "install_pinned_gh", side_effect=use_real_verifier):
                    original_gh_verifier(
                        attestation["bundle"],
                        verifier.b106_subject_bytes(item["cold_attestation"], item["deployment"]),
                        item["deployment"],
                        attestation["verification"],
                    )
        except verifier.EvidenceError:
            if len(installer_calls) != 1:
                raise AssertionError("CORELINK_GH_BIN selected the verifier instead of the pinned installer")
            return
        raise AssertionError(f"real gh verifier accepted mutation: {label}")

    verifier.verify_attestation_with_gh = lambda _bundle, _subject, _deployment, expected: expected
    result = verifier.assess(packet(), ROOT, NOW)
    assert result["B-108"] == "closed"
    assert all(result[item] == "open" for item in verifier.ITEMS[:-1])
    assert collector.storage_percentiles([
        {"storage_total_ms": value} for value in (10, 20, 30, 40, 50)
    ]) == {"p50_ms": 30.0, "p90_ms": 46.0, "p99_ms": 49.6}
    expect_error(lambda p: p.update(captured_at="1970-01-01T00:00:00Z"), "stale packet")
    expect_error(lambda p: p["items"]["B-102"]["requests"][0].update(tenant_id="223e4567-e89b-42d3-a456-426614174000"), "B102 tenant")
    expect_error(lambda p: p["items"]["B-102"]["deployment"].update(github_repository="HuGR/corelink-server"), "canonical repository")
    expect_error(lambda p: p["items"]["B-103"]["runs"][-1].update(throughput_rps=1), "B103 math/scaling")
    expect_error(lambda p: p["items"]["B-103"]["runs"][0].update(failures={"429": 1}), "B103 low-level failure")
    expect_error(lambda p: p["items"]["B-103"]["runs"][0].update(raw_output_sha256=ZERO64), "raw hash prefix")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].update(operation_id=""), "B104 operation")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].pop("auth_source"), "B104 auth source")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].pop("colo"), "B104 colo")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].pop("response_request_id"), "B104 response request identity")
    expect_error(lambda p: p["items"]["B-105"]["pairs"][0]["treatment"].update(cache_mode="disabled"), "B105 cache wiring")
    expect_error(lambda p: p["items"]["B-106"]["cold_attestation"].update(unused_since_epoch=NOW - 1), "B106 idle")
    def edited_attestation_timestamp_with_rebound_public_hash(p: dict) -> None:
        attestation = p["items"]["B-106"]["cold_attestation"]
        attestation["observed_at_epoch"] = NOW - 58
        attestation["mint_response_binding_sha256"] = verifier.mint_binding_sha256(attestation)
        rebound = github_attestation(attestation, p["items"]["B-106"]["deployment"])
        p["items"]["B-106"]["github_attestation"]["subject_sha256"] = rebound["subject_sha256"]
    expect_error(edited_attestation_timestamp_with_rebound_public_hash, "B106 timestamp rebound without valid attestation")
    def stale_mint(p: dict) -> None:
        attestation = p["items"]["B-106"]["cold_attestation"]
        attestation["minted_at_epoch"] = NOW - verifier.FRESH_MINT_MAX_AGE_SECONDS - 1
        attestation["mint_response_binding_sha256"] = verifier.mint_binding_sha256(attestation)
    expect_error(stale_mint, "B106 stale mint")
    expect_error(lambda p: p["items"]["B-106"].update(kv_ttl_seconds=60), "B106 runtime TTL")
    expect_error(lambda p: p["items"]["B-106"]["cold"].update(token_fingerprint="sha256:" + "b" * 64), "B106 token binding")
    expect_error(lambda p: p["items"]["B-106"]["cold_attestation"].update(mint_response_sha256="sha256:" + "b" * 64), "B106 response digest")
    expect_error(lambda p: p["items"]["B-106"]["cold_attestation"].update(mint_response_binding_sha256="sha256:" + "b" * 64), "B106 binding digest")
    expect_error(lambda p: p["items"]["B-106"]["cold_attestation"].update(mint_request_id="substituted-request"), "B106 request identity")
    def mismatched_attestation_source(p: dict) -> None:
        attestation = p["items"]["B-106"]["cold_attestation"]
        attestation["attestation_source"]["head_sha"] = "b" * 40
        attestation["mint_response_binding_sha256"] = verifier.mint_binding_sha256(attestation)
    expect_error(mismatched_attestation_source, "B106 trusted source correlation")
    expect_error(lambda p: p["items"]["B-106"]["cold"].pop("response_request_id"), "B106 wire request identity")
    expect_error(lambda p: p["items"]["B-105"]["pairs"].pop(), "B105 six pairs")
    expect_error(lambda p: p["items"]["B-107"]["samples"][0].update(status=500), "B107 status")
    expect_error(lambda p: p["items"]["B-107"]["samples"][0].update(storage_total_ms=31), "B107 phase math")
    def forged_b107_phase(p: dict) -> None:
        sample = p["items"]["B-107"]["samples"][0]
        sample["server_timing"] = "ostore;dur=21, oaccounting;dur=10"
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
        sample["r2_raw_output_sha256"] = sample["raw_output_sha256"]
        sample["accounting_raw_output_sha256"] = sample["raw_output_sha256"]
    expect_error(forged_b107_phase, "B107 wire phase binding")
    def overcounted_b107_wall(p: dict) -> None:
        sample = p["items"]["B-107"]["samples"][0]
        sample["elapsed_ms"] = 1
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
        sample["r2_raw_output_sha256"] = sample["raw_output_sha256"]
        sample["accounting_raw_output_sha256"] = sample["raw_output_sha256"]
    expect_error(overcounted_b107_wall, "B107 phase sum versus wall")
    def phases_hidden_inside_description(p: dict) -> None:
        sample = p["items"]["B-107"]["samples"][0]
        sample["server_timing"] = (
            'auth;dur=1;desc="ostore;dur=20, oaccounting;dur=10"'
        )
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
        sample["r2_raw_output_sha256"] = sample["raw_output_sha256"]
        sample["accounting_raw_output_sha256"] = sample["raw_output_sha256"]
    expect_error(phases_hidden_inside_description, "B107 description phase injection")
    def missing_b102_blocking_phases(p: dict) -> None:
        sample = p["items"]["B-102"]["requests"][0]
        sample["server_timing"] = "auth;dur=1"
        sample["raw_output_sha256"] = verifier.wire_output_sha256(sample)
    expect_error(missing_b102_blocking_phases, "B102 remediated phase population")
    expect_error(lambda p: p["items"]["B-108"]["source_binding"].update(blob_sha256="b" * 64), "B108 deployed blob")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].update(operation_id=p["items"]["B-104"]["samples"][1]["operation_id"]), "duplicate operation")
    expect_error(lambda p: p["items"]["B-104"].pop("computed"), "B104 derived percentiles")
    expect_error(lambda p: p["items"]["B-104"]["computed"].update(p90_ms=999), "B104 p90 recomputation")
    expect_error(lambda p: p["items"]["B-104"]["samples"][0].update(elapsed_ms=999), "B104 raw hash elapsed binding")
    def wrong_b105_revision(p: dict) -> None:
        for pair in p["items"]["B-105"]["pairs"]:
            pair["control"]["revision"] = pair["treatment"]["revision"] = "0" * 40
    expect_error(wrong_b105_revision, "B105 deployed SHA binding")
    def wrong_deployed_sha(p: dict) -> None:
        parent = subprocess.run(("git", "rev-parse", f"{SHA}^"), cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        for item in verifier.ITEMS:
            d = p["items"][item]["deployment"]
            d["deployed_commit"] = d["version"] = parent
            d["provider_record"]["commit"] = parent
        source = subprocess.run(("git", "show", f"{parent}:{verifier.SOURCE}"), cwd=ROOT, capture_output=True, check=True).stdout
        p["items"]["B-108"]["source_binding"].update(commit=parent, blob_sha256="sha256:" + hashlib.sha256(source).hexdigest())
    expect_error(wrong_deployed_sha, "exact deployed SHA")
    def wrong_attestation_san(p: dict) -> None:
        p["items"]["B-106"]["github_attestation"]["verification"][0]["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"] = f"https://github.com/{verifier.REPO}/.github/workflows/perf-production-evidence.yml@refs/heads/evil"
    expect_error(wrong_attestation_san, "exact signer workflow ref")
    def wrong_attestation_invocation(p: dict) -> None:
        p["items"]["B-106"]["github_attestation"]["verification"][0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = f"https://github.com/{verifier.REPO}/actions/runs/1/attempts/1"
    expect_error(wrong_attestation_invocation, "exact attested run")
    def wrong_attestation_subject_name(p: dict) -> None:
        attestation = p["items"]["B-106"]["github_attestation"]
        bundle = attestation["bundle"]
        subject = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        subject["subject"][0]["name"] = "other.json"
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(subject, sort_keys=True, separators=(",", ":")).encode()).decode()
        attestation["bundle_sha256"] = verifier.sha(verifier.canonical_json(bundle))
    expect_error(wrong_attestation_subject_name, "exact attested subject name")
    def forged_dsse_signature(p: dict) -> None:
        bundle = p["items"]["B-106"]["github_attestation"]["bundle"]
        forged = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
        forged[-1] ^= 1
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(forged).decode()
        p["items"]["B-106"]["github_attestation"]["bundle_sha256"] = verifier.sha(verifier.canonical_json(bundle))
    expect_real_gh_error(forged_dsse_signature, "DSSE signature/bundle linkage")
    def rebound_forged_dsse_signature(p: dict) -> None:
        attestation = p["items"]["B-106"]["github_attestation"]
        bundle = attestation["bundle"]
        forged = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
        forged[-1] ^= 1
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(forged).decode()
        attestation["verification"][0]["attestation"] = copy.deepcopy(bundle)
        attestation["bundle_sha256"] = verifier.sha(verifier.canonical_json(bundle))
    expect_real_gh_error(rebound_forged_dsse_signature, "rebound forged DSSE signature")
    expect_error(lambda p: p["items"]["B-105"].update(password="redacted"), "secret-shaped field")
    collector_wire_and_join_round_trip()
    mint_wire_binding_round_trip()
    provider_record_boundary()
    workflow_run_timestamp_contract()
    repository_identity_scope()
    verifier.verify_attestation_with_gh = original_gh_verifier
    print("B102-B108 evidence verifier mutations: PASS (fake bundle rejected by pinned gh gate)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
