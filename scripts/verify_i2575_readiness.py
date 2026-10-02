#!/usr/bin/env python3
"""Verify exact-SHA #1700 deployment and canonical endpoint readiness artifacts."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
HOST = "staging.corelink.humangr.com"
WORKER = "corelink-staging"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
DOMAIN_ID = re.compile(r"[0-9a-f]{32}", re.I)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
HTTP_ORIGIN = "https://corelink-staging.gmhelmold.workers.dev"
HTTP_NONCE = "issue-1700-recovery-20261002-v14"
HTTP_START_MS = 1790935200000
HTTP_LAST_ENTRY_MS = 1790942400000
HTTP_EXPIRES_MS = 1790946900000
HTTP_WRAPPER_KEYS = frozenset("contract carrier account_id worker_name workflow_sha worker_release container_image_digest probe_nonce origin http_proof receipt schedules_empty tails_empty".split())
HTTP_PROOF_KEYS = frozenset("contract carrier worker_release probe_nonce status rollback_safe native_receipt v8_cleanup v9_cleanup".split())
HTTP_NATIVE_FLAGS = frozenset("old_probe_retired old_probe_tables_absent v5_probe_retired v5_probe_tables_absent v4_probe_catalog_absent parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent".split())
HTTP_NATIVE_KEYS = HTTP_NATIVE_FLAGS | frozenset("contract probe_nonce outcome worker_release scheduled_time_ms old_probe_release v5_probe_release v5_prior_execution".split())
HTTP_CLEANUP_KEYS = frozenset("contract old_release old_nonce worker_release prior_execution prior_admission_present container_stopped alarm_absent tables_absent completed_at_ms".split())
HTTP_OLD_RELEASES = {
    "v8": "7d18bcfc450db97b1b987923050b92971da530a8",
    "v9": "5da497051f0b11dbfc8b87d1dfa8e753304e2719",
}


class ReadinessError(ValueError):
    pass


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("readiness evidence is missing or malformed") from exc


def validate_run(run: Any, *, expected_sha: str, workflow_path: str) -> None:
    if not isinstance(run, dict) or (
        run.get("path") != workflow_path
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != expected_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise ReadinessError("readiness run is not a successful exact-SHA protected workflow")


def _exact_keys(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _valid_http_native(value: Any, release: str) -> bool:
    if not _exact_keys(value, HTTP_NATIVE_KEYS):
        return False
    scheduled = value["scheduled_time_ms"]
    return (
        value["contract"] == "corelink-staging-d1-binding-runtime-v1"
        and value["probe_nonce"] == HTTP_NONCE and value["outcome"] == "pass"
        and value["worker_release"] == release
        and type(scheduled) is int and scheduled % 120_000 == 0
        and HTTP_START_MS <= scheduled <= HTTP_LAST_ENTRY_MS
        and value["old_probe_release"] == "0f785fb9b096afe01247f1057d46377b9f604f13"
        and value["v5_probe_release"] == "cc32b3d819181bf9175e795868f66212aa5456c1"
        and value["v5_prior_execution"] == "unknown"
        and all(value[key] is True for key in HTTP_NATIVE_FLAGS)
    )


def _validate_http_runtime(runtime: dict, release: str) -> None:
    """Read retained HTTP proof without claiming Scheduled/Tail execution.

    This consumer checks the immutable execution window, not the current clock:
    a protected successful run remains attributable after its window expires.
    """
    error = "authenticated HTTP runtime proof is incomplete or malformed"
    if (
        not _exact_keys(runtime, HTTP_WRAPPER_KEYS)
        or runtime["carrier"] != "authenticated_http"
        or runtime["origin"] != HTTP_ORIGIN or runtime["probe_nonce"] != HTTP_NONCE
        or runtime["schedules_empty"] is not True or runtime["tails_empty"] is not True
        or release in HTTP_OLD_RELEASES.values()
    ):
        raise ReadinessError(error)
    proof = runtime["http_proof"]
    if (
        not _exact_keys(proof, HTTP_PROOF_KEYS)
        or proof["contract"] != "corelink-staging-d1-http-proof-v1"
        or proof["carrier"] != "authenticated_http" or proof["worker_release"] != release
        or proof["probe_nonce"] != HTTP_NONCE or proof["status"] != "complete"
        or proof["rollback_safe"] is not True
        or not _valid_http_native(proof["native_receipt"], release)
        or not _valid_http_native(runtime["receipt"], release)
        or runtime["receipt"] != proof["native_receipt"]
    ):
        raise ReadinessError(error)
    scheduled = proof["native_receipt"]["scheduled_time_ms"]
    for version, old_release in HTTP_OLD_RELEASES.items():
        cleanup = proof[version + "_cleanup"]
        if not _exact_keys(cleanup, HTTP_CLEANUP_KEYS):
            raise ReadinessError(error)
        completed = cleanup["completed_at_ms"]
        if (
            cleanup["contract"] != f"corelink-staging-{version}-cleanup-v1"
            or cleanup["old_release"] != old_release
            or cleanup["old_nonce"] != "issue-1700-recovery-20261001-" + version
            or cleanup["worker_release"] != release or cleanup["prior_execution"] != "unknown"
            or type(cleanup["prior_admission_present"]) is not bool
            or any(cleanup[key] is not True for key in ("container_stopped", "alarm_absent", "tables_absent"))
            or type(completed) is not int or not scheduled <= completed < HTTP_EXPIRES_MS
        ):
            raise ReadinessError(error)


def validate_deployment_receipts(deployment: Any, runtime: Any, *, expected_sha: str) -> dict[str, str]:
    if not SHA.fullmatch(expected_sha):
        raise ReadinessError("expected source SHA is malformed")
    if not isinstance(deployment, dict) or not isinstance(runtime, dict):
        raise ReadinessError("deployment receipt is malformed")
    candidate_version = deployment.get("candidate_version_id")
    postflight = deployment.get("provider_postflight")
    if (
        deployment.get("rollout_state") != "candidate"
        or not isinstance(candidate_version, str)
        or not UUID.fullmatch(candidate_version)
        or not isinstance(postflight, dict)
        or postflight.get("verified") is not True
    ):
        raise ReadinessError("active Worker deployment readback does not match the protected target")
    image = runtime.get("container_image_digest")
    if (
        runtime.get("contract") != "corelink-staging-runtime-deployment-proof-v1"
        or runtime.get("account_id") != ACCOUNT_ID
        or runtime.get("worker_name") != WORKER
        or runtime.get("workflow_sha") != expected_sha
        or runtime.get("worker_release") != expected_sha
        or not isinstance(image, str)
        or not DIGEST.fullmatch(image)
    ):
        raise ReadinessError("active Container or Worker runtime readback is incomplete")
    # Any HTTP-specific field selects the strict branch, so partial/mixed proof
    # cannot fall back to the historical Scheduled/Tail receipt contract.
    if {"carrier", "origin", "http_proof", "schedules_empty", "tails_empty"} & runtime.keys():
        _validate_http_runtime(runtime, expected_sha)
    elif runtime.get("schedule_restored_empty") is not True or runtime.get("tail_deleted") is not True:
        raise ReadinessError("active Container or Worker runtime readback is incomplete")
    return {"worker_version_id": candidate_version, "image_digest": image}


def validate_protected_binding(binding: dict[str, str], *, worker_version: str, image_digest: str) -> None:
    if binding.get("worker_version_id") != worker_version or binding.get("image_digest") != image_digest:
        raise ReadinessError("protected Worker or Container binding differs from exact readback")


def validate_endpoint_receipt(receipt: Any) -> None:
    # The #1700 `already-exact` receipt intentionally omits account_id/zone_id.
    # Its exact workflow SHA is separately verified, and that pinned publisher
    # validates both against its fixed account/zone constants before writing the
    # receipt. Bind here through that run identity plus its emitted host/worker.
    if not isinstance(receipt, dict) or (
        receipt.get("mode") != "publish"
        or receipt.get("action") not in {"published-and-health-verified", "already-exact-health-verified"}
        or receipt.get("hostname") != HOST
        or receipt.get("worker") != WORKER
        or receipt.get("health_result") != "healthy"
        or receipt.get("runtime_secret_bindings_ready") is not True
        or receipt.get("canonical_route_count") != 0
        or receipt.get("custom_domain_count") != 1
        or not isinstance(receipt.get("custom_domain_id"), str)
        or not DOMAIN_ID.fullmatch(receipt["custom_domain_id"])
        or not isinstance(receipt.get("certificate_id"), str)
        or not UUID.fullmatch(receipt["certificate_id"])
        or receipt.get("dns_record_count") != 1
    ):
        raise ReadinessError("canonical endpoint receipt lacks exact healthy DNS/TLS/route evidence")


def single_json(directory: Path, filename: str) -> Any:
    path = directory / filename
    return _json(path)


def verify(args: argparse.Namespace) -> dict[str, str]:
    if not SHA.fullmatch(args.expected_sha):
        raise ReadinessError("expected source SHA is malformed")
    validate_run(_json(args.container_run), expected_sha=args.expected_sha,
                 workflow_path=".github/workflows/issue-1700-container-staging-deploy.yml")
    validate_run(_json(args.endpoint_run), expected_sha=args.expected_sha,
                 workflow_path=".github/workflows/issue-1700-staging-custom-domain.yml")
    deployment = single_json(args.container_receipt_dir, "staging-deploy-receipt.json")
    runtime = single_json(args.container_receipt_dir, "staging-runtime-probe-receipt.json")
    binding = validate_deployment_receipts(deployment, runtime, expected_sha=args.expected_sha)
    validate_endpoint_receipt(single_json(args.endpoint_receipt_dir, "staging-custom-domain-" + args.endpoint_run_id + ".json"))
    validate_protected_binding(binding, worker_version=args.expected_worker_version,
                               image_digest=args.expected_image_digest)
    return binding


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-run", type=Path, required=True)
    parser.add_argument("--endpoint-run", type=Path, required=True)
    parser.add_argument("--container-receipt-dir", type=Path, required=True)
    parser.add_argument("--endpoint-receipt-dir", type=Path, required=True)
    parser.add_argument("--endpoint-run-id", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-worker-version", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        binding = verify(args)
        args.output.write_text(json.dumps(binding, sort_keys=True) + "\n", encoding="utf-8")
    except ReadinessError as exc:
        print(f"#2575 readiness rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
