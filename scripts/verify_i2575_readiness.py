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
        or runtime.get("schedule_restored_empty") is not True
        or runtime.get("tail_deleted") is not True
    ):
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
