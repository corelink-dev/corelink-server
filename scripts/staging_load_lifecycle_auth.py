#!/usr/bin/env python3
"""Mint redacted v1 staging lifecycle credentials for seal and teardown."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import time

MAX_LIFETIME_MS = 15 * 60 * 1_000
DEFAULT_LIFETIME_MS = 60_000
GOLDEN_KEY = "01234567890123456789012345678901"
GOLDEN_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
GOLDEN_SHA = "a" * 40
GOLDEN_V1 = "v1.123.cas.staging." + GOLDEN_SHA + ".100.200." + GOLDEN_NONCE + ".70fa88c64030477e8acbee233efb48d2f8996f98ae8983a8ea5a705b39fdea8c"
GOLDEN_V2 = "v2.123.cas.staging." + GOLDEN_SHA + ".100.200." + GOLDEN_NONCE + ".4e2eac1b4406894df9d64b59ef5ad2446ab0ab707425280f37fb207ca8eb0ab0"
RESOURCE_CLASSES = (
    "audit_evidence",
    "billing_audit",
    "byok_artifact",
    "cas_reference",
    "dsr_artifact",
    "dsr_obligation",
    "signup_artifact",
    "webhook_effect",
    "webhook_inbox",
)
SEAL_RECEIPT_KEYS = {
    "schema",
    "run_id",
    "scenario",
    "target_deployment_sha",
    "state",
    "resources",
}


def _canonical(version: str, run_id: str, scenario: str, sha: str, issued: int, expires: int, nonce: str) -> str:
    if version not in {"v1", "v2"}:
        raise ValueError("unsupported admission version")
    if not run_id.isdigit() or run_id.startswith("0") or len(run_id) > 20:
        raise ValueError("run id is not canonical")
    if scenario not in {"signup", "webhook", "dsr", "cas", "byok", "endurance-2h"}:
        raise ValueError("scenario is not allowlisted")
    if len(sha) != 40 or any(char not in "0123456789abcdef" for char in sha):
        raise ValueError("deployment SHA is not canonical")
    if not (0 <= issued < expires and expires - issued <= MAX_LIFETIME_MS):
        raise ValueError("lifetime is invalid")
    if len(nonce) != 64 or any(char not in "0123456789abcdef" for char in nonce):
        raise ValueError("nonce is not 256-bit lowercase hex")
    return f"{version}.{run_id}.{scenario}.staging.{sha}.{issued}.{expires}.{nonce}"


def mint(version: str, key: str, run_id: str, scenario: str, sha: str, *, issued: int | None = None, nonce: str | None = None, lifetime_ms: int = DEFAULT_LIFETIME_MS) -> str:
    if len(key.encode()) < 32:
        raise ValueError("admission key is too short")
    issued = int(time.time() * 1_000) if issued is None else issued
    payload = _canonical(version, run_id, scenario, sha, issued, issued + lifetime_ms, nonce or secrets.token_hex(32))
    domain = f"corelink/staging-load-admission-auth/{version}\0".encode()
    tag = hmac.new(key.encode(), domain + payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{tag}"


def validate_seal_receipt(receipt_path: str, run_id: str, scenario: str, sha: str) -> None:
    """Accept only the frozen, bounded, canonical nine-class seal receipt."""
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        receipt: dict[str, object] = {}
        for key, value in pairs:
            if key in receipt:
                raise ValueError("seal receipt contains a duplicate JSON key")
            receipt[key] = value
        return receipt

    with open(receipt_path, encoding="utf-8") as stream:
        receipt = json.load(stream, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(receipt, dict):
        raise ValueError("seal receipt must be an object")
    if set(receipt) != SEAL_RECEIPT_KEYS:
        raise ValueError("seal receipt top-level keys are invalid")
    identity = (receipt.get("schema"), receipt.get("run_id"), receipt.get("scenario"), receipt.get("target_deployment_sha"), receipt.get("state"))
    if identity != ("corelink.staging-load-test-seal-receipt.v1", run_id, scenario, sha, "sealed"):
        raise ValueError("seal receipt identity is invalid")
    resources = receipt.get("resources")
    if not isinstance(resources, dict) or tuple(resources) != RESOURCE_CLASSES:
        raise ValueError("seal receipt resource classes or order are invalid")
    if any(type(count) is not int or count < 0 for count in resources.values()):
        raise ValueError("seal receipt counts are invalid")
    if sum(resources.values()) > 256:
        raise ValueError("seal receipt exceeds the 256-resource cap")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-seal", action="store_true")
    parser.add_argument("--receipt")
    parser.add_argument("--version", choices=("v1", "v2"))
    parser.add_argument("--key")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--deployment-sha", required=True)
    args = parser.parse_args(argv)
    if args.validate_seal:
        if not args.receipt:
            parser.error("--validate-seal requires --receipt")
        validate_seal_receipt(args.receipt, args.run_id, args.scenario, args.deployment_sha)
        return 0
    if not args.version or not args.key:
        parser.error("minting requires --version and --key")
    print(mint(args.version, args.key, args.run_id, args.scenario, args.deployment_sha))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
