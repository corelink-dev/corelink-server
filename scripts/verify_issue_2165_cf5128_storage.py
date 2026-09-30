"""Validate a redacted, read-only Cloudflare storage inventory receipt.

This helper is intentionally offline. It never opens provider credentials or
contacts Cloudflare; its two environment inputs are public target metadata.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


SCHEMA = "corelink-issue-2165-cf5128-storage-v1"
ACCOUNT_ALIAS = "cf5128"
PRODUCTION_ALIAS = "prod6a"
PRODUCTION_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
ENVIRONMENT = "b083-kms-lifecycle"
D1_BINDING = "B083_D1"
R2_BINDING = "B083_R2"
R2_REGION = "auto"


class ContractError(ValueError):
    """Input failed a fail-closed inventory contract check."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"JSON input {path} must be an object")
    return value


def _reject_secret_material(value: Any, path: str = "$") -> None:
    """Reject secret-bearing fields without ever echoing their values."""
    forbidden = {"secret", "secret_access_key", "access_key", "token", "password", "authorization", "credential", "credentials"}
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in forbidden or any(part in normalized for part in ("secret", "credential", "password", "token")):
                raise ContractError(f"secret-bearing field is forbidden at {path}.{key}")
            _reject_secret_material(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secret_material(nested, f"{path}[{index}]")


def _contains_prod_alias(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_prod_alias(key) or _contains_prod_alias(nested) for key, nested in value.items())
    if isinstance(value, list):
        return any(_contains_prod_alias(nested) for nested in value)
    return isinstance(value, str) and value.casefold() == PRODUCTION_ALIAS


def verify(manifest: dict[str, Any], receipt: dict[str, Any], environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate manifest and receipt; return a metadata-only summary."""
    env = os.environ if environ is None else environ
    _reject_secret_material(manifest)
    _reject_secret_material(receipt)
    if _contains_prod_alias(manifest) or _contains_prod_alias(receipt):
        raise ContractError("production Cloudflare account alias is forbidden")

    if manifest.get("schema") != SCHEMA or receipt.get("schema") != SCHEMA:
        raise ContractError(f"both documents must use schema {SCHEMA}")
    if manifest.get("environment") != ENVIRONMENT or receipt.get("environment") != ENVIRONMENT:
        raise ContractError(f"both documents must target protected environment {ENVIRONMENT}")

    if manifest.get("account_alias") != ACCOUNT_ALIAS or receipt.get("account_alias") != ACCOUNT_ALIAS:
        raise ContractError("manifest and receipt must be labeled cf5128")
    account_id = manifest.get("account_id")
    if not isinstance(account_id, str) or not account_id or account_id != receipt.get("account_id"):
        raise ContractError("manifest and receipt account metadata must match")
    if account_id == PRODUCTION_ACCOUNT_ID or env.get("B083_CF_ACCOUNT_ID") != account_id:
        raise ContractError("B083_CF_ACCOUNT_ID must match the isolated manifest account")
    if account_id == PRODUCTION_ALIAS:
        raise ContractError("production account marker is forbidden")

    d1 = manifest.get("d1")
    r2 = manifest.get("r2")
    if not isinstance(d1, dict) or not isinstance(r2, dict):
        raise ContractError("manifest must include D1 and R2 target objects")
    database_id = d1.get("database_id")
    endpoint = r2.get("endpoint")
    if not database_id or not isinstance(database_id, str):
        raise ContractError("D1 database_id is required")
    if not endpoint or not isinstance(endpoint, str):
        raise ContractError("R2 endpoint is required")
    if env.get("B083_D1_DATABASE_ID") != database_id:
        raise ContractError("B083_D1_DATABASE_ID does not match the redacted D1 target")
    if env.get("B083_R2_S3_ENDPOINT") != endpoint:
        raise ContractError("B083_R2_S3_ENDPOINT does not match the redacted R2 target")
    if d1.get("binding") != D1_BINDING or not isinstance(d1.get("region"), str) or not d1["region"].strip():
        raise ContractError(f"D1 binding/region metadata must identify {D1_BINDING} and a location")
    if r2.get("binding") != R2_BINDING or r2.get("region") != R2_REGION:
        raise ContractError(f"R2 binding/region must be {R2_BINDING}/{R2_REGION}")
    if endpoint != f"https://{account_id}.r2.cloudflarestorage.com":
        raise ContractError("R2 endpoint does not bind the manifest account metadata")

    audit = manifest.get("audit_sink")
    if not isinstance(audit, dict) or audit.get("durable") is not True or not all(
        isinstance(audit.get(key), str) and audit[key].strip() for key in ("kind", "target_id")
    ):
        raise ContractError("a durable audit_sink with kind and target_id is required")
    bucket = r2.get("bucket")
    if not isinstance(bucket, str) or not bucket.strip():
        raise ContractError("R2 bucket name is required")

    tenants = manifest.get("disposable_tenants")
    if not isinstance(tenants, list) or len(tenants) != 2 or any(not isinstance(t, str) or not t.strip() for t in tenants):
        raise ContractError("exactly two named disposable tenants are required")
    if len(set(tenants)) != 2:
        raise ContractError("disposable tenant identifiers must be distinct")

    if receipt.get("read_only") is not True:
        raise ContractError("receipt must attest read_only=true for provider inventory")
    if receipt.get("inventory_method") != "cloudflare-native-http-read-only":
        raise ContractError("receipt must identify native HTTP read-only inventory")
    targets = receipt.get("targets")
    if not isinstance(targets, dict):
        raise ContractError("receipt targets object is required")
    if (
        targets.get("d1_database_id") != database_id
        or targets.get("d1_binding") != D1_BINDING
        or targets.get("d1_region") != d1["region"]
        or env.get("B083_D1_REGION") != d1["region"]
        or targets.get("r2_endpoint") != endpoint
        or targets.get("r2_binding") != R2_BINDING
        or targets.get("r2_region") != r2["region"]
        or targets.get("r2_bucket") != bucket
    ):
        raise ContractError("receipt D1/R2 inventory targets do not match manifest")
    if targets.get("audit_sink_target_id") != audit["target_id"]:
        raise ContractError("receipt audit sink does not match manifest")
    if receipt.get("tenant_aliases") != tenants:
        raise ContractError("receipt tenant plan must match both disposable tenant aliases")
    phase = receipt.get("phase")
    if phase not in {"preflight", "postcleanup"}:
        raise ContractError("receipt phase must be preflight or postcleanup")
    cleanup_complete = False
    if phase == "preflight":
        if receipt.get("provider_writes") is not False or "cleanup" in receipt or "lifecycle" in receipt:
            raise ContractError("preflight must contain no provider writes, lifecycle, or cleanup claim")
    else:
        lifecycle = receipt.get("lifecycle")
        cleanup = receipt.get("cleanup")
        remaining = cleanup.get("remaining_resources") if isinstance(cleanup, dict) else None
        if receipt.get("provider_writes") is not True:
            raise ContractError("postcleanup must attest lifecycle provider writes")
        if not isinstance(lifecycle, dict) or lifecycle.get("tenant_create_count") != 2 or lifecycle.get("tenant_cleanup_count") != 2 or lifecycle.get("audit_records_durable") is not True:
            raise ContractError("postcleanup must attest both tenant lifecycles and durable audit records")
        if not isinstance(cleanup, dict) or cleanup.get("complete") is not True or type(remaining) is not int or remaining != 0:
            raise ContractError("postcleanup must attest complete cleanup and zero remaining resources")
        cleanup_complete = True

    return {
        "schema": SCHEMA,
        "environment": ENVIRONMENT,
        "tenant_count": 2,
        "audit_sink_durable": True,
        "read_only_inventory": True,
        "phase": phase,
        "cleanup_complete": cleanup_complete,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="redacted target manifest JSON")
    parser.add_argument("--receipt", required=True, type=Path, help="redacted read-only inventory receipt JSON")
    args = parser.parse_args(argv)
    try:
        summary = verify(_read_json(args.manifest), _read_json(args.receipt))
    except ContractError as exc:
        parser.error(str(exc))
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
