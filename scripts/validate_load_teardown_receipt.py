#!/usr/bin/env python3
"""Validate a canonical, redacted exact-run staging teardown receipt."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

# Kept for the existing bounded endurance consumer.  The #2584 exact-run route
# emits STAGING_SCHEMA; accepting the older receipt here avoids changing a load
# workflow outside this issue's ownership map.
SCHEMA = "corelink.load-test-teardown-receipt.v1"
STAGING_SCHEMA = "corelink.staging-load-test-teardown-receipt.v2"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
RESOURCE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
REQUIRED_RESOURCE_CLASSES = frozenset({"cas_reference", "webhook_inbox", "webhook_effect", "dsr_artifact", "dsr_obligation", "audit_evidence", "billing_audit", "signup_artifact", "byok_artifact"})
RETAINED_RESOURCE_CLASSES = frozenset({"cas_reference", "dsr_obligation", "audit_evidence", "billing_audit"})
REQUIRED_FIELDS = {"schema", "run_id", "scenario", "target_deployment_sha", "terminal_state", "resources", "cross_run_deletions"}
FORBIDDEN_REDACTION_TERMS = frozenset({"opaque_handle", "handle", "token", "secret", "credential", "nonce", "tenant"})

class TeardownReceiptError(ValueError):
    """The endpoint did not prove complete, exact run-scoped deletion."""

def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TeardownReceiptError("receipt contains a duplicate JSON key")
        result[key] = value
    return result

def parse_receipt(text: str) -> object:
    return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)

def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TeardownReceiptError(f"{field} must be a nonnegative integer")
    return value

def _reject_sensitive_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or any(term in key.lower() for term in FORBIDDEN_REDACTION_TERMS):
                raise TeardownReceiptError("receipt contains a non-redacted field")
            _reject_sensitive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_keys(nested)

def validate(receipt: object, *, run_id: str, scenario: str, deployment_sha: str) -> dict[str, object]:
    if not RUN_ID_RE.fullmatch(run_id):
        raise TeardownReceiptError("expected run id must be canonical positive decimal text")
    if not SHA_RE.fullmatch(deployment_sha):
        raise TeardownReceiptError("expected deployment SHA must be a full lowercase commit SHA")
    if isinstance(receipt, dict) and receipt.get("schema") == SCHEMA:
        return _validate_legacy_receipt(receipt, run_id=run_id, scenario=scenario, deployment_sha=deployment_sha)
    if not isinstance(receipt, dict) or set(receipt) != REQUIRED_FIELDS:
        raise TeardownReceiptError("receipt fields are not the exact required set")
    _reject_sensitive_keys(receipt)
    if receipt["schema"] != STAGING_SCHEMA:
        raise TeardownReceiptError("unsupported teardown receipt schema")
    if receipt["run_id"] != run_id or receipt["scenario"] != scenario:
        raise TeardownReceiptError("receipt identity does not match this authenticated run")
    if receipt["target_deployment_sha"] != deployment_sha:
        raise TeardownReceiptError("receipt deployment SHA does not match the validated target")
    if receipt["terminal_state"] != "reconciled":
        raise TeardownReceiptError("receipt does not attest a reconciled terminal state")
    if _count(receipt["cross_run_deletions"], "cross_run_deletions") != 0:
        raise TeardownReceiptError("receipt reports a cross-run deletion")
    resources = receipt["resources"]
    if not isinstance(resources, dict) or set(resources) != REQUIRED_RESOURCE_CLASSES:
        raise TeardownReceiptError("receipt must enumerate the exact nine migration-0147 classes")
    normalized: dict[str, dict[str, int]] = {}
    for resource, counts in resources.items():
        if not isinstance(resource, str) or not RESOURCE_RE.fullmatch(resource):
            raise TeardownReceiptError("resource names must be lowercase identifiers")
        expected = {"inventory", "attempted", "deleted", "preserved", "quarantined", "remaining"}
        if not isinstance(counts, dict) or set(counts) != expected:
            raise TeardownReceiptError(f"{resource} counts have an invalid shape")
        parsed = {field: _count(counts[field], f"{resource}.{field}") for field in expected}
        if resource in RETAINED_RESOURCE_CLASSES:
            if parsed["attempted"] != 0 or parsed["deleted"] != 0 or parsed["preserved"] != parsed["inventory"] or parsed["remaining"] != 0 or parsed["quarantined"] != 0:
                raise TeardownReceiptError(f"{resource} retained/shared state was not preserved")
        elif parsed["attempted"] != parsed["inventory"] or parsed["deleted"] != parsed["inventory"] or parsed["preserved"] != 0 or parsed["remaining"] != 0 or parsed["quarantined"] != 0:
            raise TeardownReceiptError(f"{resource} disposable state was not completely deleted")
        normalized[resource] = parsed
    return {"schema": STAGING_SCHEMA, "run_id": run_id, "scenario": scenario, "target_deployment_sha": deployment_sha, "terminal_state": "reconciled", "resources": normalized, "cross_run_deletions": 0}

def _validate_legacy_receipt(receipt: dict[str, object], *, run_id: str, scenario: str, deployment_sha: str) -> dict[str, object]:
    fields = {"schema", "run_id", "scenario", "target_deployment_sha", "inventory_complete", "resources", "cross_run_deletions"}
    classes = {"cas_objects", "webhook_idempotency_rows", "dsr_jobs", "audit_entries"}
    if set(receipt) != fields or receipt["run_id"] != run_id or receipt["scenario"] != scenario or receipt["target_deployment_sha"] != deployment_sha:
        raise TeardownReceiptError("legacy receipt identity does not match this run")
    if receipt["inventory_complete"] is not True or _count(receipt["cross_run_deletions"], "cross_run_deletions") != 0:
        raise TeardownReceiptError("legacy receipt is incomplete")
    resources = receipt["resources"]
    if not isinstance(resources, dict) or set(resources) != classes:
        raise TeardownReceiptError("legacy receipt has an invalid resource census")
    normalized: dict[str, dict[str, int]] = {}
    for name, counts in resources.items():
        if not isinstance(counts, dict) or set(counts) != {"inventory", "attempted", "deleted", "remaining"}:
            raise TeardownReceiptError("legacy receipt has invalid counts")
        parsed = {field: _count(counts[field], f"{name}.{field}") for field in counts}
        if parsed["attempted"] != parsed["inventory"] or parsed["deleted"] != parsed["inventory"] or parsed["remaining"] != 0:
            raise TeardownReceiptError("legacy receipt is not reconciled")
        normalized[name] = parsed
    return {"schema": SCHEMA, "run_id": run_id, "scenario": scenario, "target_deployment_sha": deployment_sha, "inventory_complete": True, "resources": normalized, "cross_run_deletions": 0}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--deployment-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = parse_receipt(args.receipt.read_text(encoding="utf-8"))
        validated = validate(receipt, run_id=args.run_id, scenario=args.scenario, deployment_sha=args.deployment_sha)
    except (OSError, json.JSONDecodeError, TeardownReceiptError) as exc:
        print(f"::error::teardown receipt rejected: {exc}")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(validated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("teardown receipt accepted: exact identity and all nine classes reconciled")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
