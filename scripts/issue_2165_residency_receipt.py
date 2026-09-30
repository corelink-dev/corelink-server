#!/usr/bin/env python3
"""Validate source-backed Issue #2165 residency evidence offline.

This program makes no provider calls. It accepts restricted provider readbacks,
checks their target bindings against the protected manifest, then publishes one
redacted residency row. Cloudflare D1's configured region is not treated as
proof of physical placement; an independent authoritative placement attestation
is required before a row can be emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "corelink-issue-2165-kms-runtime-v1"
INPUT_SCHEMA = "corelink.issue-2165-residency-input.v1"
OUTPUT_SCHEMA = "corelink.issue-2165-residency-receipt.v1"
ENVIRONMENT = "b083-kms-lifecycle"
SLOTS = ("tenant_a", "tenant_b")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


class ResidencyError(ValueError):
    """Evidence is incomplete, unbound, or does not prove residency."""


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResidencyError(f"{where} must be an object")
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResidencyError(f"{where} is missing")
    return value


def _utc(value: Any, where: str) -> str:
    raw = _text(value, where)
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResidencyError(f"{where} must be ISO-8601 UTC") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
        raise ResidencyError(f"{where} must be ISO-8601 UTC")
    return stamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _source(source: Any, name: str) -> dict[str, str]:
    obj = _obj(source, name)
    ref = _text(obj.get("provider_ref"), f"{name}.provider_ref")
    digest = _text(obj.get("raw_sha256"), f"{name}.raw_sha256")
    if not HEX64.fullmatch(digest):
        raise ResidencyError(f"{name}.raw_sha256 must be lowercase SHA-256")
    observed = _utc(obj.get("observed_at_utc"), f"{name}.observed_at_utc")
    if not re.fullmatch(r"[A-Za-z0-9:/._#=-]{1,512}", ref):
        raise ResidencyError(f"{name}.provider_ref is malformed")
    return {"provider_ref": ref, "raw_sha256": digest, "observed_at_utc": observed}


def validate(manifest: Any, bundle: Any, raw_evidence: Any) -> dict[str, Any]:
    """Validate restricted AWS/Cloudflare readbacks; return one redacted row.

    A metadata region is a target binding, not a physical-placement source.
    """
    m = _obj(manifest, "manifest")
    if m.get("schema") != MANIFEST_SCHEMA or m.get("environment") != ENVIRONMENT:
        raise ResidencyError("manifest is not the protected #2165 lifecycle target")
    aws = _obj(m.get("aws"), "manifest.aws")
    cf = _obj(m.get("cloudflare"), "manifest.cloudflare")
    d1 = _obj(cf.get("d1"), "manifest.cloudflare.d1")
    r2 = _obj(cf.get("r2"), "manifest.cloudflare.r2")
    tenant_ids = m.get("disposable_tenants")
    if not isinstance(tenant_ids, list) or len(tenant_ids) != 2 or len(set(tenant_ids)) != 2:
        raise ResidencyError("manifest must bind exactly two distinct disposable tenants")
    if cf.get("account_alias") != "cf5128" or d1.get("binding") != "B083_D1" or r2.get("binding") != "B083_R2":
        raise ResidencyError("Cloudflare D1/R2 bindings must be cf5128 B083_D1 and B083_R2")
    if r2.get("region") != "auto" or not isinstance(cf.get("r2_prefixes"), list):
        raise ResidencyError("manifest R2 region/prefix target is incomplete")

    b = _obj(bundle, "sources")
    if b.get("schema") != INPUT_SCHEMA:
        raise ResidencyError("source bundle schema is not the frozen residency input")
    raw = _obj(raw_evidence, "raw evidence")
    app = _obj(b.get("app"), "sources.app")
    app_src = _source(app.get("source"), "sources.app.source")
    if app.get("method") != "ecs-describe-tasks+describe-task-definition":
        raise ResidencyError("app source must be authenticated ECS task and task-definition readbacks")
    task = _obj(app.get("task"), "sources.app.task")
    taskdef = _obj(app.get("task_definition"), "sources.app.task_definition")
    expected_image = _text(aws.get("image_uri"), "manifest.aws.image_uri")
    if (task.get("last_status") != "RUNNING" or task.get("task_definition_arn") != aws.get("task_definition_arn")
            or task.get("cluster_arn") != aws.get("cluster_arn") or task.get("region") != aws.get("region")
            or taskdef.get("task_definition_arn") != aws.get("task_definition_arn")
            or taskdef.get("task_role_arn") != aws.get("runtime_role_arn")
            or taskdef.get("image_uri") != expected_image
            or not re.search(r"@sha256:[a-fA-F0-9]{64}$", expected_image)
            or task.get("image_digest") != expected_image.rsplit("@", 1)[1]):
        raise ResidencyError("running ECS task, immutable image digest, region, and runtime role must exactly match manifest")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}[a-f0-9]{0,32}", _text(task.get("availability_zone"), "app.task.availability_zone")):
        raise ResidencyError("ECS availability zone is malformed")

    d1src = _source(_obj(b.get("d1"), "sources.d1").get("source"), "sources.d1.source")
    d1e = _obj(b.get("d1"), "sources.d1")
    if (d1e.get("method") != "parameterized-select-post" or d1e.get("account_alias") != "cf5128"
            or d1e.get("account_id") != cf.get("account_id") or d1e.get("binding") != "B083_D1"
            or d1e.get("database_id") != d1.get("database_id") or d1e.get("region") != d1.get("region")
            or d1e.get("changed_db") is not False or d1e.get("rows_written") != 0 or d1e.get("changes") != 0):
        raise ResidencyError("D1 target must be an exact CF5128 zero-write SELECT readback")
    tenant_rows = d1e.get("tenant_rows")
    if not isinstance(tenant_rows, list) or len(tenant_rows) != 2:
        raise ResidencyError("D1 readback must contain exactly two tenant rows")
    if {row.get("tenant_id") for row in tenant_rows if isinstance(row, dict)} != set(tenant_ids):
        raise ResidencyError("D1 readback tenants do not match both protected disposable tenants")
    by_slot = {row.get("tenant_slot"): row for row in tenant_rows if isinstance(row, dict)}
    if set(by_slot) != set(SLOTS) or len({row.get("tenant_id") for row in by_slot.values()}) != 2:
        raise ResidencyError("D1 readback must bind distinct tenant_a and tenant_b slots")

    r2e = _obj(b.get("r2"), "sources.r2")
    r2src = _source(r2e.get("source"), "sources.r2.source")
    if (r2e.get("method") != "s3-list-objects-v2-read-only" or r2e.get("binding") != "B083_R2"
            or r2e.get("account_id") != cf.get("account_id") or r2e.get("endpoint") != r2.get("endpoint")
            or r2e.get("bucket") != r2.get("bucket") or r2e.get("region") != "auto"):
        raise ResidencyError("R2 readback must bind the exact CF5128 endpoint, bucket, region, and B083_R2 binding")
    expected_prefixes = {(p.get("tenant_id"), p.get("region"), p.get("prefix")) for p in cf["r2_prefixes"] if isinstance(p, dict)}
    observed_prefixes = {(p.get("tenant_id"), p.get("region"), p.get("prefix")) for p in r2e.get("prefix_inventory", []) if isinstance(p, dict)}
    if not expected_prefixes or observed_prefixes != expected_prefixes:
        raise ResidencyError("R2 inventory must read exactly the manifest tenant prefixes and regions")

    placement = b.get("d1_physical_placement")
    if not isinstance(placement, dict):
        raise ResidencyError("missing authoritative Cloudflare D1 physical-placement attestation; configured region metadata is insufficient")
    psrc = _source(placement.get("source"), "sources.d1_physical_placement.source")
    if (placement.get("authority") != "cloudflare-d1-placement-attestation" or placement.get("account_id") != cf.get("account_id")
            or placement.get("database_id") != d1.get("database_id") or placement.get("physical_region") != d1.get("region")
            or placement.get("scope") != "primary-and-replicas"):
        raise ResidencyError("D1 physical-placement attestation does not prove exact database primary and replicas in the bound region")
    for key, source in (("ecs", app_src), ("d1_select", d1src), ("d1_physical_placement", psrc), ("r2_inventory", r2src)):
        if key not in raw or hashlib.sha256(json.dumps(raw[key], sort_keys=True, separators=(",", ":")).encode()).hexdigest() != source["raw_sha256"]:
            raise ResidencyError(f"raw evidence digest does not match authenticated {key} readback")

    occurred = max(app_src["observed_at_utc"], d1src["observed_at_utc"], r2src["observed_at_utc"], psrc["observed_at_utc"])
    sources = {"ecs": app_src, "d1_select": d1src, "d1_physical_placement": psrc, "r2_inventory": r2src}
    redacted = {"schema": OUTPUT_SCHEMA, "rows": [{"step": "residency", "occurred_at_utc": occurred,
                 "source": {"kind": "provider-readbacks", "refs": {k: v["provider_ref"] for k, v in sources.items()},
                            "digest": hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
                 "targets": {"aws_region": aws.get("region"), "cf_alias": "cf5128", "d1_region": d1.get("region"), "r2_region": "auto",
                             "tenant_slots": list(SLOTS)}, "status": "verified"}]}
    return redacted


def _private_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ResidencyError(f"{label} must be a regular mode-0600 file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResidencyError(f"{label} is not readable JSON") from exc


def _write_private(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise ResidencyError("output must not already exist")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    path.chmod(0o600)


def _validate_environment_binding(manifest: Any, env: dict[str, str]) -> None:
    m = _obj(manifest, "manifest")
    aws = _obj(m.get("aws"), "manifest.aws")
    cf = _obj(m.get("cloudflare"), "manifest.cloudflare")
    d1 = _obj(cf.get("d1"), "manifest.cloudflare.d1")
    required = {
        "B083_AWS_ACCOUNT_ID": aws.get("account_id"),
        "B083_AWS_REGION": aws.get("region"),
        "B083_AWS_CLUSTER_ARN": aws.get("cluster_arn"),
        "B083_AWS_TASK_DEFINITION_ARN": aws.get("task_definition_arn"),
        "B083_AWS_RUNTIME_ROLE_ARN": aws.get("runtime_role_arn"),
        "B083_IMAGE_URI": aws.get("image_uri"),
        "B083_CF_ACCOUNT_ID": cf.get("account_id"),
        "B083_D1_DATABASE_ID": d1.get("database_id"),
        "B083_D1_REGION": d1.get("region"),
    }
    if any(not isinstance(value, str) or not value or env.get(name) != value for name, value in required.items()):
        raise ResidencyError("protected AWS/CF target variables do not exactly match manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--raw-evidence", required=True, type=Path, help="private raw provider response bundle retained for audit")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        runner_temp = os.environ.get("RUNNER_TEMP")
        paths = (args.manifest, args.sources, args.raw_evidence)
        if not runner_temp or any(path.resolve().parent != Path(runner_temp).resolve() for path in paths):
            raise ResidencyError("protected inputs must reside directly under RUNNER_TEMP")
        if args.output.resolve().parent != Path(runner_temp).resolve():
            raise ResidencyError("receipt output must be directly under RUNNER_TEMP")
        manifest = _private_json(args.manifest, "protected manifest")
        sources = _private_json(args.sources, "restricted source bundle")
        raw_evidence = _private_json(args.raw_evidence, "raw provider evidence")
        _validate_environment_binding(manifest, dict(os.environ))
        if args.output.exists() or args.output.is_symlink():
            raise ResidencyError("output must not already exist")
        _write_private(args.output, validate(manifest, sources, raw_evidence))
    except (ResidencyError, OSError) as exc:
        print(f"residency receipt: blocked ({exc})", file=sys.stderr)
        return 2
    print("residency receipt: verified")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
