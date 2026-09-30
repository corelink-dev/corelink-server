#!/usr/bin/env python3
"""Archive source-validated B-083 lifecycle receipts to exact R2 objects.

The parent R2 key is used only to mint a short-lived, one-object credential.
The object is never overwritten, and audit references are emitted only after
an authenticated HEAD and GET confirm the exact uploaded bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import verify_b083_kms_lifecycle_evidence as lifecycle


REQUIRED_STEPS = lifecycle.LIFECYCLE_STEPS
SOURCE_STEPS = REQUIRED_STEPS - {"audit_receipts"}
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVENT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
PARENT_ID = "B083_R2_AUDIT_PARENT_ACCESS_KEY_ID"
PARENT_SECRET = "B083_R2_AUDIT_PARENT_SECRET_ACCESS_KEY"


class ArchiveError(ValueError):
    """Input or authenticated archive operation failed closed."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt_credentials(account: str, endpoint: str, bucket: str, key: str | list[str],
                     parent_id: str, parent_secret: str, *, now: int | None = None,
                     ttl: int = 900) -> dict[str, str]:
    if not 1 <= ttl <= 900:
        raise ArchiveError("temporary credential TTL must be between 1 and 900 seconds")
    if not parent_id or not parent_secret:
        raise ArchiveError("protected parent R2 audit key pair is required")
    host = urlparse(endpoint).netloc
    if not host or urlparse(endpoint).scheme != "https":
        raise ArchiveError("R2 endpoint must be HTTPS")
    issued = int(time.time()) if now is None else now
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "bucket": bucket,
        "scope": "object-read-write",
        "actions": ["PutObject", "GetObject", "HeadObject"],
        "paths": {"prefixPaths": [], "objectPaths": key if isinstance(key, list) else [key]},
        "sub": account,
        "iss": parent_id,
        "aud": host,
        "iat": issued,
        "exp": issued + ttl,
    }
    unsigned = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = hmac.new(parent_secret.encode(), unsigned.encode(), hashlib.sha256).digest()
    jwt = f"{unsigned}.{_b64url(signature)}"
    return {
        "access_key_id": parent_id,
        "secret_access_key": hashlib.sha256(jwt.encode()).hexdigest(),
        "session_token": base64.b64encode(("jwt/" + jwt).encode()).decode("ascii"),
    }


def _load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ArchiveError("input must be a regular non-symlink file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("input JSON is unreadable or invalid") from exc


def _protected_manifest(path: Path, env: dict[str, str]) -> dict[str, Any]:
    runner_temp = env.get("RUNNER_TEMP", "")
    if not runner_temp or path.resolve().parent != Path(runner_temp).resolve():
        raise ArchiveError("protected manifest must reside directly under RUNNER_TEMP")
    if not env.get("B083_TARGET_MANIFEST_SECRET_ARN"):
        raise ArchiveError("protected target manifest provenance is missing")
    if path.stat().st_mode & 0o077:
        raise ArchiveError("protected manifest permissions must exclude group and other access")
    value = _load_json(path)
    if not isinstance(value, dict):
        raise ArchiveError("protected manifest must be a JSON object")
    cloudflare = value.get("cloudflare")
    account = cloudflare.get("account_id") if isinstance(cloudflare, dict) else None
    r2 = cloudflare.get("r2") if isinstance(cloudflare, dict) else None
    sink = value.get("audit_sink")
    if not isinstance(cloudflare, dict) or not isinstance(sink, dict) or not isinstance(r2, dict):
        raise ArchiveError("manifest lacks bound R2 and audit sink targets")
    if cloudflare.get("account_alias") != "cf5128":
        raise ArchiveError("protected R2 manifest must identify isolated account cf5128")
    bucket = r2.get("bucket") or sink.get("r2_bucket")
    endpoint = r2.get("endpoint")
    run_id = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
        raise ArchiveError("GITHUB_RUN_ID must be a bounded opaque run identifier")
    expected_key = f"issue-2165/{run_id}/audit/receipts.ndjson"
    if sink.get("r2_archive_key") != expected_key:
        raise ArchiveError("manifest archive key must equal the exact protected per-run object key")
    if not isinstance(account, str) or account != env.get("B083_CF_ACCOUNT_ID"):
        raise ArchiveError("manifest account must match protected B083_CF_ACCOUNT_ID")
    if not isinstance(bucket, str) or not bucket or not isinstance(endpoint, str):
        raise ArchiveError("manifest R2 bucket and endpoint are required")
    if r2.get("binding", "B083_R2") != "B083_R2" or r2.get("region", "auto") != "auto":
        raise ArchiveError("manifest must bind B083_R2 in the auto region")
    if endpoint != env.get("B083_R2_S3_ENDPOINT") or endpoint != f"https://{account}.r2.cloudflarestorage.com":
        raise ArchiveError("manifest R2 endpoint must match the protected account-bound endpoint")
    if sink.get("r2_bucket", bucket) != bucket:
        raise ArchiveError("audit sink bucket differs from the bound R2 bucket")
    return {"account": account, "bucket": bucket, "endpoint": endpoint, "key": expected_key}


def validate_source_receipts(value: Any) -> list[dict[str, Any]]:
    """Validate the nine source-backed lifecycle receipts preceding archival."""
    if not isinstance(value, list) or len(value) != len(SOURCE_STEPS):
        raise ArchiveError("exactly nine source-validated pre-archive lifecycle receipts are required")
    expected_fields = {"step", "occurred_at_utc", "source"}
    sources: set[str] = set()
    steps: set[str] = set()
    result = []
    for row in value:
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise ArchiveError("each receipt must contain exactly step, occurred_at_utc, and source")
        step = row["step"]
        if not isinstance(step, str) or step not in SOURCE_STEPS or step in steps:
            raise ArchiveError("receipt steps must be the nine distinct pre-archive B-083 lifecycle labels")
        steps.add(step)
        if not isinstance(row["occurred_at_utc"], str) or not UTC.fullmatch(row["occurred_at_utc"]):
            raise ArchiveError("receipt timestamps must be UTC second-precision timestamps")
        try:
            datetime.strptime(row["occurred_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ArchiveError("receipt timestamp is not a valid UTC date-time") from exc
        source = row["source"]
        if not isinstance(source, dict) or set(source) != {"kind", "event_ref", "digest"}:
            raise ArchiveError("receipt source must contain exactly kind, event_ref, and digest")
        if not isinstance(source["kind"], str) or source["kind"] not in {"cloudtrail", "d1", "runtime", "r2"}:
            raise ArchiveError("receipt source kind is unsupported")
        if not isinstance(source["event_ref"], str) or not EVENT_REF.fullmatch(source["event_ref"]):
            raise ArchiveError("receipt requires a source-backed event reference")
        if re.search(r":sha256:[a-f0-9]{64}$", source["event_ref"]):
            raise ArchiveError("source event_ref cannot be only a local content hash")
        if not isinstance(source["digest"], str) or not SHA.fullmatch(source["digest"]):
            raise ArchiveError("receipt source digest must be lowercase SHA-256 hex")
        if source["event_ref"] in sources:
            raise ArchiveError("source event references must be unique")
        sources.add(source["event_ref"])
        result.append({"step": step, "occurred_at_utc": row["occurred_at_utc"], "source": dict(source)})
    if steps != SOURCE_STEPS:
        raise ArchiveError("all nine pre-archive B-083 lifecycle steps must have source receipts")
    return sorted(result, key=lambda item: item["step"])


def archive(manifest: dict[str, Any], receipts: Any, env: dict[str, str], *,
            s3_factory: Callable[..., Any], now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    """Perform exact-key create-only PUT, HEAD, GET; return refs after readback."""
    rows = validate_source_receipts(receipts)
    account, bucket, endpoint, key = (manifest[k] for k in ("account", "bucket", "endpoint", "key"))
    run_id = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id) or key != f"issue-2165/{run_id}/audit/receipts.ndjson":
        raise ArchiveError("archive target must be the exact protected per-run receipts object")
    source_key = f"issue-2165/{run_id}/audit/source-receipts.ndjson"
    parent_id, parent_secret = env.get(PARENT_ID, ""), env.get(PARENT_SECRET, "")
    creds = _jwt_credentials(account, endpoint, bucket, [source_key, key], parent_id, parent_secret)
    client = s3_factory(
        endpoint_url=endpoint,
        region_name="auto",
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        aws_session_token=creds["session_token"],
    )
    def ensure_absent(object_key: str) -> None:
        try:
            client.head_object(Bucket=bucket, Key=object_key)
        except Exception as exc:
            response = getattr(exc, "response", {})
            code = str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(response, dict) else None
            if code not in {"404", "NoSuchKey", "NotFound"} and status != 404:
                raise ArchiveError("could not prove an exact audit object is absent") from None
        else:
            raise ArchiveError("refusing to overwrite an existing audit object")

    def put_and_verify(object_key: str, body: bytes) -> str:
        expected = hashlib.sha256(body).hexdigest()
        try:
            client.put_object(Bucket=bucket, Key=object_key, Body=body, ContentType="application/x-ndjson", IfNoneMatch="*")
            head = client.head_object(Bucket=bucket, Key=object_key)
            readback = client.get_object(Bucket=bucket, Key=object_key)["Body"].read()
        except Exception:
            raise ArchiveError("R2 authenticated PUT/HEAD/GET failed") from None
        if head.get("ContentLength") != len(body) or readback != body or hashlib.sha256(readback).hexdigest() != expected:
            raise ArchiveError("R2 authenticated readback bytes or digest do not match the submitted archive")
        return expected

    ensure_absent(source_key)
    ensure_absent(key)
    source_body = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows)
    source_digest = put_and_verify(source_key, source_body)
    audit_row = {
        "step": "audit_receipts",
        "occurred_at_utc": now().astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "kind": "r2",
            "event_ref": f"{source_key}:sha256:{source_digest}",
            "digest": source_digest,
        },
    }
    rows.append(audit_row)
    rows.sort(key=lambda item: item["step"])
    body = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows)
    digest = put_and_verify(key, body)
    captured = now().astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in rows:
        suffix = hashlib.sha256((row["step"] + "\0" + row["source"]["event_ref"] + "\0" + digest).encode()).hexdigest()[:24]
        row["audit_uri"] = f"audit://{row['step']}/{suffix}"
    lifecycle_receipts = {
        row["step"]: {
            "status": "PASS",
            "receipt_reference": row["audit_uri"],
            "completed_at": captured if row["step"] == "audit_receipts" else row["occurred_at_utc"],
            "blocker": None,
        }
        for row in rows
    }
    return {
        "schema": "corelink.issue-2165-r2-audit-archive.v1",
        "captured_at": captured,
        "object_key": key,
        "object_sha256": f"sha256:{digest}",
        "source_object_key": source_key,
        "source_object_sha256": f"sha256:{source_digest}",
        "lifecycle": lifecycle_receipts,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path, help="protected, source-validated nine-step receipts JSON")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        env = dict(os.environ)
        target = _protected_manifest(args.manifest, env)
        runner_temp = Path(env["RUNNER_TEMP"]).resolve()
        if args.receipts.resolve().parent != runner_temp or args.receipts.stat().st_mode & 0o077:
            raise ArchiveError("source receipt JSON must be mode 0600 directly under RUNNER_TEMP")
        if args.output.resolve().parent != runner_temp:
            raise ArchiveError("archive result must be written directly under RUNNER_TEMP")
        rows = _load_json(args.receipts)
        validate_source_receipts(rows)  # reject incomplete sources before importing/creating any client
        import boto3
        result = archive(target, rows, env, s3_factory=boto3.client)
        _atomic_write(args.output, (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
        print("R2 audit archive: PASS")
        return 0
    except Exception as exc:
        print(f"R2 audit archive: FAIL: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
