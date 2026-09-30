#!/usr/bin/env python3
"""Reconcile one B-046 source run against CloudTrail logs covered by valid digests.

This tool deliberately accepts only log files named by a successful
``cloudtrail validate-logs --verbose`` response. It never queries CloudTrail
Lake and never mutates AWS resources.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path
from urllib.parse import urlparse


VALID_URI = re.compile(r"^Log file\s+(s3://[^\s]+)\s+valid$")
INVALID = re.compile(r"\b(?:INVALID|invalid)\b")
SUMMARY = re.compile(r"^(\d+)/(\d+) (digest|log) files valid$")
MAX_LOG_FILES = 64
MAX_LOG_BYTES = 64 * 1024 * 1024


class ReconcileError(ValueError):
    """Evidence does not establish the exact B-046 event pair."""


class PendingEvents(ReconcileError):
    """Valid logs are not yet delivered with both exact source events."""


def validated_log_uris(output: str) -> list[str]:
    """Return exact S3 log URIs only from a complete, all-valid response."""
    if INVALID.search(output):
        raise ReconcileError("CloudTrail validation reports an invalid file")
    summaries: dict[str, tuple[int, int]] = {}
    for line in output.splitlines():
        match = SUMMARY.fullmatch(line.strip())
        if match:
            valid, total = int(match.group(1)), int(match.group(2))
            kind = match.group(3)
            if kind in summaries:
                raise ReconcileError(f"duplicate CloudTrail {kind} summary")
            summaries[kind] = (valid, total)
    if set(summaries) != {"digest", "log"}:
        raise ReconcileError("CloudTrail digest/log summaries are incomplete")
    if any(total < 1 or valid != total for valid, total in summaries.values()):
        raise ReconcileError("CloudTrail digest/log chain is incomplete or invalid")
    uris: list[str] = []
    for line in output.splitlines():
        match = VALID_URI.fullmatch(line.strip())
        if match:
            uri = match.group(1)
            parsed = urlparse(uri)
            if (
                parsed.scheme != "s3" or not parsed.netloc or not parsed.path
                or "@" in parsed.netloc or ":" in parsed.netloc
                or parsed.query or parsed.fragment or "%" in parsed.path or "\\" in parsed.path
            ):
                raise ReconcileError("CloudTrail emitted a malformed valid-log URI")
            if uri not in uris:
                uris.append(uri)
    if not uris or len(uris) > MAX_LOG_FILES:
        raise ReconcileError("validated CloudTrail log URI count is outside the bound")
    if summaries["log"] != (len(uris), len(uris)):
        raise ReconcileError("CloudTrail log summary does not match the unique validated log URI manifest")
    return uris


def _load_records(path: Path) -> list[dict[str, object]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
        raise ReconcileError("downloaded log is not a bounded regular file")
    try:
        if path.suffix == ".gz":
            with path.open("rb") as compressed, gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
                raw = stream.read(MAX_LOG_BYTES + 1)
        else:
            with path.open("rb") as stream:
                raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise ReconcileError("decompressed CloudTrail log exceeds size bound")
        document = json.loads(raw)
    except (OSError, EOFError, gzip.BadGzipFile, json.JSONDecodeError, zlib.error) as exc:
        raise ReconcileError("validated CloudTrail log could not be parsed") from exc
    records = document.get("Records") if isinstance(document, dict) else None
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        raise ReconcileError("CloudTrail log has no valid Records array")
    return records


def _json_object(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReconcileError("CloudTrail event parameters are malformed") from exc
        if isinstance(decoded, dict):
            return decoded
    raise ReconcileError("CloudTrail event parameters are missing")


def reconcile_events(
    paths: list[Path], *, bucket: str, key: str, version: str,
    put_principal_arn: str, put_principal_session_arn: str,
    delete_principal_arn: str, delete_principal_session_arn: str,
    log_uris: list[str], log_bucket: str, log_prefix: str,
    expected_put_request_id: str, expected_delete_request_id: str, retention_expiry: str,
) -> dict[str, object]:
    """Require one exact PutObject and one exact-version denied DeleteObject."""
    if not paths or len(paths) > MAX_LOG_FILES:
        raise ReconcileError("downloaded log count is outside the bound")
    if len(paths) != len(log_uris) or bool(expected_put_request_id) != bool(expected_delete_request_id):
        raise ReconcileError("validated URI mapping or source request IDs are incomplete")
    for uri in log_uris:
        parsed = urlparse(uri)
        prefix = log_prefix.rstrip("/") + "/"
        if parsed.scheme != "s3" or parsed.netloc != log_bucket or not parsed.path.lstrip("/").startswith(prefix):
            raise ReconcileError("validated log URI is outside the pinned trail destination prefix")
    puts: list[dict[str, object]] = []
    deletes: list[dict[str, object]] = []
    contradictory_target_event = False
    hashes: list[str] = []
    put_uri_hashes: list[str] = []
    delete_uri_hashes: list[str] = []
    for path, uri in zip(paths, log_uris, strict=True):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
            raise ReconcileError("downloaded log is not a bounded regular file")
        hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
        for event in _load_records(path):
            if event.get("eventCategory") != "Data" or event.get("eventSource") != "s3.amazonaws.com":
                continue
            if event.get("eventName") not in ("PutObject", "DeleteObject"):
                continue
            request = _json_object(event.get("requestParameters"))
            if request.get("bucketName") != bucket or request.get("key") != key:
                continue
            name = event.get("eventName")
            identity = event.get("userIdentity")
            if not isinstance(identity, dict):
                contradictory_target_event = True
                continue
            session = identity.get("sessionContext")
            session_issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
            issuer_arn = session_issuer.get("arn") if isinstance(session_issuer, dict) else None
            expected_principal = put_principal_arn if name == "PutObject" else delete_principal_arn
            expected_session = put_principal_session_arn if name == "PutObject" else delete_principal_session_arn
            if issuer_arn != expected_principal or identity.get("arn") != expected_session:
                contradictory_target_event = True
                continue
            response = event.get("responseElements")
            response = response if isinstance(response, dict) else {}
            if name == "PutObject":
                if event.get("errorCode") is None and response.get("x-amz-version-id") == version:
                    puts.append(event)
                    put_uri_hashes.append(hashlib.sha256(uri.encode()).hexdigest())
                else:
                    contradictory_target_event = True
            elif name == "DeleteObject":
                if request.get("versionId") == version and event.get("errorCode") == "AccessDenied":
                    deletes.append(event)
                    delete_uri_hashes.append(hashlib.sha256(uri.encode()).hexdigest())
                else:
                    contradictory_target_event = True
    if len(puts) > 1 or len(deletes) > 1:
        raise ReconcileError("validated logs contain duplicate target PutObject or DeleteObject events")
    if not puts or not deletes:
        if contradictory_target_event:
            raise ReconcileError("delivered target event contradicts expected principal, version, or AccessDenied")
        raise PendingEvents("matching source events have not both reached validated trail logs")
    put, delete = puts[0], deletes[0]
    if not all(isinstance(event.get("eventID"), str) and event.get("eventID") for event in (put, delete)):
        raise ReconcileError("matching CloudTrail event ID is absent")
    if put["eventID"] == delete["eventID"]:
        raise ReconcileError("PutObject and DeleteObject unexpectedly share one event ID")
    put_request = put.get("requestID")
    delete_request = delete.get("requestID")
    if not isinstance(put_request, str) or not put_request or not isinstance(delete_request, str) or not delete_request:
        raise ReconcileError("matching CloudTrail request ID is absent")
    if expected_put_request_id and (put_request != expected_put_request_id or delete_request != expected_delete_request_id):
        raise ReconcileError("CloudTrail events do not match source-run request IDs")
    try:
        put_time = dt.datetime.fromisoformat(str(put.get("eventTime", "")).replace("Z", "+00:00"))
        delete_time = dt.datetime.fromisoformat(str(delete.get("eventTime", "")).replace("Z", "+00:00"))
        retain_until = dt.datetime.fromisoformat(retention_expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconcileError("CloudTrail event time or retention expiry is malformed") from exc
    if any(value.tzinfo is None or value.utcoffset() != dt.timedelta(0) for value in (put_time, delete_time, retain_until)):
        raise ReconcileError("CloudTrail event time and retention expiry must be UTC")
    if put_time > delete_time or delete_time >= retain_until:
        raise ReconcileError("CloudTrail delete denial is not after the put and before retention expiry")
    return {
        "put_event_id": put["eventID"],
        "put_request_id": put_request,
        "delete_event_id": delete["eventID"],
        "delete_request_id": delete_request,
        "put_event_time": put_time.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "delete_event_time": delete_time.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "validated_log_sha256": sorted(hashes),
        "put_validated_log_uri_sha256": put_uri_hashes[0],
        "delete_validated_log_uri_sha256": delete_uri_hashes[0],
        "events_share_validated_log": put_uri_hashes[0] == delete_uri_hashes[0],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation-output", type=Path, required=True)
    parser.add_argument("--logs-dir", type=Path, required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--put-principal-arn", required=True)
    parser.add_argument("--put-principal-session-arn", required=True)
    parser.add_argument("--delete-principal-arn", required=True)
    parser.add_argument("--delete-principal-session-arn", required=True)
    parser.add_argument("--log-uris", type=Path, required=True)
    parser.add_argument("--log-bucket", required=True)
    parser.add_argument("--log-prefix", required=True)
    parser.add_argument("--expected-put-request-id", default="")
    parser.add_argument("--expected-delete-request-id", default="")
    parser.add_argument("--retention-expiry", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        uris = validated_log_uris(args.validation_output.read_text(encoding="utf-8"))
        if args.log_uris.read_text(encoding="utf-8").splitlines() != uris:
            raise ReconcileError("downloaded URI manifest differs from validator output")
        paths = [args.logs_dir / f"{index:03d}.json.gz" for index in range(len(uris))]
        result = reconcile_events(paths, bucket=args.bucket, key=args.key,
                                  version=args.version,
                                  put_principal_arn=args.put_principal_arn,
                                  put_principal_session_arn=args.put_principal_session_arn,
                                  delete_principal_arn=args.delete_principal_arn,
                                  delete_principal_session_arn=args.delete_principal_session_arn,
                                  log_uris=uris, log_bucket=args.log_bucket, log_prefix=args.log_prefix,
                                  expected_put_request_id=args.expected_put_request_id,
                                  expected_delete_request_id=args.expected_delete_request_id,
                                  retention_expiry=args.retention_expiry)
        result["validated_log_uri_sha256"] = sorted(hashlib.sha256(uri.encode()).hexdigest() for uri in uris)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except PendingEvents as exc:
        print(f"B-046 trail reconciliation pending: {exc}", file=sys.stderr)
        return 2
    except (OSError, ReconcileError) as exc:
        raise SystemExit(f"B-046 trail reconciliation refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
