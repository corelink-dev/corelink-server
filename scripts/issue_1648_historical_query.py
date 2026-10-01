#!/usr/bin/env python3
"""One fixed, read-only Workers Observability query for the #1648 cron window.

The API returns log events, which are treated as sensitive in memory. The only
persisted output is a fixed set of aggregate counters; event text and payload
hashes are never written or printed.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd"
WORKER = "corelink-signup-worker"
BASE = "https://api.cloudflare.com/client/v4"
QUERY_PATH = f"/accounts/{ACCOUNT}/workers/observability/telemetry/query"
START_MS = 1790798400000  # 2026-09-30T20:00:00Z
END_MS = 1790799300000  # 2026-09-30T20:15:00Z
TAG = "[audit-archive-cron]"
MAX_EVENTS = 100
MAX_RESPONSE_BYTES = 2_000_000
QUERY = {
    "queryId": "issue1648-run36766314363-readonly",
    "dry": True,
    "view": "events",
    "limit": MAX_EVENTS,
    "timeframe": {"from": START_MS, "to": END_MS},
    "parameters": {
        "filterCombination": "and",
        "filters": [
            {"key": "$metadata.service", "operation": "eq", "type": "string", "value": WORKER},
            {"key": "$metadata.message", "operation": "includes", "type": "string", "value": TAG},
        ],
    },
}
COUNTERS = (
    "event_count", "limit_reached", "object_events", "metadata_events",
    "worker_name_matches", "scheduled_events", "timestamps_in_window",
    "archive_tag_matches", "eligible_events", "counter_lines_parsed",
    "success_true", "status_200", "rows_sum", "chunks_sum",
    "failed_partitions_sum", "quarantined_rows_sum",
    "quarantined_partitions_sum", "incomplete_true", "quarantine_warning_events",
)
NUMERIC_FIELDS = (
    "status", "rows", "chunks", "failed_partitions", "quarantined_rows",
    "quarantined_partitions",
)
FIELD_RE = {key: re.compile(rf"(?:^|\s){key}=([0-9]+)(?:\s|$)") for key in NUMERIC_FIELDS}


def request() -> tuple[int, dict[str, Any]]:
    """Issue exactly one fixed POST; do not redirect, retry, or paginate."""
    if QUERY.get("dry") is not True or QUERY.get("limit") != MAX_EVENTS:
        raise ValueError("query_contract_changed")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    req = urllib.request.Request(
        BASE + QUERY_PATH,
        data=json.dumps(QUERY, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + os.environ["CF_API_TOKEN"],
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        response = urllib.request.build_opener(NoRedirect).open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response_bound")
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError("response_envelope")
        return response.status, body


def _event_counters(events: list[Any]) -> dict[str, int | bool]:
    out: dict[str, int | bool] = {key: 0 for key in COUNTERS}
    out["event_count"] = len(events)
    out["limit_reached"] = len(events) == MAX_EVENTS
    for event in events:
        if not isinstance(event, dict):
            continue
        out["object_events"] += 1
        metadata = event.get("$metadata")
        workers = event.get("$workers")
        if isinstance(metadata, dict) and isinstance(workers, dict):
            out["metadata_events"] += 1
        else:
            continue
        message = metadata.get("message")
        worker_matches = workers.get("scriptName") == WORKER
        scheduled = workers.get("eventType") in ("scheduled", "cron")
        timestamp = event.get("timestamp")
        in_window = type(timestamp) is int and START_MS <= timestamp < END_MS
        tag_matches = isinstance(message, str) and message.startswith(TAG)
        out["worker_name_matches"] += worker_matches
        out["scheduled_events"] += scheduled
        out["timestamps_in_window"] += in_window
        out["archive_tag_matches"] += tag_matches
        if not (worker_matches and scheduled and in_window and tag_matches):
            continue
        out["eligible_events"] += 1
        if message.startswith(TAG + " ok="):
            parsed: dict[str, int] = {}
            for key, pattern in FIELD_RE.items():
                match = pattern.search(message)
                if match is not None:
                    parsed[key] = int(match.group(1))
            required = {"status", "rows", "chunks", "failed_partitions", "quarantined_rows", "quarantined_partitions"}
            if required.issubset(parsed):
                out["counter_lines_parsed"] += 1
                out["status_200"] += parsed["status"] == 200
                for field, counter in (
                    ("rows", "rows_sum"), ("chunks", "chunks_sum"),
                    ("failed_partitions", "failed_partitions_sum"),
                    ("quarantined_rows", "quarantined_rows_sum"),
                    ("quarantined_partitions", "quarantined_partitions_sum"),
                ):
                    out[counter] += parsed[field]
                out["success_true"] += bool(re.search(r"(?:^|\s)ok=true(?:\s|$)", message))
                out["incomplete_true"] += bool(re.search(r"(?:^|\s)incomplete=true(?:\s|$)", message))
        if message.startswith(TAG + " QUARANTINED "):
            out["quarantine_warning_events"] += 1
    return out


def collect(call: Callable[[], tuple[int, dict[str, Any]]] = request) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "contract": "issue1648-historical-query-fixed-counters-v1",
        "run_id": "36766314363",
        "dry": True,
        "worker": WORKER,
        "timeframe_ms": {"from": START_MS, "to": END_MS},
        "limit": MAX_EVENTS,
        "new_runtime_proof": False,
        "classification": "unknown",
        "query_http": 0,
        "api_success": False,
        "error_count": 0,
        "response_bound_bytes": MAX_RESPONSE_BYTES,
        "counters": {key: 0 for key in COUNTERS},
    }
    try:
        status, body = call()
        receipt["query_http"] = status
        receipt["api_success"] = status == 200 and body.get("success") is True
        errors = body.get("errors")
        receipt["error_count"] = len(errors) if isinstance(errors, list) else 0
        if status != 200 or body.get("success") is not True:
            receipt["classification"] = "historical_query_forbidden" if status == 403 else (
                "historical_query_unauthorized" if status == 401 else "historical_query_rejected"
            )
            return receipt
        events = body.get("result", {}).get("events", {}).get("events")
        if not isinstance(events, list) or len(events) > MAX_EVENTS:
            receipt["classification"] = "historical_query_malformed_or_over_limit"
            return receipt
        receipt["counters"] = _event_counters(events)
        receipt["classification"] = (
            "matching_historical_events_observed"
            if receipt["counters"]["eligible_events"] else "no_matching_historical_events"
        )
    except Exception:
        # Exception text, source events, and provider error details are sensitive.
        receipt["classification"] = "bounded_query_error"
    return receipt


def main() -> int:
    expected = os.environ.get("EXPECTED_SHA", "")
    current = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", expected) or expected != current:
        raise SystemExit("exact workflow SHA required")
    receipt = collect()
    target = Path(os.environ["RUNNER_TEMP"]) / "issue-1648-historical-query.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    # stdout contains only the fixed aggregate receipt, never event content.
    print(json.dumps({"classification": receipt["classification"], "counters": receipt["counters"]}, sort_keys=True))
    return 0 if receipt["query_http"] == 200 and receipt["api_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
