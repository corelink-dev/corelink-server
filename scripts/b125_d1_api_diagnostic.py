#!/usr/bin/env python3
"""Make one fixed, read-only D1 API diagnostic and retain only safe metadata."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

QUERY_ID = "hourly"
EXPECTED_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
EXPECTED_DATABASE_ID = "d64742ea-e102-40b2-a844-ff02e3f94562"
QUERY_SHA256 = "b94e4288df40054bf23f70e24d5ceecebee94ef1f0422fe373731dd279fe280a"
MAX_RESPONSE_BYTES = 65536
TIMEOUT_SECONDS = 45
ALLOWED_ROOT_KEYS = {"errors", "messages", "result", "success"}
ALLOWED_ERROR_KEYS = {"code", "message", "documentation_url", "source"}
ALLOWED_CATEGORIES = {
    "syntax", "missing_table", "missing_column", "bind_mismatch",
    "unsupported_function", "memory_limit", "query_timeout", "auth_error",
    "http_error", "transport_timeout", "transport_error", "query_succeeded", "unknown",
}
_CATEGORY_PATTERNS = (
    ("syntax", r"\bsyntax error\b|\bnear\s+.{1,100}?:\s+syntax error\b"),
    ("missing_table", r"\bno such table\b|\btable .{1,100}? does not exist\b"),
    ("missing_column", r"\bno such column\b|\bcolumn .{1,100}? does not exist\b"),
    ("bind_mismatch", r"\b(?:binding|bind) (?:parameter )?.{0,40}\b(?:mismatch|missing|not supplied|not found)\b|\bincorrect number of bindings\b|\bparameter count mismatch\b"),
    ("unsupported_function", r"\bno such function\b|\bfunction .{1,100}? (?:not supported|not allowed|unsupported)\b"),
    ("memory_limit", r"\bout of memory\b|\bmemory limit exceeded\b|\bsqlite_nomem\b"),
    ("query_timeout", r"\bquery (?:execution )?timed out\b|\bexecution timeout\b|\bmaximum execution time\b|\bexceeded (?:the )?maximum (?:query )?(?:duration|execution time)\b"),
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _safe_shape(document: object) -> dict[str, object]:
    if not isinstance(document, dict):
        return {
            "root_kind": "object_other",
            "root_keys": [],
            "error_count": 0,
            "message_count": 0,
        }
    raw_errors = document.get("errors")
    raw_messages = document.get("messages")
    errors = raw_errors if isinstance(raw_errors, list) else []
    messages = raw_messages if isinstance(raw_messages, list) else []
    first = errors[0] if errors else None
    return {
        "root_kind": "object",
        "root_keys": sorted(set(document) & ALLOWED_ROOT_KEYS),
        "error_count": min(len(errors), 1000),
        "message_count": min(len(messages), 1000),
        "error_entry_kind": (
            "object" if isinstance(first, dict) else ("none" if first is None else "other")
        ),
        "error_entry_keys": (
            sorted(set(first) & ALLOWED_ERROR_KEYS) if isinstance(first, dict) else []
        ),
    }


def _error_strings(document: object) -> list[str]:
    """Read only documented D1 error/message strings in memory."""
    if not isinstance(document, dict):
        return []
    found: list[str] = []
    entries = document.get("errors")
    if isinstance(entries, list):
        for entry in entries[:1000]:
            if isinstance(entry, dict):
                message = entry.get("message")
                if isinstance(message, str):
                    found.append(message[:8192])
    return found


def _category(status: int, document: object, transport_timeout: bool = False) -> str:
    if transport_timeout:
        return "transport_timeout"
    if status == 599:
        return "transport_error"
    if status in (401, 403):
        return "auth_error"
    text = "\n".join(_error_strings(document)).casefold()
    for category, pattern in _CATEGORY_PATTERNS:
        if re.search(pattern, text):
            return category
    if status < 200 or status >= 300:
        return "http_error"
    if isinstance(document, dict) and document.get("success") is True and not document.get("errors"):
        return "query_succeeded"
    return "unknown"


def classify_response(status: int, raw_body: bytes, *, transport_timeout: bool = False) -> dict[str, object]:
    """Convert an API response to a receipt-safe enum and schema shape."""
    bounded = raw_body[:MAX_RESPONSE_BYTES]
    truncated = len(raw_body) > MAX_RESPONSE_BYTES
    try:
        document: object = json.loads(bounded.decode("utf-8"))
        response_format = "json"
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        document = None
        response_format = "non_json"
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ValueError("HTTP status is invalid")
    provider_code = None
    if isinstance(document, dict):
        errors = document.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            code = errors[0].get("code")
            if isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 999999:
                provider_code = str(code)
    return {
        "http_status_class": (
            "2xx" if 200 <= status < 300 else
            "3xx" if 300 <= status < 400 else
            "4xx" if 400 <= status < 500 else "5xx"
        ),
        "response_format": response_format,
        "response_truncated": truncated,
        "provider_code": provider_code,
        "semantic_error_category": _category(status, document, transport_timeout),
        "schema_shape": _safe_shape(document),
    }


def request_once(account_id: str, database_id: str, sql: str, token: str) -> tuple[int, bytes, bool]:
    """POST one fixed SQL statement; never follow redirects or retry."""
    if account_id != EXPECTED_ACCOUNT_ID or not re.fullmatch(r"[0-9a-f]{32}", account_id):
        raise ValueError("account identity is invalid")
    database_id_format = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    if database_id != EXPECTED_DATABASE_ID or not re.fullmatch(database_id_format, database_id):
        raise ValueError("database identity is invalid")
    if not token:
        raise ValueError("API token is missing")
    if hashlib.sha256(sql.encode("utf-8")).hexdigest() != QUERY_SHA256:
        raise ValueError("hourly SQL is not the frozen allowlisted statement")
    if ";" in sql or not re.match(r"^\s*WITH\b", sql, re.IGNORECASE):
        raise ValueError("hourly SQL is not one read-only statement")
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{database_id}/query"
    body = json.dumps({"sql": sql}, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            return response.status, raw, False
    except HTTPError as error:
        try:
            return error.code, error.read(MAX_RESPONSE_BYTES + 1), False
        except (TimeoutError, socket.timeout):
            return 599, b"", True
        except OSError:
            return 599, b"", False
    except (TimeoutError, socket.timeout):
        return 599, b"", True
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            return 599, b"", True
        return 599, b"", False
    except OSError:
        return 599, b"", False


def record_diagnostic(receipt_path: Path, account_id: str, database_id: str, sql: str, token: str) -> None:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["provider_queries_started"] = [QUERY_ID]
    reasons = receipt.setdefault("failure_reasons", [])
    if not isinstance(reasons, list):
        raise ValueError("receipt failure reasons are invalid")
    receipt["failure_reasons"] = [
        reason for reason in reasons if reason != "read_not_started"
    ]
    receipt["diagnostic_only"] = True
    receipt["valid"] = False
    reasons = receipt["failure_reasons"]
    if "diagnostic_only_capture_not_closure_evidence" not in reasons:
        reasons.append("diagnostic_only_capture_not_closure_evidence")
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    status, raw_body, timed_out = request_once(account_id, database_id, sql, token)
    result = classify_response(status, raw_body, transport_timeout=timed_out)
    if result["semantic_error_category"] not in ALLOWED_CATEGORIES:
        raise ValueError("diagnostic category is not allowlisted")
    receipt["provider_diagnostic"] = result
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: b125_d1_api_diagnostic.py RECEIPT ACCOUNT_ID DATABASE_ID SQL")
    record_diagnostic(
        Path(sys.argv[1]),
        sys.argv[2],
        sys.argv[3],
        sys.argv[4],
        os.environ.get("CF_API_TOKEN", ""),
    )
