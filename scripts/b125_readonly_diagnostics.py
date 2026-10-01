#!/usr/bin/env python3
"""Record bounded, data-free diagnostics for a failed B-125 read."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

QUERY_IDS = {"population", "partition", "hourly", "latency", "heads", "burst", "integrity", "replay", "head_tail", "attribution"}
ERROR_CLASSES = {
    "D1_ERROR", "SQLITE_BUSY", "SQLITE_CONSTRAINT", "SQLITE_ERROR",
    "WRANGLER_ERROR", "HTTP_ERROR", "PROVIDER_ERROR", "UNKNOWN_ERROR",
}
PROVIDER_ERROR_CATEGORIES = {
    "syntax", "missing_table", "missing_column", "bind_mismatch",
    "unsupported_function", "memory_limit", "query_timeout", "unknown",
}
SCHEMA_KEYS = {
    "code", "data", "error", "errors", "meta", "message", "messages",
    "result", "results", "success", "status",
}
MAX_PROVIDER_OUTPUT_BYTES = 65536
MAX_ERROR_SCAN_NODES = 512
MAX_ERROR_SCAN_DEPTH = 16
PROVIDER_CODE = re.compile(r"^[0-9]{1,6}$")


def _kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "unknown"


def _shape(value: object) -> tuple[str, list[str], int]:
    if not isinstance(value, dict):
        return _kind(value), [], 0
    keys = {str(key) for key in value}
    return "object", sorted(keys & SCHEMA_KEYS), len(keys - SCHEMA_KEYS)


def _error_entry(document: object) -> object:
    """Accept both D1 `errors[]` and Wrangler's singular top-level `error`."""
    if not isinstance(document, dict):
        return None
    errors = document.get("errors")
    if isinstance(errors, list) and errors:
        return errors[0]
    if "error" in document:
        return document["error"]
    result = document.get("result")
    if isinstance(result, dict):
        errors = result.get("errors")
        if isinstance(errors, list) and errors:
            return errors[0]
        if "error" in result:
            return result["error"]
    return None


def _semantic_error_category(stdout: str, stderr: str) -> str:
    """Classify known provider wording without retaining any provider text."""
    message_text: list[str] = [stderr]
    try:
        document = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeError):
        document = None
    pending = [(_error_entry(document), 0)]
    visited = 0
    while pending and visited < MAX_ERROR_SCAN_NODES:
        value, depth = pending.pop()
        visited += 1
        if isinstance(value, str):
            message_text.append(value)
        elif depth < MAX_ERROR_SCAN_DEPTH and isinstance(value, dict):
            # Provider versions may put their message under an undocumented
            # field. Inspect nested values in memory, but emit only the fixed
            # category below; never retain field names or text.
            for child in value.values():
                if len(pending) + visited >= MAX_ERROR_SCAN_NODES:
                    break
                pending.append((child, depth + 1))
        elif depth < MAX_ERROR_SCAN_DEPTH and isinstance(value, list):
            for child in value:
                if len(pending) + visited >= MAX_ERROR_SCAN_NODES:
                    break
                pending.append((child, depth + 1))
    text = "\n".join(message_text).casefold()
    categories = (
        ("syntax", r"\bsyntax error\b|\bnear\s+.+?:\s+syntax error\b"),
        ("missing_table", r"\bno such table\b|\btable .+? does not exist\b"),
        ("missing_column", r"\bno such column\b|\bcolumn .+? does not exist\b"),
        ("bind_mismatch", r"\b(?:binding|bind) (?:parameter )?.{0,40}\b(?:mismatch|missing|not supplied|not found)\b|\bincorrect number of bindings\b|\bparameter count mismatch\b"),
        ("unsupported_function", r"\bno such function\b|\bfunction .+? (?:not supported|not allowed|unsupported)\b"),
        ("memory_limit", r"\bout of memory\b|\bmemory limit exceeded\b|\bsqlite_nomem\b"),
        ("query_timeout", r"\bquery (?:execution )?timed out\b|\bexecution timeout\b|\bmaximum execution time\b"),
    )
    for category, pattern in categories:
        if re.search(pattern, text):
            return category
    return "unknown"


def _schema(stdout: str, stdout_truncated: bool, stderr_truncated: bool) -> dict[str, object]:
    if not stdout.strip():
        document, fmt = None, "empty"
    else:
        try:
            document, fmt = json.loads(stdout), "json"
        except (json.JSONDecodeError, UnicodeError):
            document, fmt = None, "non_json"
    root = _shape(document)
    result = document.get("result") if isinstance(document, dict) else None
    if isinstance(document, list) and document:
        result = document[0]
    error = _error_entry(document)
    shaped = {"format": fmt, "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated}
    for name, value in (("root", document), ("result", result), ("error_entry", error)):
        kind, keys, unknown = root if name == "root" else _shape(value)
        shaped[f"{name}_kind"] = kind
        shaped[f"{name}_keys"] = keys
        shaped[f"{name}_unknown_key_count"] = unknown
    return shaped


def make_provider_diagnostic(
    query_id: str, exit_code: int, stdout: str, stderr: str,
    *, stdout_truncated: bool = False, stderr_truncated: bool = False,
) -> dict[str, object]:
    if (
        query_id not in QUERY_IDS
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not 1 <= exit_code <= 255
    ):
        raise ValueError("provider query identity or exit code is invalid")
    combined = f"{stdout}\n{stderr}"
    error_class = next(
        (code for code in ("D1_ERROR", "SQLITE_BUSY", "SQLITE_CONSTRAINT", "SQLITE_ERROR")
         if re.search(rf"\b{code}\b", combined, re.IGNORECASE)),
        None,
    )
    if error_class is None:
        if re.search(r"\bHTTP(?:\s+status)?\s*[:=]?\s*[45][0-9]{2}\b", combined, re.IGNORECASE):
            error_class = "HTTP_ERROR"
        elif re.search(r"\bwrangler\b|\bCloudflare API\b", combined, re.IGNORECASE):
            error_class = "WRANGLER_ERROR"
        else:
            error_class = "PROVIDER_ERROR" if combined.strip() else "UNKNOWN_ERROR"
    try:
        error = _error_entry(json.loads(stdout))
    except (json.JSONDecodeError, UnicodeError):
        error = None
    code = error.get("code") if isinstance(error, dict) else None
    provider_code = str(code) if isinstance(code, (int, str)) and not isinstance(code, bool) else None
    if provider_code is not None and not PROVIDER_CODE.fullmatch(provider_code):
        provider_code = None
    return {
        "query_stage": "wrangler_d1_execute", "query_id": query_id, "exit_code": exit_code,
        "error_class": error_class, "provider_code": provider_code,
        "semantic_error_category": _semantic_error_category(stdout, stderr),
        "schema_shape": _schema(stdout, stdout_truncated, stderr_truncated),
    }


def validate_provider_diagnostic(value: dict[str, object]) -> None:
    fields = {"query_stage", "query_id", "exit_code", "error_class", "provider_code", "semantic_error_category", "schema_shape"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("provider diagnostic fields differ from the allowlist")
    if value["query_stage"] != "wrangler_d1_execute" or value["query_id"] not in QUERY_IDS:
        raise ValueError("provider query stage or id is not allowlisted")
    if (
        isinstance(value["exit_code"], bool)
        or not isinstance(value["exit_code"], int)
        or not 1 <= value["exit_code"] <= 255
    ):
        raise ValueError("provider exit code is invalid")
    if value["error_class"] not in ERROR_CLASSES:
        raise ValueError("provider error class is not allowlisted")
    if value["semantic_error_category"] not in PROVIDER_ERROR_CATEGORIES:
        raise ValueError("provider semantic error category is not allowlisted")
    code = value["provider_code"]
    if code is not None and (not isinstance(code, str) or not PROVIDER_CODE.fullmatch(code)):
        raise ValueError("provider code is invalid")
    shape = value["schema_shape"]
    names = {"root", "result", "error_entry"}
    expected = {"format", "stdout_truncated", "stderr_truncated"} | {
        f"{name}_{suffix}" for name in names for suffix in ("kind", "keys", "unknown_key_count")
    }
    if not isinstance(shape, dict) or set(shape) != expected or shape["format"] not in {"empty", "json", "non_json"}:
        raise ValueError("provider schema fields differ from the allowlist")
    kinds = {"null", "boolean", "object", "array", "number", "string", "unknown"}
    for name in names:
        if shape[f"{name}_kind"] not in kinds:
            raise ValueError("provider schema kind is invalid")
        keys = shape[f"{name}_keys"]
        if not isinstance(keys, list) or keys != sorted(set(keys)) or any(key not in SCHEMA_KEYS for key in keys):
            raise ValueError("provider schema keys are invalid")
        count = shape[f"{name}_unknown_key_count"]
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_PROVIDER_OUTPUT_BYTES:
            raise ValueError("provider unknown-key count is invalid")
    if any(not isinstance(shape[key], bool) for key in ("stdout_truncated", "stderr_truncated")):
        raise ValueError("provider truncation marker is invalid")


def _read_bounded(path: Path) -> tuple[str, bool]:
    if not path.exists():
        return "", False
    with path.open("rb") as stream:
        raw = stream.read(MAX_PROVIDER_OUTPUT_BYTES + 1)
    return raw[:MAX_PROVIDER_OUTPUT_BYTES].decode("utf-8", errors="replace"), len(raw) > MAX_PROVIDER_OUTPUT_BYTES


def record_provider_failure(receipt: Path, query_id: str, exit_code: int, stdout_path: Path, stderr_path: Path) -> None:
    stdout, stdout_truncated = _read_bounded(stdout_path)
    stderr, stderr_truncated = _read_bounded(stderr_path)
    diagnostic = make_provider_diagnostic(
        query_id, exit_code, stdout, stderr,
        stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
    )
    validate_provider_diagnostic(diagnostic)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["provider_failure"] = diagnostic
    receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def mark_query_started(receipt: Path, query_id: str) -> None:
    """Replace the preflight marker when the first allowlisted provider call begins."""
    if query_id not in QUERY_IDS:
        raise ValueError("provider query identity is not allowlisted")
    document = json.loads(receipt.read_text(encoding="utf-8"))
    reasons = document.setdefault("failure_reasons", [])
    if not isinstance(reasons, list):
        raise ValueError("receipt failure reasons are invalid")
    document["failure_reasons"] = [reason for reason in reasons if reason != "read_not_started"]
    started = document.setdefault("provider_queries_started", [])
    if not isinstance(started, list) or any(item not in QUERY_IDS for item in started):
        raise ValueError("receipt provider query history is invalid")
    started.append(query_id)
    document["provider_queries_started"] = started
    receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "mark-started":
        mark_query_started(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 7 and sys.argv[1] == "record":
        record_provider_failure(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]))
    else:
        raise SystemExit("usage: b125_readonly_diagnostics.py mark-started RECEIPT QUERY | record RECEIPT QUERY EXIT STDOUT STDERR")
