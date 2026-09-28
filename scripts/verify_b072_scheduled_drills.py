#!/usr/bin/env python3
"""Verify the B-072 scheduled-drill contract without contacting PagerDuty.

This is intentionally a small, fail-closed verifier. It proves that the
repository has no active synthetic trigger and that the dormant Worker seam
retains its safety guards. External deployment, delivery, and human receipt
remain owner evidence; a passing local check never proves those events.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def strip_comments(text: str) -> str:
    """Remove JS/TS comments while preserving quoted strings and newlines.

    The verifier checks executable wiring, so a comment containing an import or
    handler name must not satisfy it. Quoted strings are retained because some
    contract values are intentionally string literals; structural checks below
    anchor those values to their actual syntax.
    """

    out: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(text):
        char = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""
        if quote is not None:
            out.append(char)
            if char == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            out.append(char)
            i += 1
            continue
        if char == "/" and next_char == "/":
            out.extend((" ", " "))
            i += 2
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if char == "/" and next_char == "*":
            out.extend((" ", " "))
            i += 2
            while i < len(text):
                if text[i] == "*" and i + 1 < len(text) and text[i + 1] == "/":
                    out.extend((" ", " "))
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def active_code(text: str) -> str:
    return strip_comments(text)


def executable_code(text: str) -> str:
    """Mask strings so identifiers in string/comment bait are not executable."""

    code = active_code(text)
    out: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(code):
        char = code[i]
        if quote is not None:
            out.append("\n" if char == "\n" else " ")
            if char == "\\" and i + 1 < len(code):
                out.append("\n" if code[i + 1] == "\n" else " ")
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            out.append(" ")
        else:
            out.append(char)
        i += 1
    return "".join(out)


def active_import(text: str, module: str) -> bool:
    """Return whether a real static import, not lexical bait, is present."""

    code = active_code(text)
    escaped = re.escape(module)
    return re.search(
        rf"(?m)^\s*import\b(?:(?!;).)*?\bfrom\s*[\"']{escaped}[\"']\s*;?\s*$",
        code,
    ) is not None


def active_assignment(text: str, pattern: str) -> bool:
    """Match a line of executable wiring after comments have been removed."""

    return re.search(rf"(?m)^\s*{pattern}\s*$", active_code(text)) is not None


def active_function(text: str, name: str) -> bool:
    return re.search(
        rf"(?m)^\s*(?:export\s+)?async\s+function\s+{re.escape(name)}\s*\(",
        active_code(text),
    ) is not None


def required_code(text: str, pattern: str, label: str, *, preserve_strings: bool = False) -> str | None:
    code = active_code(text) if preserve_strings else executable_code(text)
    if re.search(pattern, code, re.MULTILINE) is None:
        return f"fail-closed/semantic guard missing: {label}"
    return None


def fail(message: str) -> int:
    print(f"B-072 FAIL: {message}", file=sys.stderr)
    return 1


def verify(root: Path) -> int:
    config = (root / "wrangler.toml").read_text(encoding="utf-8")
    config_data = tomllib.loads(config)
    entry = (root / "worker/src/index.ts").read_text(encoding="utf-8")
    fetch = (root / "worker/src/index_fetch.ts").read_text(encoding="utf-8")
    schedule = (root / "worker/src/index_schedule.ts").read_text(encoding="utf-8")
    common = (root / "worker/src/index_common.ts").read_text(encoding="utf-8")

    try:
        config_data = tomllib.loads(config)
    except tomllib.TOMLDecodeError as error:
        return fail(f"wrangler.toml is not valid TOML: {error}")

    def active_crons(value: object, path: str = "") -> list[str]:
        if isinstance(value, dict):
            found: list[str] = []
            for key, child in value.items():
                found.extend(active_crons(child, f"{path}.{key}" if path else key))
            return found
        if path.endswith(".crons") and isinstance(value, list) and value:
            return [path]
        return []

    active_trigger_paths = active_crons(config_data)
    if active_trigger_paths:
        return fail(
            "synthetic triggers must remain absent until external evidence exists: "
            + ", ".join(active_trigger_paths)
        )
    if '"0 6 * * 1"' in config:
        return fail("retired chaos cron must not be scheduled")
    receivers = [
        item
        for item in config_data.get("services", [])
        if item.get("binding") == "SCHEDULED_DRILL_DELIVERY"
    ]
    if receivers != [{"binding": "SCHEDULED_DRILL_DELIVERY", "service": "corelink-synthetic-pager"}]:
        return fail("default/dev receiver service binding is missing or ambiguous")

    for environment in ("prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd"):
        section = re.search(
            rf"(?ms)^\[env\.{re.escape(environment)}\](.*?)(?=^\[env\.|\Z)",
            config,
        )
        if section is None:
            # Absence of an env section is not a safe production override.
            return fail(f"missing explicit production environment section: {environment}")
        if not re.search(r"(?m)^\[env\." + re.escape(environment) + r"\.triggers\]\s*\ncrons\s*=\s*\[\s*\]", config):
            return fail(f"{environment} must explicitly disable inherited crons")

    if not active_import(entry, "./index_fetch.js"):
        return fail("worker entry is missing active static import of index_fetch")
    if not active_assignment(entry, r"scheduled\s*:\s*baseHandler\.scheduled!?,?"):
        return fail("worker entry is missing active scheduled -> baseHandler wiring")
    if not active_import(fetch, "./index_schedule.js"):
        return fail("index_fetch is missing active static import of index_schedule")
    if not active_assignment(fetch, r"scheduled\s*:\s*runScheduled\s*,?"):
        return fail("index_fetch is missing active scheduled -> runScheduled wiring")
    if not active_function(schedule, "runScheduled"):
        return fail("scheduled handler is missing from index_schedule.ts")
    if not re.search(r'(?m)^\s*"0 14 \* \* 1"\s*:\s*"synthetic_page"\s*,?\s*$', active_code(common)):
        return fail("cron mapping missing: 0 14 * * 1 -> synthetic_page")
    if "CHAOS_EXPERIMENTS" in active_code(schedule) or 'drill === "chaos"' in active_code(schedule):
        return fail("retired chaos drill must not remain in the scheduled handler")
    required_controls = (
        (r"\benv\.SCHEDULED_DRILL_DELIVERY\b", "SCHEDULED_DRILL_DELIVERY", False),
        (r"(?m)^\s*console\.error\s*\([^\n]*\bdelivery_binding_unavailable\b", "delivery_binding_unavailable", True),
        (r"(?m)^\s*console\.error\s*\([^\n]*\bdelivery_exception\b", "delivery_exception", True),
        (r"(?m)^\s*console\.error\s*\([^\n]*\bdelivery_status\b", "delivery_status", True),
        # The weekly unknown-cron guard must own its noRetry call; a separate
        # staging-probe rejection must not mask removal of this guard.
        (r"\bif\s*\(\s*drill\s*===\s*undefined\s*\)\s*\{[^{}]*\bcontroller\.noRetry\s*\(\s*\)", "controller.noRetry()", False),
        (r"\bawait\s+delivery\.fetch\s*\(", "await delivery.fetch(...)", False),
        (r"(?m)^\s*if\s*\(\s*!response\.ok\s*\)\s*\{", "non-2xx response guard", False),
        (r"\bsynthetic_page\s*:\s*\{", "synthetic_page payload", False),
        (r"\.\.\.\s*SYNTHETIC_PAGE_CONTRACT\b", "...SYNTHETIC_PAGE_CONTRACT payload spread", False),
        (r"\bsyntheticEmitAtMs\s*\(", "syntheticEmitAtMs", False),
        (r"\bemit_at_ms\s*:\s*syntheticEmitAtMs\s*\(", "emit_at_ms synthetic timestamp", False),
        (r"\bdelivery_mode\s*:\s*\(\(week\s*%\s*4\)\s*\+\s*4\)\s*%\s*4\s*===\s*3", "delivery_mode rotation", False),
    )
    for pattern, label, preserve_strings in required_controls:
        error = required_code(schedule, pattern, label, preserve_strings=preserve_strings)
        if error is not None:
            return fail(error)
    if not re.search(r'(?m)^\s*service\s*:\s*"synthetic-drill"\s*,?\s*$', active_code(common)):
        return fail("fail-closed/semantic guard missing: service synthetic-drill contract")
    if not re.search(r'(?m)^\s*synthetic_severity\s*:\s*"sev2_synthetic"\s*,?\s*$', active_code(common)):
        return fail("fail-closed/semantic guard missing: synthetic sev2 contract")

    # A scheduler body hidden behind a constant-false branch is a no-op while
    # retaining every required token below.  Check executable code so comments
    # and string bait cannot satisfy (or evade) this reachability guard.
    if re.search(r"(?m)^\s*if\s*\(\s*false\s*\)\s*\{", executable_code(schedule)):
        return fail("scheduled handler body is unreachable/no-op")

    # The scheduler must not grow a direct PagerDuty integration. This catches
    # accidental routing-key or endpoint additions while preserving the
    # receiver's real external-delivery responsibility.
    handler = active_code(schedule)
    if re.search(r"pagerduty\.com|routing[_-]?key|PAGERDUTY_(?:EVENTS_URL|(?:SYNTHETIC_)?ROUTING_KEY|WEBHOOK_SECRET)", handler, re.IGNORECASE):
        return fail("scheduled handler contains direct PagerDuty credential/endpoint material")

    print("B-072 PASS: synthetic trigger absent; dormant handoff seam remains fail-closed (external evidence pending)")
    return 0


def main() -> int:
    return verify(ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
