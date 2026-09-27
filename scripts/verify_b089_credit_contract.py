#!/usr/bin/env python3
"""Semantic B-089 contract check; comments and generated trees are not evidence."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIM = re.compile(r"issued automatically|automatic(?:ly)?[^\n]*credit", re.I)
TOKENS = re.compile(r"\b(?:service_credit|sla_credit|credit_note|balance_transaction)\b")
HISTORICAL_V1_SHA256 = "4b6e39a0891eecf32640e9815386436e155e3334cd655ea180ca6f3bc1af6d09"


def fail(message: str) -> None:
    raise RuntimeError(message)


def code_with_comments_blank(text: str) -> str:
    """Blank comments while retaining string literals as fail-closed evidence."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def visible_markdown(text: str) -> str:
    """Return visible prose; comments and fenced examples are not policy evidence."""
    visible: list[str] = []
    fence = False
    html = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        if html:
            if "-->" in raw:
                raw = raw.split("-->", 1)[1]
                html = False
            else:
                continue
        if "<!--" in raw:
            before, after = raw.split("<!--", 1)
            raw = before
            if "-->" in after:
                raw += after.split("-->", 1)[1]
            else:
                html = True
        if raw.strip() and not raw.lstrip().startswith("#"):
            visible.append(raw)
    if fence or html:
        fail("unterminated Markdown fence/comment")
    return "\n".join(visible)


def check_draft(text: str) -> None:
    visible_lines = visible_markdown(text).splitlines()
    visible = re.sub(r"\s+", " ", " ".join(visible_lines))
    required = (
        "DRAFT — NOT EFFECTIVE", "not a customer agreement", "Enterprise-only",
        "No SLA service-credit program is currently active", "SLA_CREDITS_ENABLED",
        "#2568", "100%", "sole and exclusive remedy", "Free", "Solo", "Starter", "Pro", "Max",
        "0 < shortfall < 0.5 pp", "0.5 pp ≤ shortfall < 1.0 pp", "1.0 pp ≤ shortfall < 2.5 pp",
        "2.5 pp ≤ shortfall ≤ 5.0 pp", "shortfall > 5.0 pp", "absolute uptime `< 95%`",
        "0 < excess ≤ 25%", "25% < excess ≤ 50%", "excess > 50%",
        "DSR erasure `30 days ≤ duration < 45 days`", "DSR erasure `duration ≥ 45 days`",
        "Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours`",
        "Credits stack only across distinct SLOs in the same Service Period.",
        "aggregate is capped at 100% of the Monthly Service Fee.",
        "Catastrophic uptime takes priority over every lower band.",
        "No separate refund is added for the same ordinary SLA breach.",
        "A signed Enterprise Order Form may change only the metrics, rates, or remedies that it expressly identifies.",
        "three consecutive months of uptime breach against an applicable §2 SLO",
        "one catastrophic uptime breach", "repeated DSR erasure breach in two consecutive months",
        "A pro-rata refund of prepaid fees applies only after a valid termination under this section",
        "is not a second recovery for the same SLA breach.",
        "no promise of automatic or manual issuance", "separate controlled release acceptance is recorded",
    )
    for marker in required:
        if marker.lower() not in visible.lower():
            fail(f"v1.1.0 draft is missing required inactive-policy marker: {marker}")
    if any(CLAIM.search(line) for line in visible_lines):
        fail("v1.1.0 draft contains an active automatic-credit promise")
    if "no credit formula is defined" not in visible.lower() or "synthetic-page or byok" not in visible.lower():
        fail("v1.1.0 draft must keep synthetic-page and BYOK credits excluded")
    check_credit_tables(text)


def check_historical(raw: bytes) -> None:
    if hashlib.sha256(raw).hexdigest() != HISTORICAL_V1_SHA256:
        fail("historical v1.0.0 SHA-256 differs from the approved base bytes")


def check_credit_tables(text: str) -> None:
    def require_table(start: str, end: str, header: str, separator: str, expected: tuple[str, ...]) -> None:
        section = text.split(start, 1)
        if len(section) != 2:
            fail(f"v1.1.0 schedule section missing: {start}")
        table = section[1].split(end, 1)[0]
        rows = [line.strip() for line in table.splitlines() if line.strip().startswith("|")]
        if rows[:2] != [header, separator] or rows[2:] != list(expected):
            fail(f"v1.1.0 exact schedule rows drifted: {start}")

    require_table(
        "### 2.1 Uptime / availability", "### 2.2 p99 GET latency",
        "| Measured result | Credit as % of Monthly Service Fee |", "|---|---:|",
        (
            "| Target met or exceeded | 0% |",
            "| `0 < shortfall < 0.5 pp` | 5% |",
            "| `0.5 pp ≤ shortfall < 1.0 pp` | 10% |",
            "| `1.0 pp ≤ shortfall < 2.5 pp` | 25% |",
            "| `2.5 pp ≤ shortfall ≤ 5.0 pp` | 50% |",
            "| `shortfall > 5.0 pp` or absolute uptime `< 95%` | 100% plus the §4 termination right |",
        ),
    )
    require_table(
        "### 2.2 p99 GET latency", "### 2.3 Freshness",
        "| Excess over target | Credit as % of Monthly Service Fee |", "|---|---:|",
        (
            "| `0 < excess ≤ 25%` | 5% |",
            "| `25% < excess ≤ 50%` | 10% |",
            "| `excess > 50%` | 25% |",
        ),
    )
    require_table(
        "### 2.3 Freshness", "## 3. Stacking, cap, and remedy",
        "| Breach | Credit |", "|---|---|",
        (
            "| DSR erasure `30 days ≤ duration < 45 days` | 5% |",
            "| DSR erasure `duration ≥ 45 days` | 25% plus DPO incident review |",
            "| Billing reconciliation drift `≥ 0.1%` sustained for `> 24 hours` | 10% |",
        ),
    )


def check_tree() -> None:
    historical = ROOT / "legal/sla/v1.0.0.md"
    draft = ROOT / "legal/sla/v1.1.0.md"
    if historical.is_symlink() or not historical.is_file(): fail("historical SLA missing or non-regular")
    if draft.is_symlink() or not draft.is_file(): fail("prelaunch draft missing or non-regular")
    check_historical(historical.read_bytes())
    check_draft(draft.read_text(encoding="utf-8"))
    config = (ROOT / "apps/signup-worker/wrangler.toml").read_text(encoding="utf-8")
    for flag in ("SLA_CREDITS_ENABLED", "SLA_OBSERVATIONS_ENABLED"):
        if not re.search(rf'{flag}\s*=\s*"false"', config):
            fail(f"provider readiness gate must remain false: {flag}")
    terms = (ROOT / "apps/docs/src/pages/legal/terms.tsx").read_text(encoding="utf-8")
    if "No SLA service-credit program is currently active" not in terms:
        fail("Terms no longer fail closed while the release gates are pending")
    pricing = (ROOT / "apps/docs/src/pages/pricing.tsx").read_text(encoding="utf-8")
    if "99.9% SLA + credits" in pricing:
        fail("public pricing page reintroduced the inactive SLA-credit claim")


def self_test() -> None:
    try: check_draft("<!-- DRAFT — NOT EFFECTIVE; Enterprise-only; no SLA program -->")
    except RuntimeError: pass
    else: fail("comment-only policy passed")
    try: check_draft("```text\nDRAFT — NOT EFFECTIVE; Enterprise-only; no SLA program\n```")
    except RuntimeError: pass
    else: fail("fenced policy passed")
    try: check_draft("## no credit")
    except RuntimeError: pass
    else: fail("missing-policy mutation passed")
    if TOKENS.search(code_with_comments_blank("// service_credit\nfn ok() {}")):
        fail("comment mutation became active")
    if not TOKENS.search(code_with_comments_blank('const x = "service_credit";')):
        fail("string mutation disappeared")


if __name__ == "__main__":
    try:
        check_tree(); self_test()
    except (OSError, RuntimeError, UnicodeError) as error:
        print(f"B-089 semantic check FAILED: {error}")
        raise SystemExit(1)
    print("B-089 semantic check PASS: inactive public policy and disabled provider gates")
