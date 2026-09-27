#!/usr/bin/env python3
"""Semantic B-089 contract check; comments and generated trees are not evidence."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIM = re.compile(r"issued automatically|automatic(?:ly)?[^\n]*credit", re.I)
TOKENS = re.compile(r"\b(?:service_credit|sla_credit|credit_note|balance_transaction)\b")


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
    visible = visible_markdown(text)
    required = (
        "DRAFT — NOT EFFECTIVE", "not a customer agreement", "Enterprise-only",
        "No SLA service-credit program is currently active", "SLA_CREDITS_ENABLED",
        "#2568", "100%", "sole and exclusive remedy", "Free", "Solo", "Starter", "Pro", "Max",
    )
    for marker in required:
        if marker.lower() not in visible.lower():
            fail(f"v1.1.0 draft is missing required inactive-policy marker: {marker}")
    if CLAIM.search(visible):
        fail("v1.1.0 draft contains an active automatic-credit promise")
    if "no credit formula is defined" not in visible.lower() or "synthetic-page or byok" not in visible.lower():
        fail("v1.1.0 draft must keep synthetic-page and BYOK credits excluded")


def check_historical(text: str) -> None:
    if "issued automatically against the next invoice" not in text:
        fail("historical v1.0.0 automatic-issuance bytes drifted")
    if "sole and exclusive remedy" not in text:
        fail("historical v1.0.0 remedy bytes drifted")


def check_tree() -> None:
    historical = ROOT / "legal/sla/v1.0.0.md"
    draft = ROOT / "legal/sla/v1.1.0.md"
    if historical.is_symlink() or not historical.is_file(): fail("historical SLA missing or non-regular")
    if draft.is_symlink() or not draft.is_file(): fail("prelaunch draft missing or non-regular")
    check_historical(historical.read_text(encoding="utf-8"))
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
