#!/usr/bin/env python3
"""Fail-closed structural proof for B-079 (Max tier and unknown-tier safety).

The old backlog check looked for a few strings and could pass when the rate
table changed to a third, mutually inconsistent value.  This verifier parses
the actual Rust resolver arms, the published rate-limit table, and the public
pricing contract, then compares the numeric values and label mapping.  Its
in-memory adversarial mutations prove that each load-bearing assertion has
teeth without running a workspace build or a remote CI job.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
RUST_PATH = ROOT / "crates/corelink-ratelimit/src/tier.rs"
DOCS_PATH = ROOT / "apps/docs/docs/explanation/rate-limits.mdx"
PRICING_PATH = ROOT / "apps/docs/src/lib/pricing.ts"
MAX_PROOF_BYTES = 2_000_000
MAX_PROOF_LINE_CHARS = 16_384
# A string-masked billing arm: the masked labels leave only blanks and `|`
# before `=>`.  This was ``^\s*(?:\s*\|\s*)*\s*=>\s*(Tier::[A-Za-z]+)\s*,?\s*$``,
# whose nested and adjacent ``\s*`` let a line of `|` separators backtrack
# exponentially (CodeQL py/redos).  ``[\s|]*`` is the same set (any run of
# blanks and pipes) and ``\s*(?:,\s*)?`` the same tail, each character now
# having exactly one way to match.
LABEL_ARM_SHAPE = re.compile(r"^[\s|]*=>\s*(Tier::[A-Za-z]+)\s*(?:,\s*)?$")


class VerificationError(RuntimeError):
    """The proof objects are missing, malformed, or inconsistent."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing B-079 proof object: {path.relative_to(ROOT)}")
    try:
        with path.open("rb") as source_file:
            raw = source_file.read(MAX_PROOF_BYTES + 1)
    except OSError as error:
        fail(f"cannot read B-079 proof object {path.relative_to(ROOT)}: {error}")
    if len(raw) > MAX_PROOF_BYTES:
        fail(f"B-079 proof object exceeds bounded input size: {path.name}")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"B-079 proof object is not UTF-8: {path.name}: {error}")
    _check_input_bounds(content, path.relative_to(ROOT).as_posix())
    return content


def _check_input_bounds(source: str, label: str) -> None:
    if len(source.encode("utf-8")) > MAX_PROOF_BYTES:
        fail(f"B-079 proof object exceeds bounded input size: {label}")
    if any(len(line) > MAX_PROOF_LINE_CHARS for line in source.splitlines()):
        fail(f"B-079 proof object has an overlong line: {label}")


def _mask_rust(source: str, *, mask_strings: bool) -> str:
    """Mask comments (and optionally literals) without changing offsets.

    B-079 is a source-structure gate.  A plain ``find("pub fn ...")`` is not
    a parser: a stale function copied into a block comment or a string can be
    selected before the live resolver and make a weakened source look sound.
    This small lexer handles nested Rust block comments, line comments, raw
    strings, normal strings, and character literals while preserving newlines
    and byte offsets for subsequent slicing.
    """

    chars = list(source)
    length = len(source)
    index = 0
    block_depth = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] != "\n":
                chars[position] = " "

    while index < length:
        if block_depth:
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
            else:
                blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            blank(index, index + 2)
            block_depth = 1
            index += 2
            continue

        raw = re.match(r"r(?P<hashes>#+)?\"", source[index:])
        if raw:
            hashes = raw.group("hashes") or ""
            opening_length = len(raw.group(0))
            closing = "\"" + hashes
            end = source.find(closing, index + opening_length)
            end = length if end < 0 else end + len(closing)
            if mask_strings:
                blank(index, end)
            index = end
            continue

        if source[index] in ('"', "'"):
            quote = source[index]
            end = index + 1
            escaped = False
            while end < length:
                char = source[end]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    end += 1
                    break
                end += 1
            if mask_strings:
                blank(index, end)
            index = end
            continue

        index += 1

    if block_depth:
        fail("unterminated Rust block comment")
    return "".join(chars)


def _mask_typescript(source: str) -> str:
    """Mask TypeScript comments and string/template literals in-place.

    Pricing is data, but it is still executable TypeScript.  Regexing the raw
    file lets a commented-out or quoted `max: { ... }` card become the card we
    verify.  This deliberately keeps offsets/newlines stable so the same
    brace-balanced pass can extract the live object.
    """

    chars = list(source)
    length = len(source)
    index = 0
    block_depth = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] != "\n":
                chars[position] = " "

    while index < length:
        if block_depth:
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
            else:
                blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            blank(index, index + 2)
            block_depth = 1
            index += 2
            continue

        if source[index] in ('"', "'", "`"):
            quote = source[index]
            end = index + 1
            escaped = False
            closed = False
            while end < length:
                char = source[end]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    end += 1
                    closed = True
                    break
                end += 1
            if not closed:
                fail("unterminated TypeScript string/template literal")
            blank(index, end)
            index = end
            continue

        index += 1

    if block_depth:
        fail("unterminated TypeScript block comment")
    return "".join(chars)


def _mask_mdx(source: str) -> str:
    """Mask MDX/HTML comments and fenced code while preserving line offsets."""

    chars = list(source)
    length = len(source)
    index = 0
    fence_char: str | None = None
    fence_length = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] != "\n":
                chars[position] = " "

    while index < length:
        line_start = index == 0 or source[index - 1] == "\n"
        if line_start:
            line_end = source.find("\n", index)
            line_end = length if line_end < 0 else line_end
            line = source[index:line_end]
            fence = re.match(r"^[ \t]{0,3}(`{3,}|~{3,})", line)
            if fence_char is not None:
                blank(index, line_end)
                if fence and fence.group(1)[0] == fence_char and len(fence.group(1)) >= fence_length:
                    fence_char = None
                    fence_length = 0
                index = line_end + (1 if line_end < length else 0)
                continue
            if fence:
                blank(index, line_end)
                fence_char = fence.group(1)[0]
                fence_length = len(fence.group(1))
                index = line_end + (1 if line_end < length else 0)
                continue
        elif fence_char is not None:
            blank(index, index + 1)
            index += 1
            continue

        if source.startswith("<!--", index):
            end = source.find("-->", index + 4)
            if end < 0:
                fail("unterminated HTML comment in rate-limit docs")
            end += 3
            blank(index, end)
            index = end
            continue
        if source.startswith("{/*", index):
            end = source.find("*/}", index + 3)
            if end < 0:
                fail("unterminated JSX comment in rate-limit docs")
            end += 3
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                fail("unterminated block comment in rate-limit docs")
            end += 2
            blank(index, end)
            index = end
            continue

        index += 1

    if fence_char is not None:
        fail("unterminated fenced code block in rate-limit docs")
    return "".join(chars)


def function_body(source: str, name: str) -> str:
    # Locate declarations and braces only in comment/string-free text.  Return
    # a comment-masked body with literals retained so the billing labels can be
    # compared as actual source tokens.  Require one declaration: selecting the
    # first textual hit would let a stale duplicate change which resolver is
    # actually being proved.
    structural = _mask_rust(source, mask_strings=True)
    declaration = re.compile(rf"(?m)^\s*pub\s+fn\s+{re.escape(name)}\s*\(")
    matches = list(declaration.finditer(structural))
    if not matches:
        fail(f"Rust resolver {name} is missing")
    if len(matches) != 1:
        fail(f"Rust resolver {name} is ambiguous: found {len(matches)} declarations")
    start = matches[0].start()
    opening = structural.find("{", start)
    if opening < 0:
        fail(f"Rust resolver {name} has no body")
    depth = 0
    for index in range(opening, len(structural)):
        char = structural[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return _mask_rust(source, mask_strings=False)[opening : index + 1]
    fail(f"Rust resolver {name} has unbalanced braces")


def rust_constant(source: str, name: str) -> int:
    # Constants are declarations, not arbitrary text.  Mask both comments and
    # literals before extracting so a bait declaration in `/* ... */` or a
    # string cannot shadow the live value.  Duplicate live declarations are
    # rejected rather than resolved by textual order.
    structural = _mask_rust(source, mask_strings=True)
    declaration = re.compile(
        rf"^\s*pub\s+const\s+{re.escape(name)}\s*:\s*u32\s*=\s*([0-9_]+);",
        re.MULTILINE,
    )
    matches = list(declaration.finditer(structural))
    if not matches:
        fail(f"missing Rust constant {name}")
    if len(matches) != 1:
        fail(f"Rust constant {name} is ambiguous: found {len(matches)} declarations")
    return int(matches[0].group(1).replace("_", ""))


def rust_tuple_arm(body: str, arm: str) -> tuple[str, str]:
    # Tuple arms contain no labels, so mask literals as well as comments.  A
    # multiline raw string containing an arm-shaped bait must not count.
    structural = _mask_rust(body, mask_strings=True)
    matches = list(re.finditer(
        rf"(?m)^\s*{re.escape(arm)}\s*=>\s*\(([^,]+),\s*([^\)]+)\),?\s*$",
        structural,
    ))
    if not matches:
        fail(f"missing or malformed Rust arm {arm!r}")
    if len(matches) != 1:
        fail(f"Rust arm {arm!r} is ambiguous: found {len(matches)} arms")
    match = matches[0]
    return match.group(1).strip(), match.group(2).strip()


def rust_label_arm(body: str, label: str) -> str:
    # First identify real code lines with strings masked; this excludes a
    # multiline raw string containing a fake arm.  Then recover labels from
    # the same offsets in comment-masked text, where actual string literals
    # remain available but comments do not.
    structural = _mask_rust(body, mask_strings=True)
    code = _mask_rust(body, mask_strings=False)
    label_re = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    matches: list[str] = []
    label_occurrences = 0
    offset = 0
    for line in structural.splitlines(keepends=True):
        candidate = line.rstrip("\r\n")
        arm_match = LABEL_ARM_SHAPE.fullmatch(candidate)
        if arm_match:
            original = code[offset : offset + len(line)].rstrip("\r\n")
            labels = [item.group(1) for item in label_re.finditer(original)]
            label_occurrences += labels.count(label)
            if label in labels:
                matches.append(arm_match.group(1))
        offset += len(line)
    if not matches:
        fail(f"missing Rust billing mapping for {label!r}")
    if len(matches) != 1 or label_occurrences != 1:
        fail(
            f"Rust billing mapping for {label!r} is ambiguous: "
            f"found {len(matches)} arms/{label_occurrences} labels"
        )
    return matches[0]


def rust_wildcard_tier_arm(body: str) -> str:
    """Extract exactly one live wildcard arm from a Rust match body.

    The body returned by :func:`function_body` keeps literals so billing
    labels can be inspected.  Mask them again here: a multiline raw string,
    byte string, or character literal containing an arm-shaped line is not
    executable routing.  Duplicate live wildcard arms are ambiguous and must
    fail closed rather than letting ``re.search`` choose the first one.
    """

    structural = _mask_rust(body, mask_strings=True)
    matches = list(
        re.finditer(
            r"(?m)^\s*_\s*=>\s*(Tier::[A-Za-z]+)\s*,?\s*$",
            structural,
        )
    )
    if not matches:
        fail("billing-label resolver has no explicit unknown fallback")
    if len(matches) != 1:
        fail(f"billing-label wildcard fallback is ambiguous: found {len(matches)} arms")
    return matches[0].group(1)


def number(text: str, context: str) -> int:
    # Published prose uses either a thin/normal space or a comma as a
    # thousands separator.  Do not accept a prefix/suffix: a changed unit or
    # an additional number must make the verifier red.
    compact = text.replace(" ", "").replace(",", "")
    if not re.fullmatch(r"\d+", compact):
        fail(f"{context} is not a single integer: {text!r}")
    return int(compact)


def docs_business_row(docs: str) -> tuple[set[str], int, int]:
    # Markdown tables inside HTML comments, JSX comments, or fenced examples
    # are not published rows.  Parse only the comment/fence-masked document.
    visible = _mask_mdx(docs)
    rows = re.findall(r"(?m)^\|\s*Business\s*\|([^\n]+)$", visible)
    if len(rows) != 1:
        fail(f"expected exactly one published Business rate row, found {len(rows)}")
    cells = [cell.strip() for cell in rows[0].split("|")]
    if cells and cells[-1] == "":
        cells.pop()
    if len(cells) != 4:
        fail(f"Business rate row has unexpected shape: {cells!r}")
    labels = set(re.findall(r"`([^`]+)`", cells[0]))
    if not labels:
        fail("Business row has no billing labels")
    return labels, number(cells[1], "published Business RPS"), number(cells[2], "published Business burst")


def pricing_max_contract(pricing: str) -> tuple[int, int]:
    # Extract one live object from comment/string-masked TypeScript and then
    # balance braces.  A raw regex over the file can select an old `max` card
    # in a block comment or a quoted fixture before the production card.
    structural = _mask_typescript(pricing)
    cards = list(re.finditer(r"(?m)^\s*max\s*:\s*\{", structural))
    if not cards:
        fail("public pricing card has no max entry")
    if len(cards) != 1:
        fail(f"public Max pricing card is ambiguous: found {len(cards)} entries")
    opening = structural.find("{", cards[0].start(), cards[0].end())
    depth = 0
    closing = -1
    for index in range(opening, len(structural)):
        if structural[index] == "{":
            depth += 1
        elif structural[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        fail("public Max pricing card has unbalanced braces")
    body = structural[opening + 1 : closing]

    def field(name: str) -> int:
        matches = list(re.finditer(rf"(?m)^\s*{re.escape(name)}\s*:\s*(\d+),", body))
        if len(matches) != 1:
            fail(f"public Max pricing card field {name} is ambiguous or missing")
        return int(matches[0].group(1))

    price = field("usdMonthlyBase")
    retention = field("retentionDays")
    if price is None or retention is None:  # pragma: no cover - fail() always raises
        fail("public Max pricing card lost price or retention fields")
    return price, retention


def validate(files: dict[str, str]) -> None:
    for label, source in files.items():
        _check_input_bounds(source, label)
    rust = files["rust"]
    docs = files["docs"]
    pricing = files["pricing"]

    constants = {
        name: rust_constant(rust, name)
        for name in (
            "TEAM_REFILL_RPS",
            "TEAM_BURST",
            "BUSINESS_REFILL_RPS",
            "BUSINESS_BURST",
            "ENTERPRISE_REFILL_RPS",
            "ENTERPRISE_BURST",
        )
    }
    if (constants["TEAM_REFILL_RPS"], constants["TEAM_BURST"]) != (200, 1000):
        fail(f"Team fallback contract changed: {constants['TEAM_REFILL_RPS']}/{constants['TEAM_BURST']}")
    if (constants["BUSINESS_REFILL_RPS"], constants["BUSINESS_BURST"]) != (1000, 5000):
        fail("Business ladder no longer has the signed 1,000/5,000 values")
    if (constants["ENTERPRISE_REFILL_RPS"], constants["ENTERPRISE_BURST"]) != (10_000, 50_000):
        fail("Enterprise ladder changed without updating the B-079 contract")

    enum_body = function_body(rust, "refill_rate_for_tier")
    string_body = function_body(rust, "tier_for_billing_label")
    for tier, refill, burst in (
        ("Tier::Team", "TEAM_REFILL_RPS", "TEAM_BURST"),
        ("Tier::Business", "BUSINESS_REFILL_RPS", "BUSINESS_BURST"),
        ("Tier::Enterprise", "ENTERPRISE_REFILL_RPS", "ENTERPRISE_BURST"),
    ):
        actual = rust_tuple_arm(enum_body, tier)
        if actual != (refill, burst):
            fail(f"Rust {tier} arm drifted: expected {(refill, burst)}, found {actual}")
    enum_fallback = rust_tuple_arm(enum_body, "_")
    if enum_fallback != ("TEAM_REFILL_RPS", "TEAM_BURST"):
        fail(f"unknown enum fallback is not the canonical Team default: {enum_fallback}")
    if "ENTERPRISE_REFILL_RPS" in enum_fallback or "ENTERPRISE_BURST" in enum_fallback:
        fail("unknown enum fallback grants Enterprise capacity")

    if rust_label_arm(string_body, "max") != "Tier::Business":
        fail("Max billing label no longer resolves to Business")
    string_fallback = rust_wildcard_tier_arm(string_body)
    if string_fallback != "Tier::Team":
        fail(f"unknown billing label fallback is not Team: {string_fallback}")

    labels, docs_rps, docs_burst = docs_business_row(docs)
    if not {"pro", "max"}.issubset(labels):
        fail(f"published Business row lost pro/max labels: {sorted(labels)}")
    if (docs_rps, docs_burst) != (
        constants["BUSINESS_REFILL_RPS"],
        constants["BUSINESS_BURST"],
    ):
        fail(
            "published Business row disagrees with Rust: "
            f"docs={docs_rps}/{docs_burst}, rust={constants['BUSINESS_REFILL_RPS']}/{constants['BUSINESS_BURST']}"
        )
    if re.search(r"(?<!\d)(?:4[ ,]?000|20[ ,]?000)(?!\d)", docs):
        fail("published rate-limit docs still contain the retired Max 4,000/20,000 claim")

    price, retention = pricing_max_contract(pricing)
    if price != 149:
        fail(f"public Max price changed from the signed $149 contract: ${price}")
    if retention != 365:
        fail(f"public Max retention no longer matches Business/Max promise: {retention} days")


def source_files() -> dict[str, str]:
    return {"rust": read(RUST_PATH), "docs": read(DOCS_PATH), "pricing": read(PRICING_PATH)}


def expect_rejection(files: dict[str, str], name: str, mutation: dict[str, str], needle: str) -> None:
    try:
        validate(mutation)
    except VerificationError as error:
        if needle not in str(error):
            fail(f"mutation {name} rejected for the wrong reason: {error}")
    else:
        fail(f"adversarial mutation unexpectedly passed: {name}")


def mutation_checks(files: dict[str, str]) -> None:
    rust = files["rust"]
    docs = files["docs"]
    pricing = files["pricing"]

    enum_marker = "_ => (TEAM_REFILL_RPS, TEAM_BURST),"
    if rust.count(enum_marker) != 1:
        fail("enum fallback mutation fixture is not unique")
    expect_rejection(
        files,
        "unknown enum grants Enterprise",
        {**files, "rust": rust.replace(enum_marker, "_ => (ENTERPRISE_REFILL_RPS, ENTERPRISE_BURST),", 1)},
        "unknown enum fallback",
    )
    # A parser that searches raw text can select this bait before the live
    # resolver.  The actual mutation stays Enterprise, so only a
    # comment/string-aware structural reader rejects it for the real reason.
    bait = "/*\npub fn refill_rate_for_tier(_: Tier) -> (u32, u32) {\n    _ => (TEAM_REFILL_RPS, TEAM_BURST),\n}\n*/"
    if bait in rust:
        fail("comment-parser mutation fixture is not unique")
    expect_rejection(
        files,
        "commented fake resolver masks Enterprise fallback",
        {
            **files,
            "rust": bait + "\n" + rust.replace(enum_marker, "_ => (ENTERPRISE_REFILL_RPS, ENTERPRISE_BURST),", 1),
        },
        "unknown enum fallback",
    )

    string_marker = "_ => Tier::Team,"
    if rust.count(string_marker) != 1:
        fail("billing fallback mutation fixture is not unique")
    expect_rejection(
        files,
        "unknown billing label grants Business",
        {**files, "rust": rust.replace(string_marker, "_ => Tier::Business,", 1)},
        "unknown billing label fallback",
    )

    max_marker = '"pro" | "org" | "max" => Tier::Business,'
    if rust.count(max_marker) != 1:
        fail("Max mapping mutation fixture is not unique")
    expect_rejection(
        files,
        "Max maps to Enterprise",
        {**files, "rust": rust.replace(max_marker, '"pro" | "org" | "max" => Tier::Enterprise,', 1)},
        "Max billing label",
    )

    docs_marker = "| Business | `pro`, `max` | 1 000 | 5 000 | Production teams. `pro` and `max` share the Business bucket. |"
    if docs.count(docs_marker) != 1:
        fail("published Business row mutation fixture is not unique")
    expect_rejection(
        files,
        "published Business rate silently changes",
        {**files, "docs": docs.replace(docs_marker, docs_marker.replace("1 000", "2 000", 1), 1)},
        "published Business row disagrees",
    )

    price_marker = "usdMonthlyBase: 149,"
    if pricing.count(price_marker) != 1:
        fail("Max pricing mutation fixture is not unique")
    expect_rejection(
        files,
        "Max price silently changes",
        {**files, "pricing": pricing.replace(price_marker, "usdMonthlyBase: 150,", 1)},
        "public Max price",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run only structural mutation teeth")
    args = parser.parse_args()
    try:
        files = source_files()
        validate(files)
        mutation_checks(files)
        print("B-079 confirmed: Max 1,000/5,000 matches Rust, docs, pricing, and 6/6 mutations rejected")
        return 0
    except VerificationError as error:
        print(f"B-079 DRIFTED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
