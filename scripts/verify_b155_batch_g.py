#!/usr/bin/env python3
"""Explicit-target semantic checks for the B-155 batch-G backlog records.

The checks in this module deliberately do not shell out to grep.  Each target
is named in code, comments are removed before executable-source assertions,
and missing or ambiguous populations fail closed.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
B110_LANES = ("cas_foundation", "coverage", "ffi-matrix-ci", "mutation-nightly")
B110_WORKFLOW_PATHS = tuple(f".github/workflows/{lane}.yml" for lane in B110_LANES)
B110_SEMGREP_PATH = ".github/workflows/semgrep.yml"
B110_EVIDENCE_PATH = "evidence/owner-actions/B-110/ci-capacity-decision.json"
B110_EVIDENCE_REQUIRED_FIELDS = (
    "schema_version",
    "captured_at",
    "selected_option",
    "workflows",
    "capacity_or_billing_reference",
    "coverage_impact",
    "runner_labels",
    "rollback_owner",
    "operator",
)
B110_EVIDENCE_ITEM_SCHEMA = (
    "workflows[] contains workflow, current_runner, selected_runner, and action; "
    "selected_option is hosted_billing, linux_self_hosted, or owner_authorized_park."
)
B110_EVIDENCE_WORKFLOWS = (
    {
        "workflow": ".github/workflows/cas_foundation.yml",
        "current_runner": "ubuntu-latest / ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/coverage.yml",
        "current_runner": "ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/ffi-matrix-ci.yml",
        "current_runner": "ubuntu-latest",
        "selected_runner": "corelink",
        "action": "migrated",
    },
    {
        "workflow": ".github/workflows/mutation-nightly.yml",
        "current_runner": "ubuntu-x64-4core",
        "selected_runner": "corelink",
        "action": "migrated",
    },
)
B110_ACTION_TYPE = "ci_capacity_decision"
B110_PROCEDURE = (
    "UI: Choose one authorized capacity path for cas_foundation, coverage, ffi-matrix-ci, and mutation-nightly: restore hosted billing, provision an adequate Linux self-hosted box, or authorize deletion/parking of the named lanes.",
    "RUN: For a self-hosted path, register a dedicated runner label with documented CPU/RAM/disk limits and verify the four workflows’ `runs-on` and toolchain assumptions before enabling it.",
    "UI: For hosted billing, confirm the GitHub account spending limit and payment state; for deletion/parking, obtain explicit owner approval describing the coverage loss. Record the selected option before any workflow mutation.",
)
B110_EXPECTED_POSTCONDITION = (
    "The owner-approved Linux self-hosted capacity decision is recorded and the four lanes use viable CoreLink capacity without deletion; B-110 is closed only after the workflow and verifier changes are present."
)
B110_RETRY_AND_ROLLBACK = (
    "Retry capacity checks before registering duplicate runners or changing billing. Roll back a new runner by disabling/unregistering only that runner; billing can be stopped by the owner. Do not restore deleted coverage without a new owner decision and workflow review."
)
B110_REFERENCES = (
    "BACKLOG.md#B-110",
    ".github/workflows/cas_foundation.yml",
    ".github/workflows/coverage.yml",
    ".github/workflows/ffi-matrix-ci.yml",
    ".github/workflows/mutation-nightly.yml",
)
B110_OWNER = "tl"
B110_STATUS = "done"
B110_INPUTS_AND_CREDENTIALS_BOUNDARY = {
    "inputs": [
        "four blocked workflow files",
        "required 4-core Linux capacity",
        "GitHub billing/account state",
        "coverage trade-off decision",
    ],
    "credentials": (
        "Owner controls GitHub billing, runner registration, and destructive workflow authorization; "
        "no payment, runner registration, workflow dispatch, or deletion is performed here."
    ),
}
IDS = {
    "B-100": "verify_b100",
    "B-109": "verify_b109",
    "B-110": "verify_b110",
    "B-111": "verify_b111",
    "B-116": "verify_b116",
    "B-117": "verify_b117",
    "B-120": "verify_b120",
    "B-126": "verify_b126",
    "B-130": "verify_b130",
    "B-137": "verify_b137",
}


class CheckError(RuntimeError):
    pass


def required(path: str) -> Path:
    candidate = ROOT / path
    if not candidate.is_file():
        raise CheckError(f"missing explicit target: {path}")
    return candidate


def text(path: str) -> str:
    return required(path).read_text(encoding="utf-8")


def files(root: str, suffixes: set[str]) -> list[Path]:
    directory = ROOT / root
    if not directory.is_dir():
        raise CheckError(f"missing explicit target: {root}")
    result = sorted(
        p for p in directory.rglob("*")
        if p.is_file() and p.suffix.lower() in suffixes
        and "node_modules" not in p.parts
    )
    if not result:
        raise CheckError(f"empty explicit population: {root}")
    return result


def active_lines(path: str) -> list[str]:
    """Return source lines outside comments without treating string URLs as comments."""
    raw = text(path).splitlines()
    result: list[str] = []
    block = False
    for line in raw:
        out: list[str] = []
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(line):
            pair = line[i : i + 2]
            if block:
                if pair == "*/":
                    block = False
                    i += 2
                else:
                    i += 1
                continue
            if quote:
                out.append(line[i])
                if escaped:
                    escaped = False
                elif line[i] == "\\":
                    escaped = True
                elif line[i] == quote:
                    quote = None
                i += 1
                continue
            if pair == "/*":
                block = True
                i += 2
                continue
            if pair == "//":
                break
            if line[i] in "'\"`":
                quote = line[i]
            out.append(line[i])
            i += 1
        current = "".join(out)
        stripped = current.lstrip()
        if stripped.startswith(("#", "<!--", "--")):
            continue
        if current.strip():
            result.append(current)
    return result


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


def rust_tokens(source: str) -> list[tuple[str, str]]:
    """Tokenize enough Rust to distinguish executable calls from bait text."""
    tokens: list[tuple[str, str]] = []
    i = 0
    block_depth = 0
    while i < len(source):
        if block_depth:
            if source.startswith("/*", i):
                block_depth += 1
                i += 2
            elif source.startswith("*/", i):
                block_depth -= 1
                i += 2
            else:
                i += 1
            continue
        if source.startswith("//", i):
            newline = source.find("\n", i + 2)
            i = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", i):
            block_depth = 1
            i += 2
            continue
        raw = re.match(r"r(?P<hashes>#+)?\"", source[i:])
        if raw:
            hashes = raw.group("hashes") or ""
            marker = '"' + hashes
            start = i + len(raw.group(0))
            end = source.find(marker, start)
            if end < 0:
                raise CheckError("unterminated Rust raw string")
            tokens.append(("string", source[start:end]))
            i = end + len(marker)
            continue
        # Rust lifetimes/labels (`'a`, `'static`, `'retry`) are not character
        # literals and must not make the bounded lexer search for a quote.
        if source[i] == "'" and i + 1 < len(source) and re.match(r"[A-Za-z_]", source[i + 1]):
            tokens.append(("punct", "'"))
            i += 1
            continue
        if source[i] in "\"'":
            quote = source[i]
            start = i + 1
            i = start
            escaped = False
            while i < len(source):
                char = source[i]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    break
                i += 1
            if i >= len(source):
                raise CheckError("unterminated Rust literal")
            if quote == '"':
                tokens.append(("string", source[start:i]))
            i += 1
            continue
        ident = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[i:])
        if ident:
            value = ident.group(0)
            tokens.append(("ident", value))
            i += len(value)
            continue
        if source[i].isspace():
            i += 1
            continue
        tokens.append(("punct", source[i]))
        i += 1
    if block_depth:
        raise CheckError("unterminated Rust block comment")
    return tokens


def executable_router_routes(source: str) -> list[str]:
    """Return route literals mounted by the real `fn router` body only."""
    tokens = rust_tokens(source)
    depth = 0
    router_body_depth: int | None = None
    pending_router = False
    routes: list[str] = []
    for index, (kind, value) in enumerate(tokens):
        next_value = tokens[index + 1][1] if index + 1 < len(tokens) else None
        if kind == "ident" and value == "fn" and next_value == "router":
            pending_router = True
        if pending_router and value == "{":
            router_body_depth = depth + 1
            pending_router = False
        if router_body_depth == depth and kind == "ident" and value == "route":
            previous = tokens[index - 1][1] if index else None
            if previous == "." and index + 3 < len(tokens):
                if tokens[index + 1][1] == "(" and tokens[index + 2][0] == "string":
                    routes.append(tokens[index + 2][1])
        if value == "{":
            depth += 1
        elif value == "}":
            if router_body_depth == depth:
                router_body_depth = None
            depth -= 1
    return routes


def route_parser_mutation_self_test() -> None:
    route = "/v1/test"
    cases = (
        ("executable", f'pub fn router() -> Router {{ Router::new().route("{route}", get(h)) }}', True),
        ("line-comment", f'pub fn router() -> Router {{ Router::new() // .route("{route}", get(h))\n }}', False),
        ("raw-string", f'pub fn router() -> Router {{ let bait = r#".route("{route}", get(h))"#; Router::new() }}', False),
        ("raw-string-no-hash", f'pub fn router() -> Router {{ let bait = r".route(\"{route}\", get(h))"; Router::new() }}', False),
        ("dead-function", f'fn dead() -> Router {{ Router::new().route("{route}", get(h)) }}\npub fn router() -> Router {{ Router::new() }}', False),
    )
    for name, source, expected in cases:
        actual = route in executable_router_routes(source)
        assert_true(actual == expected, f"route reachability mutation survived: {name}")


def verify_b100() -> None:
    candidates = files("apps", {".ts", ".tsx", ".md", ".mdx"})
    bad = [p for p in candidates if re.search(r"[A-Za-z0-9._%+-]+@corelink\.example", p.read_text(encoding="utf-8"))]
    assert_true(not bad, "placeholder @corelink.example remains in explicit apps population")
    notices = sorted((ROOT / "apps/admin-ui/src/content").glob("privacy-notice.*"))
    assert_true(notices, "privacy notice population is empty")
    for notice in notices:
        body = notice.read_text(encoding="utf-8")
        assert_true("privacy@humangr.com" in body or "dpo@humangr.com" in body, f"contact missing: {notice}")


def verify_b109() -> None:
    source = "\n".join(active_lines("crates/corelink-container/src/origin_timing.rs"))
    assert_true('parts.push(format!("oother;dur={other_ms}"))' in source, "oother emission is not executable")
    for phase in ("opat", "oquota", "ostore", "oaccounting", "oargon", "opermit", "ortier", "oaudit", "oratelimit"):
        assert_true(f'("{phase}",' in source, f"origin phase missing: {phase}")
    print("open: oother remains the explicit origin-timing residue")


def workflow_runs_on(path: str) -> list[str]:
    # YAML comments are line comments; do not use the language-source helper,
    # whose `//` rule would also truncate URL-like YAML values.
    return [
        match.group(1)
        for raw in text(path).splitlines()
        if not raw.lstrip().startswith("#")
        if (match := re.match(r"^\s*runs-on:\s*(\S+)", raw))
    ]


def workflow_active_lines(path: str) -> list[str]:
    """Return non-empty workflow lines with YAML comment-only lines removed."""
    return [
        line
        for line in text(path).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def workflow_top_block(path: str, key: str) -> list[str]:
    """Return one top-level YAML mapping block, failing closed if ambiguous."""
    lines = workflow_active_lines(path)
    matches = [index for index, line in enumerate(lines) if line == f"{key}:"]
    assert_true(len(matches) == 1, f"workflow top-level block is not unique: {path}:{key}")
    start = matches[0] + 1
    end = next(
        (index for index in range(start, len(lines)) if not lines[index].startswith((" ", "\t"))),
        len(lines),
    )
    return lines[start:end]


def workflow_triggers(path: str) -> list[str]:
    """Return active event keys directly under the workflow's `on:` block."""
    return [
        match.group(1)
        for line in workflow_top_block(path, "on")
        if (match := re.match(r"^  ([A-Za-z_][A-Za-z0-9_-]*):(?:\s|$)", line))
    ]


def workflow_job_block(path: str, job: str) -> list[str]:
    """Return one named job block, excluding sibling jobs."""
    lines = workflow_top_block(path, "jobs")
    matches = [
        index for index, line in enumerate(lines)
        if line == f"  {job}:"
    ]
    assert_true(len(matches) == 1, f"workflow job is not unique: {path}:{job}")
    start = matches[0]
    end = next(
        (
            index for index in range(start + 1, len(lines))
            if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", lines[index])
        ),
        len(lines),
    )
    return lines[start:end]


def workflow_job_names(path: str) -> list[str]:
    return [
        match.group(1)
        for line in workflow_top_block(path, "jobs")
        if (match := re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line))
    ]


def _strip_yaml_comment(line: str) -> str:
    """Strip a YAML comment without truncating quoted expression content."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = None
        elif quote == "'":
            if character == "'":
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _decode_yaml_double_quoted(value: str, label: str) -> str:
    """Decode YAML double-quoted escapes used by an `if` scalar."""
    if not (value.startswith('"') and value.endswith('"')):
        return value
    value = value[1:-1]
    simple = {
        "0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n",
        "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ",
        '"': '"', "/": "/", "\\": "\\", "N": "\u0085", "_": "\u00a0",
        "L": "\u2028", "P": "\u2029",
    }
    decoded: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise CheckError(f"unterminated YAML escape in {label}")
        escape = value[index]
        if escape in simple:
            decoded.append(simple[escape])
            index += 1
            continue
        width = {"x": 2, "u": 4, "U": 8}.get(escape)
        if width is None or index + width > len(value):
            raise CheckError(f"unsupported YAML escape in {label}")
        digits = value[index + 1 : index + 1 + width]
        if not re.fullmatch(rf"[0-9A-Fa-f]{{{width}}}", digits):
            raise CheckError(f"invalid YAML escape in {label}")
        decoded.append(chr(int(digits, 16)))
        index += width + 1
    return "".join(decoded)


def _semantic_if_expression(value: str, label: str) -> str:
    """Inspect the scalar after YAML quoting/escape decoding.

    The verifier intentionally accepts only scalar forms whose YAML meaning it
    can establish locally.  Tags, anchors, and aliases change the node
    semantics before GitHub evaluates the expression, so accepting their text
    would make an encoded ``||`` invisible to this check.  A safe YAML parser
    is not available in the hermetic verifier environment; reject these node
    prefixes rather than attempting to emulate their resolution.
    """
    value = value.strip()
    if value.startswith((">", "|")):
        # `workflow_job_if_expressions` has already joined continuation lines,
        # so remove only the YAML block header and inspect its scalar body.
        block = re.match(r"^[>|](?:[1-9])?(?:[+-])?(?:\s+|$)(.*)$", value)
        if block is None:
            raise CheckError(f"ambiguous YAML block scalar in {label}")
        value = block.group(1).strip()
        if not value:
            raise CheckError(f"empty YAML block scalar in {label}")
    if value.startswith(("!", "&", "*")):
        raise CheckError(f"YAML tag, anchor, or alias is not allowed in {label}")
    if value.startswith('"'):
        if not value.endswith('"'):
            raise CheckError(f"unterminated YAML double-quoted scalar in {label}")
        return _decode_yaml_double_quoted(value, label)
    if value.startswith("'"):
        if not value.endswith("'"):
            raise CheckError(f"unterminated YAML single-quoted scalar in {label}")
        return value[1:-1].replace("''", "'")
    return value


def _permission_writes(value: str, label: str) -> list[str]:
    """Parse a permissions scalar or inline mapping, fail-closed on ambiguity."""
    value = _strip_yaml_comment(value).strip()
    if value in {"read-all", "{}"}:
        return []
    if value == "write-all":
        return ["*"]
    if not (value.startswith("{") and value.endswith("}")):
        raise CheckError(f"unsupported permissions form: {label}")
    inner = value[1:-1].strip()
    if not inner:
        return []
    writes: list[str] = []
    for entry in inner.split(","):
        if ":" not in entry:
            raise CheckError(f"ambiguous inline permissions: {label}")
        key, permission = (part.strip() for part in entry.split(":", 1))
        key = key.strip("'\"")
        permission = permission.strip().strip("'\"")
        if not key or permission not in {"read", "write", "none"}:
            raise CheckError(f"ambiguous inline permissions: {label}")
        if permission == "write":
            writes.append(key)
    return writes


def _permission_block_writes(lines: list[str], start: int, parent_indent: int, label: str) -> list[str]:
    """Parse direct child entries of a block-style permissions mapping."""
    writes: list[str] = []
    child_indent = parent_indent + 2
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        current_indent = _indent(line)
        if current_indent <= parent_indent:
            break
        if current_indent != child_indent:
            continue
        entry = _strip_yaml_comment(line).strip()
        if ":" not in entry:
            raise CheckError(f"ambiguous permissions block: {label}")
        key, permission = (part.strip() for part in entry.split(":", 1))
        if permission not in {"read", "write", "none"}:
            raise CheckError(f"ambiguous permissions block: {label}")
        if permission == "write":
            writes.append(key.strip("'\""))
    return writes


def workflow_top_permissions(path: str) -> tuple[bool, list[str]]:
    lines = [_strip_yaml_comment(line) for line in workflow_active_lines(path)]
    matches = [index for index, line in enumerate(lines) if re.match(r"^permissions:(?:\s|$)", line)]
    assert_true(len(matches) == 1, f"workflow top-level permissions is not unique: {path}")
    index = matches[0]
    value = lines[index].split(":", 1)[1].strip()
    if value:
        return True, _permission_writes(value, f"{path}:permissions")
    return True, _permission_block_writes(lines, index, 0, f"{path}:permissions")


def workflow_job_permissions(block: list[str], path: str, job: str) -> tuple[bool, list[str]]:
    lines = [_strip_yaml_comment(line) for line in block]
    matches = [index for index, line in enumerate(lines) if re.match(r"^    permissions:(?:\s|$)", line)]
    assert_true(len(matches) <= 1, f"job permissions is not unique: {path}:{job}")
    if not matches:
        return False, []
    index = matches[0]
    value = lines[index].split(":", 1)[1].strip()
    if value:
        return True, _permission_writes(value, f"{path}:{job}:permissions")
    return True, _permission_block_writes(lines, index, 4, f"{path}:{job}:permissions")


def workflow_job_if_expressions(block: list[str]) -> list[str]:
    """Collect complete job-level YAML `if` scalars, including continuations."""
    lines = [_strip_yaml_comment(line) for line in block]
    expressions: list[str] = []
    for index, line in enumerate(lines):
        if not re.match(r"^    if:\s*", line):
            continue
        parts = [line.split(":", 1)[1].strip()]
        # YAML double-quoted scalars use a backslash immediately before a
        # physical newline as a folding escape.  The local line collector
        # cannot reproduce YAML's no-space join exactly; accepting it would
        # permit two separately written escape fragments to resolve into `||`.
        # Reject the construct before any hand-decoding instead.
        if parts[0].endswith("\\"):
            raise CheckError("backslash-newline YAML folding is not allowed in job if")
        for continuation in lines[index + 1 :]:
            if not continuation.strip() or _indent(continuation) <= 4:
                break
            parts.append(continuation.strip())
            if parts[-1].endswith("\\"):
                raise CheckError("backslash-newline YAML folding is not allowed in job if")
        expressions.append(_semantic_if_expression(" ".join(part for part in parts if part), "job if"))
    return expressions


def assert_trusted_write_boundary(block: list[str], label: str) -> None:
    """Require a job-level guard for every effective write permission."""
    job_conditions = workflow_job_if_expressions(block)
    assert_true(len(job_conditions) == 1, f"{label} does not have one job-level trust guard")
    source = job_conditions[0]
    assert_true("||" not in source, f"{label} trust guard contains an OR bypass")
    # Either canonical repository-ID guard; which one a workflow must use (and
    # the rendered literal value) is owned by sync_workflow_repository_guards.py.
    assert_true(
        re.search(r"github\.repository_id == (?:'[0-9]+'|vars\.CORELINK_SERVER_REPO_ID)(?![\w.])", source) is not None,
        f"{label} is missing trusted-source guard: github.repository_id",
    )
    required = (
        "github.ref == 'refs/heads/main'",
        "github.ref_protected",
    )
    for marker in required:
        assert_true(marker in source, f"{label} is missing trusted-source guard: {marker}")
    assert_true("github.event_name == '" in source, f"{label} is missing trusted-event guard")


def assert_trusted_write_guard(block: list[str], event: str, label: str) -> None:
    """Require all four dimensions of the self-hosted write trust boundary."""
    assert_trusted_write_boundary(block, label)
    source = workflow_job_if_expressions(block)[0]
    assert_true(f"github.event_name == '{event}'" in source, f"{label} has the wrong trusted event")


def assert_literal_concurrency(path: str, group: str) -> None:
    block = workflow_top_block(path, "concurrency")
    groups = [line for line in block if re.match(r"^  group:\s*", line)]
    cancels = [line for line in block if re.match(r"^  cancel-in-progress:\s*", line)]
    assert_true(groups == [f'  group: "{group}"'], f"concurrency group is not literal: {path}")
    assert_true(cancels == ["  cancel-in-progress: false"], f"concurrency is cancelling: {path}")
    assert_true("github.ref" not in "\n".join(block), f"concurrency is ref-split: {path}")


def packet_item(item_id: str) -> dict[str, object]:
    packet = json.loads(text("docs/handoff/2026-09-05-owner-action-packets-b008-b154.json"))
    items = packet.get("items")
    assert_true(isinstance(items, list), "owner packet items population missing")
    matches = [item for item in items if isinstance(item, dict) and item.get("id") == item_id]
    assert_true(len(matches) == 1, f"owner packet population for {item_id} is not unique")
    return matches[0]


def _verify_b110_packet(item: dict[str, object]) -> None:
    """Bind the closed B-110 row to the exact redacted decision evidence."""
    assert_true(item.get("owner") == B110_OWNER, "B-110 owner drifted")
    assert_true(item.get("status") == B110_STATUS, "B-110 status drifted")
    assert_true(item.get("action_type") == B110_ACTION_TYPE, "B-110 action type drifted")
    assert_true(item.get("procedure") == list(B110_PROCEDURE), "B-110 procedure drifted")
    assert_true(item.get("expected_postcondition") == B110_EXPECTED_POSTCONDITION, "B-110 postcondition drifted")
    assert_true(item.get("retry_and_rollback") == B110_RETRY_AND_ROLLBACK, "B-110 rollback contract drifted")
    assert_true(item.get("references") == list(B110_REFERENCES), "B-110 references drifted")
    assert_true(
        item.get("inputs_and_credentials_boundary") == B110_INPUTS_AND_CREDENTIALS_BOUNDARY,
        "B-110 inputs and credentials boundary drifted",
    )
    evidence = item.get("evidence")
    assert_true(isinstance(evidence, dict), "B-110 owner packet evidence is not an object")
    assert_true(evidence.get("path") == B110_EVIDENCE_PATH, "B-110 evidence path drifted")
    assert_true(evidence.get("format") == "json", "B-110 evidence format drifted")
    assert_true(
        evidence.get("required_fields") == list(B110_EVIDENCE_REQUIRED_FIELDS),
        "B-110 evidence required fields drifted",
    )
    assert_true(evidence.get("item_schema") == B110_EVIDENCE_ITEM_SCHEMA, "B-110 evidence schema drifted")

    evidence_path = required(B110_EVIDENCE_PATH)
    try:
        record = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"B-110 evidence is not valid JSON: {error}") from error
    assert_true(isinstance(record, dict), "B-110 evidence root is not an object")
    assert_true(set(record) == set(B110_EVIDENCE_REQUIRED_FIELDS), "B-110 evidence fields drifted")
    assert_true(record.get("schema_version") == 1, "B-110 evidence schema version drifted")
    assert_true(record.get("selected_option") == "linux_self_hosted", "B-110 capacity decision drifted")
    assert_true(record.get("workflows") == list(B110_EVIDENCE_WORKFLOWS), "B-110 workflow decision evidence drifted")
    assert_true(
        record.get("capacity_or_billing_reference")
        == "CoreLink runner image documentation: Linux x86_64, 4 vCPU, 12.5 GB; migration commit 41c47f236",
        "B-110 capacity reference drifted",
    )
    assert_true(
        record.get("coverage_impact")
        == "No lane was deleted or parked. The FFI Python/Go/Node matrices remain intact; cache guards remain self-hosted-safe; workflow assertions are unchanged.",
        "B-110 coverage impact drifted",
    )
    assert_true(record.get("runner_labels") == ["corelink"], "B-110 runner labels drifted")
    assert_true(record.get("rollback_owner") == "owner", "B-110 rollback owner drifted")
    assert_true(record.get("operator") == "owner-authorized automation", "B-110 operator drifted")


def verify_b110() -> None:
    workflow_paths = [*B110_WORKFLOW_PATHS, B110_SEMGREP_PATH]
    for lane, path in zip(B110_LANES, B110_WORKFLOW_PATHS):
        values = workflow_runs_on(path)
        assert_true(values, f"runner population missing: {lane}")
        assert_true(all(value == "corelink" for value in values), f"non-corelink runner present: {lane}")
        assert_true(
            workflow_triggers(path) == ["workflow_dispatch"],
            f"untrusted or implicit trigger present: {lane}",
        )
    values = workflow_runs_on(B110_SEMGREP_PATH)
    assert_true(len(values) == 1, "semgrep runner population is not exactly one")
    assert_true(not re.search(r"ubuntu|macos|windows", values[0], re.I), "semgrep returned to hosted runner")
    assert_true(workflow_triggers(B110_SEMGREP_PATH) == ["workflow_dispatch"], "semgrep trigger is not dispatch-only")

    for path in workflow_paths:
        _, top_permissions = workflow_top_permissions(path)
        for job in workflow_job_names(path):
            block = workflow_job_block(path, job)
            if not any(re.match(r"^\s+runs-on:\s+corelink(?:\s|$)", line) for line in block):
                continue
            has_job_permissions, job_permissions = workflow_job_permissions(block, path, job)
            effective = job_permissions if has_job_permissions else top_permissions
            if effective:
                assert_trusted_write_boundary(block, f"{path}:{job} ({','.join(effective)})")

    # Every self-hosted job with a write-capable token is checked by name so a
    # future job cannot satisfy this predicate merely by placing a guard in a
    # neighboring job or in a comment.
    assert_trusted_write_guard(
        workflow_job_block(".github/workflows/cas_foundation.yml", "cosign-sign"),
        "workflow_dispatch",
        "cas cosign-sign",
    )
    mutation_block = workflow_job_block(".github/workflows/mutation-nightly.yml", "aggregate")
    assert_trusted_write_guard(mutation_block, "workflow_dispatch", "mutation aggregate")
    assert_true(
        "if: github.event_name == 'workflow_dispatch' && github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.ref == 'refs/heads/main' && github.ref_protected"
        in "\n".join(mutation_block),
        "mutation commit step is missing the trusted-source guard",
    )
    perf_evidence_block = workflow_job_block(".github/workflows/perf-production-evidence.yml", "collect")
    assert_trusted_write_guard(perf_evidence_block, "workflow_dispatch", "perf production evidence")
    semgrep_block = workflow_job_block(".github/workflows/semgrep.yml", "semgrep")
    assert_trusted_write_guard(
        semgrep_block,
        "workflow_dispatch",
        "semgrep",
    )
    semgrep_permissions = workflow_top_block(".github/workflows/semgrep.yml", "permissions")
    assert_true(
        semgrep_permissions == ["  security-events: write", "  contents: read"],
        "semgrep permissions are broader than SARIF upload plus checkout",
    )
    coverage_permissions = workflow_top_block(".github/workflows/coverage.yml", "permissions")
    assert_true(coverage_permissions == ["  contents: read"], "coverage retains dead write permissions")
    assert_literal_concurrency(".github/workflows/cas_foundation.yml", "corelink-heavy-cargo-build")
    assert_literal_concurrency(".github/workflows/coverage.yml", "corelink-heavy-cargo-build")
    packet = packet_item("B-110")
    assert_true(packet.get("status") == "done", "B-110 owner packet is not done")
    _verify_b110_packet(packet)
    print("done: corelink runners, trusted write guards, least privilege, and shared heavy-build serialization verified")


def verify_b111() -> None:
    item = packet_item("B-111")
    assert_true(item.get("status") == "open", "B-111 owner packet is not open")
    procedure = " ".join(str(value) for value in item.get("procedure", []))
    required_names = (
        "APPLE_DEVELOPER_ID", "APPLE_DEVELOPER_ID_PASSWORD", "APPLE_TEAM_ID",
        "APPLE_NOTARIZATION_API_KEY", "APPLE_NOTARIZATION_KEY_ID",
        "APPLE_NOTARIZATION_ISSUER", "APPLE_DEVELOPER_ID_FINGERPRINT",
        "WINDOWS_CODE_SIGNING_CERT", "WINDOWS_CODE_SIGNING_PASSWORD",
        "WINDOWS_CODE_SIGNING_FINGERPRINT", "WINDOWS_CODE_SIGNING_SUBJECT",
    )
    for name in required_names:
        assert_true(name in procedure, f"B-111 packet lost required secret name: {name}")
    assert_true("never pass secret values" in procedure, "B-111 packet lost secret boundary")
    print("open: signing prerequisites remain owner-controlled")


def verify_b116() -> None:
    route_parser_mutation_self_test()
    routes = executable_router_routes(text("crates/corelink-container/src/routes/dpa_accept.rs"))
    assert_true(routes.count("/v1/onboarding/dpa-accept") == 1, "DPA route wiring is missing or ambiguous")
    spec = json.loads("{}") if False else None
    import yaml
    contract = yaml.safe_load(text("openapi/corelink-v1.yaml"))
    assert_true("/v1/onboarding/dpa-accept" in contract.get("paths", {}), "DPA route missing from OpenAPI")
    docs = files("apps/docs", {".md", ".mdx"})
    ghost = [p for p in docs if "/v1/dpa/accept" in p.read_text(encoding="utf-8")]
    assert_true(not ghost, "phantom /v1/dpa/accept remains in published docs")


def verify_b117() -> None:
    route_parser_mutation_self_test()
    routes = executable_router_routes(text("crates/corelink-container/src/routes/customer/part-00.rs"))
    for route in ("/v1/customer/account/delete", "/v1/customer/account/export"):
        assert_true(routes.count(route) == 1, f"route wiring missing or ambiguous: {route}")
        docs = files("apps/docs", {".md", ".mdx"})
        assert_true(any(route in p.read_text(encoding="utf-8") for p in docs), f"documentation missing: {route}")


def verify_b120() -> None:
    assert_true(not (ROOT / "apps/docs/docs/reference/api/endpoints/post-v1-enterprise-inquire.mdx").exists(), "phantom enterprise page exists")
    for path in ("crates", "worker/src", "apps/docs", "openapi"):
        root = ROOT / path
        assert_true(root.is_dir(), f"explicit target missing: {path}")
        hits = [p for p in root.rglob("*") if p.is_file() and "/v1/enterprise/inquire" in p.read_text(encoding="utf-8", errors="replace")]
        assert_true(not hits, f"enterprise inquiry remains in published/source target: {path}")
    assert_true("corelink-enterprise-inquiry" not in text("crates/corelink-container/Cargo.toml"), "enterprise dependency remains")


def code_files() -> list[Path]:
    suffixes = {".rs", ".ts", ".tsx", ".py", ".js", ".jsx", ".mjs", ".c", ".h", ".cc", ".cpp", ".cxx", ".go", ".java", ".kt", ".kts", ".rb", ".php", ".swift", ".scala", ".cs"}
    result = [Path(line) for line in subprocess.check_output(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=ROOT, text=True).splitlines() if Path(line).suffix in suffixes and not any(part in {"node_modules", "target", ".open-next", ".wrangler"} for part in Path(line).parts)]
    assert_true(result, "code population is empty")
    return result


def verify_b126() -> None:
    population = code_files()
    # A zero result is meaningful only for a nonempty, closed Git-tracked
    # source population.  Empty or bypassed populations fail closed.
    assert_true(population, "code population is empty")
    oversized = [p for p in population if sum(1 for _ in (ROOT / p).open(encoding="utf-8")) > 1000]
    assert_true(not oversized, "file-size census found oversized code files: " + ", ".join(map(str, oversized)))
    print(f"done: closed code population has no files above 1000 lines ({len(population)} files)")


def verify_b130() -> None:
    result = subprocess.run([sys.executable, "scripts/validate_api_surface.py"], cwd=ROOT, stdout=subprocess.DEVNULL, check=False)
    assert_true(result.returncode == 0, "API surface validator failed")


def verify_b137() -> None:
    names = ("byok_kill_switch_drill_weekly", "byok_matrix_weekly", "dr-drill-monthly", "nightly", "perf-nightly")
    for name in names:
        lines = active_lines(f".github/workflows/{name}.yml")
        try:
            start = next(i for i, line in enumerate(lines) if line.strip() == "concurrency:")
        except StopIteration as error:
            raise CheckError(f"concurrency block missing: {name}") from error
        block = lines[start + 1 :]
        block = block[: next((i for i, line in enumerate(block) if line and not line.startswith((" ", "\t"))), len(block))]
        joined = "\n".join(block)
        assert_true("group:" in joined, f"concurrency group missing: {name}")
        assert_true("github.event_name" in joined and "github.ref" in joined, f"concurrency group is not event/ref scoped: {name}")


CHECKS = {
    "B-100": verify_b100, "B-109": verify_b109, "B-110": verify_b110, "B-111": verify_b111,
    "B-116": verify_b116, "B-117": verify_b117, "B-120": verify_b120, "B-126": verify_b126,
    "B-130": verify_b130, "B-137": verify_b137,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", choices=sorted(CHECKS), required=True)
    args = parser.parse_args()
    try:
        CHECKS[args.id]()
    except (CheckError, OSError, ValueError, KeyError) as error:
        print(f"B-155 batch-G {args.id}: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"B-155 batch-G {args.id}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
