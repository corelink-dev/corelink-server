#!/usr/bin/env python3
"""Verify the B-029 load gate's executable contract.

This is deliberately a small structural verifier.  The comparison itself is
exercised by ``tests/test_b029_load_gate.py``; this command makes the workflow
wiring and the backlog's open/done polarity executable as well.  AST contract
checks follow only conservatively reachable code, so dead ``if False`` bait
cannot stand in for the load gate.
"""

from __future__ import annotations

import argparse
import ast
import json
import operator
import re
import shlex
import textwrap
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/load-test-nightly.yml"
FOCUSED_PACK = ".github/workflows/b029-load-gate.yml"
COMPARATOR = "scripts/load-test-baseline-check.py"
SANITIZER = "scripts/sanitize_k6_summary.py"
TARGET_RECEIPT_VALIDATOR = "scripts/validate_load_target_receipt.py"
LIFECYCLE_AUTH = "scripts/staging_load_lifecycle_auth.py"
ADMISSION_HELPER = "tests/load/k6/lib/staging_load_admission.js"
ADMISSION_CALLS = {
    "tests/load/k6/byok-revoke-stampede.js": ("headers: adminHeaders()", 4),
    "tests/load/k6/cas-write-read.js": ("headers: casHeaders(", 2),
    "tests/load/k6/dsr-api.js": ("headers: dsrHeaders()", 2),
    "tests/load/k6/signup-orchestration.js": ("headers: signupHeaders(idemKey)", 2),
    "tests/load/k6/stripe-webhook-burst.js": ("headers: admissionHeaders({", 1),
    "tests/load/k6/scenarios/endurance-24h.js": ("headers: authHeaders(", 6),
}
OPERATOR_README = "tests/load/README.md"
COMPARE_STEP = "compare median vs stored baseline"
POPULATION_STEP = "classify scenario population"
CANONICAL_STAGING_HOST = "staging.corelink.humangr.com"
CANONICAL_STAGING_URL = f"https://{CANONICAL_STAGING_HOST}"
STALE_STAGING_HOST = "api-staging.corelink.humangr.com"
STAGING_HOST_VARIANTS = (
    STALE_STAGING_HOST,
    "api.staging.corelink.humangr.com",
    "dev.corelink.humangr.com",
)
HOSTNAME_SOURCES = (
    ".github/workflows/load-test-nightly.yml",
    "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json",
    "evidence/owner-actions/B-029/staging-load-gate.json",
    "docs/internal/secrets-checklist.md",
)
FOCUSED_PACK_REQUIRED_PATHS = (
    FOCUSED_PACK,
    WORKFLOW,
    COMPARATOR,
    SANITIZER,
    TARGET_RECEIPT_VALIDATOR,
    "scripts/verify_b029_load_gate.py",
    "tests/test_b029_load_gate.py",
)
EXPECTED_COMPARATOR = (
    "python3",
    "scripts/load-test-baseline-check.py",
    "--results-dir",
    "tests/load/results/current",
    "--baseline",
    "tests/load/baseline/k6-baseline.json",
    "--threshold",
    "${REGRESSION_THRESHOLD}",
    "--expected-scenarios",
    "${EXPECTED_SCENARIOS}",
)
PROTECTED_DISPATCH_GUARD = (
    "github.repository == 'HuGR-dev/corelink-server' && "
    "github.event_name == 'workflow_dispatch' && "
    "github.ref == 'refs/heads/main' && github.ref_protected"
)


@dataclass(frozen=True)
class _YamlStep:
    name: str
    line: int
    runs: tuple[str, ...]
    uses: tuple[str, ...]


def _yaml_run_blocks(lines: list[str]) -> tuple[str, ...]:
    """Extract literal YAML ``run: |`` blocks from one step section."""

    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent>\s*)run:\s*\|[+-]?\s*$", line)
        if not match:
            continue
        run_indent = len(match.group("indent"))
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= run_indent:
                break
            body.append(candidate)
        blocks.append(textwrap.dedent("\n".join(body)).strip("\n"))
    return tuple(blocks)


def _yaml_steps(workflow: str) -> tuple[_YamlStep, ...]:
    """Read step names, run blocks, and uses keys without trusting prose."""

    lines = workflow.splitlines()
    starts: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent>\s*)-\s+name:\s*(?P<name>.+?)\s*$", line)
        if match:
            starts.append((index, len(match.group("indent")), match.group("name")))
    steps: list[_YamlStep] = []
    for offset, (start, indent, name) in enumerate(starts):
        end = len(lines)
        for candidate, candidate_indent, _ in starts[offset + 1 :]:
            if candidate_indent <= indent:
                end = candidate
                break
        section = lines[start:end]
        uses = tuple(
            match.group(1)
            for line in section
            if (match := re.match(r"^\s*uses:\s*([^\s#]+)", line))
        )
        steps.append(
            _YamlStep(
                name=name,
                line=start,
                runs=_yaml_run_blocks(section),
                uses=uses,
            )
        )
    return tuple(steps)


def _pull_request_path_filters(workflow: str) -> set[str]:
    """Return only literal entries under the top-level pull_request.paths key."""

    lines = workflow.splitlines()
    event_index = next(
        (
            index
            for index, line in enumerate(lines)
            if re.fullmatch(r"  pull_request:\s*", line)
        ),
        None,
    )
    if event_index is None:
        return set()

    paths_index = next(
        (
            index
            for index in range(event_index + 1, len(lines))
            if lines[index].strip()
            and len(lines[index]) - len(lines[index].lstrip()) <= 2
        ),
        len(lines),
    )
    for index in range(event_index + 1, paths_index):
        if re.fullmatch(r"    paths:\s*", lines[index]):
            paths_index = index
            break
    else:
        return set()

    paths: set[str] = set()
    for line in lines[paths_index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= 4:
            break
        match = re.fullmatch(r'      -\s*"([^\"]+)"\s*', line)
        if match:
            paths.add(match.group(1))
    return paths


def _shell_tokens(source: str) -> list[str]:
    lexer = shlex.shlex(source, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def _without_heredoc_bodies(source: str) -> str:
    """Remove heredoc payloads so text in them is not executable evidence."""

    pending: list[tuple[str, bool]] = []
    kept: list[str] = []
    for line in source.splitlines():
        if pending:
            candidate = line.lstrip("\t") if pending[0][1] else line
            if candidate.strip() == pending[0][0]:
                pending.pop(0)
            continue
        kept.append(line)
        try:
            tokens = _shell_tokens(line)
        except ValueError:
            continue
        for index, token in enumerate(tokens[:-1]):
            if token != "<<":
                continue
            delimiter = tokens[index + 1]
            strip_tabs = delimiter.startswith("-")
            if strip_tabs:
                delimiter = delimiter[1:]
            if delimiter and delimiter not in {";", "&", "|"}:
                pending.append((delimiter, strip_tabs))
    return "\n".join(kept)


def _split_shell_commands(source: str) -> list[list[str]]:
    """Tokenize shell commands while retaining simple-command boundaries."""

    try:
        # A physical newline terminates a shell command unless escaped.  Turn
        # those boundaries into the same separator used by ``;`` before
        # tokenizing; this also keeps a five-line continued invocation one
        # command while preventing ``set -e`` from swallowing the next line.
        shell = _without_heredoc_bodies(source)
        shell = shell.replace("\\\n", " ").replace("\n", ";")
        tokens = _shell_tokens(shell)
    except ValueError:
        return []
    commands: list[list[str]] = []
    command: list[str] = []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&", "(", ")"}:
            if command:
                commands.append(command)
                command = []
        else:
            command.append(token)
    if command:
        commands.append(command)
    return commands


def _false_shell_condition(tokens: list[str]) -> bool | None:
    if tokens in (["false"], [":"]):
        return tokens == [":"]
    if len(tokens) == 5 and tokens[0] in {"[", "test"} and tokens[-1] == "]":
        left, operator_name, right = tokens[1:4]
        if operator_name in {"=", "==", "-eq"}:
            return left == right
        if operator_name in {"!=", "-ne"}:
            return left != right
    return None


def _active_shell_commands(source: str) -> tuple[tuple[str, ...], ...]:
    """Return executable simple commands, excluding comments/strings/heredocs."""

    commands = _split_shell_commands(source)
    active_branches: list[bool | None] = []
    found: list[tuple[str, ...]] = []
    reserved = {"if", "then", "else", "elif", "fi", "do", "done", "for", "in", "while", "until", "{", "}"}

    for command in commands:
        if not command:
            continue
        first = command[0]
        if first == "if":
            condition = command[1:]
            if "then" in condition:
                condition = condition[:condition.index("then")]
            active_branches.append(_false_shell_condition(condition))
            continue
        if first == "else" and active_branches:
            state = active_branches[-1]
            active_branches[-1] = None if state is None else not state
            continue
        if first == "elif" and active_branches:
            condition = command[1:]
            if "then" in condition:
                condition = condition[:condition.index("then")]
            active_branches[-1] = _false_shell_condition(condition)
            continue
        if first == "fi":
            if active_branches:
                active_branches.pop()
            continue
        if active_branches and False in active_branches:
            continue
        while command and ("=" in command[0] and not command[0].startswith("-")):
            command = command[1:]
        while command and command[0] in reserved:
            command = command[1:]
        if command:
            found.append(tuple(command))
    return tuple(found)


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )


def _static_truth(test: ast.AST) -> bool | None:
    """Evaluate only conditions that are statically and safely decidable."""

    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        value = _static_truth(test.operand)
        return None if value is None else not value
    if isinstance(test, ast.BoolOp):
        values = [_static_truth(value) for value in test.values]
        if isinstance(test.op, ast.And):
            if any(value is False for value in values):
                return False
            return True if all(value is True for value in values) else None
        if any(value is True for value in values):
            return True
        return False if all(value is False for value in values) else None
    if isinstance(test, ast.Compare):
        try:
            values = [ast.literal_eval(test.left)] + [
                ast.literal_eval(comparator) for comparator in test.comparators
            ]
        except (ValueError, TypeError, SyntaxError, MemoryError):
            return None
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
            ast.In: lambda left, right: left in right,
            ast.NotIn: lambda left, right: left not in right,
        }
        results: list[bool] = []
        for index, comparison in enumerate(test.ops):
            operation = next(
                (fn for kind, fn in operations.items() if isinstance(comparison, kind)),
                None,
            )
            if operation is None:
                return None
            try:
                results.append(operation(values[index], values[index + 1]))
            except (TypeError, ValueError, KeyError):
                return None
        return all(results)
    try:
        return bool(ast.literal_eval(test))
    except (ValueError, TypeError, SyntaxError, MemoryError):
        return None


def _block_terminates(statements: list[ast.stmt]) -> bool:
    """Whether every path through a small statement block terminates."""

    for statement in statements:
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True
        if isinstance(statement, ast.If):
            truth = _static_truth(statement.test)
            if truth is True and _block_terminates(statement.body):
                return True
            if truth is False and _block_terminates(statement.orelse):
                return True
            if truth is None and statement.orelse:
                if _block_terminates(statement.body) and _block_terminates(statement.orelse):
                    return True
    return False


def _reachable_nodes(function: ast.AST) -> list[ast.AST]:
    """Collect AST nodes that can execute in *function*.

    Unknown predicates retain both branches. Constant-false/zero/always-false
    branches are omitted, and statements after unconditional return/raise are
    not considered live. Nested function/class bodies are declarations, not
    executable implementations of the target function.
    """

    nodes: list[ast.AST] = []

    def visit(node: ast.AST, *, descend_function: bool = False) -> None:
        nodes.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if descend_function:
                visit_block(node.body)
            return
        if isinstance(node, ast.ClassDef):
            return
        if isinstance(node, ast.If):
            visit(node.test)
            truth = _static_truth(node.test)
            if truth is True:
                visit_block(node.body)
            elif truth is False:
                visit_block(node.orelse)
            else:
                visit_block(node.body)
                visit_block(node.orelse)
            return
        if isinstance(node, ast.While):
            visit(node.test)
            truth = _static_truth(node.test)
            if truth is False:
                visit_block(node.orelse)
            elif truth is True:
                visit_block(node.body)
            else:
                visit_block(node.body)
                visit_block(node.orelse)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.target)
            visit(node.iter)
            visit_block(node.body)
            visit_block(node.orelse)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                visit(item)
            visit_block(node.body)
            return
        if isinstance(node, ast.Try):
            visit_block(node.body)
            for handler in node.handlers:
                if handler.type is not None:
                    visit(handler.type)
                visit_block(handler.body)
            visit_block(node.orelse)
            visit_block(node.finalbody)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.type is not None:
                visit(node.type)
            visit_block(node.body)
            return
        if isinstance(node, ast.Match):
            visit(node.subject)
            for case in node.cases:
                if case.guard is not None:
                    visit(case.guard)
                visit_block(case.body)
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    def visit_block(statements: list[ast.stmt]) -> None:
        for statement in statements:
            visit(statement)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break
            if isinstance(statement, ast.If):
                truth = _static_truth(statement.test)
                if (
                    (truth is True and _block_terminates(statement.body))
                    or (truth is False and _block_terminates(statement.orelse))
                    or (
                        truth is None
                        and statement.orelse
                        and _block_terminates(statement.body)
                        and _block_terminates(statement.orelse)
                    )
                ):
                    break

    visit(function, descend_function=True)
    return nodes


def _calls(function: ast.AST, name: str) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
        for node in _reachable_nodes(function)
    )


def _rglob(function: ast.AST, filename: str) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "rglob"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == filename
        for node in _reachable_nodes(function)
    )


def _string_constants(function: ast.AST) -> set[str]:
    """Return executable string literals, excluding docstrings/comments."""
    values: set[str] = set()
    parents = {
        child: node
        for node in _reachable_nodes(function)
        for child in ast.iter_child_nodes(node)
    }
    for node in _reachable_nodes(function):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Expr) and parent.value is node:
            continue
        values.add(node.value)
    return values


def _set_population_check(function: ast.AST, variable: str) -> bool:
    return any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Call)
        and isinstance(node.left.func, ast.Name)
        and node.left.func.id == "set"
        and len(node.left.args) == 1
        and isinstance(node.left.args[0], ast.Name)
        and node.left.args[0].id == variable
        and any(
            isinstance(comparator, ast.Name) and comparator.id == "expected"
            for comparator in node.comparators
        )
        for node in _reachable_nodes(function)
    )


def _comparison(function: ast.AST, left: str, right: str) -> bool:
    return any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == left
        and any(
            isinstance(comparator, ast.Name) and comparator.id == right
            for comparator in node.comparators
        )
        for node in _reachable_nodes(function)
    )


def _raises(function: ast.AST, name: str) -> bool:
    return any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == name
        for node in _reachable_nodes(function)
    )


def _hostname_gaps(root: Path) -> list[str]:
    """Require exact agreement across the executable B-029 target sources.

    This validates naming only. It deliberately does not assert that staging
    is deployed or reachable; the receipt remains the parked/unresolved proof.
    """

    gaps: list[str] = []
    paths = {relative: root / relative for relative in HOSTNAME_SOURCES}
    texts: dict[str, str] = {}
    for relative, path in paths.items():
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except OSError as exc:
            gaps.append(f"B-029 hostname source unreadable ({relative}): {exc}")

    workflow = texts.get(WORKFLOW)
    if workflow is not None:
        target_match = re.search(
            r"CANONICAL_TARGET\s*=\s*(['\"])(?P<url>[^'\"]+)\1", workflow
        )
        if target_match is None or target_match.group("url") != CANONICAL_STAGING_URL:
            observed = target_match.group("url") if target_match else "missing"
            gaps.append(
                f"B-029 workflow target must equal {CANONICAL_STAGING_URL}; "
                f"observed {observed}"
            )
        if 'TARGET_HOST="${K6_TARGET_HOST%/}"' not in workflow:
            gaps.append("B-029 workflow must explicitly normalize one trailing slash")
        if 'K6_TARGET_HOST:        ${{ steps.target_host.outputs.target_host }}' not in workflow:
            gaps.append("B-029 runtime must consume the exact pre-flight target output")

    packet_relative = "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json"
    packet = texts.get(packet_relative)
    if packet is not None:
        try:
            packet_data = json.loads(packet)
            b029 = next(item for item in packet_data["items"] if item.get("id") == "B-029")
            procedure = b029["procedure"][0]
            match = re.search(r"for ([^ ]+) and the staging environment", procedure)
            observed = match.group(1) if match else "missing"
            if observed != CANONICAL_STAGING_HOST:
                gaps.append(
                    f"B-029 packet target must equal {CANONICAL_STAGING_HOST}; "
                    f"observed {observed}"
                )
        except (KeyError, IndexError, StopIteration, TypeError, json.JSONDecodeError) as exc:
            gaps.append(f"B-029 packet target is not parseable: {exc}")

    receipt_relative = "evidence/owner-actions/B-029/staging-load-gate.json"
    receipt = texts.get(receipt_relative)
    if receipt is not None:
        try:
            observed = json.loads(receipt).get("target_host")
        except json.JSONDecodeError as exc:
            observed = f"unparseable ({exc})"
        if observed != CANONICAL_STAGING_HOST:
            gaps.append(
                f"B-029 receipt target must equal {CANONICAL_STAGING_HOST}; "
                f"observed {observed}"
            )

    checklist_relative = "docs/internal/secrets-checklist.md"
    checklist = texts.get(checklist_relative)
    if checklist is not None:
        row = next(
            (line for line in checklist.splitlines() if line.startswith("| 101 |")),
            "",
        )
        urls = re.findall(r"https://[A-Za-z0-9.-]+", row)
        observed = urls[0] if urls else "missing"
        if observed != CANONICAL_STAGING_URL:
            gaps.append(
                f"B-029 checklist target must equal {CANONICAL_STAGING_URL}; "
                f"observed {observed}"
            )

    for relative, text in texts.items():
        for variant in STAGING_HOST_VARIANTS:
            if variant in text:
                gaps.append(f"B-029 hostname drift in {relative}: {variant}")
    return gaps


def admission_client_gaps(root: Path) -> list[str]:
    """Prove every workload HTTP operation obtains a fresh v2 header."""
    gaps: list[str] = []
    try:
        helper = (root / ADMISSION_HELPER).read_text(encoding="utf-8")
        lifecycle = (root / LIFECYCLE_AUTH).read_text(encoding="utf-8")
    except OSError as exc:
        return [f"admission helper is unreadable: {exc}"]
    for marker in (
        "corelink/staging-load-admission-auth/v2\\0",
        "crypto.randomBytes(32)",
        "crypto.hmac('sha256', KEY, DOMAIN + payload, 'hex')",
        "ADMISSION_GOLDEN_VECTOR_V2",
    ):
        if marker not in helper:
            gaps.append(f"v2 k6 signer is missing {marker}")
    for marker in ("GOLDEN_V1", "GOLDEN_V2", "validate_seal_receipt", "sum(resources.values()) > 256"):
        if marker not in lifecycle:
            gaps.append(f"lifecycle helper is missing {marker}")
    for relative, (header_expression, expected_calls) in ADMISSION_CALLS.items():
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except OSError as exc:
            gaps.append(f"workload source is unreadable: {relative}: {exc}")
            continue
        if "staging_load_admission.js" not in source:
            gaps.append(f"workload source does not import request signer: {relative}")
        if "K6_AUTH_BEARER" in source or "authorization:" in source:
            gaps.append(f"legacy static workload auth remains in {relative}")
        if source.count(header_expression) != expected_calls:
            gaps.append(f"fresh admission call census mismatch in {relative}")
    endurance = (root / "tests/load/k6/scenarios/endurance-24h.js").read_text(encoding="utf-8")
    if endurance.count("headers: admissionHeaders({") != 1:
        gaps.append("endurance memory poll does not mint exactly one fresh admission header")
    return gaps


def assess(root: Path, *, expect: str) -> list[str]:
    gaps: list[str] = []
    workflow_path = root / WORKFLOW
    focused_pack_path = root / FOCUSED_PACK
    comparator_path = root / COMPARATOR
    readme_path = root / OPERATOR_README
    try:
        workflow = workflow_path.read_text(encoding="utf-8")
        focused_pack = focused_pack_path.read_text(encoding="utf-8")
        comparator = comparator_path.read_text(encoding="utf-8")
        sanitizer = (root / SANITIZER).read_text(encoding="utf-8")
        readme = readme_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"instrument error: {exc}"]

    focused_pack_paths = _pull_request_path_filters(focused_pack)
    missing_pack_paths = sorted(set(FOCUSED_PACK_REQUIRED_PATHS) - focused_pack_paths)
    if missing_pack_paths:
        gaps.append(
            "focused B-029 CI pack does not trigger for required inputs: "
            + ", ".join(missing_pack_paths)
        )

    if "BASELINE_SCHEMA = 2" not in comparator or 'BASELINE_VERSION = "k6-baseline-v2"' not in comparator:
        gaps.append("baseline schema/version is not explicit")
    if 'DEFAULT_REGRESSION_THRESHOLD = 1.20' not in comparator or "threshold_multiplier" not in comparator:
        gaps.append("baseline threshold is not explicit")
    if 'SUITE_VERSION = "r3-prep-v2"' not in comparator or 'SUITE_VERSION = "r3-prep-v2"' not in sanitizer:
        gaps.append("load suite version is not explicit")
    for needle in (
        "sanitize_k6_summary.py",
        "summary.raw.json",
        "--summary-export tests/load/results/${{ matrix.scenario.id }}/summary.raw.json",
    ):
        if needle not in workflow:
            gaps.append(f"workflow does not require sanitized summaries: {needle}")

    gaps.extend(_hostname_gaps(root))
    if (root / ADMISSION_HELPER).exists():
        gaps.extend(admission_client_gaps(root))

    # The gate must compare the current run with a prior cached baseline and
    # publish only after a successful comparison.  These checks are intentionally
    # anchored to the executable command/action, not to prose in the header.
    if workflow.count("runs-on: ubuntu-24.04") != 2:
        gaps.append("both load jobs must run on ubuntu-24.04")
    if workflow.count(PROTECTED_DISPATCH_GUARD) != 2:
        gaps.append("both load jobs must require the canonical protected manual dispatch")
    if "actions/cache/restore@" not in workflow or "restore-keys:" not in workflow:
        gaps.append("previous baseline is not restored by cache prefix")
    steps = _yaml_steps(workflow)
    population_steps = [step for step in steps if step.name == POPULATION_STEP]
    if len(population_steps) != 1 or len(population_steps[0].runs) != 1:
        gaps.append("workflow must contain exactly one literal scenario population classifier")
    else:
        population_run = population_steps[0].runs[0]
        population_commands = _active_shell_commands(population_run)
        if not any(command[:2] == ("exit", "1") for command in population_commands):
            gaps.append("scenario population classifier must fail closed")
        if "duplicate scenario" not in population_run:
            gaps.append("scenario population classifier does not reject duplicates")
        if "partial dispatches are invalid" not in population_run:
            gaps.append("scenario population classifier does not reject partial input")
        if "non-empty comma-separated population" not in population_run:
            gaps.append("scenario population classifier does not reject empty input")
        if any(command[:2] == ("sort", "-u") for command in population_commands):
            gaps.append("scenario population classifier collapses duplicate input")
        if "full=false" in population_run or "diagnostic-only" in population_run:
            gaps.append("partial scenario input remains a green diagnostic path")
    compare_steps = [step for step in steps if step.name == COMPARE_STEP]
    if len(compare_steps) != 1 or len(compare_steps[0].runs) != 1:
        gaps.append("workflow must contain exactly one literal comparator run block")
    else:
        compare_step = compare_steps[0]
        compare_run = compare_step.runs[0]
        invocations = _active_shell_commands(compare_run)
        comparator_invocations = [
            command
            for command in invocations
            if command and command[0] == "python3"
        ]
        if len(comparator_invocations) != 1:
            gaps.append(
                "comparison run block must contain exactly one active comparator invocation"
            )
        elif comparator_invocations[0] != EXPECTED_COMPARATOR:
            gaps.append("comparator invocation flags or values are not exact")
        comparator_index = next(
            index
            for index, command in enumerate(invocations)
            if command == comparator_invocations[0]
        ) if comparator_invocations else -1
        if not any(
            index < comparator_index
            and command[:3] == ("set", "-euo", "pipefail")
            for index, command in enumerate(invocations)
        ):
            gaps.append("comparison step is not fail-closed shell")
        save_after = any(
            step.line > compare_step.line
            and any(uses.startswith("actions/cache/save@") for uses in step.uses)
            for step in steps
        )
        if not save_after:
            gaps.append("baseline is not saved after the comparison")
    if not any(
        any(uses.startswith("actions/cache/save@") for uses in step.uses)
        for step in steps
    ):
        gaps.append("new baseline is not persisted")
    if "BASELINE_CACHE_PREFIX }}-" not in workflow:
        gaps.append("cache restore is not scoped to the baseline prefix")
    if workflow.count("persist-credentials: false") != 2:
        gaps.append("both checkouts must disable credential persistence")
    if "K6_TARGET_HOST" not in workflow or "exit 1" not in workflow:
        gaps.append("missing staging target is not a hard pre-flight failure")
    if "dispatch-only until staging is provisioned" not in readme:
        gaps.append("operator README overclaims that staging load tests are live")
    if "Until then it is dispatch-only" not in readme:
        gaps.append("operator README does not state the disabled-schedule truth")

    # Inspect the comparator's AST rather than raw source strings.  A string
    # or comment containing `status.json` / `collect_statuses` is not evidence
    # that the executable path enforces the contract.
    try:
        tree = ast.parse(comparator, filename=str(comparator_path))
    except SyntaxError as exc:
        gaps.append(f"comparator is not valid Python: {exc}")
    else:
        current_fn = _function(tree, "collect_current")
        statuses_fn = _function(tree, "collect_statuses")
        # The identity-bound comparator's executable loader is
        # ``load_baseline_record``.  Keep accepting the compatibility
        # ``load_baseline`` view for older trees, but inspect and require the
        # record loader whenever it is present so the target identity and
        # threshold checks remain part of the verified path.
        baseline_name = (
            "load_baseline_record"
            if _function(tree, "load_baseline_record") is not None
            else "load_baseline"
        )
        baseline_fn = _function(tree, baseline_name)
        main_fn = _function(tree, "main")
        if current_fn is None:
            gaps.append("comparator has no executable collect_current function")
        else:
            current_strings = _string_constants(current_fn)
            if not _rglob(current_fn, "summary.json"):
                gaps.append("collect_current does not enumerate k6 summary artifacts")
            if not _set_population_check(current_fn, "out"):
                gaps.append("collect_current does not enforce the exact scenario population")
            if "http_req_duration" not in current_strings or "p(99)" not in current_strings:
                gaps.append("collect_current does not validate the k6 duration metrics")
        if statuses_fn is None:
            gaps.append("comparator has no executable collect_statuses function")
        else:
            statuses_strings = _string_constants(statuses_fn)
            if not _rglob(statuses_fn, "status.json"):
                gaps.append("collect_statuses does not enumerate matrix status artifacts")
            if "success" not in statuses_strings or not _set_population_check(statuses_fn, "statuses"):
                gaps.append("collect_statuses does not require an exact successful population")
        if baseline_fn is None:
            gaps.append(f"comparator has no executable {baseline_name} function")
        else:
            if not _raises(baseline_fn, "BaselineError"):
                gaps.append("missing or malformed baseline is not fail-closed")
            baseline_strings = _string_constants(baseline_fn)
            if "captured_at" not in baseline_strings or "commit" not in baseline_strings:
                gaps.append("baseline provenance does not require captured_at and commit")
        if main_fn is None:
            gaps.append("comparator has no executable main function")
        else:
            required_calls = ("collect_statuses", "collect_current", baseline_name)
            for call in required_calls:
                if not _calls(main_fn, call):
                    gaps.append(f"main does not execute {call}")
            main_names = {
                node.id for node in _reachable_nodes(main_fn) if isinstance(node, ast.Name)
            }
            if "expected_set" not in main_names or "InputError" not in main_names:
                gaps.append("main does not require an explicit expected scenario set")
            if not _comparison(main_fn, "cur_med", "limit"):
                gaps.append("main does not compare current median against the threshold")
            comparator_names = {
                node.id for node in _reachable_nodes(main_fn) if isinstance(node, ast.Name)
            }
            if "EXIT_REGRESSION" not in comparator_names or "EXIT_USAGE" not in comparator_names:
                gaps.append("main does not expose distinct regression and input failures")
            if not _calls(main_fn, "write_baseline"):
                gaps.append("main does not persist a passing baseline")

    active_cron = any(
        re.match(r"^\s*-\s*cron:", line) and not line.lstrip().startswith("#")
        for line in workflow.splitlines()
    )
    if expect in {"open", "parked"} and active_cron:
        gaps.append(f"{expect} B-029 cannot have an active nightly schedule")
    if expect == "done" and not active_cron:
        gaps.append("done B-029 requires the nightly schedule to be enabled")
    return gaps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--expect", choices=("open", "parked", "done"), required=True)
    args = parser.parse_args(argv)
    gaps = assess(args.root, expect=args.expect)
    state = "open" if gaps and args.expect != "parked" else ("parked" if args.expect == "parked" else args.expect)
    print(f"B-029 {state}: {len(gaps)} gap(s)")
    for gap in gaps:
        print(f"- {gap}")
    return 0 if not gaps else 1


if __name__ == "__main__":
    raise SystemExit(main())
