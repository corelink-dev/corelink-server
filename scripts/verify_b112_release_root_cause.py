#!/usr/bin/env python3
"""Fail-closed static gate for the engineering-owned B-112 release fix.

The historical Actions logs are expired, so this gate does not pretend that a
live release is green.  It proves the bounded claim we can make from the
workflow bytes and the repository's deterministic reproduction: the old
source-install/shared-home race is removed from ``release-cli`` while the
former OCI/Cosign lane remains retired under B-118.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
import posixpath
import re
import shlex
import stat
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ".github/workflows/release-cli.yml"
COSIGN = ".github/workflows/cosign-sign.yml"
BACKLOG = "BACKLOG.md"
# This marker belongs to the former B-118 lane.  It is retained only as a
# negative control: a retired workflow must not silently bring its old waiver
# back into the B-112 release contract.
RETIRED_WAIVER = "authorized-by: repo owner | 2026-08-11"
CARGO_HOME_BINDING = 'CARGO_HOME="${RUNNER_TEMP}/corelink-cargo/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"'
CARGO_TARGET_BINDING = 'CARGO_TARGET_DIR="${RUNNER_TEMP}/corelink-target/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"'
ZIGBUILD_CACHE_BINDING = 'ZIGBUILD_CACHE="${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"'
ARTIFACT_PATH = 'SRC="${CARGO_TARGET_DIR}/${TARGET_TRIPLE}/release/corelink"'
CARGO_HOME_VALUE = "${RUNNER_TEMP}/corelink-cargo/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"
CARGO_TARGET_VALUE = "${RUNNER_TEMP}/corelink-target/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"
ZIGBUILD_CACHE_VALUE = "${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"
ARTIFACT_VALUE = "${CARGO_TARGET_DIR}/${TARGET_TRIPLE}/release/corelink"
MAX_INPUT_BYTES = 2_000_000
_YAML_LOADER = getattr(yaml, "CLoader", yaml.Loader)


class B112InputError(RuntimeError):
    """An input cannot be safely interpreted, so the gate must stay red."""


def _strip_shell_comment(line: str) -> str:
    """Remove a shell comment without interpreting # inside shell quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _active_lines(text: str) -> list[str]:
    """Return workflow lines with full-line and inline YAML comments removed."""
    lines: list[str] = []
    for line in text.splitlines():
        line = _strip_shell_comment(line)
        if not line.strip():
            continue
        lines.append(line)
    return lines


def _yaml_root(text: str) -> yaml.nodes.Node:
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise B112InputError("workflow input exceeds bounded parser size")
    try:
        # The release workflow is large and each mutation is intentionally
        # parsed as an independent input.  PyYAML's pure-Python scanner made
        # that fail-closed population dominate the focal timeout; libyaml is
        # the same parser/AST contract with bounded native traversal.
        node = yaml.compose(text, Loader=_YAML_LOADER)
    except yaml.YAMLError as exc:
        raise B112InputError(f"invalid workflow YAML: {exc}") from exc
    if node is None:
        raise B112InputError("workflow YAML is empty")
    return node


def _walk_yaml(node: yaml.nodes.Node, seen: set[int] | None = None):
    """Walk YAML aliases once so adversarial anchors cannot recurse forever."""
    if seen is None:
        seen = set()
    if id(node) in seen:
        return
    seen.add(id(node))
    yield node
    if isinstance(node, yaml.nodes.MappingNode):
        for key, value in node.value:
            yield from _walk_yaml(key, seen)
            yield from _walk_yaml(value, seen)
    elif isinstance(node, yaml.nodes.SequenceNode):
        for child in node.value:
            yield from _walk_yaml(child, seen)


@lru_cache(maxsize=8)
def _run_blocks(text: str) -> list[tuple[int, list[str]]]:
    """Extract semantic YAML ``run`` scalars, never commented/string bait."""
    root = _yaml_root(text)
    blocks: list[tuple[int, list[str]]] = []
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, value in node.value:
            if key.value != "run" or not isinstance(value, yaml.nodes.ScalarNode):
                continue
            first_line = key.start_mark.line + 2
            blocks.append((first_line, value.value.splitlines()))
    if not blocks:
        raise B112InputError("workflow has no semantic run blocks")
    return blocks


def _has_continuation(line: str) -> bool:
    stripped = line.rstrip()
    slashes = len(stripped) - len(stripped.rstrip("\\"))
    return bool(slashes % 2)


@lru_cache(maxsize=8)
def _logical_shell_lines(text: str) -> list[tuple[int, str]]:
    """Join shell backslash continuations before tokenization."""
    logical: list[tuple[int, str]] = []
    for first_line, block in _run_blocks(text):
        pending: str | None = None
        pending_line = first_line
        heredoc_end: str | None = None
        heredoc_closure = False
        for offset, raw in enumerate(block):
            line = raw.rstrip()
            if heredoc_end is not None:
                if line.strip() == heredoc_end:
                    if heredoc_closure:
                        heredoc_end = "__B112_HEREDOC_CLOSURE__"
                        heredoc_closure = False
                    else:
                        heredoc_end = None
                elif heredoc_end == "__B112_HEREDOC_CLOSURE__":
                    if re.fullmatch(r"\)?[\"']?", line.strip()):
                        heredoc_end = None
                continue
            heredoc = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_-]*)['\"]?", line)
            if heredoc is not None:
                # The heredoc payload is a different language.  Retain a
                # parseable shell prefix when possible, then skip its body.
                prefix = line[:heredoc.start()].rstrip()
                if prefix:
                    try:
                        if _shell_tokens(prefix):
                            logical.append((first_line + offset, prefix))
                    except B112InputError:
                        pass
                heredoc_end = heredoc.group(1)
                heredoc_closure = "$((" in prefix or "$($(" in prefix or "$ (" in prefix or "$(" in prefix
                pending = None
                continue
            if pending is None:
                pending = line
                pending_line = first_line + offset
            else:
                pending += " " + line.lstrip()
            if _has_continuation(line):
                pending = pending.rstrip("\\").rstrip()
                continue
            if _strip_shell_comment(pending).strip():
                logical.append((pending_line, pending))
            pending = None
        if pending is not None:
            if _strip_shell_comment(pending).strip():
                logical.append((pending_line, pending))
        if heredoc_end is not None:
            raise B112InputError("unclosed heredoc in workflow run block")
    return logical


def _shell_tokens(line: str) -> list[str]:
    line = _strip_shell_comment(line).strip()
    if not line:
        return []
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError as exc:
        raise B112InputError(f"invalid shell quoting in workflow line: {line!r}") from exc


@lru_cache(maxsize=8)
def _shell_commands(text: str) -> list[tuple[int, list[str]]]:
    commands: list[tuple[int, list[str]]] = []
    operators = {";", "&&", "||", "|", "&"}
    for line, raw in _logical_shell_lines(text):
        segment: list[str] = []
        for token in _shell_tokens(raw) + [";"]:
            if token in operators:
                if segment:
                    commands.append((line, segment))
                    segment = []
            else:
                segment.append(token)
    return commands


def _active_shell_lines(text: str) -> list[str]:
    return [raw for _line, raw in _logical_shell_lines(text)]


_ASSIGNMENT = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$")
_CONTROL = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case", "esac"}
_SHELL_WRAPPERS = {"bash", "sh", "dash", "zsh", "ksh"}


def _basename(executable: str) -> str:
    return executable.rsplit("/", 1)[-1]


def _skip_sudo_options(tokens: list[str], index: int) -> int:
    options_with_arg = {"-u", "--user", "-g", "--group", "-C", "--chdir", "-h", "--host"}
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        index += 1
        if option in options_with_arg and index < len(tokens):
            index += 1
    return index


def _unwrap_command(command: list[str]) -> tuple[list[tuple[str, str]], str | None, list[str]]:
    """Normalize assignments and common sudo/env/shell wrappers."""
    index = 0
    assignments: list[tuple[str, str]] = []
    while index < len(command) and command[index] in _CONTROL:
        index += 1
    if index < len(command) and command[index] == "!":
        index += 1
    while index < len(command):
        match = _ASSIGNMENT.fullmatch(command[index])
        if not match:
            break
        assignments.append((match.group("name"), match.group("value")))
        index += 1
    while index < len(command):
        executable = _basename(command[index])
        if executable == "sudo":
            index = _skip_sudo_options(command, index + 1)
            continue
        if executable in {"command", "exec", "nice", "nohup", "setsid"}:
            index += 1
            continue
        if executable == "timeout":
            index = _skip_sudo_options(command, index + 1)
            if index < len(command) and not command[index].startswith("-"):
                index += 1
            continue
        if executable == "env":
            index += 1
            while index < len(command):
                token = command[index]
                if token == "--":
                    index += 1
                    while index < len(command):
                        match = _ASSIGNMENT.fullmatch(command[index])
                        if not match:
                            break
                        assignments.append((match.group("name"), match.group("value")))
                        index += 1
                    break
                if token in {"-i", "--ignore-environment"}:
                    index += 1
                    continue
                if token in {"-S", "--split-string"}:
                    if index + 1 >= len(command):
                        raise B112InputError("env -S is missing its command string")
                    split_string = command[index + 1]
                    if "$" in split_string or "`" in split_string:
                        raise B112InputError("dynamic env -S command cannot be proven safe")
                    nested = _shell_tokens(split_string)
                    nested_assignments, nested_executable, nested_args = _unwrap_command(nested)
                    return assignments + nested_assignments, nested_executable, nested_args
                if token in {"-u", "--unset"} and index + 1 < len(command):
                    index += 2
                    continue
                match = _ASSIGNMENT.fullmatch(token)
                if not match:
                    break
                assignments.append((match.group("name"), match.group("value")))
                index += 1
            continue
        if executable in _SHELL_WRAPPERS:
            try:
                c_index = next(
                    i for i in range(index + 1, len(command))
                    if command[i] == "-c" or (
                        command[i].startswith("-") and "c" in command[i][1:]
                    )
                )
            except StopIteration:
                return assignments, executable, command[index + 1:]
            if c_index + 1 >= len(command):
                raise B112InputError(f"{executable} -c is missing its command string")
            split_string = command[c_index + 1]
            if "$" in split_string or "`" in split_string:
                raise B112InputError("dynamic shell -c indirection cannot be proven safe")
            nested = _shell_tokens(split_string)
            nested_assignments, nested_executable, nested_args = _unwrap_command(nested)
            return assignments + nested_assignments, nested_executable, nested_args
        return assignments, executable, command[index + 1:]
    return assignments, None, []


@lru_cache(maxsize=8)
def _active_assignments(text: str) -> list[tuple[int, str, str]]:
    assignments: list[tuple[int, str, str]] = []
    for line, command in _shell_commands(text):
        prefix, executable, args = _unwrap_command(command)
        assignments.extend((line, name, value) for name, value in prefix)
        if executable == "export":
            for token in args:
                match = _ASSIGNMENT.fullmatch(token)
                if match:
                    assignments.append((line, match.group("name"), match.group("value")))
    return assignments


def _normalize_path(value: str) -> str:
    """Canonicalize shell path spellings without resolving runtime variables."""
    value = value.replace("${HOME}", "/__HOME__").replace("$HOME", "/__HOME__")
    value = re.sub(r"(?<!:)//+", "/", value)
    value = re.sub(r"(^|/)\./", r"\1", value)
    if value.startswith("~/"):
        value = "/__HOME__/" + value[2:]
    return posixpath.normpath(value)


def _shared_cargo_path(value: str) -> bool:
    normalized = _normalize_path(value)
    return normalized.startswith(("/__HOME__/.cargo", "/__HOME__/target"))


@lru_cache(maxsize=16)
def _active_commands(text: str, executable: str) -> list[tuple[int, list[str]]]:
    return [
        (line, args)
        for line, command in _shell_commands(text)
        for _prefix, actual, args in [_unwrap_command(command)]
        if actual == executable
    ]


def _block_for_line(text: str, line_number: int) -> int | None:
    for block_number, (first_line, block) in enumerate(_run_blocks(text)):
        if first_line <= line_number < first_line + len(block):
            return block_number
    return None


@lru_cache(maxsize=8)
def _active_yaml_env_values(text: str) -> list[tuple[int, str, str]]:
    values: list[tuple[int, str, str]] = []
    root = _yaml_root(text)
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, value in node.value:
            if key.value != "env" or not isinstance(value, yaml.nodes.MappingNode):
                continue
            for env_key, env_value in value.value:
                if env_key.value in {"CARGO_HOME", "CARGO_TARGET_DIR"} and isinstance(env_value, yaml.nodes.ScalarNode):
                    values.append((env_key.start_mark.line + 1, env_key.value, str(env_value.value)))
    return values


@lru_cache(maxsize=16)
def _yaml_key_values(text: str, wanted: str) -> list[tuple[int, str]]:
    """Return executable scalar values for a YAML mapping key."""
    values: list[tuple[int, str]] = []
    root = _yaml_root(text)
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, value in node.value:
            if key.value == wanted and isinstance(value, yaml.nodes.ScalarNode):
                values.append((key.start_mark.line + 1, str(value.value)))
    return values


@lru_cache(maxsize=16)
def _yaml_key_nodes(text: str, wanted: str) -> list[tuple[int, yaml.nodes.Node]]:
    """Return semantic YAML values, retaining sequence/mapping structure."""
    values: list[tuple[int, yaml.nodes.Node]] = []
    root = _yaml_root(text)
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, value in node.value:
            if key.value == wanted:
                values.append((key.start_mark.line + 1, value))
    return values


@lru_cache(maxsize=16)
def _yaml_job_key_nodes(text: str, job_name: str, wanted: str) -> list[tuple[int, yaml.nodes.Node]]:
    """Return a key only from the named semantic GitHub Actions job."""
    values: list[tuple[int, yaml.nodes.Node]] = []
    root = _yaml_root(text)
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, jobs in node.value:
            if key.value != "jobs" or not isinstance(jobs, yaml.nodes.MappingNode):
                continue
            for job, job_value in jobs.value:
                if job.value != job_name or not isinstance(job_value, yaml.nodes.MappingNode):
                    continue
                for child, value in job_value.value:
                    if child.value == wanted:
                        values.append((child.start_mark.line + 1, value))
                    if child.value == "strategy" and isinstance(value, yaml.nodes.MappingNode):
                        for strategy_key, strategy_value in value.value:
                            if strategy_key.value == wanted:
                                values.append((strategy_key.start_mark.line + 1, strategy_value))
    return values


@lru_cache(maxsize=16)
def _yaml_job_nodes(text: str, job_name: str) -> list[yaml.nodes.MappingNode]:
    """Return the named job mapping for checks that span nested job fields."""
    values: list[yaml.nodes.MappingNode] = []
    root = _yaml_root(text)
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, jobs in node.value:
            if key.value != "jobs" or not isinstance(jobs, yaml.nodes.MappingNode):
                continue
            values.extend(
                job_value
                for job, job_value in jobs.value
                if job.value == job_name and isinstance(job_value, yaml.nodes.MappingNode)
            )
    return values


@lru_cache(maxsize=16)
def _yaml_trigger_values(text: str, trigger: str) -> list[str]:
    """Read tag values from the semantic ``on.push`` trigger mapping."""
    root = _yaml_root(text)
    values: list[str] = []
    for node in _walk_yaml(root):
        if not isinstance(node, yaml.nodes.MappingNode):
            continue
        for key, value in node.value:
            if key.value != "on" or not isinstance(value, yaml.nodes.MappingNode):
                continue
            for event, event_value in value.value:
                if event.value != "push" or not isinstance(event_value, yaml.nodes.MappingNode):
                    continue
                for child, child_value in event_value.value:
                    if child.value != trigger or not isinstance(child_value, yaml.nodes.SequenceNode):
                        continue
                    values.extend(
                        str(item.value) for item in child_value.value
                        if isinstance(item, yaml.nodes.ScalarNode)
                    )
    return values


@lru_cache(maxsize=16)
def _env_export_lines(text: str, name: str, source: str | None = None) -> list[int]:
    """Find semantic ``echo NAME=${NAME} >> $GITHUB_ENV`` shell commands."""
    source = source or name
    lines: list[int] = []
    for line, command in _shell_commands(text):
        _prefix, executable, args = _unwrap_command(command)
        if executable != "echo":
            continue
        joined = " ".join(args)
        if f"{name}=${{{source}}}" in joined and "GITHUB_ENV" in joined:
            lines.append(line)
    return lines


def _isolation_errors(release: str) -> list[str]:
    """Validate active shell wiring, its scope, and its order before Cargo."""
    errors: list[str] = []
    assignments = _active_assignments(release)
    expected = {
        "CARGO_HOME": CARGO_HOME_VALUE,
        "CARGO_TARGET_DIR": CARGO_TARGET_VALUE,
        "ZIGBUILD_CACHE": ZIGBUILD_CACHE_VALUE,
        "SRC": ARTIFACT_VALUE,
    }
    expected_lines: dict[str, int] = {}
    for name, value in expected.items():
        matches = [
            line for line, actual, candidate in assignments
            if actual == name and _normalize_path(candidate) == _normalize_path(value)
        ]
        if not matches:
            errors.append(f"missing active job-local {name} assignment")
        else:
            expected_lines[name] = min(matches)

    home_line = expected_lines.get("CARGO_HOME")
    target_line = expected_lines.get("CARGO_TARGET_DIR")
    if home_line is not None and target_line is not None:
        if _block_for_line(release, home_line) != _block_for_line(release, target_line):
            errors.append("CARGO_HOME and CARGO_TARGET_DIR must be exported from one run block")
        else:
            block_number = _block_for_line(release, home_line)
            if block_number is not None:
                home_exports = _env_export_lines(release, "CARGO_HOME")
                target_exports = _env_export_lines(release, "CARGO_TARGET_DIR")
                home_export = next((line for line in home_exports if _block_for_line(release, line) == block_number), None)
                target_export = next((line for line in target_exports if _block_for_line(release, line) == block_number), None)
                if home_export is None or target_export is None:
                    errors.append("Cargo isolation must export both variables through GITHUB_ENV")
                elif home_export <= home_line or target_export <= target_line:
                    errors.append("Cargo isolation exports must follow both active assignments")

    cargo_consumers = [line for line, _args in _active_commands(release, "cargo")]
    cargo_exports = _env_export_lines(release, "CARGO_HOME") + _env_export_lines(release, "CARGO_TARGET_DIR")
    if cargo_consumers and (len(cargo_exports) < 2 or any(line <= max(cargo_exports) for line in cargo_consumers)):
        errors.append("Cargo isolation must be exported before every Cargo consumer")

    zig_line = expected_lines.get("ZIGBUILD_CACHE")
    zig_exports = _env_export_lines(release, "CARGO_ZIGBUILD_CACHE_DIR", "ZIGBUILD_CACHE")
    zigbuild_lines = [line for line, args in _active_commands(release, "cargo") if args and args[0] == "zigbuild"]
    if zig_line is None or not zig_exports:
        errors.append("cargo-zigbuild cache requires an active assignment and GITHUB_ENV export")
    elif zigbuild_lines and (min(zig_exports) <= zig_line or any(line <= min(zig_exports) for line in zigbuild_lines)):
        errors.append("cargo-zigbuild cache export must precede every zigbuild command")

    src_line = expected_lines.get("SRC")
    src_consumers = [
        line for line, command in _shell_commands(release)
        if any(token in {"$SRC", "${SRC}"} or "$SRC" in token or "${SRC}" in token for token in command)
    ]
    if src_line is None:
        errors.append("missing active artifact SRC assignment")
    elif src_consumers and min(src_consumers) <= src_line:
        errors.append("artifact SRC must be assigned before its first consumer")

    return errors


@lru_cache(maxsize=16)
def _backlog_blocks(backlog: str) -> list[tuple[int, int, str]]:
    """Return backlog contract contents and offsets with a linear scan."""
    marker = "```backlog\n"
    blocks: list[tuple[int, int, str]] = []
    search_from = 0
    while True:
        marker_start = backlog.find(marker, search_from)
        if marker_start < 0:
            return blocks
        content_start = marker_start + len(marker)
        content_end = backlog.find("\n```", content_start)
        if content_end < 0:
            return blocks
        blocks.append((content_start, content_end, backlog[content_start:content_end]))
        search_from = content_end + len("\n```")


@lru_cache(maxsize=32)
def _backlog_block(backlog: str, item_id: str) -> str | None:
    """Return one exact backlog contract block, not a status from another item."""
    for _start, _end, block in _backlog_blocks(backlog):
        if re.search(rf"^id:\s*{re.escape(item_id)}\s*$", block, flags=re.MULTILINE):
            return block
    return None


def verify_texts(release: str, cosign: str, backlog: str, release_api: str) -> list[str]:
    """Return all violations for supplied bytes; never return green on absence."""
    errors: list[str] = []
    release_code = "\n".join(_active_lines(release))

    def require(haystack: str, needle: str, label: str) -> None:
        if needle not in haystack:
            errors.append(f"missing {label}: {needle}")

    release_tags = _yaml_trigger_values(release, "tags")
    if "workflow_dispatch:" not in release_code:
        errors.append("release-cli must be an explicit workflow_dispatch operation")
    if release_tags:
        errors.append("release-cli must not publish from a tag-push trigger")
    trigger_section = release.split("permissions:", 1)[0]
    if re.search(r"(?m)^  (?:push|schedule|release):", trigger_section):
        errors.append("release-cli must remain manually dispatched without automatic release triggers")
    require(
        release_code,
        "github.ref == format('refs/tags/{0}', inputs.release_tag)",
        "build bound to the requested immutable tag",
    )
    require(
        release_code,
        "ref: refs/tags/${{ inputs.release_tag }}",
        "checkout of the requested immutable tag",
    )
    expected_targets = {
        ("x86_64-unknown-linux-gnu", "corelink-linux-x86_64", "ubuntu-24.04"),
        ("aarch64-unknown-linux-gnu", "corelink-linux-aarch64", "ubuntu-24.04"),
        ("x86_64-pc-windows-gnu", "corelink-windows-x86_64", "windows-2022"),
    }
    try:
        workflow = yaml.load(release, Loader=_YAML_LOADER)
        targets = workflow["jobs"]["build"]["strategy"]["matrix"]["target"]
        actual_targets = {
            (target.get("triple"), target.get("name"), target.get("runner"))
            for target in targets
            if isinstance(target, dict)
        }
        if actual_targets != expected_targets or len(targets) != len(expected_targets):
            errors.append("release-cli target matrix is not the closed Linux + Windows inventory")
    except (AttributeError, KeyError, TypeError, yaml.YAMLError):
        errors.append("release-cli target matrix is not a valid closed inventory")
    if any(marker in release_code.lower() for marker in ("apple_", "apple-darwin", "corelink-darwin-", "notarize-macos")):
        errors.append("release-cli contains an unsupported Apple release surface")
    if not any(
        isinstance(value, yaml.nodes.ScalarNode)
        and str(value.value) == "${{ matrix.target.runner }}"
        for _line, value in _yaml_job_key_nodes(release, "build", "runs-on")
    ):
        errors.append("build must select an isolated GitHub-hosted runner per target")
    for runner in ("ubuntu-24.04", "windows-2022"):
        if f"runner: {runner}" not in release_code:
            errors.append(f"missing hosted target runner: {runner}")
    build_jobs = _yaml_job_nodes(release, "build")
    if len(build_jobs) != 1 or any(
        isinstance(node, yaml.nodes.ScalarNode)
        and re.search(r"\$\{\{\s*secrets\.", str(node.value))
        for job in build_jobs
        for node in _walk_yaml(job)
    ):
        errors.append("release build jobs must not receive signing or publication secrets")
    pinned_guards = [
        (line, args)
        for line, args in _active_commands(release, "bash")
        if args and args[0] == "scripts/ci-assert-pinned-toolchain.sh"
    ]
    target_installs = [
        line
        for line, args in _active_commands(release, "rustup")
        if args[:3] == ["target", "add", "${TARGET_TRIPLE}"]
    ]
    if not any(
        pre_args == ["scripts/ci-assert-pinned-toolchain.sh"]
        and post_args == ["scripts/ci-assert-pinned-toolchain.sh", "${TARGET_TRIPLE}"]
        and pre_line < target_line < post_line
        for pre_line, pre_args in pinned_guards
        for target_line in target_installs
        for post_line, post_args in pinned_guards
    ):
        errors.append("pinned Rust toolchain must precede target installation and assert the installed target")
    if not any(
        args == ["config", "--global", "core.longpaths", "true"]
        for _line, args in _active_commands(release, "git")
    ):
        errors.append("Windows hosted checkout must enable Git long paths")
    longpaths_step = release.find("- name: Enable Git long paths for Windows checkout")
    checkout_step = release.find("- name: Checkout", longpaths_step + 1)
    if longpaths_step < 0 or checkout_step < 0 or longpaths_step >= checkout_step:
        errors.append("Windows long-path setup must run before checkout")
    if not any(name == "EXPECTED_ZIG_VERSION" and value == "0.16.0" for _line, name, value in _active_assignments(release)):
        errors.append("missing active Zig version pin")
    if not any(
        value == "taiki-e/install-action@07b4745e0c39a41822af610387492e3e53aa222b"
        for _line, value in _yaml_key_values(release, "uses")
    ):
        errors.append("missing active prebuilt installer pin")
    if not any(
        value == "mlugg/setup-zig@d1434d08867e3ee9daa34448df10607b98908d29"
        for _line, value in _yaml_key_values(release, "uses")
    ):
        errors.append("missing active pinned Zig setup action")
    if "cargo-zigbuild@0.19.8" not in [
        value for _line, value in _yaml_key_values(release, "tool")
    ]:
        errors.append("missing semantic cargo-zigbuild version pin")
    if not any(
        args[:1] == ["--help"]
        for _line, args in _active_commands(release, "cargo-zigbuild")
    ):
        errors.append("cargo-zigbuild executable must be called with its supported --help option")
    if "command -v cargo-zigbuild" not in _active_shell_lines(release):
        errors.append("release-cli must verify that cargo-zigbuild is installed on PATH")
    if any(
        args[:1] in (["--version"], ["-V"])
        for _line, args in _active_commands(release, "cargo-zigbuild")
    ) or any(
        args[:2] in (["zigbuild", "--version"], ["zigbuild", "-V"])
        for _line, args in _active_commands(release, "cargo")
    ):
        errors.append("release-cli must not use unsupported cargo-zigbuild version probes")
    errors.extend(_isolation_errors(release))
    if not _env_export_lines(release, "CARGO_ZIGBUILD_CACHE_DIR", "ZIGBUILD_CACHE"):
        errors.append("missing active cargo-zigbuild cache export")
    if not any(args and args[0] == "zigbuild" for _line, args in _active_commands(release, "cargo")):
        errors.append("missing active cargo-zigbuild command")
    for line, args in _active_commands(release, "cargo"):
        if args and args[0] in {"fetch", "install"}:
            errors.append(f"release-cli must not run cargo {args[0]} in any wrapper (line {line})")
    if any(value.startswith("Swatinem/rust-cache@") for _line, value in _yaml_key_values(release, "uses")):
        errors.append("release-cli must not mutate shared cargo state with rust-cache")
    for line, name, value in _active_assignments(release) + _active_yaml_env_values(release):
        if name in {"CARGO_HOME", "CARGO_TARGET_DIR"} and _shared_cargo_path(value):
            errors.append(f"release-cli {name} must not point at shared Cargo state (line {line})")
    for line, args in _active_commands(release, "rm"):
        options = "".join(arg[1:] for arg in args if arg.startswith("-") and arg != "--").lower()
        paths = [arg for arg in args if not arg.startswith("-") or arg == "--"]
        if "r" in options and "f" in options and any(_shared_cargo_path(path) for path in paths):
            errors.append(f"release-cli must not delete packages from shared $HOME/.cargo (line {line})")
    if re.search(r"(?m)^\s*[^#\n]*--repo\s+HumanGuardrail/corelink-cli", release_code):
        errors.append("release-cli contains the forbidden stale release repository")
    create_step = "--create-or-reuse-empty-draft"
    if release.count(create_step) != 1 or "--expected-state draft --allow-absent" not in release:
        errors.append("release-cli must use the stable-ID helper to create or reuse a draft")
    if any(args[:2] == ["release", "create"] for _line, args in _active_commands(release, "gh")):
        errors.append("release-cli must not use the legacy gh release create command")
    helper_requirements = (
        'if release.get("tag_name") != tag:',
        'if release.get("prerelease") is not False:',
        'if draft is not True or published_at is not None:',
        '"--method", "POST"', "create_or_reuse_empty_draft", "len(matches) > 1",
        'if release["assets"]:\n            raise ReleaseApiError("existing draft is non-empty; refusing overwrite or resume")',
    )
    for marker in helper_requirements:
        if marker not in release_api:
            errors.append(f"stable draft API helper is missing required validation: {marker}")
    if "if len(matches) != 1" not in release_api or 'existing draft is non-empty; refusing overwrite or resume' not in release_api:
        errors.append("stable draft API helper must reject ambiguous and non-empty draft states")
    require(
        release_code,
        "--create-or-reuse-empty-draft",
        "idempotent exact-draft creation or reuse",
    )
    require(
        release_api,
        '"published_at"',
        "published-release retry refusal",
    )

    # B-118 retired the former OCI signing workflow.  Keep this negative
    # control in the B-112 gate so a stale/reintroduced file cannot make the
    # bundled release contract look green.  The dedicated B-118 verifier owns
    # the independent signing-path and public-surface checks.
    if cosign.strip():
        errors.append("retired .github/workflows/cosign-sign.yml must remain absent")

    b112 = _backlog_block(backlog, "B-112")
    if b112 is None:
        errors.append("missing exact B-112 backlog contract block")
    else:
        require(b112, "id: B-112", "B-112 record")
        require(b112, "owner: tl", "B-112 owner")
        statuses = re.findall(r"^status:\s*(\S+)\s*$", b112, flags=re.MULTILINE)
        if statuses != ["parked"]:
            errors.append("B-112 must retain the exact parked production status")
        means = re.search(
            r"^verify-means:\s*\|\s*$\n(?P<body>(?:^  .*\n?)+)",
            b112,
            flags=re.MULTILINE,
        )
        if means is None or not means.group("body").lstrip().startswith("parked —"):
            errors.append("B-112 parked claim must start verify-means with parked —")
        if re.search(r"fronteira\s+de aposentadoria", b112) is None:
            errors.append("B-112 verify-means must name the retired-lane boundary")
    require(backlog, "id: B-112", "B-112 record")
    require(backlog, "`cosign-sign.yml` foi removido em 2026-09-08 (B-118)", "B-118 retirement statement")
    require(backlog, "waiver não foi carregado para a árvore atual", "retired waiver boundary")
    if RETIRED_WAIVER in backlog:
        errors.append("B-112 must not restore the retired B-118 owner waiver")
    require(backlog, "26663769142", "historical release run evidence")
    require(backlog, "78592387578", "historical failing job evidence")
    require(backlog, "HTTP 410", "expired-log limitation")
    require(backlog, "could not execute process rustc", "reproduction signature")
    require(backlog, "No such file or directory (os error 2)", "reproduction errno")
    require(backlog, "could not parse/generate dep info", "secondary reproduction signature")
    require(backlog, "exit 101", "historical process status")
    require(backlog, "python3 scripts/verify_b112_release_root_cause.py", "canonical verifier command")
    require(backlog, "D03 bundle", "exact D03 bundle label")
    return errors


def _read_regular(path: Path, label: str) -> str:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise RuntimeError(f"{label} is unreadable: {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise RuntimeError(f"{label} is not a regular file: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"{label} is unreadable: {path}: {exc}") from exc
    if not text.strip():
        raise RuntimeError(f"{label} is empty: {path}")
    return text


def _mutate_b112_status(backlog: str) -> str:
    """Change only B-112's status for the fail-closed mutation fixture."""
    for start, end, block in _backlog_blocks(backlog):
        if not re.search(r"^id:\s*B-112\s*$", block, flags=re.MULTILINE):
            continue
        mutated = re.sub(r"^status:\s*parked\s*$", "status: done", block, count=1, flags=re.MULTILINE)
        if mutated == block:
            raise RuntimeError("B-112 status mutation could not find status: parked")
        return backlog[:start] + mutated + backlog[end:]
    raise RuntimeError("B-112 status mutation could not find contract block")


def _inject_run_command(release: str, command: str) -> str:
    """Place a mutation inside the first real build run scalar."""
    needle = "          cargo-zigbuild --help >/dev/null\n"
    if needle not in release:
        raise RuntimeError("B-112 mutation could not find semantic build command")
    return release.replace(needle, needle + f"          {command}\n", 1)


def mutation_self_test(release: str, cosign: str, backlog: str, release_api: str) -> None:
    """Prove each critical positive is load-bearing, not decorative text."""
    mutations = {
        "cache export": (release.replace("CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}", "CARGO_ZIGBUILD_CACHE_MUTATED=${ZIGBUILD_CACHE}", 1), cosign, backlog),
        "prebuilt action": (release.replace("taiki-e/install-action@07b4745e0c39a41822af610387492e3e53aa222b", "actions/checkout@deadbeef", 1), cosign, backlog),
        "manual trigger": (release.replace("  workflow_dispatch:", "  # dispatch removed", 1), cosign, backlog),
        "retired workflow": (release, "name: stale\n", backlog),
        "retirement statement": (release, cosign, backlog.replace(
            "`cosign-sign.yml` foi removido em 2026-09-08 (B-118)",
            "`cosign-sign.yml` permaneceu ativo",
            1,
        )),
        "retired waiver boundary": (release, cosign, backlog.replace(
            "waiver não foi carregado para a árvore atual",
            "waiver was silently restored",
            1,
        )),
        "retirement boundary wording": (release, cosign, re.sub(
            r"fronteira\s+de aposentadoria",
            "preservação do waiver",
            backlog,
            count=1,
        )),
        "failure signature": (release, cosign, backlog.replace("could not execute process rustc", "compiler invocation", 1)),
        "B-112 status": (release, cosign, _mutate_b112_status(backlog)),
        "shared Cargo home": (release.replace(CARGO_HOME_BINDING, 'CARGO_HOME="$HOME/.cargo"', 1), cosign, backlog),
        "shared target directory": (release.replace(CARGO_TARGET_BINDING, 'CARGO_TARGET_DIR="$HOME/target"', 1), cosign, backlog),
        "Cargo home echo bait": (release.replace(CARGO_HOME_BINDING, 'echo \'CARGO_HOME="$HOME/.cargo"\'', 1), cosign, backlog),
        "Cargo home comment bait": (release.replace(CARGO_HOME_BINDING, '# CARGO_HOME="$HOME/.cargo"', 1), cosign, backlog),
        "Cargo target echo bait": (release.replace(CARGO_TARGET_BINDING, 'echo \'CARGO_TARGET_DIR="$HOME/target"\'', 1), cosign, backlog),
        "Cargo target comment bait": (release.replace(CARGO_TARGET_BINDING, '# CARGO_TARGET_DIR="$HOME/target"', 1), cosign, backlog),
        "shared registry deletion": (_inject_run_command(release, 'rm -rf "$HOME/.cargo"'), cosign, backlog),
        "manual Cargo fetch": (_inject_run_command(release, 'cargo fetch --target "${TARGET_TRIPLE}"'), cosign, backlog),
        "missing stable draft-state classification": (release.replace(
            "--expected-state draft --allow-absent --create-or-reuse-empty-draft",
            "--expected-state draft --create-or-reuse-empty-draft",
            1,
        ), cosign, backlog),
        "wrapped Cargo fetch": (_inject_run_command(release, 'sudo -n cargo fetch --target "${TARGET_TRIPLE}"'), cosign, backlog),
        "wrapped Cargo install": (_inject_run_command(release, "env CARGO_NET_OFFLINE=false cargo install cargo-zigbuild"), cosign, backlog),
        "env separator Cargo fetch": (_inject_run_command(release, "env -- CARGO_NET_OFFLINE=false cargo fetch --locked"), cosign, backlog),
        "nested shell fetch": (_inject_run_command(release, "bash -lc 'cargo fetch --locked'"), cosign, backlog),
        "dynamic shell fetch": (_inject_run_command(release, 'bash -c "$COMMAND"'), cosign, backlog),
        "normalized registry deletion": (_inject_run_command(release, 'sudo rm -Rf -- "$HOME//./.cargo/registry"'), cosign, backlog),
        "unclosed heredoc": (_inject_run_command(release, "cat <<'B112_EOF'"), cosign, backlog),
        "shared artifact path": (release.replace(ARTIFACT_PATH, 'SRC="target/${TARGET_TRIPLE}/release/corelink"', 1), cosign, backlog),
        "cache assignment order": (release.replace(
            "          cargo-zigbuild --help >/dev/null\n"
            '          ZIGBUILD_CACHE="${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"\n'
            '          mkdir -p "$ZIGBUILD_CACHE"\n'
            '          echo "CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}" >> "$GITHUB_ENV"\n',
            "          cargo-zigbuild --help >/dev/null\n"
            '          mkdir -p "$ZIGBUILD_CACHE"\n'
            '          echo "CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}" >> "$GITHUB_ENV"\n'
            '          ZIGBUILD_CACHE="${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"\n', 1), cosign, backlog),
        "Cargo export order": (release.replace('          echo "CARGO_HOME=${CARGO_HOME}" >> "$GITHUB_ENV"\n', '', 1), cosign, backlog),
        "SRC consumer order": (_inject_run_command(release, 'cp "$SRC" /tmp/early-artifact'), cosign, backlog),
        "hosted Windows runner": (release.replace(
            "runner: windows-2022", "runner: self-hosted", 1
        ), cosign, backlog),
        "missing release target standard library": (release.replace(
            '          rustup target add "${TARGET_TRIPLE}"\n', "", 1
        ), cosign, backlog),
        "missing Windows long paths configuration": (release.replace(
            "        run: git config --global core.longpaths true\n", "", 1
        ), cosign, backlog),
        "invalid cargo-zigbuild version probe": (release.replace(
            "          cargo-zigbuild --help >/dev/null\n",
            "          cargo-zigbuild --version\n", 1
        ), cosign, backlog),
        "missing cargo-zigbuild PATH check": (release.replace(
            "          command -v cargo-zigbuild\n", "", 1
        ), cosign, backlog),
        "missing immutable tag binding": (release.replace(
            "github.ref == format('refs/tags/{0}', inputs.release_tag)",
            "github.ref == 'refs/heads/main'"
        ), cosign, backlog),
        "build job signing secret": (release.replace(
            "      TARGET_EXT: ${{ matrix.target.ext }}\n",
            "      TARGET_EXT: ${{ matrix.target.ext }}\n"
            "      SIGNING_KEY: ${{ secrets.SIGNING_KEY }}\n", 1
        ), cosign, backlog),
        "pinned target installation order": (release.replace(
            '          bash scripts/ci-assert-pinned-toolchain.sh\n'
            '          rustup target add "${TARGET_TRIPLE}"\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh "${TARGET_TRIPLE}"\n',
            '          rustup target add "${TARGET_TRIPLE}"\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh "${TARGET_TRIPLE}"\n', 1
        ), cosign, backlog),
        "toolchain echo bait": (release.replace(
            '          bash scripts/ci-assert-pinned-toolchain.sh\n',
            "          echo 'bash scripts/ci-assert-pinned-toolchain.sh'\n", 1), cosign, backlog),
        "zig pin echo bait": (release.replace(
            "          EXPECTED_ZIG_VERSION=0.16.0\n",
            "          echo 'EXPECTED_ZIG_VERSION=0.16.0'\n", 1), cosign, backlog),
        "tool echo bait": (release.replace(
            "          tool: cargo-zigbuild@0.19.8\n", "          tool: cargo-zigbuild@0.19.7\n", 1
        ).replace(
            "          cargo-zigbuild --help >/dev/null\n",
            "          echo 'tool: cargo-zigbuild@0.19.8'\n"
            "          cargo-zigbuild --help >/dev/null\n", 1), cosign, backlog),
    }
    # These mutations exercise the active helper contract rather than stale
    # inline shell snippets from the retired create flow.
    helper_mutations = {
        "published response accepted": release_api.replace('"published_at"', '"published_time"', 1),
        "wrong tag accepted": release_api.replace('"tag_name"', '"tag"', 1),
        "non-empty draft overwrite allowed": release_api.replace('if release["assets"]:', "if False:", 1),
        "duplicate tag accepted": release_api.replace("if len(matches) > 1:", "if False:", 1),
    }
    expanded = {
        name: (mutated_release, mutated_cosign, mutated_backlog, release_api)
        for name, (mutated_release, mutated_cosign, mutated_backlog) in mutations.items()
    }
    expanded.update({
        name: (release, cosign, backlog, mutated_helper)
        for name, mutated_helper in helper_mutations.items()
    })
    for name, (mutated_release, mutated_cosign, mutated_backlog, mutated_helper) in expanded.items():
        try:
            mutation_errors = verify_texts(mutated_release, mutated_cosign, mutated_backlog, mutated_helper)
        except RuntimeError:
            continue
        if not mutation_errors:
            raise RuntimeError(f"mutation was accepted as green: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        release = _read_regular(root / RELEASE, RELEASE)
        release_api = _read_regular(root / "scripts/cli_release_api.py", "scripts/cli_release_api.py")
        cosign_path = root / COSIGN
        # Missing is the expected B-118 state.  A regular file or symlink is
        # still read so the negative control can reject a reintroduced lane;
        # a broken symlink must not be mistaken for a clean retirement.
        cosign = _read_regular(cosign_path, COSIGN) if cosign_path.exists() or cosign_path.is_symlink() else ""
        backlog = _read_regular(root / BACKLOG, BACKLOG)
        errors = verify_texts(release, cosign, backlog, release_api)
        if errors:
            for error in errors:
                print(f"B112 RED: {error}", file=sys.stderr)
            return 1
        mutation_self_test(release, cosign, backlog, release_api)
    except RuntimeError as error:
        print(f"B112 RED: {error}", file=sys.stderr)
        return 1
    print("B112 bounded root-cause guard: PASS (production release remains parked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
