#!/usr/bin/env python3
"""Fail-closed static gate for the B-103..B-129 attribution contract.

This gate verifies the portable half of the performance work: disjoint
container phase boundaries, scoped propagation across ``spawn_blocking``,
Worker reconciliation helpers, and an owner packet that explicitly leaves
production-dependent backlog items open. It never contacts production and
never treats a source marker as a latency measurement.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = "docs/handoff/2026-09-05-b103-b129-attribution-owner-packet.md"


class VerificationError(RuntimeError):
    pass


def _read(root: Path, path: str, overrides: dict[str, str]) -> str:
    if path in overrides:
        return overrides[path]
    try:
        return (root / path).read_text(encoding="utf-8")
    except OSError as exc:
        raise VerificationError(f"required file is unreadable: {path}: {exc}") from exc


def _rust_tokens(source: str) -> list[tuple[str, str]]:
    """Tokenize enough Rust to inspect active macro calls.

    This intentionally skips line/block comments (including nested Rust block
    comments) and treats regular/raw strings as single tokens.  A textual
    ``include!(...)`` search would accept a decoy in either place and would
    let the re-anchor guard pass after the real include was removed.
    """

    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise VerificationError("byte_accounting.rs has an unterminated block comment")
            continue

        # Raw strings are allowed in Rust macro arguments.  Recognize them
        # before identifiers so `r#"include!(...)"#` cannot become tokens.
        if char == "r":
            quote = index + 1
            while quote < length and source[quote] == "#":
                quote += 1
            if quote < length and source[quote] == '"':
                hashes = quote - index - 1
                closing = '"' + ("#" * hashes)
                end = source.find(closing, quote + 1)
                if end < 0:
                    raise VerificationError("byte_accounting.rs has an unterminated raw string")
                tokens.append(("string", source[quote + 1 : end]))
                index = end + len(closing)
                continue

        if char == '"':
            start = index + 1
            index += 1
            escaped = False
            while index < length:
                current = source[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    tokens.append(("string", source[start:index]))
                    index += 1
                    break
                index += 1
            else:
                raise VerificationError("byte_accounting.rs has an unterminated string")
            continue

        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(("ident", source[index:end]))
            index = end
            continue

        tokens.append(("punct", char))
        index += 1
    return tokens


def _rust_sequence(tokens: list[tuple[str, str]], values: tuple[str, ...]) -> list[int]:
    """Return active Rust token-sequence positions, excluding comments/strings."""
    wanted = []
    for value in values:
        if value.startswith('"') and value.endswith('"'):
            wanted.append(("string", value[1:-1]))
        elif value[0].isalpha() or value[0] == "_":
            wanted.append(("ident", value))
        else:
            wanted.append(("punct", value))
    return [
        index
        for index in range(len(tokens) - len(wanted) + 1)
        if tokens[index : index + len(wanted)] == wanted
    ]


def _active_include_paths(source: str) -> set[str]:
    tokens = _rust_tokens(source)
    paths: set[str] = set()
    for index in range(len(tokens) - 4):
        if tokens[index : index + 5] == [
            ("ident", "include"),
            ("punct", "!"),
            ("punct", "("),
            ("string", tokens[index + 3][1]),
            ("punct", ")"),
        ]:
            paths.add(tokens[index + 3][1])
    return paths


def _rust_include_closure(
    root: Path,
    entry: str,
    overrides: dict[str, str],
) -> str:
    """Read an active Rust ``include!`` tree, matching compiler resolution.

    The B126-M2 accounting module is intentionally split into nested fragments.
    Checking only the first fragment lets a required symbol disappear into a
    child include without the attribution gate noticing.  Resolve each include
    relative to its containing file, reject paths outside the repository, and
    fail closed on missing files or include cycles.
    """

    root = root.resolve()
    visiting: list[Path] = []
    visited: set[Path] = set()

    def visit(relative: str) -> str:
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise VerificationError(f"Rust include escapes repository root: {relative}") from exc
        canonical = path.relative_to(root)
        if path in visiting:
            chain = " -> ".join(str(item.relative_to(root)) for item in (*visiting, path))
            raise VerificationError(f"Rust include cycle detected: {chain}")
        if path in visited:
            return ""
        source = _read(root, canonical.as_posix(), overrides)
        visiting.append(path)
        try:
            fragments = [source]
            for include in sorted(_active_include_paths(source)):
                child = (path.parent / include).resolve()
                try:
                    child_relative = child.relative_to(root).as_posix()
                except ValueError as exc:
                    raise VerificationError(
                        f"Rust include escapes repository root: {canonical} -> {include}"
                    ) from exc
                fragments.append(visit(child_relative))
            visited.add(path)
            return "\n".join(fragments)
        finally:
            visiting.pop()

    return visit(entry)


def _typescript_tokens(source: str) -> list[tuple[str, str]]:
    """Tokenize executable TypeScript while excluding comments as decoys."""
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise VerificationError("TypeScript source has an unterminated block comment")
            continue
        if char in {'"', "'", "`"}:
            quote = char
            start = index + 1
            index += 1
            escaped = False
            while index < length:
                current = source[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    tokens.append(("string", source[start:index]))
                    index += 1
                    break
                index += 1
            else:
                raise VerificationError("TypeScript source has an unterminated string")
            continue
        if char.isalpha() or char in {"_", "$"}:
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in {"_", "$"}):
                end += 1
            tokens.append(("ident", source[index:end]))
            index = end
            continue
        tokens.append(("punct", char))
        index += 1
    return tokens


def _token_values(tokens: list[tuple[str, str]]) -> list[str]:
    return [value for _kind, value in tokens]


def _origin_allowlist_strings(source: str) -> list[str]:
    tokens = _typescript_tokens(source)
    for index, token in enumerate(tokens):
        if token != ("ident", "ORIGIN_CONTAINER_PHASES"):
            continue
        if tokens[index + 1 : index + 3] != [("punct", "="), ("punct", "[")]:
            continue
        values: list[str] = []
        depth = 1
        for candidate in tokens[index + 3 :]:
            if candidate == ("punct", "["):
                depth += 1
            elif candidate == ("punct", "]"):
                depth -= 1
                if depth == 0:
                    return values
            elif depth == 1 and candidate[0] == "string":
                values.append(candidate[1])
        raise VerificationError("ORIGIN_CONTAINER_PHASES has an unterminated array")
    raise VerificationError("worker observability allowlist is not active code")


def _has_token_sequence(tokens: list[tuple[str, str]], sequence: tuple[str, ...]) -> bool:
    values = _token_values(tokens)
    width = len(sequence)
    return any(values[index : index + width] == list(sequence) for index in range(len(values) - width + 1))


def _token_sequence_count(tokens: list[tuple[str, str]], sequence: tuple[str, ...]) -> int:
    values = _token_values(tokens)
    width = len(sequence)
    return sum(values[index : index + width] == list(sequence) for index in range(len(values) - width + 1))


def _call_argument_tokens(tokens: list[tuple[str, str]], name: str) -> list[tuple[str, str]] | None:
    """Return the balanced argument tokens for the one named call."""
    values = _token_values(tokens)
    positions = [i for i in range(len(values) - 1) if values[i : i + 2] == [name, "("]]
    if len(positions) != 1:
        return None
    opening = positions[0] + 1
    depth = 1
    for index in range(opening + 1, len(tokens)):
        if tokens[index] == ("punct", "("):
            depth += 1
        elif tokens[index] == ("punct", ")"):
            depth -= 1
            if depth == 0:
                return tokens[opening + 1 : index]
    return None


def _rust_call_arguments_at(
    tokens: list[tuple[str, str]], opening: int
) -> list[tuple[str, str]] | None:
    """Return arguments for a call whose opening parenthesis is at ``opening``."""
    if opening >= len(tokens) or tokens[opening] != ("punct", "("):
        return None
    depth = 1
    for index in range(opening + 1, len(tokens)):
        if tokens[index] == ("punct", "("):
            depth += 1
        elif tokens[index] == ("punct", ")"):
            depth -= 1
            if depth == 0:
                return tokens[opening + 1 : index]
    return None


def _rate_limit_scope_positions(tokens: list[tuple[str, str]]) -> list[int]:
    """Find active one-argument ``PhaseScope::enter(Phase::RateLimit)`` calls."""
    prefix = ("PhaseScope", ":", ":", "enter", "(")
    expected = ("crate", ":", ":", "origin_timing", ":", ":", "Phase", ":", ":", "RateLimit")
    positions: list[int] = []
    for position in _rust_sequence(tokens, prefix):
        arguments = _rust_call_arguments_at(tokens, position + len(prefix) - 1)
        if arguments is not None and tuple(_token_values(arguments)) == expected:
            positions.append(position)
    return positions


def _typescript_function_body(source: str, name: str) -> list[tuple[str, str]] | None:
    tokens = _typescript_tokens(source)
    for index in range(len(tokens) - 2):
        if tokens[index : index + 3] != [
            ("ident", "export"),
            ("ident", "function"),
            ("ident", name),
        ]:
            continue
        opening = next(
            (candidate for candidate in range(index + 3, len(tokens)) if tokens[candidate] == ("punct", "{")),
            None,
        )
        if opening is None:
            return None
        depth = 1
        for candidate in range(opening + 1, len(tokens)):
            if tokens[candidate] == ("punct", "{"):
                depth += 1
            elif tokens[candidate] == ("punct", "}"):
                depth -= 1
                if depth == 0:
                    return tokens[opening + 1 : candidate]
        return None
    return None


def _rust_function_body(source: str, name: str) -> list[tuple[str, str]] | None:
    tokens = _rust_tokens(source)
    for index in range(len(tokens) - 1):
        if tokens[index] != ("ident", "fn") or tokens[index + 1] != ("ident", name):
            continue
        opening = next(
            (candidate for candidate in range(index + 2, len(tokens)) if tokens[candidate] == ("punct", "{")),
            None,
        )
        if opening is None:
            return None
        depth = 1
        for candidate in range(opening + 1, len(tokens)):
            if tokens[candidate] == ("punct", "{"):
                depth += 1
            elif tokens[candidate] == ("punct", "}"):
                depth -= 1
                if depth == 0:
                    return tokens[opening + 1 : candidate]
        return None
    return None


def b129_inline_issues(root: Path = ROOT, *, overrides: dict[str, str] | None = None) -> list[str]:
    """Check B-129's executable residue contract at its current module seams."""
    values = overrides or {}
    diagnostic_workflow = _read(root, ".github/workflows/issue-1671-b129-diagnostic.yml", values)
    worker_observability = _read(root, "worker/src/index_observability.ts", values)
    worker_finish = _read(root, "worker/src/index_finish_stage.ts", values)
    origin = _read(root, "crates/corelink-container/src/origin_timing.rs", values)
    result: list[str] = []
    workflow_markers = (
        "github.repository_id == '",
        "github.ref == 'refs/heads/main' && github.ref_protected",
        "environment: production",
        "CORELINK_PERF_BASE: ${{ vars.CORELINK_PERF_BASE }}",
    )
    for marker in workflow_markers:
        if marker not in diagnostic_workflow:
            result.append(f"B-129 diagnostic workflow must retain protected production target binding: {marker}")
    try:
        wdb_body = _typescript_function_body(worker_observability, "wdbControlPhase")
        origin_body = _typescript_function_body(worker_observability, "originSubPhases")
        finish_tokens = _typescript_tokens(worker_finish)
        rust_body = _rust_function_body(origin, "server_timing_value_with")
    except VerificationError as exc:
        return [str(exc)]

    if wdb_body is None:
        result.append("worker/src/index_observability.ts must actively define wdbControlPhase")
    else:
        if any(kind == "string" and "qother" in value for kind, value in _typescript_tokens(worker_observability)):
            result.append("worker observability must not actively emit the historical qother name")
        for marker in (
            "let", "sum", "for", "const", "of", "phases", "if", ">", "wdbMs",
        ):
            if marker not in _token_values(wdb_body):
                result.append(f"wdbControlPhase is missing active semantic marker: {marker}")
        strings = [value for kind, value in wdb_body if kind == "string"]
        if not any("qcontrol" in value for value in strings):
            result.append("wdbControlPhase must actively emit qcontrol")
        if not any("unreconciled" in value for value in strings):
            result.append("wdbControlPhase must retain the unreconciled overshoot branch")
        if sum("wdbMs - sum" in value for value in strings) != 1:
            result.append("wdbControlPhase must actively subtract phases from wdbMs")
        if sum("unreconciled" in value for value in strings) != 1:
            result.append("wdbControlPhase must have exactly one unreconciled return")
        if _token_sequence_count(wdb_body, ("sum", "+", "=", "v")) != 1:
            result.append("wdbControlPhase must accumulate each phase exactly once")
        else:
            update = _token_values(wdb_body)
            at = next(
                i for i in range(len(update) - 3) if update[i : i + 4] == ["sum", "+", "=", "v"]
            )
            if update[at : at + 5] != ["sum", "+", "=", "v", ";"]:
                result.append("wdbControlPhase must add the raw phase value exactly once")
        if _token_sequence_count(wdb_body, ("return",)) != 2:
            result.append("wdbControlPhase must have exactly two executable return arms")
        else:
            values = _token_values(wdb_body)
            if_index = values.index("if")
            opening = next((i for i in range(if_index, len(values)) if values[i] == "{"), -1)
            depth = 0
            closing = -1
            for i in range(opening, len(values)):
                if values[i] == "{":
                    depth += 1
                elif values[i] == "}":
                    depth -= 1
                    if depth == 0:
                        closing = i
                        break
            branch_strings = [
                value for kind, value in wdb_body[opening + 1 : closing] if kind == "string"
            ] if opening >= 0 and closing >= 0 else []
            tail_strings = [
                value for kind, value in wdb_body[closing + 1 :] if kind == "string"
            ] if closing >= 0 else []
            if len(branch_strings) != 1 or "unreconciled" not in branch_strings[0]:
                result.append("wdbControlPhase overshoot arm must emit unreconciled")
            if len(tail_strings) != 1 or "wdbMs - sum" not in tail_strings[0]:
                result.append("wdbControlPhase normal arm must emit the subtraction")
    if origin_body is None:
        result.append("worker/src/index_observability.ts must actively define originSubPhases")
    elif not any("ohop" in value for kind, value in origin_body if kind == "string"):
        result.append("originSubPhases must actively emit ohop")
    if _token_sequence_count(
        finish_tokens,
        (".", "SERVER_TIMING_WDB_DETAIL", "=", "=", "=", "on"),
    ) != 1:
        result.append("index_finish_stage.ts must actively gate SERVER_TIMING_WDB_DETAIL on \"on\"")
    call_args = _call_argument_tokens(finish_tokens, "wdbControlPhase")
    if call_args is None:
        result.append("index_finish_stage.ts must actively call wdbControlPhase")
    else:
        call_values = _token_values(call_args)
        for name in ("stQTierMs", "stQDoMs", "stQBatchMs", "stQResidMs"):
            if call_values.count(name) != 1:
                result.append(f"wdbControlPhase call must pass {name} exactly once")
    if _token_sequence_count(finish_tokens, ("originSubPhases", "(")) != 1:
        result.append("index_finish_stage.ts must actively call originSubPhases")
    if rust_body is None:
        result.append("origin_timing.rs must actively define server_timing_value_with")
    else:
        strings = [value for kind, value in rust_body if kind == "string"]
        if sum("oother;dur={handler_ms}" in value and "legacy-alias" in value for value in strings) != 1:
            result.append("server_timing_value_with must emit exactly one oother compatibility alias")
        if sum("ohandler" in value for value in strings) != 1:
            result.append("server_timing_value_with must actively emit ohandler")
        if "attributed_ms" not in _token_values(rust_body) or "max" not in _token_values(rust_body):
            result.append("server_timing_value_with must retain attributed-ms residual flooring")
    return result


def issues(root: Path = ROOT, *, overrides: dict[str, str] | None = None) -> list[str]:
    values = overrides or {}
    source = _read(root, "crates/corelink-container/src/origin_timing.rs", values)
    cache = _read(root, "crates/corelink-container/src/adapter_cache.rs", values)
    rate_limit = _read(root, "crates/corelink-container/src/routes/ratelimit_layer.rs", values)
    # B126-M2 keeps `byte_accounting.rs` as a thin include wrapper.  The
    # attribution bridge lives in the implementation fragment, so inspect
    # the included source rather than relying on the wrapper retaining a
    # particular symbol.  Keeping the wrapper in the read set makes this
    # fail closed if the composition point disappears.
    accounting_wrapper = _read(root, "crates/corelink-container/src/byte_accounting.rs", values)
    accounting = _rust_include_closure(
        root,
        "crates/corelink-container/src/byte_accounting.rs",
        values,
    )
    worker = _read(root, "worker/src/index.ts", values)
    worker_observability = _read(root, "worker/src/index_observability.ts", values)
    worker_finish = _read(root, "worker/src/index_finish_stage.ts", values)
    worker_test = _read(root, "worker/tests/server_timing_wdb_residual_phase.test.ts", values)
    origin_test = _read(root, "worker/tests/server_timing_origin_subphases.test.ts", values)
    probe = _read(root, "scripts/probe-cargo-cache-latency.sh", values)
    packet = _read(root, PACKET, values)
    result: list[str] = []

    required = {
        "origin_timing.rs": (source, ("Phase::Accounting", '"oaccounting"', "BLOCKING_LEDGER", "attributed_ms", "max(0)", "legacy-alias")),
        "adapter_cache.rs": (cache, ("Phase::Accounting", "PhaseScope::with_ledger", "spawn_blocking")),
        "byte_accounting.rs": (accounting, ("Phase::Accounting", "block_on_accrue", "block_on_release")),
        "worker/src/index.ts": (worker, ("originSubPhases", "wdbControlPhase")),
        "worker/src/index_observability.ts": (
            worker_observability,
            (
                "oaccounting",
                "wdbControlPhase",
                "originSubPhases",
                "LEGACY_ORIGIN_CONTAINER_PHASES",
                "canonicalOriginPhase",
            ),
        ),
        "worker/src/index_finish_stage.ts": (worker_finish, ("SERVER_TIMING_WDB_DETAIL", "wdbControlPhase")),
        "wdb residual test": (worker_test, ("exceeds `wdb`", "-1", "unreconciled")),
        "origin split test": (origin_test, ("oaccounting", "unreconciled", "sum")),
        "probe-cargo-cache-latency.sh": (
            probe,
            (
                "reconcile_origin_split",
                "oaccounting",
                "handler_seen",
                "legacy-alias",
                "rendered",
                "decimal_zero",
                "oaccounting;dur=abc",
                "oother;dur=Inf",
                "no_origin_malformed",
                "--self-test",
            ),
        ),
    }
    for label, (text, markers) in required.items():
        for marker in markers:
            if marker not in text:
                result.append(f"{label} is missing required marker: {marker}")

    # B-109's closed engineering population: retain the synchronous
    # token-bucket admission phase and its single Worker allowlist entry.
    try:
        origin_tokens = _rust_tokens(source)
        rate_tokens = _rust_tokens(rate_limit)
        rate_scope = _rate_limit_scope_positions(rate_tokens)
        rate_calls = _rust_sequence(rate_tokens, ("try_acquire", "("))
        if len(rate_scope) != 2:
            result.append(f"ratelimit_layer.rs must have exactly two active RateLimit scopes (found {len(rate_scope)})")
        if len(rate_calls) != 2:
            result.append(f"ratelimit_layer.rs must retain exactly two active token-bucket calls (found {len(rate_calls)})")
        if len(rate_scope) == 2 and len(rate_calls) == 2 and any(
            call <= scope or call - scope > 28 for scope, call in zip(rate_scope, rate_calls)
        ):
            result.append("each token-bucket call must be inside its own bounded RateLimit scope")
        if not _rust_sequence(origin_tokens, ("Phase", ":", ":", "RateLimit")):
            result.append("origin_timing.rs must actively wire Phase::RateLimit")
        emission = _rust_sequence(origin_tokens, ('"oratelimit"', ",", "Phase", ":", ":", "RateLimit"))
        if len(emission) != 1:
            result.append(f"origin_timing.rs must emit oratelimit exactly once from Phase::RateLimit (found {len(emission)})")
    except VerificationError as exc:
        result.append(str(exc))

    try:
        expected_phases = ["opat", "oquota", "ostore", "oaccounting", "oargon", "opermit", "ortier", "oaudit", "oratelimit", "ohandler"]
        if _origin_allowlist_strings(worker_observability) != expected_phases:
            result.append("worker origin phase allowlist must be the closed ordered population: " + ", ".join(expected_phases))
    except VerificationError as exc:
        result.append(str(exc))

    try:
        include_paths = _active_include_paths(accounting_wrapper)
    except VerificationError as exc:
        result.append(str(exc))
        include_paths = set()
    if "byte_accounting/b126_m2_impl_01.rs" not in include_paths:
        result.append(
            "byte_accounting.rs must actively include byte_accounting/b126_m2_impl_01.rs"
        )

    if cache.count("spawn_blocking") < 2:
        result.append("adapter_cache.rs must retain both blocking read/write boundaries")
    if cache.count("PhaseScope::with_ledger") < 2:
        result.append("both adapter blocking boundaries must install a scoped ledger")
    if packet.count("status: **open**") != 1:
        result.append("owner packet must state one explicit all-items status open")
    for item in ("B-103", "B-104", "B-105", "B-107", "B-109", "B-122", "B-129"):
        if item not in packet:
            result.append(f"owner packet omits {item}")
    for marker in ("does not contain production timings", "never contacts production", "10%", "oaccounting"):
        if marker.lower() not in packet.lower():
            result.append(f"owner packet omits truth/safety marker: {marker}")
    if "status **closed**" in packet.lower() or "status: closed" in packet.lower():
        result.append("owner packet must not claim a production-dependent item closed")
    return result


def verify(root: Path = ROOT, *, overrides: dict[str, str] | None = None) -> None:
    found = issues(root, overrides=overrides)
    if found:
        raise VerificationError("\n".join(found))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--b129-inline", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        # The closure guard must inspect executable tokens, not prose.  Remove
        # one real phase name from each side and require the corresponding
        # polarity check to fail; comment/string bait is covered by the same
        # tokenizer used by the normal guard.
        obs = _read(args.root, "worker/src/index_observability.ts", {})
        origin = _read(args.root, "crates/corelink-container/src/origin_timing.rs", {})
        mutated_obs = obs.replace('"ohandler",', '"removed",', 1)
        try:
            verify(args.root, overrides={"worker/src/index_observability.ts": mutated_obs})
        except VerificationError:
            pass
        else:
            raise VerificationError("allowlist phase removal mutation survived the attribution guard")

        mutated_origin = origin.replace(
            '"ohandler;dur={handler_ms}{handler_suffix}"',
            '"removed;dur={handler_ms}{handler_suffix}"',
            1,
        )
        if mutated_origin == origin:
            raise VerificationError("ohandler self-test mutation did not change active source")
        origin_issues = b129_inline_issues(
            args.root,
            overrides={"crates/corelink-container/src/origin_timing.rs": mutated_origin},
        )
        if not any("ohandler" in issue for issue in origin_issues):
            raise VerificationError("emitted phase removal mutation survived the B-129 guard")
        mutated_alias = origin.replace(
            '"oother;dur={handler_ms};desc=\\"legacy-alias\\""',
            '"removed;dur={handler_ms};desc=\\"legacy-alias\\""',
            1,
        )
        alias_issues = b129_inline_issues(
            args.root,
            overrides={"crates/corelink-container/src/origin_timing.rs": mutated_alias},
        )
        if not any("compatibility alias" in issue for issue in alias_issues):
            raise VerificationError("legacy-alias removal mutation survived the B-129 guard")
        print("self-test: allowlist, emitted-phase, and legacy-alias mutations are RED")
        return 0
    if args.b129_inline:
        found = b129_inline_issues(args.root)
        if found:
            raise VerificationError("\n".join(found))
        print("verify_b129_inline: OK (named attribution contract; production latency claims remain separately gated)")
    else:
        verify(args.root)
        print("verify_b103_b129_attribution: OK (named attribution contract; production measurements remain separately gated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
