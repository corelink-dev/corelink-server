#!/usr/bin/env python3
"""Parse backlog verify commands for comment-sensitive grep checks.

This is a structural census, not a grep for the word ``grep``.  It parses every
backlog record, every verify payload, and every grep invocation, distinguishes
``grep -v`` filters from assertions, and probes assertion regexes against
language/document comment prefixes.  Missing or unparsable records fail
closed.  The compatibility entry point owns the in-memory mutation test and
CLI, while this module keeps the parser and census implementation bounded.
"""
from __future__ import annotations

from functools import lru_cache
import re
import shlex
from dataclasses import dataclass

try:
    import yaml
except ImportError as error:  # pragma: no cover - exercised by the CLI environment
    raise SystemExit(f"instrument error: PyYAML is required: {error}") from error


FENCE = re.compile(r"```backlog\n(.*?)\n```", re.DOTALL)
BACKLOG_OPEN = re.compile(r"^```backlog(?:[ \t]*)$", re.MULTILINE)
GREP = re.compile(
    r"\bgrep\s+(?P<options>(?:-[A-Za-z0-9-]+\s+)*)"
    # Keep shell-escaped quotes inside a quoted regex instead of truncating
    # the pattern at the first escaped quote.
    r"(?P<quote>[\"'])(?P<pattern>(?:\\.|(?!(?P=quote)).)*?)(?P=quote)"
)
GREP_UNQUOTED = re.compile(
    r"\bgrep\s+(?P<options>(?:-[A-Za-z0-9-]+\s+)*)(?P<pattern>[^\s;&|()<>]+)"
)
# --- Command-boundary grammars (linear time) --------------------------------
#
# Until #1674 the three boundaries below were regexes of the shape
#
#   (?:^|[;&|(!]|\$\(|\b(?:if|elif|...|exec)\b)
#   \s*(?:!\s*)?(?:NAME=(?:'[^']*'|"[^"]*"|\S+)\s*)* <tail> $
#
# CPython's backtracking engine needed exponential time to reject them (CodeQL
# py/redos): an unquoted value ``\S+`` can swallow the next ``NAME=VALUE`` when
# no whitespace separates them, and a redirection target ``[^\s;&|()]+`` can
# swallow the next redirection.  ``"A=" + "!A=" * 20 + " x"`` took 2.6 s, and
# ``"<<!" * 12 + " x"`` (38 characters) took 27 s, over ten times longer per
# two more repetitions; the 8 KiB line cap added by #2852 cannot bound that, and
# CodeQL judges the pattern, not the cap.  The overlap is inherent to the
# language: a quote after ``NAME=`` may open a quoted value or be the first
# character of an unquoted one, and which reading succeeds depends on text
# arbitrarily far ahead, so an unambiguous regex for it would be unreviewable.
# The grammar is therefore kept below, term for term, as data, and matched by
# a Thompson simulation over a lazily built DFA: every character is read once,
# so a search is O(len(text)) for every input, and the accepted language is
# exactly that of the replaced regexes, including Unicode ``\s``/``\d`` and
# ``$`` before a final newline.
_SPACE_CHAR = re.compile(r"\s").fullmatch
_DIGIT_CHAR = re.compile(r"\d").fullmatch
_BOUNDARY_CHARS = frozenset(";&|(!")
_SUBSHELL_OPEN = re.compile(r"\$\(")
_CONTROL_WORD = re.compile(r"\b(?:if|elif|then|while|until|do|command|builtin|exec)\b")


def _is_space(char: str) -> bool:
    return _SPACE_CHAR(char) is not None


def _is_name_start(char: str) -> bool:
    return char == "_" or ("A" <= char <= "Z") or ("a" <= char <= "z")


def _is_name_char(char: str) -> bool:
    return _is_name_start(char) or "0" <= char <= "9"


def _lit(text: str) -> tuple:
    return ("seq", tuple(("char", lambda char, expected=expected: char == expected) for expected in text))


def _cls(predicate) -> tuple:
    return ("char", predicate)


def _seq(*parts: tuple) -> tuple:
    return ("seq", parts)


def _alt(*parts: tuple) -> tuple:
    return ("alt", parts)


def _star(part: tuple) -> tuple:
    return ("star", part)


def _plus(part: tuple) -> tuple:
    return _seq(part, _star(part))


def _opt(part: tuple) -> tuple:
    return _alt(part, _seq())


def _boundary_ends(text: str) -> set[int]:
    """End offsets of every ``(?:^|[;&|(!]|\\$\\(|\\b(?:if|...)\\b)`` match."""
    ends = {0}
    ends.update(index + 1 for index, char in enumerate(text) if char in _BOUNDARY_CHARS)
    ends.update(match.end() for match in _SUBSHELL_OPEN.finditer(text))
    # A control word between two \b is a whole \w run, so matches cannot
    # overlap and finditer reports every one of them.
    ends.update(match.end() for match in _CONTROL_WORD.finditer(text))
    return ends


class _BoundaryGrammar:
    """``search``-compatible matcher for ``<boundary> <tail> $``.

    ``search(text)`` returns ``True`` exactly when the replaced regex's
    ``search`` returned a match, and ``None`` otherwise.
    """

    def __init__(self, tail: tuple) -> None:
        self._epsilon: list[list[int]] = []
        self._edges: list[list[tuple[object, int]]] = []
        entry, self._accept = self._build(tail)
        self._entry = self._closure((entry,))
        # Lazily built DFA: each state is an interned set of NFA states.  The
        # automaton is finite, so these tables are bounded by the grammar.
        self._sets: list[frozenset[int]] = []
        self._ids: dict[frozenset[int], int] = {}
        self._dead = self._intern(frozenset())
        self._moves: dict[tuple[int, object], int] = {}
        self._entered: dict[int, int] = {}

    def _state(self) -> int:
        self._epsilon.append([])
        self._edges.append([])
        return len(self._edges) - 1

    def _build(self, node: tuple) -> tuple[int, int]:
        kind, value = node
        start = self._state()
        if kind == "char":
            end = self._state()
            self._edges[start].append((value, end))
        elif kind == "seq":
            end = start
            for part in value:
                part_start, part_end = self._build(part)
                self._epsilon[end].append(part_start)
                end = part_end
        elif kind == "alt":
            end = self._state()
            for part in value:
                part_start, part_end = self._build(part)
                self._epsilon[start].append(part_start)
                self._epsilon[part_end].append(end)
        elif kind == "star":
            end = self._state()
            part_start, part_end = self._build(value)
            self._epsilon[start] += [part_start, end]
            self._epsilon[part_end] += [part_start, end]
        else:  # pragma: no cover - the grammar below is closed
            raise ValueError(f"unknown grammar node {kind!r}")
        return start, end

    def _closure(self, states) -> frozenset[int]:
        pending = list(states)
        seen = set(pending)
        while pending:
            for following in self._epsilon[pending.pop()]:
                if following not in seen:
                    seen.add(following)
                    pending.append(following)
        return frozenset(seen)

    def _intern(self, states: frozenset[int]) -> int:
        found = self._ids.get(states)
        if found is None:
            found = self._ids[states] = len(self._sets)
            self._sets.append(states)
        return found

    def _move(self, state: int, char: str) -> int:
        # Every predicate depends only on an ASCII character's identity or,
        # beyond ASCII, on whether it is \s or \d, so that class is the key.
        key: object = char if char < "\x80" else (_is_space(char), _DIGIT_CHAR(char) is not None)
        target = self._moves.get((state, key))
        if target is None:
            target = self._moves[(state, key)] = self._intern(self._closure([
                following
                for current in self._sets[state]
                for predicate, following in self._edges[current]
                if predicate(char)
            ]))
        return target

    def _enter(self, state: int) -> int:
        """Start another match attempt here, as ``search`` does at a boundary."""
        target = self._entered.get(state)
        if target is None:
            target = self._entered[state] = self._intern(self._sets[state] | self._entry)
        return target

    def search(self, text: str) -> bool | None:
        starts = _boundary_ends(text)
        length = len(text)
        state = self._dead
        for index in range(length + 1):
            if index in starts:
                state = self._enter(state)
            # ``$`` matches at the end and before a final newline.
            if self._accept in self._sets[state] and (
                index == length or (index == length - 1 and text[index] == "\n")
            ):
                return True
            if index < length:
                state = self._move(state, text[index])
        return None


_SPACE = _cls(_is_space)
_SPACES = _star(_SPACE)
_NAME = _seq(_cls(_is_name_start), _star(_cls(_is_name_char)))
_SINGLE_QUOTED = _seq(_lit("'"), _star(_cls(lambda char: char != "'")), _lit("'"))
_DOUBLE_QUOTED = _seq(_lit('"'), _star(_cls(lambda char: char != '"')), _lit('"'))
_WORD = _plus(_cls(lambda char: not _is_space(char)))  # \S+
_OPERAND = _plus(_cls(lambda char: not _is_space(char) and char not in ";&|()"))  # [^\s;&|()]+
# \s*(?:!\s*)?(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s*)*
_ASSIGNMENT_PREFIX = _seq(
    _SPACES,
    _opt(_seq(_lit("!"), _SPACES)),
    _star(_seq(_NAME, _lit("="), _alt(_SINGLE_QUOTED, _DOUBLE_QUOTED, _WORD), _SPACES)),
)
COMMAND_BOUNDARY = _BoundaryGrammar(_ASSIGNMENT_PREFIX)
# These are still shell command boundaries: the grep executable is wrapped
# rather than invoked as the first word.  Keeping the wrappers explicit avoids
# treating prose such as `echo sudo grep ...` as an assertion while covering
# the common command forms used by backlog verifies.
# (?:(?:sudo|env|git|xargs)(?:\s+-[^\s;&|()]+|\s+NAME=[^\s;&|()]+)*\s+)+
WRAPPED_COMMAND_BOUNDARY = _BoundaryGrammar(_seq(
    _ASSIGNMENT_PREFIX,
    _plus(_seq(
        _alt(_lit("sudo"), _lit("env"), _lit("git"), _lit("xargs")),
        _star(_alt(
            _seq(_plus(_SPACE), _lit("-"), _OPERAND),
            _seq(_plus(_SPACE), _NAME, _lit("="), _OPERAND),
        )),
        _plus(_SPACE),
    )),
))
# (?:\d*(?:>>>|<<<|>>|<<|>|<)\s*(?:'[^']*'|"[^"]*"|[^\s;&|()]+)\s*)+
REDIRECTION_BOUNDARY = _BoundaryGrammar(_seq(
    _ASSIGNMENT_PREFIX,
    _plus(_seq(
        _star(_cls(lambda char: _DIGIT_CHAR(char) is not None)),
        _alt(*(_lit(operator) for operator in (">>>", "<<<", ">>", "<<", ">", "<"))),
        _SPACES,
        _alt(_SINGLE_QUOTED, _DOUBLE_QUOTED, _OPERAND),
        _SPACES,
    )),
))
NESTED_SHELL = re.compile(r"\b(?:bash|sh|zsh)\s+-c\b")
ID = re.compile(r"^B-\d{3}$")
COMMENT_PREFIXES = ("//", "#", "/*", "<!--", "*", "--")
MAX_BACKLOG_BYTES = 2_000_000
MAX_NESTED_SHELL_DEPTH = 8
MAX_NESTED_PAYLOAD_BYTES = 200_000
MAX_VERIFY_LINE_BYTES = 8_192
POSIX_CLASSES = {
    "[[:space:]]": r"\s",
    "[[:digit:]]": r"\d",
    "[[:alpha:]]": r"[A-Za-z]",
    "[[:alnum:]]": r"[A-Za-z0-9]",
}


class InstrumentError(RuntimeError):
    """The census cannot be trusted."""


@dataclass(frozen=True)
class GrepCheck:
    record_id: str
    line: int
    pattern: str
    options: str
    source: str
    quote: str = ""
    resolved_patterns: tuple[str, ...] = ()
    source_kind: str = "unknown"
    comment_prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ShellToken:
    value: str
    start: int
    end: int
    kind: str = "word"


@dataclass(frozen=True)
class Census:
    records: int
    command_records: int
    manual_records: int
    grep_invocations: int
    assertions: tuple[GrepCheck, ...]
    unsafe: tuple[GrepCheck, ...]
    indeterminate: tuple[GrepCheck, ...]


# Derived independently from the exact reanchored fenced-record tree (2026-09-09).
# Keep these closed: adding/removing/changing a record must require an explicit
# census reconciliation instead of silently shrinking or growing the proof.
EXPECTED_RECORDS = 373
EXPECTED_COMMAND_RECORDS = 354
EXPECTED_MANUAL_RECORDS = 19
EXPECTED_GREP_INVOCATIONS = 194
EXPECTED_ASSERTIONS = 191

@lru_cache(maxsize=32)
def _records(backlog: str) -> list[dict[str, object]]:
    if len(backlog.encode("utf-8")) > MAX_BACKLOG_BYTES:
        raise InstrumentError("backlog exceeds bounded census size")
    blocks = list(FENCE.finditer(backlog))
    if not blocks:
        raise InstrumentError("no ```backlog records found")
    if len(BACKLOG_OPEN.findall(backlog)) != len(blocks):
        raise InstrumentError("unclosed or malformed ```backlog fence")
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, match in enumerate(blocks, 1):
        try:
            record = yaml.safe_load(match.group(1))
        except yaml.YAMLError as error:
            raise InstrumentError(f"record {index} has invalid YAML: {error}") from error
        if not isinstance(record, dict):
            raise InstrumentError(f"record {index} is not a mapping")
        record_id = record.get("id")
        if not isinstance(record_id, str) or not ID.fullmatch(record_id):
            raise InstrumentError(f"record {index} has malformed id: {record_id!r}")
        if record_id in seen:
            raise InstrumentError(f"duplicate backlog id: {record_id}")
        seen.add(record_id)
        records.append(record)
    return records


SHELL_VARIABLE = re.compile(r"(?<!\\)\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")


def _shell_values(verify: str) -> dict[str, tuple[str, ...]]:
    """Resolve only literal assignments and finite ``for x in ...`` lists."""
    values: dict[str, tuple[str, ...]] = {}
    # printf command substitutions are deliberately restricted to a single
    # quoted format string; no command or shell expansion is evaluated here.
    assignment = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"$]*)\"|'([^']*)'|\$\(printf\s+\"([^\"$]*)\"\))"
    )
    for match in assignment.finditer(verify):
        value = next((item for item in match.groups()[1:] if item is not None), None)
        if value is not None:
            values[match.group(1)] = (value,)
    for match in re.finditer(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+(.+?);\s*do\b", verify):
        try:
            words = tuple(shlex.split(match.group(2)))
        except ValueError:
            continue
        expanded: list[str] = []
        for word in words:
            variable = SHELL_VARIABLE.fullmatch(word)
            if variable:
                expanded.extend(values.get(variable.group("braced") or variable.group("plain"), ()))
            else:
                expanded.append(word)
        if expanded and all("$" not in word and "$(" not in word for word in expanded):
            values[match.group(1)] = tuple(expanded)
    return values


_GREP_SHORT_VALUE_OPTIONS = frozenset("e f A B C D d m".split())
_GREP_LONG_VALUE_OPTIONS = frozenset(
    {
        "after-context",
        "before-context",
        "binary-files",
        "color",
        "context",
        "directories",
        "exclude",
        "exclude-from",
        "group-separator",
        "include",
        "label",
        "max-count",
        "regexp",
        "file",
    }
)


def _redirection_parts(raw: str) -> tuple[str, str] | None:
    match = re.match(r"^(?:\d*)(>>>|<<<|>>|<<|>|<)(.*)$", raw)
    return (match.group(1), match.group(2)) if match else None


def _skip_grep_redirection(
    tokens: tuple[_ShellToken, ...], index: int, text: str
) -> tuple[int, bool]:
    """Skip a shell redirection and its target; return process-substitution state."""
    token = tokens[index]
    parts = _redirection_parts(text[token.start : token.end])
    if parts is None:
        return index + 1, False
    _, attached = parts
    # `<(...)` and `>(...)` are streams, not literal source files.  Returning a
    # sentinel makes the caller fail closed even when a later positional file
    # happens to have a recognizable extension.
    if attached.startswith("("):
        return index + 1, True
    if attached:
        return index + 1, False
    if index + 1 < len(tokens) and tokens[index + 1].kind == "word":
        return index + 2, False
    return index + 1, False


def _skip_grep_option(
    tokens: tuple[_ShellToken, ...], index: int
) -> tuple[int, bool]:
    """Skip one grep option and its argument, if that option takes one."""
    value = tokens[index].value
    if value == "--":
        return index + 1, False
    if value.startswith("--"):
        name, separator, _ = value[2:].partition("=")
        if separator:
            return index + 1, name in {"regexp", "file"}
        if name not in _GREP_LONG_VALUE_OPTIONS:
            return index + 1, False
        return index + 2, name in {"regexp", "file"}
    body = value[1:]
    for position, option in enumerate(body):
        if option in _GREP_SHORT_VALUE_OPTIONS:
            # `-efoo`/`-ffile` carries its argument in the same token; plain
            # `-e foo`/`-f file` consumes the next shell word.
            return (
                (index + 1 if position + 1 < len(body) else index + 2),
                option in {"e", "f"},
            )
    return index + 1, False


def _grep_file_operands(line: str, grep_start: int) -> tuple[str, ...]:
    """Return only literal file operands from one grep command.

    The pattern is deliberately skipped before collecting operands.  This
    prevents a regex such as ``foo.rs`` from becoming evidence that the target
    is Rust.  Missing, variable, redirected, process-substitution, and piped
    targets remain empty so the caller can fail closed instead of guessing a
    syntax.
    """
    tokens = _shell_tokens(line[grep_start:])
    if not tokens or tokens[0].value != "grep":
        return ()
    text = line[grep_start:]
    index = 1
    options_end = False
    pattern_from_option = False
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "separator":
            return ()
        if token.kind == "redirection":
            index, process_substitution = _skip_grep_redirection(tokens, index, text)
            if process_substitution:
                return ("<process-substitution>",)
            continue
        value = token.value
        if not options_end and value == "--":
            options_end = True
            index += 1
            continue
        if not options_end and value.startswith("-") and value != "-":
            index, option_provides_pattern = _skip_grep_option(tokens, index)
            pattern_from_option = pattern_from_option or option_provides_pattern
            continue
        break
    if index >= len(tokens):
        return ()
    if not pattern_from_option:
        # Without -e/-f, the first positional word is grep's pattern, not a
        # source file.  A literal `-` is still a pattern in this position.
        index += 1
    operands: list[str] = []
    while index < len(tokens) and tokens[index].kind != "separator":
        token = tokens[index]
        if token.kind == "redirection":
            index, process_substitution = _skip_grep_redirection(tokens, index, text)
            if process_substitution:
                operands.append("<process-substitution>")
            continue
        if token.kind == "word":
            operands.append(token.value)
        index += 1
    return tuple(operands)


def _source_kind(
    line: str, verify: str, grep_start: int | None = None
) -> tuple[str, tuple[str, ...]]:
    """Classify the likely target syntax for a grep assertion.

    The classifier is intentionally conservative: a missing target keeps the
    full comment-prefix set, while known mixed targets union their prefixes.
    """
    assignments: dict[str, str] = {}
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']+)'|\"([^\"]+)\"|([^\s;&|()]+))",
        verify,
    ):
        assignments[match.group(1)] = next(
            part for part in match.groups()[1:] if part is not None
        )
    if grep_start is None:
        grep_start = line.find("grep")
    operands = _grep_file_operands(line, grep_start) if grep_start >= 0 else ()
    resolved_operands: list[str] = []
    for operand in operands:
        names = re.findall(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)", operand)
        if not names:
            resolved_operands.append(operand)
            continue
        resolved = operand
        for name in names:
            if name not in assignments:
                return "unknown", COMMENT_PREFIXES
            resolved = resolved.replace("${" + name + "}", assignments[name])
            resolved = resolved.replace("$" + name, assignments[name])
        resolved_operands.append(resolved)
    # A grep with no proven file operand is not classified from its pattern or
    # from unrelated paths elsewhere in the verify payload.  Stdin/pipes are
    # intentionally unknown and therefore indeterminate at census level.
    if not resolved_operands or "<process-substitution>" in resolved_operands:
        return "unknown", COMMENT_PREFIXES

    kinds: list[tuple[str, tuple[str, ...]]] = []
    for operand in resolved_operands:
        if operand in {"-", "<process-substitution>"}:
            return "unknown", COMMENT_PREFIXES
        basename = operand.rsplit("/", 1)[-1]
        # Only a basename suffix controls syntax. A directory named
        # `fixtures.md` must not turn `fixtures.md/generated/file.rs` into a
        # Markdown target, and a brace glob with several suffixes is mixed.
        suffixes = {
            suffix.lower()
            for suffix in re.findall(r"\.([A-Za-z0-9]+)(?=$|[,}])", basename)
        }
        if "rs" in suffixes:
            kinds.append(("rust", ("//", "/*", "*")))
        elif suffixes & {"ts", "tsx", "js", "mjs"}:
            kinds.append(("typescript", ("//", "/*", "*")))
        elif (
            suffixes & {"yaml", "yml", "toml", "sql", "bazelrc", "env"}
            or ".github/workflows" in operand
            or "migrations/" in operand
            or "Dockerfile" in operand
        ):
            kinds.append(("config", ("#",)))
        elif suffixes & {"sh"}:
            kinds.append(("shell", ("#",)))
        elif suffixes & {"py"}:
            kinds.append(("python", ("#",)))
        elif suffixes & {"md", "mdx"} or "apps/docs" in operand or "marketing/" in operand:
            kinds.append(("markdown", ("#", "<!--", ">", "*", "-")))
        elif suffixes & {"json"}:
            kinds.append(("data", ()))
        else:
            return "unknown", COMMENT_PREFIXES
    if len(set(kind for kind, _ in kinds)) == 1:
        return kinds[0]
    # A command may legitimately name several files. Never let the first
    # extension decide: union every known syntax's comment prefixes.
    prefixes = tuple(dict.fromkeys(prefix for _, values in kinds for prefix in values))
    return "mixed", prefixes or COMMENT_PREFIXES


def _is_command_boundary(text: str) -> bool:
    """Recognize direct, wrapped, and redirection-prefixed shell commands."""
    return bool(
        COMMAND_BOUNDARY.search(text)
        or WRAPPED_COMMAND_BOUNDARY.search(text)
        or REDIRECTION_BOUNDARY.search(text)
    )


_COMMAND_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "{", "}"}
_CONTROL_WORDS = {"if", "elif", "then", "while", "until", "do", "command", "builtin", "exec", "!"}
_KNOWN_WRAPPERS = {"sudo", "env", "git", "xargs"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECTION = re.compile(r"^(?:\d*)?(?:>>>|<<<|>>|<<|>|<)")


def _shell_tokens(text: str) -> tuple[_ShellToken, ...]:
    """Lex enough shell structure to distinguish commands from prose.

    This is deliberately not a shell interpreter.  It preserves token spans,
    separators, assignments, and redirections so the grep scanner can prove
    that a match starts an executable word.  Anything not understood by this
    small grammar is left as a word and handled by the fail-closed wrapper
    classification below.
    """
    tokens: list[_ShellToken] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index].isspace():
            index += 1
            continue
        if text[index] == "#":
            # An unquoted # starts a shell comment when it begins a word.
            if not tokens or text[index - 1].isspace():
                break
        start = index
        if text.startswith("&&", index) or text.startswith("||", index) or text.startswith(";;", index):
            op = text[index : index + 2]
            tokens.append(_ShellToken(op, index, index + 2, "separator"))
            index += 2
            continue
        if text[index] in ";|&(){}":
            tokens.append(_ShellToken(text[index], index, index + 1, "separator"))
            index += 1
            continue
        value: list[str] = []
        quote: str | None = None
        while index < length:
            char = text[index]
            if quote is None and (char.isspace() or char in ";|&(){}"):
                break
            if quote is None and char == "#" and (index == start or text[index - 1].isspace()):
                break
            if char == "\\" and quote != "'":
                if index + 1 >= length:
                    value.append("\\")
                    index += 1
                else:
                    value.append(text[index + 1])
                    index += 2
                continue
            if char in "'\"":
                if quote is None:
                    quote = char
                elif quote == char:
                    quote = None
                else:
                    value.append(char)
                index += 1
                continue
            value.append(char)
            index += 1
        if quote is not None:
            # Keep the malformed word visible; it will not be mistaken for a
            # command because its span starts before any inner grep spelling.
            value.append(quote)
        raw = text[start:index]
        kind = "word"
        if _REDIRECTION.match(raw):
            kind = "redirection"
        elif _ASSIGNMENT.match(raw):
            kind = "assignment"
        tokens.append(_ShellToken("".join(value), start, index, kind))
    return tuple(tokens)


def _grep_command_kind(line: str, offset: int) -> str | None:
    """Return direct/wrapped/unknown-wrapper, or None for grep-looking prose."""
    prefix_text = line[:offset]
    # A command substitution starts a fresh command even when it appears in a
    # quoted argument (e.g. ``test "$(grep -c ...)"``).  The lightweight lexer
    # intentionally keeps that surrounding word intact, so recurse on the
    # substitution body before looking at ordinary shell tokens.
    substitution = prefix_text.rfind("$(")
    if substitution >= 0 and (substitution == 0 or prefix_text[substitution - 1] != "\\"):
        nested_prefix = prefix_text[substitution + 2 :]
        nested_line = nested_prefix + "grep"
        nested_kind = _grep_command_kind(nested_line, len(nested_prefix))
        if nested_kind is not None:
            return nested_kind
    tokens = _shell_tokens(line)
    target_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if token.start == offset and token.value == "grep" and token.kind == "word"
        ),
        None,
    )
    if target_index is None:
        return None
    prefix = list(tokens[:target_index])
    boundary = -1
    for index, token in enumerate(prefix):
        if token.kind == "separator" and token.value in _COMMAND_SEPARATORS:
            boundary = index
    segment = prefix[boundary + 1 :]
    while segment and segment[0].kind in {"assignment", "redirection"}:
        segment.pop(0)
    while segment and segment[0].kind == "word" and segment[0].value in _CONTROL_WORDS:
        segment.pop(0)
    if not segment:
        return "direct"
    if segment[0].kind == "word" and segment[0].value in _KNOWN_WRAPPERS:
        return "wrapped"
    return "unknown-wrapper"


def _resolved_patterns(pattern: str, verify: str) -> tuple[tuple[str, ...], bool]:
    variables = SHELL_VARIABLE.findall(pattern)
    if not variables:
        return (pattern,), False
    values = _shell_values(verify)
    resolved = [pattern]
    unresolved = False
    for braced, plain in variables:
        name = braced or plain
        options = values.get(name)
        if not options:
            unresolved = True
            continue
        expanded: list[str] = []
        for candidate in resolved:
            for value in options:
                expanded.append(candidate.replace("${" + name + "}", value).replace("$" + name, value))
        resolved = expanded
    return tuple(resolved), unresolved


def _generated_hex_pattern_file(check: GrepCheck, verify: str) -> bool:
    """Recognize B-061's generated ``^hex`` pattern file without executing it."""
    generated = any(
        not line.lstrip().startswith("#")
        and (("s|^|^|" in line and "$tmp/pat" in line) or "$tmp/hit" in line)
        and ">" in line
        for line in verify.splitlines()
    )
    return (
        "f" in check.options
        and ("$tmp/pat" in check.pattern or "$tmp/hit" in check.pattern)
        and generated
        and ("$tmp/reach" in check.source or "$tmp/pairs" in check.source)
    )


def _grep_checks(record: dict[str, object]) -> tuple[list[GrepCheck], int, list[GrepCheck]]:
    verify = record.get("verify")
    if not isinstance(verify, str) or verify.strip() == "manual":
        return [], 0, []
    return _grep_checks_text(verify, str(record["id"]), verify)


def _grep_checks_text(
    verify: str,
    record_id: str,
    context: str,
    line_offset: int = 0,
    depth: int = 0,
) -> tuple[list[GrepCheck], int, list[GrepCheck]]:
    """Census shell text and recurse into literal ``shell -c`` payloads.

    A quoted ``bash -c '...'`` is a second shell program, not prose. Its
    payload is masked from the outer scan (newlines are retained for line
    numbers) and scanned recursively. Dynamic or unterminated payloads fail
    closed instead of silently shrinking the grep population.
    """
    if depth > MAX_NESTED_SHELL_DEPTH:
        raise InstrumentError("nested shell depth exceeds bounded census limit")
    if len(verify.encode("utf-8")) > MAX_NESTED_PAYLOAD_BYTES:
        raise InstrumentError("nested shell payload exceeds bounded census limit")
    if any(len(line.encode("utf-8")) > MAX_VERIFY_LINE_BYTES for line in verify.splitlines()):
        raise InstrumentError("verify line exceeds bounded parser limit")
    masked, nested = _mask_nested_shells(verify)
    checks: list[GrepCheck] = []
    indeterminate: list[GrepCheck] = []
    invocations = 0
    known_starts: set[int] = set()
    for line_number, line in enumerate(masked.splitlines(), 1):
        known_starts: set[int] = set()
        for match in GREP.finditer(line):
            # A grep-looking string in an embedded Python/awk expression is
            # not a shell invocation. Require a structurally valid command
            # token; unknown wrappers are counted but fail closed below.
            command_kind = _grep_command_kind(line, match.start())
            if command_kind is None:
                continue
            invocations += 1
            known_starts.add(match.start())
            options = match.group("options") or ""
            pattern = match.group("pattern")
            resolved, unresolved = _resolved_patterns(pattern, context)
            kind, prefixes = _source_kind(line, context, match.start())
            check = GrepCheck(
                record_id=record_id,
                line=line_number + line_offset,
                pattern=pattern,
                options=options,
                source=line.strip(),
                quote=match.group("quote"),
                resolved_patterns=resolved,
                source_kind=kind,
                comment_prefixes=prefixes,
            )
            # `grep -v` is a filter in a pipeline, not a positive capability
            # assertion. It remains in the invocation census, but is not in the
            # population whose comment sensitivity determines this item.
            if "v" not in options.replace("--", ""):
                checks.append(check)
            if unresolved and not _generated_hex_pattern_file(check, verify):
                indeterminate.append(check)
            if check.source_kind == "unknown":
                indeterminate.append(check)
            if command_kind == "unknown-wrapper":
                indeterminate.append(check)
        # The shell permits a bare regex word (`grep unsafe file`) in addition
        # to the quoted form above.  Parse it separately, retaining the same
        # boundary and polarity rules.  A variable or shell expression is
        # intentionally not guessed: it becomes an explicit indeterminate
        # population member below.
        for match in GREP_UNQUOTED.finditer(line):
            if match.start() in known_starts:
                continue
            command_kind = _grep_command_kind(line, match.start())
            if command_kind is None:
                continue
            invocations += 1
            known_starts.add(match.start())
            options = match.group("options") or ""
            pattern = match.group("pattern")
            resolved, unresolved = _resolved_patterns(pattern, context)
            kind, prefixes = _source_kind(line, context, match.start())
            check = GrepCheck(
                record_id=record_id,
                line=line_number + line_offset,
                pattern=pattern,
                options=options,
                source=line.strip(),
                resolved_patterns=resolved,
                source_kind=kind,
                comment_prefixes=prefixes,
            )
            if "v" not in options.replace("--", ""):
                checks.append(check)
            if unresolved and not _generated_hex_pattern_file(check, verify):
                indeterminate.append(check)
            if check.source_kind == "unknown":
                indeterminate.append(check)
            if command_kind == "unknown-wrapper":
                indeterminate.append(check)
        # A grep invocation with an unquoted/dynamic pattern is still an
        # invocation, but its dialect and polarity cannot be proven by this
        # parser.  Count it and fail closed instead of silently shrinking the
        # assertion population.
        for word in re.finditer(r"\bgrep\b", line):
            if word.start() in known_starts:
                continue
            command_kind = _grep_command_kind(line, word.start())
            if command_kind is None:
                continue
            invocations += 1
            indeterminate.append(
                GrepCheck(
                    record_id=record_id,
                    line=line_number + line_offset,
                    pattern="",
                    options="",
                    source=line.strip(),
                )
            )
    for payload, first_line in nested:
        nested_checks, nested_invocations, nested_indeterminate = _grep_checks_text(
            payload, record_id, context, line_offset + first_line - 1, depth + 1
        )
        checks.extend(nested_checks)
        invocations += nested_invocations
        indeterminate.extend(nested_indeterminate)
    return checks, invocations, indeterminate


def _is_shell_expansion(text: str, offset: int) -> bool:
    """Return whether ``$`` at *offset* starts active shell syntax."""
    if offset + 1 >= len(text):
        return False
    next_char = text[offset + 1]
    return (
        next_char in "{("
        or next_char in "@*#?$!-0123456789"
        or next_char == "_"
        or next_char.isalpha()
    )


def _decode_nested_payload(text: str, start: int) -> tuple[str, int]:
    """Decode one quoted ``shell -c`` argument using shell quote rules."""
    if start >= len(text) or text[start] not in "\"'":
        raise InstrumentError("nested shell -c payload is not a literal quote")
    quote = text[start]
    index = start + 1
    decoded: list[str] = []
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
                index += 1
                continue
            # Backslash has no special meaning in a POSIX single-quoted word.
            decoded.append(char)
            index += 1
            continue
        if quote == '"' and char == '"':
            quote = ""
            index += 1
            continue
        if not quote:
            # Adjacent quoted/unquoted pieces form one shell word.  This is
            # how a literal payload can contain an apostrophe, and it is also
            # where an expansion can be smuggled after a literal prefix.
            if char.isspace() or char in ";;&|()<>\n":
                return "".join(decoded), index
            if char in "\"'":
                quote = char
                index += 1
                continue
            if char == "\\":
                if index + 1 >= len(text):
                    raise InstrumentError("unterminated nested shell -c payload")
                decoded.append(text[index + 1])
                index += 2
                continue
            if char == "$" and _is_shell_expansion(text, index):
                raise InstrumentError(
                    "nested shell -c payload contains an active expansion"
                )
            if char == "`":
                raise InstrumentError(
                    "nested shell -c payload contains an active command substitution"
                )
            decoded.append(char)
            index += 1
            continue
        # In double quotes, backslash quotes only $, `, ", \\, and newline.
        if char == "\\":
            if index + 1 >= len(text):
                raise InstrumentError("unterminated nested shell -c payload")
            escaped = text[index + 1]
            if escaped in "$`\"\\\n":
                if escaped != "\n":
                    decoded.append(escaped)
            else:
                decoded.extend(("\\", escaped))
            index += 2
            continue
        if char == "$" and _is_shell_expansion(text, index):
            raise InstrumentError(
                "nested shell -c payload contains an active expansion"
            )
        if char == "`":
            raise InstrumentError(
                "nested shell -c payload contains an active command substitution"
            )
        decoded.append(char)
        index += 1
    if not quote:
        return "".join(decoded), index
    raise InstrumentError("unterminated nested shell -c payload")


def _mask_nested_shells(text: str) -> tuple[str, list[tuple[str, int]]]:
    """Mask static ``bash|sh|zsh -c`` bodies and return their payloads."""
    spans: list[tuple[int, int, str, int]] = []
    for match in NESTED_SHELL.finditer(text):
        # An outer match owns its quoted body; inner shell text is discovered
        # when that body is scanned recursively.
        if any(start <= match.start() < end for start, end, _, _ in spans):
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        if not _is_command_boundary(text[line_start : match.start()]):
            continue
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
        payload, end = _decode_nested_payload(text, pos)
        first_line = text.count("\n", 0, pos + 1) + 1
        spans.append((match.start(), end, payload, first_line))

    if not spans:
        return text, []
    chars = list(text)
    payloads: list[tuple[str, int]] = []
    for start, end, payload, first_line in spans:
        payloads.append((payload, first_line))
        for index in range(start, end):
            if chars[index] != "\n":
                chars[index] = " "
    return "".join(chars), payloads


def _as_python_regex(pattern: str, options: str = "") -> re.Pattern[str]:
    # The census sees shell source before double-quoted `\\` escapes are
    # reduced to one regex escape by the shell.
    pattern = pattern.replace("\\\\", "\\")
    if "F" in options:
        return re.compile(re.escape(pattern))
    translated = pattern
    translated = translated.replace("[^[:space:]]", r"[^\s]")
    translated = translated.replace("[[:space:]-]", r"[\s-]")
    for source, target in POSIX_CLASSES.items():
        translated = translated.replace(source, target)
    # In basic grep, escaped `|` is alternation while an unescaped pipe is
    # literal.  ERE reverses that rule.  Preserve the distinction for Python's
    # regex dialect, especially for Markdown-table and shell-`||` checks.
    if "E" not in options:
        # Python defaults to ERE.  BRE only enables grouping/quantifiers when
        # those operators are escaped, so normalize the opposite spellings
        # before compiling.  This matters for literal code such as
        # ``blockConcurrencyWhile(async () =>`` in the live backlog.
        normalized: list[str] = []
        index = 0
        while index < len(translated):
            char = translated[index]
            if char == "\\" and index + 1 < len(translated):
                escaped = translated[index + 1]
                if escaped in "(){}+?":
                    # BRE enables these operators only in escaped form.
                    normalized.append(escaped)
                    index += 2
                    continue
            if char in "(){}+?":
                normalized.append("\\" + char)
            else:
                normalized.append(char)
            index += 1
        translated = "".join(normalized)
        marker = "__B155_ALTERNATION__"
        translated = translated.replace(r"\|", marker)
        translated = translated.replace("|", r"\|")
        translated = translated.replace(marker, "|")
    return re.compile(translated)


def _split_alternatives(pattern: str, options: str) -> list[str]:
    """Split only real BRE/ERE alternation operators, not quoted pipes."""
    needle = "|" if "E" in options else r"\|"
    return pattern.split(needle) if needle in pattern else [pattern]


def _regex_witness(pattern: str, options: str) -> list[str]:
    """Build conservative text witnesses for the complete regex expression."""
    if "F" in options:
        return [pattern]
    witnesses: list[str] = []
    for branch in _split_alternatives(pattern, options):
        value = branch
        # Shell-escaped regex punctuation is represented by its literal byte;
        # BRE grouping delimiters are syntax and therefore disappear.
        value = re.sub(r"\\([()])", "", value)
        value = re.sub(r"\\([.|+?{}])", r"\1", value)
        value = value.replace(r"\[", "[").replace(r"\]", "]")
        value = value.replace(r"\*", "*")
        value = value.replace(r"\^", "^").replace(r"\$", "$")
        value = value.replace(r"[[:space:]]", " ")
        value = value.replace(r"[[:digit:]]", "0")
        value = value.replace(r"[[:alpha:]]", "a")
        value = value.replace(r"[[:alnum:]]", "a")
        value = re.sub(r"\[\^?[^]]*\]", "a", value)
        value = re.sub(r"\.\*|\.\+|\.\?", "x", value)
        value = value.replace(".", "x")
        value = re.sub(r"\\[+?]", "x", value)
        value = re.sub(r"\\\{\d+(?:,\d*)?\\\}", "x", value)
        value = value.replace("^", "", 1) if value.startswith("^") else value
        if value.endswith("$"):
            value = value[:-1]
        value = re.sub(r"[+?*]", "", value)
        value = re.sub(r"\{\d+(?:,\d*)?\}", "", value)
        value = value.replace("(", "").replace(")", "")
        witnesses.append(value)
    return witnesses or ["verify"]


def _matches_comment(check: GrepCheck) -> bool:
    """Return true when the assertion regex can match a comment-shaped line."""
    # A double-quoted shell variable is expanded at runtime.  Its value is
    # unknown to the census, so conservatively mark it unsafe; the repair tool
    # can put a line guard around the expansion without resolving its value.
    if check.quote == '"' and re.search(r"(?<!\\)\$[A-Za-z_][A-Za-z0-9_]*", check.pattern) and not check.resolved_patterns:
        return True
    for pattern in check.resolved_patterns or (check.pattern,):
        # A leading negated character class is the reviewed line guard for
        # the target syntax.  Evaluate it structurally before witness
        # generation: the generic regex witnesses cannot safely model nested
        # POSIX classes and would otherwise mistake a guarded expression for
        # a comment match.
        guard = re.match(r"^\^\[\^([^]]+)\]\*", pattern)
        if guard:
            excluded = set(guard.group(1))
            prefixes = check.comment_prefixes or COMMENT_PREFIXES
            if all(prefix and prefix[0] in excluded for prefix in prefixes):
                continue
        try:
            expression = _as_python_regex(pattern, check.options)
        except re.error:
            return True  # An unmodelled dialect is an instrument gap, fail closed.
        for witness in _regex_witness(pattern, check.options):
            prefixes = check.comment_prefixes or COMMENT_PREFIXES
            probes = tuple(f"{prefix} {witness}" for prefix in prefixes)
            if any(expression.search(probe) for probe in probes):
                return True
    return False


@lru_cache(maxsize=32)
def census(backlog: str) -> Census:
    records = _records(backlog)
    assertions: list[GrepCheck] = []
    invocations = 0
    command_records = 0
    manual_records = 0
    unknown_indeterminate: list[GrepCheck] = []
    for record in records:
        verify = record.get("verify")
        if isinstance(verify, str) and verify.strip() == "manual":
            manual_records += 1
        elif isinstance(verify, str):
            command_records += 1
        checks, count, unknown = _grep_checks(record)
        assertions.extend(checks)
        unknown_indeterminate.extend(unknown)
        invocations += count
    unsafe: list[GrepCheck] = []
    indeterminate: list[GrepCheck] = list(unknown_indeterminate)
    for check in assertions:
        try:
            _as_python_regex(check.pattern, check.options)
        except re.error:
            indeterminate.append(check)
        if _matches_comment(check):
            unsafe.append(check)
    result = Census(
        records=len(records),
        command_records=command_records,
        manual_records=manual_records,
        grep_invocations=invocations,
        assertions=tuple(assertions),
        unsafe=tuple(unsafe),
        indeterminate=tuple(indeterminate),
    )
    if (
        result.records != EXPECTED_RECORDS
        or result.command_records != EXPECTED_COMMAND_RECORDS
        or result.manual_records != EXPECTED_MANUAL_RECORDS
        or result.grep_invocations != EXPECTED_GREP_INVOCATIONS
        or len(result.assertions) != EXPECTED_ASSERTIONS
    ):
        raise InstrumentError(
            "B-155 population drift: "
            f"records={result.records}, command_records={result.command_records}, "
            f"manual={result.manual_records}, grep_invocations={result.grep_invocations}, "
            f"assertions={len(result.assertions)}"
        )
    return result
