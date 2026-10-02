#!/usr/bin/env python3
"""rust_clippy_debt — hold a package's clippy debt to a reviewed baseline, one diagnostic at a time.

Used by the clippy job of `.github/workflows/rust-affected-tests.yml` for each
package in its CLIPPY_DEBT ledger. Such a package is left out of the strict
`-D warnings` run because main already fails it. Instead it is linted with
every lint capped at warn, and this script compares what clippy reported with
the committed baseline `.github/rust-affected-tests/clippy-debt/<package>.txt`.
The ledger is empty today: listing a package narrows the lane's `-D warnings`
gate, so an entry needs the owner's explicit scope amendment.

IDENTITY
--------
A diagnostic is identified by its lint code, its message, its file, the
source text of the lines its primary span covers, the highlighted text, and
the source text of every macro call site it was expanded from. Line and
column numbers are NOT part of it: an edit elsewhere in the file that moves a
diagnostic up or down leaves it alone. Any edit to the flagged code changes
it.

A diagnostic without a primary span (a crate-level lint such as
`clippy::multiple_crate_versions`, or a compiler session warning) has no
source to identify it by. Its identity is its lint code and message, with the
file and source fields empty, and it is compared like any other. The only
messages dropped are rustc's end-of-crate summaries ("3 warnings emitted",
"aborting due to 2 previous errors"), which restate counts of diagnostics the
stream already carries. They are recognized by exact text, and only when they
also have no span and no lint code.

Occurrences are first deduplicated by exact position, so the same diagnostic
reported by two targets (the lib, and the lib compiled for its tests) counts
once. Then they are counted by identity. Two flagged expressions with
identical text in one file are two entries of the same identity.

VERDICT
-------
Two checks, both required.

RATCHET: the committed baseline against the base revision's. The baseline in
the checkout under test is part of the change, so on its own it proves
nothing: a change that adds a diagnostic could commit the regenerated baseline
that lists it. The workflow therefore also hands over the same baseline file
as committed at the base revision (`--reviewed-baseline`), and the committed
baseline must be a sub-multiset of it. An identity the base revision does not
list, or lists fewer times, is ADDED, and that is red. The one exception is
`--bootstrap`, which the workflow passes only when the base revision has no
baseline file for the package at all, i.e. the change that introduces it.
That run prints a warning that none of its entries were held to a base.

MATCH: what clippy reported against the committed baseline, entry for entry.
* an identity that occurs more often than the baseline lists it is a NEW
  diagnostic. That is red, and each one is printed with its location.
* an identity the baseline lists more often than it occurs is FIXED debt.
  That is also red until the baseline drops it.
Comparing totals would admit a new diagnostic whenever an old one is fixed.
This compares identities, so it does not. Together the two checks hold the
current diagnostics to a subset of the base revision's reviewed baseline.

Without `--messages` only the ratchet runs. The workflow does that for a
ledger package the change did not select, so its baseline is still held to
the base revision's although clippy did not lint it.

WHAT IT DOES NOT SEE: a new diagnostic whose identity equals a fixed one —
the same lint and message on byte-identical code in the same file — in the
same change. Seeing it would need line numbers, and then every unrelated edit
above a diagnostic would turn the lane red. Nor does it guard the lane against
an edit to the lane itself: the workflow, this script and the ledger are read
from the change under test, so a change to any of them is reviewed as a
change to the gate. That includes renaming the baseline directory, which
turns every ledger entry into a bootstrap.

FAIL-CLOSED
-----------
A missing, unreadable or non-canonical baseline (committed or reviewed), no
statement of which reviewed baseline applies (`--reviewed-baseline` or
`--bootstrap` is required), a clippy stream that does not end in a successful
`build-finished`, a stream with no `compiler-artifact` for the package (clippy
did not check it, so its silence proves nothing), and an empty baseline that
matches an empty result (the package is clean: delete the ledger entry) are
all failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# Bound one text field. Longer text keeps its prefix plus a digest of the whole,
# so the identity stays exact but a baseline line stays readable.
TEXT_LIMIT = 240

# Absolute paths that differ between machines or builds, rewritten to a stable
# placeholder. Spans in workspace members are already workspace-relative.
_PATH_REWRITES = (
    (re.compile(r"^.*/registry/src/[^/]+/"), "<registry>/"),
    (re.compile(r"^.*/git/checkouts/[^/]+/[^/]+/"), "<git>/"),
    (re.compile(r"^.*/build/([A-Za-z0-9_.-]+)-[0-9a-f]{16}/out/"), r"<out:\1>/"),
    (re.compile(r"^/rustc/[0-9a-f]+/"), "<rustc>/"),
)

# rustc's end-of-crate summaries, as `print_error_count` words them (the
# count-less "previous error" is the pre-1.74 spelling). Nothing looser: a
# message this does not match in full is a diagnostic.
_SUMMARY = re.compile(
    r"\d+ warnings? emitted"
    r"|aborting due to (?:\d+ )?previous errors?(?:; \d+ warnings? emitted)?"
)

# Where a diagnostic without a primary span is reported.
NO_SPAN = "<no primary span>"

BASELINE_HEADER = (
    "# Reviewed clippy debt for {package}: one diagnostic per line, read by\n"
    "# scripts/rust_clippy_debt.py. Shrink-only. Fields: lint code, message, file,\n"
    "# source lines of the primary span, highlighted text, macro call sites.\n"
)


class DebtError(RuntimeError):
    """The comparison could not be made; the lane must fail, not guess."""


@dataclass(frozen=True)
class Occurrence:
    identity: tuple
    location: str
    rendered: str


def _bounded(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= TEXT_LIMIT:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{text[:TEXT_LIMIT]}…#{digest}"


def _path(name: str) -> str:
    for pattern, replacement in _PATH_REWRITES:
        rewritten, count = pattern.subn(replacement, name, count=1)
        if count:
            return rewritten
    return name


def _span_texts(span: dict) -> tuple[str, str]:
    """(the covered source lines, the highlighted part), whitespace-collapsed."""
    lines = span.get("text")
    if not isinstance(lines, list):
        return "", ""
    whole, highlight = [], []
    for line in lines:
        if not isinstance(line, dict) or not isinstance(line.get("text"), str):
            raise DebtError(f"span text entry is malformed: {line!r}")
        text = line["text"]
        whole.append(text)
        start, end = line.get("highlight_start"), line.get("highlight_end")
        if isinstance(start, int) and isinstance(end, int):
            highlight.append(text[start - 1:end - 1])
    return _bounded("\n".join(whole)), _bounded("\n".join(highlight))


def _expansions(span: dict) -> tuple[list[tuple[str, str]], list[tuple]]:
    """The macro call sites the span came through: (identities, positions)."""
    identities, positions = [], []
    expansion = span.get("expansion")
    while isinstance(expansion, dict):
        call = expansion.get("span")
        if not isinstance(call, dict):
            raise DebtError("macro expansion without a call-site span")
        whole, highlight = _span_texts(call)
        name = expansion.get("macro_decl_name") or ""
        identities.append((name, _bounded(f"{whole} | {highlight}")))
        positions.append((_path(call.get("file_name", "")), call.get("line_start"), call.get("column_start"),
                          call.get("line_end"), call.get("column_end")))
        expansion = call.get("expansion")
    return identities, positions


def _is_summary(message: dict) -> bool:
    """rustc's own count of what it emitted: no span, no lint code, exact text."""
    text = message.get("message")
    return (not message.get("spans") and message.get("code") is None and isinstance(text, str)
            and _SUMMARY.fullmatch(text) is not None)


def occurrences(stream: str, package_id: str) -> list[Occurrence]:
    """The package's lint diagnostics in a `cargo --message-format=json` stream,
    deduplicated by exact position."""
    finished = []
    checked = False
    seen: dict[tuple, Occurrence] = {}
    for number, line in enumerate(stream.splitlines(), 1):
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise DebtError(f"clippy output line {number} is not JSON: {error}") from error
        reason = item.get("reason")
        if reason == "build-finished":
            finished.append(item.get("success"))
            continue
        if item.get("package_id") != package_id:
            continue
        if reason == "compiler-artifact":
            checked = True
            continue
        if reason != "compiler-message":
            continue
        message = item.get("message")
        if not isinstance(message, dict):
            raise DebtError(f"clippy output line {number} has no message object")
        if message.get("level") not in ("warning", "error"):
            continue
        if _is_summary(message):
            continue
        code = (message.get("code") or {}).get("code") or ""
        text = message.get("message") or ""
        primary = [s for s in message.get("spans") or [] if isinstance(s, dict) and s.get("is_primary")]
        if primary:
            span = primary[0]
            whole, highlight = _span_texts(span)
            expansion_ids, expansion_positions = _expansions(span)
            file_name = _path(span.get("file_name", ""))
            position = (code, text, file_name, span.get("line_start"), span.get("column_start"),
                        span.get("line_end"), span.get("column_end"), tuple(expansion_positions))
            identity = (code, text, file_name, whole, highlight, tuple(expansion_ids))
            location = f"{file_name}:{span.get('line_start')}"
        else:
            # Identified by what it says. Its secondary spans, if any, still
            # keep two reports at different places from collapsing into one.
            position = (code, text, tuple((_path(s.get("file_name", "")), s.get("line_start"), s.get("column_start"),
                                           s.get("line_end"), s.get("column_end"))
                                          for s in message.get("spans") or [] if isinstance(s, dict)))
            identity = (code, text, "", "", "", ())
            location = NO_SPAN
        seen.setdefault(position, Occurrence(identity, location, message.get("rendered") or text))
    if finished != [True]:
        raise DebtError(f"the clippy stream did not end in one successful build-finished (got {finished}) — "
                        "it is truncated or the build failed, so its diagnostics are not the whole list")
    if not checked:
        raise DebtError(f"the clippy stream has no compiler-artifact for {package_id} — clippy did not "
                        "check the package, so an empty diagnostic list would prove nothing")
    return list(seen.values())


def encode(identity: tuple) -> str:
    code, text, file_name, whole, highlight, expansions = identity
    return json.dumps([code, text, file_name, whole, highlight, [list(e) for e in expansions]], ensure_ascii=False)


def _decode(line: str, number: int) -> tuple:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        raise DebtError(f"baseline line {number} is not JSON: {error}") from error
    shape_ok = (isinstance(value, list) and len(value) == 6 and all(isinstance(v, str) for v in value[:5])
                and isinstance(value[5], list)
                and all(isinstance(e, list) and len(e) == 2 and all(isinstance(x, str) for x in e)
                        for e in value[5]))
    if not shape_ok:
        raise DebtError(f"baseline line {number} is not [code, message, file, source, highlight, [[macro, call]...]]")
    return (value[0], value[1], value[2], value[3], value[4], tuple(tuple(e) for e in value[5]))


def read_baseline(text: str) -> Counter:
    lines, identities = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        identity = _decode(line, number)
        if encode(identity) != line:
            raise DebtError(f"baseline line {number} is not in canonical form — replace the file with the "
                            "regenerated baseline instead of editing it by hand")
        lines.append(line)
        identities.append(identity)
    if lines != sorted(lines):
        raise DebtError("baseline entries are not sorted — replace the file with the regenerated baseline")
    return Counter(identities)


def render_baseline(package: str, current: Counter) -> str:
    lines = sorted(encode(identity) for identity in current.elements())
    return BASELINE_HEADER.format(package=package) + "".join(f"{line}\n" for line in lines)


def ratchet(package: str, baseline: Counter, reviewed: Counter | None) -> tuple[bool, list[str]]:
    """The committed baseline may only lose entries against the base revision's
    reviewed baseline. `reviewed` is None only for a bootstrap: the base
    revision has no baseline file for the package."""
    if reviewed is None:
        return True, [f"::warning::clippy debt '{package}': BOOTSTRAP — the base revision has no baseline for "
                      f"this package, so none of the {sum(baseline.values())} entries this change commits was "
                      "held to a base; review every one"]
    added = baseline - reviewed
    report = [f"clippy debt '{package}': the committed baseline lists {sum(baseline.values())}, the base "
              f"revision's reviewed baseline lists {sum(reviewed.values())}"]
    if added:
        report.append(f"::error::the baseline of '{package}' ADDS {sum(added.values())} entry(ies) the base "
                      "revision's reviewed baseline does not list — it only shrinks; fix the diagnostic "
                      "instead of listing it:")
        for identity in sorted(added, key=encode):
            report.append(f"ADDED x{added[identity]} (committed baseline lists {baseline[identity]}, base "
                          f"revision lists {reviewed[identity]}): {encode(identity)}")
    return not added, report


def compare(package: str, found: list[Occurrence], baseline: Counter) -> tuple[bool, list[str]]:
    current = Counter(o.identity for o in found)
    new = current - baseline
    fixed = baseline - current
    report = [f"clippy debt '{package}': {sum(current.values())} distinct diagnostics, "
              f"baseline lists {sum(baseline.values())}"]
    if not current and not baseline:
        report.append(f"::error::clippy debt in '{package}' is now zero — delete its CLIPPY_DEBT entry and its "
                      "baseline so -D warnings covers it")
        return False, report
    if new:
        report.append(f"::error::clippy debt in '{package}' has {sum(new.values())} NEW diagnostic(s) the reviewed "
                      "baseline does not list — fix them:")
        for identity in sorted(new, key=encode):
            places = [o for o in found if o.identity == identity]
            report.append(f"NEW x{new[identity]} (occurs {current[identity]}, baseline lists {baseline[identity]}) "
                          f"at {', '.join(o.location for o in places)}: {encode(identity)}")
            report.extend(o.rendered.rstrip("\n") for o in places)
    if fixed:
        report.append(f"::error::clippy debt in '{package}' lost {sum(fixed.values())} diagnostic(s) — drop them "
                      "from its baseline (it only shrinks):")
        for identity in sorted(fixed, key=encode):
            report.append(f"FIXED x{fixed[identity]}: {encode(identity)}")
    return not new and not fixed, report


def _read(path: Path, what: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise DebtError(f"cannot read {what} {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--package", required=True)
    parser.add_argument("--baseline", type=Path, required=True,
                        help="the baseline committed in the checkout under test")
    reviewed = parser.add_mutually_exclusive_group(required=True)
    reviewed.add_argument("--reviewed-baseline", type=Path,
                          help="the same baseline file as committed at the base revision")
    reviewed.add_argument("--bootstrap", action="store_true",
                          help="the base revision has no baseline file for the package: this change introduces it")
    parser.add_argument("--package-id", help="`cargo pkgid -p <package>`; required with --messages")
    parser.add_argument("--messages", type=Path,
                        help="stdout of `cargo clippy -p <package> --message-format=json`; without it only "
                             "the ratchet runs")
    parser.add_argument("--regenerated", type=Path, help="write the baseline that would match this run here")
    args = parser.parse_args(argv)
    if args.messages is None and (args.package_id or args.regenerated):
        parser.error("--package-id and --regenerated need --messages")
    if args.messages is not None and not args.package_id:
        parser.error("--messages needs --package-id")
    try:
        found = None
        if args.messages is not None:
            found = occurrences(_read(args.messages, "the clippy output"), args.package_id)
            if args.regenerated:
                args.regenerated.write_text(render_baseline(args.package, Counter(o.identity for o in found)),
                                            encoding="utf-8")
        baseline = read_baseline(_read(args.baseline, "the committed baseline"))
        base = None if args.bootstrap else read_baseline(
            _read(args.reviewed_baseline, "the base revision's reviewed baseline"))
        ok, report = ratchet(args.package, baseline, base)
        if found is None:
            report.append(f"clippy debt '{args.package}': not linted by this run; only the ratchet ran")
        else:
            matched, compared = compare(args.package, found, baseline)
            ok = ok and matched
            report.extend(compared)
    except DebtError as error:
        print(f"::error title=rust-affected-tests clippy debt::{args.package}: {error}")
        return 1
    print("\n".join(report))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
