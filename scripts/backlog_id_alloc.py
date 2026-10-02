#!/usr/bin/env python3
"""Dense BACKLOG id allocation and merge-time revalidation primitives.

The merge gate uses this module as the small, deliberately boring authority for
the numeric part of BACKLOG.md.  It never edits a candidate branch.  Instead it
computes the contiguous ids that the candidate is allowed to add and rejects
anything that was allocated from a stale or malformed census.

``--hold-lock`` is a process-wide lock held by the merge gate for the complete
snapshot/revalidation/merge interval.  ``fcntl.flock`` releases it when the
owner dies, so a crashed gate cannot leave a permanent lock or require a
destructive stale-lock cleanup.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by the CLI guard
    raise SystemExit(f"BACKLOG allocator requires PyYAML: {exc}") from exc

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backlog_verify  # noqa: E402


class AllocationError(ValueError):
    """The ledger cannot safely be allocated or revalidated."""


ID_RE = re.compile(r"^B-(\d+)$")


# Historical external-issue identities sit outside the allocator sequence.
# backlog_verify owns the table (B-1630 = GitHub issue #1630, bound by immutable
# V0004); importing it keeps one authority. Such an id is never allocated and
# never counted toward the dense primary range or its maximum, but once present
# it may not disappear. Every other gap stays fatal.
HISTORICAL_ALIASES = frozenset(
    int(ID_RE.fullmatch(key).group(1))  # type: ignore[union-attr]
    for key in backlog_verify.HISTORICAL_EXTERNAL_ISSUE_IDS
)


@dataclass(frozen=True)
class Census:
    ids: tuple[int, ...]
    aliases: tuple[int, ...] = ()

    @property
    def maximum(self) -> int:
        return self.ids[-1]


# backlog_verify.parse is lenient by design: its BLOCK_RE only sees a fence
# line that is exactly ```backlog, and a block that never closes simply does
# not match. Whatever it does not match is an item the allocator would never
# count, so B-001..B-003 followed by an unclosed B-004, or by a B-004 whose
# opener carries a trailing space, read as "adds nothing" and passed
# (review round 6). So the structure is checked line by line first, on its
# own terms, and the parser's blocks must be exactly the ones it delimits.
LOOSE_OPENER_RE = re.compile(r"^\s*(?:`{3,}|~{3,})\s*backlog", re.IGNORECASE)


def _structure(text: str, source: str) -> list[int]:
    """Return the opener line of every backlog block, refusing every shape
    the lenient parser would skip or misread: a fence that only looks like
    ```backlog, a block closed by anything but a bare ```, a block that never
    closes, a block with no ``### B-NNN`` heading before it, and a heading
    with no block (or a second heading) before the next one."""
    openers: list[int] = []
    heading: tuple[int, str] | None = None
    open_line: int | None = None
    for number, line in enumerate(text.split("\n"), start=1):
        if open_line is not None:
            # BLOCK_RE ends a block at the first line that starts with ```.
            if line.startswith("```"):
                if line != "```":
                    raise AllocationError(
                        f"{source}:{number}: backlog block opened at line {open_line} ends at {line!r}; "
                        "only a bare ``` may close it"
                    )
                open_line = None
            continue
        match = backlog_verify.HEADING_RE.match(line)
        if match:
            if heading is not None:
                raise AllocationError(f"{source}:{heading[0]}: item heading {heading[1]} has no backlog block")
            heading = (number, match.group(1))
        elif line == "```backlog":
            if heading is None:
                raise AllocationError(f"{source}:{number}: backlog block has no `### B-NNN` heading before it")
            heading = None
            open_line = number
            openers.append(number)
        elif LOOSE_OPENER_RE.match(line):
            raise AllocationError(
                f"{source}:{number}: malformed backlog fence {line!r}; the parser skips it, so its item "
                "would never be counted"
            )
    if open_line is not None:
        raise AllocationError(f"{source}:{open_line}: backlog block is never closed")
    if heading is not None:
        raise AllocationError(f"{source}:{heading[0]}: item heading {heading[1]} has no backlog block")
    headings = len(backlog_verify.HEADING_RE.findall(text))
    if headings != len(openers):
        raise AllocationError(f"{source}: {headings} item headings for {len(openers)} backlog blocks")
    return openers


def _strict_ids(text: str, source: str) -> Census:
    """Parse exactly the fenced backlog population, failing closed."""
    openers = _structure(text, source)
    items = backlog_verify.parse(text)
    if not items:
        raise AllocationError(f"{source}: no parseable backlog blocks")
    if [item.line for item in items] != openers:
        raise AllocationError(
            f"{source}: the parser read {len(items)} backlog blocks where the fences delimit {len(openers)}"
        )

    numbers: list[int] = []
    for item in items:
        if item.verdict == backlog_verify.BROKEN:
            raise AllocationError(f"{source}:{item.line}: unparseable backlog block")
        raw = item.raw.get("id")
        if not isinstance(raw, str):
            raise AllocationError(f"{source}:{item.line}: missing/string id required")
        match = ID_RE.fullmatch(raw)
        if match is None:
            raise AllocationError(f"{source}:{item.line}: malformed id {raw!r}")
        number = int(match.group(1))
        canonical = f"B-{number:03d}"
        if number <= 0:
            raise AllocationError(f"{source}:{item.line}: non-positive id {raw!r}")
        if raw != canonical:
            raise AllocationError(
                f"{source}:{item.line}: non-canonical id {raw!r}; expected {canonical!r}"
            )
        numbers.append(number)

    if len(numbers) != len(set(numbers)):
        duplicates = sorted(number for number in set(numbers) if numbers.count(number) > 1)
        raise AllocationError(
            f"{source}: duplicate ids: {', '.join(f'B-{n:03d}' for n in duplicates)}"
        )
    aliases = sorted(number for number in numbers if number in HISTORICAL_ALIASES)
    ordered = sorted(number for number in numbers if number not in HISTORICAL_ALIASES)
    if not ordered:
        raise AllocationError(f"{source}: no primary backlog ids")
    expected = list(range(1, ordered[-1] + 1))
    if ordered != expected:
        missing = sorted(set(expected) - set(ordered))
        rendered = ", ".join(f"B-{n:03d}" for n in missing[:12])
        suffix = " …" if len(missing) > 12 else ""
        raise AllocationError(f"{source}: dense census has gaps: {rendered}{suffix}")
    return Census(tuple(ordered), tuple(aliases))


def allocation(
    main_text: str,
    candidate_text: str,
    *,
    base_text: str | None = None,
    main_source: str = "main",
    candidate_source: str = "candidate",
    base_source: str = "base",
) -> tuple[int, ...]:
    """Return the ids the candidate is allowed to add over ``main``.

    The candidate must preserve every main item (no deletion/silent
    disappearance).  New ids are exactly the next contiguous range.  A
    candidate with no new ids is valid, which keeps the guard applicable to
    PRs that do not touch BACKLOG.md.
    """
    main = _strict_ids(main_text, main_source)
    candidate = _strict_ids(candidate_text, candidate_source)
    main_set = set(main.ids)
    candidate_set = set(candidate.ids)
    missing = sorted((main_set | set(main.aliases)) - (candidate_set | set(candidate.aliases)))
    if missing:
        shown = ", ".join(f"B-{n:03d}" for n in missing[:12])
        suffix = " …" if len(missing) > 12 else ""
        raise AllocationError(f"candidate silently removed main ids: {shown}{suffix}")
    reference_aliases = set(main.aliases)
    if base_text is not None:
        reference_aliases &= set(_strict_ids(base_text, base_source).aliases)
    minted = sorted(set(candidate.aliases) - reference_aliases)
    if minted:
        shown = ", ".join(f"B-{n:03d}" for n in minted)
        raise AllocationError(f"historical alias cannot be allocated: {shown}")
    # An ID introduced by this PR must be identified against the PR's base,
    # not only against current main.  Otherwise a second PR carrying the same
    # B-NNN after the first one merged would appear to add nothing and pass.
    if base_text is not None:
        base = _strict_ids(base_text, base_source)
        introduced = sorted(candidate_set - set(base.ids))
        collisions = sorted(set(introduced) & main_set)
        if collisions:
            shown = ", ".join(f"B-{n:03d}" for n in collisions[:12])
            raise AllocationError(f"candidate allocation collides with current main: {shown}")
        new = introduced
    else:
        new = sorted(candidate_set - main_set)
    expected = list(range(main.maximum + 1, main.maximum + len(new) + 1))
    if new != expected:
        got = ", ".join(f"B-{n:03d}" for n in new) or "<none>"
        want = ", ".join(f"B-{n:03d}" for n in expected) or "<none>"
        raise AllocationError(f"stale allocation: candidate adds [{got}], expected [{want}]")
    return tuple(new)


def _validated_lock_path(path: Path) -> Path:
    """Resolve and validate the lock's git-common-dir parent."""
    if path.parent.is_symlink():
        raise AllocationError("lock parent must not be a symlink")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir() or parent.is_symlink():
        raise AllocationError(f"lock parent is not a real directory: {parent}")
    resolved = (parent / path.name).resolve(strict=False)
    if resolved.parent != parent or resolved.name != path.name:
        raise AllocationError("lock path escapes its validated git common directory")
    return resolved


def _same_regular_inode(path: Path, fd: int) -> bool:
    """Reject unlink, replacement, and symlink attacks on a held lock path."""
    try:
        path_stat = os.stat(path, follow_symlinks=False)
        fd_stat = os.fstat(fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(path_stat.st_mode)
        and path_stat.st_dev == fd_stat.st_dev
        and path_stat.st_ino == fd_stat.st_ino
    )


def _hold_lock(path: Path, ready: Path, common_dir: Path) -> int:
    """Acquire an exclusive lock under git common-dir and monitor its path."""
    common_dir = common_dir.resolve(strict=True)
    if not common_dir.is_dir() or common_dir.is_symlink():
        raise AllocationError("git common-dir is not a real directory")
    if path.parent.resolve(strict=True) != common_dir:
        raise AllocationError("lock path is outside the validated git common directory")
    path = _validated_lock_path(path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        ready.write_text(f"error {exc}\n", encoding="utf-8")
        return 74
    try:
        if not _same_regular_inode(path, fd):
            ready.write_text("error lock path is not a regular stable file\n", encoding="utf-8")
            return 74
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            ready.write_text("busy\n", encoding="utf-8")
            return 75
        ready.write_text(f"locked pid={os.getpid()}\n", encoding="utf-8")
        stop = False

        def request_stop(_signum: int, _frame: object) -> None:
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        while not stop:
            if not _same_regular_inode(path, fd):
                ready.write_text("lost lock path changed while held\n", encoding="utf-8")
                return 74
            time.sleep(0.2)
        return 0
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _self_test() -> None:
    def item(number: int) -> str:
        return (
            f"### B-{number:03d} — fixture\n\n```backlog\n"
            f"id: B-{number:03d}\nrepo: corelink-server\nowner: tl\n"
            "status: done\nverify: 'true'\nverify-means: fixture\n"
            "last-verified: 2026-09-06\n```\n"
        )

    baseline = "\n".join(item(number) for number in range(1, 4))
    assert allocation(baseline, baseline + item(4), base_text=baseline) == (4,)
    try:
        allocation(baseline + item(4), baseline + item(4), base_text=baseline)
    except AllocationError as exc:
        assert "collides" in str(exc)
    else:
        raise AssertionError("same-snapshot duplicate allocation was accepted")
    try:
        allocation(
            baseline + item(4),
            baseline + item(4) + item(5),
            base_text=baseline + item(4),
        )
    except AllocationError:
        raise AssertionError("a fresh allocation was incorrectly rejected")
    try:
        allocation(baseline, "\n".join(item(number) for number in (1, 2)))
    except AllocationError as exc:
        assert "removed" in str(exc)
    else:
        raise AssertionError("silent disappearance was accepted")
    # Structure the lenient parser skips: each tail reads as "adds nothing" to it.
    unclosed = baseline + item(4).rsplit("```\n", 1)[0]
    for label, mutated in (
        ("unclosed block", unclosed),
        ("opener with a trailing space", baseline + item(4).replace("```backlog\n", "```backlog \n")),
        ("orphan heading", baseline + "### B-004 — fixture\n\nno block\n"),
    ):
        try:
            allocation(baseline, mutated, base_text=baseline)
        except AllocationError:
            pass
        else:
            raise AssertionError(f"skipped backlog structure was accepted: {label}")
    for bad in ("B-000", "B-04", "B-0042", "B-TBD"):
        mutated = baseline.replace("id: B-003", f"id: {bad}", 1)
        try:
            _strict_ids(mutated, "mutation")
        except AllocationError:
            pass
        else:
            raise AssertionError(f"malformed mutation was accepted: {bad}")
    print("B-315 allocator self-test: PASS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--hold-lock", type=Path)
    parser.add_argument("--common-dir", type=Path)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            _self_test()
            return 0
        if args.hold_lock:
            if args.ready is None:
                raise AllocationError("--hold-lock requires --ready")
            if args.common_dir is None:
                raise AllocationError("--hold-lock requires --common-dir")
            return _hold_lock(args.hold_lock, args.ready, args.common_dir)
        if args.main is None or args.candidate is None:
            raise AllocationError("--main and --candidate are required")
        main_text = args.main.read_text(encoding="utf-8")
        candidate_text = args.candidate.read_text(encoding="utf-8")
        base_text = args.base.read_text(encoding="utf-8") if args.base else None
        added = allocation(
            main_text,
            candidate_text,
            base_text=base_text,
            main_source=str(args.main),
            candidate_source=str(args.candidate),
            base_source=str(args.base) if args.base else "base",
        )
        rendered = ", ".join(f"B-{number:03d}" for number in added) or "none"
        print(f"B-315 allocation valid: added={rendered}")
        return 0
    except (AllocationError, OSError, UnicodeError) as exc:
        print(f"B-315 allocation refused: {exc}", file=sys.stderr)
        return 74 if args.hold_lock else 1


if __name__ == "__main__":
    raise SystemExit(main())
