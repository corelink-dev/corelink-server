#!/usr/bin/env python3
"""B-315 executable population, wiring and landing-behaviour guard.

Four layers, each a refusal on its own:

1. wiring — the merge gate plus its helper still carry every token of the
   PR-API landing design and none of the retired designs (the direct dual-ref
   push that branch protection declined, the `gh pr merge` CLI); and the gate
   wrapper itself has exactly one helper call site, which forwards
   ``"$DRY_RUN"``, and names no merge call of its own (REST ``pulls/…/merge``,
   ``gh pr merge``, or a GraphQL ``mergePullRequest(`` / auto-merge mutation).
   Tokens are a tripwire for an accidental revert, not a proof: a token can sit
   in a comment, and a merge spelled some other way (a query read from a file,
   say) is not detected. Layer 4 is the proof for the helper (its fake `gh`
   also refuses every call it does not model, so a helper that fetched bytes
   through the API would fail there); nothing here EXECUTES the wrapper.
2. the allocator's fixture self-test;
3. the allocator on the real BACKLOG.md population;
4. behaviour — scripts/b315_merge_harness.py runs the REAL helper against a
   fake GitHub in throwaway repositories (land, dry run, every race, a 409, a
   405, a merge on an unvalidated main, a wrong tree, a lost response, a stale
   lease, a busy lock, a refs/replace-substituted BACKLOG.md blob, a graft that
   hides a BEHIND head, a PR retargeted at the merge boundary, a merge GitHub
   lands on another base or that main does not contain, a refused merge call
   after which another actor merges a head with the same tree, and the lock
   holder dying before or during the merge call). At every merge-endpoint call
   it checks that the local allocation lock and the remote lease are still
   held, and every scenario allows no mutating gh call but its pinned merge
   PUT (a dry run: none at all). It proves the helper against the harness's
   model of GitHub; that GitHub enforces the model is argued, not proven, here.

Trust: the BASE-owned candidate gate in scripts/backlog_verify.py, when it runs
(its lane, backlog-verify.yml, was disabled_manually on 2026-10-01), refuses a
PR that changes this file or the harness: its static closure follows the
``spec_from_file_location(..., HARNESS)`` below. Freezing those two files is
not enough on its own, because what they DO depends on how Python resolves
imports in the checkout they run in, and a candidate can ADD files there that
no closure lists. So B-315's declared verify command starts the interpreter
isolated (``python3 -I -S -B``: no PYTHONPATH, no site hooks, no script
directory on sys.path), and this verifier (a) re-runs itself that way when a
caller did not, before importing anything a file could shadow, (b) loads the
harness by path, compiled from its source bytes (no package import, no
bytecode cache), and checks that the self_test it calls is the function those
bytes define, and (c) refuses outright when the checkout carries a file that
would steer import resolution (scripts/__init__.*, sitecustomize/usercustomize,
*.pth at the root or in scripts/). The helper, the gate wrapper and the
allocator are run by path and are NOT frozen: a PR may change them, and what
judges the change is this verifier and its harness when they run on the
changed tree.
"""

import sys  # built in: no file in any checkout can stand in for it


def _isolate() -> None:
    """Re-run this verifier where no checkout file can steer its imports.

    Run as plain ``python3 scripts/verify_b315_dense_id_allocation.py``, Python
    puts scripts/ first on sys.path, so a candidate file such as
    scripts/tempfile.py would replace a standard-library module this verifier
    imports before any check here could run (measured 2026-10-02: a shadow
    tempfile.py ran from the script's directory). So the first thing this
    verifier does, using only built-in modules, is re-exec itself with -I (no
    PYTHON* environment, no user site and, since Python 3.11, no script
    directory on sys.path), -S (no site hooks, so no sitecustomize,
    usercustomize or .pth processing) and -B (no bytecode written).

    This is a backstop, not the defence: a re-exec cannot undo what already ran
    while the first interpreter started. With PYTHONPATH pointing into the
    checkout, a sitecustomize.py there runs during startup and can print PASS
    and exit before this function is reached (review round 5). That is why
    B-315's declared verify command itself starts with ``python3 -I -S -B``.
    """
    flags = sys.flags
    if flags.isolated and flags.no_site and flags.dont_write_bytecode:
        if not getattr(flags, "safe_path", False):
            print(
                "B-315 instrument broken: before Python 3.11, isolated mode still puts the "
                "script's directory on sys.path",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return
    import posix  # built in, like sys

    script = __file__ if __file__.startswith("/") else posix.getcwd() + "/" + __file__
    if not sys.executable:
        print("B-315 instrument broken: no interpreter path to re-run isolated", file=sys.stderr)
        raise SystemExit(2)
    posix.execv(sys.executable, [sys.executable, "-I", "-S", "-B", script, *sys.argv[1:]])


if __name__ == "__main__":
    _isolate()

# Imported only after the isolated re-exec above.
import importlib.machinery  # noqa: E402
import importlib.util  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ALLOCATOR = ROOT / "scripts/backlog_id_alloc.py"
GATE = ROOT / "scripts/pre-merge-gate-check.sh"
ATOMIC = ROOT / "scripts/b315_atomic_merge.sh"
HARNESS = ROOT / "scripts/b315_merge_harness.py"
HARNESS_MODULE = "_b315_trusted_harness"


REQUIRED = (
    # one authority, crash-safe lock across allocation AND merge
    "start_backlog_allocation_lock",
    "backlog_lock_healthy",
    "--common-dir",
    # exact base/main/head capture and same-repository ownership
    "CAPTURED_HEAD",
    "CAPTURED_BASE",
    "CAPTURED_MAIN",
    "CAPTURED_BASE_NAME",
    "CAPTURED_HEAD_REF",
    "headRepositoryOwner",
    "isCrossRepository",
    "baseRefName",
    '[ "$CAPTURED_BASE" = "$CAPTURED_MAIN" ]',
    'git merge-base --is-ancestor "$CAPTURED_MAIN" "$CAPTURED_HEAD"',
    # revalidation after allocation and at the merge boundary
    "main_sha_before",
    "main_sha_after",
    "main_sha_final",
    "moved during allocation",
    "main moved at merge boundary",
    "candidate force-pushed at merge boundary",
    # allocator on exact object bytes, with local object substitution off:
    # refs/replace disabled for every git the helper runs, a graft file refused
    "backlog_id_alloc.py",
    "--base",
    'git cat-file blob "$1:BACKLOG.md"',
    "export GIT_NO_REPLACE_OBJECTS=1",
    "git rev-parse --path-format=absolute --git-path info/grafts",
    "rewrites commit parents",
    # cross-machine lease, owner-safe release
    "REMOTE_LEASE_REF",
    "REMOTE_LEASE_CONFIRMED",
    "release_remote_backlog_lease",
    '--force-with-lease="$REMOTE_LEASE_REF:$REMOTE_LEASE_OID"',
    # the landing: one head-pinned squash through the PR merge API
    "MERGE_METHOD=squash",
    'gh api -X PUT "repos/{owner}/{repo}/pulls/$PR/merge" -f sha="$CAPTURED_HEAD" -f merge_method="$MERGE_METHOD"',
    "merge endpoint NOT called",
    # post-merge proof
    "no false merged claim",
    "head_tree",
    "actual_tree",
    '[ "$parents" = "$merge_oid $CAPTURED_MAIN" ]',
    "LANDED_UNPROVEN",
    # the merge call pins only the head: the base is re-read as the LAST call
    # before it, and a merge that lands anywhere but main is named as such
    '[ "$b_base_name" = main ] && [ "$b_base" = "$CAPTURED_MAIN" ]',
    "PR base retargeted at merge boundary",
    "boundary_pr_check   # the LAST read before the PUT",
    "MERGED_INTO_UNEXPECTED_BASE=4",
    "merged_into_unexpected_base",
    '[ "$post_base" = main ] || wrong_base',
    'git merge-base --is-ancestor "$merge_oid" "$main_oid"',
    # a refused or lost merge call is never success, and the merged head must be
    # the captured one; the lock is re-checked right before and right after the PUT
    "MERGED_BY_OTHER_ACTOR=5",
    "merged_by_other_actor",
    '[ "$post_head" = "$CAPTURED_HEAD" ] || other_actor',
    '[ "$api_ok" -eq 1 ] || unproven "merge_response_not_success',
    'backlog_lock_healthy || refuse "local allocation lock lost before the merge call',
    "lock_held_after_put=1; backlog_lock_healthy || lock_held_after_put=0",
    'case "$stat" in [RSIDU]*) ;; *) return 1 ;; esac',
    '[ -n "$LOCK_IDENTITY" ] && [ "$now" = "$LOCK_IDENTITY" ]',
    'kill -CONT "$LOCK_PID"',
)

# Retired designs. The first three were the pre-B-315 squash CLI; the rest are
# the direct dual-ref push that branch protection declines on main.
OBSOLETE = (
    "--match-head-commit",
    "gh pr merge",
    "--squash",
    "--atomic",
    'commit-tree "$head_tree"',
    '--force-with-lease="refs/heads/main',
)


def wiring_problems(text: str) -> list[str]:
    """Return one line per missing/obsolete token in ``text`` (gate + helper)."""
    if not text.strip():
        return ["gate + helper text is EMPTY: nothing to check"]
    problems = [f"missing: {token}" for token in REQUIRED if token not in text]
    problems += [f"obsolete: {token}" for token in OBSOLETE if token in text]
    if re.search(r"gh api -X DELETE[^\n]*corelink-backlog-id-merge-lock", text):
        problems.append("obsolete: unconditional lease DELETE")
    # Any push whose refspec names main is the retired design, however spelled
    # on one line; branch protection would decline it anyway.
    for line in text.splitlines():
        if re.search(r"\bgit\b[^\n]*\bpush\b", line) and re.search(r"(?:^|[:\s\"'])(?:refs/heads/)?main\b", line):
            problems.append(f"direct push to main: {line.strip()[:120]}")
    return problems


HELPER_CALL = "bash scripts/b315_atomic_merge.sh"
HELPER_CALL_ARGS = 'bash scripts/b315_atomic_merge.sh "$PR" "$CAPTURED_HEAD" "$DRY_RUN" '
# A merge issued by the wrapper itself would bypass the helper's lock, its
# allocator check and its dry-run stop. Raw lines, comments included: a hit in
# a comment is a false alarm a human clears in one edit, never a miss.
WRAPPER_MERGE_CALL = re.compile(
    r"pulls/[^\s\"']*/merge\b|\bgh\s+pr\s+merge\b|\bmergePullRequest\s*\(|\benablePullRequestAutoMerge\b"
)


def gate_problems(gate: str) -> list[str]:
    """Return one line per way the wrapper could merge without the helper."""
    if not gate.strip():
        return ["gate wrapper text is EMPTY: nothing to check"]
    problems: list[str] = []
    call_sites = [line.strip() for line in gate.splitlines() if HELPER_CALL in line and not line.lstrip().startswith("#")]
    if len(call_sites) != 1:
        problems.append(f"gate wrapper has {len(call_sites)} helper call sites, expected exactly 1")
    elif HELPER_CALL_ARGS not in call_sites[0]:
        problems.append(f"helper call site does not forward \"$DRY_RUN\": {call_sites[0][:160]}")
    for number, line in enumerate(gate.splitlines(), start=1):
        if WRAPPER_MERGE_CALL.search(line):
            problems.append(f"gate wrapper names its own merge call at line {number}: {line.strip()[:120]}")
    return problems


# ── The import surface and the harness load (layer 4's trust) ────────────────
# Files that change how Python resolves imports once they exist: an initializer
# for scripts/ (it turns the namespace directory into a regular package whose
# code runs on any `scripts.` import), site hooks, and path configuration
# files. Checked where this repository's Python entry points put directories on
# sys.path: the root and scripts/. BASE has none of them. The isolated re-exec
# and the by-path loader already make them inert for this verifier; they are
# refused anyway, so an attempt is named instead of silently ignored.
SITE_HOOKS = ("sitecustomize", "usercustomize")


def import_surface_problems(root: Path) -> list[str]:
    """One line per file under ``root`` that would steer import resolution."""
    suffixes = tuple(importlib.machinery.all_suffixes())
    watched = ((root / "scripts", ("__init__", *SITE_HOOKS)), (root, SITE_HOOKS))
    problems = []
    for directory, stems in watched:
        for entry in sorted(directory.iterdir()):
            name = entry.name
            module_file = any(
                name == stem or (name.startswith(stem + ".") and name.endswith(suffixes)) for stem in stems
            )
            if module_file or name.endswith(".pth"):
                problems.append(
                    f"{entry.relative_to(root).as_posix()} would steer Python's import resolution; "
                    "BASE has no such file"
                )
    return problems


class HarnessTrustError(RuntimeError):
    """The harness could not be loaded as exactly its tree file's source."""


class _SourceOnlyLoader:
    """Loads a module by compiling its source file's bytes, and nothing else.

    The default loader for a .py file runs ``__pycache__/<name>.<tag>.pyc``
    instead whenever that file is an unchecked-hash pyc, without comparing it
    to the source, and then reports the .py as its co_filename (measured
    2026-10-02, Python 3.14). A candidate could commit such a file next to the
    frozen harness. Compiling the bytes here leaves no cache to consult.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.code = None

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        self.code = compile(self.path.read_bytes(), str(self.path), "exec", dont_inherit=True)
        exec(self.code, module.__dict__)


def harness_identity_problems(module: types.ModuleType, code: types.CodeType) -> list[str]:
    """The self_test this verifier calls must be the function the harness
    source defines: the very code object compiled from its bytes, bound to that
    module's globals."""
    problems = []
    if getattr(module, "__file__", None) != str(HARNESS):
        problems.append(f"harness module file is {getattr(module, '__file__', None)!r}, not {HARNESS}")
    defined = [const for const in code.co_consts if isinstance(const, types.CodeType) and const.co_name == "self_test"]
    self_test = getattr(module, "self_test", None)
    if len(defined) != 1:
        problems.append(f"harness source defines self_test {len(defined)} times at module level, expected 1")
    elif (
        getattr(self_test, "__code__", None) is not defined[0]
        or getattr(self_test, "__globals__", None) is not module.__dict__
    ):
        problems.append("harness self_test is not the function its source defines")
    scenarios = getattr(module, "SCENARIOS", None)
    if not isinstance(scenarios, tuple) or not scenarios:
        problems.append("harness SCENARIOS is not a non-empty tuple")
    return problems


def load_trusted_harness() -> types.ModuleType:
    """Load scripts/b315_merge_harness.py by path, from its source bytes.

    Not ``from scripts import b315_merge_harness``: that runs scripts/__init__.py
    first whenever one exists, and a candidate can add one that imports the real
    harness and replaces its self_test with a stub while ``__file__`` stays right
    (reproduced in review on 2026-10-02: exit 0, every scenario reported PASS).
    """
    loader = _SourceOnlyLoader(HARNESS)
    spec = importlib.util.spec_from_file_location(HARNESS_MODULE, HARNESS, loader=loader)
    if spec is None:
        raise HarnessTrustError(f"no module spec for {HARNESS}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses look their defining module up in sys.modules while the body runs.
    sys.modules[HARNESS_MODULE] = module
    loader.exec_module(module)
    problems = harness_identity_problems(module, loader.code)
    if problems:
        raise HarnessTrustError("; ".join(problems))
    return module


def main() -> int:
    surface = import_surface_problems(ROOT)
    if surface:
        print("B-315 instrument refused: the checkout changes Python's import surface:",
              *surface, sep="\n  ", file=sys.stderr)
        return 2
    missing_files = [str(p.relative_to(ROOT)) for p in (ALLOCATOR, GATE, ATOMIC, HARNESS) if not p.is_file()]
    if missing_files:
        print(f"B-315 instrument broken: missing {missing_files}", file=sys.stderr)
        return 2
    gate = GATE.read_text(encoding="utf-8")
    text = gate + "\n" + ATOMIC.read_text(encoding="utf-8")
    problems = wiring_problems(text) + gate_problems(gate)
    if problems:
        print("B-315 merge wiring:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    result = subprocess.run(
        [sys.executable, str(ALLOCATOR), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1
    # The self-test only sees fixtures. From 2026-09-22 to 2026-10-01 the real
    # ledger carried an id the allocator did not know (B-1630), every --merge was
    # refused, and this verifier stayed green. Run the allocator on the real
    # population too: if it cannot allocate on BACKLOG.md, no merge can.
    backlog = str(ROOT / "BACKLOG.md")
    result = subprocess.run(
        [sys.executable, str(ALLOCATOR), "--main", backlog, "--candidate", backlog, "--base", backlog],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or "added=none" not in result.stdout:
        print("B-315 allocator refuses the real BACKLOG.md population:", file=sys.stderr)
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1
    try:
        harness = load_trusted_harness()
    except Exception as error:  # any way of not getting the tree's own harness is a refusal
        print(f"B-315 instrument broken: harness not loaded as its tree source: {error}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="b315-verify-") as directory:
        problems = harness.self_test(Path(directory))
    if problems:
        print("B-315 landing behaviour:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    print(
        f"B-315 dense allocation, PR-API landing wiring ({len(REQUIRED)} required / "
        f"{len(OBSOLETE)} retired tokens) and {len(harness.SCENARIOS)} landing scenarios: PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
