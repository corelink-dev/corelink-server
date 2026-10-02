#!/usr/bin/env python3
"""Hermetic fake-GitHub harness that EXECUTES scripts/b315_atomic_merge.sh.

Each scenario builds a throwaway world and runs the real helper in it:

* ``origin.git`` — a bare repository whose ``pre-receive`` hook declines every
  push to ``refs/heads/main`` ("protected branch hook declined"), which is what
  branch protection on the real main returns for a direct push;
* ``work/`` — the clone the helper runs in (its git common-dir holds the lock);
* a fake ``gh`` first on PATH, served by this file (``fake-gh`` sub-command),
  answering ``gh pr view --json`` and ``gh api -X PUT .../pulls/<n>/merge``.

The fake models exactly the GitHub behaviour the landing argument rests on:
``sha`` mismatch -> HTTP 409; head not containing main (strict status checks)
-> HTTP 405; ``merge_method=merge`` (required linear history) -> HTTP 405; a
successful squash appends one commit whose parent is main and whose tree is
the head's tree. That model is the CLAIM, not GitHub: these scenarios prove the
helper's behaviour against it; that GitHub enforces it is argued from its
documented branch-protection semantics in the helper's header, not proven here.
Fault injections (head/main moving at a named call, a merge landing on another
main, a wrong tree, a lost API response) are applied inside the fake at the
exact call where the race would happen.

The merge DESTINATION is a parameter of the fake, not a constant: ``base_ref``
(main by default) is what ``gh pr view`` reports as ``baseRefName`` and where a
successful PUT lands, as on GitHub, whose merge endpoint pins only the head.
A ``retarget_base`` injection points the PR at a branch cut from the current
main tip (the hardest retarget to see: parent and tree proofs alone would
pass), and ``rewind_base_after_merge`` lands the merge and then puts the base
back, so GitHub reports MERGED for a commit main does not contain.

Two more faults model what can happen around a REFUSED merge call and around
the lock: ``same_tree_head_merged_by_other`` pushes a head H2 carrying H1's
exact tree (so the pinned PUT gets 409) and then lets another actor merge H2,
and ``kill_lock_holder`` SIGKILLs the helper's allocation-lock holder and waits
until the kernel has released its flock.

Every call the helper (or the wrapper) makes to the fake is classified by
``is_mutating``: only ``pr view``/``pr checks``/``pr list`` and GET ``api``
calls are reads; anything else, including an unknown subcommand, mutates. A
scenario allows exactly its pinned merge PUTs and nothing else, so a dry run
must make ZERO mutating calls. ``run_wrapper`` executes the real
scripts/pre-merge-gate-check.sh from the world's clone against the same fake.

Every scenario also asserts the helper never pushed to main and never left the
remote lease behind, and, at every call of the merge endpoint, that the local
allocation lock (probed with the allocator's own ``fcntl.flock``) and the
remote lease ref were still held: the lock must span allocation AND merge.

Two scenarios plant local object substitution in the helper's clone only, so
the clone and origin (which plays GitHub) disagree about what an oid holds:
``refs/replace`` swapping the candidate's invalid BACKLOG.md blob for a valid
one, and a graft file making a BEHIND head look as if it contains main. Each
first proves that plain git in the clone really reads the substitute, so a
helper that is not fooled is distinguishable from a planting that failed.
No network, no credentials: ``gh`` cannot reach GitHub.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "b315_atomic_merge.sh"
GATE = ROOT / "scripts" / "pre-merge-gate-check.sh"
ALLOCATOR = ROOT / "scripts" / "backlog_id_alloc.py"
PR = 7
OWNER, REPO, HEAD_REF = "acme", "corelink-server", "feature"
LEASE_REF = "refs/heads/corelink-backlog-id-merge-lock"
RETARGET_REF = "release"
MERGE_PATH = f"repos/{{owner}}/{{repo}}/pulls/{PR}/merge"

PROTECTED_MAIN_HOOK = """#!/bin/sh
# Models branch protection on main: every direct push to main is declined.
while read -r old new ref; do
  echo "$ref $old $new" >> pushes.log
  if [ "$ref" = refs/heads/main ]; then
    echo "protected branch hook declined" >&2
    exit 1
  fi
done
exit 0
"""


class HarnessError(RuntimeError):
    """The harness itself could not build or read its world."""


def backlog(*ids: int) -> str:
    return "\n".join(
        f"### B-{number:03d} — fixture\n\n```backlog\n"
        f"id: B-{number:03d}\nrepo: corelink-server\nowner: tl\n"
        "status: done\nverify: 'true'\nverify-means: fixture\n"
        "last-verified: 2026-09-06\n```\n"
        for number in ids
    )


def _git(env: dict[str, str], *args: str, cwd: Path | None = None, stdin: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, env=env, input=stdin, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise HarnessError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _isolated_env(home: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GIT_", "GH_")) and key not in {"GITHUB_TOKEN", "BASH_ENV", "ENV"}
    }
    config = home / "gitconfig"
    config.write_text(
        "[user]\n\tname = B315 Harness\n\temail = harness@example.invalid\n"
        "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n"
        "[init]\n\tdefaultBranch = main\n[advice]\n\tdetachedHead = false\n",
        encoding="utf-8",
    )
    env.update(
        GIT_CONFIG_GLOBAL=str(config),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        GH_CONFIG_DIR=str(home / "gh"),
        HOME=str(home),
    )
    return env


@dataclass
class World:
    root: Path
    origin: Path
    work: Path
    bin: Path
    state: Path
    env: dict[str, str]
    main0: str
    head: str


def malformed_backlog(kind: str) -> str:
    """A candidate BACKLOG.md that backlog_verify.parse reads as just
    B-001..B-003 (so the allocator used to report "adds nothing" for it):
    B-004 with an unclosed block, with an opener carrying a trailing space, or
    as a heading with no block at all."""
    head, tail = backlog(1, 2, 3) + "\n", backlog(4)
    if kind == "unclosed_block":
        return head + tail.rsplit("```\n", 1)[0]
    if kind == "opener_trailing_space":
        return head + tail.replace("```backlog\n", "```backlog \n", 1)
    if kind == "orphan_heading":
        return head + "### B-004 — fixture\n\nprose only, no backlog block\n"
    raise HarnessError(f"unknown malformed backlog {kind!r}")


def build_world(
    root: Path,
    *,
    main_ids: tuple[int, ...] = (1, 2, 3),
    candidate_ids: tuple[int, ...] = (1, 2, 3, 4),
    variant: str = "fresh",
    candidate_text: str | None = None,
) -> World:
    """Create origin/work/fake-gh. ``variant`` shapes the PR relative to main:

    fresh      — head contains main, PR base snapshot == main (mergeable);
    behind     — main advanced, base snapshot == new main, head lacks it;
    stale-base — main advanced, base snapshot still the old main.
    """
    root.mkdir(parents=True, exist_ok=True)
    home = root / "home"
    home.mkdir()
    (root / "tmp").mkdir()
    env = _isolated_env(home)
    origin = root / "origin.git"
    _git(env, "init", "--quiet", "--bare", str(origin))
    _git(env, "--git-dir", str(origin), "symbolic-ref", "HEAD", "refs/heads/main")
    _git(env, "--git-dir", str(origin), "config", "uploadpack.allowAnySHA1InWant", "true")
    seed = root / "seed"
    seed.mkdir()
    _git(env, "init", "--quiet", "-b", "main", cwd=seed)
    _git(env, "remote", "add", "origin", str(origin), cwd=seed)
    (seed / "BACKLOG.md").write_text(backlog(*main_ids), encoding="utf-8")
    _git(env, "add", "BACKLOG.md", cwd=seed)
    _git(env, "commit", "--quiet", "-m", "base", cwd=seed)
    _git(env, "push", "--quiet", "origin", "HEAD:refs/heads/main", cwd=seed)
    main0 = _git(env, "rev-parse", "HEAD", cwd=seed)
    _git(env, "checkout", "--quiet", "-b", HEAD_REF, cwd=seed)
    (seed / "NOTE.md").write_text("an unrelated first commit on the PR\n", encoding="utf-8")
    _git(env, "add", "NOTE.md", cwd=seed)
    _git(env, "commit", "--quiet", "-m", "note", cwd=seed)
    head_parent = _git(env, "rev-parse", "HEAD", cwd=seed)
    (seed / "BACKLOG.md").write_text(
        backlog(*candidate_ids) if candidate_text is None else candidate_text, encoding="utf-8"
    )
    _git(env, "add", "BACKLOG.md", cwd=seed)
    _git(env, "commit", "--quiet", "-m", "candidate", cwd=seed)
    head = _git(env, "rev-parse", "HEAD", cwd=seed)
    _git(env, "push", "--quiet", "origin", f"HEAD:refs/heads/{HEAD_REF}", cwd=seed)
    base_sha = main0
    if variant in {"behind", "stale-base"}:
        advanced = _add_commit(env, str(origin), "refs/heads/main", "unrelated-main.txt")
        main0 = advanced
        if variant == "behind":
            base_sha = advanced
    elif variant != "fresh":
        raise HarnessError(f"unknown world variant {variant!r}")
    hook = origin / "hooks" / "pre-receive"
    hook.write_text(PROTECTED_MAIN_HOOK, encoding="utf-8")
    hook.chmod(0o755)
    work = root / "work"
    _git(env, "clone", "--quiet", str(origin), str(work))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    # -I -S -B: the fake GitHub must not import a module that a checkout file
    # shadows (since Python 3.11, -I also keeps the script's directory off
    # sys.path), and must not run site hooks or write bytecode.
    gh.write_text(
        f"#!/bin/sh\nexec {json.dumps(sys.executable)} -I -S -B {json.dumps(str(Path(__file__).resolve()))} "
        "fake-gh \"$@\"\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    state = root / "state.json"
    state.write_text(
        json.dumps(
            {
                "pr": PR,
                "head_ref": HEAD_REF,
                "head_parent": head_parent,
                "base_sha": base_sha,
                "base_ref": "main",
                "state": "OPEN",
                "merge_commit": None,
                "owner": OWNER,
                "repo": REPO,
                "cross": False,
                "inject": {},
                "views": 0,
                "calls": [],
            }
        ),
        encoding="utf-8",
    )
    return World(root, origin, work, bin_dir, state, env, main0, head)


def copy_world(template: World, root: Path) -> World:
    """Clone a pristine template world (cheaper than rebuilding it per scenario)."""
    shutil.copytree(template.root, root, symlinks=True)
    env = _isolated_env(root / "home")
    work = root / "work"
    _git(env, "remote", "set-url", "origin", str(root / "origin.git"), cwd=work)
    return World(root, root / "origin.git", work, root / "bin", root / "state.json", env,
                 template.main0, template.head)


# ── the fake gh ──────────────────────────────────────────────────────────────


def _rev(origin: str, ref: str) -> str:
    return _git(dict(os.environ), "--git-dir", origin, "rev-parse", "--verify", ref)


def _add_commit(env: dict[str, str], origin: str, ref: str, name: str) -> str:
    parent = _git(env, "--git-dir", origin, "rev-parse", "--verify", ref)
    blob = _git(env, "--git-dir", origin, "hash-object", "-w", "--stdin", stdin=f"{name}\n")
    listing = _git(env, "--git-dir", origin, "ls-tree", parent)
    tree = _git(env, "--git-dir", origin, "mktree", stdin=f"{listing}\n100644 blob {blob}\t{name}\n")
    new = _git(env, "--git-dir", origin, "commit-tree", tree, "-p", parent, "-m", name)
    _git(env, "--git-dir", origin, "update-ref", ref, new, parent)
    return new


def _inject(state: dict, origin: str, point: str) -> None:
    env = dict(os.environ)
    for action in state["inject"].get(point, []):
        if action == "advance_main":
            _add_commit(env, origin, "refs/heads/main", f"main-{point}.txt")
        elif action == "move_head":
            _add_commit(env, origin, f"refs/heads/{state['head_ref']}", f"head-{point}.txt")
        elif action == "ff_main_to_head_parent":
            # A direct push of a commit already in the head's history: main
            # moves but stays an ancestor of the head, so "up to date" holds.
            main = _rev(origin, "refs/heads/main")
            _git(env, "--git-dir", origin, "update-ref", "refs/heads/main", state["head_parent"], main)
        elif action == "retarget_base":
            # The PR now targets a branch cut from the current main tip. GitHub
            # updates baseRefName and baseRefOid on a retarget; so does the fake.
            tip = _rev(origin, "refs/heads/main")
            _git(env, "--git-dir", origin, "update-ref", f"refs/heads/{RETARGET_REF}", tip)
            state["base_ref"] = RETARGET_REF
            state["base_sha"] = tip
        elif action == "same_tree_head_merged_by_other":
            # H2: a new commit with H1's exact tree. The pinned PUT now gets 409,
            # and another actor merges H2 right after it (see _fake_dispatch).
            head_ref = f"refs/heads/{state['head_ref']}"
            head = _rev(origin, head_ref)
            tree = _rev(origin, f"{head}^{{tree}}")
            other = _git(env, "--git-dir", origin, "commit-tree", tree, "-p", head, "-m", "same tree, other head")
            _git(env, "--git-dir", origin, "update-ref", head_ref, other, head)
            state["other_actor_merges_after_put"] = True
        elif action == "kill_lock_holder":
            _kill_lock_holder()
        elif action in {"land_wrong_tree", "drop_merge_response", "rewind_base_after_merge"}:
            state[action] = True
        else:
            raise HarnessError(f"unknown injection {action!r}")


def _kill_lock_holder() -> None:
    """SIGKILL the helper's allocation-lock holder (its pid is in the ready
    file next to the lock) and wait until the kernel has released the flock."""
    lock = Path(os.environ["B315_FAKE_LOCK"])
    pids = []
    for ready in lock.parent.glob("backlogalloc.ready.*"):
        match = re.match(r"locked pid=(\d+)", ready.read_text(encoding="utf-8"))
        if match:
            pids.append(int(match.group(1)))
    if len(pids) != 1:
        raise HarnessError(f"expected exactly one lock holder, found {pids}")
    os.kill(pids[0], signal.SIGKILL)
    deadline = time.monotonic() + 10
    while lock_held(lock):
        if time.monotonic() > deadline:
            raise HarnessError("the allocation lock is still held after its holder was killed")
        time.sleep(0.02)


def lock_held(path: Path) -> bool:
    """True when another process holds the allocator's flock on ``path``.

    Same primitive as scripts/backlog_id_alloc.py (``fcntl.flock``), probed
    non-blocking and released at once. A missing file is not held: the helper
    creates it when it takes the lock.
    """
    import fcntl

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _record_guards_at_merge_call(state: dict, origin: str) -> None:
    """Note, at the instant the merge endpoint is called, whether the helper
    still holds the local allocation lock and the remote lease. The B-315
    guarantee is that both span allocation AND merge, not just allocation."""
    lock = os.environ.get("B315_FAKE_LOCK", "")
    lease = subprocess.run(
        ["git", "--git-dir", origin, "rev-parse", "--verify", "--quiet", LEASE_REF],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    state.setdefault("guards_at_put", []).append(
        {"lock": bool(lock) and lock_held(Path(lock)), "lease": bool(lease)}
    )


def _http_error(code: int, message: str) -> int:
    print(json.dumps({"message": message, "status": str(code)}))
    print(f"gh: {message} (HTTP {code})", file=sys.stderr)
    return 1


def _fake_merge(state: dict, origin: str, params: dict[str, str]) -> int:
    env = dict(os.environ)
    head = _rev(origin, f"refs/heads/{state['head_ref']}")
    base_ref = f"refs/heads/{state['base_ref']}"
    base = _rev(origin, base_ref)
    if state["state"] != "OPEN":
        return _http_error(405, "Pull Request is not mergeable")
    if "sha" in params and params["sha"] != head:
        return _http_error(409, "Head branch was modified. Review and try the merge again.")
    method = params.get("merge_method", "merge")
    if method == "merge":
        return _http_error(405, "Merge commits are not allowed on this branch.")
    if method != "squash":
        return _http_error(422, f"merge_method {method!r} is not modelled by this fake")
    ancestor = subprocess.run(
        ["git", "--git-dir", origin, "merge-base", "--is-ancestor", base, head],
        env=env, capture_output=True, check=False,
    )
    if ancestor.returncode:
        return _http_error(405, "Head branch is out of date with the base branch.")
    new = _land(state, origin, head)
    if state.get("drop_merge_response"):
        return _http_error(502, "Bad Gateway")
    print(json.dumps({"sha": new, "merged": True, "message": "Pull Request successfully merged"}))
    return 0


def _land(state: dict, origin: str, head: str) -> str:
    """Squash ``head`` onto the PR's current base, as a successful merge does."""
    env = dict(os.environ)
    base_ref = f"refs/heads/{state['base_ref']}"
    base = _rev(origin, base_ref)
    tree_of = base if state.get("land_wrong_tree") else head
    tree = _rev(origin, f"{tree_of}^{{tree}}")
    new = _git(env, "--git-dir", origin, "commit-tree", tree, "-p", base, "-m", f"squash (#{state['pr']})")
    _git(env, "--git-dir", origin, "update-ref", base_ref, new, base)
    if state.get("rewind_base_after_merge"):
        _git(env, "--git-dir", origin, "update-ref", base_ref, base, new)
    state["state"] = "MERGED"
    state["merge_commit"] = new
    return new


READ_SUBCOMMANDS = {("pr", "view"), ("pr", "checks"), ("pr", "list")}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def is_mutating(argv: list[str]) -> bool:
    """True unless ``argv`` is a gh call that only reads. Fail-closed: any
    subcommand not known to read, any ``api`` call that is not a GET, and any
    ``api`` argument form the parser below does not model count as a mutation.
    ``gh api`` sends POST when it is given a body (fields or ``--input``) and
    no explicit method, so that is a mutation too."""
    if tuple(argv[:2]) in READ_SUBCOMMANDS:
        return False
    if argv[:1] != ["api"]:
        return True
    call = _parse_api(argv)
    return bool(call.unknown) or call.effective_method != "GET"


PR_CHECKS = [
    {"name": "dco", "bucket": "pass", "link": ""},
    {"name": "gitleaks detect", "bucket": "pass", "link": ""},
    {"name": "CHANGELOG.md updated when feat/fix present", "bucket": "pass", "link": ""},
]


def _flag_value(argv: list[str], names: tuple[str, ...]) -> str | None:
    for index, arg in enumerate(argv[:-1]):
        if arg in names:
            return argv[index + 1]
    return None


def _jq(expression: str, data: dict) -> str | None:
    """The two jq shapes the gate wrapper uses: ``.a.b`` and a string with
    ``\\(.a.b)`` interpolations. Anything else is unsupported (None)."""

    def lookup(path: str):
        value = data
        for key in path.strip(".").split("."):
            if key:
                value = value.get(key) if isinstance(value, dict) else None
        return value

    def render(value) -> str:
        if value is True or value is False:
            return "true" if value else "false"
        return "null" if value is None else str(value)

    if len(expression) >= 2 and expression[0] == expression[-1] == '"':
        return re.sub(r"\\\((\.[A-Za-z0-9_.]*)\)", lambda match: render(lookup(match.group(1))), expression[1:-1])
    if re.fullmatch(r"\.[A-Za-z0-9_.]*", expression):
        return render(lookup(expression))
    return None


# gh api's flags, as the cobra/pflag parser accepts them: a value may be the
# next argument or attached (``--method=PATCH``, ``-XDELETE``, ``-fbody=x``).
API_VALUE_FLAGS = {
    "-X": "method", "--method": "method",
    "-f": "field", "-F": "field", "--field": "field", "--raw-field": "field",
    "--input": "input",
    "-H": "ignore", "--header": "ignore", "-q": "ignore", "--jq": "ignore", "-t": "ignore",
    "--template": "ignore", "-p": "ignore", "--preview": "ignore", "--hostname": "ignore", "--cache": "ignore",
}
API_BOOL_FLAGS = {"-i", "--include", "--paginate", "--silent", "--verbose", "--slurp"}


@dataclass
class ApiCall:
    method: str | None = None
    path: str | None = None
    params: dict[str, str] = field(default_factory=dict)
    body: bool = False
    unknown: list[str] = field(default_factory=list)

    @property
    def effective_method(self) -> str:
        return self.method or ("POST" if self.body else "GET")


def _parse_api(argv: list[str]) -> ApiCall:
    """Parse ``gh api`` arguments; anything not modelled lands in ``unknown``."""
    call = ApiCall()
    i = 1
    while i < len(argv):
        arg = argv[i]
        i += 1
        if arg.startswith("--"):
            name, eq, attached = arg.partition("=")
            has_value = bool(eq)
        elif arg.startswith("-") and len(arg) > 1:
            name, attached = arg[:2], arg[2:]
            has_value = attached != ""
            attached = attached[1:] if attached.startswith("=") else attached
        else:
            if call.path is None:
                call.path = arg
            else:
                call.unknown.append(arg)
            continue
        if name in API_BOOL_FLAGS and not has_value:
            continue
        kind = API_VALUE_FLAGS.get(name)
        if kind is None:
            call.unknown.append(arg)
            continue
        if has_value:
            value = attached
        elif i < len(argv):
            value = argv[i]
            i += 1
        else:
            call.unknown.append(arg)
            continue
        if kind == "method":
            call.method = value.upper()
        elif kind == "field":
            key, _, field_value = value.partition("=")
            call.params[key] = field_value
            call.body = True
        elif kind == "input":
            call.body = True
    return call


def _fake_dispatch(state: dict, origin: str, argv: list[str]) -> int:
    if argv[:2] == ["pr", "view"]:
        if len(argv) < 3 or argv[2] != str(state["pr"]) or "--json" not in argv:
            print("fake gh: unsupported pr view", file=sys.stderr)
            return 2
        fields = argv[argv.index("--json") + 1].split(",")
        state["views"] += 1
        _inject(state, origin, f"view{state['views']}")
        full = {
            "headRefOid": _rev(origin, f"refs/heads/{state['head_ref']}"),
            "baseRefOid": state["base_sha"],
            "baseRefName": state["base_ref"],
            "headRefName": state["head_ref"],
            "isCrossRepository": state["cross"],
            "headRepositoryOwner": {"login": state["owner"]},
            "headRepository": {"name": state["repo"]},
            "state": state["state"],
            "mergeCommit": {"oid": state["merge_commit"]} if state["merge_commit"] else None,
            "mergeable": "MERGEABLE" if state["state"] == "OPEN" else "UNKNOWN",
            "mergeStateStatus": "CLEAN",
            "isDraft": False,
        }
        unknown = [name for name in fields if name not in full]
        if unknown:
            print(f"fake gh: unknown JSON fields {unknown}", file=sys.stderr)
            return 1
        selected = {name: full[name] for name in fields}
        expression = _flag_value(argv, ("-q", "--jq"))
        if expression is None:
            print(json.dumps(selected))
            return 0
        rendered = _jq(expression, selected)
        if rendered is None:
            print(f"fake gh: unsupported jq {expression!r}", file=sys.stderr)
            return 2
        print(rendered)
        return 0
    if argv[:2] == ["pr", "checks"]:
        if len(argv) < 3 or argv[2] != str(state["pr"]) or "--json" not in argv:
            print("fake gh: unsupported pr checks", file=sys.stderr)
            return 2
        print(json.dumps(PR_CHECKS))
        return 0
    if argv[:1] == ["api"]:
        call = _parse_api(argv)
        params = call.params
        if (
            not call.unknown and call.effective_method == "PUT"
            and call.path == f"repos/{{owner}}/{{repo}}/pulls/{state['pr']}/merge"
        ):
            _record_guards_at_merge_call(state, origin)
            _inject(state, origin, "put")
            code = _fake_merge(state, origin, params)
            if state.pop("other_actor_merges_after_put", False):
                _land(state, origin, _rev(origin, f"refs/heads/{state['head_ref']}"))
            return code
    print(f"fake gh: unsupported invocation {argv}", file=sys.stderr)
    return 2


def fake_gh(argv: list[str]) -> int:
    state_path = Path(os.environ["B315_FAKE_STATE"])
    origin = os.environ["B315_FAKE_ORIGIN"]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["calls"].append(argv)
    try:
        return _fake_dispatch(state, origin, argv)
    finally:
        state_path.write_text(json.dumps(state), encoding="utf-8")


# ── running the real helper ──────────────────────────────────────────────────


@dataclass
class Run:
    rc: int
    out: str
    err: str
    state: dict
    puts: list[list[str]]
    pushes: str
    lease: str
    main: str
    mutations: list[list[str]] = field(default_factory=list)


def run_helper(
    world: World, *, dry_run: bool = False, expected_head: str | None = None, helper: Path = HELPER
) -> Run:
    return _run(world, ["bash", str(helper), str(PR), expected_head or world.head, "1" if dry_run else "0",
                        HEAD_REF, OWNER, REPO])


def run_wrapper(world: World, *args: str, wrapper: Path = GATE) -> Run:
    """Execute the merge gate wrapper from the world's clone, as an operator
    runs it from a checkout. It calls ``bash scripts/b315_atomic_merge.sh``
    relative to its working directory, so the clone gets scripts/ links to the
    real helper and allocator (untracked; the helper does not read the tree)."""
    scripts = world.work / "scripts"
    scripts.mkdir(exist_ok=True)
    for name in ("b315_atomic_merge.sh", "backlog_id_alloc.py"):
        if not (scripts / name).exists():
            (scripts / name).symlink_to(ROOT / "scripts" / name)
    return _run(world, ["bash", str(wrapper), *args])


def _run(world: World, argv: list[str]) -> Run:
    env = dict(world.env)
    env["PATH"] = f"{world.bin}{os.pathsep}{env.get('PATH', '')}"
    env["B315_FAKE_STATE"] = str(world.state)
    env["B315_FAKE_ORIGIN"] = str(world.origin)
    env["B315_FAKE_LOCK"] = str(lock_path(world))
    env["TMPDIR"] = str(world.root / "tmp")
    result = subprocess.run(argv, cwd=world.work, env=env, capture_output=True, text=True, timeout=180, check=False)
    state = json.loads(world.state.read_text(encoding="utf-8"))
    puts = [call for call in state["calls"] if call[:1] == ["api"] and "PUT" in call]
    mutations = [call for call in state["calls"] if is_mutating(call)]
    pushes_log = world.origin / "pushes.log"
    pushes = pushes_log.read_text(encoding="utf-8") if pushes_log.exists() else ""
    lease = subprocess.run(
        ["git", "--git-dir", str(world.origin), "rev-parse", "--verify", "--quiet", LEASE_REF],
        env=world.env, capture_output=True, text=True, check=False,
    ).stdout.strip()
    main = _git(world.env, "--git-dir", str(world.origin), "rev-parse", "refs/heads/main")
    return Run(result.returncode, result.stdout, result.stderr, state, puts, pushes, lease, main, mutations)


@dataclass(frozen=True)
class Scenario:
    name: str
    rc: int
    puts: int
    merged: bool
    text: str
    inject: dict = field(default_factory=dict)
    dry_run: bool = False
    variant: str = "fresh"
    candidate_ids: tuple[int, ...] = (1, 2, 3, 4)
    precondition: str = ""
    candidate_text: str | None = None


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("lands_through_pr_api", 0, 1, True, "MERGED via the PR API"),
    Scenario("dry_run_never_calls_merge_endpoint", 0, 0, False, "merge endpoint NOT called", dry_run=True),
    Scenario("head_pushed_after_gate_capture", 1, 0, False, "head ownership changed",
             inject={"view1": ["move_head"]}),
    Scenario("head_moved_during_allocation", 1, 0, False, "moved during allocation",
             inject={"view2": ["move_head"]}),
    Scenario("main_moved_during_allocation", 1, 0, False, "moved during allocation",
             inject={"view2": ["advance_main"]}),
    Scenario("main_moved_at_merge_boundary", 1, 0, False, "main moved at merge boundary",
             inject={"view3": ["advance_main"]}),
    Scenario("head_moved_at_merge_boundary", 1, 0, False, "candidate force-pushed at merge boundary",
             inject={"view3": ["move_head"]}),
    Scenario("behind_main_refused_before_api", 1, 0, False, "(BEHIND)", variant="behind"),
    Scenario("stale_base_snapshot_refused", 1, 0, False, "candidate base/head is stale", variant="stale-base"),
    Scenario("allocation_gap_refused", 1, 0, False, "allocation refused", candidate_ids=(1, 2, 3, 5)),
    Scenario("head_moved_inside_api_call_409", 1, 1, False, "no false merged claim",
             inject={"put": ["move_head"]}),
    Scenario("main_moved_inside_api_call_405", 1, 1, False, "no false merged claim",
             inject={"put": ["advance_main"]}),
    Scenario("landed_on_unvalidated_main", 3, 1, True, "did not validate",
             inject={"put": ["ff_main_to_head_parent"]}),
    Scenario("landed_tree_mismatch", 3, 1, True, "tree mismatch", inject={"put": ["land_wrong_tree"]}),
    # A merge whose call did not report success is never claimed, even when it
    # landed exactly as validated.
    Scenario("lost_merge_response_never_claimed", 3, 1, True, "merge_response_not_success",
             inject={"put": ["drop_merge_response"]}),
    Scenario("stale_remote_lease_refused", 1, 0, False, "stale remote lease observed", precondition="lease"),
    Scenario("local_lock_busy_refused", 1, 0, False, "lock busy", precondition="lock"),
    Scenario("replaced_candidate_blob_refused", 1, 0, False, "allocation refused",
             candidate_ids=(1, 2, 3, 5), precondition="replace_blob"),
    Scenario("grafted_behind_head_refused_before_api", 1, 0, False, "rewrites commit parents",
             variant="behind", precondition="graft"),
    # view4 is the last read before the PUT (the second boundary check).
    Scenario("base_retargeted_at_merge_boundary_refused", 1, 0, False, "PR base retargeted at merge boundary",
             inject={"view4": ["retarget_base"]}),
    Scenario("base_retargeted_inside_merge_window_detected", 4, 1, True, "base reads 'release'",
             inject={"put": ["retarget_base"]}),
    Scenario("merge_missing_from_main_detected", 4, 1, True, "is not reachable from refs/heads/main",
             inject={"put": ["rewind_base_after_merge"]}),
    Scenario("same_tree_head_merged_by_other_actor_after_409", 5, 1, True, "merged_by_other_actor",
             inject={"put": ["same_tree_head_merged_by_other"]}),
    Scenario("lock_holder_dies_before_merge_call_refused", 1, 0, False, "lock lost before the merge call",
             inject={"view4": ["kill_lock_holder"]}),
    Scenario("lock_holder_dies_during_merge_call_reported", 3, 1, True, "LOCK LOST DURING THE MERGE CALL",
             inject={"put": ["kill_lock_holder"]}),
    # Candidate ledgers the lenient parser reads as B-001..B-003 ("adds nothing").
    Scenario("unclosed_backlog_block_refused_before_api", 1, 0, False, "backlog block is never closed",
             candidate_text=malformed_backlog("unclosed_block")),
    Scenario("malformed_backlog_opener_refused_before_api", 1, 0, False, "malformed backlog fence",
             candidate_text=malformed_backlog("opener_trailing_space")),
    Scenario("orphan_item_heading_refused_before_api", 1, 0, False, "has no backlog block",
             candidate_text=malformed_backlog("orphan_heading")),
)


def lock_path(world: World) -> Path:
    """The helper's allocation lock: ``<git common-dir>/corelink-backlog-id-allocation.lock``."""
    return world.work / ".git" / "corelink-backlog-id-allocation.lock"


def _hold_lock(world: World) -> subprocess.Popen:
    common = world.work / ".git"
    ready = world.root / "held.ready"
    holder = subprocess.Popen(
        [sys.executable, str(ALLOCATOR), "--hold-lock", str(lock_path(world)),
         "--common-dir", str(common), "--ready", str(ready)],
        stdin=subprocess.DEVNULL, env=world.env,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if ready.exists() and ready.read_text(encoding="utf-8").startswith("locked "):
            return holder
        time.sleep(0.02)
    holder.kill()
    raise HarnessError("could not pre-hold the allocation lock")


def substitute_candidate_backlog(world: World) -> str:
    """Plant ``refs/replace`` in the helper's clone so the candidate's real
    BACKLOG.md blob READS as a valid dense population there, while origin
    (playing GitHub) keeps, and would merge, the real bytes. A blob replacement
    leaves every tree oid unchanged. Returns the substitute text."""
    substitute = backlog(1, 2, 3, 4)
    real = _git(world.env, "rev-parse", f"{world.head}:BACKLOG.md", cwd=world.work)
    fake = _git(world.env, "hash-object", "-w", "--stdin", cwd=world.work, stdin=substitute)
    _git(world.env, "replace", real, fake, cwd=world.work)
    served = _git(world.env, "cat-file", "blob", f"{world.head}:BACKLOG.md", cwd=world.work)
    if served != substitute.strip():
        raise HarnessError("refs/replace precondition did not take effect in the clone")
    return substitute


def graft_head_onto_main(world: World) -> Path:
    """Write a graft file in the helper's clone that makes the head's only
    parent the current main, so plain git there believes a BEHIND head
    contains main. Origin (playing GitHub) has no graft."""
    graft = world.work / ".git" / "info" / "grafts"
    graft.parent.mkdir(exist_ok=True)
    graft.write_text(f"{world.head} {world.main0}\n", encoding="utf-8")
    probe = subprocess.run(
        ["git", "merge-base", "--is-ancestor", world.main0, world.head],
        cwd=world.work, env=world.env, capture_output=True, text=True, check=False,
    )
    if probe.returncode:
        raise HarnessError("graft precondition did not take effect in the clone")
    return graft


def run_scenario(
    scenario: Scenario, root: Path, template: World | None = None, helper: Path = HELPER
) -> tuple[Run, list[str]]:
    """Run one scenario in a fresh world under ``root``; return the failures."""
    if template is None:
        world = build_world(root, candidate_ids=scenario.candidate_ids, variant=scenario.variant,
                            candidate_text=scenario.candidate_text)
    else:
        world = copy_world(template, root)
    state = json.loads(world.state.read_text(encoding="utf-8"))
    state["inject"] = scenario.inject
    world.state.write_text(json.dumps(state), encoding="utf-8")
    planted_lease = ""
    holder = None
    if scenario.precondition == "lease":
        planted_lease = world.main0
        _git(world.env, "--git-dir", str(world.origin), "update-ref", LEASE_REF, planted_lease)
    elif scenario.precondition == "lock":
        holder = _hold_lock(world)
    elif scenario.precondition == "replace_blob":
        substitute_candidate_backlog(world)
    elif scenario.precondition == "graft":
        graft_head_onto_main(world)
    elif scenario.precondition:
        raise HarnessError(f"unknown precondition {scenario.precondition!r}")
    try:
        run = run_helper(world, dry_run=scenario.dry_run, helper=helper)
    finally:
        if holder is not None:
            holder.send_signal(signal.SIGTERM)
            holder.wait(timeout=10)
    failures: list[str] = []
    if run.rc != scenario.rc:
        failures.append(f"exit {run.rc}, expected {scenario.rc}")
    if len(run.puts) != scenario.puts:
        failures.append(f"merge endpoint called {len(run.puts)}x, expected {scenario.puts}x")
    expected_put = ["api", "-X", "PUT", MERGE_PATH, "-f", f"sha={world.head}", "-f", "merge_method=squash"]
    for call in run.puts:
        if call != expected_put:
            failures.append(f"merge call {call} is not the exact head-pinned squash {expected_put}")
    guards = run.state.get("guards_at_put", [])
    if len(guards) != len(run.puts):
        failures.append(f"guard probe ran {len(guards)}x for {len(run.puts)} merge call(s)")
    for guard in guards:
        if not guard["lock"]:
            failures.append("local allocation lock was NOT held when the merge endpoint was called")
        if not guard["lease"]:
            failures.append("remote lease was NOT held when the merge endpoint was called")
    if (run.state["state"] == "MERGED") != scenario.merged:
        failures.append(f"fake PR state {run.state['state']}, expected merged={scenario.merged}")
    if scenario.text not in run.out + run.err:
        failures.append(f"output lacks {scenario.text!r}")
    if "refs/heads/main " in run.pushes:
        failures.append("helper attempted a direct push to main")
    if run.lease != planted_lease:
        failures.append(f"remote lease left as {run.lease or '<absent>'}, expected {planted_lease or '<absent>'}")
    if run.mutations != run.puts:
        failures.append(f"mutating gh calls besides the pinned merge PUTs: {run.mutations}")
    if scenario.dry_run and run.pushes:
        failures.append(f"dry run pushed to origin: {run.pushes.strip()}")
    if scenario.rc == 4 and "merged_into_unexpected_base" not in run.err:
        failures.append("exit 4 without the merged_into_unexpected_base marker")
    if run.state.get("base_ref", "main") != "main" or run.state.get("rewind_base_after_merge"):
        # These worlds must leave main where it was; otherwise the scenario
        # would be testing a merge onto main, not a merge somewhere else.
        if run.main != world.main0:
            failures.append(f"main moved to {run.main} in a world whose merge must not land on main")
    if run.state.get("base_ref", "main") != "main" and run.state["state"] == "MERGED":
        tip = _git(world.env, "--git-dir", str(world.origin), "rev-parse", f"refs/heads/{RETARGET_REF}")
        if tip != run.state["merge_commit"]:
            failures.append("the fake did not land the merge on the retargeted base")
    if scenario.rc == 0 and scenario.merged:
        parents = _git(world.env, "--git-dir", str(world.origin), "rev-list", "--parents", "-n", "1", run.main)
        tree = _git(world.env, "--git-dir", str(world.origin), "rev-parse", f"{run.main}^{{tree}}")
        head_tree = _git(world.env, "--git-dir", str(world.origin), "rev-parse", f"{world.head}^{{tree}}")
        if parents != f"{run.main} {world.main0}" or tree != head_tree:
            failures.append("landed main is not one commit on the captured main carrying tree(head)")
    return run, failures


def template_key(scenario: Scenario) -> tuple:
    """Scenarios whose worlds start identical share one built template."""
    return (scenario.variant, scenario.candidate_ids, scenario.candidate_text)


def self_test(root: Path, workers: int = 6) -> list[str]:
    """Run every scenario; return one line per failure (empty = all held)."""
    if not SCENARIOS:
        return ["harness has ZERO scenarios: nothing would be proven"]
    templates: dict[tuple, World] = {}
    for scenario in SCENARIOS:
        key = template_key(scenario)
        if key not in templates:
            templates[key] = build_world(
                root / f"template-{len(templates)}", candidate_ids=scenario.candidate_ids,
                variant=scenario.variant, candidate_text=scenario.candidate_text,
            )
    from concurrent.futures import ThreadPoolExecutor

    def one(indexed: tuple[int, Scenario]) -> list[str]:
        index, scenario = indexed
        _, failures = run_scenario(
            scenario, root / f"{index:02d}-{scenario.name}",
            templates[template_key(scenario)],
        )
        return [f"{scenario.name}: {failure}" for failure in failures]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(one, enumerate(SCENARIOS)))
    if len(results) != len(SCENARIOS):
        return [f"ran {len(results)} of {len(SCENARIOS)} scenarios"]
    return [problem for result in results for problem in result]


def main(argv: list[str]) -> int:
    if argv[:1] == ["fake-gh"]:
        return fake_gh(argv[1:])
    import tempfile

    with tempfile.TemporaryDirectory(prefix="b315-harness-") as directory:
        problems = self_test(Path(directory))
    for problem in problems:
        print(f"B-315 harness: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"B-315 landing harness: {len(SCENARIOS)} scenarios PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
