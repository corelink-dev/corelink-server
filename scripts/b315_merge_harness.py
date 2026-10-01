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

Every scenario also asserts the helper never pushed to main and never left the
remote lease behind. No network, no credentials: ``gh`` cannot reach GitHub.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "b315_atomic_merge.sh"
ALLOCATOR = ROOT / "scripts" / "backlog_id_alloc.py"
PR = 7
OWNER, REPO, HEAD_REF = "acme", "corelink-server", "feature"
LEASE_REF = "refs/heads/corelink-backlog-id-merge-lock"
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


def build_world(
    root: Path,
    *,
    main_ids: tuple[int, ...] = (1, 2, 3),
    candidate_ids: tuple[int, ...] = (1, 2, 3, 4),
    variant: str = "fresh",
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
    (seed / "BACKLOG.md").write_text(backlog(*candidate_ids), encoding="utf-8")
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
    gh.write_text(
        f"#!/bin/sh\nexec {json.dumps(sys.executable)} {json.dumps(str(Path(__file__).resolve()))} fake-gh \"$@\"\n",
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
        elif action in {"land_wrong_tree", "drop_merge_response"}:
            state[action] = True
        else:
            raise HarnessError(f"unknown injection {action!r}")


def _http_error(code: int, message: str) -> int:
    print(json.dumps({"message": message, "status": str(code)}))
    print(f"gh: {message} (HTTP {code})", file=sys.stderr)
    return 1


def _fake_merge(state: dict, origin: str, params: dict[str, str]) -> int:
    env = dict(os.environ)
    head = _rev(origin, f"refs/heads/{state['head_ref']}")
    main = _rev(origin, "refs/heads/main")
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
        ["git", "--git-dir", origin, "merge-base", "--is-ancestor", main, head],
        env=env, capture_output=True, check=False,
    )
    if ancestor.returncode:
        return _http_error(405, "Head branch is out of date with the base branch.")
    tree_of = main if state.get("land_wrong_tree") else head
    tree = _rev(origin, f"{tree_of}^{{tree}}")
    new = _git(env, "--git-dir", origin, "commit-tree", tree, "-p", main, "-m", f"squash (#{state['pr']})")
    _git(env, "--git-dir", origin, "update-ref", "refs/heads/main", new, main)
    state["state"] = "MERGED"
    state["merge_commit"] = new
    if state.get("drop_merge_response"):
        return _http_error(502, "Bad Gateway")
    print(json.dumps({"sha": new, "merged": True, "message": "Pull Request successfully merged"}))
    return 0


def _parse_api(argv: list[str]) -> tuple[str, str | None, dict[str, str]]:
    method, path, params = "GET", None, {}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in {"-X", "--method"}:
            method = argv[i + 1]
            i += 2
        elif arg in {"-f", "-F", "--raw-field", "--field"}:
            key, _, value = argv[i + 1].partition("=")
            params[key] = value
            i += 2
        elif arg in {"-H", "--header", "-q", "--jq"}:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            path = path or arg
            i += 1
    return method, path, params


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
            "baseRefName": "main",
            "headRefName": state["head_ref"],
            "isCrossRepository": state["cross"],
            "headRepositoryOwner": {"login": state["owner"]},
            "headRepository": {"name": state["repo"]},
            "state": state["state"],
            "mergeCommit": {"oid": state["merge_commit"]} if state["merge_commit"] else None,
        }
        unknown = [name for name in fields if name not in full]
        if unknown:
            print(f"fake gh: unknown JSON fields {unknown}", file=sys.stderr)
            return 1
        print(json.dumps({name: full[name] for name in fields}))
        return 0
    if argv[:1] == ["api"]:
        method, path, params = _parse_api(argv)
        if method == "PUT" and path == f"repos/{{owner}}/{{repo}}/pulls/{state['pr']}/merge":
            _inject(state, origin, "put")
            return _fake_merge(state, origin, params)
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


def run_helper(
    world: World, *, dry_run: bool = False, expected_head: str | None = None, helper: Path = HELPER
) -> Run:
    env = dict(world.env)
    env["PATH"] = f"{world.bin}{os.pathsep}{env.get('PATH', '')}"
    env["B315_FAKE_STATE"] = str(world.state)
    env["B315_FAKE_ORIGIN"] = str(world.origin)
    env["TMPDIR"] = str(world.root / "tmp")
    result = subprocess.run(
        ["bash", str(helper), str(PR), expected_head or world.head, "1" if dry_run else "0",
         HEAD_REF, OWNER, REPO],
        cwd=world.work, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    state = json.loads(world.state.read_text(encoding="utf-8"))
    puts = [call for call in state["calls"] if call[:1] == ["api"] and "PUT" in call]
    pushes_log = world.origin / "pushes.log"
    pushes = pushes_log.read_text(encoding="utf-8") if pushes_log.exists() else ""
    lease = subprocess.run(
        ["git", "--git-dir", str(world.origin), "rev-parse", "--verify", "--quiet", LEASE_REF],
        env=world.env, capture_output=True, text=True, check=False,
    ).stdout.strip()
    main = _git(world.env, "--git-dir", str(world.origin), "rev-parse", "refs/heads/main")
    return Run(result.returncode, result.stdout, result.stderr, state, puts, pushes, lease, main)


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
    Scenario("lost_merge_response_still_proven", 0, 1, True, "MERGED via the PR API",
             inject={"put": ["drop_merge_response"]}),
    Scenario("stale_remote_lease_refused", 1, 0, False, "stale remote lease observed", precondition="lease"),
    Scenario("local_lock_busy_refused", 1, 0, False, "lock busy", precondition="lock"),
)


def _hold_lock(world: World) -> subprocess.Popen:
    common = world.work / ".git"
    ready = world.root / "held.ready"
    holder = subprocess.Popen(
        [sys.executable, str(ALLOCATOR), "--hold-lock", str(common / "corelink-backlog-id-allocation.lock"),
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


def run_scenario(
    scenario: Scenario, root: Path, template: World | None = None
) -> tuple[Run, list[str]]:
    """Run one scenario in a fresh world under ``root``; return the failures."""
    if template is None:
        world = build_world(root, candidate_ids=scenario.candidate_ids, variant=scenario.variant)
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
    try:
        run = run_helper(world, dry_run=scenario.dry_run)
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
    if (run.state["state"] == "MERGED") != scenario.merged:
        failures.append(f"fake PR state {run.state['state']}, expected merged={scenario.merged}")
    if scenario.text not in run.out + run.err:
        failures.append(f"output lacks {scenario.text!r}")
    if "refs/heads/main " in run.pushes:
        failures.append("helper attempted a direct push to main")
    if run.lease != planted_lease:
        failures.append(f"remote lease left as {run.lease or '<absent>'}, expected {planted_lease or '<absent>'}")
    if scenario.rc == 0 and scenario.merged:
        parents = _git(world.env, "--git-dir", str(world.origin), "rev-list", "--parents", "-n", "1", run.main)
        tree = _git(world.env, "--git-dir", str(world.origin), "rev-parse", f"{run.main}^{{tree}}")
        head_tree = _git(world.env, "--git-dir", str(world.origin), "rev-parse", f"{world.head}^{{tree}}")
        if parents != f"{run.main} {world.main0}" or tree != head_tree:
            failures.append("landed main is not one commit on the captured main carrying tree(head)")
    return run, failures


def self_test(root: Path, workers: int = 6) -> list[str]:
    """Run every scenario; return one line per failure (empty = all held)."""
    if not SCENARIOS:
        return ["harness has ZERO scenarios: nothing would be proven"]
    templates: dict[tuple[str, tuple[int, ...]], World] = {}
    for scenario in SCENARIOS:
        key = (scenario.variant, scenario.candidate_ids)
        if key not in templates:
            templates[key] = build_world(
                root / f"template-{len(templates)}", candidate_ids=scenario.candidate_ids,
                variant=scenario.variant,
            )
    from concurrent.futures import ThreadPoolExecutor

    def one(indexed: tuple[int, Scenario]) -> list[str]:
        index, scenario = indexed
        _, failures = run_scenario(
            scenario, root / f"{index:02d}-{scenario.name}",
            templates[(scenario.variant, scenario.candidate_ids)],
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
