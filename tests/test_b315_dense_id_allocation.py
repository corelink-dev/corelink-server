from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from backlog_id_alloc import AllocationError, allocation  # noqa: E402
import b315_merge_harness as harness  # noqa: E402
import verify_b315_dense_id_allocation as verifier  # noqa: E402


SCRIPT = ROOT / "scripts/backlog_id_alloc.py"


def _gate_and_helper() -> str:
    return (
        (ROOT / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8")
        + "\n"
        + (ROOT / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    )


def _backlog(*ids: int) -> str:
    return "\n".join(
        f"### B-{number:03d} — fixture\n\n```backlog\n"
        f"id: B-{number:03d}\nrepo: corelink-server\nowner: tl\n"
        "status: done\nverify: 'true'\nverify-means: fixture\n"
        "last-verified: 2026-09-06\n```\n"
        for number in ids
    )


def test_candidate_gets_only_the_next_contiguous_ids():
    base = _backlog(1, 2)
    assert allocation(base, _backlog(1, 2, 3, 4), base_text=base) == (3, 4)


def test_adversarial_two_pr_race_rejects_id_already_merged_from_current_main():
    base = _backlog(1, 2)
    candidate = _backlog(1, 2, 3)
    current_main = _backlog(1, 2, 3)
    with pytest.raises(AllocationError, match="collides"):
        allocation(current_main, candidate, base_text=base)


@pytest.mark.parametrize("candidate", [_backlog(1, 2, 4), _backlog(1)])
def test_stale_or_disappearing_candidate_is_rejected(candidate: str):
    with pytest.raises(AllocationError, match="(stale allocation|removed|gaps)"):
        allocation(_backlog(1, 2), candidate)


@pytest.mark.parametrize("bad", ["B-000", "B-04", "B-0042", "B-TBD", "B-3"])
def test_malformed_non_positive_and_noncanonical_ids_fail_closed(bad: str):
    candidate = _backlog(1, 2).replace("id: B-002", f"id: {bad}", 1)
    with pytest.raises(AllocationError):
        allocation(_backlog(1, 2), candidate)


def test_duplicate_ids_fail_closed():
    duplicate = _backlog(1, 2) + _backlog(2).replace("### B-002", "### B-003", 1)
    with pytest.raises(AllocationError, match="duplicate"):
        allocation(_backlog(1, 2), duplicate)


def _item(number: int, *, opener: str = "```backlog", closer: str | None = "```") -> str:
    return (
        f"### B-{number:03d} — fixture\n\n{opener}\nid: B-{number:03d}\nrepo: corelink-server\nowner: tl\n"
        "status: done\nverify: 'true'\nverify-means: fixture\nlast-verified: 2026-09-06\n"
        + (f"{closer}\n" if closer is not None else "")
    )


SKIPPED_STRUCTURE = {
    # The review's two reproductions, verbatim in shape: each read as "adds nothing".
    "unclosed B-005 after B-001..B-003": (_backlog(1, 2, 3) + _item(5, closer=None), "is never closed"),
    "opener with trailing whitespace": (_backlog(1, 2, 3) + _item(4, opener="```backlog "), "malformed backlog fence"),
    "orphan heading": (_backlog(1, 2, 3) + "### B-004 — fixture\n\nno block\n", "B-004 has no backlog block"),
    # Review round 7: heading spellings HEADING_RE does not count.
    "orphan heading with two spaces": (_backlog(1, 2, 3) + "###  B-004 — fixture\n\nno block\n",
                                       "non-canonical item heading"),
    "orphan heading with a tab": (_backlog(1, 2, 3) + "###\tB-004 — fixture\n\nno block\n", "non-canonical item heading"),
    "orphan indented heading": (_backlog(1, 2, 3) + " ### B-004 — fixture\n\nno block\n", "non-canonical item heading"),
    "lower-case orphan heading": (_backlog(1, 2, 3) + "### b-004 — fixture\n\nno block\n", "non-canonical item heading"),
    "tilde fence": (_backlog(1, 2, 3) + _item(4, opener="~~~backlog", closer="~~~"), "malformed backlog fence"),
    "block closed by a tagged fence": (_backlog(1, 2, 3) + _item(4, closer="```yaml"), "only a bare ``` may close it"),
    "block with no heading": (_backlog(1, 2, 3) + _item(4).split("\n", 2)[2], "has no `### B-NNN` heading"),
    "two headings, one block": (
        _backlog(1, 2, 3) + "### B-004 — fixture\n\n" + _item(4), "B-004 has no backlog block"
    ),
}


@pytest.mark.parametrize("label", sorted(SKIPPED_STRUCTURE))
def test_backlog_structure_the_parser_skips_is_refused(label: str):
    """Review round 6: backlog_verify.parse skips these, so the allocator used
    to validate only part of the ledger. Each is refused on its own terms."""
    candidate, named = SKIPPED_STRUCTURE[label]
    base = _backlog(1, 2, 3)
    with pytest.raises(AllocationError, match=re.escape(named)):
        allocation(base, candidate, base_text=base)


def test_other_heading_levels_stay_prose():
    """BACKLOG.md uses `#### B-054 dependency ledger` inside an item's prose."""
    candidate = _backlog(1, 2, 3) + "\n#### B-003 dependency ledger\n\nprose\n"
    assert allocation(_backlog(1, 2, 3), candidate, base_text=_backlog(1, 2, 3)) == ()


def test_a_heading_inside_a_block_is_counted_against_the_blocks():
    candidate = _backlog(1, 2, 3).replace("verify-means: fixture\n", "verify-means: fixture\n### B-009 aside\n", 1)
    from backlog_verify import parse
    assert len(parse(candidate)) == 3  # the parser still sees three blocks
    with pytest.raises(AllocationError, match="4 item headings for 3 backlog blocks"):
        allocation(_backlog(1, 2, 3), candidate)


def test_rejecting_a_mutation_does_not_poison_the_next_valid_allocation():
    main = _backlog(1, 2)
    with pytest.raises(AllocationError):
        allocation(main, _backlog(1, 2, 4))
    assert allocation(main, _backlog(1, 2, 3)) == (3,)


def test_two_same_snapshot_allocators_cannot_hold_the_merge_lock(tmp_path: Path):
    lock = tmp_path / "merge.lock"
    first_ready = tmp_path / "first.ready"
    second_ready = tmp_path / "second.ready"
    command = [
        sys.executable,
        str(SCRIPT),
        "--hold-lock",
        str(lock),
        "--common-dir",
        str(tmp_path),
    ]
    first = subprocess.Popen(command + ["--ready", str(first_ready)], stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while (
            (not first_ready.exists() or not first_ready.read_text(encoding="utf-8"))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert first_ready.read_text(encoding="utf-8").startswith("locked ")

        second = subprocess.run(
            command + ["--ready", str(second_ready)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        assert second.returncode == 75
        assert second_ready.read_text(encoding="utf-8") == "busy\n"
    finally:
        first.send_signal(signal.SIGTERM)
        first.wait(timeout=5)


def test_lock_path_unlink_is_detected_while_held(tmp_path: Path):
    lock = tmp_path / "merge.lock"
    ready = tmp_path / "ready"
    holder = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--hold-lock",
            str(lock),
            "--common-dir",
            str(tmp_path),
            "--ready",
            str(ready),
        ],
        stdin=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while (
            (not ready.exists() or not ready.read_text(encoding="utf-8"))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert ready.read_text(encoding="utf-8").startswith("locked ")
        lock.unlink()
        holder.wait(timeout=5)
        assert holder.returncode == 74
        assert "lost lock path" in ready.read_text(encoding="utf-8")
    finally:
        if holder.poll() is None:
            holder.send_signal(signal.SIGTERM)
            holder.wait(timeout=5)


def test_lock_path_replacement_is_detected_while_held(tmp_path: Path):
    lock = tmp_path / "merge.lock"
    ready = tmp_path / "ready"
    holder = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--hold-lock",
            str(lock),
            "--common-dir",
            str(tmp_path),
            "--ready",
            str(ready),
        ],
        stdin=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while (
            (not ready.exists() or not ready.read_text(encoding="utf-8"))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert ready.read_text(encoding="utf-8").startswith("locked ")
        lock.unlink()
        lock.touch()
        holder.wait(timeout=5)
        assert holder.returncode == 74
        assert "lost lock path" in ready.read_text(encoding="utf-8")
    finally:
        if holder.poll() is None:
            holder.send_signal(signal.SIGTERM)
            holder.wait(timeout=5)


def test_lock_symlink_and_alternate_environment_are_rejected(tmp_path: Path):
    real = tmp_path / "real.lock"
    lock = tmp_path / "merge.lock"
    ready = tmp_path / "ready"
    real.touch()
    lock.symlink_to(real)
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--hold-lock",
            str(lock),
            "--common-dir",
            str(tmp_path),
            "--ready",
            str(ready),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 74
    assert not ready.exists()

    helper = (ROOT / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    start = helper.index("start_backlog_allocation_lock() {")
    lock_section = helper[start: helper.index("start_backlog_allocation_lock || exit 1", start)]
    # This slice used to run from the first `start_…` to the first `stop_…`,
    # which is defined ABOVE it: an empty string that satisfied every
    # `not in`. Prove the slice holds the lock code before trusting absences.
    assert "--git-common-dir" in lock_section and "--hold-lock" in lock_section
    assert "TMPDIR" not in lock_section
    assert "CORELINK_BACKLOG_ALLOC_LOCK" not in lock_section


def test_gate_covers_head_base_main_boundary_and_temp_cleanup_fail_closed():
    gate = _gate_and_helper()
    for marker in (
        'baseRefName',
        '[ "$bk_base_name" = main ]',
        '[ "$CAPTURED_BASE" = "$CAPTURED_MAIN" ]',
        'REMOTE_LEASE_REF=refs/heads/corelink-backlog-id-merge-lock',
        'no false merged claim',
        'main_sha_final',
        'backlog_lock_healthy',
        'rm -rf -- "$BACKLOG_TMP"',
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
    ):
        assert marker in gate
    for obsolete in ("--match-head-commit", "gh pr merge", "--squash", "--atomic"):
        assert obsolete not in gate


def test_helper_self_test_is_executable():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


# ── The landing: behaviour, executed against a fake GitHub ───────────────────
# Each scenario runs the REAL scripts/b315_atomic_merge.sh in a throwaway world
# whose origin declines every push to main (as branch protection does) and
# whose `gh` is the harness's model of the PR merge API. See the harness
# docstring for what that model does and does not prove.


@pytest.fixture(scope="module")
def world_template(tmp_path_factory):
    root = tmp_path_factory.mktemp("b315-templates")
    cache: dict = {}

    def template(scenario):
        key = harness.template_key(scenario)
        if key not in cache:
            cache[key] = harness.build_world(
                root / f"t{len(cache)}", candidate_ids=scenario.candidate_ids, variant=scenario.variant,
                candidate_text=scenario.candidate_text,
            )
        return cache[key]

    return template


@pytest.mark.parametrize("scenario", harness.SCENARIOS, ids=lambda scenario: scenario.name)
def test_landing_scenario(scenario, tmp_path: Path, world_template):
    run, failures = harness.run_scenario(scenario, tmp_path / "world", world_template(scenario))
    assert failures == [], f"{failures}\n--- stdout\n{run.out}\n--- stderr\n{run.err}"


def test_scenarios_are_named_and_cover_land_dry_run_and_refusal():
    names = [scenario.name for scenario in harness.SCENARIOS]
    assert len(names) == len(set(names)) and all(names)
    outcomes = {(s.rc, s.puts, s.merged, s.dry_run) for s in harness.SCENARIOS}
    assert (0, 1, True, False) in outcomes  # lands
    assert (0, 0, False, True) in outcomes  # dry run, endpoint never called
    assert (1, 0, False, False) in outcomes  # refused before the API
    assert (1, 1, False, False) in outcomes  # API refused, no merged claim
    assert (3, 1, True, False) in outcomes  # merged but unproven
    assert (4, 1, True, False) in outcomes  # merged, but not into main
    assert (5, 1, True, False) in outcomes  # merged, but another head than the one validated


def _fake_gh(world, *args: str) -> subprocess.CompletedProcess:
    env = dict(world.env)
    env["PATH"] = f"{world.bin}{os.pathsep}{env.get('PATH', '')}"
    env["B315_FAKE_STATE"] = str(world.state)
    env["B315_FAKE_ORIGIN"] = str(world.origin)
    return subprocess.run(["gh", *args], cwd=world.work, env=env, capture_output=True, text=True, check=False)


def test_fake_github_enforces_the_model_the_scenarios_rely_on(tmp_path: Path):
    """If the fake accepted these, the refusal scenarios would prove nothing."""
    world = harness.build_world(tmp_path / "fresh")
    put = ("api", "-X", "PUT", harness.MERGE_PATH)
    result = _fake_gh(world, *put, "-f", f"sha={world.head}", "-f", "merge_method=merge")
    assert result.returncode and "HTTP 405" in result.stderr  # linear history
    result = _fake_gh(world, *put, "-f", f"sha={world.main0}", "-f", "merge_method=squash")
    assert result.returncode and "HTTP 409" in result.stderr  # sha pin
    result = _fake_gh(world, "api", "repos/{owner}/{repo}/contents/BACKLOG.md")
    assert result.returncode == 2  # anything unmodelled is refused, never faked
    behind = harness.build_world(tmp_path / "behind", variant="behind")
    result = _fake_gh(behind, *put, "-f", f"sha={behind.head}", "-f", "merge_method=squash")
    assert result.returncode and "HTTP 405" in result.stderr  # strict: up to date
    result = _fake_gh(world, *put, "-f", f"sha={world.head}", "-f", "merge_method=squash")
    assert result.returncode == 0, result.stderr
    landed = json.loads(result.stdout)["sha"]
    git = ["git", "--git-dir", str(world.origin)]
    parents = subprocess.run([*git, "rev-list", "--parents", "-n", "1", "refs/heads/main"],
                             env=world.env, capture_output=True, text=True, check=True).stdout.split()
    trees = [subprocess.run([*git, "rev-parse", f"{oid}^{{tree}}"], env=world.env, capture_output=True,
                            text=True, check=True).stdout.strip() for oid in (landed, world.head)]
    assert parents == [landed, world.main0] and trees[0] == trees[1]


def test_lock_probe_sees_free_absent_and_held_locks(tmp_path: Path):
    """The guard check at the merge call is only as good as this probe."""
    lock = tmp_path / "corelink-backlog-id-allocation.lock"
    assert harness.lock_held(lock) is False  # absent
    lock.touch()
    assert harness.lock_held(lock) is False  # present, nobody holds it
    ready = tmp_path / "ready"
    holder = subprocess.Popen(
        [sys.executable, str(SCRIPT), "--hold-lock", str(lock), "--common-dir", str(tmp_path),
         "--ready", str(ready)],
        stdin=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while not (ready.exists() and ready.read_text(encoding="utf-8")) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.read_text(encoding="utf-8").startswith("locked ")
        assert harness.lock_held(lock) is True
    finally:
        holder.send_signal(signal.SIGTERM)
        holder.wait(timeout=10)
    assert harness.lock_held(lock) is False  # released with the holder


def _mutated_helper(tmp_path: Path, needle: str, replacement: str) -> Path:
    """A copy of the real helper with ONE content mutation, next to the allocator it needs."""
    source = (ROOT / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    assert source.count(needle) == 1, f"mutation needle matched {source.count(needle)}x, expected 1"
    directory = tmp_path / "mutant"
    directory.mkdir()
    # A symlink, not a copy: the allocator imports its siblings from its
    # resolved directory, i.e. the real scripts/.
    (directory / "backlog_id_alloc.py").symlink_to(SCRIPT)
    helper = directory / "b315_atomic_merge.sh"
    helper.write_text(source.replace(needle, replacement), encoding="utf-8")
    return helper


@pytest.mark.parametrize(
    ("replacement", "named"),
    [
        ("stop_backlog_allocation_lock", "local allocation lock was NOT held when the merge endpoint was called"),
        ("release_remote_backlog_lease", "remote lease was NOT held when the merge endpoint was called"),
    ],
)
def test_releasing_a_guard_before_the_merge_call_is_caught(tmp_path: Path, replacement: str, named: str):
    """Teeth for the lock/lease-at-merge check: a helper that drops either guard
    after its last health check still merges, and the harness must say so."""
    helper = _mutated_helper(
        tmp_path, 'backlog_lock_healthy || refuse "local allocation lock lost before the merge call; not merging."',
        replacement,
    )
    landing = next(s for s in harness.SCENARIOS if s.name == "lands_through_pr_api")
    run, failures = harness.run_scenario(landing, tmp_path / "world", helper=helper)
    assert run.puts, "the mutant never reached the merge endpoint, so nothing was probed"
    assert named in failures, failures


def _lock_health(pid: int, ready: Path, lock: Path | None = None, identity: str | None = None) -> str:
    """Run the helper's own backlog_lock_healthy (extracted by its delimiters)
    against a holder ``pid``, its ``ready`` file and the ``lock`` path with the
    ``identity`` (dev:ino) the holder reported. By default the lock is a fresh
    file next to ``ready`` and the identity is its own."""
    if lock is None:
        lock = ready.with_name("lock")
        lock.touch()
    if identity is None:
        held = lock.stat()
        identity = f"{held.st_dev}:{held.st_ino}"
    helper = (ROOT / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    start = helper.index("backlog_lock_healthy() {")
    function = helper[start: helper.index("\n}\n", start) + 3]
    result = subprocess.run(
        ["bash", "-c", function + "backlog_lock_healthy && echo healthy || echo lost\n"],
        env={**os.environ, "LOCK_PID": str(pid), "LOCK_READY": str(ready), "LOCK_PATH": str(lock),
             "LOCK_IDENTITY": identity},
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def test_lock_health_reads_a_stopped_holder_and_a_replaced_lock_file_as_lost(tmp_path: Path):
    """Review round 7: a stopped holder keeps its flock but cannot notice the
    lock path being replaced, and a replaced lock file leaves the flock on the
    old inode. Each alone must read as lost."""
    ready = tmp_path / "ready"
    ready.write_text("locked pid=0 dev=0 ino=0\n", encoding="utf-8")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        lock = tmp_path / "lock"
        lock.touch()
        held = lock.stat()
        identity = f"{held.st_dev}:{held.st_ino}"
        assert _lock_health(holder.pid, ready, lock, identity) == "healthy"  # positive control
        replacement = tmp_path / "replacement"
        replacement.touch()
        os.replace(replacement, lock)
        assert lock.stat().st_ino != held.st_ino
        assert _lock_health(holder.pid, ready, lock, identity) == "lost"
        fresh = lock.stat()
        identity = f"{fresh.st_dev}:{fresh.st_ino}"
        assert _lock_health(holder.pid, ready, lock, identity) == "healthy"
        os.kill(holder.pid, signal.SIGSTOP)
        deadline = time.monotonic() + 10
        while not subprocess.run(["ps", "-o", "stat=", "-p", str(holder.pid)], capture_output=True,
                                 text=True).stdout.strip().startswith("T"):
            assert time.monotonic() < deadline, "the probe never stopped"
            time.sleep(0.02)
        assert _lock_health(holder.pid, ready, lock, identity) == "lost"
    finally:
        holder.kill()
        holder.wait()


def test_lock_health_reads_an_unreaped_zombie_holder_as_lost(tmp_path: Path):
    """A holder that died but was not yet reaped is a zombie: `kill -0` still
    succeeds on it, yet it no longer holds the flock. The health check must
    read it as lost. (In the harness bash reaps the killed holder before the
    check, so only this test reaches the zombie case.)"""
    ready = tmp_path / "ready"
    ready.write_text("locked pid=0\n", encoding="utf-8")
    zombie = subprocess.Popen([sys.executable, "-c", "pass"])
    alive = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        deadline = time.monotonic() + 10
        while not subprocess.run(["ps", "-o", "stat=", "-p", str(zombie.pid)], capture_output=True,
                                 text=True).stdout.strip().startswith("Z"):
            assert time.monotonic() < deadline, "the probe child never became a zombie"
            time.sleep(0.02)
        assert subprocess.run(["kill", "-0", str(zombie.pid)]).returncode == 0  # why kill -0 is not enough
        assert _lock_health(alive.pid, ready) == "healthy"  # positive control
        assert _lock_health(zombie.pid, ready) == "lost"
        ready.write_text("lost lock path changed while held\n", encoding="utf-8")
        assert _lock_health(alive.pid, ready) == "lost"
    finally:
        alive.kill()
        alive.wait()
        zombie.wait()


@pytest.mark.parametrize(
    "planted",
    ['gh api -X PATCH "repos/{owner}/{repo}/pulls/$PR" -f state=closed >/dev/null 2>&1 || true; ',
     'gh api "repos/{owner}/{repo}/issues/$PR/comments" -f body=x >/dev/null 2>&1 || true; ',
     'gh pr comment "$PR" --body x >/dev/null 2>&1 || true; ',
     # Attached flag values (review round 6): each escaped the first classifier.
     'gh api --method=PATCH "repos/{owner}/{repo}/pulls/$PR" >/dev/null 2>&1 || true; ',
     'gh api -XDELETE "repos/{owner}/{repo}/git/refs/heads/x" >/dev/null 2>&1 || true; ',
     'gh api -fbody=x "repos/{owner}/{repo}/issues/$PR/comments" >/dev/null 2>&1 || true; ',
     'gh api --input=request.json "repos/{owner}/{repo}/issues/$PR/comments" >/dev/null 2>&1 || true; ',
     'gh api "repos/{owner}/{repo}/issues/$PR/comments" --raw-field=body=x >/dev/null 2>&1 || true; '],
)
def test_a_dry_run_that_mutates_anything_is_caught(tmp_path: Path, planted: str):
    """Teeth for the zero-mutation rule: a dry run that sends any mutating gh
    call (an explicit PATCH, gh api's implicit POST when given fields, a PR
    comment) is named, although it never calls the merge endpoint."""
    needle = 'if [ "$DRY_RUN" -eq 1 ]; then echo'
    helper = _mutated_helper(tmp_path, needle, 'if [ "$DRY_RUN" -eq 1 ]; then ' + planted + "echo")
    dry = next(s for s in harness.SCENARIOS if s.dry_run)
    run, failures = harness.run_scenario(dry, tmp_path / "world", helper=helper)
    assert run.rc == 0 and not run.puts, run.err
    assert any("mutating gh calls besides the pinned merge PUTs" in failure for failure in failures), failures


@pytest.mark.parametrize(
    ("call", "mutating"),
    [(["pr", "view", "7", "--json", "state"], False), (["pr", "checks", "7"], False),
     (["api", "-H", "Accept: application/vnd.github.raw", "repos/o/r/contents/BACKLOG.md"], False),
     (["api", "-X", "GET", "repos/o/r/pulls", "-f", "state=open"], False),
     (["api", "-X", "PUT", "repos/o/r/pulls/7/merge"], True), (["api", "repos/o/r/issues/7/comments", "-f", "body=x"], True),
     (["api", "--method", "delete", "repos/o/r/git/refs/heads/x"], True), (["pr", "merge", "7"], True),
     (["pr", "comment", "7"], True), (["pr", "edit", "7"], True), (["repo", "view"], True),
     # attached values and implicit POST bodies
     (["api", "--method=PATCH", "repos/o/r/pulls/7"], True), (["api", "-XDELETE", "repos/o/r/git/refs/heads/x"], True),
     (["api", "-fbody=x", "repos/o/r/issues/7/comments"], True), (["api", "--input=req.json", "repos/o/r/x"], True),
     (["api", "--input", "req.json", "repos/o/r/x"], True), (["api", "repos/o/r/x", "--raw-field=body=x"], True),
     (["api", "--field=body=x", "repos/o/r/x"], True), (["api", "-X=GET", "repos/o/r/x"], False),
     (["api", "--method=GET", "repos/o/r/x"], False),
     (["api", "-HAccept: x", "repos/o/r/x"], False), (["api", "--paginate", "repos/o/r/x"], False),
     # forms the parser does not model are writes
     (["api", "--some-new-flag", "repos/o/r/x"], True), (["api", "repos/o/r/x", "extra"], True), (["api", "-X"], True)],
)
def test_mutating_call_classifier_is_fail_closed(call: list, mutating: bool):
    assert harness.is_mutating(call) is mutating


def test_replace_precondition_fools_plain_git_but_not_no_replace_git(tmp_path: Path):
    """The substitution scenario proves something only if plain git in the
    clone really serves the substitute, and only GIT_NO_REPLACE_OBJECTS undoes it."""
    world = harness.build_world(tmp_path / "w", candidate_ids=(1, 2, 3, 5))
    substitute = harness.substitute_candidate_backlog(world)
    spec = f"{world.head}:BACKLOG.md"
    plain = subprocess.run(["git", "cat-file", "blob", spec], cwd=world.work, env=world.env,
                           capture_output=True, text=True, check=True).stdout
    off = subprocess.run(["git", "cat-file", "blob", spec], cwd=world.work,
                         env={**world.env, "GIT_NO_REPLACE_OBJECTS": "1"},
                         capture_output=True, text=True, check=True).stdout
    assert plain == substitute
    assert off == harness.backlog(1, 2, 3, 5)
    trees = {
        subprocess.run(["git", "rev-parse", f"{world.head}^{{tree}}"], cwd=world.work, env=env,
                       capture_output=True, text=True, check=True).stdout
        for env in (world.env, {**world.env, "GIT_NO_REPLACE_OBJECTS": "1"})
    }
    assert len(trees) == 1, "a blob replacement must leave the tree oid unchanged, or the tree proof would catch it"


def test_graft_precondition_survives_git_no_replace_objects(tmp_path: Path):
    """Why the helper refuses a graft file instead of relying on the variable:
    git still applies grafts with GIT_NO_REPLACE_OBJECTS set."""
    world = harness.build_world(tmp_path / "w", variant="behind")
    harness.graft_head_onto_main(world)
    probe = subprocess.run(
        ["git", "merge-base", "--is-ancestor", world.main0, world.head], cwd=world.work,
        env={**world.env, "GIT_NO_REPLACE_OBJECTS": "1"}, capture_output=True, check=False,
    )
    assert probe.returncode == 0


@pytest.mark.parametrize(
    ("scenario_name", "needle", "replacement", "lands"),
    [
        ("replaced_candidate_blob_refused", "export GIT_NO_REPLACE_OBJECTS=1\n", "\n", True),
        ("grafted_behind_head_refused_before_api",
         '[ ! -e "$graft_file" ] && [ ! -L "$graft_file" ] || refuse', "true || refuse", False),
    ],
)
def test_dropping_an_object_substitution_defence_reaches_the_merge_endpoint(
    tmp_path: Path, scenario_name: str, needle: str, replacement: str, lands: bool
):
    """Teeth for the two substitution scenarios: without the defence the helper
    validates substituted objects and calls the merge endpoint. For the blob,
    GitHub merges the real (gapped) bytes and the helper calls it proven."""
    helper = _mutated_helper(tmp_path, needle, replacement)
    scenario = next(s for s in harness.SCENARIOS if s.name == scenario_name)
    run, failures = harness.run_scenario(scenario, tmp_path / "world", helper=helper)
    assert "merge endpoint called 1x, expected 0x" in failures, failures
    if lands:
        assert run.rc == 0 and run.state["state"] == "MERGED" and "MERGED via the PR API" in run.out, run.err


def test_origin_in_the_harness_declines_a_direct_push_to_main(tmp_path: Path):
    """The world reproduces production's refusal of the retired design."""
    world = harness.build_world(tmp_path / "w")
    result = subprocess.run(
        ["git", "push", "origin", f"{world.head}:refs/heads/main"],
        cwd=world.work, env=world.env, capture_output=True, text=True, check=False,
    )
    assert result.returncode and "protected branch hook declined" in result.stderr


# ── The wiring tripwire (scripts/verify_b315_dense_id_allocation.py) ─────────


def test_wiring_holds_on_the_real_gate_and_helper():
    assert verifier.wiring_problems(_gate_and_helper()) == []


@pytest.mark.parametrize(
    ("planted", "named"),
    [
        ('git push --atomic --force-with-lease="refs/heads/main:$m" origin "$c:refs/heads/main"',
         "direct push to main"),
        ('git push origin "$merge_oid:main"', "direct push to main"),
        ("gh pr merge \"$PR\" --squash --match-head-commit \"$H\"", "obsolete: gh pr merge"),
        ('merge_oid="$(git commit-tree "$head_tree" -p "$b" -p "$h")"', 'obsolete: commit-tree "$head_tree"'),
        ("gh api -X DELETE repos/x/y/git/refs/heads/corelink-backlog-id-merge-lock", "unconditional lease DELETE"),
    ],
)
def test_wiring_names_a_planted_retired_design(planted: str, named: str):
    problems = verifier.wiring_problems(_gate_and_helper() + "\n" + planted + "\n")
    assert any(named in problem for problem in problems), problems


@pytest.mark.parametrize(
    "removed",
    [' -f sha="$CAPTURED_HEAD"', "MERGE_METHOD=squash", 'git merge-base --is-ancestor "$CAPTURED_MAIN" "$CAPTURED_HEAD"',
     "export GIT_NO_REPLACE_OBJECTS=1", "git rev-parse --path-format=absolute --git-path info/grafts",
     '[ "$b_base_name" = main ] && [ "$b_base" = "$CAPTURED_MAIN" ]', '[ "$post_base" = main ] || wrong_base'],
)
def test_wiring_names_a_removed_guarantee(removed: str):
    text = _gate_and_helper()
    mutated = text.replace(removed, "")
    assert mutated != text, "the mutation did not apply"
    assert verifier.wiring_problems(mutated), "removing a guarantee left the wiring green"


def test_wiring_refuses_empty_text():
    assert verifier.wiring_problems("   \n") == ["gate + helper text is EMPTY: nothing to check"]


def _gate() -> str:
    return (ROOT / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8")


def test_gate_wrapper_has_one_dry_run_forwarding_call_site_and_no_merge_of_its_own():
    assert verifier.gate_problems(_gate()) == []


@pytest.mark.parametrize(
    ("planted", "named"),
    [
        ('gh api -X PUT "repos/{owner}/{repo}/pulls/$PR/merge" -f sha="$CAPTURED_HEAD"', "names its own merge call"),
        ('gh pr merge "$PR" --squash', "names its own merge call"),
        ("gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: $id}) { clientMutationId } }'",
         "names its own merge call"),
        ("gh api graphql -f query='mutation { enablePullRequestAutoMerge(input: {}) { clientMutationId } }'",
         "names its own merge call"),
        ('bash scripts/b315_atomic_merge.sh "$PR" "$CAPTURED_HEAD" 0 "$CAPTURED_HEAD_REF" a b',
         "2 helper call sites"),
    ],
)
def test_gate_wrapper_check_names_a_planted_bypass(planted: str, named: str):
    problems = verifier.gate_problems(_gate() + "\n" + planted + "\n")
    assert any(named in problem for problem in problems), problems


def test_gate_wrapper_check_names_a_call_site_that_drops_dry_run():
    gate = _gate()
    mutated = gate.replace('"$CAPTURED_HEAD" "$DRY_RUN" "$CAPTURED_HEAD_REF"', '"$CAPTURED_HEAD" 0 "$CAPTURED_HEAD_REF"')
    assert mutated.count('"$CAPTURED_HEAD" 0 "$CAPTURED_HEAD_REF"') == 1, "the mutation did not apply exactly once"
    problems = verifier.gate_problems(mutated)
    assert any('does not forward "$DRY_RUN"' in problem for problem in problems), problems


def test_gate_wrapper_check_refuses_empty_text_and_a_missing_call_site():
    assert verifier.gate_problems(" \n") == ["gate wrapper text is EMPTY: nothing to check"]
    without = "\n".join(line for line in _gate().splitlines() if "bash scripts/b315_atomic_merge.sh" not in line)
    assert any("0 helper call sites" in problem for problem in verifier.gate_problems(without))


# ── Trust: the BASE-owned candidate gate must freeze the harness too ─────────
# The verifier's layer 4 is the harness's word. scripts/backlog_verify.py, run
# from BASE, refuses a PR that changes a trusted control, and it finds those
# controls by a static closure from each item's `verify` command. That closure
# follows `scripts.`-package imports and `spec_from_file_location` paths only,
# so a bare `import b315_merge_harness` left the harness outside it: a later PR
# could stub the harness's self_test and the verifier would report every
# scenario passed. Freezing the file is not enough either: a PR can ADD files
# that change how Python resolves the verifier's imports. The tests after the
# closure ones build throwaway checkouts that carry such files.

VERIFIER_CONTROL = "scripts/verify_b315_dense_id_allocation.py"
HARNESS_CONTROL = "scripts/b315_merge_harness.py"
SELF_TEST_SIGNATURE = "def self_test(root: Path, workers: int = 6) -> list[str]:\n"


def _trusted_items():
    from scripts import backlog_verify

    return backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))


def test_real_harness_is_a_trusted_backlog_control():
    from scripts import backlog_verify

    controls = backlog_verify._candidate_control_paths(ROOT, _trusted_items())
    assert VERIFIER_CONTROL in controls, "B-315's verify command no longer names its verifier"
    assert HARNESS_CONTROL in controls, "the BASE gate would not refuse a PR that edits the harness"


def _control_roots(tmp_path: Path):
    """BASE and candidate copies of every trusted control (plus the harness,
    named explicitly, so that a closure which misses it fails the assertion
    below rather than a file lookup)."""
    from scripts import backlog_verify

    items = _trusted_items()
    controls = backlog_verify._candidate_control_paths(ROOT, items) | {HARNESS_CONTROL}
    roots = []
    for name in ("trusted", "candidate"):
        root = tmp_path / name
        for relative in sorted(controls):
            source = ROOT / relative
            if source.is_file():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        roots.append(root)
    return roots[0], roots[1], items


def test_candidate_that_stubs_the_harness_self_test_is_refused_by_the_base_gate(tmp_path: Path):
    from scripts import backlog_verify

    trusted, candidate, items = _control_roots(tmp_path)
    # Positive control: identical copies are admitted, so the refusal below is
    # about the stub and not about the fixture.
    backlog_verify.check_candidate_controls(candidate, trusted, items)

    harness_file = candidate / HARNESS_CONTROL
    text = harness_file.read_text(encoding="utf-8")
    assert text.count(SELF_TEST_SIGNATURE) == 1, "the stub did not apply exactly once"
    harness_file.write_text(text.replace(SELF_TEST_SIGNATURE, SELF_TEST_SIGNATURE + "    return []\n"), encoding="utf-8")
    with pytest.raises(RuntimeError, match=re.escape(f"candidate mutated trusted backlog control {HARNESS_CONTROL}")):
        backlog_verify.check_candidate_controls(candidate, trusted, items)


VERIFIER_SOURCE = ROOT / VERIFIER_CONTROL
STUB_HARNESS = 'SCENARIOS = ("stub",)\n\n\ndef self_test(root, workers=6):\n    return [%r]\n'
PASS_LINE = "landing scenarios: PASS"


def _checkout(tmp_path: Path, *, harness_source: str | None = None, support: bool = True) -> Path:
    """A throwaway checkout holding a copy of the real verifier. With
    ``support`` it also carries the gate, the helper, the allocator and
    BACKLOG.md, so the verifier reaches layer 4; the harness is the real one
    unless ``harness_source`` is given."""
    root = tmp_path / "checkout"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(VERIFIER_SOURCE, root / VERIFIER_CONTROL)
    if support:
        # The allocator imports backlog_verify from its own directory.
        for relative in ("scripts/pre-merge-gate-check.sh", "scripts/b315_atomic_merge.sh",
                         "scripts/backlog_id_alloc.py", "scripts/backlog_verify.py", "BACKLOG.md"):
            shutil.copy2(ROOT / relative, root / relative)
        if harness_source is None:
            shutil.copy2(ROOT / HARNESS_CONTROL, root / HARNESS_CONTROL)
        else:
            (root / HARNESS_CONTROL).write_text(harness_source, encoding="utf-8")
    return root


def _run_verifier(root: Path, **env: str) -> subprocess.CompletedProcess:
    """The verifier run by a caller that does NOT start it isolated (B-315's
    declared command until review round 5), so these tests exercise the
    verifier's own re-exec backstop and its by-path harness load."""
    return subprocess.run(
        ["python3", VERIFIER_CONTROL, "--self-test"],
        cwd=root, env={**os.environ, **env}, capture_output=True, text=True, check=False, timeout=600,
    )


def _declared_verify_command() -> str:
    from scripts import backlog_verify

    items = backlog_verify.parse((ROOT / "BACKLOG.md").read_text(encoding="utf-8"))
    return next(item for item in items if item.raw.get("id") == "B-315").raw["verify"]


def test_declared_verify_command_starts_isolated_so_a_startup_sitecustomize_cannot_pass_it(tmp_path: Path):
    """Review round 5: the re-exec runs AFTER Python's startup, so with
    PYTHONPATH pointing into the checkout an added sitecustomize.py printed
    PASS and exited 0 before any verifier code ran. The declared command
    itself must start isolated. Executed the way backlog_verify.py runs it."""
    root = _checkout(tmp_path)
    (root / "sitecustomize.py").write_text(
        "import os\nprint('SITECUSTOMIZE: 99 " + PASS_LINE + "', flush=True)\nos._exit(0)\n", encoding="utf-8"
    )
    env = {**os.environ, "PYTHONPATH": str(root)}

    def run(command: str) -> subprocess.CompletedProcess:
        return subprocess.run(["/bin/bash", "-o", "pipefail", "-c", command], cwd=root, env=env,
                              capture_output=True, text=True, check=False, timeout=600)

    # Positive control: the pre-round-5 command runs the planted hook and "passes".
    plain = run(f"python3 {VERIFIER_CONTROL} --self-test")
    assert plain.returncode == 0 and "SITECUSTOMIZE" in plain.stdout, plain.stdout + plain.stderr
    declared = _declared_verify_command()
    assert declared == f"python3 -I -S -B {VERIFIER_CONTROL} --self-test", declared
    result = run(declared)
    assert "SITECUSTOMIZE" not in result.stdout, result.stdout
    assert result.returncode == 2, result.stdout + result.stderr
    assert "sitecustomize.py would steer Python's import resolution" in result.stderr, result.stderr


def test_added_scripts_init_that_stubs_self_test_is_refused(tmp_path: Path):
    """The review reproduction (2026-10-02): a candidate ADDS scripts/__init__.py,
    which imports the real harness and replaces its self_test. With the harness
    imported through the `scripts` package, that initializer ran first,
    `__file__` stayed right, and the verifier printed PASS for every scenario."""
    root = _checkout(tmp_path)
    (root / "scripts/__init__.py").write_text(
        "from . import b315_merge_harness as _real\n_real.self_test = lambda root, workers=6: []\n",
        encoding="utf-8",
    )
    result = _run_verifier(root)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "scripts/__init__.py would steer Python's import resolution" in result.stderr, result.stderr
    assert PASS_LINE not in result.stdout


def test_shadowed_stdlib_module_in_scripts_never_runs(tmp_path: Path):
    """Run as a script, the verifier has scripts/ first on sys.path, so a
    candidate scripts/tempfile.py replaced the standard module before any check
    could run. The isolated re-exec takes scripts/ off the path first."""
    root = _checkout(tmp_path, support=False)
    (root / "scripts/tempfile.py").write_text(
        "import os\nprint('SHADOW RAN: 99 " + PASS_LINE + "', flush=True)\nos._exit(0)\n", encoding="utf-8"
    )
    result = _run_verifier(root)
    assert "SHADOW RAN" not in result.stdout, result.stdout
    # The real tempfile was imported; the verifier went on to its own refusal.
    assert result.returncode == 2 and "B-315 instrument broken: missing" in result.stderr, result.stderr


def test_shadow_scripts_package_on_pythonpath_is_never_loaded(tmp_path: Path):
    """A regular `scripts` package elsewhere on PYTHONPATH used to win over the
    namespace directory. The isolated re-exec ignores PYTHONPATH and the
    harness is loaded by path, so the tree file is what runs."""
    shadow = tmp_path / "shadow" / "scripts"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "b315_merge_harness.py").write_text(STUB_HARNESS % "shadow ran", encoding="utf-8")
    root = _checkout(tmp_path, harness_source=STUB_HARNESS % "tree harness ran")
    result = _run_verifier(root, PYTHONPATH=str(shadow.parent))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "tree harness ran" in result.stderr and "shadow ran" not in result.stderr, result.stderr
    assert PASS_LINE not in result.stdout


def test_unchecked_hash_pyc_cannot_replace_the_harness_source(tmp_path: Path, monkeypatch):
    """The default .py loader runs an unchecked-hash __pycache__ pyc instead of
    the source and reports the .py as its file. The verifier's loader compiles
    the source bytes, so a committed pyc next to the frozen harness is inert."""
    import importlib.util
    import py_compile

    target = tmp_path / "scripts" / "b315_merge_harness.py"
    target.parent.mkdir()
    target.write_text(STUB_HARNESS % "cache ran", encoding="utf-8")
    py_compile.compile(str(target), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    target.write_text(STUB_HARNESS % "source ran", encoding="utf-8")
    # Positive control: the planted pyc really fools the default loader.
    spec = importlib.util.spec_from_file_location("b315_pyc_probe", target)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    assert probe.self_test(tmp_path) == ["cache ran"]
    assert probe.self_test.__code__.co_filename == str(target)
    monkeypatch.setattr(verifier, "HARNESS", target)
    assert verifier.load_trusted_harness().self_test(tmp_path) == ["source ran"]


def test_harness_identity_check_names_a_rebound_self_test(tmp_path: Path, monkeypatch):
    target = tmp_path / "b315_merge_harness.py"
    monkeypatch.setattr(verifier, "HARNESS", target)
    target.write_text(STUB_HARNESS % "real", encoding="utf-8")
    assert verifier.load_trusted_harness().self_test(tmp_path) == ["real"]  # positive control
    target.write_text(
        STUB_HARNESS % "real" + "\n\ndef _stub(root, workers=6):\n    return []\n\n\nself_test = _stub\n",
        encoding="utf-8",
    )
    with pytest.raises(verifier.HarnessTrustError, match="self_test is not the function its source defines"):
        verifier.load_trusted_harness()


@pytest.mark.parametrize(
    "relative",
    ["scripts/__init__.py", "scripts/__init__.pyc", "scripts/sitecustomize.py", "scripts/usercustomize.py",
     "sitecustomize.py", "usercustomize.py", "scripts/paths.pth", "extra.pth", "scripts/sitecustomize"],
)
def test_import_surface_names_each_steering_file(tmp_path: Path, relative: str):
    (tmp_path / "scripts").mkdir()
    assert verifier.import_surface_problems(tmp_path) == []  # positive control
    target = tmp_path / relative
    if relative.endswith("customize"):
        target.mkdir()  # a package of that name steers imports as well as a module
    else:
        target.write_text("", encoding="utf-8")
    assert verifier.import_surface_problems(tmp_path) == [
        f"{relative} would steer Python's import resolution; BASE has no such file"
    ]


def test_import_surface_ignores_look_alike_names_and_the_real_checkout(tmp_path: Path):
    (tmp_path / "scripts").mkdir()
    for relative in ("scripts/__init__helper.py", "scripts/sitecustomize_notes.md", "README.pthx", "scripts/init.py"):
        (tmp_path / relative).write_text("", encoding="utf-8")
    assert verifier.import_surface_problems(tmp_path) == []
    assert verifier.import_surface_problems(ROOT) == []


# ── The gate wrapper (scripts/pre-merge-gate-check.sh) ──────────────────────


def test_gate_header_states_the_real_required_checks():
    """Pins the dated 2026-10-01 read of main's protection, which the header
    quotes. GitHub is the oracle and cannot be read hermetically, so this is a
    copy: when protection changes, re-read it and update header and test."""
    gate = (ROOT / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8")
    header = gate[: gate.index("set -euo pipefail")]
    assert "Branch protection has `required checks = []`" not in header
    assert "exactly TWO checks" not in header
    for fact in (
        "FOUR required checks",
        "`dco`",
        "`cargo fmt --all --check`",
        "`gitleaks detect`",
        "`CHANGELOG.md updated when feat/fix present`",
        "strict",
        "enforce_admins",
        "linear history",
        "branches/main/protection",
    ):
        assert fact in header, fact


# The wrapper itself is EXECUTED here: harness.run_wrapper runs the real
# scripts/pre-merge-gate-check.sh from a throwaway world's clone, with the same
# fake gh (which also answers the wrapper's pr view -q/--jq and pr checks).


def _world_with(tmp_path: Path, inject: dict):
    world = harness.build_world(tmp_path / "world")
    state = json.loads(world.state.read_text(encoding="utf-8"))
    state["inject"] = inject
    world.state.write_text(json.dumps(state), encoding="utf-8")
    return world


def test_wrapper_dry_run_makes_no_mutating_call(tmp_path: Path):
    world = _world_with(tmp_path, {})
    run = harness.run_wrapper(world, "--merge", "--dry-run", str(harness.PR))
    assert run.rc == 0, run.out + run.err
    assert "All gates green" in run.out and "merge endpoint NOT called" in run.out, run.out + run.err
    assert run.mutations == [], run.mutations
    assert run.pushes == "" and run.lease == "" and run.state["state"] == "OPEN"
    assert run.main == world.main0


def _unproven_wrapper_failures(run, helper_rc: int, marker: str) -> list[str]:
    failures = []
    if run.rc != 3:
        failures.append(f"wrapper exit {run.rc}, expected 3")
    if "UNPROVEN" not in run.out or f"merge helper exited {helper_rc}" not in run.out:
        failures.append("wrapper did not report the merge as UNPROVEN with the helper's exit")
    if "PR #7 merged." in run.out:
        failures.append("wrapper reported a clean merge")
    if marker not in run.err:
        failures.append(f"helper marker {marker!r} missing")
    if run.mutations != run.puts or len(run.puts) != 1:
        failures.append(f"wrapper made mutating calls besides the one merge PUT: {run.mutations}")
    return failures


UNPROVEN_LANDINGS = [
    ({"put": ["land_wrong_tree"]}, 3, "tree mismatch"),
    ({"put": ["drop_merge_response"]}, 3, "merge_response_not_success"),
    ({"put": ["retarget_base"]}, 4, "merged_into_unexpected_base"),
    ({"put": ["same_tree_head_merged_by_other"]}, 5, "merged_by_other_actor"),
]


@pytest.mark.parametrize(("inject", "helper_rc", "marker"), UNPROVEN_LANDINGS,
                         ids=[marker for _, _, marker in UNPROVEN_LANDINGS])
def test_wrapper_reports_a_merged_but_unproven_landing_as_exit_3(tmp_path: Path, inject: dict, helper_rc: int,
                                                                   marker: str):
    run = harness.run_wrapper(_world_with(tmp_path, inject), "--merge", str(harness.PR))
    assert run.state["state"] == "MERGED", run.err
    assert _unproven_wrapper_failures(run, helper_rc, marker) == [], run.out + run.err


def test_a_wrapper_that_calls_an_unproven_landing_clean_is_caught(tmp_path: Path):
    """Teeth: with the MERGED-but-helper-failed branch disabled, the wrapper
    reports a clean merge (and goes on to record lanes and delete the branch)."""
    gate = (ROOT / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8")
    needle = 'if [ "$merge_rc" -ne 0 ]; then\n  echo "  ⛔ PR #$PR IS MERGED'
    assert gate.count(needle) == 1
    mutant = tmp_path / "pre-merge-gate-check.sh"
    mutant.write_text(gate.replace(needle, 'if false; then\n  echo "  ⛔ PR #$PR IS MERGED'), encoding="utf-8")
    run = harness.run_wrapper(_world_with(tmp_path, {"put": ["land_wrong_tree"]}), "--merge", str(harness.PR),
                              wrapper=mutant)
    failures = _unproven_wrapper_failures(run, 3, "tree mismatch")
    assert "wrapper exit 0, expected 3" in failures and "wrapper reported a clean merge" in failures, failures


@pytest.mark.parametrize("mutation", ["--squash", "--match-head-commit", "gh pr merge", "--atomic"])
def test_obsolete_merge_mutations_are_absent(mutation: str):
    assert mutation not in _gate_and_helper()


def test_head_force_push_after_checks_cannot_replace_expected_h1():
    root = Path(__file__).resolve().parents[1]
    gate = (root / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8")
    assert 'bash scripts/b315_atomic_merge.sh "$PR" "$CAPTURED_HEAD"' in gate
    checked_to_helper = gate[gate.index('checked_head='): gate.index('bash scripts/b315_atomic_merge.sh')]
    assert 'GATED_SHA="$(gh pr view' not in checked_to_helper
    helper = (root / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    assert 'EXPECTED_HEAD=${2:?captured head required}' in helper
    assert '[ "$bk_head" = "$EXPECTED_HEAD" ]' in helper


def test_backlog_verify_commands_cannot_recurse_on_their_own_record():
    from scripts import backlog_verify

    text = (Path(__file__).resolve().parents[1] / "BACKLOG.md").read_text(encoding="utf-8")
    for item in backlog_verify.parse(text):
        record_id = item.raw.get("id")
        verify = item.raw.get("verify")
        if isinstance(record_id, str) and isinstance(verify, str):
            assert f"backlog_verify.py --id {record_id}" not in verify


# B-1630 is the one historical external-issue identity (backlog_verify owns the
# table). It sits outside the dense allocator sequence; nothing else may.
def test_historical_alias_is_outside_the_dense_sequence():
    main = _backlog(1, 2, 1630)
    assert allocation(main, main, base_text=main) == ()
    assert allocation(main, _backlog(1, 2, 3, 1630), base_text=main) == (3,)


def test_historical_alias_does_not_move_the_next_allocation():
    main = _backlog(1, 2, 1630)
    for candidate in (_backlog(1, 2, 1630, 1631), _backlog(1, 2, 4, 1630)):
        with pytest.raises(AllocationError, match="gaps"):
            allocation(main, candidate, base_text=main)


def test_historical_alias_cannot_disappear():
    with pytest.raises(AllocationError, match="removed"):
        allocation(_backlog(1, 2, 1630), _backlog(1, 2), base_text=_backlog(1, 2, 1630))


def test_historical_alias_cannot_be_minted_by_a_candidate():
    base = _backlog(1, 2)
    with pytest.raises(AllocationError, match="historical alias cannot be allocated"):
        allocation(base, _backlog(1, 2, 1630), base_text=base)


@pytest.mark.parametrize("ids", [(1, 3, 1630), (1, 2, 1629), (1, 2, 1631)])
def test_every_other_gap_stays_fatal(ids: tuple[int, ...]):
    with pytest.raises(AllocationError, match="gaps"):
        allocation(_backlog(*ids), _backlog(*ids))


def test_real_main_backlog_allocates_cleanly():
    text = (Path(__file__).resolve().parents[1] / "BACKLOG.md").read_text(encoding="utf-8")
    assert allocation(text, text, base_text=text) == ()
