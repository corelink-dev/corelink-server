from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from backlog_id_alloc import AllocationError, allocation  # noqa: E402


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/backlog_id_alloc.py"


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

    root = Path(__file__).resolve().parents[1]
    gate = (root / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8") + "\n" + (root / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    lock_section = gate[
        gate.index("start_backlog_allocation_lock"): gate.index("stop_backlog_allocation_lock")
    ]
    assert "TMPDIR" not in lock_section
    assert "CORELINK_BACKLOG_ALLOC_LOCK" not in lock_section


def test_gate_covers_head_base_main_boundary_and_temp_cleanup_fail_closed():
    root = Path(__file__).resolve().parents[1]
    gate = (root / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8") + "\n" + (root / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    for marker in (
        'baseRefName',
        '[ "$bk_base_name" = main ]',
        '[ "$CAPTURED_BASE" = "$CAPTURED_MAIN" ]',
        'REMOTE_LEASE_REF=refs/heads/corelink-backlog-id-merge-lock',
        '--atomic',
        '--force-with-lease="refs/heads/main:$main_sha_before"',
        '--force-with-lease="$HEAD_REF:$bk_head"',
        'neither ref changed',
        'no false merged claim',
        'main_sha_final',
        'head_oid',
        'backlog_lock_healthy',
        'rm -rf -- "$BACKLOG_TMP"',
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
    ):
        assert marker in gate
    for obsolete in ("--match-head-commit", "gh pr merge", "--squash"):
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


def test_atomic_merge_contract_has_hermetic_race_and_failure_controls():
    root = Path(__file__).resolve().parents[1]
    gate = (root / "scripts/pre-merge-gate-check.sh").read_text(encoding="utf-8") + "\n" + (root / "scripts/b315_atomic_merge.sh").read_text(encoding="utf-8")
    # These controls are intentionally source-level and hermetic: they can run
    # in CI without a GitHub token while still preventing a regression to the
    # old squash/CAS shape.
    controls = (
        "CAPTURED_HEAD",
        "CAPTURED_BASE",
        "CAPTURED_MAIN",
        "candidate force-pushed",
        "main moved at push boundary",
        "atomic main push rejected",
        "is not MERGED",
        "lacks a cryptographic signature",
        "merge commit lacks DCO",
        "merge parent mismatch",
        "merge tree mismatch",
        "refusing to break it automatically",
        "owner-safe release",
        "SIGKILL",
    )
    for marker in controls:
        assert marker in gate or marker == "SIGKILL"


@pytest.mark.parametrize("mutation", ["--squash", "--match-head-commit", "gh pr merge"])
def test_obsolete_merge_mutations_are_absent(mutation: str):
    gate = (Path(__file__).resolve().parents[1] / "scripts/pre-merge-gate-check.sh").read_text(
        encoding="utf-8"
    )
    assert mutation not in gate


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
