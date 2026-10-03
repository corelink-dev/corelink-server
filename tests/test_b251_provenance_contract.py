from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "collect_b251_provenance", ROOT / "scripts/collect_b251_provenance.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_static_contract() -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_b251_provenance_contract", ROOT / "scripts/verify_b251_provenance_contract.py"
    )
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.verify(ROOT)


CONTRACT_FILES = (
    ".github/workflows/b251-d03-read-only-probe.yml",
    "scripts/collect_b251_provenance.py",
    "crates/corelink-billing/tests/b251_identity_operation.rs",
    "scripts/run_b251_latency_probe.py",
)
SAME_REPOSITORY_LINE = "          repository: ${{ github.repository }}\n"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_b251_provenance_contract", ROOT / "scripts/verify_b251_provenance_contract.py"
    )
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def _candidate_copy(tmp_path: Path) -> Path:
    for relative in CONTRACT_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    return tmp_path


def _candidate_with_workflow(tmp_path: Path, old: str, new: str, count: int) -> Path:
    _candidate_copy(tmp_path)
    workflow = tmp_path / CONTRACT_FILES[0]
    text = workflow.read_text(encoding="utf-8")
    # Prove the mutation lands before trusting a red result.
    assert text.count(old) == 2
    mutated = text.replace(old, new, count)
    assert mutated != text
    workflow.write_text(mutated, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "label, replacement, count",
    [
        ("old owner", "          repository: HuGR-dev/corelink-server\n", 1),
        ("older owner", "          repository: HuGR-Labs/corelink-server\n", 1),
        ("new owner literal", "          repository: corelink-dev/corelink-server\n", 1),
        ("both checkouts", "          repository: HuGR-dev/corelink-server\n", 2),
        ("comment-masked", "          # repository: ${{ github.repository }}\n          repository: HuGR-dev/corelink-server\n", 1),
        ("line removed", "", 1),
    ],
)
def test_d02_checkout_must_fetch_from_the_running_repository(
    tmp_path: Path, label: str, replacement: str, count: int
) -> None:
    verifier = _load_verifier()
    candidate = _candidate_with_workflow(tmp_path, SAME_REPOSITORY_LINE, replacement, count)
    with pytest.raises(ValueError, match="repository"):
        verifier.verify(candidate)


def test_unmutated_candidate_copy_passes(tmp_path: Path) -> None:
    # Positive control: the copy harness itself does not make verify() fail.
    verifier = _load_verifier()
    verifier.verify(_candidate_copy(tmp_path))


def test_mutated_identity_is_rejected_without_values() -> None:
    original = {"seed": "a" * 64, "failure": "b" * 64, "blob": "c" * 64}
    mutated = {**original, "blob": "d" * 64}
    with pytest.raises(MODULE.CollectionError, match="blob") as raised:
        MODULE.compare(original, mutated)
    assert "c" * 64 not in str(raised.value)
    assert "d" * 64 not in str(raised.value)


def test_d02_revision_is_an_immutable_producer_contract() -> None:
    assert MODULE.D02_COMMIT == "f88c6ca41868f6a02e78ba9f4357d3abf67da4be"
    assert len(MODULE.D02_COMMIT) == 40


def test_run_operation_accepts_adapter_already_at_destination(tmp_path: Path, monkeypatch) -> None:
    operation = tmp_path / MODULE.OPERATION
    operation.parent.mkdir(parents=True)
    operation.write_text("checked-in adapter\n", encoding="utf-8")
    output = (
        f"{MODULE.COUNT}1000\n"
        f"{MODULE.FAILURES}\n"
        f"{MODULE.MARKER}00\n"
    )

    def completed_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(MODULE.subprocess, "run", completed_run)
    identity = MODULE.run_operation(tmp_path, operation)

    assert set(identity) == {"seed", "failure", "blob"}
    assert operation.read_text(encoding="utf-8") == "checked-in adapter\n"


def test_collector_and_adapter_share_a_fixed_reproducible_operation_seed() -> None:
    operation = (ROOT / MODULE.OPERATION).read_text(encoding="utf-8")

    assert f'const OPERATION_SEED_HEX: &str = "{MODULE.OPERATION_SEED_HEX}";' in operation
