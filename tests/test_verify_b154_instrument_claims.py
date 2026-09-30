"""Focused tests for the B-154 active-Markdown claim guard."""

from __future__ import annotations

import importlib.util
import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_b154_instrument_claims.py"
SPEC = importlib.util.spec_from_file_location("verify_b154_instrument_claims", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _sources() -> tuple[str, str]:
    return (
        MODULE.DPA.read_text(encoding="utf-8"),
        MODULE.SLA.read_text(encoding="utf-8"),
    )


def test_backlog_b154_remains_open_until_root_reconciles_the_owner_row() -> None:
    backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
    section = backlog.split("### B-154 —", 1)[1].split("### B-155 —", 1)[0]
    assert "status: open" in section


def test_current_instruments_publish_only_explicit_prelaunch_limits() -> None:
    dpa, sla = _sources()
    assert MODULE.verify_texts(dpa, sla) == []
    assert "Object Lock COMPLIANCE retention" in dpa
    assert "not available or promised" in dpa
    assert "BYOK unavailable; no kill-switch SLO" in sla
    MODULE.verify_repository_state()


def test_all_localized_legal_copies_omit_positive_capability_claims() -> None:
    for name in (
        "legal/dpa/v1.0.0.en-US.md",
        "legal/dpa/v1.0.0.es-419.md",
        "legal/dpa/v1.0.0.pt-BR.md",
        "legal/privacy-notice/v1.0.0/en-US.md",
        "legal/privacy-notice/v1.0.0/es-MX.md",
        "legal/privacy-notice/v1.0.0/pt-BR.md",
        "docs/customer/byok-kill-switch.md",
        "docs/customer/gc-feature-overview.md",
    ):
        source = (ROOT / name).read_text(encoding="utf-8")
        if name != "docs/customer/byok-kill-switch.md":
            assert "Object Lock" in source
        assert not MODULE.scan_claims(source, MODULE.DPA)
        assert not MODULE.scan_claims(source, MODULE.SLA)


def _capability_sources() -> tuple[dict, dict, str]:
    return (
        json.loads((ROOT / MODULE.B083_RECEIPT).read_text(encoding="utf-8")),
        json.loads((ROOT / MODULE.B046_PROBE).read_text(encoding="utf-8")),
        (ROOT / MODULE.DOCKERFILE).read_text(encoding="utf-8"),
    )


def test_current_capability_boundary_is_not_an_unconditional_501_claim() -> None:
    byok, probe, dockerfile = _capability_sources()
    MODULE.verify_capability_state(byok, probe, dockerfile)
    assert "--features byok-aws-real" in dockerfile


@pytest.mark.parametrize("mutant", ["byok", "object_lock", "dockerfile"])
def test_capability_evidence_drift_fails_closed(mutant: str) -> None:
    byok, probe, dockerfile = _capability_sources()
    if mutant == "byok":
        byok = copy.deepcopy(byok)
        byok["evidence_state"] = "VERIFIED"
    elif mutant == "object_lock":
        probe = copy.deepcopy(probe)
        probe["classification"] = "SUPPORTED"
    else:
        dockerfile = dockerfile.replace("--features byok-aws-real;", "--features byok-no-real-provider;", 1)
        dockerfile += "\n# cargo build -p corelink-server --bin corelink-server --features byok-aws-real;\n"
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_capability_state(byok, probe, dockerfile)


@pytest.mark.parametrize(
    ("dpa_mutation", "sla_mutation"),
    [
        ("immutable R2 with retention metadata", "BYOK kill-switch p99 ≤ 5 min"),
        ("immutable R2 with Object Lock", "BYOK activation is unavailable"),
        ("## Object Lock\nR2 retention is not configured.", "BYOK kill-switch p99 ≤ 5 min"),
        ("R2 does not implement Object Lock.", "BYOK kill-switch is not available."),
        ("No immutable R2 with Object Lock is guaranteed.", "BYOK kill-switch p99 ≤ 5 min"),
        ("immutable R2 with Object Lock", "BYOK kill-switch p99 ≤ 5 min is not guaranteed."),
    ],
)
def test_claim_removal_or_negative_status_fails_closed(
    dpa_mutation: str, sla_mutation: str
) -> None:
    dpa, sla = _sources()
    if dpa_mutation != "immutable R2 with Object Lock":
        dpa = dpa_mutation
    if sla_mutation != "BYOK kill-switch p99 ≤ 5 min":
        sla = sla_mutation
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_texts(dpa, sla)


def test_markdown_emphasis_is_not_a_claim_evasion() -> None:
    dpa, sla = _sources()
    plain_dpa = dpa.replace("**Object Lock**", "Object Lock")
    plain_sla = sla.replace("**BYOK**", "BYOK")
    assert MODULE.verify_texts(plain_dpa, plain_sla) == []


def test_long_filler_cannot_hide_sentence_negation() -> None:
    _, sla = _sources()
    filler = "x" * 120
    dpa = f"No {filler} immutable R2 with Object Lock is guaranteed.\n"
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_texts(dpa, sla)


def test_wrapped_sentence_negation_cannot_hide_behind_a_line_break() -> None:
    _, sla = _sources()
    dpa = f"No {'x' * 120}\nimmutable R2 with Object Lock is guaranteed.\n"
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_texts(dpa, sla)


def test_sentence_scope_does_not_borrow_an_unrelated_prior_negation() -> None:
    _, sla = _sources()
    dpa, _ = _sources()
    dpa += "\nNo unrelated retention feature is guaranteed. Immutable R2 with Object Lock is active.\n"
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_texts(dpa, sla)
