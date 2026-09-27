from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_b314_gdpr_sigstore as verify


def _text(path: str) -> str:
    return (verify.ROOT / path).read_text(encoding="utf-8")


def test_done_baseline_and_mutations_pass() -> None:
    verify.verify()
    assert verify.mutation_checks() == 24


def test_wrapped_scoped_posture_is_not_a_false_negative() -> None:
    source = _text(verify.TRUST)
    wrapped = source.replace("no customer-data path is wired", "no customer-data path is\n  wired", 1)
    assert "no customer-data path is wired" not in wrapped
    verify.verify(overrides={verify.TRUST: wrapped})


@pytest.mark.parametrize("path", verify.LOCALES)
def test_every_locale_has_only_the_signed_recipient_row(path: str) -> None:
    source = _text(path)
    assert verify.CANONICAL_ROW in source.splitlines()
    assert "PagerDuty / GitHub / Sigstore" not in source
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={path: source.replace(verify.CANONICAL_ROW, verify.PRE_DECISION_ROW, 1)})


def test_decision_evidence_must_match_signed_receipt() -> None:
    evidence = _text(verify.EVIDENCE)
    mutated = evidence.replace("issuecomment-5854794010", "issuecomment-1", 1)
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={verify.EVIDENCE: mutated})


def test_packet_duplicate_key_is_rejected() -> None:
    source = _text(verify.PACKET)
    mutated = source.replace('"status": "decision-applied",', '"status": "decision-applied",\n  "status": "decision-applied",', 1)
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={verify.PACKET: mutated})


@pytest.mark.parametrize("path", (verify.LEGAL_REGISTER, verify.VENDOR_REGISTER))
def test_register_posture_is_load_bearing(path: str) -> None:
    source = _text(path)
    marker = "not a customer-data sub-processor" if path == verify.LEGAL_REGISTER else "no customer-data path is wired"
    mutated = source.replace(marker, "customer-data path is wired", 1)
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={path: mutated})


def test_missing_target_and_unknown_override_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(verify.VerificationError):
        verify.verify(root=tmp_path)
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={"unknown": ""})


def test_workflow_requires_exact_head_path_admission_and_redaction() -> None:
    source = _text(verify.WORKFLOW)
    for needle in (verify.CHECKOUT_ACTION, "pull_request:", "github.event.pull_request.head.sha", "expected_paths = [", "PRIVATE KEY", "chr(64)", "line[1:]", "lowercase_email_fixture", "pytest_decorator_fixture"):
        assert needle in source
    mutated = source.replace("github.event.pull_request.head.sha", "github.event.pull_request.base.sha", 1)
    with pytest.raises(verify.VerificationError):
        verify.verify(overrides={verify.WORKFLOW: mutated})
