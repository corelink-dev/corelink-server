"""Negative controls for the prelaunch B-170 evidence boundary."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_b170_owner_actions as verifier  # noqa: E402


def _packet() -> str:
    return (ROOT / verifier.PACKET).read_text(encoding="utf-8")


def test_frozen_no_customer_no_circulation_contract_is_accepted() -> None:
    fields = verifier.validate_packet(_packet())
    assert fields["customers"] == "none"
    assert fields["questionnaire_circulation"] == "none"
    assert fields["pagerduty"] == "excluded; deferred"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("Lifecycle", "launched", "lifecycle contradicts"),
        ("Customers", "one", "customers contradicts"),
        ("Questionnaire circulation", "sent", "questionnaire_circulation contradicts"),
        ("Customer notice", "sent", "customer_notice contradicts"),
        ("PagerDuty", "active", "pagerduty contradicts"),
        ("D1 topology", "tenant-pinned", "d1_topology contradicts"),
        ("D1 claim", "tenant-pinned D1", "d1_claim contradicts"),
        ("Object Lock claim", "available seven-year Object Lock", "object_lock_claim contradicts"),
        ("BYOK claim", "available five-minute BYOK", "byok_claim contradicts"),
    ],
)
def test_contradictory_or_unsupported_claim_is_rejected(
    field: str, value: str, message: str
) -> None:
    packet = _packet().replace(
        next(line for line in _packet().splitlines() if line.startswith(f"- **{field}:") ),
        f"- **{field}:** {value}",
    )
    with pytest.raises(verifier.PacketError, match=message):
        verifier.validate_packet(packet)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("D1 receipt", "pending", "not the accepted terminal #1654 receipt"),
        ("B154 source reference", "https://github.com/HuGR-dev/corelink-server/pull/9999", "B-154 input does not match frozen b154_source_reference"),
        ("D1 source revision", "ca6a", "stale or does not match merged #1654 source"),
        ("B154 source date", "unknown", "merged B-154 source date must be an ISO date"),
    ],
)
def test_missing_or_placeholder_source_reference_is_rejected(
    field: str, value: str, message: str
) -> None:
    packet = _packet().replace(
        next(line for line in _packet().splitlines() if line.startswith(f"- **{field}:") ),
        f"- **{field}:** {value}",
    )
    with pytest.raises(verifier.PacketError, match=message):
        verifier.validate_packet(packet)


def test_duplicate_fields_are_rejected() -> None:
    with pytest.raises(verifier.PacketError, match="duplicate packet field"):
        verifier.validate_packet(_packet() + "\n- **Customers:** none\n")


def test_missing_fact_is_rejected() -> None:
    with pytest.raises(verifier.PacketError, match="missing packet field: pagerduty"):
        verifier.validate_packet("\n".join(line for line in _packet().splitlines() if "**PagerDuty:" not in line))


def test_current_contract_keeps_unproven_capabilities_limited() -> None:
    fields = verifier.validate_packet(_packet())
    assert fields["object_lock_claim"] == "limited"
    assert fields["object_lock_boundary"] == (
        "seven-year unavailable/not promised; one-day synthetic proof only"
    )
    assert fields["byok_claim"] == "limited"
    assert fields["byok_boundary"] == "unavailable; no kill-switch SLO"


def _current_contract_packet() -> str:
    return _packet()


def test_canonical_packet_binds_merged_2597_source_and_pending_followups() -> None:
    fields = verifier.validate_packet(_current_contract_packet())
    result = verifier.verify(ROOT)
    assert fields["b154_state"] == "merged source; provider follow-ups pending"
    assert fields["b154_source_reference"] == "https://github.com/HuGR-dev/corelink-server/pull/2807"
    assert fields["object_lock_boundary"].startswith("seven-year unavailable")
    assert fields["byok_boundary"] == "unavailable; no kill-switch SLO"
    assert result["status"] == "source_admitted_provider_followups_pending"
    assert result["source_inputs_admitted"] is True
    assert result["closure_ready"] is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("D1 receipt", "https://github.com/HuGR-dev/corelink-server/issues/1654#issuecomment-1", "not the accepted terminal #1654 receipt"),
        ("D1 source revision", "a" * 40, "stale or does not match merged #1654 source"),
        ("Object Lock boundary", "available for seven years", "Object Lock boundary overstates"),
        ("BYOK boundary", "p99 under five minutes", "BYOK boundary overstates"),
        ("B154 source reference", "https://github.com/HuGR-dev/corelink-server/pull/9999", "B-154 input does not match frozen b154_source_reference"),
        ("B154 source revision", "a" * 40, "B-154 input does not match frozen b154_source_revision"),
        ("B154 source date", "2026-09-29", "B-154 input does not match frozen b154_source_date"),
        ("B154 provider followups", "#1646/#1653 available", "provider follow-ups do not match frozen source outcomes"),
    ],
)
def test_merged_source_rejects_stale_or_fabricated_inputs(
    field: str, value: str, message: str
) -> None:
    packet = _current_contract_packet().replace(
        next(line for line in _current_contract_packet().splitlines() if line.startswith(f"- **{field}:")),
        f"- **{field}:** {value}",
    )
    with pytest.raises(verifier.PacketError, match=message):
        verifier.validate_packet(packet)


def test_b154_admission_state_cannot_be_omitted() -> None:
    packet = "\n".join(
        line for line in _packet().splitlines() if "**B154 state:**" not in line
    )
    with pytest.raises(verifier.PacketError, match="missing packet field: b154_state"):
        verifier.validate_packet(packet)


def test_canonical_packet_symlink_is_rejected(tmp_path: Path) -> None:
    destination = tmp_path / verifier.PACKET
    destination.parent.mkdir(parents=True)
    target = tmp_path / "packet-copy.md"
    target.write_text(_packet(), encoding="utf-8")
    destination.symlink_to(target)
    with pytest.raises(verifier.PacketError, match="path contains a symlink"):
        verifier.verify(tmp_path)


def test_canonical_packet_parent_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    packet = outside / "b170-prelaunch-reconciliation.md"
    packet.write_text(_packet(), encoding="utf-8")
    (tmp_path / "reports").symlink_to(outside, target_is_directory=True)
    with pytest.raises(verifier.PacketError, match="path contains a symlink"):
        verifier.verify(tmp_path)


def test_merged_source_admits_truthful_open_provider_followups_without_fake_receipts() -> None:
    fields = verifier.validate_packet(_packet())
    assert fields["b154_source_reference"] == "https://github.com/HuGR-dev/corelink-server/pull/2807"
    assert fields["b154_source_revision"] == "f2ab5d43b1f7a5dc691f30e0cae419155b4643c5"
    assert fields["b154_source_date"] == "2026-09-30"
    assert fields["b154_provider_followups"] == (
        "#1646 Object Lock availability pending; "
        "#1653/#2165 BYOK lifecycle and p99 pending"
    )
    assert "b154_receipt" not in fields


def test_merged_source_rejects_provider_followup_overclaim() -> None:
    packet = _current_contract_packet().replace(
        "#1646 Object Lock availability pending; #1653/#2165 BYOK lifecycle and p99 pending",
        "#1646 and #1653 provider outcomes terminal and available",
    )
    with pytest.raises(verifier.PacketError, match="provider follow-ups do not match frozen source outcomes"):
        verifier.validate_packet(packet)
