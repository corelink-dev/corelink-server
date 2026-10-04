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


def _b154_backlog_record() -> dict:
    import yaml

    backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
    section = backlog.split("### B-154 —", 1)[1].split("### B-155 —", 1)[0]
    block = section.split("```backlog\n", 1)[1].split("```", 1)[0]
    record = yaml.safe_load(block)
    assert record["id"] == "B-154"
    return record


def test_backlog_b154_is_done_with_a_conjunctive_regression_guard() -> None:
    record = _b154_backlog_record()
    assert record["status"] == "done"
    assert record["owner"] == "tl"
    # The policy-pinned conjunction: a packet failure cannot be masked by the
    # exit status of the claims check that follows it.
    assert record["verify"] == (
        "python3 -S scripts/verify_owner_action_packets.py --id B-154 &&\n"
        "python3 -S scripts/verify_b154_instrument_claims.py --self-test\n"
    )
    assert record["verify-means"].lstrip().lower().startswith("done")


def _resolution() -> dict:
    return json.loads((ROOT / MODULE.RESOLUTION).read_text(encoding="utf-8"))


def _resolution_with(tmp_path: Path, record: dict) -> Path:
    """Copy every input verify_prelaunch_resolution reads, with a mutated resolution."""
    for relative in (
        MODULE.RESOLUTION, MODULE.B086_RESOLUTION, MODULE.WRANGLER, MODULE.B046_ACCEPTED_TARGET,
        *MODULE.PUBLIC_COPY_PATHS,
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    (tmp_path / MODULE.RESOLUTION).write_text(json.dumps(record), encoding="utf-8")
    return tmp_path


def test_terminal_resolution_copy_is_accepted(tmp_path: Path) -> None:
    MODULE.verify_prelaunch_resolution(_resolution_with(tmp_path, _resolution()))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(status="OPEN_PENDING_OBJECT_LOCK_BYOK_PROVIDER_EVIDENCE_AND_COUNSEL_REVIEW"),
        lambda r: r.update(provider_chains_closed=True),
        lambda r: r.pop("terminal_outcomes"),
        lambda r: r["terminal_outcomes"]["object_lock"].update(launch_claim="AVAILABLE"),
        lambda r: r["terminal_outcomes"]["object_lock"].update(merge_commit="0" * 40),
        lambda r: r["terminal_outcomes"]["byok_kill_switch"].update(outcome="CAPABILITY_PROVEN"),
        lambda r: r["terminal_outcomes"]["byok_kill_switch"].update(
            owner_decision="https://github.com/HuGR-dev/corelink-server/issues/1676#issuecomment-1"
        ),
        lambda r: r["terminal_outcomes"].update(nonclaims="Seven-year retention is established."),
        lambda r: r["claims"]["byok_kill_switch"].update(capability_status="PROVEN"),
    ],
    ids=[
        "status-reverted-open", "chains-claimed-closed", "outcomes-removed", "object-lock-promoted",
        "merge-commit-swapped", "byok-promoted", "owner-decision-swapped", "nonclaims-weakened",
        "byok-capability-promoted",
    ],
)
def test_terminal_resolution_mutations_fail_closed(tmp_path: Path, mutate) -> None:
    record = _resolution()
    mutate(record)
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_prelaunch_resolution(_resolution_with(tmp_path, record))


def test_terminal_outcome_rejects_changed_accepted_target_bytes(tmp_path: Path) -> None:
    root = _resolution_with(tmp_path, _resolution())
    accepted = root / MODULE.B046_ACCEPTED_TARGET
    accepted.write_bytes(accepted.read_bytes() + b"\n")
    with pytest.raises(MODULE.VerificationError, match="accepted target bytes"):
        MODULE.verify_prelaunch_resolution(root)


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


def test_byok_docs_page_states_unavailable_service_and_pending_review() -> None:
    page = (ROOT / MODULE.BYOK_DOCS).read_text(encoding="utf-8")
    matrix = (ROOT / MODULE.BYOK_MATRIX).read_text(encoding="utf-8")
    MODULE.verify_byok_docs_page(page)
    MODULE.verify_byok_matrix_scope(matrix)


@pytest.mark.parametrize(
    "positive_claim",
    [
        "CoreLink Enterprise tenants can supply their own root key.",
        "BYOK is available on the Enterprise tier.",
        "| AWS KMS | FIPS 140-3 | Available |",
        "Key revocation works within one DEK cache TTL (≤ 60s).",
        "BYOK kill-switch p99 ≤ 5 min is guaranteed.",
    ],
)
def test_byok_draft_banner_cannot_hide_positive_service_claim(positive_claim: str) -> None:
    page = (ROOT / MODULE.BYOK_DOCS).read_text(encoding="utf-8")
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_byok_docs_page(page + "\n" + positive_claim + "\n")


def test_provider_module_certificate_cannot_imply_corelink_availability() -> None:
    matrix = (ROOT / MODULE.BYOK_MATRIX).read_text(encoding="utf-8")
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_byok_matrix_scope(
            matrix.replace("Provider-module scope, not CoreLink feature availability.", "AWS KMS is available for all CoreLink customers.")
        )


def _capability_sources() -> tuple[dict, dict, str]:
    return (
        json.loads((ROOT / MODULE.B083_RECEIPT).read_text(encoding="utf-8")),
        json.loads((ROOT / MODULE.B046_PROBE).read_text(encoding="utf-8")),
        (ROOT / MODULE.DOCKERFILE).read_text(encoding="utf-8"),
    )


def test_current_capability_boundary_ships_no_kms_provider() -> None:
    byok, probe, dockerfile = _capability_sources()
    MODULE.verify_capability_state(byok, probe, dockerfile)
    assert "ARG CORELINK_BYOK_PROVIDER_FEATURE=\n" in dockerfile
    assert "--features byok-aws-real" not in dockerfile


@pytest.mark.parametrize(
    "mutant", ["byok", "object_lock", "armed_default", "literal_feature", "switch_removed"]
)
def test_capability_evidence_drift_fails_closed(mutant: str) -> None:
    byok, probe, dockerfile = _capability_sources()
    if mutant == "byok":
        byok = copy.deepcopy(byok)
        byok["evidence_state"] = "VERIFIED"
    elif mutant == "object_lock":
        probe = copy.deepcopy(probe)
        probe["classification"] = "SUPPORTED"
    elif mutant == "armed_default":
        dockerfile = dockerfile.replace(
            "ARG CORELINK_BYOK_PROVIDER_FEATURE=\n",
            "ARG CORELINK_BYOK_PROVIDER_FEATURE=byok-aws-real\n",
            1,
        )
    elif mutant == "literal_feature":
        dockerfile = dockerfile.replace(
            "--bin corelink-server \\\n", "--bin corelink-server --features byok-aws-real \\\n", 1
        )
    else:
        dockerfile = dockerfile.replace(
            "${CORELINK_BYOK_PROVIDER_FEATURE:+--features $CORELINK_BYOK_PROVIDER_FEATURE};", ";", 1
        )
        dockerfile += (
            "\n# cargo build -p corelink-server --bin corelink-server "
            "${CORELINK_BYOK_PROVIDER_FEATURE:+--features $CORELINK_BYOK_PROVIDER_FEATURE};\n"
        )
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


def _b086_inputs() -> tuple[dict, str]:
    b086 = json.loads((ROOT / MODULE.B086_RESOLUTION).read_text(encoding="utf-8"))
    wrangler = (ROOT / MODULE.WRANGLER).read_text(encoding="utf-8")
    return b086, wrangler


def test_b154_binding_does_not_decay_on_the_wall_clock_but_b086_still_does() -> None:
    b086, wrangler = _b086_inputs()
    aged = copy.deepcopy(b086)
    aged["provider_readback"]["captured_at"] = "2000-01-01T00:00:00Z"
    aged["deployed_active_readback"]["captured_at"] = "2000-01-01T00:00:00Z"
    # The binding call B-154 uses has no wall-clock window...
    MODULE.verify_readback_record(aged, wrangler, max_age=None)
    # ...while B-086's default gate keeps its 24-hour freshness window.
    with pytest.raises(MODULE.B086VerificationError, match="24-hour limit"):
        MODULE.verify_readback_record(aged, wrangler)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["provider_readback"].update(captured_at="2999-01-01T00:00:00Z"),
        lambda value: value["deployed_active_readback"].update(captured_at="2026-09-30T14:37:23"),
        lambda value: value["provider_readback"].update(physical_location_conclusion="PHYSICAL_LOCATION_GUARANTEED"),
        lambda value: value["deployed_active_readback"]["active_workers"][0].update(
            CONFIG_DB_database_id="00000000-0000-4000-8000-000000000000"
        ),
    ],
    ids=["future-dated", "timezone-naive", "physical-location-inferred", "wrong-active-binding"],
)
def test_b154_binding_still_rejects_b086_content_drift(mutate) -> None:
    b086, wrangler = _b086_inputs()
    mutated = copy.deepcopy(b086)
    mutate(mutated)
    with pytest.raises(MODULE.B086VerificationError):
        MODULE.verify_readback_record(mutated, wrangler, max_age=None)


def test_b154_resolution_uses_the_hash_bound_no_window_call(monkeypatch) -> None:
    seen: list[object] = []
    real = MODULE.verify_readback_record

    def spy(record, wrangler_text, **kwargs):
        seen.append(kwargs.get("max_age", "default"))
        return real(record, wrangler_text, **kwargs)

    monkeypatch.setattr(MODULE, "verify_readback_record", spy)
    MODULE.verify_prelaunch_resolution(ROOT)
    assert seen == [None]


def test_b154_resolution_rejects_a_b086_receipt_that_is_not_hash_pinned(tmp_path, monkeypatch) -> None:
    b086, _ = _b086_inputs()
    rebound = copy.deepcopy(b086)
    rebound["provider_readback"]["captured_at"] = "2000-01-01T00:00:00Z"
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes
    target = (ROOT / MODULE.B086_RESOLUTION).resolve()
    replacement = json.dumps(rebound)

    def read_text(self, *args, **kwargs):
        return replacement if self.resolve() == target else original_read_text(self, *args, **kwargs)

    def read_bytes(self):
        return replacement.encode("utf-8") if self.resolve() == target else original_read_bytes(self)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_prelaunch_resolution(ROOT)
