from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_b316_pending_vendor_reviews as verifier  # noqa: E402


@pytest.fixture()
def texts() -> dict[str, str]:
    return verifier.load()


def test_canonical_population_is_truthfully_open(texts: dict[str, str]):
    assert verifier.assess(texts) == "open"


def test_target_population_is_exactly_the_approved_eight():
    assert verifier.REQUIRED_COMMITMENT_IDS == (
        "cloudflare", "clerk", "resend", "stripe", "github", "sentry",
        "plausible", "betterstack",
    )
    assert "neon" not in verifier.REQUIRED_COMMITMENT_IDS
    assert "pagerduty" not in verifier.REQUIRED_COMMITMENT_IDS


@pytest.mark.parametrize(
    "ids",
    [
        ("cloudflare", "clerk", "resend", "stripe", "github", "sentry", "plausible"),
        (*verifier.REQUIRED_COMMITMENT_IDS, "pagerduty"),
        (*verifier.REQUIRED_COMMITMENT_IDS, "neon"),
    ],
)
def test_completed_disclosure_population_rejects_missing_or_extra_vendor(ids):
    with pytest.raises(verifier.ReviewError, match="not the exact approved eight"):
        verifier._require_approved_population(list(ids), "completed legal disclosure")


@pytest.mark.parametrize("extra", ["rogue", ["rogue"]])
def test_completed_disclosure_rejects_non_mapping_extra_entries(extra):
    entries = [{"id": vendor_id} for vendor_id in verifier.REQUIRED_COMMITMENT_IDS]
    entries.append(extra)
    with pytest.raises(verifier.ReviewError, match="is not a mapping"):
        verifier._processor_ids(entries)


def test_completed_disclosure_rejects_duplicate_ids():
    entries = [{"id": vendor_id} for vendor_id in verifier.REQUIRED_COMMITMENT_IDS]
    entries.append({"id": verifier.REQUIRED_COMMITMENT_IDS[0]})
    with pytest.raises(verifier.ReviewError, match="duplicate sub-processor ids"):
        verifier._processor_ids(entries)


def test_completed_resend_cannot_coexist_with_pending_vendor_reviews(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    artifact = verifier.VENDORS[0].artifact
    document = changed[artifact].replace(verifier.TEMPLATE_BANNER, "", 1)
    document = document.replace("`TBD (YYYY-MM-DD)`", "`2026-09-30`", 2)
    document = document.replace("`TBD (named Legal Counsel / Privacy Officer)`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD (signed copy pending — VR-6)`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD (confirm flow-down per GDPR Art. 28(4))`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD`", "`SYNTHETIC FIXTURE`")
    document = document.replace("`TBD (approved / approved-with-conditions / rejected)`", "`SYNTHETIC FIXTURE`", 1)
    changed[artifact] = document
    changed[verifier.LEGAL] = changed[verifier.LEGAL].replace(
        "contract_signed_at: null", 'contract_signed_at: "2026-09-30"', 1
    )
    changed[verifier.REGISTER] = changed[verifier.REGISTER].replace(
        "| Legal | 2026-09-23 | Open |", "| Legal | 2026-09-23 | Closed |", 1
    )
    with pytest.raises(verifier.ReviewError, match="cannot mix completed vendor reviews"):
        verifier.assess(changed)


def test_completed_review_rejects_impossible_calendar_date(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    artifact = verifier.VENDORS[0].artifact
    document = changed[artifact].replace(verifier.TEMPLATE_BANNER, "", 1)
    document = document.replace("`TBD (YYYY-MM-DD)`", "`2026-09-30`", 2)
    document = document.replace("`TBD (named Legal Counsel / Privacy Officer)`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD (signed copy pending — VR-6)`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD (confirm flow-down per GDPR Art. 28(4))`", "`SYNTHETIC FIXTURE`", 1)
    document = document.replace("`TBD`", "`SYNTHETIC FIXTURE`")
    document = document.replace("`TBD (approved / approved-with-conditions / rejected)`", "`SYNTHETIC FIXTURE`", 1)
    changed[artifact] = document
    changed[verifier.LEGAL] = changed[verifier.LEGAL].replace(
        "contract_signed_at: null", 'contract_signed_at: "2026-99-99"', 1
    )
    changed[verifier.REGISTER] = changed[verifier.REGISTER].replace(
        "| Legal | 2026-09-23 | Open |", "| Legal | 2026-09-23 | Closed |", 1
    )
    with pytest.raises(verifier.ReviewError, match="mixed pending/completed"):
        verifier.assess(changed)


def test_mutation_suite_has_teeth(texts: dict[str, str]):
    verifier.mutation_self_test(texts)


def test_template_cannot_be_present_with_a_claimed_signature(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.LEGAL] = changed[verifier.LEGAL].replace(
        "contract_signed_at: null", 'contract_signed_at: "2026-09-06"', 1
    )
    with pytest.raises(verifier.ReviewError, match="mixed pending/completed"):
        verifier.assess(changed)


def test_closed_risk_action_cannot_coexist_with_pending_packet(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.REGISTER] = changed[verifier.REGISTER].replace(
        "| Legal | 2026-09-23 | Open |", "| Legal | 2026-09-23 | Closed |", 1
    )
    with pytest.raises(verifier.ReviewError, match="mixed pending/completed"):
        verifier.assess(changed)


def test_action_packet_population_is_closed(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    packet = json.loads(changed[verifier.ACTION_PACKET])
    packet["vendors"]["extra"] = packet["vendors"]["resend"]
    changed[verifier.ACTION_PACKET] = json.dumps(packet)
    with pytest.raises(verifier.ReviewError, match="population is not exact"):
        verifier.assess(changed)


def test_action_packet_cannot_reintroduce_deferred_pagerduty(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    packet = json.loads(changed[verifier.ACTION_PACKET])
    packet["effective_legal_text"]["required_active_ids"].insert(5, "pagerduty")
    changed[verifier.ACTION_PACKET] = json.dumps(packet)
    with pytest.raises(verifier.ReviewError, match="pending effective-legal-text"):
        verifier.assess(changed)


def test_commitments_reject_deferred_pagerduty_as_an_extra(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.COMMITMENTS] = changed[verifier.COMMITMENTS].replace(
        "### 1.4 Neon, Inc. *(optional / tenant-selectable Postgres)*",
        "### 1.4 PagerDuty, Inc.",
        1,
    )
    with pytest.raises(verifier.ReviewError, match="neither the recorded residue"):
        verifier.assess(changed)


def test_action_packet_authority_must_remain_legal(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    packet = json.loads(changed[verifier.ACTION_PACKET])
    packet["authority"] = "Automated"
    changed[verifier.ACTION_PACKET] = json.dumps(packet)
    with pytest.raises(verifier.ReviewError, match="authority drifted"):
        verifier.assess(changed)


@pytest.mark.parametrize("index", range(len(verifier.EXPECTED_NON_CLAIMS)))
def test_each_action_packet_non_claim_is_bound(texts: dict[str, str], index: int):
    changed = copy.deepcopy(texts)
    packet = json.loads(changed[verifier.ACTION_PACKET])
    packet["non_claims"][index] = f"Drifted non-claim {index + 1}."
    changed[verifier.ACTION_PACKET] = json.dumps(packet)
    with pytest.raises(verifier.ReviewError, match="non-claims drifted"):
        verifier.assess(changed)


def test_evidence_path_must_be_exact(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.LEGAL] = changed[verifier.LEGAL].replace(
        verifier.VENDORS[0].artifact,
        "docs/compliance/vendor-reviews/resend-dpa-review-latest.md",
        1,
    )
    with pytest.raises(verifier.ReviewError, match="evidence path drifted"):
        verifier.assess(changed)
