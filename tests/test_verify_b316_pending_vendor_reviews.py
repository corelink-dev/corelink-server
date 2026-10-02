from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_b316_pending_vendor_reviews as verifier  # noqa: E402

GITHUB_DPA = "https://github.com/customer-terms/github-data-protection-agreement"
RESEND_DPA = "https://resend.com/legal/dpa"


@pytest.fixture()
def texts() -> dict[str, str]:
    return verifier.load()


def _pending_everywhere(texts: dict[str, str], url: str) -> dict[str, str]:
    changed = copy.deepcopy(texts)
    verifier._replace_link_everywhere(url)(changed)
    packet = json.loads(changed[verifier.PACKET])
    packet["status"] = "pending_links"
    changed[verifier.PACKET] = json.dumps(packet)
    return changed


def test_canonical_tree_is_done(texts: dict[str, str]):
    assert verifier.assess(texts) == "done"


def test_approved_population_is_exactly_the_eight():
    assert verifier.APPROVED == (
        "cloudflare", "clerk", "resend", "stripe", "github", "sentry", "plausible", "betterstack",
    )
    assert set(verifier.EXCLUDED) == {"pagerduty", "neon"}
    assert not set(verifier.APPROVED) & set(verifier.EXCLUDED)


def test_every_surface_is_read(texts: dict[str, str]):
    # A surface the gate does not load is a surface it cannot protect.
    for path in (*verifier.TRUST_PAGES, *verifier.EXPLANATION_PAGES, verifier.ADMIN_JSON,
                 verifier.ADMIN_TS, verifier.DOCS_LEGAL_PAGE, verifier.DOCS_REGISTER_PAGE,
                 verifier.LEGAL, verifier.COMMITMENTS, verifier.REGISTER, verifier.GENERATOR):
        assert path in texts
    assert len(verifier.TRUST_PAGES) == 4 and len(verifier.EXPLANATION_PAGES) == 4


@pytest.mark.parametrize("name", [name for name, _ in verifier.MUTATIONS])
def test_each_mutation_is_rejected(texts: dict[str, str], name: str):
    mutate = dict(verifier.MUTATIONS)[name]
    changed = copy.deepcopy(texts)
    mutate(changed)
    assert changed != texts, "mutation did not change anything"
    with pytest.raises(verifier.ReviewError):
        verifier.assess(changed)


@pytest.mark.parametrize("path", [verifier.TRUST_EN, verifier.LEGAL, verifier.ADMIN_JSON, verifier.COMMITMENTS])
@pytest.mark.parametrize("vendor", ["PagerDuty", "Neon", "pagerduty"])
def test_excluded_vendor_name_anywhere_fails(texts: dict[str, str], path: str, vendor: str):
    changed = copy.deepcopy(texts)
    changed[path] = changed[path] + f"\n{vendor}\n"
    with pytest.raises(verifier.ReviewError, match="names excluded vendor"):
        verifier.assess(changed)


def test_register_cannot_reactivate_pagerduty(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.GENERATOR] = changed[verifier.GENERATOR].replace(
        '"PagerDuty, Inc.": "Deferred by the owner', '"Retired": "Deferred by the owner', 1
    )
    with pytest.raises(verifier.ReviewError):
        verifier.assess(changed)


def test_register_must_record_the_deferral(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.REGISTER] = changed[verifier.REGISTER].replace(
        "| PagerDuty, Inc. | 9 | Deferred by the owner", "| PagerDuty, Inc. | 9 | Paused by", 1
    )
    with pytest.raises(verifier.ReviewError, match="deferred exactly once"):
        verifier.assess(changed)


@pytest.mark.parametrize("path", verifier.TRUST_PAGES + verifier.EXPLANATION_PAGES)
def test_missing_dpa_link_on_any_page_fails(texts: dict[str, str], path: str):
    changed = copy.deepcopy(texts)
    changed[path] = changed[path].replace(f"[DPA]({RESEND_DPA})", "", 1)
    assert changed[path] != texts[path]
    with pytest.raises(verifier.ReviewError):
        verifier.assess(changed)


def test_missing_terms_link_in_register_fails(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.LEGAL] = changed[verifier.LEGAL].replace(
        '    terms_url: "https://plausible.io/terms"\n', "", 1
    )
    with pytest.raises(verifier.ReviewError, match="lacks a terms_url or dpa_url"):
        verifier.assess(changed)


def test_surfaces_that_disagree_fail(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    changed[verifier.EXPLANATION_PAGES[0]] = changed[verifier.EXPLANATION_PAGES[0]].replace(
        "[Terms](https://stripe.com/legal/ssa)", "[Terms](https://stripe.com/legal)", 1
    )
    with pytest.raises(verifier.ReviewError, match="stripe terms link"):
        verifier.assess(changed)


def test_consistent_link_pending_is_open_not_done(texts: dict[str, str]):
    assert verifier.assess(_pending_everywhere(texts, GITHUB_DPA)) == "open"


def test_link_pending_for_a_vr_vendor_reopens_its_action(texts: dict[str, str]):
    changed = _pending_everywhere(texts, RESEND_DPA)
    with pytest.raises(verifier.ReviewError, match="VR-6 must be Owner/Open"):
        verifier.assess(changed)
    changed[verifier.REGISTER] = changed[verifier.REGISTER].replace(
        "| Owner | 2026-09-23 | Closed |", "| Owner | 2026-09-23 | Open |", 1
    )
    assert verifier.assess(changed) == "open"


def test_acceptance_date_in_packet_fails(texts: dict[str, str]):
    changed = copy.deepcopy(texts)
    packet = json.loads(changed[verifier.PACKET])
    packet["vendors"]["stripe"]["online_acceptance_date"] = "2026-04-23"
    changed[verifier.PACKET] = json.dumps(packet)
    with pytest.raises(verifier.ReviewError, match="acceptance date"):
        verifier.assess(changed)


def test_generator_refuses_an_active_vendor_without_links(texts: dict[str, str]):
    generator = verifier._generator(texts[verifier.GENERATOR])
    rows, updated = generator.parse_register(texts[verifier.REGISTER])
    generator.PUBLIC_LEGAL_LINKS.pop("Clerk, Inc.")
    with pytest.raises(generator.MissingLegalLinks):
        generator.render_mdx(rows, updated)


def test_generator_renders_link_pending_as_text(texts: dict[str, str]):
    generator = verifier._generator(texts[verifier.GENERATOR])
    generator.PUBLIC_LEGAL_LINKS["Clerk, Inc."] = ("https://clerk.com/legal/standard-terms", "link pending")
    assert generator.legal_links("Clerk, Inc.") == ("[Terms](https://clerk.com/legal/standard-terms)", "link pending")
    generator.PUBLIC_LEGAL_LINKS["Clerk, Inc."] = ("https://clerk.com/legal/standard-terms", "http://clerk.com/dpa")
    with pytest.raises(generator.MissingLegalLinks):
        generator.legal_links("Clerk, Inc.")


def test_mutation_suite_has_teeth(texts: dict[str, str]):
    assert verifier.mutation_self_test(texts) == len(verifier.MUTATIONS) >= 20


def test_cli_reports_done_and_rejects_wrong_expectation():
    script = ROOT / "scripts" / "verify_b316_pending_vendor_reviews.py"
    done = subprocess.run([sys.executable, str(script), "--expect", "done"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("B-316 done: vendors=8")
    wrong = subprocess.run([sys.executable, str(script), "--expect", "open"], capture_output=True, text=True)
    assert wrong.returncode == 1
