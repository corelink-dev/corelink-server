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


@pytest.fixture(scope="module")
def canonical() -> dict[str, str]:
    return verifier.load()


@pytest.fixture()
def texts(canonical: dict[str, str]) -> dict[str, str]:
    return copy.deepcopy(canonical)


def _status(texts: dict[str, str], status: str) -> None:
    verifier._edit_json(verifier.PACKET, lambda d: d.__setitem__("status", status))(texts)


def test_canonical_tree_is_done_with_no_blockers(texts: dict[str, str]):
    assert verifier.assess(texts) == "done"
    assert verifier.blockers(texts) == []


@pytest.mark.parametrize("path", [p for p in verifier.load() if p.endswith("explanation/privacy/gdpr.mdx")])
def test_gdpr_rows_carry_the_b314_github_only_row(texts: dict[str, str], path: str):
    assert verifier.B314_GDPR_ROW in texts[path].splitlines()
    texts[path] = texts[path].replace("| GitHub | US |", "| PagerDuty / GitHub | US |", 1)
    with pytest.raises(verifier.ReviewError, match="excluded-vendor mentions differ"):
        verifier.assess(texts)


def test_approved_population_is_exactly_the_eight():
    assert verifier.APPROVED == (
        "cloudflare", "clerk", "resend", "stripe", "github", "sentry", "plausible", "betterstack",
    )
    assert set(verifier.EXCLUDED) == {"pagerduty", "neon"}


def test_discovery_reads_the_published_trees(texts: dict[str, str]):
    published = verifier.published_paths(texts)
    assert len(published) > 1000
    for root in verifier.PUBLISHED_ROOTS:
        assert any(path.startswith(root + "/") for path in published), root
    assert "README.md" in published


@pytest.mark.parametrize("name", [name for name, _ in verifier.MUTATIONS])
def test_each_mutation_is_rejected(texts: dict[str, str], name: str):
    mutate = dict(verifier.MUTATIONS)[name]
    before = copy.deepcopy(texts)
    mutate(texts)
    assert texts != before, "mutation did not change anything"
    with pytest.raises(verifier.ReviewError):
        verifier.assess(texts)


@pytest.mark.parametrize(
    "spelling", ["PagerDuty", "Pager-Duty", "pager_duty", "Pager Duty", "Neon", "NEON-hosted"],
)
def test_excluded_vendor_spellings_on_a_parsed_surface_fail(texts: dict[str, str], spelling: str):
    verifier._append(verifier.LEGAL, f"Billing is also routed through {spelling}.")(texts)
    with pytest.raises(verifier.ReviewError, match="names an excluded vendor"):
        verifier.assess(texts)


def test_new_disclosure_surface_must_be_declared(texts: dict[str, str]):
    verifier._new_file(
        "marketing/sales/new-vendor-sheet.md",
        "# Sub-processors\n\nWe use Cloudflare, Resend, Sentry and Plausible.\n",
    )(texts)
    with pytest.raises(verifier.ReviewError, match="neither parsed nor declared"):
        verifier.assess(texts)


@pytest.mark.parametrize(
    "line",
    [
        "Resend contract signed and Legal approved on 2026-04-23.",
        "All DPAs effective 2026-04-23.",
        "Clerk DPA accepted on April 23, 2026.",
        "Contrato assinado em 23 de abril de 2026 (DPA).",
        "Stripe DPA countersigned by counsel.",
        "18/19 vendors have a signed DPA.",
        "We use 9 active sub-processors.",
        "Register a subprocessor-changes@ address in your tenant settings.",
    ],
)
def test_claim_lines_fail_on_a_parsed_surface(texts: dict[str, str], line: str):
    verifier._append(verifier.EXPLANATION_EN, line)(texts)
    verifier._append(verifier.EXPLANATION_LOCALE_PAGES[0], line)(texts)
    with pytest.raises(verifier.ReviewError, match="states "):
        verifier.assess(texts)


@pytest.mark.parametrize(
    "line",
    [
        "Signed commits and DCO protect the GitHub repository.",
        "No countersigned copy exists for Stripe.",
        "Stripe Elements tokenizes cards; the webhook payload is signed.",
        "GDPR Art. 28 sub-processor controls apply to Cloudflare.",
    ],
)
def test_benign_lines_on_a_declared_surface_pass(texts: dict[str, str], line: str):
    verifier._append("marketing/sales/FAQ-MASTER.md", line)(texts)
    assert verifier.assess(texts) == "done"


def test_register_columns_are_the_link_source(texts: dict[str, str]):
    generator = verifier._generator(texts[verifier.GENERATOR])
    assert not hasattr(generator, "PUBLIC_LEGAL_LINKS")
    rows, _ = generator.parse_register(texts[verifier.REGISTER])
    active = [row for row in rows if row.is_customer_data_processor]
    assert len(active) == 8
    assert all(row.terms.startswith("[Terms](https://") and row.dpa.startswith("[DPA](https://") for row in active)


def test_generator_refuses_an_active_vendor_without_links(texts: dict[str, str]):
    texts[verifier.REGISTER] = texts[verifier.REGISTER].replace("[DPA](https://clerk.com/legal/dpa)", "Clerk DPA (on request)", 1)
    generator = verifier._generator(texts[verifier.GENERATOR])
    rows, updated = generator.parse_register(texts[verifier.REGISTER])
    with pytest.raises(generator.MissingLegalLinks):
        generator.render_mdx(rows, updated)


def test_consistent_link_pending_is_an_open_blocker(texts: dict[str, str]):
    verifier._replace_link_everywhere(GITHUB_DPA)(texts)
    with pytest.raises(verifier.ReviewError, match="disagrees with derived open"):
        verifier.assess(texts)
    _status(texts, "pending")
    assert verifier.assess(texts) == "open"
    assert "github: link pending" in verifier.blockers(texts)


def test_link_pending_for_a_vr_vendor_reopens_its_action(texts: dict[str, str]):
    verifier._replace_link_everywhere(RESEND_DPA)(texts)
    _status(texts, "pending")
    with pytest.raises(verifier.ReviewError, match="VR-6 must be Owner/Open"):
        verifier.assess(texts)
    texts[verifier.REGISTER] = texts[verifier.REGISTER].replace(
        "| Owner | 2026-09-23 | Closed |", "| Owner | 2026-09-23 | Open |", 1
    )
    assert verifier.assess(texts) == "open"


def test_non_claims_are_bound_exactly(texts: dict[str, str]):
    verifier._edit_json(verifier.PACKET, lambda d: d["non_claims"].pop())(texts)
    with pytest.raises(verifier.ReviewError, match="non-claims"):
        verifier.assess(texts)


def test_render_contract_rejects_a_filtered_admin_table(texts: dict[str, str]):
    texts[verifier.ADMIN_TABLE] = texts[verifier.ADMIN_TABLE].replace(
        "{sorted.map((row) => (", '{sorted.filter((r) => r.id !== "github").map((row) => (', 1
    )
    with pytest.raises(verifier.ReviewError, match="render"):
        verifier.assess(texts)


def test_ledger_cannot_declare_a_new_pagerduty_disclosure(texts: dict[str, str]):
    path = "apps/docs/docs/trust/index.mdx"
    line = "PagerDuty receives incident metadata for every tenant."
    verifier._append(path, line)(texts)
    ledger = json.loads(texts[verifier.LEDGER])
    ledger["excluded_vendor_mentions"][path] = [{"category": "pending-b314-repin", "line": line}]
    texts[verifier.LEDGER] = json.dumps(ledger)
    with pytest.raises(verifier.ReviewError, match="unknown category"):
        verifier.assess(texts)


def test_mutation_suite_has_teeth(texts: dict[str, str]):
    assert verifier.mutation_self_test(texts) == len(verifier.MUTATIONS) >= 50


def test_cli_reports_done_and_rejects_wrong_expectation():
    script = ROOT / "scripts" / "verify_b316_pending_vendor_reviews.py"
    done = subprocess.run([sys.executable, str(script), "--expect", "done"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("B-316 done: vendors=8")
    assert "blockers=0" in done.stdout
    wrong = subprocess.run([sys.executable, str(script), "--expect", "open"], capture_output=True, text=True)
    assert wrong.returncode == 1
