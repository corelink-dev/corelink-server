#!/usr/bin/env python3
"""B-316 gate: one approved sub-processor set, linked to each vendor's own
terms and DPA, identical on every surface that lists sub-processors, with no
invented date or approval anywhere near it.

Re-chartered by the owner on 2026-10-01 (#2593): CoreLink is a single-owner
company, so B-316 closes on a public sub-processor list that names each vendor
in the approved set and links that vendor's standard terms and DPA, accepted
online at signup. Countersigned contracts and a named Legal reviewer are no
longer required. Dates are never invented.

What is checked, against the B-316 action packet (``PACKET``):

* Parsed surfaces — the legal register (frontmatter and table), the
  commitments, the vendor risk register's own Terms/DPA columns, the generated
  trust page (re-rendered and compared byte for byte) and its locale copies
  (compared to it through a declared delta), the explanation pages, the admin
  JSON and its TS mirror, the four VR records and the four 2026-04 records.
* Renderers — the three React components and their data path are pinned to
  the exact JSX that maps over the shared JSON, so a filtered list, an altered
  href or a hard-coded row fails.
* Discovery — every published file (docs, admin-ui source, legal, marketing,
  README) is read. A file that names a sub-processor term and three or more
  approved vendors must be a parsed surface or declared in the ledger
  (``LEDGER``); any line naming PagerDuty or Neon anywhere must be declared
  there, exactly, with a category.
* Claims — on parsed and declared surfaces, a line with a date and a
  contract/approval word, an approval or signature claim near a vendor, a
  sub-processor count other than eight, or an unshipped notice channel fails
  unless the exact line is declared in the ledger.

States (``--expect``): ``done`` when everything holds and nothing pending is
declared; ``open`` when the only remaining items are declared blockers (a
consistent "link pending", or a ledger line in a blocking category). Anything
else is an error (exit 2).
"""

from __future__ import annotations

import argparse
import copy
import difflib
import functools
import json
import os
import re
import sys
import types
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[1]

PACKET = "docs/handoff/2026-09-06-b316-vendor-legal-review.json"
LEDGER = "docs/handoff/2026-10-02-b316-surface-ledger.json"
LEGAL = "legal/sub-processors.md"
COMMITMENTS = "legal/dpa/SUB-PROCESSOR-COMMITMENTS.md"
REGISTER = "specs/_compliance/VENDOR-RISK-REGISTER.md"
GENERATOR = "scripts/gen-public-subprocessors.py"
LOCALES = ("de", "es-419", "pt-BR")
TRUST_EN = "apps/docs/docs/trust/subprocessors.mdx"
TRUST_LOCALE_PAGES = tuple(
    f"apps/docs/i18n/{loc}/docusaurus-plugin-content-docs/current/trust/subprocessors.mdx" for loc in LOCALES
)
TRUST_PAGES = (TRUST_EN, *TRUST_LOCALE_PAGES)
EXPLANATION_EN = "apps/docs/docs/explanation/compliance/sub-processors.mdx"
EXPLANATION_LOCALE_PAGES = tuple(
    f"apps/docs/i18n/{loc}/docusaurus-plugin-content-docs/current/explanation/compliance/sub-processors.mdx"
    for loc in LOCALES
)
EXPLANATION_PAGES = (EXPLANATION_EN, *EXPLANATION_LOCALE_PAGES)
ADMIN_JSON = "apps/admin-ui/src/content/sub-processors.json"
ADMIN_TS = "apps/admin-ui/src/content/sub-processors.ts"
ADMIN_LOAD = "apps/admin-ui/src/content/load.ts"
ADMIN_DIR = "apps/admin-ui/src/app/[locale]/privacy/sub-processors"
ADMIN_TABLE = f"{ADMIN_DIR}/SubProcessorsTable.tsx"
ADMIN_PAGE = f"{ADMIN_DIR}/SubProcessorsPage.tsx"
ADMIN_ROUTE = f"{ADMIN_DIR}/page.tsx"
DOCS_LEGAL_PAGE = "apps/docs/src/pages/legal/sub-processors.tsx"
DOCS_REGISTER_PAGE = "apps/docs/src/pages/trust/sub-processor-register.tsx"

APPROVED = ("cloudflare", "clerk", "resend", "stripe", "github", "sentry", "plausible", "betterstack")
EXCLUDED = ("pagerduty", "neon")
RISK_ACTIONS = {"resend": "VR-6", "sentry": "VR-7", "plausible": "VR-8", "betterstack": "VR-9"}
VR_RECORDS = {vid: f"docs/compliance/vendor-reviews/{vid}-dpa-review-2026-09.md" for vid in RISK_ACTIONS}
APRIL_RECORDS = {
    vid: f"docs/compliance/vendor-reviews/{vid}-dpa-review-2026-04.md"
    for vid in ("cloudflare", "clerk", "stripe", "github")
}
LINK_PENDING = "link pending"
RECORD_PATHS = frozenset((*VR_RECORDS.values(), *APRIL_RECORDS.values()))

# Every spelling a list uses for a vendor. A name outside this map on a vendor
# list is an error, so a new vendor cannot slip onto one list alone.
NAMES = {
    "Cloudflare, Inc.": "cloudflare",
    "Clerk, Inc.": "clerk",
    "Resend, Inc.": "resend",
    "Stripe, Inc.": "stripe",
    "GitHub, Inc.": "github",
    "GitHub, Inc. (Microsoft Enterprise)": "github",
    "Functional Software, Inc. (Sentry)": "sentry",
    "Plausible Insights OÜ (Plausible Analytics)": "plausible",
    "Better Stack, Inc. (BetterStack / Statuspage)": "betterstack",
    "PagerDuty, Inc.": "pagerduty",
    "Neon, Inc.": "neon",
    "Neon, Inc. *(optional / tenant-selectable Postgres)*": "neon",
}

# --- published-tree discovery ------------------------------------------------
PUBLISHED_ROOTS = ("apps/docs", "apps/admin-ui/src", "legal", "marketing")
PUBLISHED_FILES = ("README.md",)
PUBLISHED_EXTENSIONS = {
    ".md", ".mdx", ".tsx", ".ts", ".jsx", ".js", ".json", ".html", ".htm",
    ".yaml", ".yml", ".mjml", ".txt", ".csv",
}
SKIP_DIRS = {"node_modules", "build", "dist", ".docusaurus", ".wrangler", "tests", "__tests__", "coverage"}
SKIP_FILE_RE = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$")
EXCLUDED_WORD_RE = re.compile(r"pager[\s_-]*duty|\bneon\b", re.IGNORECASE)
SUBPROCESSOR_TERM_RE = re.compile(
    r"sub-?processor|subprocessad|subprocesad|sub-?encargad|unterauftragsverarbeiter|auftragsverarbeiter",
    re.IGNORECASE,
)
APPROVED_NAME_RES = {
    "cloudflare": re.compile(r"cloudflare", re.IGNORECASE),
    "clerk": re.compile(r"\bclerk\b", re.IGNORECASE),
    "resend": re.compile(r"\bresend\b", re.IGNORECASE),
    "stripe": re.compile(r"\bstripe\b", re.IGNORECASE),
    "github": re.compile(r"\bgithub\b", re.IGNORECASE),
    "sentry": re.compile(r"\bsentry\b", re.IGNORECASE),
    "plausible": re.compile(r"\bplausible\b", re.IGNORECASE),
    "betterstack": re.compile(r"better[\s_-]*stack|better[\s_-]*uptime", re.IGNORECASE),
}
VENDOR_LINE_RE = re.compile(
    "|".join(p.pattern for p in APPROVED_NAME_RES.values()) + r"|" + EXCLUDED_WORD_RE.pattern
    + r"|sub-?processor|\bDPA\b|data processing (?:agreement|addendum)",
    re.IGNORECASE,
)
DISCOVERY_THRESHOLD = 3

# --- claim rules ------------------------------------------------------------
_MONTHS_EN = r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
_MONTHS_OTHER = (
    r"janeiro|fevereiro|março|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro|"
    r"enero|febrero|marzo|mayo|junio|julio|septiembre|octubre|noviembre|diciembre|"
    r"Januar|Februar|März|Juni|Juli|Oktober|Dezember"
)
DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}\b"
    rf"|\b(?:{_MONTHS_EN})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}\b"
    rf"|\b\d{{1,2}}\.?\s+(?:de\s+)?(?:{_MONTHS_EN}|{_MONTHS_OTHER})\.?,?\s+(?:de\s+)?\d{{4}}\b"
    r"|\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:\d{4}|\d{2})\b"
    r"|\b(?:0?[1-9]|[12]\d|3[01])/(?:0?[1-9]|1[0-2])/\d{4}\b",
    re.IGNORECASE,
)
CLAIM_WORD_RE = re.compile(
    r"contract|agreement|\bdpa|dpa_|_dpa|terms of|countersign|\bsign(?:ed|ature|s)?\b|execut|"
    r"effective|approv|accept(?:ed|ance)|\baudit(?:ed)?\b|ratif",
    re.IGNORECASE,
)
# A contract-approval claim, not cryptographic signing ("signed commits",
# "signed head"): a signature/approval word bound to a contract-like noun, or
# an explicit legal approval.
_CONTRACT_NOUN = r"(?:DPAs?|contracts?|agreements?|SCCs?|terms|cop(?:y|ies)|addend(?:um|a))"
APPROVAL_RE = re.compile(
    r"\bcounter-?signed\b|\blegally approved\b|\blegal[- ]approv(?:ed|al)\b|"
    r"\bapproved (?:by|on)\b|\b(?:certified|attested) by (?:legal|counsel)\b|"
    rf"\b(?:signed|executed|ratified)\s+(?:by\s+\w+\s+)?(?:[\w.-]+\s+){{0,3}}?{_CONTRACT_NOUN}\b|"
    rf"\b{_CONTRACT_NOUN}\s+(?:[\w.-]+\s+){{0,4}}?(?:signed|executed|ratified)\b",
    re.IGNORECASE,
)
NEGATED_APPROVAL_RE = re.compile(
    r"\b(?:no|not|never|without|nothing|nor|neither)\b[^.;|]{0,60}?\b(?:counter-?signed|signed|signature|executed|approved)\b",
    re.IGNORECASE,
)
COUNT_RE = re.compile(
    r"\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+"
    r"(?:active\s+|live\s+|current\s+)?(?:customer-data\s+)?sub-?processors?\b",
    re.IGNORECASE,
)
WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}
NOTICE_CLAIM_RE = re.compile(
    r"subprocessor-changes@|tenant[- ]registered|reminder 7 days|digest the moment|"
    r"DKIM-signed (?:email|notice)|\bRSS\b[^|\n]{0,25}post-GA|in-app banner|"
    r"/v1/privacy/sub-processor-objection",
    re.IGNORECASE,
)

LEDGER_CATEGORIES = {
    # category -> blocks B-316 (state stays open while any line remains).
    # The one blocking category, pending-b314-repin, was retired on 2026-10-02
    # when the owner's B-314 re-pin made the GDPR row GitHub-only.
    "negative-status": False,
    "historical": False,
    "superseded-design": False,
    "paging-capability": False,
    "not-a-vendor": False,
}
SUPERSEDED_BANNER = "> **Superseded data-store assumption (B-316, 2026-10-02).**"
B314_GDPR_ROW = "| GitHub | US | DPF + SCC + sub-processor-specific posture | Operational metadata; no end-user PII |"

TRUST_HEADER = "| # | Vendor | Service to CoreLink | Customer-data class | Regions | Terms | DPA |"
EXPLANATION_HEADER = "| Provider | Role | Region | Terms | DPA |"
LEGAL_HEADER = "| ID | Nome | Função | Região | Terms | DPA |"
ADMIN_KEYS = ("id", "name", "role", "region", "certifications", "terms_url", "dpa_url")
LEGAL_ENTRY_KEYS = {
    "id", "name", "role", "data_categories_processed", "region", "certifications", "terms_url",
    "dpa_url", "primary_jurisdiction", "contract_signed_at", "legal_review_evidence",
}
PACKET_KEYS = {
    "schema_version", "backlog_id", "status", "authority", "recharter", "approved_population",
    "excluded_vendors", "vendors", "link_confirmation", "related_owner_backlog", "non_claims",
}
PACKET_VENDOR_KEYS = {"name", "terms_url", "dpa_url", "contract_basis", "online_acceptance_date", "record"}
EXPECTED_NON_CLAIMS = [
    "No countersigned contract or signature is claimed for any vendor.",
    "No online acceptance date is recorded, so none is stated.",
    "Acceptance of each vendor's standard online terms and DPA rests on the owner's statement in the re-charter, not on a vendor-side record held in this repository.",
    "No transfer impact assessment, SOC 2 report or certification is claimed as verified.",
]
COMMITMENT_FIELDS = (
    "Role", "Data categories", "Region", "Terms reference", "DPA reference",
    "SCCs / transfer mechanism", "Schrems II TIA", "Vendor review evidence",
    "Contract basis", "Online acceptance date",
)
RECORD_FIELDS = (
    "Vendor", "Sub-processor id", "Contract basis", "Terms reference", "DPA reference",
    "Online acceptance date", "Reviewer", "Owner disposition", "SCC / transfer mechanism",
    "Schrems II TIA", "Data categories processed", "Data residency / region",
    "Certifications verified", "Conditions / follow-ups", "Next review due",
)
RECORD_BANNER = "> STATUS: RECORDED — owner re-charter of B-316, 2026-10-01"
NOT_RECORDED = "Not recorded."
EXPECTED_RECHARTER = {
    "decided_at": "2026-10-01T21:39:30Z",
    "reference": "https://github.com/HuGR-dev/corelink-server/issues/2593#issuecomment-5941195884",
}
EXPECTED_RELATED = {
    "vendor_review_cadence_and_Drata_access": "B-032",
    "GDPR_Sigstore_transfer_table_disposition": "B-314",
}
URL_RE = re.compile(r"https://[^\s<>()\"'|]+")
ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

# --- render contracts ---------------------------------------------------------
# The exact JSX that maps the shared JSON to rows and links. Compared after
# collapsing whitespace; each must occur exactly once. Changing how a list is
# rendered means changing it here, in review, on purpose.
_VENDOR_LINK_DOCS = """
function VendorLink({ href, label, }: { readonly href: string; readonly label: string; }): ReactElement {
  if (!href.startsWith("https://")) return <span>{href}</span>;
  return ( <a href={href} target="_blank" rel="noopener noreferrer"> {label} </a> );
}"""
RENDER_CONTRACTS: dict[str, dict[str, Any]] = {
    DOCS_LEGAL_PAGE: {
        "snippets": (
            'import subProcessorsData from "../../../../admin-ui/src/content/sub-processors.json";',
            "const subProcessors: SubProcessorList = subProcessorsData as SubProcessorList;",
            "const { version, items } = subProcessors;",
            _VENDOR_LINK_DOCS,
            """<tbody> {items.map((item) => ( <tr key={item.id}> <td> <strong>{item.name}</strong> </td>
            <td>{item.role}</td> <td>{item.region}</td> <td>{item.certifications.join(" · ")}</td>
            <td> <VendorLink href={item.terms_url} label="Terms" /> </td>
            <td> <VendorLink href={item.dpa_url} label="DPA" /> </td> </tr> ))} </tbody>""",
        ),
        "counts": {r"<tr\b": 2, r"<td\b": 6, r"\bitems\b": 3, r"<VendorLink\b": 2},
    },
    DOCS_REGISTER_PAGE: {
        "snippets": (
            'import subProcessorsData from "../../../../admin-ui/src/content/sub-processors.json";',
            "const { version: LAST_REFRESHED, items: ACTIVE_SUB_PROCESSORS } = subProcessorsData as SubProcessorList;",
            _VENDOR_LINK_DOCS,
            """function SubProcessorRow({ sp, num, }: { readonly sp: SubProcessor; readonly num: number; }): ReactElement {
            return ( <tr> <td>{num}</td> <td> <strong>{sp.name}</strong> </td> <td>{sp.role}</td> <td>{sp.region}</td>
            <td> <VendorLink href={sp.terms_url} label="Terms" /> </td>
            <td> <VendorLink href={sp.dpa_url} label="DPA" /> </td> </tr> ); }""",
            """<tbody> {ACTIVE_SUB_PROCESSORS.map((sp, index) => (
            <SubProcessorRow key={sp.id} sp={sp} num={index + 1} /> ))} </tbody>""",
        ),
        "counts": {r"<tr\b": 2, r"<td\b": 6, r"\bACTIVE_SUB_PROCESSORS\b": 3, r"<VendorLink\b": 2, r"<SubProcessorRow\b": 1},
    },
    ADMIN_TABLE: {
        "snippets": (
            """const sorted = React.useMemo(() => { if (sortKey == null) return items; const copy = [...items];
            copy.sort((a, b) => { const av = String(a[sortKey]); const bv = String(b[sortKey]);
            return asc ? av.localeCompare(bv) : bv.localeCompare(av); }); return copy; }, [items, sortKey, asc]);""",
            """function VendorLink({ href, label, vendor }: { href: string; label: string; vendor: string }) {
            if (!href.startsWith("https://")) return <span>{href}</span>;
            return ( <a href={href} target="_blank" rel="noopener noreferrer" className={linkClass}
            aria-label={`${label} — ${vendor}`} > {label} </a> ); }""",
            """<tbody> {sorted.map((row) => ( <tr key={row.id}> <td className="text-[var(--t1)]">{row.name}</td>
            <td>{row.role}</td> <td>{row.region}</td> <td>{row.certifications.join(", ")}</td>
            <td> <VendorLink href={row.terms_url} label={headers.termsLink} vendor={row.name} /> </td>
            <td> <VendorLink href={row.dpa_url} label={headers.dpaLink} vendor={row.name} /> </td> </tr> ))} </tbody>""",
        ),
        "counts": {r"<tr\b": 2, r"<td\b": 6, r"\bitems\b": 6, r"<VendorLink\b": 2, r"\bsorted\b": 2},
    },
    ADMIN_PAGE: {
        "snippets": (
            """function toCsv(items: SubProcessor[]): string {
            const header = ["id", "name", "role", "region", "certifications", "terms_url", "dpa_url"];
            const rows = items.map((it) =>
            [it.id, it.name, it.role, it.region, it.certifications.join("|"), it.terms_url, it.dpa_url]
            .map((v) => `"${String(v).replace(/"/g, '""')}"`) .join(",") );
            return [header.join(","), ...rows].join("\\n"); }""",
            "<SubProcessorsTable locale={locale} caption={TITLE[locale]} headers={headers} items={items} />",
        ),
        "counts": {r"\bitems\b": 7},
    },
    ADMIN_ROUTE: {
        "snippets": (
            "const list = loadSubProcessors();",
            "return <SubProcessorsPage locale={locale} version={list.version} items={list.items} />;",
        ),
        "counts": {r"\blist\b": 3},
    },
    ADMIN_LOAD: {
        "snippets": ("export function loadSubProcessors(): SubProcessorList { return subProcessors; }",),
        "counts": {r"\bsubProcessors\b": 2},
    },
}
RENDER_FORBIDDEN_RE = re.compile(
    r"\.(?:filter|slice|splice|find|findLast|reduce|pop|shift|unshift|push|reverse)\(|\bfetch\(|dangerouslySetInnerHTML",
)

Links = dict[str, tuple[str, str]]


class ReviewError(ValueError):
    pass


def _norm(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------- parsing ---

def _json(text: str, source: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReviewError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise ReviewError(f"{source}: invalid JSON: {exc}") from exc


def _frontmatter(text: str, source: str) -> dict[str, Any]:
    if not text.startswith("---\n"):
        raise ReviewError(f"{source}: no leading frontmatter")
    try:
        _, body, _ = text.split("---", 2)
        parsed = yaml.safe_load(body)
    except (ValueError, yaml.YAMLError) as exc:
        raise ReviewError(f"{source}: invalid frontmatter: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReviewError(f"{source}: frontmatter is not a mapping")
    return parsed


def _cells(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def _table(text: str, header: str, source: str) -> list[list[str]]:
    """Rows of the single table under ``header``; zero or two tables is an error."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == header]
    if len(starts) != 1:
        raise ReviewError(f"{source}: expected exactly one table headed {header!r}, found {len(starts)}")
    i = starts[0] + 1
    if i >= len(lines) or not re.fullmatch(r"\|(?:\s*-{3,}\s*\|)+", lines[i].strip()):
        raise ReviewError(f"{source}: table {header!r} has no separator row")
    width = len(_cells(header))
    rows = []
    for line in lines[i + 1:]:
        if not line.startswith("|"):
            break
        cells = _cells(line)
        if len(cells) != width:
            raise ReviewError(f"{source}: row has {len(cells)} cells, expected {width}: {line[:80]}")
        rows.append(cells)
    if not rows:
        raise ReviewError(f"{source}: table {header!r} has no rows")
    return rows


def _link_cell(cell: str, label: str, source: str, vendor: str) -> str:
    """A table cell is either ``[label](https://…)`` or the literal ``link pending``."""
    if cell == LINK_PENDING:
        return LINK_PENDING
    match = re.fullmatch(rf"\[{re.escape(label)}\]\((https://[^)\s]+)\)", cell)
    if not match:
        raise ReviewError(f"{source}: {vendor} {label} cell is neither a link nor {LINK_PENDING!r}: {cell!r}")
    return match.group(1)


def _angle_value(value: str, field: str, source: str, *, allow_note: bool = False) -> str:
    note = r"(?: \([^|]*\))?" if allow_note else ""
    if re.fullmatch(re.escape(LINK_PENDING) + note, value):
        return LINK_PENDING
    match = re.fullmatch(r"<(https://[^>\s]+)>" + note, value)
    if not match:
        raise ReviewError(f"{source}: {field} is neither <https://…> nor {LINK_PENDING!r}: {value!r}")
    return match.group(1)


def _vendor_id(name: str, source: str) -> str:
    vendor_id = NAMES.get(name)
    if vendor_id is None:
        raise ReviewError(f"{source}: unknown vendor on a sub-processor list: {name!r}")
    return vendor_id


def _collect(pairs: list[tuple[str, tuple[str, str]]], source: str) -> Links:
    links: Links = {}
    for vendor_id, value in pairs:
        if vendor_id in EXCLUDED:
            raise ReviewError(f"{source}: excluded vendor {vendor_id!r} is listed")
        if vendor_id in links:
            raise ReviewError(f"{source}: vendor {vendor_id!r} is listed twice")
        links[vendor_id] = value
    return links


def _compare(source: str, got: Links, expected: Links) -> None:
    if set(got) != set(expected):
        raise ReviewError(
            f"{source}: vendor set disagrees with the approved set: "
            f"missing={sorted(set(expected) - set(got))} extra={sorted(set(got) - set(expected))}"
        )
    for vendor_id, (terms, dpa) in got.items():
        want_terms, want_dpa = expected[vendor_id]
        if terms != want_terms:
            raise ReviewError(f"{source}: {vendor_id} terms link {terms!r} disagrees with {want_terms!r}")
        if dpa != want_dpa:
            raise ReviewError(f"{source}: {vendor_id} DPA link {dpa!r} disagrees with {want_dpa!r}")


def _fields(text: str, source: str, *, start: int = 0, end: int | None = None) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in re.findall(r"(?m)^\| ([^|]+?) \| (.*?) \|$", text[start:end]):
        if key in ("Field", "---", "Document", "Vendor ", "#"):
            continue
        if key in fields:
            raise ReviewError(f"{source}: duplicate field {key!r}")
        fields[key] = value
    return fields


def _approval_claim(value: str) -> bool:
    stripped = NEGATED_APPROVAL_RE.sub(" ", value)
    return bool(APPROVAL_RE.search(stripped))


# ---------------------------------------------------------------- surfaces ---

def _packet(texts: dict[str, str]) -> tuple[dict[str, Any], Links]:
    packet = _json(texts[PACKET], PACKET)
    if not isinstance(packet, dict) or set(packet) != PACKET_KEYS:
        raise ReviewError(f"{PACKET}: top-level fields drifted (expected {sorted(PACKET_KEYS)})")
    if packet["schema_version"] != 2 or packet["backlog_id"] != "B-316":
        raise ReviewError(f"{PACKET}: identity/schema drifted")
    if packet["authority"] != "Owner":
        raise ReviewError(f"{PACKET}: authority is not the owner re-charter")
    recharter = packet["recharter"]
    if not isinstance(recharter, dict) or any(recharter.get(k) != v for k, v in EXPECTED_RECHARTER.items()):
        raise ReviewError(f"{PACKET}: re-charter reference drifted")
    if packet["approved_population"] != list(APPROVED):
        raise ReviewError(f"{PACKET}: approved population is not the exact eight")
    excluded = packet["excluded_vendors"]
    if not isinstance(excluded, dict) or set(excluded) != set(EXCLUDED):
        raise ReviewError(f"{PACKET}: excluded vendors drifted")
    if packet["related_owner_backlog"] != EXPECTED_RELATED:
        raise ReviewError(f"{PACKET}: lost its B-032/B-314 ownership boundaries")
    if packet["non_claims"] != EXPECTED_NON_CLAIMS:
        raise ReviewError(f"{PACKET}: non-claims are not the exact reviewed list")
    vendors = packet["vendors"]
    if not isinstance(vendors, dict) or list(vendors) != list(APPROVED):
        raise ReviewError(f"{PACKET}: vendor population is not the exact approved eight")
    expected: Links = {}
    for vendor_id, entry in vendors.items():
        want_keys = PACKET_VENDOR_KEYS | ({"risk_action"} if vendor_id in RISK_ACTIONS else set())
        if not isinstance(entry, dict) or set(entry) != want_keys:
            raise ReviewError(f"{PACKET}: {vendor_id} fields drifted")
        if NAMES.get(entry["name"]) != vendor_id:
            raise ReviewError(f"{PACKET}: {vendor_id} name {entry['name']!r} is not a known spelling")
        if entry["contract_basis"] != "vendor_standard_online_terms_and_dpa":
            raise ReviewError(f"{PACKET}: {vendor_id} contract basis drifted")
        if entry["online_acceptance_date"] is not None:
            raise ReviewError(f"{PACKET}: {vendor_id} records an acceptance date with no acceptance record")
        want_record = VR_RECORDS.get(vendor_id) or APRIL_RECORDS.get(vendor_id)
        if entry["record"] != want_record:
            raise ReviewError(f"{PACKET}: {vendor_id} record path drifted")
        if vendor_id in RISK_ACTIONS and entry["risk_action"] != RISK_ACTIONS[vendor_id]:
            raise ReviewError(f"{PACKET}: {vendor_id} risk action drifted")
        links = []
        for key in ("terms_url", "dpa_url"):
            value = entry[key]
            if value != LINK_PENDING and not (isinstance(value, str) and URL_RE.fullmatch(value)):
                raise ReviewError(f"{PACKET}: {vendor_id} {key} is neither https:// nor {LINK_PENDING!r}")
            links.append(value)
        expected[vendor_id] = (links[0], links[1])
    return packet, expected


def _legal(texts: dict[str, str]) -> tuple[Links, Links]:
    text = texts[LEGAL]
    front = _frontmatter(text, LEGAL)
    entries = front.get("sub_processors")
    if not isinstance(entries, list) or not entries:
        raise ReviewError(f"{LEGAL}: sub_processors is not a non-empty list")
    pairs = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ReviewError(f"{LEGAL}: sub_processors[{index}] has no id")
        vendor_id = entry["id"]
        if set(entry) != LEGAL_ENTRY_KEYS:
            raise ReviewError(
                f"{LEGAL}: {vendor_id} fields drifted: missing={sorted(LEGAL_ENTRY_KEYS - set(entry))} "
                f"extra={sorted(set(entry) - LEGAL_ENTRY_KEYS)}"
            )
        if entry["contract_signed_at"] is not None:
            raise ReviewError(f"{LEGAL}: {vendor_id} contract_signed_at must be null — no acceptance date is recorded")
        want = VR_RECORDS.get(vendor_id) or APRIL_RECORDS.get(vendor_id)
        if want is not None and entry["legal_review_evidence"] != want:
            raise ReviewError(f"{LEGAL}: {vendor_id} evidence path disagrees with the packet")
        terms, dpa = entry["terms_url"], entry["dpa_url"]
        if not isinstance(terms, str) or not isinstance(dpa, str) or not terms or not dpa:
            raise ReviewError(f"{LEGAL}: {vendor_id} lacks a terms_url or dpa_url")
        for value in entry.values():
            if isinstance(value, str) and (DATE_RE.search(value) or _approval_claim(value)):
                raise ReviewError(f"{LEGAL}: {vendor_id} states a date or approval: {value!r}")
        pairs.append((vendor_id, (terms, dpa)))
    frontmatter_links = _collect(pairs, f"{LEGAL} frontmatter")
    body_pairs = []
    for cells in _table(text, LEGAL_HEADER, LEGAL):
        vendor_id = cells[0]
        body_pairs.append((
            vendor_id,
            (_link_cell(cells[4], "Terms", LEGAL, vendor_id), _link_cell(cells[5], "DPA", LEGAL, vendor_id)),
        ))
    return frontmatter_links, _collect(body_pairs, f"{LEGAL} body table")


def _commitments(texts: dict[str, str]) -> Links:
    text = texts[COMMITMENTS]
    headings = list(re.finditer(r"(?m)^### 1\.(\d+) (.+)$", text))
    if not headings:
        raise ReviewError(f"{COMMITMENTS}: no §1 vendor sections")
    pairs = []
    for position, match in enumerate(headings, 1):
        if int(match.group(1)) != position:
            raise ReviewError(f"{COMMITMENTS}: §1 numbering is not sequential at {match.group(0)!r}")
        vendor_id = _vendor_id(match.group(2), COMMITMENTS)
        end = headings[position].start() if position < len(headings) else text.index("\n---\n", match.end())
        fields = _fields(text, COMMITMENTS, start=match.end(), end=end)
        if tuple(fields) != COMMITMENT_FIELDS:
            raise ReviewError(f"{COMMITMENTS}: {vendor_id} fields drifted: {list(fields)}")
        if fields["Online acceptance date"] != NOT_RECORDED:
            raise ReviewError(f"{COMMITMENTS}: {vendor_id} must say the online acceptance date is {NOT_RECORDED!r}")
        for key, value in fields.items():
            if DATE_RE.search(value) or _approval_claim(value):
                raise ReviewError(f"{COMMITMENTS}: {vendor_id} {key} states a date or approval: {value!r}")
        pairs.append((
            vendor_id,
            (
                _angle_value(fields["Terms reference"], f"{vendor_id} Terms reference", COMMITMENTS),
                _angle_value(fields["DPA reference"], f"{vendor_id} DPA reference", COMMITMENTS),
            ),
        ))
    return _collect(pairs, COMMITMENTS)


def _generator(source: str) -> types.ModuleType:
    module = types.ModuleType("b316_generator_under_test")
    module.__file__ = str(ROOT / GENERATOR)
    sys.modules[module.__name__] = module
    try:
        exec(compile(source, GENERATOR, "exec"), module.__dict__)  # noqa: S102 — the repository's own generator
    except Exception as exc:  # a generator that does not import is a failed gate
        raise ReviewError(f"{GENERATOR}: cannot be loaded: {exc}") from exc
    finally:
        sys.modules.pop(module.__name__, None)
    return module


def _register(texts: dict[str, str], expected: Links) -> Links:
    generator = _generator(texts[GENERATOR])
    if hasattr(generator, "PUBLIC_LEGAL_LINKS"):
        raise ReviewError(f"{GENERATOR}: links must come from the register's own columns, not a generator map")
    rows, updated = generator.parse_register(texts[REGISTER])
    if not rows:
        raise ReviewError(f"{REGISTER}: parsed no §2 rows")
    try:
        rendered = generator.render_mdx(rows, updated)
    except ValueError as exc:
        raise ReviewError(f"{GENERATOR}: cannot render the public page: {exc}") from exc
    if rendered != texts[TRUST_EN]:
        raise ReviewError(f"{TRUST_EN}: drifted from the register (run scripts/gen-public-subprocessors.py)")
    pairs = []
    for row in rows:
        vendor_id = NAMES.get(row.vendor)
        if vendor_id in EXCLUDED:
            if row.is_customer_data_processor or row.is_inert or not row.is_deferred:
                raise ReviewError(f"{REGISTER}: {row.vendor} must be deferred and off every public list")
            continue
        if not row.is_customer_data_processor:
            if row.terms != "—" or row.dpa != "—":
                raise ReviewError(f"{REGISTER}: {row.vendor} is not on the public list but carries Terms/DPA cells")
            continue
        if vendor_id is None:
            raise ReviewError(f"{REGISTER}: unknown active vendor {row.vendor!r}")
        terms = _link_cell(row.terms, "Terms", REGISTER, vendor_id)
        dpa = _link_cell(row.dpa, "DPA", REGISTER, vendor_id)
        for label, url in re.findall(r"\[([^\]]+)\]\((https://[^)\s]+)\)", row.attestation + " " + row.contract):
            if re.search(r"\bDPA\b|data processing", label, re.IGNORECASE) and url != expected.get(vendor_id, ("", ""))[1]:
                raise ReviewError(f"{REGISTER}: {vendor_id} attestation cell links a different DPA: {url}")
            if re.search(r"\bterms\b", label, re.IGNORECASE) and url != expected.get(vendor_id, ("", ""))[0]:
                raise ReviewError(f"{REGISTER}: {vendor_id} attestation cell links different terms: {url}")
        if DATE_RE.search(row.contract) or _approval_claim(row.contract):
            raise ReviewError(f"{REGISTER}: {vendor_id} contract cell states a date or approval: {row.contract!r}")
        pairs.append((vendor_id, (terms, dpa)))
    deferred_rows = re.findall(r"(?m)^\| PagerDuty, Inc\. \| 9 \| Deferred by the owner", texts[REGISTER])
    if len(deferred_rows) != 1:
        raise ReviewError(f"{REGISTER}: §4c must record PagerDuty (row 9) as deferred exactly once")
    return _collect(pairs, f"{REGISTER} active rows")


def _risk_actions(texts: dict[str, str], expected: Links) -> None:
    for vendor_id, action_id in RISK_ACTIONS.items():
        rows = [_cells(line) for line in texts[REGISTER].splitlines() if line.startswith(f"| {action_id} |")]
        if len(rows) != 1 or len(rows[0]) != 5:
            raise ReviewError(f"{REGISTER}: expected one five-column {action_id} row")
        _, action, owner, _, status = rows[0]
        want = "Open" if LINK_PENDING in expected[vendor_id] else "Closed"
        if owner != "Owner" or status != want:
            raise ReviewError(f"{REGISTER}: {action_id} must be Owner/{want}, found {owner}/{status}")
        if "re-chartered 2026-10-01" not in action or f"`{VR_RECORDS[vendor_id]}`" not in action:
            raise ReviewError(f"{REGISTER}: {action_id} lost its re-charter disposition or record path")


def _records(texts: dict[str, str]) -> dict[str, Links]:
    result: dict[str, Links] = {}
    for vendor_id, path in VR_RECORDS.items():
        text = texts[path]
        if not text.startswith("# Vendor Contract-Basis Record — ") or RECORD_BANNER not in text:
            raise ReviewError(f"{path}: not a re-chartered contract-basis record")
        if "STATUS: TEMPLATE" in text:
            raise ReviewError(f"{path}: still carries the TEMPLATE banner")
        fields = _fields(text, path)
        if tuple(fields) != RECORD_FIELDS:
            raise ReviewError(f"{path}: field population drifted: {list(fields)}")
        if fields["Sub-processor id"] != f"`{vendor_id}`":
            raise ReviewError(f"{path}: id disagrees with its file")
        if fields["Online acceptance date"] != NOT_RECORDED:
            raise ReviewError(f"{path}: online acceptance date must be {NOT_RECORDED!r}")
        if fields["Next review due"] != "Not scheduled." or any("TBD" in v for v in fields.values()):
            raise ReviewError(f"{path}: template or invented scheduling fields remain")
        for key, value in fields.items():
            if DATE_RE.search(value) or _approval_claim(value):
                raise ReviewError(f"{path}: {key} states a date or approval: {value!r}")
        result[path] = {vendor_id: (
            _angle_value(fields["Terms reference"], "Terms reference", path),
            _angle_value(fields["DPA reference"], "DPA reference", path),
        )}
    for vendor_id, path in APRIL_RECORDS.items():
        text = texts[path]
        terms_rows = re.findall(r"(?m)^\| Terms reference \| (.*?) \|$", text)
        dpa_rows = re.findall(r"(?m)^\| DPA reference \| (.*?) \|$", text)
        if len(terms_rows) != 1 or len(dpa_rows) != 1:
            raise ReviewError(f"{path}: needs exactly one Terms reference and one DPA reference row")
        result[path] = {vendor_id: (
            _angle_value(terms_rows[0], "Terms reference", path, allow_note=True),
            _angle_value(dpa_rows[0], "DPA reference", path, allow_note=True),
        )}
    return result


def _trust_pages(texts: dict[str, str], ledger: dict[str, Any]) -> dict[str, Links]:
    result: dict[str, Links] = {}
    for path in TRUST_PAGES:
        pairs = []
        for cells in _table(texts[path], TRUST_HEADER, path):
            name = re.fullmatch(r"\*\*(.+)\*\*", cells[1])
            if not name:
                raise ReviewError(f"{path}: vendor cell is not bold: {cells[1]!r}")
            vendor_id = _vendor_id(name.group(1), path)
            pairs.append((vendor_id, (_link_cell(cells[5], "Terms", path, vendor_id), _link_cell(cells[6], "DPA", path, vendor_id))))
        result[path] = _collect(pairs, path)
    for path in EXPLANATION_PAGES:
        pairs = []
        for cells in _table(texts[path], EXPLANATION_HEADER, path):
            vendor_id = _vendor_id(cells[0], path)
            pairs.append((vendor_id, (_link_cell(cells[3], "Terms", path, vendor_id), _link_cell(cells[4], "DPA", path, vendor_id))))
        result[path] = _collect(pairs, path)
    deltas = ledger["locale_deltas"]
    for en, copies in ((TRUST_EN, TRUST_LOCALE_PAGES), (EXPLANATION_EN, EXPLANATION_LOCALE_PAGES)):
        for path in copies:
            if _locale_delta_json(texts[en], texts[path]) != json.dumps(deltas.get(path), ensure_ascii=False):
                raise ReviewError(f"{path}: differs from {en} beyond its declared locale delta")
    return result


@functools.lru_cache(maxsize=None)
def _locale_delta_json(en: str, localized: str) -> str:
    return json.dumps(_locale_delta(en, localized), ensure_ascii=False)


def _locale_delta(en: str, localized: str) -> list[dict[str, list[str]]]:
    a, b = en.splitlines(), localized.splitlines()
    hunks = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag != "equal":
            hunks.append({"en": a[i1:i2], "locale": b[j1:j2]})
    return hunks


def _admin(texts: dict[str, str]) -> Links:
    data = _json(texts[ADMIN_JSON], ADMIN_JSON)
    if not isinstance(data, dict) or set(data) != {"version", "items"}:
        raise ReviewError(f"{ADMIN_JSON}: top-level shape drifted")
    if not isinstance(data["version"], str) or not ISO_DATE_RE.fullmatch(data["version"]):
        raise ReviewError(f"{ADMIN_JSON}: version is not a list date")
    items = data["items"]
    if not isinstance(items, list) or not items:
        raise ReviewError(f"{ADMIN_JSON}: items is not a non-empty list")
    pairs = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or tuple(item) != ADMIN_KEYS:
            # Exact keys: this is also what keeps an audit/acceptance date field out.
            raise ReviewError(f"{ADMIN_JSON}: item {index} keys drifted (expected {ADMIN_KEYS})")
        if item["id"] in EXCLUDED or item["id"] not in APPROVED:
            raise ReviewError(f"{ADMIN_JSON}: vendor id {item['id']!r} is not in the approved set")
        values = [item["name"], item["role"], item["region"], *item["certifications"]]
        if any(DATE_RE.search(str(v)) or _approval_claim(str(v)) for v in values):
            raise ReviewError(f"{ADMIN_JSON}: {item['id']} states a date or approval in a displayed field")
        for key in ("terms_url", "dpa_url"):
            if item[key] != LINK_PENDING and not URL_RE.fullmatch(str(item[key])):
                raise ReviewError(f"{ADMIN_JSON}: {item['id']} {key} is neither https:// nor {LINK_PENDING!r}")
        pairs.append((item["id"], (item["terms_url"], item["dpa_url"])))
    links = _collect(pairs, ADMIN_JSON)

    ts = texts[ADMIN_TS]
    version = re.findall(r'(?m)^  version: (".*"),$', ts)
    mirrored = []
    for block in re.findall(r"(?ms)^    \{\n(.*?)^    \},$", ts):
        entry: dict[str, Any] = {}
        for key, value in re.findall(r"(?m)^      (\w+): (.*),$", block):
            try:
                entry[key] = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ReviewError(f"{ADMIN_TS}: unparseable value for {key}: {exc}") from exc
        mirrored.append(entry)
    if version != [json.dumps(data["version"])] or mirrored != items:
        raise ReviewError(f"{ADMIN_TS}: does not mirror {ADMIN_JSON} exactly")
    return links


def _strip_comments(text: str) -> str:
    """Drop /* */ and // comments (a // preceded by ':' — a URL — is code)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"(?m)(^|\s)//.*$", r"\1", text)


def _render_contracts(texts: dict[str, str]) -> None:
    for path, contract in RENDER_CONTRACTS.items():
        text = _strip_comments(texts[path])
        normalized = _norm(text)
        for snippet in contract["snippets"]:
            count = normalized.count(_norm(snippet))
            if count != 1:
                raise ReviewError(f"{path}: render contract not met exactly once ({count}): {_norm(snippet)[:90]!r}")
        for pattern, want in contract["counts"].items():
            got = len(re.findall(pattern, text))
            if got != want:
                raise ReviewError(f"{path}: {pattern} occurs {got} times, the render contract allows {want}")
        forbidden = RENDER_FORBIDDEN_RE.search(text)
        if forbidden:
            raise ReviewError(f"{path}: render path may not reshape or replace the list: {forbidden.group(0)!r}")


# --------------------------------------------------------------- discovery ---

def _ledger(texts: dict[str, str]) -> dict[str, Any]:
    ledger = _json(texts[LEDGER], LEDGER)
    keys = {"schema_version", "backlog_id", "purpose", "categories", "excluded_vendor_mentions",
            "disclosure_files", "claim_line_allowlist", "locale_deltas"}
    if not isinstance(ledger, dict) or set(ledger) != keys or ledger["schema_version"] != 1 or ledger["backlog_id"] != "B-316":
        raise ReviewError(f"{LEDGER}: schema drifted")
    categories = ledger["categories"]
    if not isinstance(categories, dict) or set(categories) != set(LEDGER_CATEGORIES) or not all(
        isinstance(reason, str) and reason.strip() for reason in categories.values()
    ):
        raise ReviewError(f"{LEDGER}: categories must be exactly {sorted(LEDGER_CATEGORIES)}, each with a reason")
    for path, entries in ledger["excluded_vendor_mentions"].items():
        if not isinstance(entries, list) or not entries:
            raise ReviewError(f"{LEDGER}: {path} declares no mentions")
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"category", "line"} or not entry["line"]:
                raise ReviewError(f"{LEDGER}: {path} mention entry is malformed")
            if entry["category"] not in LEDGER_CATEGORIES:
                raise ReviewError(f"{LEDGER}: {path} uses unknown category {entry['category']!r}")
    for path, reason in ledger["disclosure_files"].items():
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewError(f"{LEDGER}: disclosure file {path} has no reason")
    for path, entries in ledger["claim_line_allowlist"].items():
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"line", "reason"} or not entry["line"] or not str(entry["reason"]).strip():
                raise ReviewError(f"{LEDGER}: claim allowlist entry in {path} needs a line and a reason")
    return ledger


def published_paths(texts: dict[str, str]) -> list[str]:
    return sorted(
        path for path in texts
        if path in PUBLISHED_FILES or any(path.startswith(root + "/") for root in PUBLISHED_ROOTS)
    )


def _parsed_surfaces() -> set[str]:
    return {
        LEGAL, COMMITMENTS, *TRUST_PAGES, *EXPLANATION_PAGES, ADMIN_JSON, ADMIN_TS,
        DOCS_LEGAL_PAGE, DOCS_REGISTER_PAGE, ADMIN_TABLE, ADMIN_PAGE,
    }


@functools.lru_cache(maxsize=None)
def _scan(text: str) -> tuple[tuple[str, ...], int]:
    """(stripped lines naming an excluded vendor, approved vendors named if a sub-processor term occurs)."""
    hits = ()
    if EXCLUDED_WORD_RE.search(text):
        hits = tuple(line.strip() for line in text.splitlines() if EXCLUDED_WORD_RE.search(line))
    named = 0
    if SUBPROCESSOR_TERM_RE.search(text):
        named = sum(1 for pattern in APPROVED_NAME_RES.values() if pattern.search(text))
    return hits, named


@functools.lru_cache(maxsize=None)
def _claim_findings(text: str, parsed: bool) -> tuple[tuple[str, str], ...]:
    """(problem, stripped line) for every claim-rule hit in one surface."""
    found = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or (not parsed and not VENDOR_LINE_RE.search(line)):
            continue
        problem = None
        if DATE_RE.search(line) and CLAIM_WORD_RE.search(line):
            problem = "a dated contract/approval claim"
        elif VENDOR_LINE_RE.search(line) and _approval_claim(line):
            problem = "an approval or signature claim"
        elif NOTICE_CLAIM_RE.search(line):
            problem = "an unshipped notice channel"
        else:
            for number in COUNT_RE.findall(re.sub(r"\bArt(?:icle|\.)?\s*\d+", " ", line)):
                value = int(number) if number.isdigit() else WORD_NUMBERS[number.lower()]
                if value != len(APPROVED):
                    problem = f"a sub-processor count of {value}"
                    break
        if problem is not None:
            found.append((problem, line))
    return tuple(found)


def _discover(texts: dict[str, str], ledger: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return (blocking findings, disclosure surfaces). Raise on anything undeclared."""
    blocking: list[str] = []
    mentions = ledger["excluded_vendor_mentions"]
    seen_mention_files = set()
    disclosure = set(_parsed_surfaces())
    for path in published_paths(texts):
        text = texts[path]
        hits, named = _scan(text)
        if hits:
            entries = mentions.get(path)
            if entries is None:
                raise ReviewError(f"{path}: names an excluded vendor and is not declared: {hits[0][:100]!r}")
            declared = Counter(entry["line"] for entry in entries)
            if Counter(hits) != declared:
                extra = sorted((Counter(hits) - declared).elements())
                missing = sorted((declared - Counter(hits)).elements())
                raise ReviewError(f"{path}: excluded-vendor mentions differ from the ledger: undeclared={extra[:2]} stale={missing[:2]}")
            categories = Counter(entry["category"] for entry in entries)
            if "superseded-design" in categories and SUPERSEDED_BANNER not in text:
                raise ReviewError(f"{path}: superseded-design mentions need the B-316 superseded banner")
            for category, count in sorted(categories.items()):
                if LEDGER_CATEGORIES[category]:
                    blocking.append(f"{path}: {category} ({count} line(s))")
            seen_mention_files.add(path)
        if named >= DISCOVERY_THRESHOLD:
            if path not in disclosure and path not in ledger["disclosure_files"]:
                raise ReviewError(f"{path}: lists sub-processors ({named} approved vendors) but is neither parsed nor declared")
            disclosure.add(path)
    stale = sorted(set(mentions) - seen_mention_files)
    if stale:
        raise ReviewError(f"{LEDGER}: declares excluded-vendor mentions that no longer exist: {stale[:3]}")
    stale = sorted(path for path in ledger["disclosure_files"] if path not in disclosure)
    if stale:
        raise ReviewError(f"{LEDGER}: declares disclosure files that are not disclosures (or missing): {stale[:3]}")
    return blocking, sorted(disclosure)


def _claims(texts: dict[str, str], ledger: dict[str, Any], surfaces: list[str]) -> None:
    allow = {path: [entry["line"] for entry in entries] for path, entries in ledger["claim_line_allowlist"].items()}
    used: dict[str, Counter] = {path: Counter() for path in allow}
    parsed = _parsed_surfaces()
    for path in surfaces:
        for problem, line in _claim_findings(texts[path], path in parsed or path in RECORD_PATHS):
            if line in allow.get(path, []):
                used[path][line] += 1
                continue
            raise ReviewError(f"{path}: states {problem}: {line[:120]!r}")
    for path, lines in allow.items():
        if path not in surfaces:
            raise ReviewError(f"{LEDGER}: claim allowlist names a non-surface {path}")
        stale = Counter(lines) - used[path]
        if stale:
            raise ReviewError(f"{LEDGER}: stale claim allowlist line in {path}: {next(iter(stale))[:100]!r}")


# ------------------------------------------------------------------ assess ---

def assess(texts: dict[str, str]) -> str:
    packet, expected = _packet(texts)
    ledger = _ledger(texts)
    blocking, surfaces = _discover(texts, ledger)
    _claims(texts, ledger, [*surfaces, *VR_RECORDS.values(), *APRIL_RECORDS.values()])
    frontmatter, body = _legal(texts)
    compared: dict[str, Links] = {
        f"{LEGAL} frontmatter": frontmatter,
        f"{LEGAL} body table": body,
        COMMITMENTS: _commitments(texts),
        f"{REGISTER} active rows": _register(texts, expected),
        ADMIN_JSON: _admin(texts),
        **_trust_pages(texts, ledger),
    }
    for source, links in compared.items():
        _compare(source, links, expected)
    for path, links in _records(texts).items():
        for vendor_id, pair in links.items():
            if pair != expected[vendor_id]:
                raise ReviewError(f"{path}: terms/DPA links disagree with the packet")
    _risk_actions(texts, expected)
    _render_contracts(texts)
    pending_links = any(LINK_PENDING in pair for pair in expected.values())
    state = "open" if pending_links or blocking else "done"
    if packet["status"] != ("complete" if state == "done" else "pending"):
        raise ReviewError(f"{PACKET}: status {packet['status']!r} disagrees with derived {state} state")
    return state


def blockers(texts: dict[str, str]) -> list[str]:
    _, expected = _packet(texts)
    found, _ = _discover(texts, _ledger(texts))
    found += [f"{vid}: link pending" for vid, pair in expected.items() if LINK_PENDING in pair]
    return found


def _walk_published(root: Path) -> list[str]:
    paths = [rel for rel in PUBLISHED_FILES if (root / rel).is_file()]
    for top in PUBLISHED_ROOTS:
        for dirpath, dirnames, filenames in os.walk(root / top):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
            for name in sorted(filenames):
                if Path(name).suffix not in PUBLISHED_EXTENSIONS or SKIP_FILE_RE.search(name):
                    continue
                paths.append((Path(dirpath) / name).relative_to(root).as_posix())
    return paths


def load(root: Path = ROOT) -> dict[str, str]:
    fixed = (
        PACKET, LEDGER, LEGAL, COMMITMENTS, REGISTER, GENERATOR, *TRUST_PAGES, *EXPLANATION_PAGES,
        ADMIN_JSON, ADMIN_TS, ADMIN_LOAD, ADMIN_TABLE, ADMIN_PAGE, ADMIN_ROUTE, DOCS_LEGAL_PAGE,
        DOCS_REGISTER_PAGE, *VR_RECORDS.values(), *APRIL_RECORDS.values(),
    )
    result: dict[str, str] = {}
    for relative in (*fixed, *_walk_published(root)):
        if relative in result:
            continue
        path = root / relative
        if not path.is_file() or path.is_symlink():
            if relative in fixed:
                raise ReviewError(f"missing/non-regular B-316 input: {relative}")
            continue
        try:
            result[relative] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    if sum(1 for p in result if p.startswith("apps/docs/")) < 100:
        raise ReviewError("published-tree discovery read too few docs files; the walk is broken")
    return result


# --------------------------------------------------------------- self-test ---

def _edit(path: str, old: str, new: str) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        if texts.get(path, "").count(old) < 1:
            raise ReviewError(f"self-test mutation did not apply: {path}: {old[:60]!r}")
        texts[path] = texts[path].replace(old, new, 1)
    return apply


def _append(path: str, line: str) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        texts[path] = texts[path].rstrip("\n") + "\n" + line + "\n"
    return apply


def _new_file(path: str, text: str) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        if path in texts:
            raise ReviewError(f"self-test new file already exists: {path}")
        texts[path] = text
    return apply


def _edit_json(path: str, change: Callable[[Any], None]) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        data = json.loads(texts[path])
        change(data)
        texts[path] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return apply


def _mirror_admin(change: Callable[[Any], None]) -> Callable[[dict[str, str]], None]:
    """Change the admin JSON and keep the TS mirror consistent with it."""
    def apply(texts: dict[str, str]) -> None:
        _edit_json(ADMIN_JSON, change)(texts)
        data = json.loads(texts[ADMIN_JSON])
        ts = texts[ADMIN_TS]
        for item in data["items"]:
            for key in ("name", "role"):
                ts = re.sub(
                    rf'(?m)^(      id: "{item["id"]}",\n(?:      .*\n)*?      {key}: ).*,$',
                    lambda m, v=item[key]: m.group(1) + json.dumps(v, ensure_ascii=False) + ",",
                    ts, count=1,
                )
        texts[ADMIN_TS] = ts
    return apply


def _replace_link_everywhere(url: str) -> Callable[[dict[str, str]], None]:
    """Turn one confirmed link into ``link pending`` on every surface at once."""
    def apply(texts: dict[str, str]) -> None:
        hits = 0
        for path, text in texts.items():
            new = text
            for label in ("Terms", "DPA"):
                new = new.replace(f"[{label}]({url})", LINK_PENDING)
            new = new.replace(f"<{url}>", LINK_PENDING).replace(f'"{url}"', f'"{LINK_PENDING}"')
            if new != text:
                hits += 1
                texts[path] = new
        if hits < 10:
            raise ReviewError(f"self-test link-pending fixture reached only {hits} surfaces")
    return apply


_LEGAL_PAGERDUTY = """  - id: "pagerduty"
    name: "PagerDuty, Inc."
    role: "Incident management"
    data_categories_processed: ["operational_alerts"]
    region: "United States"
    certifications: []
    terms_url: "https://www.pagerduty.com/terms-of-use/"
    dpa_url: "https://www.pagerduty.com/dpa/"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/pagerduty-dpa-review-2026-04.md"
---
"""
_DOCS_LEGAL_TBODY_OLD = "{items.map((item) => ("
_GITHUB_DPA = "https://github.com/customer-terms/github-data-protection-agreement"

MUTATIONS: tuple[tuple[str, Callable[[dict[str, str]], None]], ...] = (
    # vendor set
    ("PagerDuty back in the contractual register", _edit(LEGAL, "\n---\n", "\n" + _LEGAL_PAGERDUTY)),
    ("PagerDuty row on the generated trust page", _edit(TRUST_EN, "| 1 | **Cloudflare", "| 0 | **PagerDuty, Inc.** | x | x | x | [Terms](https://www.pagerduty.com/terms-of-use/) | [DPA](https://www.pagerduty.com/dpa/) |\n| 1 | **Cloudflare")),
    ("Neon section back in the commitments", _edit(COMMITMENTS, "### 1.8 Better Stack", "### 1.8 Neon, Inc.\n\n### 1.9 Better Stack")),
    ("Pager-Duty spelled with a hyphen", _append(LEGAL, "Incidents page via Pager-Duty.")),
    ("PagerDuty no longer deferred by the generator", _edit(GENERATOR, '    "PagerDuty, Inc.": "Deferred by the owner', '    "PagerDuty, Inc. (retired)": "Deferred by the owner')),
    ("vendor dropped from an explanation page", lambda t: t.__setitem__(EXPLANATION_PAGES[3], re.sub(r"(?m)^\| Stripe, Inc\. \|.*\n", "", t[EXPLANATION_PAGES[3]], count=1))),
    ("vendor missing from the packet", _edit_json(PACKET, lambda d: d["vendors"].pop("github"))),
    ("unknown extra vendor on the legal body table", _edit(LEGAL, "| betterstack | Better Stack", "| acme | Acme | x | x | [Terms](https://acme.test/t) | [DPA](https://acme.test/d) |\n| betterstack | Better Stack")),
    # discovery
    ("new page lists sub-processors", _new_file("apps/docs/docs/trust/vendors-new.mdx", "# Our sub-processors\n\nCloudflare, Stripe and Clerk process your data.\n")),
    ("Neon named on an undeclared published page", _append("apps/docs/docs/trust/index.mdx", "Billing lives in Neon.")),
    ("PagerDuty added to a declared paging file", _append("marketing/sales/FAQ-MASTER.md", "PagerDuty also receives your build logs.")),
    ("old B-314 GDPR row restored", _edit("apps/docs/docs/explanation/privacy/gdpr.mdx", B314_GDPR_ROW, B314_GDPR_ROW.replace("| GitHub |", "| PagerDuty / GitHub |", 1))),
    # links
    ("vendor DPA link deleted from the admin JSON", _edit_json(ADMIN_JSON, lambda d: d["items"][0].pop("dpa_url"))),
    ("terms link changed on one locale only", _edit(TRUST_PAGES[2], "[Terms](https://sentry.io/terms/)", "[Terms](https://sentry.io/terms-old/)")),
    ("Clerk DPA back to 'on request'", _edit(LEGAL, 'dpa_url: "https://clerk.com/legal/dpa"', 'dpa_url: "Clerk DPA (on request)"')),
    ("register row carries a wrong Resend DPA", _edit(REGISTER, "[DPA](https://resend.com/legal/dpa) |", "[DPA](https://resend.com/legal/dpa-old) |")),
    ("register attestation cell links another DPA", _edit(REGISTER, "Terms and DPA: last two columns", "[Resend DPA](https://resend.com/old-dpa)")),
    ("register row loses its terms link", _edit(REGISTER, "| [Terms](https://plausible.io/terms) |", "| — |")),
    ("link pending on one surface only", _edit(COMMITMENTS, "| DPA reference | <https://betterstack.com/dpa> |", "| DPA reference | link pending |")),
    ("guessed non-https DPA link", _edit(EXPLANATION_PAGES[0], "[DPA](https://resend.com/legal/dpa)", "[DPA](http://resend.com/dpa)")),
    ("2026-04 record links a different DPA", _edit(APRIL_RECORDS["stripe"], "| DPA reference | <https://stripe.com/legal/dpa> |", "| DPA reference | <https://stripe.com/dpa-2019> |")),
    # renderers
    ("docs legal page filters GitHub out", _edit(DOCS_LEGAL_PAGE, _DOCS_LEGAL_TBODY_OLD, '{items.filter((i) => i.id !== "github").map((item) => (')),
    ("docs legal page alters a DPA href", _edit(DOCS_LEGAL_PAGE, "<VendorLink href={item.dpa_url}", "<VendorLink href={item.dpa_url && 'https://example.com/'}")),
    ("docs legal page hard-codes an extra row", _edit(DOCS_LEGAL_PAGE, "</tbody>", "<tr><td>Grafana Labs</td></tr></tbody>")),
    ("docs register page hard-codes a dated cell", _edit(DOCS_REGISTER_PAGE, "<td>{sp.region}</td>", "<td>{sp.region}</td><td>Stripe DPA signed 2026-04-23</td>")),
    ("admin table hard-codes an extra row", _edit(ADMIN_TABLE, "</tbody>", "<tr><td>Grafana Labs</td></tr></tbody>")),
    ("admin CSV drops the DPA column", _edit(ADMIN_PAGE, ', it.terms_url, it.dpa_url]', ', it.terms_url]')),
    ("admin route fetches a remote list", _edit(ADMIN_ROUTE, "const list = loadSubProcessors();", "const list = await (await fetch('/v1/subprocessors')).json();")),
    ("admin TS mirror diverges from the JSON", _edit(ADMIN_TS, 'dpa_url: "https://plausible.io/dpa"', 'dpa_url: "https://plausible.io/data-policy"')),
    # dates and approvals
    ("invented contract date in the register", _edit(LEGAL, "contract_signed_at: null", 'contract_signed_at: "2026-04-23"')),
    ("extra dated frontmatter field", _edit(LEGAL, '    contract_signed_at: null\n', '    contract_signed_at: null\n    dpa_effective_date: "2026-04-23"\n')),
    ("dated approval prose appended to the register", _append(LEGAL, "Resend contract signed and Legal approved on 2026-04-23.")),
    ("dated claim on a localized trust page", _append(TRUST_PAGES[1], "Contract signed 2026-04-23 for every vendor.")),
    ("dated claim on an explanation page", _append(EXPLANATION_PAGES[0], "All DPAs effective 2026-04-23.")),
    ("dated DPA row in the commitments", _edit(COMMITMENTS, "| Online acceptance date | Not recorded. |", "| Online acceptance date | Not recorded. |\n| DPA effective date | 2026-04-23 |")),
    ("acceptance date stated in the commitments", _edit(COMMITMENTS, "| Online acceptance date | Not recorded. |", "| Online acceptance date | 2026-04-23 |")),
    ("contract date added to the packet", _edit_json(PACKET, lambda d: d.__setitem__("contract_date", "2026-04-23"))),
    ("countersigned date in a displayed admin field", _mirror_admin(lambda d: d["items"][2].__setitem__("role", d["items"][2]["role"] + " (DPA countersigned 2026-04-23)"))),
    ("approval claim in an admin name, mirrored", _mirror_admin(lambda d: d["items"][3].__setitem__("name", d["items"][3]["name"] + " — DPA signed by Legal"))),
    ("dated approval appended to the commitments", _append(COMMITMENTS, "Resend contract signed and Legal approved on 2026-04-23.")),
    ("dated approval appended to a VR record", _append(VR_RECORDS["resend"], "Resend contract signed and Legal approved on 2026-04-23.")),
    ("dated approval appended to a 2026-04 record", _append(APRIL_RECORDS["clerk"], "Clerk DPA countersigned on 2026-04-23.")),
    ("TIA field claims Legal approval", _edit(VR_RECORDS["resend"], "| Schrems II TIA | None recorded. |", "| Schrems II TIA | Approved by Legal |")),
    ("TEMPLATE banner restored on a record", _edit(VR_RECORDS["plausible"], RECORD_BANNER, "> STATUS: TEMPLATE — pending")),
    ("acceptance date stated on a record", _edit(VR_RECORDS["sentry"], "| Online acceptance date | Not recorded. |", "| Online acceptance date | 2026-09-30 |")),
    ("audit date back in the admin JSON", _edit_json(ADMIN_JSON, lambda d: d["items"][1].__setitem__("last_audit", "2026-01-30"))),
    ("signed-DPA count claim in a questionnaire", _edit("marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md", "No countersigned copies exist", "18/19 vendors have a signed DPA")),
    ("stale sub-processor count on a disclosure", _append("marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md", "We have 6 active sub-processors.")),
    ("unshipped notice channel back on the trust page", _edit(TRUST_PAGES[3], "How notices reach you today:", "Register a `subprocessor-changes@` address in tenant settings.\n\nHow notices reach you today:")),
    ("generated page edited by hand", _edit(TRUST_EN, "so this page shows none.", "so this page shows none. Contract signed 2026-04-23.")),
    # bookkeeping
    ("non-claims replaced with fabricated claims", _edit_json(PACKET, lambda d: d.__setitem__("non_claims", ["All contracts signed.", "Legal approved.", "TIA done.", "SOC 2 verified."]))),
    ("VR-7 reopened while its links are confirmed", _edit(REGISTER, "| Owner | 2026-09-24 | Closed |", "| Owner | 2026-09-24 | Open |")),
    ("packet claims done while a link is pending", lambda t: (_replace_link_everywhere(_GITHUB_DPA)(t), _edit_json(PACKET, lambda d: d.__setitem__("status", "complete"))(t))),
    ("packet claims pending while nothing is pending", _edit_json(PACKET, lambda d: d.__setitem__("status", "pending"))),
    ("stale ledger allowlist line", _edit_json(LEDGER, lambda d: d["claim_line_allowlist"].setdefault(LEGAL, []).append({"line": "A line that does not exist.", "reason": "x"}))),
    ("retired blocking category reintroduced", _edit_json(LEDGER, lambda d: d["categories"].__setitem__("pending-b314-repin", "x"))),
    ("superseded banner removed from a DPIA", _edit("legal/dpia/s10-billing-cross-border.md", SUPERSEDED_BANNER, "> **Design note.**")),
)


def mutation_self_test(texts: dict[str, str]) -> int:
    baseline = assess(texts)
    if baseline not in ("open", "done"):
        raise ReviewError(f"unexpected baseline state {baseline}")
    for name, mutate in MUTATIONS:
        changed = copy.deepcopy(texts)
        mutate(changed)
        if changed == texts:
            raise ReviewError(f"self-test mutation changed nothing: {name}")
        try:
            assess(changed)
        except ReviewError:
            continue
        raise ReviewError(f"mutation accepted: {name}")
    # Positive control: a link pending consistently everywhere is a reported
    # blocker (open), not an error; the unmutated tree has no blocker.
    changed = copy.deepcopy(texts)
    _replace_link_everywhere(_GITHUB_DPA)(changed)
    _edit_json(PACKET, lambda d: d.__setitem__("status", "pending"))(changed)
    if assess(changed) != "open" or "github: link pending" not in blockers(changed):
        raise ReviewError("consistent 'link pending' did not derive a reported open blocker")
    if baseline == "done" and blockers(texts):
        raise ReviewError("done state reported with blockers")
    return len(MUTATIONS)


SURFACES_COMPARED = 2 + 1 + 1 + 2 + len(TRUST_PAGES) + len(EXPLANATION_PAGES) + len(VR_RECORDS) + len(APRIL_RECORDS) + len(RENDER_CONTRACTS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expect", choices=("open", "done"), required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        texts = load()
        state = assess(texts)
        mutations = mutation_self_test(texts) if args.self_test else 0
        pending = blockers(texts)
        published = len(published_paths(texts))
    except (OSError, ReviewError) as exc:
        print(f"B-316 instrument error: {exc}", file=sys.stderr)
        return 2
    print(
        f"B-316 {state}: vendors={len(APPROVED)} parsed_surfaces={SURFACES_COMPARED} "
        f"published_files_scanned={published} blockers={len(pending)}"
        + (f" mutations_rejected={mutations}" if args.self_test else "")
    )
    for item in pending:
        print(f"  blocker: {item}")
    if state != args.expect:
        print(f"expected {args.expect}, found {state}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
