#!/usr/bin/env python3
"""B-316 gate: one approved sub-processor set, linked to each vendor's own
terms and DPA, identical on every surface that lists sub-processors.

Re-chartered by the owner on 2026-10-01 (#2593): CoreLink is a single-owner
company, so B-316 closes on a public sub-processor list that names each vendor
in the approved set and links that vendor's standard terms and DPA, accepted
online at signup. Countersigned contracts and a named Legal reviewer are no
longer required. Dates are never invented: no online-acceptance date is
recorded, so every surface must say so or show none.

The B-316 action packet (``PACKET``) is the expected value. Every surface is
parsed structurally and compared to it; any way of failing to read a surface
is a named error, never an empty pass.

States (``--expect``):
  done  every surface lists exactly the approved eight, each with a confirmed
        https:// terms link and DPA link, all equal to the packet.
  open  the same, except at least one link is the literal "link pending"
        (never a guessed URL) consistently on every surface.
Errors (exit 2): a deferred/stale vendor (PagerDuty, Neon) on any list or
surface; a missing or extra vendor; a missing terms or DPA link; two surfaces
that disagree; a recorded acceptance date, audit date or contract date; a
generated page that drifted from the register; a reopened or half-closed
VR-6..VR-9 action.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import types
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[1]

PACKET = "docs/handoff/2026-09-06-b316-vendor-legal-review.json"
LEGAL = "legal/sub-processors.md"
COMMITMENTS = "legal/dpa/SUB-PROCESSOR-COMMITMENTS.md"
REGISTER = "specs/_compliance/VENDOR-RISK-REGISTER.md"
GENERATOR = "scripts/gen-public-subprocessors.py"
TRUST_EN = "apps/docs/docs/trust/subprocessors.mdx"
LOCALES = ("de", "es-419", "pt-BR")
TRUST_PAGES = (
    TRUST_EN,
    *(f"apps/docs/i18n/{loc}/docusaurus-plugin-content-docs/current/trust/subprocessors.mdx" for loc in LOCALES),
)
EXPLANATION_PAGES = (
    "apps/docs/docs/explanation/compliance/sub-processors.mdx",
    *(
        f"apps/docs/i18n/{loc}/docusaurus-plugin-content-docs/current/explanation/compliance/sub-processors.mdx"
        for loc in LOCALES
    ),
)
ADMIN_JSON = "apps/admin-ui/src/content/sub-processors.json"
ADMIN_TS = "apps/admin-ui/src/content/sub-processors.ts"
ADMIN_TABLE = "apps/admin-ui/src/app/[locale]/privacy/sub-processors/SubProcessorsTable.tsx"
DOCS_LEGAL_PAGE = "apps/docs/src/pages/legal/sub-processors.tsx"
DOCS_REGISTER_PAGE = "apps/docs/src/pages/trust/sub-processor-register.tsx"
JSON_IMPORT = 'from "../../../../admin-ui/src/content/sub-processors.json"'

APPROVED = ("cloudflare", "clerk", "resend", "stripe", "github", "sentry", "plausible", "betterstack")
EXCLUDED = ("pagerduty", "neon")
RISK_ACTIONS = {"resend": "VR-6", "sentry": "VR-7", "plausible": "VR-8", "betterstack": "VR-9"}
RECORDS = {vid: f"docs/compliance/vendor-reviews/{vid}-dpa-review-2026-09.md" for vid in RISK_ACTIONS}
LINK_PENDING = "link pending"

# Every spelling a surface uses for a vendor. A name outside this map on a
# vendor list is an error, so a new vendor cannot slip onto one list alone.
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
EXCLUDED_WORD_RE = re.compile(r"\b(?:pager\s*duty|neon)\b", re.IGNORECASE)
# Surfaces on which a deferred/stale vendor may not appear at all. The
# register and generator are internal and keep PagerDuty as a deferred row.
WORD_BANNED = (
    LEGAL, COMMITMENTS, *TRUST_PAGES, *EXPLANATION_PAGES, ADMIN_JSON, ADMIN_TS,
    ADMIN_TABLE, DOCS_LEGAL_PAGE, DOCS_REGISTER_PAGE, *RECORDS.values(),
)
TRUST_HEADER = "| # | Vendor | Service to CoreLink | Customer-data class | Regions | Terms | DPA |"
EXPLANATION_HEADER = "| Provider | Role | Region | Terms | DPA |"
LEGAL_HEADER = "| ID | Nome | Função | Região | Terms | DPA |"
ADMIN_KEYS = ("id", "name", "role", "region", "certifications", "terms_url", "dpa_url")
PACKET_VENDOR_KEYS = {"name", "terms_url", "dpa_url", "contract_basis", "online_acceptance_date", "record"}
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
# Every surface compared to the packet: legal frontmatter + body table,
# commitments, the register's active subset (through the generator), the admin
# JSON + its TS mirror, each trust/explanation page, each VR record, and the
# three React renderers checked to render the JSON rather than hard-code it.
SURFACES_COMPARED = 2 + 1 + 1 + 2 + len(TRUST_PAGES) + len(EXPLANATION_PAGES) + len(RECORDS) + 3
URL_RE = re.compile(r"https://[^\s<>()\"'|]+")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

Links = dict[str, tuple[str, str]]


class ReviewError(ValueError):
    pass


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


def _angle_value(value: str, field: str, source: str) -> str:
    if value == LINK_PENDING:
        return LINK_PENDING
    match = re.fullmatch(r"<(https://[^>\s]+)>", value)
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


# ---------------------------------------------------------------- surfaces ---

def _packet(texts: dict[str, str]) -> tuple[dict[str, Any], Links]:
    packet = _json(texts[PACKET], PACKET)
    if not isinstance(packet, dict):
        raise ReviewError(f"{PACKET}: not an object")
    if packet.get("schema_version") != 2 or packet.get("backlog_id") != "B-316":
        raise ReviewError(f"{PACKET}: identity/schema drifted")
    if packet.get("authority") != "Owner":
        raise ReviewError(f"{PACKET}: authority is not the owner re-charter")
    recharter = packet.get("recharter")
    if not isinstance(recharter, dict) or any(recharter.get(k) != v for k, v in EXPECTED_RECHARTER.items()):
        raise ReviewError(f"{PACKET}: re-charter reference drifted")
    if packet.get("approved_population") != list(APPROVED):
        raise ReviewError(f"{PACKET}: approved population is not the exact eight")
    excluded = packet.get("excluded_vendors")
    if not isinstance(excluded, dict) or set(excluded) != set(EXCLUDED):
        raise ReviewError(f"{PACKET}: excluded vendors drifted")
    if packet.get("related_owner_backlog") != EXPECTED_RELATED:
        raise ReviewError(f"{PACKET}: lost its B-032/B-314 ownership boundaries")
    non_claims = packet.get("non_claims")
    if not isinstance(non_claims, list) or len(non_claims) < 3 or not all(isinstance(c, str) and c for c in non_claims):
        raise ReviewError(f"{PACKET}: non-claims are missing")
    vendors = packet.get("vendors")
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
        if vendor_id in RISK_ACTIONS and (
            entry["risk_action"] != RISK_ACTIONS[vendor_id] or entry["record"] != RECORDS[vendor_id]
        ):
            raise ReviewError(f"{PACKET}: {vendor_id} risk action/record drifted")
        links = []
        for key in ("terms_url", "dpa_url"):
            value = entry[key]
            if value != LINK_PENDING and not (isinstance(value, str) and URL_RE.fullmatch(value)):
                raise ReviewError(f"{PACKET}: {vendor_id} {key} is neither https:// nor {LINK_PENDING!r}")
            links.append(value)
        expected[vendor_id] = (links[0], links[1])
    return packet, expected


def _legal(texts: dict[str, str], packet: dict[str, Any]) -> tuple[Links, Links]:
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
        if "contract_signed_at" not in entry or entry["contract_signed_at"] is not None:
            raise ReviewError(f"{LEGAL}: {vendor_id} contract_signed_at must be null — no acceptance date is recorded")
        if vendor_id in packet["vendors"] and entry.get("legal_review_evidence") != packet["vendors"][vendor_id]["record"]:
            raise ReviewError(f"{LEGAL}: {vendor_id} evidence path disagrees with the packet")
        terms, dpa = entry.get("terms_url"), entry.get("dpa_url")
        if not isinstance(terms, str) or not isinstance(dpa, str) or not terms or not dpa:
            raise ReviewError(f"{LEGAL}: {vendor_id} lacks a terms_url or dpa_url")
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
        section = text[match.end():end]
        fields: dict[str, str] = {}
        for row in re.findall(r"(?m)^\| ([^|]+?) \| (.+?) \|$", section):
            if row[0] in ("Field", "---"):
                continue
            if row[0] in fields:
                raise ReviewError(f"{COMMITMENTS}: {vendor_id} repeats field {row[0]!r}")
            fields[row[0]] = row[1]
        if "Contract signed" in fields:
            raise ReviewError(f"{COMMITMENTS}: {vendor_id} states a contract-signed date")
        if fields.get("Online acceptance date") != NOT_RECORDED:
            raise ReviewError(f"{COMMITMENTS}: {vendor_id} must say the online acceptance date is {NOT_RECORDED!r}")
        for field in ("Terms reference", "DPA reference"):
            if field not in fields:
                raise ReviewError(f"{COMMITMENTS}: {vendor_id} lacks a {field}")
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


def _register(texts: dict[str, str]) -> Links:
    generator = _generator(texts[GENERATOR])
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
            continue
        if vendor_id is None:
            raise ReviewError(f"{REGISTER}: unknown active vendor {row.vendor!r}")
        links = generator.PUBLIC_LEGAL_LINKS.get(row.vendor)
        if not isinstance(links, tuple) or len(links) != 2:
            raise ReviewError(f"{GENERATOR}: {row.vendor} has no terms/DPA entry")
        pairs.append((vendor_id, (links[0], links[1])))
    deferred_rows = re.findall(r"(?m)^\| PagerDuty, Inc\. \| 9 \| Deferred by the owner", texts[REGISTER])
    if len(deferred_rows) != 1:
        raise ReviewError(f"{REGISTER}: §4c must record PagerDuty (row 9) as deferred exactly once")
    return _collect(pairs, f"{REGISTER} active subset")


def _risk_actions(texts: dict[str, str], expected: Links) -> None:
    for vendor_id, action_id in RISK_ACTIONS.items():
        rows = [
            _cells(line) for line in texts[REGISTER].splitlines() if line.startswith(f"| {action_id} |")
        ]
        if len(rows) != 1 or len(rows[0]) != 5:
            raise ReviewError(f"{REGISTER}: expected one five-column {action_id} row")
        _, action, owner, _, status = rows[0]
        pending = LINK_PENDING in expected[vendor_id]
        want = "Open" if pending else "Closed"
        if owner != "Owner" or status != want:
            raise ReviewError(f"{REGISTER}: {action_id} must be Owner/{want}, found {owner}/{status}")
        if "re-chartered 2026-10-01" not in action or f"`{RECORDS[vendor_id]}`" not in action:
            raise ReviewError(f"{REGISTER}: {action_id} lost its re-charter disposition or record path")


def _records(texts: dict[str, str]) -> Links:
    pairs = []
    for vendor_id, path in RECORDS.items():
        text = texts[path]
        if not text.startswith("# Vendor Contract-Basis Record — ") or RECORD_BANNER not in text:
            raise ReviewError(f"{path}: not a re-chartered contract-basis record")
        if "STATUS: TEMPLATE" in text:
            raise ReviewError(f"{path}: still carries the TEMPLATE banner")
        fields: dict[str, str] = {}
        for key, value in re.findall(r"(?m)^\| ([^|]+?) \| (.*?) \|$", text):
            if key in ("Field", "---"):
                continue
            if key in fields:
                raise ReviewError(f"{path}: duplicate field {key!r}")
            fields[key] = value
        if tuple(fields) != RECORD_FIELDS:
            raise ReviewError(f"{path}: field population drifted: {list(fields)}")
        if fields["Sub-processor id"] != f"`{vendor_id}`":
            raise ReviewError(f"{path}: id disagrees with its file")
        if fields["Online acceptance date"] != NOT_RECORDED:
            raise ReviewError(f"{path}: online acceptance date must be {NOT_RECORDED!r}")
        if fields["Next review due"] != "Not scheduled." or any("TBD" in v for v in fields.values()):
            raise ReviewError(f"{path}: template or invented scheduling fields remain")
        pairs.append((
            vendor_id,
            (
                _angle_value(fields["Terms reference"], "Terms reference", path),
                _angle_value(fields["DPA reference"], "DPA reference", path),
            ),
        ))
    return dict(pairs)


def _markdown_pages(texts: dict[str, str]) -> dict[str, Links]:
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
        count = re.findall(r"sub-processors\*\* table \((\d+) of them\)", texts[path])
        if count != [str(len(APPROVED))]:
            raise ReviewError(f"{path}: active-vendor count sentence disagrees with the approved {len(APPROVED)}")
    for path in EXPLANATION_PAGES:
        pairs = []
        for cells in _table(texts[path], EXPLANATION_HEADER, path):
            vendor_id = _vendor_id(cells[0], path)
            pairs.append((vendor_id, (_link_cell(cells[3], "Terms", path, vendor_id), _link_cell(cells[4], "DPA", path, vendor_id))))
        result[path] = _collect(pairs, path)
    return result


def _admin(texts: dict[str, str]) -> Links:
    data = _json(texts[ADMIN_JSON], ADMIN_JSON)
    if not isinstance(data, dict) or set(data) != {"version", "items"}:
        raise ReviewError(f"{ADMIN_JSON}: top-level shape drifted")
    if not isinstance(data["version"], str) or not DATE_RE.fullmatch(data["version"]):
        raise ReviewError(f"{ADMIN_JSON}: version is not a list date")
    items = data["items"]
    if not isinstance(items, list) or not items:
        raise ReviewError(f"{ADMIN_JSON}: items is not a non-empty list")
    pairs = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or tuple(item) != ADMIN_KEYS:
            # Exact keys: this is also what keeps an audit/acceptance date out.
            raise ReviewError(f"{ADMIN_JSON}: item {index} keys drifted (expected {ADMIN_KEYS})")
        if item["id"] in EXCLUDED:
            raise ReviewError(f"{ADMIN_JSON}: excluded vendor {item['id']!r} is listed")
        if item["id"] not in APPROVED:
            raise ReviewError(f"{ADMIN_JSON}: unknown vendor id {item['id']!r}")
        for key in ("terms_url", "dpa_url"):
            if item[key] != LINK_PENDING and not URL_RE.fullmatch(str(item[key])):
                raise ReviewError(f"{ADMIN_JSON}: {item['id']} {key} is neither https:// nor {LINK_PENDING!r}")
        pairs.append((item["id"], (item["terms_url"], item["dpa_url"])))
    links = _collect(pairs, ADMIN_JSON)

    ts = texts[ADMIN_TS]
    version = re.findall(r'(?m)^  version: (".*"),$', ts)
    blocks = re.findall(r"(?ms)^    \{\n(.*?)^    \},$", ts)
    mirrored = []
    for block in blocks:
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


def _rendered_from_json(texts: dict[str, str], expected: Links) -> None:
    vendor_urls = {url for pair in expected.values() for url in pair if url != LINK_PENDING}
    for path, accessors in (
        (DOCS_LEGAL_PAGE, ("item.terms_url", "item.dpa_url")),
        (DOCS_REGISTER_PAGE, ("sp.terms_url", "sp.dpa_url")),
        (ADMIN_TABLE, ("row.terms_url", "row.dpa_url")),
    ):
        text = texts[path]
        if path != ADMIN_TABLE and text.count(JSON_IMPORT) != 1:
            raise ReviewError(f"{path}: does not render the shared sub-processors.json")
        if any(accessor not in text for accessor in accessors):
            raise ReviewError(f"{path}: does not render each vendor's terms and DPA links")
        hard_coded = sorted(url for url in vendor_urls if url in text)
        if hard_coded:
            raise ReviewError(f"{path}: hard-codes vendor links instead of rendering the JSON: {hard_coded}")
        if "last_audit" in text or re.search(r'dateTime="\d{4}-', text):
            raise ReviewError(f"{path}: shows a per-vendor date")


# ------------------------------------------------------------------ assess ---

def assess(texts: dict[str, str]) -> str:
    for path in WORD_BANNED:
        match = EXCLUDED_WORD_RE.search(texts[path])
        if match:
            raise ReviewError(f"{path}: names excluded vendor {match.group(0)!r}")
    packet, expected = _packet(texts)
    frontmatter, body = _legal(texts, packet)
    surfaces: dict[str, Links] = {
        f"{LEGAL} frontmatter": frontmatter,
        f"{LEGAL} body table": body,
        COMMITMENTS: _commitments(texts),
        f"{REGISTER} active subset via {GENERATOR}": _register(texts),
        ADMIN_JSON: _admin(texts),
        **_markdown_pages(texts),
    }
    for source, links in surfaces.items():
        _compare(source, links, expected)
    records = _records(texts)
    for vendor_id, links in records.items():
        if links != expected[vendor_id]:
            raise ReviewError(f"{RECORDS[vendor_id]}: terms/DPA links disagree with the packet")
    _risk_actions(texts, expected)
    _rendered_from_json(texts, expected)
    state = "open" if any(LINK_PENDING in pair for pair in expected.values()) else "done"
    if packet.get("status") != ("complete" if state == "done" else "pending_links"):
        raise ReviewError(f"{PACKET}: status {packet.get('status')!r} disagrees with derived {state} state")
    return state


def load(root: Path = ROOT) -> dict[str, str]:
    paths = (
        PACKET, LEGAL, COMMITMENTS, REGISTER, GENERATOR, *TRUST_PAGES, *EXPLANATION_PAGES,
        ADMIN_JSON, ADMIN_TS, ADMIN_TABLE, DOCS_LEGAL_PAGE, DOCS_REGISTER_PAGE, *RECORDS.values(),
    )
    result: dict[str, str] = {}
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ReviewError(f"missing/non-regular B-316 input: {relative}")
        result[relative] = path.read_text(encoding="utf-8")
    return result


# --------------------------------------------------------------- self-test ---

def _edit(path: str, old: str, new: str) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        if texts[path].count(old) < 1:
            raise ReviewError(f"self-test mutation did not apply: {path}: {old[:60]!r}")
        texts[path] = texts[path].replace(old, new, 1)
    return apply


def _edit_json(path: str, change: Callable[[Any], None]) -> Callable[[dict[str, str]], None]:
    def apply(texts: dict[str, str]) -> None:
        data = json.loads(texts[path])
        change(data)
        texts[path] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
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

MUTATIONS: tuple[tuple[str, Callable[[dict[str, str]], None]], ...] = (
    ("PagerDuty back in the contractual register", _edit(LEGAL, "\n---\n", "\n" + _LEGAL_PAGERDUTY)),
    ("PagerDuty row on the generated trust page", _edit(TRUST_EN, "| 1 | **Cloudflare", "| 0 | **PagerDuty, Inc.** | x | x | x | [Terms](https://www.pagerduty.com/terms-of-use/) | [DPA](https://www.pagerduty.com/dpa/) |\n| 1 | **Cloudflare")),
    ("Neon section back in the commitments", _edit(COMMITMENTS, "### 1.8 Better Stack", "### 1.8 Neon, Inc.\n\n### 1.9 Better Stack")),
    ("Neon item in the admin JSON", _edit_json(ADMIN_JSON, lambda d: d["items"].append({"id": "neon", "name": "Neon", "role": "db", "region": "US", "certifications": ["x"], "terms_url": "https://neon.tech/terms", "dpa_url": "https://neon.tech/dpa"}))),
    ("PagerDuty named on a localized trust page", _edit(TRUST_PAGES[1], "## Active sub-processors", "## Active sub-processors\n\nPagerDuty")),
    ("PagerDuty no longer deferred by the generator", _edit(GENERATOR, '    "PagerDuty, Inc.": "Deferred by the owner', '    "PagerDuty, Inc. (retired)": "Deferred by the owner')),
    ("vendor DPA link deleted from the admin JSON", _edit_json(ADMIN_JSON, lambda d: d["items"][0].pop("dpa_url"))),
    ("terms link changed on one locale only", _edit(TRUST_PAGES[2], "[Terms](https://sentry.io/terms/)", "[Terms](https://sentry.io/terms-old/)")),
    ("Clerk DPA back to 'on request'", _edit(LEGAL, 'dpa_url: "https://clerk.com/legal/dpa"', 'dpa_url: "Clerk DPA (on request)"')),
    ("invented contract date in the register", _edit(LEGAL, "contract_signed_at: null", 'contract_signed_at: "2026-04-23"')),
    ("audit date back in the admin JSON", _edit_json(ADMIN_JSON, lambda d: d["items"][1].__setitem__("last_audit", "2026-01-30"))),
    ("acceptance date stated in the commitments", _edit(COMMITMENTS, "| Online acceptance date | Not recorded. |", "| Online acceptance date | 2026-04-23 |")),
    ("TEMPLATE banner restored on a record", _edit(RECORDS["plausible"], RECORD_BANNER, "> STATUS: TEMPLATE — pending")),
    ("acceptance date stated on a record", _edit(RECORDS["sentry"], "| Online acceptance date | Not recorded. |", "| Online acceptance date | 2026-09-30 |")),
    ("VR-7 reopened while its links are confirmed", _edit(REGISTER, "| Owner | 2026-09-24 | Closed |", "| Owner | 2026-09-24 | Open |")),
    ("hard-coded vendor row on the docs legal page", _edit(DOCS_LEGAL_PAGE, "</tbody>", '<tr><td><a href="https://sentry.io/legal/dpa/">DPA</a></td></tr></tbody>')),
    ("admin TS mirror diverges from the JSON", _edit(ADMIN_TS, 'dpa_url: "https://plausible.io/dpa"', 'dpa_url: "https://plausible.io/data-policy"')),
    ("vendor dropped from an explanation page", lambda t: t.__setitem__(EXPLANATION_PAGES[3], re.sub(r"(?m)^\| Stripe, Inc\. \|.*\n", "", t[EXPLANATION_PAGES[3]], count=1))),
    ("vendor missing from the packet", _edit_json(PACKET, lambda d: d["vendors"].pop("github"))),
    ("link pending on one surface only", _edit(COMMITMENTS, "| DPA reference | <https://betterstack.com/dpa> |", "| DPA reference | link pending |")),
    ("generated page edited by hand", _edit(TRUST_EN, "so this page shows none.", "so this page shows none. Contract signed 2026-04-23.")),
    ("packet claims done while a link is pending", _replace_link_everywhere("https://github.com/customer-terms/github-data-protection-agreement")),
    ("guessed non-https DPA link", _edit(EXPLANATION_PAGES[0], "[DPA](https://resend.com/legal/dpa)", "[DPA](http://resend.com/dpa)")),
    ("unknown extra vendor on the legal body table", _edit(LEGAL, "| betterstack | Better Stack", "| acme | Acme | x | x | [Terms](https://acme.test/t) | [DPA](https://acme.test/d) |\n| betterstack | Better Stack")),
)


def mutation_self_test(texts: dict[str, str]) -> int:
    if assess(texts) != "done":
        raise ReviewError("canonical tree is not done; the self-test needs the done fixture")
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
    # Positive control: a link pending consistently everywhere is OPEN, not an error.
    changed = copy.deepcopy(texts)
    _replace_link_everywhere("https://github.com/customer-terms/github-data-protection-agreement")(changed)
    _edit_json(PACKET, lambda d: d.__setitem__("status", "pending_links"))(changed)
    if assess(changed) != "open":
        raise ReviewError("consistent 'link pending' did not derive the open state")
    return len(MUTATIONS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expect", choices=("open", "done"), required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        texts = load()
        state = assess(texts)
        mutations = mutation_self_test(texts) if args.self_test else 0
    except (OSError, ReviewError) as exc:
        print(f"B-316 instrument error: {exc}", file=sys.stderr)
        return 2
    _, expected = _packet(texts)
    pending = sum(LINK_PENDING in pair for pair in expected.values())
    print(
        f"B-316 {state}: vendors={len(expected)} surfaces={SURFACES_COMPARED} "
        f"link_pending={pending}" + (f" mutations_rejected={mutations}" if args.self_test else "")
    )
    if state != args.expect:
        print(f"expected {args.expect}, found {state}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
