#!/usr/bin/env python3
"""Fail-closed state gate for the four pending sub-processor Legal reviews."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
LEGAL = "legal/sub-processors.md"
REGISTER = "specs/_compliance/VENDOR-RISK-REGISTER.md"
ACTION_PACKET = "docs/handoff/2026-09-06-b316-vendor-legal-review.json"
COMMITMENTS = "legal/dpa/SUB-PROCESSOR-COMMITMENTS.md"
TEMPLATE_BANNER = (
    "> STATUS: TEMPLATE — pending the actual legal review record "
    "(owner/counsel to complete)."
)


@dataclass(frozen=True)
class Vendor:
    vendor_id: str
    risk_action: str
    due: str
    artifact: str


VENDORS = (
    Vendor("resend", "VR-6", "2026-09-23", "docs/compliance/vendor-reviews/resend-dpa-review-2026-09.md"),
    Vendor("sentry", "VR-7", "2026-09-24", "docs/compliance/vendor-reviews/sentry-dpa-review-2026-09.md"),
    Vendor("plausible", "VR-8", "2026-09-24", "docs/compliance/vendor-reviews/plausible-dpa-review-2026-09.md"),
    Vendor("betterstack", "VR-9", "2026-09-24", "docs/compliance/vendor-reviews/betterstack-dpa-review-2026-09.md"),
)
EXPECTED_IDS = {vendor.vendor_id for vendor in VENDORS}
COMMITMENT_NAMES = {
    "Cloudflare, Inc.": "cloudflare",
    "Clerk, Inc.": "clerk",
    "Resend, Inc.": "resend",
    "Stripe, Inc.": "stripe",
    "GitHub, Inc.": "github",
    "PagerDuty, Inc.": "pagerduty",
    "Functional Software, Inc. (Sentry)": "sentry",
    "Plausible Insights OÜ (Plausible Analytics)": "plausible",
    "Better Stack, Inc. (BetterStack / Statuspage)": "betterstack",
    "Neon, Inc. *(optional / tenant-selectable Postgres)*": "neon",
}
CURRENT_COMMITMENT_IDS = ("cloudflare", "clerk", "stripe", "neon")
REQUIRED_COMMITMENT_IDS = (
    "cloudflare", "clerk", "resend", "stripe", "github", "sentry",
    "plausible", "betterstack",
)
EXPECTED_AUTHORITY = "Legal"
EXPECTED_NON_CLAIMS = (
    "Packet existence is not a signature or executed DPA.",
    "TEMPLATE records are not completed Legal reviews.",
    "Public vendor policy pages are not execution evidence.",
    "No SOC 2 or transfer assessment is inferred.",
)


class ReviewError(ValueError):
    pass


def _require_approved_population(ids: list[str], source: str) -> None:
    if set(ids) != set(REQUIRED_COMMITMENT_IDS) or len(ids) != len(REQUIRED_COMMITMENT_IDS):
        raise ReviewError(f"{source} population is not the exact approved eight")


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _frontmatter(text: str) -> dict[str, Any]:
    if not text.startswith("---\n"):
        raise ReviewError("legal register has no leading frontmatter")
    try:
        _, body, _ = text.split("---", 2)
        parsed = yaml.safe_load(body)
    except (ValueError, yaml.YAMLError) as exc:
        raise ReviewError(f"invalid legal frontmatter: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReviewError("legal frontmatter is not a mapping")
    return parsed


def _packet(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text, object_pairs_hook=_json_no_duplicates)
    except (json.JSONDecodeError, ReviewError) as exc:
        raise ReviewError(f"invalid B-316 action packet: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReviewError("B-316 action packet is not an object")
    return parsed


def _processor_ids(processors: Any) -> list[str]:
    if not isinstance(processors, list):
        raise ReviewError("sub_processors is not a list")
    ids: list[str] = []
    for index, item in enumerate(processors):
        if not isinstance(item, dict):
            raise ReviewError(f"sub-processor entry {index} is not a mapping")
        vendor_id = item.get("id")
        if not isinstance(vendor_id, str) or not vendor_id.strip():
            raise ReviewError(f"sub-processor entry {index} has no valid id")
        ids.append(vendor_id)
    if len(ids) != len(set(ids)):
        raise ReviewError("legal disclosure has duplicate sub-processor ids")
    return ids


def _is_calendar_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if normalized.startswith("`") and normalized.endswith("`"):
        normalized = normalized[1:-1]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", normalized):
        return False
    try:
        date.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def _table_fields(text: str, artifact: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\| ([^|]+?) \| (.*?) \|", line)
        if not match or match.group(1) in ("Field", "---"):
            continue
        key, value = match.group(1).strip(), match.group(2).strip()
        if key in fields:
            raise ReviewError(f"{artifact}: duplicate field {key!r}")
        fields[key] = value
    required = {
        "Vendor", "Sub-processor id", "Review date", "Reviewer", "DPA reference",
        "DPA status", "SCC / transfer mechanism", "Schrems II TIA",
        "Data categories processed", "Data residency / region",
        "Sub-processor flow-down", "Certifications verified", "Review outcome",
        "Conditions / follow-ups", "Next review due",
    }
    if set(fields) != required:
        raise ReviewError(
            f"{artifact}: review field population mismatch: "
            f"missing={sorted(required - set(fields))}, extra={sorted(set(fields) - required)}"
        )
    return fields


def _risk_row(register: str, vendor: Vendor) -> tuple[str, str, str]:
    matches = []
    for line in register.splitlines():
        if line.startswith(f"| {vendor.risk_action} |"):
            columns = [part.strip() for part in line.strip().strip("|").split("|")]
            if len(columns) == 5:
                matches.append((columns[1], columns[2], columns[3], columns[4]))
    if len(matches) != 1:
        raise ReviewError(f"{vendor.risk_action}: expected one five-column action row")
    action, owner, due, status = matches[0]
    if owner != "Legal" or due != vendor.due:
        raise ReviewError(f"{vendor.risk_action}: owner/due drifted")
    if f"`{vendor.artifact}`" not in action:
        raise ReviewError(f"{vendor.risk_action}: canonical artifact is not named")
    return action, owner, status


def _commitment_ids(text: str) -> tuple[str, ...]:
    names = re.findall(r"^### 1\.\d+ (.+)$", text, re.MULTILINE)
    unknown = [name for name in names if name not in COMMITMENT_NAMES]
    if unknown:
        raise ReviewError(f"unknown effective-commitment headings: {unknown}")
    ids = tuple(COMMITMENT_NAMES[name] for name in names)
    if len(ids) != len(set(ids)):
        raise ReviewError("duplicate effective-commitment vendor")
    return ids


def assess(texts: dict[str, str]) -> str:
    legal = _frontmatter(texts[LEGAL])
    processors = legal.get("sub_processors")
    processor_ids = _processor_ids(processors)
    by_id = {item["id"]: item for item in processors}
    if not EXPECTED_IDS.issubset(by_id):
        raise ReviewError("one or more B-316 vendors are absent from legal register")

    packet = _packet(texts[ACTION_PACKET])
    if packet.get("schema_version") != 1 or packet.get("backlog_id") != "B-316":
        raise ReviewError("B-316 packet identity/schema drifted")
    if packet.get("authority") != EXPECTED_AUTHORITY:
        raise ReviewError("B-316 packet authority drifted")
    if packet.get("non_claims") != list(EXPECTED_NON_CLAIMS):
        raise ReviewError("B-316 packet non-claims drifted")
    entries = packet.get("vendors")
    if not isinstance(entries, dict) or set(entries) != EXPECTED_IDS:
        raise ReviewError("B-316 packet vendor population is not exact")
    related = packet.get("related_owner_backlog")
    if related != {
        "vendor_review_cadence_and_Drata_access": "B-032",
        "GDPR_Sigstore_transfer_table_disposition": "B-314",
    }:
        raise ReviewError("B-316 packet lost its B-032/B-314 ownership boundaries")
    effective = packet.get("effective_legal_text")
    if not isinstance(effective, dict):
        raise ReviewError("B-316 packet has no effective-legal-text disposition")
    commitment_ids = _commitment_ids(texts[COMMITMENTS])
    register = texts[REGISTER]
    vendor_states: list[str] = []
    for vendor in VENDORS:
        entry = entries[vendor.vendor_id]
        if not isinstance(entry, dict) or set(entry) != {"risk_action", "due", "artifact", "action"}:
            raise ReviewError(f"{vendor.vendor_id}: action-packet fields drifted")
        if entry["risk_action"] != vendor.risk_action or entry["due"] != vendor.due or entry["artifact"] != vendor.artifact:
            raise ReviewError(f"{vendor.vendor_id}: action-packet authority drifted")
        if not isinstance(entry["action"], str) or "Legal" not in entry["action"]:
            raise ReviewError(f"{vendor.vendor_id}: action is not assigned to Legal")

        disclosure = by_id[vendor.vendor_id]
        if disclosure.get("legal_review_evidence") != vendor.artifact:
            raise ReviewError(f"{vendor.vendor_id}: legal evidence path drifted")
        document = texts.get(vendor.artifact)
        if document is None:
            raise ReviewError(f"{vendor.vendor_id}: canonical review artifact is missing")
        fields = _table_fields(document, vendor.artifact)
        if fields["Sub-processor id"] != f"`{vendor.vendor_id}`":
            raise ReviewError(f"{vendor.vendor_id}: packet id disagrees with disclosure")
        _, _, risk_status = _risk_row(register, vendor)

        pending_markers = (
            TEMPLATE_BANNER in document,
            disclosure.get("contract_signed_at") is None,
            fields["Review date"] == "`TBD (YYYY-MM-DD)`",
            fields["Reviewer"] == "`TBD (named Legal Counsel / Privacy Officer)`",
            fields["Review outcome"] == "`TBD (approved / approved-with-conditions / rejected)`",
            risk_status == "Open",
        )
        if all(pending_markers):
            if vendor.risk_action not in fields["DPA status"] or vendor.risk_action not in fields["Conditions / follow-ups"]:
                raise ReviewError(f"{vendor.vendor_id}: pending packet lost its risk-action link")
            vendor_states.append("open")
            continue

        completed_markers = (
            TEMPLATE_BANNER not in document,
            _is_calendar_date(disclosure.get("contract_signed_at")),
            _is_calendar_date(fields["Review date"]),
            _is_calendar_date(fields["Next review due"]),
            all("TBD" not in value for value in fields.values()),
            risk_status == "Closed",
        )
        if all(completed_markers):
            vendor_states.append("done")
            continue
        raise ReviewError(f"{vendor.vendor_id}: mixed pending/completed state fails closed")

    if commitment_ids == CURRENT_COMMITMENT_IDS:
        commitments_state = "open"
        current_effective = {
            "artifact": COMMITMENTS,
            "current_active_ids": list(CURRENT_COMMITMENT_IDS),
            "required_active_ids": list(REQUIRED_COMMITMENT_IDS),
            "stale_extra_ids": ["neon"],
            "missing_ids": ["resend", "github", "sentry", "plausible", "betterstack"],
            "decision": "Legal must approve and version the effective commitments text; this remediation does not edit it.",
            "status": "pending_external",
        }
        if effective != current_effective:
            raise ReviewError("B-316 pending effective-legal-text packet drifted")
    elif commitment_ids == REQUIRED_COMMITMENT_IDS:
        commitments_state = "done"
        if (
            effective.get("artifact") != COMMITMENTS
            or effective.get("current_active_ids") != list(REQUIRED_COMMITMENT_IDS)
            or effective.get("required_active_ids") != list(REQUIRED_COMMITMENT_IDS)
            or effective.get("stale_extra_ids") != []
            or effective.get("missing_ids") != []
            or effective.get("status") != "approved"
            or not isinstance(effective.get("decision"), str)
            or "Legal" not in effective["decision"]
        ):
            raise ReviewError("B-316 approved effective-legal-text packet is incomplete")
    else:
        raise ReviewError("effective commitments are neither the recorded residue nor the approved target")
    any_completed = any(value == "done" for value in vendor_states)
    all_completed = all(value == "done" for value in vendor_states)
    if any_completed and (not all_completed or commitments_state != "done"):
        raise ReviewError("B-316 cannot mix completed vendor reviews with pending reviews or commitments")
    if commitments_state == "done" and not all_completed:
        raise ReviewError("B-316 cannot approve commitments before all four vendor reviews are complete")
    state = (
        "done"
        if all(value == "done" for value in vendor_states) and commitments_state == "done"
        else "open"
    )
    if state == "done":
        _require_approved_population(processor_ids, "completed legal disclosure")
    if packet.get("status") != ("complete" if state == "done" else "pending_external"):
        raise ReviewError(f"B-316 action packet status disagrees with derived {state} state")
    return state


def load(root: Path = ROOT) -> dict[str, str]:
    paths = [LEGAL, REGISTER, ACTION_PACKET, COMMITMENTS, *(vendor.artifact for vendor in VENDORS)]
    result: dict[str, str] = {}
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ReviewError(f"missing/non-regular B-316 input: {relative}")
        result[relative] = path.read_text(encoding="utf-8")
    return result


def mutation_self_test(texts: dict[str, str]) -> None:
    if assess(texts) != "open":
        raise ReviewError("canonical pending fixture is not open")
    mutations: list[dict[str, str]] = []
    for mutate in (
        lambda value: value.replace(TEMPLATE_BANNER, "> STATUS: APPROVED", 1),
        lambda value: value.replace("contract_signed_at: null", 'contract_signed_at: "2026-09-06"', 1),
    ):
        changed = copy.deepcopy(texts)
        target = VENDORS[0].artifact if len(mutations) == 0 else LEGAL
        changed[target] = mutate(changed[target])
        mutations.append(changed)
    changed = copy.deepcopy(texts)
    changed[REGISTER] = changed[REGISTER].replace("| Legal | 2026-09-23 | Open |", "| Legal | 2026-09-23 | Closed |", 1)
    mutations.append(changed)
    changed = copy.deepcopy(texts)
    packet = _packet(changed[ACTION_PACKET])
    del packet["vendors"]["resend"]
    changed[ACTION_PACKET] = json.dumps(packet)
    mutations.append(changed)
    changed = copy.deepcopy(texts)
    changed[LEGAL] = changed[LEGAL].replace(VENDORS[0].artifact, "docs/compliance/vendor-reviews/wrong.md", 1)
    mutations.append(changed)
    changed = copy.deepcopy(texts)
    changed[COMMITMENTS] = changed[COMMITMENTS].replace("### 1.4 Neon, Inc.", "### 1.4 Unknown Vendor", 1)
    mutations.append(changed)
    changed = copy.deepcopy(texts)
    changed[COMMITMENTS] = changed[COMMITMENTS].replace(
        "### 1.4 Neon, Inc.", "### 1.4 PagerDuty, Inc.", 1
    )
    mutations.append(changed)
    changed = copy.deepcopy(texts)
    packet = _packet(changed[ACTION_PACKET])
    packet["authority"] = "Automated"
    changed[ACTION_PACKET] = json.dumps(packet)
    mutations.append(changed)
    for index in range(len(EXPECTED_NON_CLAIMS)):
        changed = copy.deepcopy(texts)
        packet = _packet(changed[ACTION_PACKET])
        packet["non_claims"][index] = f"Drifted non-claim {index + 1}."
        changed[ACTION_PACKET] = json.dumps(packet)
        mutations.append(changed)
    for index, changed in enumerate(mutations, 1):
        try:
            assess(changed)
        except ReviewError:
            continue
        raise ReviewError(f"mutation {index} was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", choices=("open", "done"), required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        texts = load()
        state = assess(texts)
        if args.self_test:
            mutation_self_test(texts)
    except (OSError, ReviewError) as exc:
        print(f"B-316 instrument error: {exc}", file=sys.stderr)
        return 2
    print(f"B-316 {state}: vendors=4 pending={4 if state == 'open' else 0}")
    if state != args.expect:
        print(f"expected {args.expect}, found {state}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
