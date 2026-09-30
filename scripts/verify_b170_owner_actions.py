#!/usr/bin/env python3
"""Semantic guard for the canonical prelaunch B-170 reconciliation packet.

This guard checks repository assertions against an explicit input contract and
admits the merged #2597 source while keeping provider follow-ups pending. It does
not authenticate GitHub references or prove provider behavior.
"""

from __future__ import annotations

import argparse
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = Path("reports/owner-actions/b170-prelaunch-reconciliation.md")
LABEL = re.compile(r"^- \*\*(?P<key>[^*]+):\*\*\s*(?P<value>.+)$", re.MULTILINE)
SHA = re.compile(r"\b[0-9a-f]{40}\b")
ISSUE_URLS = {
    "d1_receipt": re.compile(
        r"https://github\.com/HuGR-dev/corelink-server/issues/1654#issuecomment-\d+"
    ),
}
D1_RECEIPT = "https://github.com/HuGR-dev/corelink-server/issues/1654#issuecomment-5916652829"
D1_SOURCE_REVISION = "99468014e84b9c68d5446c931b5c3dfd4b9e247c"
B154_ISSUE = "https://github.com/HuGR-dev/corelink-server/issues/2597"


@dataclass(frozen=True)
class InputContract:
    """Facts frozen by the parent; receipt-specific values bind at publication."""

    d1_topology: str = "shared"
    d1_claim: str = "shared D1 control-plane; not tenant-pinned"
    object_lock_status: str = "limited"
    byok_status: str = "limited"
    lifecycle: str = "prelaunch"
    customers: str = "none"
    circulation: str = "none"
    notices: str = "none"
    pagerduty: str = "excluded; deferred"
    b154_state: str = "merged source; provider follow-ups pending"
    b154_source_reference: str = "https://github.com/HuGR-dev/corelink-server/pull/2807"
    b154_source_revision: str = "f2ab5d43b1f7a5dc691f30e0cae419155b4643c5"
    b154_source_date: str = "2026-09-30"
    b154_provider_followups: str = (
        "#1646 Object Lock availability pending; "
        "#1653/#2165 BYOK lifecycle and p99 pending"
    )


class PacketError(RuntimeError):
    """The packet is missing, stale, contradictory, or overclaims evidence."""


def _fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in LABEL.finditer(text):
        key = match.group("key").strip().lower().replace(" ", "_")
        if key in fields:
            raise PacketError(f"duplicate packet field: {key}")
        fields[key] = match.group("value").strip()
    return fields


def validate_packet(text: str, contract: InputContract = InputContract()) -> dict[str, str]:
    """Validate prelaunch facts and bind source inputs only after the #2597 merge."""

    fields = _fields(text)
    required = {
        "lifecycle": contract.lifecycle,
        "customers": contract.customers,
        "questionnaire_circulation": contract.circulation,
        "customer_notice": contract.notices,
        "pagerduty": contract.pagerduty,
        "d1_topology": contract.d1_topology,
        "d1_claim": contract.d1_claim,
        "object_lock_claim": contract.object_lock_status,
        "byok_claim": contract.byok_status,
    }
    for key, expected in required.items():
        actual = fields.get(key)
        if actual is None:
            raise PacketError(f"missing packet field: {key}")
        if actual.casefold() != expected.casefold():
            raise PacketError(f"{key} contradicts frozen input contract: {actual!r}")

    b154_state = fields.get("b154_state")
    if b154_state is None:
        raise PacketError("missing packet field: b154_state")
    if b154_state.casefold() != contract.b154_state.casefold():
        raise PacketError("b154_state contradicts the current #2597 merge admission")
    if fields.get("d1_receipt") != D1_RECEIPT:
        raise PacketError("d1_receipt is not the accepted terminal #1654 receipt")
    if fields.get("d1_source_revision") != D1_SOURCE_REVISION:
        raise PacketError("d1 source revision is stale or does not match merged #1654 source")
    if fields.get("d1_source_date") != "2026-09-30":
        raise PacketError("d1 source date does not match the terminal #1654 outcome")
    if fields.get("b154_issue") != B154_ISSUE:
        raise PacketError("B-154 input must identify native issue #2597")
    if fields.get("object_lock_boundary") != "seven-year unavailable/not promised; one-day synthetic proof only":
        raise PacketError("Object Lock boundary overstates or loses the accepted #2597 WP1 scope")
    if fields.get("byok_boundary") != "unavailable; no kill-switch SLO":
        raise PacketError("BYOK boundary overstates or loses the accepted #2597 WP1 scope")
    if fields.get("b154_provider_followups") != contract.b154_provider_followups:
        raise PacketError("B-154 provider follow-ups do not match frozen source outcomes")
    if contract.b154_state.casefold().startswith("awaiting #2597 source merge"):
        for key in ("b154_source_reference", "b154_source_revision", "b154_source_date"):
            if fields.get(key) != getattr(contract, key):
                raise PacketError(f"pending B-154 input must match frozen {key}")
    else:
        source = fields.get("b154_source_reference", "")
        if not re.fullmatch(r"https://github\.com/HuGR-dev/corelink-server/pull/\d+", source):
            raise PacketError("merged B-154 source must cite its actual PR")
        if not SHA.fullmatch(fields.get("b154_source_revision", "")):
            raise PacketError("merged B-154 source revision must be a full commit SHA")
        if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", fields.get("b154_source_date", "")):
            raise PacketError("merged B-154 source date must be an ISO date")
        for key in (
            "b154_source_reference",
            "b154_source_revision",
            "b154_source_date",
        ):
            if fields.get(key) != getattr(contract, key):
                raise PacketError(f"B-154 input does not match frozen {key}")

    if re.search(r"\b(customer|recipient|notice)\s*[:=]\s*[1-9]\d*\b", text, re.IGNORECASE):
        raise PacketError("packet invents a customer, recipient, or notice count")
    return fields


def _read_packet_without_symlinks(root: Path) -> str:
    current = root
    parts = PACKET.parts
    try:
        for index, part in enumerate(parts):
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise PacketError(f"canonical packet path contains a symlink: {current}")
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise PacketError(f"canonical packet parent is not a directory: {current}")
        if not stat.S_ISREG(metadata.st_mode):
            raise PacketError(f"canonical B-170 packet is not a regular file: {PACKET}")
        return current.read_text(encoding="utf-8")
    except PacketError:
        raise
    except (OSError, UnicodeError) as exc:
        raise PacketError(f"cannot read canonical B-170 packet: {PACKET}: {exc}") from exc


def verify(root: Path = ROOT, contract: InputContract = InputContract()) -> dict[str, object]:
    text = _read_packet_without_symlinks(root)
    if not text.strip():
        raise PacketError(f"canonical B-170 packet is empty: {PACKET}")
    fields = validate_packet(text, contract)
    admitted = fields.get("b154_state", "").casefold().startswith("merged source")
    return {
        "status": "source_admitted_provider_followups_pending" if admitted else "awaiting_2597_source_merge",
        "source_inputs_admitted": admitted,
        "closure_ready": False,
        "fields": sorted(fields),
        "non_claim": "GitHub references and provider outcomes are not authenticated by this repository guard.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = verify(Path(args.root).resolve())
    except PacketError as exc:
        print(f"B-170 packet invalid: {exc}", file=sys.stderr)
        return 2
    if args.json:
        import json

        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "source_admitted_provider_followups_pending":
            print("B-170 source inputs are admitted; provider follow-ups remain pending")
        else:
            print("B-170 awaits the accurate merged #2597 source reconciliation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
