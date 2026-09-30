#!/usr/bin/env python3
"""Fail-closed detector for the two active B-154 Markdown instrument claims.

The historical B-154 shell check excluded ``*`` from its anchored character
class.  Both source claims use Markdown emphasis, so the check silently
returned an empty population and could report a false clean result.  This
guard scans active Markdown text after removing formatting markers, while
ignoring fenced code and HTML comments.  Missing claims are an error: deleting
the evidence must not turn an open item into a green result.

This is a local source check only.  It does not amend legal documents, contact
counsel, notify customers, or infer that the documents were executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_b086_d1_residency import VerificationError as B086VerificationError
from verify_b086_d1_residency import verify_readback_record


ROOT = Path(__file__).resolve().parents[1]
DPA = ROOT / "legal/dpa/v1.0.0.en-US.md"
SLA = ROOT / "legal/sla/v1.0.0.md"
B083_RECEIPT = Path("evidence/owner-actions/B-083/byok-real-kms-lifecycle.json")
B046_PROBE = Path("evidence/owner-actions/B-046/object-lock-probe.json")
RESOLUTION = Path("evidence/owner-actions/B-154/prelaunch-claim-resolution.json")
BYOK_DOCS = Path("apps/docs/docs/explanation/security/byok.mdx")
BYOK_MATRIX = Path("compliance/byok-fips-matrix.md")
B086_RESOLUTION = Path("evidence/owner-actions/B-086/d1-residency-resolution.json")
WRANGLER = Path("wrangler.toml")
DOCKERFILE = Path("Dockerfile")
PUBLIC_COPY_PATHS = (
    BYOK_DOCS,
    BYOK_MATRIX,
    Path("legal/dpa-residency-amendment.md"),
    Path("legal/dpa/v1.0.0.en-US.md"),
    Path("legal/dpa/v1.0.0.es-419.md"),
    Path("legal/dpa/v1.0.0.pt-BR.md"),
    Path("legal/privacy-notice/v1.0.0/en-US.md"),
    Path("legal/privacy-notice/v1.0.0/es-MX.md"),
    Path("legal/privacy-notice/v1.0.0/pt-BR.md"),
    Path("legal/privacy-notice/v1.0.0/metadata.yaml"),
    Path("legal/sla/v1.0.0.md"),
    Path("legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md"),
    Path("legal/tia-template.md"),
    Path("docs/customer/dpa-onboarding.md"),
    Path("docs/customer/byok-kill-switch.md"),
    Path("docs/customer/gc-feature-overview.md"),
    Path("legal/breach-notification/gdpr-irish-dpc-template.en.md"),
    Path("legal/breach-notification/lgpd-anpd-template.pt-br.md"),
)


class VerificationError(RuntimeError):
    """The active-claim population is missing or malformed."""


@dataclass(frozen=True)
class Claim:
    label: str
    path: Path
    pattern: re.Pattern[str]


CLAIMS = (
    Claim(
        "dpa_object_lock",
        DPA,
        re.compile(
            r"\b(?:immutable\s+R2\s+with\s+Object\s+Lock|R2\s+Object\s+Lock.{0,60}(?:retention|7\s+years?)|Object\s+Lock.{0,60}(?:7\s+years?|seven\s+years?|7\s+años|7\s+anos|retention|retención|retenção))\b",
            re.IGNORECASE,
        ),
    ),
    Claim(
        "sla_byok_kill_switch",
        SLA,
        re.compile(
            r"\bBYOK\s+kill[-\u2010\u2011\u2012\u2013\u2014]?switch\s+p99\s*[\u2264<]\s*5\s*min\b",
            re.IGNORECASE,
        ),
    ),
)

POLARITY_RE = re.compile(
    r"\b(?:no|not|never|without|cannot|can't|não|nao|does\s+not|doesn't|"
    r"isn't|is\s+not|aren't|are\s+not|unavailable|deferred|"
    r"future(?:[- ]only)?|not\s+guaranteed)\b",
    re.IGNORECASE,
)
SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")


def _active_lines(markdown: str) -> list[tuple[int, str]]:
    """Return active Markdown lines with presentation syntax removed."""
    lines: list[tuple[int, str]] = []
    fenced = False
    html_comment = False
    for line_number, raw in enumerate(markdown.splitlines(), 1):
        stripped = raw.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fenced = not fenced
            continue
        if fenced:
            continue
        line = raw
        if "<!--" in line:
            line = line.split("<!--", 1)[0]
            html_comment = True
        if html_comment:
            if "-->" in raw:
                line = raw.split("-->", 1)[1]
                html_comment = False
            else:
                continue
        # Preserve visible link labels, then remove Markdown emphasis/heading
        # markers.  The claim words remain unchanged regardless of bold/italic
        # presentation, including the current ``**Object Lock**`` form.
        line = re.sub(r"!?(\[([^\]]+)\])\([^)]*\)", r"\2", line)
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = re.sub(r"^\s{0,3}>\s?", "", line)
        line = re.sub(r"[`*_~]", "", line)
        if line.strip():
            lines.append((line_number, line))
    return lines


def _claim_sentence_scope(
    active_lines: list[tuple[int, str]], line_index: int, match: re.Match[str]
) -> str:
    """Return the sentence containing a claim, including wrapped Markdown lines."""
    current = active_lines[line_index][1]
    if current.lstrip().startswith("|"):
        # Markdown table rows are independent claims; never borrow polarity
        # from the row above or below.
        combined = current
        claim_start = match.start()
    else:
        start = line_index
        while start > 0:
            previous_number, previous = active_lines[start - 1]
            if previous_number != active_lines[start][0] - 1:
                break
            if previous.lstrip().startswith("|"):
                break
            start -= 1
        end = line_index
        while end + 1 < len(active_lines):
            next_number, following = active_lines[end + 1]
            if next_number != active_lines[end][0] + 1:
                break
            if following.lstrip().startswith("|"):
                break
            end += 1
        combined = " ".join(line for _number, line in active_lines[start : end + 1])
        claim_start = sum(
            len(line) + 1 for _number, line in active_lines[start:line_index]
        ) + match.start()

    scope_start = 0
    for boundary in SENTENCE_END_RE.finditer(combined, 0, claim_start):
        scope_start = boundary.end()
    scope_end_match = SENTENCE_END_RE.search(combined, claim_start + len(match.group(0)))
    scope_end = scope_end_match.start() if scope_end_match else len(combined)
    return combined[scope_start:scope_end]


def scan_claims(markdown: str, path: Path) -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    active_lines = _active_lines(markdown)
    for claim in CLAIMS:
        if claim.path != path:
            continue
        for line_index, (line_number, line) in enumerate(active_lines):
            for match in claim.pattern.finditer(line):
                # A negated/disclaimed sentence is not evidence of an active
                # positive instrument claim.  Scope the polarity check to the
                # whole sentence containing the claim; a fixed character
                # window would let a long filler string separate ``No`` from
                # the claim and turn a disclaimer into a false positive.
                sentence = _claim_sentence_scope(active_lines, line_index, match)
                if POLARITY_RE.search(sentence):
                    continue
                found.append((claim.label, line_number, line.strip()))
    return found


def verify_texts(dpa_text: str, sla_text: str) -> list[tuple[str, int, str]]:
    """Reject positive claims and require explicit prelaunch limitations."""
    found = scan_claims(dpa_text, DPA) + scan_claims(sla_text, SLA)
    if found:
        details = "; ".join(f"{label}@{line}" for label, line, _text in found)
        raise VerificationError(f"unproved B-154 feature claim is active: {details}")

    dpa_active = " ".join(text for _line, text in _active_lines(dpa_text))
    sla_active = " ".join(text for _line, text in _active_lines(sla_text))
    required_limits = (
        ("Object Lock COMPLIANCE retention", dpa_active),
        ("Seven-year Object Lock retention and storage-enforced immutability are not available or promised", dpa_active),
        ("BYOK key revocation, crypto-erase, and a BYOK kill switch are unavailable", dpa_active),
        ("BYOK unavailable; no kill-switch SLO", sla_active),
    )
    missing = [label for label, source in required_limits if label not in source]
    if missing:
        raise VerificationError(
            "prelaunch B-154 feature limitation is missing: " + ", ".join(missing)
        )
    return found


def verify_capability_state(byok: dict, object_lock: dict, dockerfile: str) -> None:
    """Require the exact current evidence boundary, never a stray 501/NotImplemented."""
    try:
        # B-083 receipt schema v2 structure
        byok_unverified = (
            byok.get("evidence_state") != "VERIFIED"
            and byok.get("lifecycle", {}).get("revoke_restore", {}).get("status") != "PASS"
        )
        probe_not_proven = object_lock.get("classification") not in ("SUPPORTED", "VERIFIED")
    except (KeyError, TypeError, AttributeError):
        raise VerificationError("B-154 capability evidence shape changed; re-review") from None
    if not byok_unverified or not probe_not_proven:
        raise VerificationError("B-154 capability evidence now proves a feature; re-review claims before publishing")

    active = "\n".join(
        line.split("#", 1)[0]
        for line in dockerfile.splitlines()
        if not line.lstrip().startswith("#")
    )
    commands = re.findall(r"(?m)^\s*cargo build\b[^;]*;", active)
    shipped = [
        command for command in commands
        if re.search(r"(?:^|\s)-p\s+corelink-server\b", command)
        and re.search(r"(?:^|\s)--bin\s+corelink-server\b", command)
    ]
    if len(shipped) != 1 or re.findall(r"--features\s+([\w-]+)", shipped[0]) != ["byok-aws-real"]:
        raise VerificationError("B-154 production Dockerfile BYOK feature changed; re-review")



def verify_byok_docs_page(source: str) -> None:
    """A draft banner must never mask current BYOK availability or timing claims."""
    active = " ".join(text for _line, text in _active_lines(source))
    required = (
        "BYOK is not available or offered in CoreLink's prelaunch service.",
        "Runtime lifecycle unverified; not offered",
        "No BYOK kill-switch timing SLO or p99 measurement is offered.",
        "No tier currently offers BYOK.",
        "Legal, Finance, and Security review remains pending.",
    )
    if any(phrase not in active for phrase in required):
        raise VerificationError("BYOK docs page lacks an explicit prelaunch limitation")
    prohibited = (
        r"\bCoreLink Enterprise tenants can supply\b",
        r"\bBYOK is available\b",
        r"\|\s*AWS KMS\s*\|[^\n]*\|\s*Available\s*\|",
        r"(?:within one DEK cache TTL|[≤<]\s*60\s*s)",
        r"\bkill[- ]switch\s+p99\s*[≤<]\s*5\s*min\b",
    )
    if any(re.search(pattern, active, re.IGNORECASE) for pattern in prohibited):
        raise VerificationError("BYOK docs page makes an unproved availability or timing claim")


def verify_byok_matrix_scope(source: str) -> None:
    active = " ".join(text for _line, text in _active_lines(source))
    required = (
        "Provider-module scope, not CoreLink feature availability.",
        "no tier currently offers BYOK.",
        "#1653/#2165",
    )
    if any(phrase not in active for phrase in required):
        raise VerificationError("BYOK module matrix lacks the service-availability boundary")
    if "supported in CoreLink's BYOK enterprise tier" in active:
        raise VerificationError("BYOK module matrix presents proposed providers as offered")


def verify_public_claim_copies(root: Path) -> None:
    for relative in PUBLIC_COPY_PATHS:
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise VerificationError(f"B-154 public copy unreadable: {relative}: {exc}") from exc
        active_claims = scan_claims(source, DPA) + scan_claims(source, SLA)
        if active_claims:
            labels = ", ".join(f"{label}@{line}" for label, line, _text in active_claims)
            raise VerificationError(f"unproved positive claim in {relative}: {labels}")
        if relative == BYOK_DOCS:
            verify_byok_docs_page(source)
        elif relative == BYOK_MATRIX:
            verify_byok_matrix_scope(source)


def verify_prelaunch_document_status(root: Path, overrides: dict[Path, str] | None = None) -> None:
    """Reject operational metadata left behind on internal prelaunch copies."""
    required = {
        Path("legal/dpa/v1.0.0.en-US.md"): (
            'effective_date: null', 'document_status: "PRELAUNCH_INTERNAL_REVIEW_DRAFT"',
            'legal_review_status: "pending"', 'NOT OFFERED, EXECUTED, OR OPERATIVE',
        ),
        Path("legal/dpa/v1.0.0.es-419.md"): (
            'effective_date: null', 'document_status: "PRELAUNCH_INTERNAL_REVIEW_DRAFT"',
            'legal_review_status: "pending"', 'NO OFRECIDO, EJECUTADO NI VIGENTE',
        ),
        Path("legal/dpa/v1.0.0.pt-BR.md"): (
            'effective_date: null', 'document_status: "PRELAUNCH_INTERNAL_REVIEW_DRAFT"',
            'legal_review_status: "pending"', 'NÃO OFERECIDO, EXECUTADO NEM VIGENTE',
        ),
        Path("legal/sla/v1.0.0.md"): (
            'effective_date: null', 'document_status: "PRELAUNCH_INTERNAL_REVIEW_DRAFT"',
            'legal_review_status: "pending"', 'NOT OFFERED, EXECUTED, OR OPERATIVE',
        ),
        Path("legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md"): (
            'effective_date: null', 'PRELAUNCH_INTERNAL_REFERENCE_DRAFT_NOT_INCORPORATED',
            'not a controlling or incorporated customer instrument',
        ),
        Path("legal/privacy-notice/v1.0.0/metadata.yaml"): (
            'published_at: null', 'publication_status: "not_published_prelaunch_internal_review"',
            'status: "pending_pre_ga"',
        ),
    }
    for relative, phrases in required.items():
        if overrides is not None and relative in overrides:
            source = overrides[relative]
        else:
            try:
                source = (root / relative).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise VerificationError(f"prelaunch status source unreadable: {relative}: {exc}") from exc
        missing = [phrase for phrase in phrases if phrase not in source]
        if missing:
            raise VerificationError(f"{relative} has stale/effective metadata or missing prelaunch boundary: {missing}")
        if relative.as_posix().startswith("legal/dpa/v1.0.0.") and 'legal_review_status: "approved"' in source:
            raise VerificationError(f"{relative} retains an approved legal-review status")


def verify_prelaunch_resolution(root: Path) -> None:
    try:
        record = json.loads((root / RESOLUTION).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise VerificationError(f"B-154 prelaunch resolution is unreadable: {exc}") from exc
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise VerificationError("B-154 prelaunch resolution schema changed")
    if record.get("issue") != 2597 or record.get("parent_issue") != 1676:
        raise VerificationError("B-154 prelaunch resolution issue identity changed")
    lifecycle = record.get("lifecycle")
    if not isinstance(lifecycle, dict) or lifecycle.get("service_launched") is not False:
        raise VerificationError("B-154 must record the confirmed prelaunch state")
    for field, expected in (
        ("customers", "NONE_CONFIRMED"),
        ("customer_instruments_executed", "NONE_CONFIRMED"),
        ("customer_notices", "NOT_APPLICABLE_NO_CUSTOMERS"),
        ("enterprise_byok_case_study", "NO_CIRCULATION_CONFIRMED"),
        ("customer_data_migration", "NOT_AUTHORIZED_OR_PERFORMED"),
    ):
        if lifecycle.get(field) != expected:
            raise VerificationError(f"B-154 lifecycle {field} does not match owner-confirmed prelaunch facts")
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise VerificationError("B-154 claim resolutions are missing")
    object_lock = claims.get("object_lock", {})
    byok = claims.get("byok_kill_switch", {})
    if object_lock.get("capability_status") != "UNPROVEN" or object_lock.get("provider_classification") != "INDETERMINATE":
        raise VerificationError("B-154 Object Lock receipt no longer has the unproven boundary")
    synthetic = object_lock.get("synthetic_aws_provider_proof")
    if not isinstance(synthetic, dict) or synthetic != {
        "status": "PROVEN_FOR_ONE_NONPRODUCTION_SYNTHETIC_VERSION_ONLY",
        "receipt": "https://github.com/HuGR-dev/corelink-server/issues/1877#issuecomment-5917836175",
        "probe_run": 36741245684,
        "digest_reconciliation_run": 36742484737,
        "retention": "ONE_DAY_COMPLIANCE_WITH_LEGAL_HOLD_ON",
        "production_runtime": "NOT_ENABLED_OR_PROVEN",
        "seven_year_guarantee": "NOT_ESTABLISHED",
    }:
        raise VerificationError("B-154 synthetic AWS proof scope drifted")
    if byok.get("capability_status") != "UNPROVEN" or byok.get("revoke_restore") != "NOT_EXECUTED" or byok.get("p99_measurement") != "NOT_MEASURED":
        raise VerificationError("B-154 BYOK lifecycle/p99 boundary changed; re-review claims")
    if byok.get("public_copy") != {
        "path": BYOK_DOCS.as_posix(),
        "state": "PRELAUNCH_LIMITATION_NOT_OFFERED",
        "provider_module_scope": "NOT_CORELINK_SERVICE_CAPABILITY",
    }:
        raise VerificationError("B-154 BYOK docs source or limitation drifted")
    if record.get("provider_chains_closed") is not False or record.get("status") != "OPEN_PENDING_OBJECT_LOCK_BYOK_PROVIDER_EVIDENCE_AND_COUNSEL_REVIEW":
        raise VerificationError("B-154 provider or counsel chain must remain open")
    d1 = claims.get("d1_residency")
    if not isinstance(d1, dict):
        raise VerificationError("B-154 shared-D1 owner resolution is missing")
    try:
        b086 = json.loads((root / B086_RESOLUTION).read_text(encoding="utf-8"))
        wrangler_text = (root / WRANGLER).read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        raise VerificationError(f"B-154 B-086 evidence input is unreadable: {exc}") from exc
    try:
        verify_readback_record(b086, wrangler_text)
    except B086VerificationError as exc:
        raise VerificationError(f"B-154 relies on invalid B-086 provider evidence: {exc}") from exc
    b086_sources = b086.get("source_sha256", {})
    if not isinstance(b086_sources, dict) or b086_sources.get("wrangler.toml") != hashlib.sha256(wrangler_text.encode("utf-8")).hexdigest():
        raise VerificationError("B-154 B-086 receipt is not bound to the current Wrangler source")
    b086_hash = hashlib.sha256((root / B086_RESOLUTION).read_bytes()).hexdigest()
    if (
        d1.get("source_record") != B086_RESOLUTION.as_posix()
        or d1.get("source_sha256") != b086_hash
        or d1.get("provider_target") != "corelink-prod-d1"
        or d1.get("provider_database_id") != "d64742ea-e102-40b2-a844-ff02e3f94562"
        or d1.get("physical_location") != "NOT_INFERRED_FROM_PROVIDER_METADATA"
        or d1.get("transfer_basis") != "PENDING_COUNSEL_REVIEW"
        or d1.get("data_migration") != "NONE"
        or d1.get("active_workers_verified") != 5
        or d1.get("active_config_db_bindings_match") is not True
        or d1.get("technical_posture_owner") != "root; not a legal approval"
        or d1.get("provider_readback_at") != b086.get("provider_readback", {}).get("captured_at")
        or d1.get("active_bindings_readback_at") != b086.get("deployed_active_readback", {}).get("captured_at")
    ):
        raise VerificationError("B-154 D1 owner resolution, source hash, or physical-location boundary drifted")
    hashes = record.get("source_sha256")
    if not isinstance(hashes, dict):
        raise VerificationError("B-154 frozen source hashes are missing")
    for relative in PUBLIC_COPY_PATHS:
        expected = hashes.get(relative.as_posix())
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise VerificationError(f"B-154 public copy missing or non-regular: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise VerificationError(f"B-154 frozen clause bytes changed: {relative}")

def verify_repository_state(root: Path = ROOT) -> None:
    sources = (B083_RECEIPT, B046_PROBE, RESOLUTION, DOCKERFILE)
    for relative in sources:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise VerificationError(f"B-154 source missing or non-regular: {relative}")
    try:
        byok = json.loads((root / B083_RECEIPT).read_text(encoding="utf-8"))
        object_lock = json.loads((root / B046_PROBE).read_text(encoding="utf-8"))
        dockerfile = (root / DOCKERFILE).read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        raise VerificationError(f"B-154 source unreadable or malformed: {exc}") from exc
    verify_capability_state(byok, object_lock, dockerfile)
    verify_public_claim_copies(root)
    verify_prelaunch_document_status(root)
    verify_prelaunch_resolution(root)


def _must_reject(dpa_text: str, sla_text: str, label: str) -> None:
    try:
        verify_texts(dpa_text, sla_text)
    except VerificationError:
        return
    raise AssertionError(f"B-154 negative mutation unexpectedly passed: {label}")


def self_test(dpa_text: str, sla_text: str) -> None:
    """Exercise missing-limit and unsupported-positive-claim negative controls."""
    verify_texts(dpa_text, sla_text)
    verify_prelaunch_document_status(ROOT)
    dpa_path = Path("legal/dpa/v1.0.0.en-US.md")
    current_dpa = (ROOT / dpa_path).read_text(encoding="utf-8")
    try:
        verify_prelaunch_document_status(ROOT, {dpa_path: current_dpa.replace('legal_review_status: "pending"', 'legal_review_status: "approved"', 1)})
    except VerificationError:
        pass
    else:
        raise AssertionError("B-154 status negative mutation unexpectedly passed: approved DPA metadata")
    _must_reject(
        dpa_text + "\nAudit events are retained in immutable R2 with Object Lock for 7 years.\n",
        sla_text,
        "positive-object-lock-claim-added",
    )
    _must_reject(
        dpa_text,
        sla_text + "\nBYOK kill-switch p99 ≤ 5 min is guaranteed.\n",
        "positive-byok-slo-added",
    )
    _must_reject(
        dpa_text.replace(
            "Seven-year Object Lock retention and storage-enforced immutability are not available or promised.",
            "Seven-year Object Lock retention and storage-enforced immutability may apply.",
        ),
        sla_text,
        "object-lock-limitation-weakened",
    )
    _must_reject(
        dpa_text,
        sla_text.replace("BYOK unavailable; no kill-switch SLO", "BYOK enabled; kill-switch SLO applies"),
        "byok-limitation-weakened",
    )
    b086 = json.loads((ROOT / B086_RESOLUTION).read_text(encoding="utf-8"))
    wrangler_text = (ROOT / WRANGLER).read_text(encoding="utf-8")
    for label, mutate in (
        ("missing D1 readback", lambda value: value.pop("provider_readback", None)),
        ("stale D1 readback", lambda value: value["provider_readback"].update(captured_at="2000-01-01T00:00:00Z")),
        ("physical location inferred", lambda value: value["provider_readback"].update(physical_location_conclusion="PHYSICAL_LOCATION_GUARANTEED")),
        ("wrong active D1 binding", lambda value: value["deployed_active_readback"]["active_workers"][0].update(CONFIG_DB_database_id="00000000-0000-4000-8000-000000000000")),
    ):
        mutated = json.loads(json.dumps(b086))
        mutate(mutated)
        try:
            verify_readback_record(mutated, wrangler_text)
        except B086VerificationError:
            continue
        raise AssertionError(f"B-154 D1 evidence mutation unexpectedly passed: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="run in-memory negative mutations")
    args = parser.parse_args()
    try:
        dpa_text = DPA.read_text(encoding="utf-8")
        sla_text = SLA.read_text(encoding="utf-8")
        found = verify_texts(dpa_text, sla_text)
        verify_repository_state()
        if args.self_test:
            self_test(dpa_text, sla_text)
    except (OSError, UnicodeError, VerificationError, AssertionError) as exc:
        print(f"FAIL: B-154 active claim verifier: {exc}", file=sys.stderr)
        return 1
    suffix = "; positive-claim mutations rejected" if args.self_test else ""
    print(f"B-154 prelaunch limits verified: Object Lock and BYOK unavailable/unproven{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
