#!/usr/bin/env python3
"""Fail-closed contract for the approved B-314 four-locale reconciliation.

The signed prelaunch decision selects remove_sigstore_row for the four
customer-data transfer tables. This verifier has done-state polarity: it exits
zero only while all four tables match the exact approved row, the evidence and
handoff agree with the signed decision, and the bounded CI workflow remains
credentialless and exact-head.

Only the GDPR transfer-table truth is in scope.  This does not delete or judge
``cosign-sign.yml`` and does not decide the B-005/B-112/B-118 keep-versus-retire
branch.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

LOCALES = (
    "apps/docs/docs/explanation/privacy/gdpr.mdx",
    "apps/docs/i18n/de/docusaurus-plugin-content-docs/current/explanation/privacy/gdpr.mdx",
    "apps/docs/i18n/es-419/docusaurus-plugin-content-docs/current/explanation/privacy/gdpr.mdx",
    "apps/docs/i18n/pt-BR/docusaurus-plugin-content-docs/current/explanation/privacy/gdpr.mdx",
)
TRUST = "apps/docs/docs/trust/subprocessors.mdx"
GENERATOR = "scripts/gen-public-subprocessors.py"
LEGAL_REGISTER = "legal/sub-processors.md"
VENDOR_REGISTER = "specs/_compliance/VENDOR-RISK-REGISTER.md"
PACKET = "docs/handoff/2026-09-06-b314-gdpr-sigstore-transfer.json"
EVIDENCE = "evidence/owner-actions/B-314/gdpr-sigstore-transfer-decision.json"
BACKLOG = "BACKLOG.md"
WORKFLOW = ".github/workflows/issue-2602-b314-reconcile.yml"
TEST = "tests/test_verify_b314_gdpr_sigstore.py"
DECISION_REFERENCE = "https://github.com/HuGR-dev/corelink-server/issues/2601#issuecomment-5854794010"
EFFECTIVE_TIMESTAMP = "2026-09-27T09:48:32Z"
NOTICE_VERSION = "B-314-prelaunch-2026-09-27"
CHECKOUT_ACTION = "uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
EMAIL_REGEX_EXPRESSION = 're.compile(r"[A-Z0-9._%+-]+" + chr(64) + r"[A-Z0-9.-]+\\.[A-Z]{2,}", re.IGNORECASE)'

TABLE_HEADING = "| Recipient | Country | Mechanism | What's transferred |"
CANONICAL_ROW = "| PagerDuty / GitHub | US | DPF + SCC + sub-processor-specific posture | Operational metadata; no end-user PII |"
PRE_DECISION_ROW = "| PagerDuty / GitHub / Sigstore | US | DPF + SCC + sub-processor-specific posture | Operational metadata; no end-user PII |"
ROW_PREFIX = re.compile(
    r"^\|\s*PagerDuty\s*/\s*GitHub(?:\s*/\s*Sigstore)?\s*\|\s*US\s*\|"
    r"\s*DPF\s*\+\s*SCC\s*\+\s*sub-processor-specific posture\s*\|"
    r"\s*Operational metadata;\s*no end-user PII\s*\|\s*$",
    re.IGNORECASE,
)
REQUIRED_PACKET_FIELDS = {
    "schema_version",
    "finding",
    "status",
    "owner",
    "non_claim",
    "scope",
    "baseline",
    "decision",
    "owner_action",
    "evidence",
    "retry_and_rollback",
    "references",
}
EXPECTED_LOCALES = list(LOCALES)
EXPECTED_CHANGED_PATHS = (
    *LOCALES,
    PACKET,
    EVIDENCE,
    BACKLOG,
    "scripts/verify_b314_gdpr_sigstore.py",
    TEST,
    WORKFLOW,
)
EXPECTED_WIRING = (*LOCALES, TRUST, GENERATOR, LEGAL_REGISTER, VENDOR_REGISTER, PACKET, EVIDENCE, BACKLOG, TEST)


class VerificationError(RuntimeError):
    """Raised when a target is absent, ambiguous, or no longer open."""


def _read(root: Path, path: str, overrides: dict[str, str]) -> str:
    if path in overrides:
        value = overrides[path]
        if not isinstance(value, str):
            raise VerificationError(f"override for {path} is not text")
        return value
    target = root / path
    try:
        if target.is_symlink() or not target.is_file():
            raise VerificationError(f"missing/non-regular target: {path}")
        return target.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerificationError(f"cannot read target: {path}") from exc


def _load_packet(text: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"packet contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, VerificationError) as exc:
        raise VerificationError(f"invalid B-314 packet JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("B-314 packet root must be an object")
    return value


def _require_text(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise VerificationError(f"B-314 packet field {key!r} is missing or empty")
    return value


def _check_packet(packet: dict[str, Any]) -> None:
    if set(packet) != REQUIRED_PACKET_FIELDS:
        missing = sorted(REQUIRED_PACKET_FIELDS - set(packet))
        extra = sorted(set(packet) - REQUIRED_PACKET_FIELDS)
        raise VerificationError(f"B-314 packet fields differ: missing={missing}, extra={extra}")
    if packet.get("schema_version") != 1:
        raise VerificationError("B-314 packet schema_version must be 1")
    for key in ("finding", "status", "owner", "non_claim", "retry_and_rollback"):
        _require_text(packet, key)
    if packet["finding"] != "B-314" or packet["owner"] != "gmhelmold":
        raise VerificationError("B-314 packet identity/owner drifted")
    if packet["status"] != "decision-applied":
        raise VerificationError("B-314 packet does not record the applied signed decision")
    for marker in (
        "does not claim Sigstore receives no operational metadata",
        "does not claim release-signing flows ceased",
        "does not infer a Sigstore transfer basis",
    ):
        if marker not in packet["non_claim"]:
            raise VerificationError(f"B-314 packet lost non-claim: {marker}")
    scope = packet["scope"]
    if not isinstance(scope, dict) or set(scope) != {"question", "population", "out_of_scope"}:
        raise VerificationError("B-314 scope must name the exact population and out-of-scope work")
    if scope["population"] != EXPECTED_LOCALES:
        raise VerificationError("B-314 scope population is not exactly the four GDPR locales")
    if not isinstance(scope["question"], str) or "Sigstore" not in scope["question"]:
        raise VerificationError("B-314 scope question lost the Sigstore decision")
    if not isinstance(scope["out_of_scope"], list) or not all(isinstance(v, str) for v in scope["out_of_scope"]):
        raise VerificationError("B-314 out_of_scope must be a list of strings")
    out = " ".join(scope["out_of_scope"])
    for marker in ("B-005", "B-112", "B-118", "cosign-sign.yml", "retire", "keep"):
        if marker not in out:
            raise VerificationError(f"B-314 scope does not fence out {marker}")

    baseline = packet["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "row_count_per_locale", "row_identity", "reviewed_source_revision", "posture_sources"
    }:
        raise VerificationError("B-314 baseline schema drifted")
    if (
        baseline["row_count_per_locale"] != 1
        or baseline["row_identity"] != "PagerDuty / GitHub / Sigstore"
        or baseline["reviewed_source_revision"] != "897efed958a36c3e1b34a5104c21906071ca44af"
    ):
        raise VerificationError("B-314 baseline does not pin the reviewed pre-decision row")
    if baseline["posture_sources"] != [TRUST, GENERATOR, LEGAL_REGISTER, VENDOR_REGISTER]:
        raise VerificationError("B-314 baseline posture sources drifted")

    decision = packet["decision"]
    decision_fields = {
        "state", "allowed_outcomes", "selected_outcome", "reviewers", "reviewer_model",
        "receipt_reference", "effective_timestamp", "notice_version", "notice_determination",
    }
    if not isinstance(decision, dict) or set(decision) != decision_fields:
        raise VerificationError("B-314 decision schema drifted")
    if (
        decision["state"] != "complete"
        or decision["allowed_outcomes"] != ["remove_sigstore_row", "retain_and_document_transfer"]
        or decision["selected_outcome"] != "remove_sigstore_row"
    ):
        raise VerificationError("B-314 does not record the one approved remove_sigstore_row outcome")
    expected_reviewers = [
        {"identity": "gmhelmold", "authority": "Legal Counsel"},
        {"identity": "gmhelmold", "authority": "DPO"},
    ]
    if decision["reviewers"] != expected_reviewers or decision["reviewer_model"] != (
        "One person exercising both functions; not two independent signers."
    ):
        raise VerificationError("B-314 reviewer identities/dual-role model drifted")
    if (
        decision["receipt_reference"] != DECISION_REFERENCE
        or decision["effective_timestamp"] != EFFECTIVE_TIMESTAMP
        or decision["notice_version"] != NOTICE_VERSION
        or "No individual notice or re-consent is required" not in decision["notice_determination"]
    ):
        raise VerificationError("B-314 signed receipt, effective time, or notice decision drifted")

    action = packet["owner_action"]
    if not isinstance(action, list) or len(action) != 4 or not all(isinstance(v, str) for v in action):
        raise VerificationError("B-314 owner_action must contain four recorded completion steps")
    if not action[0].startswith("RECEIPT:") or not action[1].startswith("RUN:") or not action[2].startswith("NOTICE:") or not action[3].startswith("VERIFY:"):
        raise VerificationError("B-314 owner_action completion boundaries drifted")
    for marker in ("Legal Counsel", "DPO", "four", "PagerDuty", "GitHub", "effective timestamp", "non-claims"):
        if marker not in " ".join(action):
            raise VerificationError(f"B-314 owner action lost {marker}")

    evidence = packet["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"path", "format", "required_fields", "completion_rule"}:
        raise VerificationError("B-314 evidence schema drifted")
    if evidence["path"] != EVIDENCE or evidence["format"] != "json":
        raise VerificationError("B-314 evidence path/format drifted")
    required = evidence["required_fields"]
    if not isinstance(required, list) or required != [
        "schema_version", "captured_at", "decision", "legal_reviewer", "dpo_reviewer",
        "notice_version", "transfer_basis", "recipient_scope", "data_category_scope",
        "approved_notice_wording", "published_diff", "signed_artifact_sha256_or_reference",
        "effective_timestamp",
    ]:
        raise VerificationError("B-314 evidence required fields drifted")
    if not isinstance(evidence["completion_rule"], str) or any(
        marker not in evidence["completion_rule"]
        for marker in ("four exact", "signed remove_sigstore_row intent", "preserve PagerDuty and GitHub", "effective timestamp")
    ):
        raise VerificationError("B-314 evidence completion rule is not decision-bound")
    refs = packet["references"]
    if not isinstance(refs, list) or not all(isinstance(v, str) for v in refs):
        raise VerificationError("B-314 references must be a list of strings")
    if any(path not in refs for path in ("BACKLOG.md#B-314", DECISION_REFERENCE, EVIDENCE, TRUST, GENERATOR, LEGAL_REGISTER, VENDOR_REGISTER)):
        raise VerificationError("B-314 references omit the signed decision, evidence, or posture source")


def _check_evidence(evidence: dict[str, Any]) -> None:
    required_keys = {
        "schema_version", "captured_at", "decision", "legal_reviewer", "dpo_reviewer",
        "notice_version", "transfer_basis", "recipient_scope", "data_category_scope",
        "approved_notice_wording", "published_diff", "signed_artifact_sha256_or_reference",
        "effective_timestamp",
    }
    if set(evidence) != required_keys or evidence.get("schema_version") != 1:
        raise VerificationError("B-314 signed-decision evidence fields/schema drifted")
    if not re.fullmatch(r"2026-09-27T\d{2}:\d{2}:\d{2}Z", str(evidence["captured_at"])):
        raise VerificationError("B-314 evidence captured_at must be a UTC timestamp")
    if evidence["decision"] != {
        "outcome": "remove_sigstore_row",
        "scope": "Only the Sigstore recipient text in the four GDPR customer-data transfer tables.",
        "reviewed_source_revision": "897efed958a36c3e1b34a5104c21906071ca44af",
    }:
        raise VerificationError("B-314 evidence decision differs from the signed receipt")
    reviewer_fields = (
        ("legal_reviewer", "Legal Counsel"),
        ("dpo_reviewer", "DPO"),
    )
    for key, authority in reviewer_fields:
        reviewer = evidence[key]
        if not isinstance(reviewer, dict) or reviewer != {
            "identity": "gmhelmold",
            "authority": authority,
            "signature_reference": DECISION_REFERENCE,
            "signer_relationship": (
                "Same person and GitHub identity as the DPO reviewer; not an independent second signer."
                if key == "legal_reviewer"
                else "Same person and GitHub identity as the Legal Counsel reviewer; not an independent second signer."
            ),
        }:
            raise VerificationError(f"B-314 {authority} reviewer identity/reference drifted")
    if evidence["notice_version"] != NOTICE_VERSION or evidence["effective_timestamp"] != EFFECTIVE_TIMESTAMP:
        raise VerificationError("B-314 notice version/effective timestamp drifted")
    if evidence["transfer_basis"] is not None:
        raise VerificationError("B-314 removal decision must not invent a Sigstore transfer basis")
    expected_recipient_scope = {
        "table_scope": "Customer-data international-transfer disclosure only.",
        "removed_recipient": "Sigstore",
        "preserved_recipients": ["PagerDuty", "GitHub"],
        "non_claim": "Sigstore continues in CoreLink-owned artifact signing/provenance flows; this decision does not assert those flows ceased or that Sigstore receives no operational metadata or personal data universally.",
    }
    if evidence["recipient_scope"] != expected_recipient_scope:
        raise VerificationError("B-314 recipient scope or non-claim drifted")
    if evidence["data_category_scope"] != (
        "This decision covers only the customer-data transfer-table row and makes no universal absence claim about operational metadata, transparency-log entries, or personal data in any Sigstore flow."
    ):
        raise VerificationError("B-314 data-category scope broadened beyond the signed decision")
    if evidence["approved_notice_wording"] != (
        "No individual notice or re-consent is required for this prelaunch correction because there are no customers and all four GDPR pages remain drafts not approved for publication."
    ):
        raise VerificationError("B-314 notice/re-consent determination drifted")
    expected_diff = {
        "reviewed_intent": "Remove only / Sigstore from the Recipient cell; preserve every other row field and all other table rows.",
        "files": list(LOCALES),
        "before": PRE_DECISION_ROW.removeprefix("| ").removesuffix(" |"),
        "after": CANONICAL_ROW.removeprefix("| ").removesuffix(" |"),
        "preserved_fields": [
            "Country: US",
            "Mechanism: DPF + SCC + sub-processor-specific posture",
            "What's transferred: Operational metadata; no end-user PII",
        ],
    }
    if evidence["published_diff"] != expected_diff:
        raise VerificationError("B-314 four-locale diff intent is not exact")
    if evidence["signed_artifact_sha256_or_reference"] != DECISION_REFERENCE:
        raise VerificationError("B-314 signed artifact reference drifted")


def _check_backlog(backlog: str) -> None:
    fence = chr(96) * 3
    match = re.search(
        rf"(?ms)^### B-314 — .*?^{fence}backlog\n(?P<body>.*?)^{fence}",
        backlog,
    )
    if match is None:
        raise VerificationError("BACKLOG.md is missing the B-314 block")
    block = match.group("body")
    if not re.search(r"(?m)^status: done$", block):
        raise VerificationError("BACKLOG B-314 is not in done state")
    normalized = " ".join(block.split())
    for marker in (
        "remove_sigstore_row",
        DECISION_REFERENCE,
        EFFECTIVE_TIMESTAMP,
        NOTICE_VERSION,
        "preserve PagerDuty and GitHub",
        "does not assert",
        "no individual notice or re-consent",
        "scripts/verify_b314_gdpr_sigstore.py",
        EVIDENCE,
        "release-signing flows ceased",
    ):
        if marker not in normalized:
            raise VerificationError(f"BACKLOG B-314 omitted completed decision detail: {marker}")


def _check_locale(path: str, text: str) -> None:
    lines = text.splitlines()
    heading_indexes = [i for i, line in enumerate(lines) if line.strip() == TABLE_HEADING]
    if len(heading_indexes) != 1:
        raise VerificationError(f"{path}: expected one transfer-table heading, found {len(heading_indexes)}")
    start = heading_indexes[0]
    table_tail = lines[start + 1 :]
    table_end = next((i for i, line in enumerate(table_tail) if line.startswith("## ")), len(table_tail))
    table_rows = [line for line in table_tail[:table_end] if line.startswith("|")]
    recipient_rows = [line for line in table_rows if "PagerDuty / GitHub" in line]
    if len(recipient_rows) != 1 or recipient_rows[0] != CANONICAL_ROW:
        raise VerificationError(f"{path}: recipient row is not the exact approved value: {recipient_rows!r}")
    if any("sigstore" in line.lower() for line in table_rows):
        raise VerificationError(f"{path}: Sigstore was restored in the customer-data transfer table")
    if ROW_PREFIX.fullmatch(recipient_rows[0]) is None:
        raise VerificationError(f"{path}: approved recipient row mechanism/categories drifted")


def _check_posture(trust: str, generator: str, legal_register: str, vendor_register: str) -> None:
    # These four files are the measured posture chain. The wording is deliberately
    # scoped to current data flows: the old absolute "never receives customer
    # data" claim would also cover a future transparency-log consumer and is not
    # accepted as a substitute for this reality-bound statement.
    required = (
        "Sigstore (Linux Foundation)",
        "no customer-data path is wired",
        "transparency-log seam is not a live transport",
        "not a customer-data sub-processor",
    )
    for label, text in (
        (TRUST, trust),
        (GENERATOR, generator),
        (LEGAL_REGISTER, legal_register),
        (VENDOR_REGISTER, vendor_register),
    ):
        # Markdown prose is routinely wrapped at a line boundary. Compare a
        # whitespace-folded view so a valid wrapped disclaimer is not rejected.
        # The contractual register names the same recipient as
        # ``The Linux Foundation (Sigstore)``; the public/register sources use
        # ``Sigstore (Linux Foundation)``. Both are exact, unambiguous names.
        folded = " ".join(text.split())
        identity = (
            "The Linux Foundation (Sigstore)"
            if label == LEGAL_REGISTER
            else required[0]
        )
        for marker in (identity, *required[1:]):
            if marker not in folded:
                raise VerificationError(f"{label}: scoped posture marker missing: {marker}")
    folded_trust = " ".join(trust.split())
    if not any(
        marker in folded_trust
        for marker in (
            "publishes no records",
            "no Fulcio certificate or Rekor entry was issued",
        )
    ):
        raise VerificationError(f"{TRUST}: proposed/non-live no-records marker missing")
    folded_generator = " ".join(generator.split())
    if "release-SLSA and CAS signing paths" not in folded_generator:
        raise VerificationError(f"{GENERATOR}: source scope no-customer-data marker missing")


def _check_runtime(workflow: str) -> None:
    if CHECKOUT_ACTION not in workflow:
        raise VerificationError(f"{WORKFLOW}: checkout action must be pinned to the approved full commit SHA")
    if len(re.findall(r"^  pull_request:$", workflow, re.MULTILINE)) != 1:
        raise VerificationError(f"{WORKFLOW}: expected one unprivileged pull_request trigger")
    for event in ("pull_request_target", "push", "schedule", "workflow_dispatch"):
        if re.search(rf"^  {event}:", workflow, re.MULTILINE):
            raise VerificationError(f"{WORKFLOW}: forbidden {event} trigger")
    trigger = re.search(r"(?ms)^  pull_request:\n(?P<body>.*?)(?=^permissions:)", workflow)
    if trigger is None:
        raise VerificationError(f"{WORKFLOW}: pull_request trigger block is malformed")
    path_match = re.search(r"(?ms)^    paths:\n(?P<body>(?:^      - \"[^\"]+\"\n)+)", trigger.group("body"))
    if path_match is None:
        raise VerificationError(f"{WORKFLOW}: exact path filter is missing")
    path_lines = [line.strip()[3:-1] for line in path_match.group("body").splitlines()]
    if path_lines != list(EXPECTED_CHANGED_PATHS):
        raise VerificationError(f"{WORKFLOW}: path filter differs from the frozen owned-file set")
    if "**" in path_match.group("body") or "*" in path_match.group("body"):
        raise VerificationError(f"{WORKFLOW}: wildcard path admission is forbidden")
    if "permissions:\n  contents: read\n" not in workflow:
        raise VerificationError(f"{WORKFLOW}: contents must be read-only")
    if "runs-on: ubuntu-24.04" not in workflow or "self-hosted" in workflow:
        raise VerificationError(f"{WORKFLOW}: runner must be GitHub-hosted ubuntu-24.04")
    if "secrets." in workflow or "id-token: write" in workflow or "deployment:" in workflow:
        raise VerificationError(f"{WORKFLOW}: secrets, deployment, or provider authority is forbidden")
    head_ref = "ref: " + "$" + "{{ github.event.pull_request.head.sha }}"
    head_repo = "repository: " + "$" + "{{ github.event.pull_request.head.repo.full_name }}"
    if workflow.count(head_ref) != 1:
        raise VerificationError(f"{WORKFLOW}: checkout must pin the exact pull-request head SHA")
    if workflow.count(head_repo) != 1:
        raise VerificationError(f"{WORKFLOW}: checkout must use the pull-request head repository")
    if "persist-credentials: false" not in workflow:
        raise VerificationError(f"{WORKFLOW}: checkout credentials must not persist")
    command = "python3 -S scripts/verify_b314_gdpr_sigstore.py --self-test"
    if sum(line.strip() in (command, f"run: {command}") for line in workflow.splitlines()) != 1:
        raise VerificationError(f"{WORKFLOW}: expected one B-314 self-test")
    pytest_command = f"python3 -m pytest -q {TEST}"
    if sum(line.strip() in (pytest_command, f"run: {pytest_command}") for line in workflow.splitlines()) != 1:
        raise VerificationError(f"{WORKFLOW}: expected one focused B-314 pytest command")
    if "pytest==8.4.2" not in workflow:
        raise VerificationError(f"{WORKFLOW}: focused pytest dependency must be pinned")
    for marker in ("github.event.pull_request.base.sha", '"--name-only"', '"--unified=0"', "expected_paths = [", "sorted(changed_paths) != sorted(expected_paths)"):
        if marker not in workflow:
            raise VerificationError(f"{WORKFLOW}: exact-head/path admission marker missing: {marker}")
    for marker in ("PRIVATE KEY", "gh[pousr]_", "AKIA[0-9A-Z]{16}", EMAIL_REGEX_EXPRESSION, "line[1:]", "lowercase_email_fixture", "pytest_decorator_fixture"):
        if marker not in workflow:
            raise VerificationError(f"{WORKFLOW}: redaction scan is missing marker: {marker}")
    if "test " not in workflow or "git rev-parse HEAD" not in workflow or "HEAD_SHA" not in workflow:
        raise VerificationError(f"{WORKFLOW}: exact checked-out head SHA is not asserted")
    admission_start = workflow.find("expected_paths = [")
    admission_end = workflow.find("]", admission_start)
    if admission_start < 0 or admission_end < 0:
        raise VerificationError(f"{WORKFLOW}: changed-file allowlist is malformed")
    admission = workflow[admission_start : admission_end + 1]
    for path in EXPECTED_CHANGED_PATHS:
        if admission.count(path) != 1:
            raise VerificationError(f"{WORKFLOW}: changed-file admission does not include exactly one {path}")


def verify(root: Path = ROOT, *, overrides: dict[str, str] | None = None) -> None:
    overrides = {} if overrides is None else dict(overrides)
    known = set(LOCALES) | {
        TRUST, GENERATOR, LEGAL_REGISTER, VENDOR_REGISTER, PACKET, EVIDENCE, BACKLOG, WORKFLOW
    }
    unknown = set(overrides) - known
    if unknown:
        raise VerificationError(f"unknown override target(s): {sorted(unknown)}")
    for path in LOCALES:
        _check_locale(path, _read(root, path, overrides))
    _check_posture(
        _read(root, TRUST, overrides),
        _read(root, GENERATOR, overrides),
        _read(root, LEGAL_REGISTER, overrides),
        _read(root, VENDOR_REGISTER, overrides),
    )
    _check_packet(_load_packet(_read(root, PACKET, overrides)))
    _check_evidence(_load_packet(_read(root, EVIDENCE, overrides)))
    _check_backlog(_read(root, BACKLOG, overrides))
    _check_runtime(_read(root, WORKFLOW, overrides))


def _must_reject(label: str, root: Path, overrides: dict[str, str]) -> None:
    try:
        verify(root, overrides=overrides)
    except VerificationError:
        return
    raise VerificationError(f"self-test mutation unexpectedly passed: {label}")


def mutation_checks(root: Path = ROOT) -> int:
    """Exercise row, decision, posture, and runtime restoration mutations."""
    originals = {path: _read(root, path, {}) for path in (*LOCALES, TRUST, GENERATOR, LEGAL_REGISTER, VENDOR_REGISTER, PACKET, EVIDENCE, BACKLOG, WORKFLOW)}
    count = 0
    for path in LOCALES:
        row = next(line for line in originals[path].splitlines() if line == CANONICAL_ROW)
        _must_reject("missing locale row", root, {path: originals[path].replace(row, "", 1)})
        count += 1
        _must_reject("Sigstore restoration", root, {path: originals[path].replace(row, PRE_DECISION_ROW, 1)})
        count += 1
        _must_reject("mechanism mutation", root, {path: originals[path].replace("DPF + SCC + sub-processor-specific posture", "SCC only", 1)})
        count += 1
    _must_reject("decision outcome mutation", root, {PACKET: originals[PACKET].replace('"selected_outcome": "remove_sigstore_row"', '"selected_outcome": "retain_and_document_transfer"', 1)})
    count += 1
    _must_reject("signed receipt reference mutation", root, {EVIDENCE: originals[EVIDENCE].replace("issuecomment-5854794010", "issuecomment-1", 1)})
    count += 1
    _must_reject("backlog done-state mutation", root, {BACKLOG: originals[BACKLOG].replace("status: done", "status: open", 1)})
    count += 1
    _must_reject("backlog signed receipt removal", root, {BACKLOG: originals[BACKLOG].replace(DECISION_REFERENCE, "https://example.invalid/decision", 1)})
    count += 1
    trust_mutation = originals[TRUST].replace("no customer-data path is wired", "customer-data path is wired", 1)
    _must_reject("trust current-flow posture removal", root, {TRUST: trust_mutation})
    count += 1
    generator_mutation = originals[GENERATOR].replace("transparency-log seam is not a live transport", "transparency-log seam is a live transport", 1)
    _must_reject("generator deferred-seam posture removal", root, {GENERATOR: generator_mutation})
    count += 1
    legal_mutation = originals[LEGAL_REGISTER].replace("not a customer-data sub-processor", "a customer-data sub-processor")
    _must_reject("contractual posture restoration", root, {LEGAL_REGISTER: legal_mutation})
    count += 1
    vendor_mutation = originals[VENDOR_REGISTER].replace("no customer-data path is wired", "customer-data path is wired", 1)
    _must_reject("vendor-register current-flow posture removal", root, {VENDOR_REGISTER: vendor_mutation})
    count += 1
    _must_reject("runtime path coverage removal", root, {WORKFLOW: originals[WORKFLOW].replace('      - "' + LOCALES[0] + '"', "", 1)})
    count += 1
    _must_reject("runtime checkout action pin removal", root, {WORKFLOW: originals[WORKFLOW].replace(CHECKOUT_ACTION, "uses: actions/checkout@v7", 1)})
    count += 1
    _must_reject("runtime email redaction pattern removal", root, {WORKFLOW: originals[WORKFLOW].replace("chr(64)", "chr(0)", 1)})
    count += 1
    _must_reject("runtime email scanner plus-prefix handling mutation", root, {WORKFLOW: originals[WORKFLOW].replace("pattern.search(line[1:])", "pattern.search(line)", 1)})
    count += 1
    command = "python3 -S scripts/verify_b314_gdpr_sigstore.py --self-test"
    _must_reject("runtime self-test duplication", root, {WORKFLOW: originals[WORKFLOW].replace(command, command + "\n          " + command, 1)})
    count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run fail-closed mutation checks")
    args = parser.parse_args(argv)
    try:
        verify()
        mutations = mutation_checks() if args.self_test else 0
    except (OSError, VerificationError) as exc:
        print(f"B-314 done-state reconciliation FAIL: {exc}", file=sys.stderr)
        return 1
    suffix = f"; mutations={mutations}" if args.self_test else ""
    print(f"B-314 done-state reconciliation PASS: exact four-locale removal + signed decision evidence{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
