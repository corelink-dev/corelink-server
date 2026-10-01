#!/usr/bin/env python3
"""Verify the repository-owned half of B-098.

The worktree/branch census in B-098 is intentionally an operator action: it is
machine-local state and must not be used as a CI gate.  This verifier covers the
portable part instead: workspace lint inheritance, the checked-in population
figures in ``CLAUDE.md``, the semver release/tag contract, and the typed
fail-closed release-governance blocker receipt.

An absent semver tag is an honest ``open`` result, not a verifier error.  Any
missing source, malformed count, drift, or malformed release evidence fails
closed.  The verifier never creates, moves, or pushes a tag.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT / "crates/corelink-runbook-tracker/Cargo.toml"
CLAUDE = ROOT / "CLAUDE.md"
PACKET = ROOT / "docs/handoff/2026-09-05-b098-owner-action-packet.md"
TAG_DRAFT = ROOT / "docs/release/v1.0.0-GA-tag-draft-final.txt"
ALLOWED_SIGNERS = ROOT / ".github/release-allowed-signers"
SIGNING_POLICY = ROOT / ".github/release-signing-policy.json"
CUT_SCRIPT = ROOT / "scripts/cut-v1-0-0-ga-tag.sh"
GOVERNANCE_RECEIPT = ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json"
OPS_CENSUS = ROOT / "docs/handoff/2026-09-09-b098-ops-authority-census.md"
CENSUS_RELATIVE = OPS_CENSUS.relative_to(ROOT).as_posix()
CANONICAL_RELEASE_TAG = "v1.0.0-GA"
DUAL_HAT_ADR = "specs/03_architecture/adrs/ADR-0034b-framework-reviewer-dual-hat-fallback.md"
DUAL_HAT_ADR_SHA256 = "0441b8e98f412225d682a36b4f93696a27a980da543d24b6637da373af26da24"
CENSUS_REMOTE_REFS = (
    "refs/tags/v1.0.0-GA*",
    "refs/tags/release-signoff-owner-v1.0.0-GA",
    "refs/tags/release-signoff-ops-v1.0.0-GA",
    "refs/tags/release-evidence-v1.0.0-GA",
)
RECEIPT_FIELDS = {
    "schema_version", "receipt_type", "backlog_id", "captured_at", "checkpoint_sha",
    "status", "release_tag", "repository_hygiene", "release_state", "owner_decisions",
    "blockers", "non_claims", "references", "census_binding",
}
RECEIPT_CENSUS_FIELDS = {
    "path", "sha256", "checkpoint_sha", "provenance", "capture_scope", "remote_status", "timestamp",
}
RECEIPT_HYGIENE_FIELDS = {
    "status", "rust_packages", "crate_directories", "okf_concepts", "specs_full_schema",
    "specs_yaml_only", "specs_total", "lint_policy",
}
RECEIPT_REMOTE_FIELDS = {
    "local_semver_tags", "remote_release_tag_present", "remote_framework_tag_present",
    "remote_evidence_anchor_present", "remote_owner_signoff_anchor_present",
    "remote_ops_signoff_anchor_present",
}
RECEIPT_NON_CLAIMS = (
    "No independent Ops signoff exists.",
    "The GA draft remains a template with unresolved placeholders.",
    "No release tag, deployment, provider action, or remote evidence anchor was created.",
    "A rehearsal or repository census is not production cutover evidence.",
)
RECEIPT_BLOCKERS = {
    "ops-authority", "framework-promotion", "cutover-attestation",
    "deployment-readback", "bundled-ci", "two-key-signoff",
}
RECEIPT_BLOCKER_BINDINGS = {
    "ops-authority": (
        "An independently controlled Ops principal and policy-pinned signing key",
        "docs/handoff/2026-09-09-b098-ops-authority-census.md",
    ),
    "framework-promotion": (
        "A trusted signed framework-v1-0-0-ga tag targeting FROZEN v1.0.0",
        "docs/knowledge/ops/release-process.md",
    ),
    "cutover-attestation": (
        "Executed GREEN cutover evidence bound to the exact release SHA",
        "docs/release/v1.0.0-GA-cutover.template.json",
    ),
    "deployment-readback": (
        "Production readback for all five environments and one OCI digest",
        "docs/release/v1.0.0-GA-deployment.template.json",
    ),
    "bundled-ci": (
        "19-pass CI evidence with release-tree identity",
        "docs/release/v1.0.0-GA-ci.template.json",
    ),
    "two-key-signoff": (
        "Distinct trusted Owner and Ops signed commits bound to the release and evidence digests",
        "docs/release/v1.0.0-GA-signoffs.template.json",
    ),
}
RECEIPT_REFERENCES = {
    "BACKLOG.md#B-098", "scripts/verify_b098_repo_hygiene.py",
    "docs/handoff/2026-09-09-b098-ops-authority-census.md",
    "docs/knowledge/ops/release-process.md", "scripts/cut-v1-0-0-ga-tag.sh",
}
CENSUS_FRONTMATTER_FIELDS = {
    "type", "title", "description", "checkpoint_sha", "provenance",
    "capture_scope", "remote_status", "tags", "timestamp",
}
REMOTE_EVIDENCE_MAX_AGE = datetime.timedelta(hours=24)
OID_PATTERN = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
OID_RE = re.compile(rf"^{OID_PATTERN}$")

MAX_TAG_LENGTH = 256
MAX_CENSUS_BYTES = 1_000_000
MAX_CENSUS_LINE_CHARS = 16_384
PACKAGE_COUNT = re.compile(r"\*\*(\d+) Rust packages\*\*")
CRATE_DIR_COUNT = re.compile(r"directory holds \*\*(\d+)\*\*")
EXTRA_PACKAGE_COUNT = re.compile(r"and (\d+) live under `tests/`, `tools/` and\s*`apps/`", re.MULTILINE)
OKF_COUNT = re.compile(r"\*\*(\d+) OKF concepts\*\*")
SPECS_COUNT = re.compile(
    r"\*\*(\d+) full-schema \+ (\d+) YAML-only \((\d+) total\)"
)

SKIP_ALL = {"_audits", "_archive", "_schemas", "_compliance"}
SKIP_SCHEMA = SKIP_ALL | {"_templates", "_followups"}


class VerificationError(RuntimeError):
    """The verifier could not establish a trustworthy result."""


class DuplicateJSONKey(ValueError):
    """A JSON object repeated a key and therefore cannot be trusted."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_loads(text: str) -> object:
    """Decode JSON recursively while rejecting duplicate keys at every depth."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def _is_oid(value: object) -> bool:
    return isinstance(value, str) and OID_RE.fullmatch(value) is not None


def _valid_numeric_identifier(value: str) -> bool:
    return bool(value) and all("0" <= char <= "9" for char in value) and (value == "0" or not value.startswith("0"))


def _valid_prerelease_identifier(value: str) -> bool:
    if not value or any(not (char.isascii() and (char.isalnum() or char == "-")) for char in value):
        return False
    return not (all("0" <= char <= "9" for char in value) and len(value) > 1 and value.startswith("0"))


def _is_semver_tag(value: str) -> bool:
    """Validate SemVer tags with bounded, linear token checks."""
    if len(value) > MAX_TAG_LENGTH or not value.startswith("v"):
        return False
    core_build = value[1:].split("+", 1)
    if len(core_build) > 2:
        return False
    core_pre = core_build[0].split("-", 1)
    core = core_pre[0].split(".")
    if len(core) != 3 or not all(_valid_numeric_identifier(part) for part in core):
        return False
    if len(core_pre) == 2 and not all(_valid_prerelease_identifier(part) for part in core_pre[1].split(".")):
        return False
    if len(core_build) == 2:
        build = core_build[1].split(".")
        if not all(part and all(char.isascii() and (char.isalnum() or char == "-") for char in part) for part in build):
            return False
    return True


def _extract_census_metadata(census_text: str) -> dict[str, object]:
    """Extract JSON-valued census front matter for cross-artifact binding."""
    if not census_text.startswith("---\n"):
        return {}
    end = census_text.find("\n---\n", 4)
    if end < 0:
        return {}
    metadata: dict[str, object] = {}
    for line in census_text[4:end].splitlines():
        match = re.fullmatch(r"([a-z_]+):\s*(.+)", line)
        if not match:
            continue
        key, raw = match.groups()
        try:
            metadata[key] = _json_loads(raw)
        except (json.JSONDecodeError, DuplicateJSONKey):
            continue
    return metadata


def _parse_timestamp(value: object, label: str, issues: list[str]) -> datetime.datetime | None:
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{label} is missing")
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        issues.append(f"{label} is not RFC3339")
        return None
    if parsed.tzinfo is None:
        issues.append(f"{label} must include a timezone")
        return None
    if parsed > datetime.datetime.now(datetime.timezone.utc):
        issues.append(f"{label} is in the future")
    return parsed


def _check_live_origin(
    root: Path,
    tags: tuple[str, ...],
    *,
    run_command: object | None = None,
) -> list[str]:
    """Read canonical origin with a bounded command and compare release refs exactly."""
    runner = subprocess.run if run_command is None else run_command
    try:
        completed = runner(
            ["git", "ls-remote", "--tags", "--heads", "origin"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return ["B-098 live origin ref check timed out after 10 seconds"]
    except OSError as exc:
        return [f"B-098 live origin ref check could not run: {exc}"]
    if completed.returncode != 0:
        return [f"B-098 live origin ref check failed: {completed.stderr.strip() or 'unknown error'}"]
    refs: set[str] = set()
    seen_refs: set[str] = set()
    issues: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not _is_oid(fields[0]) or not set(fields[0]) - {"0"}:
            issues.append("B-098 live origin ref check returned malformed output")
            continue
        raw_ref = fields[1]
        if not re.fullmatch(r"refs/(?:heads|tags)/[^\s]+(?:\^\{\})?", raw_ref):
            issues.append("B-098 live origin ref check returned malformed output")
            continue
        if raw_ref in seen_refs:
            issues.append(f"B-098 live origin ref check returned duplicate ref: {raw_ref}")
            continue
        seen_refs.add(raw_ref)
        ref = raw_ref.removesuffix("^{}")
        if re.fullmatch(r"refs/tags/v[^/]+", ref) or ref in {
            "refs/tags/framework-v1-0-0-ga",
            "refs/tags/release-evidence-v1.0.0-GA",
            "refs/tags/release-signoff-owner-v1.0.0-GA",
            "refs/tags/release-signoff-ops-v1.0.0-GA",
        }:
            refs.add(ref)
    semver_refs = {
        ref for ref in refs
        if ref.startswith("refs/tags/") and _is_semver_tag(ref.removeprefix("refs/tags/"))
    }
    special_refs = refs - semver_refs
    expected_semver = {f"refs/tags/{tag}" for tag in tags}
    expected_special = {
        "refs/tags/framework-v1-0-0-ga",
        "refs/tags/release-evidence-v1.0.0-GA",
        "refs/tags/release-signoff-owner-v1.0.0-GA",
        "refs/tags/release-signoff-ops-v1.0.0-GA",
    } if CANONICAL_RELEASE_TAG in tags else set()
    if semver_refs != expected_semver:
        issues.append(f"B-098 live origin semver refs mismatch: expected {sorted(expected_semver)}, got {sorted(semver_refs)}")
    if special_refs != expected_special:
        issues.append(f"B-098 live origin release refs mismatch: expected {sorted(expected_special)}, got {sorted(special_refs)}")
    return issues


def _check_census(root: Path, *, census_text: str | None = None) -> list[str]:
    """Validate the signed-off metadata and remote absence boundary of the Ops census."""
    path = root / OPS_CENSUS.relative_to(ROOT)
    if census_text is None:
        if not path.is_file() or path.is_symlink():
            return [f"B-098 Ops authority census is missing: {path.relative_to(root)}"]
        try:
            with path.open("rb") as source_file:
                raw = source_file.read(MAX_CENSUS_BYTES + 1)
        except (OSError, UnicodeDecodeError) as exc:
            return [f"B-098 Ops authority census is unreadable: {exc}"]
        if len(raw) > MAX_CENSUS_BYTES:
            return ["B-098 Ops authority census exceeds bounded input size"]
        try:
            census_text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            return [f"B-098 Ops authority census is unreadable: {exc}"]
    if len(census_text.encode("utf-8")) > MAX_CENSUS_BYTES:
        return ["B-098 Ops authority census exceeds bounded input size"]
    if any(len(line) > MAX_CENSUS_LINE_CHARS for line in census_text.splitlines()):
        return ["B-098 Ops authority census has an overlong line"]
    issues: list[str] = []
    if not census_text.startswith("---\n"):
        return ["B-098 Ops authority census front matter is missing"]
    end = census_text.find("\n---\n", 4)
    if end < 0:
        return ["B-098 Ops authority census front matter is unterminated"]
    frontmatter = census_text[4:end]
    body = census_text[end + len("\n---\n"):]
    metadata: dict[str, object] = {}
    for line in frontmatter.splitlines():
        match = re.fullmatch(r"([a-z_]+):\s*(.+)", line)
        if not match:
            issues.append(f"B-098 census front matter line is malformed: {line}")
            continue
        key, raw = match.groups()
        if key in metadata:
            issues.append(f"B-098 census front matter duplicates {key}")
            continue
        try:
            metadata[key] = _json_loads(raw)
        except (json.JSONDecodeError, DuplicateJSONKey):
            issues.append(f"B-098 census front matter value is not JSON: {key}")
    if set(metadata) != CENSUS_FRONTMATTER_FIELDS:
        issues.append("B-098 census front matter fields are not exact")
    expected_metadata = {
        "type": "Evidence",
        "title": "B-098 Ops authority and key census",
        "description": "Metadata-only census proving that the independent Ops release authority is not yet provisioned.",
        "provenance": "AUTHORED",
        "capture_scope": "current-tree",
        "remote_status": "ABSENT",
        "tags": ["b-098", "release", "ops", "fail-closed", "key-census"],
    }
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            issues.append(f"B-098 census front matter {key} is not the expected value")
    checkpoint = metadata.get("checkpoint_sha", "")
    if not _is_oid(checkpoint) or not set(checkpoint) - {"0"}:
        issues.append("B-098 census checkpoint_sha is missing, malformed, or all-zero")
    else:
        if subprocess.run(["git", "cat-file", "-e", f"{checkpoint}^{{commit}}"], cwd=root, check=False).returncode != 0:
            issues.append("B-098 census checkpoint_sha is not a commit in this repository")
        elif subprocess.run(["git", "merge-base", "--is-ancestor", checkpoint, "HEAD"], cwd=root, check=False).returncode != 0:
            issues.append("B-098 census checkpoint_sha is not ancestral to this checkout")
        if f"checkpoint `{checkpoint}`" not in body:
            issues.append("B-098 census body is not bound to its front-matter checkpoint")
    _parse_timestamp(metadata.get("timestamp"), "B-098 census timestamp", issues)
    for marker in (
        "No independently controlled Ops principal and release-signing key were found.",
        "roles.ops.principal: null",
        "roles.ops.fingerprint: null",
        "`git ls-remote --tags origin` returned no matching refs for:",
        "This is an absence record, not a release authorization.",
    ):
        if marker not in body:
            issues.append(f"B-098 Ops authority census missing fail-closed marker: {marker}")
    object_patterns = {
        "policy": rf"\.github/release-signing-policy\.json.*?git-object\s+({OID_PATTERN})",
        "allowlist": rf"\.github/release-allowed-signers.*?git-object\s+({OID_PATTERN})",
    }
    expected_objects = {
        "policy": ".github/release-signing-policy.json",
        "allowlist": ".github/release-allowed-signers",
    }
    for label, pattern in object_patterns.items():
        match = re.search(pattern, body, re.DOTALL)
        if not match:
            issues.append(f"B-098 census is missing the {label} git-object field")
        else:
            actual = subprocess.run(
                ["git", "hash-object", expected_objects[label]], cwd=root,
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            if not set(match.group(1)) - {"0"} or match.group(1) != actual:
                issues.append(f"B-098 census {label} git-object does not match the checked-in object")
    remote_refs = re.findall(r"^- `([^`]+)`$", body, re.MULTILINE)
    if remote_refs != list(CENSUS_REMOTE_REFS):
        issues.append("B-098 census remote ref list is not the exact expected absence set")
    return issues


def _check_signing_policy(root: Path, *, policy_text: str | None = None) -> list[str]:
    """Validate role/schema shape even while no release tag exists."""
    path = root / SIGNING_POLICY.relative_to(ROOT)
    if policy_text is None:
        if not path.is_file() or path.is_symlink():
            return [f"canonical release role policy is missing: {path.relative_to(root)}"]
        try:
            policy_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [f"canonical release role policy is unreadable: {exc}"]
    try:
        policy = _json_loads(policy_text)
    except (json.JSONDecodeError, DuplicateJSONKey) as exc:
        return [f"canonical release role policy is invalid JSON: {exc}"]
    issues: list[str] = []
    if not isinstance(policy, dict) or set(policy) != {"version", "roles"}:
        return ["canonical release role policy must have exactly version and roles"]
    if policy.get("version") != 1 or not isinstance(policy.get("roles"), dict) or set(policy["roles"]) != {"owner", "ops"}:
        issues.append("canonical release role policy must define exactly owner and ops roles at version 1")
        return issues
    owner = policy["roles"]["owner"]
    ops = policy["roles"]["ops"]
    if not isinstance(owner, dict) or set(owner) != {"principal", "fingerprint"}:
        issues.append("canonical release owner role fields are not exact")
    elif owner != {
        "principal": "gustavo@humangr.com",
        "fingerprint": "SHA256:grBP7UAeYUlzeyv9oe6TDk1OMADK0QrMOVfaIm9Zbwo",
    }:
        issues.append("canonical release owner role does not match the pinned trust root")
    if not isinstance(ops, dict) or set(ops) != {"principal", "fingerprint"}:
        issues.append("canonical release Ops role fields are not exact")
    elif ops != {"principal": None, "fingerprint": None}:
        issues.append("canonical release Ops role must remain explicitly unprovisioned")
    return issues


def _check_dual_hat_adr(root: Path, decision: dict[str, object], *, adr_text: str | None = None) -> list[str]:
    """Bind the receipt's dual-hat row to the exact, still-uninvoked ADR."""
    adr_path = root / DUAL_HAT_ADR
    if adr_text is None:
        if not adr_path.is_file() or adr_path.is_symlink():
            return ["B-098 dual-hat ADR is missing or not a regular file"]
        try:
            adr_text = adr_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [f"B-098 dual-hat ADR is unreadable: {exc}"]
    issues: list[str] = []
    actual_sha = hashlib.sha256(adr_text.encode("utf-8")).hexdigest()
    if decision.get("sha256") != DUAL_HAT_ADR_SHA256 or actual_sha != DUAL_HAT_ADR_SHA256:
        issues.append("B-098 dual-hat ADR hash binding is invalid")
    for marker in ('doc_status: "DRAFT"', "**PROPOSED**", "The Owner MAY invoke a **dual-hat fallback**"):
        if marker not in adr_text:
            issues.append(f"B-098 dual-hat ADR is missing required uninvoked marker: {marker}")
    return issues


def _check_governance_receipt(
    root: Path,
    tags: tuple[str, ...],
    *,
    package_count: int,
    crate_dir_count: int,
    okf_count: int,
    specs_schema_count: int,
    specs_yaml_only_count: int,
    receipt_text: str | None = None,
    census_text: str | None = None,
    verify_origin: bool = False,
) -> list[str]:
    """Require a strict typed blocker instead of silently treating absent evidence as green."""
    path = root / GOVERNANCE_RECEIPT.relative_to(ROOT)
    issues: list[str] = []
    if receipt_text is None:
        if not path.is_file() or path.is_symlink():
            return [f"B-098 release-governance blocker receipt is missing: {path.relative_to(root)}"]
        try:
            receipt_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [f"B-098 release-governance blocker receipt is unreadable: {exc}"]
    try:
        data = _json_loads(receipt_text)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKey) as exc:
        return [f"B-098 release-governance blocker receipt is invalid: {exc}"]
    if not isinstance(data, dict):
        return ["B-098 release-governance blocker receipt root must be an object"]
    if set(data) != RECEIPT_FIELDS:
        issues.append("B-098 release-governance blocker receipt has missing or unexpected top-level fields")
    if data.get("schema_version") != 1 or data.get("receipt_type") != "b098_ga_release_governance_blocker":
        issues.append("B-098 release-governance blocker receipt has the wrong schema")
    if data.get("backlog_id") != "B-098" or data.get("release_tag") != CANONICAL_RELEASE_TAG:
        issues.append("B-098 release-governance blocker receipt is bound to the wrong backlog/release")
    if data.get("status") != "BLOCKED":
        issues.append("B-098 release-governance blocker receipt must remain BLOCKED until external gates exist")
    captured_at = _parse_timestamp(data.get("captured_at"), "receipt captured_at", issues)
    # A normal repository audit must be reproducible from the checked-in tree.
    # Wall-clock freshness is only meaningful when the caller explicitly asks
    # for the live origin check; otherwise the result would change every day
    # without a repository change.
    if verify_origin and captured_at is not None and datetime.datetime.now(datetime.timezone.utc) - captured_at > REMOTE_EVIDENCE_MAX_AGE:
        issues.append("B-098 remote absence receipt is stale; run --verify-origin before relying on it")
    checkpoint = data.get("checkpoint_sha", "")
    if not _is_oid(checkpoint) or not set(checkpoint) - {"0"}:
        issues.append("B-098 release-governance blocker receipt lacks a full checkpoint SHA")
    elif subprocess.run(
        ["git", "merge-base", "--is-ancestor", checkpoint, "HEAD"], cwd=root, check=False
    ).returncode != 0:
        issues.append("B-098 release-governance blocker receipt checkpoint is not reachable from this tree")
    census_path = root / CENSUS_RELATIVE
    if census_text is None:
        if not census_path.is_file() or census_path.is_symlink():
            issues.append("B-098 receipt census binding source is missing")
            census_text = ""
        else:
            try:
                census_text = census_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                issues.append(f"B-098 receipt census binding source is unreadable: {exc}")
                census_text = ""
    census_metadata = _extract_census_metadata(census_text)
    census_sha256 = hashlib.sha256(census_text.encode("utf-8")).hexdigest()
    census_checkpoint = census_metadata.get("checkpoint_sha")
    census_timestamp = _parse_timestamp(
        census_metadata.get("timestamp"), "census timestamp bound to receipt", issues
    )
    binding = data.get("census_binding")
    expected_binding = {
        "path": CENSUS_RELATIVE,
        "sha256": census_sha256,
        "checkpoint_sha": census_checkpoint,
        "provenance": census_metadata.get("provenance"),
        "capture_scope": census_metadata.get("capture_scope"),
        "remote_status": census_metadata.get("remote_status"),
        "timestamp": census_metadata.get("timestamp"),
    }
    if not isinstance(binding, dict) or set(binding) != RECEIPT_CENSUS_FIELDS:
        issues.append("B-098 blocker receipt census_binding fields are not exact")
    elif binding != expected_binding:
        issues.append("B-098 blocker receipt census_binding does not match the captured census")
    if checkpoint != census_checkpoint:
        issues.append("B-098 receipt checkpoint_sha must exactly match the census checkpoint_sha")
    if captured_at is not None and census_timestamp is not None and captured_at != census_timestamp:
        issues.append("B-098 receipt captured_at must exactly match the census capture timestamp")
    expected_population = {
        "rust_packages": package_count,
        "crate_directories": crate_dir_count,
        "okf_concepts": okf_count,
        "specs_full_schema": specs_schema_count,
        "specs_yaml_only": specs_yaml_only_count,
        "specs_total": specs_schema_count + specs_yaml_only_count,
    }
    observed_population = data.get("repository_hygiene")
    if not isinstance(observed_population, dict):
        issues.append("B-098 release-governance blocker receipt lacks repository hygiene counts")
    else:
        if set(observed_population) != RECEIPT_HYGIENE_FIELDS:
            issues.append("B-098 blocker receipt repository_hygiene fields are not exact")
        for key, expected in expected_population.items():
            if observed_population.get(key) != expected:
                issues.append(
                    f"B-098 blocker receipt {key}={observed_population.get(key)!r} but repository reports {expected}"
                )
        if observed_population.get("status") != "PASS" or observed_population.get("lint_policy") != "workspace-inherited":
            issues.append("B-098 blocker receipt does not attest the repaired repository hygiene boundary")
    state = data.get("release_state")
    if not isinstance(state, dict):
        issues.append("B-098 blocker receipt lacks release_state")
    elif set(state) != RECEIPT_REMOTE_FIELDS:
        issues.append("B-098 blocker receipt remote fields are not exact")
    if not isinstance(state, dict) or state.get("local_semver_tags") != list(tags):
        issues.append("B-098 blocker receipt local semver tag census is stale")
    if isinstance(state, dict):
        for field in RECEIPT_REMOTE_FIELDS - {"local_semver_tags"}:
            if state.get(field) is not False:
                issues.append(f"B-098 blocker receipt {field} must be false while release is blocked")
    if tags:
        issues.append("B-098 blocker receipt must be refreshed once any semver release tag exists")
    decisions = data.get("owner_decisions")
    expected_decisions = {
        "dual_hat_release_path": (
            "NOT_INVOKED", DUAL_HAT_ADR, DUAL_HAT_ADR_SHA256,
        ),
        "release_mutation": (
            "NOT_AUTHORIZED", "docs/handoff/2026-09-05-b098-owner-action-packet.md", None,
        ),
    }
    if not isinstance(decisions, list) or len(decisions) != 2 or any(
        not isinstance(row, dict) or set(row) != {"decision", "status", "reference", "reason", "sha256"}
        or row.get("decision") not in expected_decisions
        or (row.get("status"), row.get("reference"), row.get("sha256")) != expected_decisions.get(row.get("decision"))
        or not isinstance(row.get("reason"), str) or not row["reason"].strip()
        for row in decisions
    ) or {row.get("decision") for row in decisions if isinstance(row, dict)} != set(expected_decisions):
        issues.append("B-098 blocker receipt owner_decisions fields are not exact")
    if not isinstance(decisions, list) or not any(
        isinstance(row, dict) and row.get("decision") == "dual_hat_release_path" and row.get("status") == "NOT_INVOKED"
        for row in decisions
    ):
        issues.append("B-098 blocker receipt must record that ADR-0034b dual-hat is not invoked")
    dual_hat_rows = [row for row in decisions if isinstance(row, dict) and row.get("decision") == "dual_hat_release_path"]
    if len(dual_hat_rows) == 1:
        issues.extend(_check_dual_hat_adr(root, dual_hat_rows[0]))
    blockers = data.get("blockers")
    if not isinstance(blockers, list) or len(blockers) != len(RECEIPT_BLOCKERS) or any(
        not isinstance(row, dict) or set(row) != {"id", "status", "required", "evidence"}
        or row.get("status") != "BLOCKED"
        or row.get("id") not in RECEIPT_BLOCKERS
        or (row.get("required"), row.get("evidence")) != RECEIPT_BLOCKER_BINDINGS.get(row.get("id"))
        or not isinstance(row.get("required"), str) or not row["required"].strip()
        or not isinstance(row.get("evidence"), str) or not row["evidence"].strip()
        or not (root / row["evidence"].split("#", 1)[0]).is_file()
        for row in blockers
    ) or {row.get("id") for row in blockers if isinstance(row, dict)} != RECEIPT_BLOCKERS:
        issues.append("B-098 blocker receipt must enumerate every unresolved GA release gate")
    non_claims = data.get("non_claims")
    if non_claims != list(RECEIPT_NON_CLAIMS):
        issues.append("B-098 blocker receipt non_claims are not the exact required non-claims")
    references = data.get("references")
    if not isinstance(references, list) or set(references) != RECEIPT_REFERENCES or len(references) != len(RECEIPT_REFERENCES):
        issues.append("B-098 blocker receipt references are not exact")
    return issues


@dataclass(frozen=True)
class Audit:
    package_count: int
    crate_dir_count: int
    okf_count: int
    specs_schema_count: int
    specs_yaml_only_count: int
    semver_tags: tuple[str, ...]
    issues: tuple[str, ...]

    @property
    def status(self) -> str:
        if CANONICAL_RELEASE_TAG not in self.semver_tags:
            return "open"
        return "invalid" if self.issues else "ready-to-close"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerificationError(f"required file is unreadable: {path}: {exc}") from exc


def _one(pattern: re.Pattern[str], text: str, label: str) -> int:
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise VerificationError(f"CLAUDE.md must contain exactly one {label} count")
    return int(matches[0])


def package_count(root: Path = ROOT) -> int:
    """Count package manifests through Cargo's workspace resolver."""
    try:
        completed = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version=1"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise VerificationError(f"cargo metadata could not run: {exc}") from exc
    if completed.returncode != 0:
        raise VerificationError(f"cargo metadata failed: {completed.stderr.strip()}")
    try:
        data = _json_loads(completed.stdout)
        packages = data["packages"]
    except (KeyError, TypeError, json.JSONDecodeError, DuplicateJSONKey) as exc:
        raise VerificationError("cargo metadata returned malformed JSON") from exc
    if not isinstance(packages, list) or not packages:
        raise VerificationError("cargo metadata returned no packages")
    package_ids = [
        package.get("id")
        for package in packages
        if isinstance(package, dict)
    ]
    if len(package_ids) != len(packages) or any(not isinstance(package_id, str) for package_id in package_ids):
        raise VerificationError("cargo metadata returned a package without an id")
    if len(set(package_ids)) != len(package_ids):
        raise VerificationError("cargo metadata returned duplicate package ids")
    return len(packages)


def okf_count(root: Path = ROOT) -> int:
    bundle = root / "docs/knowledge"
    if not bundle.is_dir():
        raise VerificationError(f"OKF bundle is missing: {bundle}")
    files = {
        path
        for path in bundle.rglob("*.md")
        if path.relative_to(bundle).as_posix() not in {"index.md", "log.md"}
    }
    if not files:
        raise VerificationError("OKF bundle contains no concepts")
    return len(files)


def specs_counts(root: Path = ROOT) -> tuple[int, int]:
    specs = root / "specs"
    if not specs.is_dir():
        raise VerificationError(f"spec corpus is missing: {specs}")
    all_files = [
        path
        for path in specs.rglob("*.md")
        if not any(part in SKIP_ALL for part in path.relative_to(specs).parts)
    ]
    if not all_files:
        raise VerificationError("spec corpus contains no documents")
    schema = [
        path
        for path in all_files
        if not any(part in SKIP_SCHEMA for part in path.relative_to(specs).parts)
    ]
    return len(schema), len(all_files) - len(schema)


def semver_tags(root: Path = ROOT) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            ["git", "tag", "--list"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise VerificationError(f"git tag could not run: {exc}") from exc
    if completed.returncode != 0:
        raise VerificationError(f"git tag failed: {completed.stderr.strip()}")
    return tuple(sorted(tag for tag in completed.stdout.splitlines() if _is_semver_tag(tag)))


def _check_release_contract(root: Path, tags: tuple[str, ...]) -> list[str]:
    issues: list[str] = []
    draft = root / TAG_DRAFT.relative_to(ROOT)
    packet = root / PACKET.relative_to(ROOT)
    allowed_signers = root / ALLOWED_SIGNERS.relative_to(ROOT)
    signing_policy = root / SIGNING_POLICY.relative_to(ROOT)
    cut_script = root / CUT_SCRIPT.relative_to(ROOT)
    if not allowed_signers.is_file():
        issues.append("canonical release signer trust root is missing")
    if not signing_policy.is_file():
        issues.append("canonical release role policy is missing")
    if not cut_script.is_file():
        issues.append("canonical release cut script is missing")
    else:
        cut_text = _read(cut_script)
        for marker in (
            'git tag -s "$TAG_NAME"',
            "--expected-main-sha is mandatory",
            "framework tag signature does not verify",
            "two-key signoff reuses one cryptographic key",
            "remote tag readback mismatch",
        ):
            if marker not in cut_text:
                issues.append(f"release cut script missing fail-closed marker: {marker}")
    if not draft.is_file():
        issues.append(f"release draft missing: {draft.relative_to(root)}")
    else:
        draft_text = _read(draft)
        for marker in (
            "git tag -s",
            "server-release provenance record",
            "does not claim SLSA provenance for CLI artifacts",
            "makes no GA-live claim for",
            "__RELEASE_SHA__",
            "__CONTAINER_DIGEST__",
            "__CI_EVIDENCE_PATH__",
            "__CI_EVIDENCE_SHA256__",
            "__DEPLOYMENT_EVIDENCE_SHA256__",
            "__CUTOVER_ATTESTATION_SHA256__",
        ):
            if marker not in draft_text:
                issues.append(f"release draft missing fail-closed marker: {marker}")
    if not packet.is_file():
        issues.append(f"owner action packet missing: {packet.relative_to(root)}")
    else:
        packet_text = _read(packet)
        for marker in ("B-098", "no semver release tag", "not create a tag"):
            if marker.lower() not in packet_text.lower():
                issues.append(f"owner action packet missing required statement: {marker}")
    if tags and CANONICAL_RELEASE_TAG not in tags:
        issues.append(f"canonical release tag is absent: {CANONICAL_RELEASE_TAG}")
    for tag in tags:
        body = _tag_body(root, tag)
        if body is None:
            issues.append(f"semver tag {tag} is not an annotated tag")
        else:
            for placeholder in sorted(set(re.findall(r"__[A-Z0-9_]+__", body))):
                issues.append(f"semver tag {tag} retains release placeholder {placeholder}")
            if "Signed-off-by:" not in body or "Co-Authored-By:" not in body:
                issues.append(f"semver tag {tag} lacks DCO/provenance trailers")
            if tag == CANONICAL_RELEASE_TAG:
                verified = subprocess.run(
                    ["git", "-c", f"gpg.ssh.allowedSignersFile={root / ALLOWED_SIGNERS.relative_to(ROOT)}", "verify-tag", "--format=%GF%n%GS", tag],
                    cwd=root, capture_output=True, text=True, check=False
                )
                if verified.returncode != 0:
                    issues.append(f"canonical release tag signature is not trusted: {tag}")
                else:
                    signature_lines = verified.stdout.strip().splitlines()
                    policy = _json_loads((root / ".github/release-signing-policy.json").read_text())
                    owner = policy.get("roles", {}).get("owner", {})
                    if signature_lines[:2] != [owner.get("fingerprint"), owner.get("principal")]:
                        issues.append("canonical release tag is not signed by policy owner")
                target = subprocess.run(
                    ["git", "rev-list", "-n", "1", tag],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                if not _is_oid(target):
                    issues.append("canonical release tag does not peel to a commit")
                elif f"Source commit: {target}" not in body:
                    issues.append("canonical release body is not bound to its peeled commit")
                framework_match = re.search(rf"^- Framework promotion tag object: ({OID_PATTERN})$", body, re.MULTILINE)
                framework_object = subprocess.run(
                    ["git", "rev-parse", "refs/tags/framework-v1-0-0-ga"],
                    cwd=root, capture_output=True, text=True, check=False,
                ).stdout.strip()
                if not framework_match or framework_match.group(1) != framework_object:
                    issues.append("canonical release is not bound to exact framework tag object")
                else:
                    allowed = root / ALLOWED_SIGNERS.relative_to(ROOT)
                    framework_verify = subprocess.run(
                        ["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-tag", "--format=%GF%n%GS", "framework-v1-0-0-ga"],
                        cwd=root, capture_output=True, text=True, check=False,
                    )
                    policy = _json_loads((root / SIGNING_POLICY.relative_to(ROOT)).read_text())
                    owner = policy.get("roles", {}).get("owner", {})
                    if framework_verify.returncode != 0 or framework_verify.stdout.strip().splitlines()[:2] != [owner.get("fingerprint"), owner.get("principal")]:
                        issues.append("framework promotion tag is not trusted policy-owner SSH evidence")
                    framework_commit = subprocess.run(
                        ["git", "rev-list", "-n", "1", "framework-v1-0-0-ga"],
                        cwd=root, capture_output=True, text=True, check=False,
                    ).stdout.strip()
                    ancestry = subprocess.run(
                        ["git", "merge-base", "--is-ancestor", framework_commit, target], cwd=root, check=False
                    )
                    framework_doc = subprocess.run(
                        ["git", "show", f"{framework_commit}:specs/00_framework.md"],
                        cwd=root, capture_output=True, text=True, check=False,
                    ).stdout.split("---", 2)
                    frontmatter = framework_doc[1] if len(framework_doc) == 3 else ""
                    if ancestry.returncode != 0 or 'doc_status: "FROZEN"' not in frontmatter or 'version: "1.0.0"' not in frontmatter:
                        issues.append("framework promotion target is not ancestral FROZEN v1.0.0")
                    remote_framework = subprocess.run(
                        ["git", "ls-remote", "--tags", "origin", "refs/tags/framework-v1-0-0-ga"],
                        cwd=root, capture_output=True, text=True, check=False,
                    ).stdout.split(maxsplit=1)
                    if not remote_framework or remote_framework[0] != framework_object:
                        issues.append("framework promotion tag object differs on canonical origin")
                for marker in (
                    "Production OCI digest: sha256:",
                    "Production deployment/readback evidence:",
                    "GA cutover execution attestation:",
                    "server-release provenance record",
                ):
                    if marker not in body:
                        issues.append(f"canonical release body lacks provenance marker: {marker}")
                remote = subprocess.run(
                    ["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}^{{}}"],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                remote_target = remote.stdout.split(maxsplit=1)[0] if remote.returncode == 0 and remote.stdout.strip() else ""
                if remote_target != target:
                    issues.append("canonical release tag is absent or has wrong target on origin")
                remote_object = subprocess.run(
                    ["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"],
                    cwd=root, capture_output=True, text=True, check=False,
                ).stdout.split(maxsplit=1)
                local_object = subprocess.run(
                    ["git", "rev-parse", f"refs/tags/{tag}"],
                    cwd=root, capture_output=True, text=True, check=False,
                ).stdout.strip()
                if not remote_object or remote_object[0] != local_object:
                    issues.append("canonical remote release tag object differs from local signed object")
                issues.extend(_released_evidence_issues(root, body, target))
    return issues


def _tag_body(root: Path, tag: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "cat-file", "-t", f"refs/tags/{tag}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0 or completed.stdout.strip() != "tag":
            return None
        body = subprocess.run(
            ["git", "cat-file", "-p", f"refs/tags/{tag}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise VerificationError(f"git tag inspection failed: {exc}") from exc
    if body.returncode != 0:
        raise VerificationError(f"cannot inspect semver tag {tag}")
    return body.stdout


def _released_evidence_issues(root: Path, body: str, target: str) -> list[str]:
    issues: list[str] = []
    patterns = {
        "ci": r"^- Bundled CI evidence: ([^ ]+) @ ([0-9a-f]{64})$",
        "deployment": r"^- Production deployment/readback evidence: ([^ ]+) @ ([0-9a-f]{64})$",
        "cutover": r"^- GA cutover execution attestation: ([^ ]+) @ ([0-9a-f]{64})$",
    }
    evidence: dict[str, dict] = {}
    evidence_hashes: dict[str, str] = {}
    evidence_commits: set[str] = set()
    for kind, pattern in patterns.items():
        match = re.search(pattern, body, re.MULTILINE)
        if not match:
            issues.append(f"canonical release lacks parseable {kind} evidence locator")
            continue
        path, expected_hash = match.groups()
        evidence_hashes[kind] = expected_hash
        evidence_commit = path.split(":", 1)[0]
        evidence_commits.add(evidence_commit)
        if not _is_oid(evidence_commit) or subprocess.run(
            ["git", "merge-base", "--is-ancestor", target, evidence_commit], cwd=root, check=False
        ).returncode != 0:
            issues.append(f"canonical release {kind} evidence locator is not a release descendant")
            continue
        completed = subprocess.run(
            ["git", "show", path], cwd=root, capture_output=True, check=False
        )
        if completed.returncode != 0 or hashlib.sha256(completed.stdout).hexdigest() != expected_hash:
            issues.append(f"canonical release {kind} evidence is absent or hash-mismatched")
            continue
        try:
            evidence[kind] = _json_loads(completed.stdout)
            stamp = datetime.datetime.fromisoformat(evidence[kind]["generated_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is None or stamp > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
                raise ValueError("invalid evidence timestamp")
        except (json.JSONDecodeError, DuplicateJSONKey, KeyError, ValueError, AttributeError):
            issues.append(f"canonical release {kind} evidence is not JSON")
    if len(evidence_commits) != 1:
        issues.append("canonical release evidence does not share one immutable commit")
    else:
        remote_evidence = subprocess.run(
            ["git", "ls-remote", "--tags", "origin", "refs/tags/release-evidence-v1.0.0-GA"],
            cwd=root, capture_output=True, text=True, check=False,
        ).stdout.split(maxsplit=1)
        if not remote_evidence or remote_evidence[0] != next(iter(evidence_commits)):
            issues.append("canonical release evidence commit lacks exact remote anchor")
    digest_match = re.search(r"^- Production OCI digest: (sha256:[0-9a-f]{64})$", body, re.MULTILINE)
    digest = digest_match.group(1) if digest_match else ""
    cutover = evidence.get("cutover", {})
    if (
        cutover.get("release_sha") != target
        or cutover.get("verdict") != "GREEN"
        or cutover.get("greenlights") != {"passed": 6, "total": 6}
        or cutover.get("steps") != {"passed": 11, "total": 11}
        or not cutover.get("generated_at")
    ):
        issues.append("canonical release cutover evidence values are invalid")
    deployment = evidence.get("deployment", {})
    envs = deployment.get("environments", []) if isinstance(deployment, dict) else []
    expected_envs = {"prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd"}
    if (
        deployment.get("release_sha") != target
        or deployment.get("oci_digest") != digest
        or not isinstance(envs, list)
        or {row.get("environment") for row in envs if isinstance(row, dict)} != expected_envs
        or any(row.get("oci_digest") != digest or row.get("failed") != 0 or row.get("healthy") != row.get("desired") for row in envs)
    ):
        issues.append("canonical release deployment evidence values are invalid")
    ci = evidence.get("ci", {})
    target_tree = subprocess.run(
        ["git", "show", "-s", "--format=%T", target], cwd=root, capture_output=True, text=True, check=False
    ).stdout.strip()
    tested_sha = ci.get("tested_sha", "") if isinstance(ci, dict) else ""
    tested_tree = subprocess.run(
        ["git", "show", "-s", "--format=%T", tested_sha], cwd=root, capture_output=True, text=True, check=False
    ).stdout.strip()
    if (
        ci.get("release_sha") != target
        or ci.get("release_tree") != target_tree
        or ci.get("tested_tree") != tested_tree
        or tested_tree != target_tree
        or (ci.get("pass"), ci.get("fail"), ci.get("infra")) != (19, 0, 0)
    ):
        issues.append("canonical release CI evidence values are invalid")
    signatures = re.findall(rf"^    Signature:\s+({OID_PATTERN})$", body, re.MULTILINE)
    if len(set(signatures)) != 2:
        issues.append("canonical release does not name two distinct signoff commits")
    else:
        fingerprints: set[str] = set()
        roles: set[str] = set()
        allowed = root / ALLOWED_SIGNERS.relative_to(ROOT)
        policy = _json_loads((root / ".github/release-signing-policy.json").read_text())
        for commit in signatures:
            verified = subprocess.run(
                ["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-commit", commit],
                cwd=root, capture_output=True, text=True, check=False,
            )
            metadata = subprocess.run(
                ["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}", "show", "-s", "--format=%GF%n%GS%n%B", commit],
                cwd=root, capture_output=True, text=True, check=False,
            ).stdout
            fingerprint, _, remainder = metadata.partition("\n")
            principal, _, signed_body = remainder.partition("\n")
            role_match = re.search(r"^CoreLink-Release-Role: (owner|ops)$", signed_body, re.MULTILINE)
            role = role_match.group(1) if role_match else ""
            authority = policy.get("roles", {}).get(role, {})
            if (
                verified.returncode != 0
                or not fingerprint
                or fingerprint in fingerprints
                or role in roles
                or authority.get("fingerprint") != fingerprint
                or authority.get("principal") != principal
            ):
                issues.append("canonical release signoff trust/independence is invalid")
                break
            for binding in (
                f"CoreLink-Release-SHA: {target}",
                f"Cutover-Attestation-SHA256: {evidence_hashes.get('cutover', '')}",
                f"Deployment-Evidence-SHA256: {evidence_hashes.get('deployment', '')}",
                f"CI-Evidence-SHA256: {evidence_hashes.get('ci', '')}",
            ):
                if binding not in signed_body:
                    issues.append("canonical release signoff is not release-bound")
            fingerprints.add(fingerprint)
            roles.add(role)
        if roles != {"owner", "ops"}:
            issues.append("canonical release signoffs do not cover owner and ops")
        for role, commit in zip(("owner", "ops"), signatures, strict=True):
            remote_signoff = subprocess.run(
                ["git", "ls-remote", "--tags", "origin", f"refs/tags/release-signoff-{role}-v1.0.0-GA"],
                cwd=root, capture_output=True, text=True, check=False,
            ).stdout.split(maxsplit=1)
            if not remote_signoff or remote_signoff[0] != commit:
                issues.append(f"canonical release {role} signoff lacks exact remote anchor")
    return issues


def audit(
    root: Path = ROOT,
    *,
    claude_text: str | None = None,
    tracker_text: str | None = None,
    verify_origin: bool = False,
) -> Audit:
    claude = _read(root / CLAUDE.relative_to(ROOT)) if claude_text is None else claude_text
    tracker = _read(root / TRACKER.relative_to(ROOT)) if tracker_text is None else tracker_text
    packages = package_count(root)
    crates = sum(1 for path in (root / "crates").iterdir() if path.is_dir())
    if crates == 0:
        raise VerificationError("crates directory contains no crate directories")
    okf = okf_count(root)
    schema, yaml_only = specs_counts(root)

    documented = {
        "package_count": _one(PACKAGE_COUNT, claude, "Rust package"),
        "crate_dir_count": _one(CRATE_DIR_COUNT, claude, "crate directory"),
        "extra_package_count": _one(EXTRA_PACKAGE_COUNT, claude, "non-crates package"),
        "okf_count": _one(OKF_COUNT, claude, "OKF concept"),
    }
    specs_matches = SPECS_COUNT.findall(claude)
    if len(specs_matches) != 1:
        raise VerificationError(
            "CLAUDE.md must contain exactly one full-schema/YAML-only spec count"
        )
    documented["specs_schema_count"], documented["specs_yaml_only_count"], documented["specs_total_count"] = map(int, specs_matches[0])

    issues: list[str] = []
    expected = {
        "package_count": packages,
        "crate_dir_count": crates,
        "okf_count": okf,
        "specs_schema_count": schema,
        "specs_yaml_only_count": yaml_only,
        "specs_total_count": schema + yaml_only,
    }
    for key, value in expected.items():
        if documented[key] != value:
            issues.append(f"CLAUDE.md {key}={documented[key]} but repository reports {value}")
    if documented["extra_package_count"] != packages - crates:
        issues.append("CLAUDE.md non-crates package count does not equal metadata minus crates")
    if "cargo metadata --no-deps --format-version=1" not in claude:
        issues.append("CLAUDE.md must name the exact cargo metadata population command")
    if "python3 scripts/validate_okf.py" not in claude:
        issues.append("CLAUDE.md must name the OKF validator command")
    if "python3 scripts/validate_specs.py" not in claude:
        issues.append("CLAUDE.md must name the specs validator command")

    lint_header = re.search(r"(?m)^\[lints\]\s*\nworkspace\s*=\s*true\s*$", tracker)
    if lint_header is None:
        issues.append("corelink-runbook-tracker must inherit [lints] workspace = true")
    if re.search(r"(?m)^\[lints\.(?:rust|clippy)\]", tracker):
        issues.append("corelink-runbook-tracker must not duplicate local rust/clippy lint tables")

    tags = semver_tags(root)
    if verify_origin:
        issues.extend(_check_live_origin(root, tags))
    issues.extend(_check_census(root))
    issues.extend(_check_signing_policy(root))
    issues.extend(
        _check_governance_receipt(
            root,
            tags,
            package_count=packages,
            crate_dir_count=crates,
            okf_count=okf,
            specs_schema_count=schema,
            specs_yaml_only_count=yaml_only,
            verify_origin=verify_origin,
        )
    )
    issues.extend(_check_release_contract(root, tags))
    return Audit(packages, crates, okf, schema, yaml_only, tags, tuple(issues))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the audit as JSON")
    parser.add_argument(
        "--verify-origin",
        action="store_true",
        help="perform a bounded live git ls-remote origin check; network errors fail closed",
    )
    args = parser.parse_args(argv)
    try:
        result = audit(verify_origin=args.verify_origin)
    except VerificationError as exc:
        print(f"B-098 verifier error (fail-closed): {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(result) | {"status": result.status}, sort_keys=True))
    else:
        print(
            f"B-098 {result.status}: semver_tags={len(result.semver_tags)} "
            f"packages={result.package_count} crates={result.crate_dir_count} "
            f"okf={result.okf_count} specs={result.specs_schema_count}+{result.specs_yaml_only_count}"
        )
        for issue in result.issues:
            print(f"FAIL: {issue}", file=sys.stderr)
    return 1 if result.issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
