#!/usr/bin/env python3
"""Fail-closed exact-main CodeQL gate for the reviewed issue 1674 findings.

The ordinary CodeQL severity gate remains strict. This entry point is only for
the canonical repository's trusted main-branch schedule/manual run; it accepts
an individual HIGH+ SARIF result only when the exact reviewed source identity,
uploaded analysis, alert number, and live dismissed alert all agree.
"""

from __future__ import annotations

import argparse
import hashlib
import functools
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from codeql_severity_gate import (
    THRESHOLD,
    SarifSeverityError,
    _as_rule_list,
    _rule_for_result,
    _security_score,
    high_findings,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "specs/_audits/2026-10-01-i1674-reviewed-codeql-dispositions.json"
MANIFEST_SHA256 = "cf7a79ae822227ab88b2440e015964bf77e29b8fe0c1f67d8860d3e0c66bca21"
REPOSITORY = "HuGR-dev/corelink-server"
REPOSITORY_ID = "1232040291"
REVIEWED_COMMIT = "145c5276834a48b93c6a0d2ae558fcb5fcbf725f"
REVIEWED_ANALYSIS_COMMIT = "76455023097b0b5e219579c3618774bedb0a0548"
ROOT_DECISION_SHA256 = "06901cfaecb90ff168d793a3122ea9f3a44b5592e204313a1cd6b302d86969d5"
SOURCE_EVIDENCE_SHA256 = "eea941e7ecd9b9ab29e71670ffebc281ace154f42c7035e5dfa152290276f05e"
CASE_CONTROL_SHA256 = "b95ef97b3540e060890b62bd8901cc0a612ae26ea4239818897d9bf247bf5e48"
APPROVED_IDS_SHA256 = "5db0e49590c93827940e5a22b052efdc5355f22692ae2d29bba76cd6a7284200"
FIXED_IDS_SHA256 = "62429c0acb9057746e9cff120d5b0229f0a24ed94698d3caa6d8f49d9bfe521e"
CODEQL_VERSION = "2.27.1"
LANGUAGE_CATEGORIES = {
    "rust": "/language:rust",
    "javascript-typescript": "/language:javascript-typescript",
    "python": "/language:python",
}
API_VERSION = "2022-11-28"
SARIF_DEFAULT_START_COLUMN = 1


class ReviewedGateError(ValueError):
    """Evidence is missing, untrusted, ambiguous, or inconsistent."""


@functools.lru_cache(maxsize=8)
def _tree_blobs(revision: str) -> dict[str, str]:
    """Read one Git tree once instead of starting Git for each manifest path."""
    try:
        raw = subprocess.check_output(
            ["git", "ls-tree", "-rz", "--full-tree", revision],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReviewedGateError("reviewed source tree cannot be verified") from exc
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_type, oid = metadata.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReviewedGateError("reviewed source tree listing is malformed") from exc
        if object_type == "blob":
            entries[path] = oid
    return entries


def _working_tree_blob(path: str) -> str:
    source_path = ROOT / path
    if source_path.is_symlink() or not source_path.is_file():
        raise ReviewedGateError("reviewed source file is not a regular file")
    try:
        content = source_path.read_bytes()
    except OSError as exc:
        raise ReviewedGateError("reviewed source file cannot be read") from exc
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def _load_manifest() -> dict[str, Any]:
    try:
        raw = MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise ReviewedGateError("reviewed disposition manifest is unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ReviewedGateError("reviewed disposition manifest digest mismatch")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReviewedGateError("reviewed disposition manifest is malformed") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        raise ReviewedGateError("reviewed disposition manifest schema is unsupported")
    if (
        manifest.get("issue") != 1674
        or manifest.get("review_decision_sha256") != ROOT_DECISION_SHA256
        or manifest.get("source_evidence_sha256") != SOURCE_EVIDENCE_SHA256
        or manifest.get("case_control_sha256") != CASE_CONTROL_SHA256
        or manifest.get("reviewed_source_commit") != REVIEWED_COMMIT
        or manifest.get("retained_analysis_commit") != REVIEWED_ANALYSIS_COMMIT
        or manifest.get("root_approved_fp_count") != 303
        or manifest.get("root_expected_fix_count") != 30
    ):
        raise ReviewedGateError("reviewed disposition manifest approval binding mismatch")
    cases = manifest.get("approved_alerts")
    if not isinstance(cases, list):
        raise ReviewedGateError("reviewed disposition manifest case list is malformed")
    numbers = [case.get("alert_number") for case in cases if isinstance(case, dict)]
    if any(isinstance(number, bool) or not isinstance(number, int) for number in numbers):
        raise ReviewedGateError("reviewed disposition alert number is malformed")
    canonical = json.dumps(sorted(numbers), separators=(",", ":")).encode("utf-8")
    if len(numbers) != len(cases) or hashlib.sha256(canonical).hexdigest() != APPROVED_IDS_SHA256:
        raise ReviewedGateError("reviewed disposition manifest alert population differs from root approval")
    fixed = manifest.get("root_expected_fix_ids")
    if not isinstance(fixed, list) or len(fixed) != 30 or any(
        isinstance(number, bool) or not isinstance(number, int) for number in fixed
    ):
        raise ReviewedGateError("root-expected fixes are malformed")
    fixed_canonical = json.dumps(sorted(fixed), separators=(",", ":")).encode("utf-8")
    if len(set(fixed)) != len(fixed) or hashlib.sha256(fixed_canonical).hexdigest() != FIXED_IDS_SHA256:
        raise ReviewedGateError("root-expected fix population differs from approved source decision")
    return manifest


def _manifest_cases(manifest: dict[str, Any], sha: str) -> dict[int, dict[str, Any]]:
    cases = manifest.get("approved_alerts")
    blobs = manifest.get("source_file_blobs")
    support = manifest.get("support_binding_paths")
    if not isinstance(cases, list) or len(cases) != 303 or not isinstance(blobs, dict):
        raise ReviewedGateError("reviewed disposition manifest has an unexpected population")
    if not isinstance(support, dict):
        raise ReviewedGateError("reviewed source support bindings are malformed")
    by_number: dict[int, dict[str, Any]] = {}
    fingerprint_identities: set[tuple[str, str, str, str, str]] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ReviewedGateError("reviewed disposition entry is malformed")
        number = case.get("alert_number")
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0 or number in by_number:
            raise ReviewedGateError("reviewed alert number is missing or duplicated")
        language = case.get("language")
        if language not in LANGUAGE_CATEGORIES or case.get("category") != LANGUAGE_CATEGORIES[language]:
            raise ReviewedGateError("reviewed alert language/category binding is invalid")
        if (
            case.get("tool") != "CodeQL"
            or case.get("tool_version") != CODEQL_VERSION
            or case.get("expected_dismissed_reason") not in ("false positive", "used in tests")
            or not isinstance(case.get("primaryLocationLineHash"), str)
            or not case.get("primaryLocationLineHash")
            or not isinstance(case.get("primaryLocationStartColumnFingerprint"), str)
            or not case.get("primaryLocationStartColumnFingerprint")
        ):
            raise ReviewedGateError("reviewed alert approval fields are invalid")
        path = case.get("path")
        if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts:
            raise ReviewedGateError("reviewed alert source path is unsafe")
        source_path = ROOT / path
        if source_path.is_symlink() or not source_path.is_file():
            raise ReviewedGateError("reviewed source path is not a regular file")
        source_blob = case.get("source_blob_oid")
        if not isinstance(source_blob, str) or not re.fullmatch(r"[0-9a-f]{40}", source_blob):
            raise ReviewedGateError("reviewed alert source blob is invalid")
        if blobs.get(path) != source_blob:
            raise ReviewedGateError("reviewed source file blob mapping is inconsistent")
        if isinstance(case.get("line"), bool) or not isinstance(case.get("line"), int) or case["line"] < 1:
            raise ReviewedGateError("reviewed alert source line is invalid")
        if (
            isinstance(case.get("start_column"), bool)
            or not isinstance(case.get("start_column"), int)
            or case["start_column"] < 1
        ):
            raise ReviewedGateError("reviewed alert source column is invalid")
        fingerprint_identity = (
            language, case["tool_version"], case["rule"], path,
            case["primaryLocationLineHash"], case["primaryLocationStartColumnFingerprint"],
        )
        if fingerprint_identity in fingerprint_identities:
            raise ReviewedGateError("reviewed SARIF fingerprint identity is ambiguous")
        fingerprint_identities.add(fingerprint_identity)
        by_number[number] = case

    retained_evidence = manifest.get("retained_sarif_evidence")
    if not isinstance(retained_evidence, dict) or set(retained_evidence) != set(LANGUAGE_CATEGORIES):
        raise ReviewedGateError("retained SARIF provenance is incomplete")
    for language, evidence in retained_evidence.items():
        if (
            not isinstance(evidence, dict)
            or evidence.get("analysis_run_id") != 36315432255
            or evidence.get("source_sha") != REVIEWED_ANALYSIS_COMMIT
            or evidence.get("ref") != "refs/heads/main"
            or not isinstance(evidence.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"])
        ):
            raise ReviewedGateError("retained SARIF provenance binding is invalid")

    for number_text, paths in support.items():
        if not isinstance(number_text, str) or not number_text.isdigit() or int(number_text) not in by_number:
            raise ReviewedGateError("reviewed case support binding has an unapproved alert number")
        if not isinstance(paths, list) or not paths or any(not isinstance(path, str) or path not in blobs for path in paths):
            raise ReviewedGateError("reviewed case support binding references an unbound source path")

    # Bind every reviewed source and case-support file to the reviewed source
    # tree and this exact scan checkout. This is a file-blob check, never a
    # path-wide finding exemption.
    reviewed_tree = _tree_blobs(REVIEWED_COMMIT)
    current_tree = _tree_blobs(sha)
    for path, expected_oid in blobs.items():
        if (
            not isinstance(path, str)
            or path.startswith("/")
            or ".." in Path(path).parts
            or not isinstance(expected_oid, str)
            or not re.fullmatch(r"[0-9a-f]{40}", expected_oid)
        ):
            raise ReviewedGateError("reviewed source blob map is malformed")
        reviewed_oid = reviewed_tree.get(path)
        current_oid = current_tree.get(path)
        worktree_oid = _working_tree_blob(path)
        if not (reviewed_oid == current_oid == worktree_oid == expected_oid):
            raise ReviewedGateError("reviewed source file changed from its approved blob")
    return by_number


def _sarif_records(payload: dict[str, Any], *, language: str, uploaded: bool) -> tuple[list[dict[str, Any]], int]:
    try:
        # Retain the established strict schema/threshold validation for every
        # rule and result before applying any individual reviewed disposition.
        high_findings(payload)
    except SarifSeverityError as exc:
        raise ReviewedGateError("SARIF severity/schema validation failed") from exc
    runs = payload.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ReviewedGateError("SARIF must contain exactly one run")
    run = runs[0]
    tool = run.get("tool")
    if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
        raise ReviewedGateError("SARIF tool metadata is missing")
    driver = tool["driver"]
    if driver.get("name") != "CodeQL" or driver.get("semanticVersion", driver.get("version")) != CODEQL_VERSION:
        raise ReviewedGateError("SARIF CodeQL tool/version does not match the approved analysis")
    driver_rules = _as_rule_list(driver, "CodeQL SARIF driver")
    extensions_raw = tool.get("extensions", [])
    if not isinstance(extensions_raw, list) or any(not isinstance(ext, dict) for ext in extensions_raw):
        raise ReviewedGateError("SARIF extensions are malformed")
    extensions: list[tuple[str | None, str | None, list[dict[str, Any]]]] = []
    for index, extension in enumerate(extensions_raw):
        extensions.append((
            extension.get("name"),
            extension.get("guid"),
            _as_rule_list(extension, f"SARIF extension[{index}]"),
        ))
    results = run.get("results")
    if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
        raise ReviewedGateError("SARIF results are malformed")
    records: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        rule_id = result.get("ruleId")
        try:
            rule = _rule_for_result(
                result,
                driver.get("name"),
                driver.get("guid"),
                driver_rules,
                extensions,
            )
            score = _security_score(rule, rule_id if isinstance(rule_id, str) else "unknown")
        except SarifSeverityError as exc:
            raise ReviewedGateError(f"SARIF result {index} has ambiguous rule metadata") from exc
        if score < THRESHOLD:
            continue
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ReviewedGateError("HIGH+ SARIF result has no primary location")
        physical = locations[0].get("physicalLocation") if isinstance(locations[0], dict) else None
        if not isinstance(physical, dict):
            raise ReviewedGateError("HIGH+ SARIF primary location is malformed")
        artifact = physical.get("artifactLocation")
        region = physical.get("region")
        if not isinstance(artifact, dict) or not isinstance(region, dict):
            raise ReviewedGateError("HIGH+ SARIF path or region is missing")
        path = artifact.get("uri")
        line = region.get("startLine")
        if not isinstance(path, str) or not path or not isinstance(line, int) or isinstance(line, bool):
            raise ReviewedGateError("HIGH+ SARIF path or line is invalid")
        # SARIF 2.1.0 (region object, startColumn property): an ABSENT
        # startColumn defaults to 1. CodeQL omits it there: trusted run
        # 36920507526 dropped it for alert 447, and none of that run's results
        # carries an explicit startColumn of 1. Only absence takes the
        # default: a present null, bool, non-integer, zero or negative value
        # is still malformed evidence and fails closed. The defaulted column
        # must then still equal the reviewed case and the live alert column.
        if "startColumn" not in region:
            start_column = SARIF_DEFAULT_START_COLUMN
        else:
            start_column = region["startColumn"]
            if not isinstance(start_column, int) or isinstance(start_column, bool) or start_column < 1:
                raise ReviewedGateError("HIGH+ SARIF start column is invalid")
        if path.startswith("/") or ".." in Path(path).parts:
            raise ReviewedGateError("HIGH+ SARIF source path is unsafe")
        fingerprints = result.get("partialFingerprints")
        if not isinstance(fingerprints, dict):
            raise ReviewedGateError("HIGH+ SARIF result lacks partial fingerprints")
        line_hash = fingerprints.get("primaryLocationLineHash")
        if not isinstance(line_hash, str) or not line_hash:
            raise ReviewedGateError("HIGH+ SARIF result lacks its line fingerprint")
        column_fingerprint = fingerprints.get("primaryLocationStartColumnFingerprint")
        if not uploaded and (not isinstance(column_fingerprint, str) or not column_fingerprint):
            raise ReviewedGateError("local HIGH+ SARIF lacks its column fingerprint")
        if uploaded and column_fingerprint is not None and (
            not isinstance(column_fingerprint, str) or not column_fingerprint
        ):
            raise ReviewedGateError("uploaded HIGH+ SARIF has a malformed column fingerprint")
        properties = result.get("properties", {})
        if uploaded:
            if not isinstance(properties, dict):
                raise ReviewedGateError("uploaded SARIF result properties are malformed")
            number = properties.get("github/alertNumber")
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ReviewedGateError("uploaded SARIF result lacks its GitHub alert number")
        else:
            number = None
        records.append({
            "language": language,
            "tool_version": CODEQL_VERSION,
            "rule": rule_id,
            "path": path,
            "line": line,
            "start_column": start_column,
            "score": score,
        "line_hash": line_hash,
        "column_fingerprint": column_fingerprint,
            "alert_number": number,
        })
    return records, len(results)


class GitHubApi:
    def __init__(self, token: str, api_url: str) -> None:
        if not token:
            raise ReviewedGateError("GitHub API token is unavailable")
        self._token = token
        self._base = api_url.rstrip("/")

    def get(self, endpoint: str, accept: str = "application/vnd.github+json") -> Any:
        request = urllib.request.Request(
            self._base + endpoint,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status != 200:
                    raise ReviewedGateError("GitHub API returned a non-200 response")
                return json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            # Do not print provider response bodies, headers, or request auth.
            raise ReviewedGateError("GitHub code-scanning API read failed") from exc

    def patch(self, endpoint: str, payload: dict[str, str]) -> Any:
        request = urllib.request.Request(
            self._base + endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "Content-Type": "application/json",
            },
            method="PATCH",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status not in (200, 201):
                    raise ReviewedGateError("GitHub API returned a non-success response")
                return json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ReviewedGateError("GitHub code-scanning API update failed") from exc


def _write_receipt(path: Path | None, receipt: dict[str, Any]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReviewedGateError("disposition receipt could not be persisted") from exc


def _validate_context(args: argparse.Namespace) -> None:
    if (
        args.repository != REPOSITORY
        or args.repository_id != REPOSITORY_ID
        or args.ref != "refs/heads/main"
        or args.event not in ("schedule", "workflow_dispatch")
        or not re.fullmatch(r"[0-9a-f]{40}", args.sha)
    ):
        raise ReviewedGateError("reviewed mode is restricted to the canonical repository's trusted main run")
    try:
        checked_out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReviewedGateError("checked-out source SHA cannot be verified") from exc
    if checked_out != args.sha:
        raise ReviewedGateError("checked-out source SHA does not match the current run")


def verify(args: argparse.Namespace) -> int:
    _validate_context(args)
    if args.language not in LANGUAGE_CATEGORIES:
        raise ReviewedGateError("unknown CodeQL language")
    category = LANGUAGE_CATEGORIES[args.language]
    if not args.sarif_id:
        raise ReviewedGateError("upload-sarif did not provide a SARIF ID")
    if len(args.sarif) != 1 or not args.sarif[0].is_file():
        raise ReviewedGateError("expected exactly one local SARIF file")

    manifest = _load_manifest()
    approved = _manifest_cases(manifest, args.sha)
    local_payload = json.loads(args.sarif[0].read_text(encoding="utf-8"))
    local_high, local_count = _sarif_records(local_payload, language=args.language, uploaded=False)

    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    api = GitHubApi(os.environ.get("GH_TOKEN", ""), api_url)
    repo_path = "/repos/" + urllib.parse.quote(args.repository, safe="/")
    query = urllib.parse.urlencode({"sarif_id": args.sarif_id, "per_page": 100})
    analyses = api.get(f"{repo_path}/code-scanning/analyses?{query}")
    if not isinstance(analyses, list) or len(analyses) != 1 or not isinstance(analyses[0], dict):
        raise ReviewedGateError("uploaded SARIF does not resolve to exactly one current analysis")
    analysis = analyses[0]
    tool = analysis.get("tool")
    if (
        analysis.get("sarif_id") != args.sarif_id
        or analysis.get("commit_sha") != args.sha
        or analysis.get("ref") != args.ref
        or analysis.get("category") != category
        or not isinstance(tool, dict)
        or tool.get("name") != "CodeQL"
        or tool.get("version") != CODEQL_VERSION
        or analysis.get("error") not in (None, "")
        or isinstance(analysis.get("results_count"), bool)
        or not isinstance(analysis.get("results_count"), int)
        or analysis.get("results_count") != local_count
    ):
        raise ReviewedGateError("uploaded analysis identity or result count does not match this run")
    analysis_id = analysis.get("id")
    if isinstance(analysis_id, bool) or not isinstance(analysis_id, int) or analysis_id <= 0:
        raise ReviewedGateError("uploaded analysis ID is invalid")

    encoded = urllib.parse.quote(str(analysis_id), safe="")
    uploaded_payload = api.get(
        f"{repo_path}/code-scanning/analyses/{encoded}",
        accept="application/sarif+json",
    )
    if not isinstance(uploaded_payload, dict):
        raise ReviewedGateError("uploaded analysis SARIF is malformed")
    uploaded_high, uploaded_count = _sarif_records(uploaded_payload, language=args.language, uploaded=True)
    if uploaded_count != local_count:
        raise ReviewedGateError("uploaded and local SARIF result counts differ")
    local_uploaded_join = Counter(
        (r["rule"], r["path"], r["line"], r["start_column"], r["score"], r["line_hash"])
        for r in local_high
    )
    api_uploaded_join = Counter(
        (r["rule"], r["path"], r["line"], r["start_column"], r["score"], r["line_hash"])
        for r in uploaded_high
    )
    if local_uploaded_join != api_uploaded_join:
        raise ReviewedGateError("local and GitHub-uploaded HIGH+ SARIF findings differ")
    if any(count != 1 for count in local_uploaded_join.values()) or any(
        count != 1 for count in api_uploaded_join.values()
    ):
        raise ReviewedGateError("local/uploaded SARIF correlation is ambiguous")

    seen_identities: set[tuple[Any, ...]] = set()
    seen_alerts: set[int] = set()
    uploaded_by_join = {
        (r["rule"], r["path"], r["line"], r["start_column"], r["score"], r["line_hash"]): r
        for r in uploaded_high
    }
    matched: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for local in local_high:
        join_key = (
            local["rule"], local["path"], local["line"], local["start_column"],
            local["score"], local["line_hash"],
        )
        uploaded = uploaded_by_join[join_key]
        identity = (
            args.language, CODEQL_VERSION, local["rule"], local["path"],
            local["line"], local["start_column"], local["line_hash"],
            local["column_fingerprint"],
        )
        if identity in seen_identities:
            raise ReviewedGateError("current HIGH+ SARIF contains a duplicate approved identity")
        seen_identities.add(identity)
        number = uploaded["alert_number"]
        case = approved.get(number)
        if case is None:
            raise ReviewedGateError("current HIGH+ SARIF contains a new or unapproved alert")
        if (
            case["language"] != args.language
            or case["category"] != category
            or local["rule"] != case["rule"]
            or local["path"] != case["path"]
            or local["line"] != case["line"]
            or local["start_column"] != case["start_column"]
            or local["line_hash"] != case["primaryLocationLineHash"]
            or local["column_fingerprint"] != case["primaryLocationStartColumnFingerprint"]
            or uploaded["line_hash"] != local["line_hash"]
            # GitHub's application/sarif+json response is a documented subset;
            # the live API response inspected for this repository omits the
            # secondary fingerprint, while retaining alertNumber, line hash,
            # and exact region columns. When the API does include the secondary
            # fingerprint, bind it too; the local current-run SARIF always has
            # to match both fingerprints in the reviewed manifest.
            or (
                uploaded["column_fingerprint"] is not None
                and uploaded["column_fingerprint"] != local["column_fingerprint"]
            )
            or uploaded["score"] != local["score"]
            or number in seen_alerts
        ):
            raise ReviewedGateError("current finding differs from its exact approved alert identity")
        seen_alerts.add(number)

        alert = api.get(f"{repo_path}/code-scanning/alerts/{number}")
        if not isinstance(alert, dict):
            raise ReviewedGateError("approved live alert response is malformed")
        live_tool = alert.get("tool")
        live_rule = alert.get("rule")
        instance = alert.get("most_recent_instance")
        location = instance.get("location") if isinstance(instance, dict) else None
        expected_severity = "critical" if local["score"] >= 9.0 else "high"
        if (
            alert.get("number") != number
            or alert.get("state") not in ("open", "dismissed")
            or (alert.get("state") == "dismissed" and alert.get("dismissed_reason") != case["expected_dismissed_reason"])
            or not isinstance(live_rule, dict)
            or live_rule.get("id") != case["rule"]
            or live_rule.get("security_severity_level") != expected_severity
            or not isinstance(live_tool, dict)
            or live_tool.get("name") != "CodeQL"
            or live_tool.get("version") != CODEQL_VERSION
            or not isinstance(instance, dict)
            or instance.get("category") != category
            or instance.get("ref") != args.ref
            or not isinstance(location, dict)
            or location.get("path") != case["path"]
            or location.get("start_line") != local["line"]
            or location.get("start_column") != local["start_column"]
        ):
            raise ReviewedGateError("live alert state/reason/tool/location differs from its approval")
        matched.append((case, local, alert))

    # Do not mutate anything until every current finding and every exact live
    # alert has passed identity, severity, location, and source verification.
    updates: list[int] = []
    receipt_path = getattr(args, "receipt", None)
    receipt = {
        "schema_version": 1,
        "issue": 1674,
        "result": "verified_pending_updates",
        "repository_id": REPOSITORY_ID,
        "event": args.event,
        "ref": args.ref,
        "commit_sha": args.sha,
        "language": args.language,
        "category": category,
        "sarif_id": args.sarif_id,
        "analysis_id": analysis_id,
        "manifest_sha256": MANIFEST_SHA256,
        "local_sarif_sha256": hashlib.sha256(args.sarif[0].read_bytes()).hexdigest(),
        "findings": [
            {
                "alert_number": case["alert_number"],
                "rule": local["rule"],
                "path": local["path"],
                "line": local["line"],
                "start_column": local["start_column"],
                "line_fingerprint": local["line_hash"],
                "column_fingerprint": local["column_fingerprint"],
                "severity": "critical" if local["score"] >= 9.0 else "high",
                "source_blob_oid": case["source_blob_oid"],
                "approved_reason": case["expected_dismissed_reason"],
                "state_before": alert["state"],
                "state_after": alert["state"],
                "updated_by_this_run": False,
            }
            for case, local, alert in matched
        ],
        "updated_alert_numbers": updates,
        "attempted_alert_numbers": [],
    }
    _write_receipt(receipt_path, receipt)
    for case, _local, alert in matched:
        number = case["alert_number"]
        if alert["state"] == "dismissed":
            continue
        if not getattr(args, "apply_approved_dispositions", False):
            receipt["result"] = "failed_open_alert_without_opt_in"
            _write_receipt(receipt_path, receipt)
            raise ReviewedGateError("an approved alert is still open; explicit disposition opt-in is required")
        receipt["attempted_alert_numbers"].append(number)
        try:
            result = api.patch(
                f"{repo_path}/code-scanning/alerts/{number}",
                {"state": "dismissed", "dismissed_reason": case["expected_dismissed_reason"]},
            )
        except ReviewedGateError:
            receipt["result"] = "patch_response_unverified"
            _write_receipt(receipt_path, receipt)
            raise
        if not isinstance(result, dict) or result.get("number") != number or result.get("state") != "dismissed" or result.get("dismissed_reason") != case["expected_dismissed_reason"]:
            receipt["result"] = "patch_response_unverified"
            _write_receipt(receipt_path, receipt)
            raise ReviewedGateError("GitHub did not confirm the exact approved disposition")
        updates.append(number)
        receipt["updated_alert_numbers"] = list(updates)
        finding_receipt = next(item for item in receipt["findings"] if item["alert_number"] == number)
        finding_receipt["state_after"] = "dismissed"
        finding_receipt["updated_by_this_run"] = True
        receipt["result"] = "update_pending_readback"
        _write_receipt(receipt_path, receipt)

    # Independently read back every state changed by this invocation.
    for number in updates:
        try:
            alert = api.get(f"{repo_path}/code-scanning/alerts/{number}")
        except ReviewedGateError:
            receipt["result"] = "readback_failed"
            _write_receipt(receipt_path, receipt)
            raise
        case = approved[number]
        _case, local, _before = next(item for item in matched if item[0]["alert_number"] == number)
        live_tool = alert.get("tool") if isinstance(alert, dict) else None
        live_rule = alert.get("rule") if isinstance(alert, dict) else None
        instance = alert.get("most_recent_instance") if isinstance(alert, dict) else None
        location = instance.get("location") if isinstance(instance, dict) else None
        if (
            not isinstance(alert, dict)
            or alert.get("number") != number
            or alert.get("state") != "dismissed"
            or alert.get("dismissed_reason") != case["expected_dismissed_reason"]
            or not isinstance(live_rule, dict)
            or live_rule.get("id") != case["rule"]
            or live_rule.get("security_severity_level") != ("critical" if local["score"] >= 9.0 else "high")
            or not isinstance(live_tool, dict)
            or live_tool.get("name") != "CodeQL"
            or live_tool.get("version") != CODEQL_VERSION
            or not isinstance(instance, dict)
            or instance.get("category") != category
            or instance.get("ref") != args.ref
            or not isinstance(location, dict)
            or location.get("path") != case["path"]
            or location.get("start_line") != case["line"]
            or location.get("start_column") != case["start_column"]
        ):
            receipt["result"] = "readback_failed"
            _write_receipt(receipt_path, receipt)
            raise ReviewedGateError("exact alert disposition readback did not match the approved reason")

    receipt["result"] = "pass"
    _write_receipt(receipt_path, receipt)
    print(f"Reviewed CodeQL gate: PASS; verified {len(seen_alerts)} exact approved HIGH+ finding(s); updated {len(updates)} exact alert(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--language", required=True)
    parser.add_argument("--sarif-id", required=True)
    parser.add_argument("--apply-approved-dispositions", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("sarif", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        return verify(args)
    except (ReviewedGateError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, ReviewedGateError) else "local evidence is unavailable or malformed"
        print(f"::error::Reviewed CodeQL gate failed closed: {reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
