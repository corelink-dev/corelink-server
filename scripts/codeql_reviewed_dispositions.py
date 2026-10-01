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
MANIFEST_SHA256 = "0f2abcd7bda9dc01e36f86bfaeadc040f53d27ee0d2b6b425772c14c8b47d8f6"
REPOSITORY = "HuGR-dev/corelink-server"
REPOSITORY_ID = "1232040291"
REVIEWED_COMMIT = "5da497051f0b11dbfc8b87d1dfa8e753304e2719"
REVIEWED_ANALYSIS_COMMIT = "76455023097b0b5e219579c3618774bedb0a0548"
CODEQL_VERSION = "2.27.1"
LANGUAGE_CATEGORIES = {
    "rust": "/language:rust",
    "javascript-typescript": "/language:javascript-typescript",
    "python": "/language:python",
}
API_VERSION = "2022-11-28"


class ReviewedGateError(ValueError):
    """Evidence is missing, untrusted, ambiguous, or inconsistent."""


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
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ReviewedGateError("reviewed disposition manifest schema is unsupported")
    if (
        manifest.get("issue") != 1674
        or manifest.get("source_evidence_sha256")
        != "d26e79b633f24a22ed50c14fbed77fe208153aa0c3fa0366dbc0e9d391cc352a"
        or manifest.get("reviewed_source_commit") != REVIEWED_COMMIT
        or manifest.get("source_analysis_commit") != REVIEWED_ANALYSIS_COMMIT
    ):
        raise ReviewedGateError("reviewed disposition manifest approval binding mismatch")
    return manifest


def _identity_key(case: dict[str, Any]) -> tuple[Any, ...]:
    fingerprints = case.get("sarif_partialFingerprints")
    if not isinstance(fingerprints, dict):
        raise ReviewedGateError("reviewed identity has malformed fingerprints")
    required = ("primaryLocationLineHash", "primaryLocationStartColumnFingerprint")
    if any(not isinstance(fingerprints.get(key), str) or not fingerprints[key] for key in required):
        raise ReviewedGateError("reviewed identity lacks a required SARIF fingerprint")
    return (
        case.get("language"),
        case.get("tool_version"),
        case.get("rule"),
        case.get("path"),
        fingerprints[required[0]],
        fingerprints[required[1]],
    )


def _manifest_cases(manifest: dict[str, Any], sha: str) -> dict[int, dict[str, Any]]:
    cases = manifest.get("approved_alerts")
    blobs = manifest.get("source_file_blobs")
    if not isinstance(cases, list) or len(cases) != 19 or not isinstance(blobs, dict):
        raise ReviewedGateError("reviewed disposition manifest has an unexpected population")
    by_number: dict[int, dict[str, Any]] = {}
    identities: set[tuple[Any, ...]] = set()
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
            case.get("state") != "dismissed"
            or case.get("tool") != "CodeQL"
            or case.get("tool_version") != CODEQL_VERSION
            or case.get("source_analysis_sha") != REVIEWED_ANALYSIS_COMMIT
            or case.get("dismissed_reason") not in ("false positive", "used in tests")
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
        identity = _identity_key(case)
        if identity in identities:
            raise ReviewedGateError("reviewed SARIF identities are not unique")
        identities.add(identity)
        by_number[number] = case

    # Bind every reviewed source file both to the approved old tree and to this
    # exact checked-out tree. This is deliberately a file-blob check, never a
    # path-wide finding exemption.
    for path, expected_oid in blobs.items():
        if not isinstance(path, str) or not isinstance(expected_oid, str):
            raise ReviewedGateError("reviewed source blob map is malformed")
        try:
            reviewed_oid = subprocess.check_output(
                ["git", "rev-parse", f"{REVIEWED_COMMIT}:{path}"],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            current_oid = subprocess.check_output(
                ["git", "rev-parse", f"{sha}:{path}"],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            worktree_oid = subprocess.check_output(
                ["git", "hash-object", "--", path],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ReviewedGateError("reviewed source file blob cannot be verified") from exc
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
        start_column = region.get("startColumn")
        if not isinstance(path, str) or not path or not isinstance(line, int) or isinstance(line, bool):
            raise ReviewedGateError("HIGH+ SARIF path or line is invalid")
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
    for local in local_high:
        join_key = (
            local["rule"], local["path"], local["line"], local["start_column"],
            local["score"], local["line_hash"],
        )
        uploaded = uploaded_by_join[join_key]
        identity = (
            args.language,
            CODEQL_VERSION,
            local["rule"],
            local["path"],
            local["line_hash"],
            local["column_fingerprint"],
        )
        if identity in seen_identities:
            raise ReviewedGateError("current HIGH+ SARIF contains a duplicate approved identity")
        seen_identities.add(identity)
        matches = [case for case in approved.values() if _identity_key(case) == identity]
        if len(matches) != 1:
            raise ReviewedGateError("current HIGH+ SARIF contains a new or ambiguous finding")
        case = matches[0]
        number = case["alert_number"]
        if (
            local["path"] != case["path"]
            or local["line"] != case["line"]
            or local["start_column"] != case["start_column"]
            or uploaded["alert_number"] != number
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
        if (
            alert.get("number") != number
            or alert.get("state") != "dismissed"
            or alert.get("dismissed_reason") != case["dismissed_reason"]
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
            raise ReviewedGateError("live alert state/reason/tool/location differs from its approval")

    print(f"Reviewed CodeQL gate: PASS; verified {len(seen_alerts)} exact approved HIGH+ finding(s).")
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
