#!/usr/bin/env python3
"""Verify the owner-reviewed B-028 Dependabot census.

This is an owner-side check because the default Actions token cannot read the
Dependabot alerts endpoint.  That limitation is deliberately fail-closed:
missing credentials, a non-JSON response, a partial page, or any unexpected
open alert is an error, never an empty census.

Run after the exact lockfile patch is on the default branch:

    python3 scripts/verify_b028_dependabot.py

The API call is read-only.  ``--alerts-file`` exists only for the focused
tests; it must contain the same JSON shape returned by ``gh api``.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from server_repository import resolve_server_repository
except ModuleNotFoundError:  # imported as scripts.verify_b028_dependabot
    from scripts.server_repository import resolve_server_repository

# The pre-merge census remains retained for the focused tests and provenance.
# The live default branch census is now separately expected to be empty after
# the dependency remediation landed.  Keeping both expectations prevents a
# stale pre-merge fixture from being mistaken for current GitHub truth.
EXPECTED_OLD_MAIN_ALERTS: dict[int, tuple[str, str, str]] = {
    26: ("image-size", "GHSA-w3rx-r6r6-pgpr", "high"),
    27: ("image-size", "GHSA-5p2g-fcmc-qvqq", "high"),
    28: ("extract-zip", "GHSA-jmr9-qjv8-65gv", "high"),
    33: ("fast-uri", "GHSA-5jgf-p345-68v8", "high"),
    34: ("fast-uri", "GHSA-fph4-wmhf-6fwf", "high"),
    35: ("qs", "GHSA-x5fp-wj9c-mxmx", "medium"),
    36: ("fast-uri", "GHSA-f65p-4m7j-42xc", "high"),
    37: ("fast-uri", "GHSA-jqff-g426-hqxp", "high"),
    38: ("qs", "GHSA-4mjr-xmp4-gh2g", "medium"),
}
# Compatibility name for focused callers and the pre-merge adjudication path.
EXPECTED_RESIDUALS = EXPECTED_OLD_MAIN_ALERTS
EXPECTED_POST_MERGE_ALERTS: dict[int, tuple[str, str, str]] = {}
POST_MERGE_SNAPSHOT = "docs/security/b028-dependabot-census-2026-09-06-postmerge.json"
# Compatibility alias: older focused tests use this name for the verified post-merge receipt.
BASELINE_SNAPSHOT = POST_MERGE_SNAPSHOT
CANDIDATE_CONTAINED = {26, 27, 28}

# The lockfile must carry the exact published fixes and the two local,
# auditable substitutes. Keep the checks narrow so an unrelated dependency
# refresh cannot hide inside a security patch.
REQUIRED_LOCK_ENTRIES = (
    "fast-uri@3.1.6",
    "qs@6.16.0",
    "postcss-selector-parser@6.1.3",
    "postcss-selector-parser@7.1.3",
)
FORBIDDEN_LOCK_ENTRIES = (
    "fast-uri@3.1.5",
    "qs@6.15.2",
    "postcss-selector-parser@6.1.2",
    "postcss-selector-parser@7.1.1",
    "extract-zip@2.0.1",
    "image-size@2.0.2",
)
REQUIRED_OVERRIDES = (
    ("fast-uri@>=3.0.0 <3.1.6", ">=3.1.6 <4"),
    ("qs@>=6.11.1 <6.16.0", ">=6.16.0 <7"),
    ("postcss-selector-parser@>=6.1.0 <6.1.3", "6.1.3"),
    ("postcss-selector-parser@>=7.1.0 <7.1.3", "7.1.3"),
)
LOCAL_OVERRIDES = (
    ("extract-zip", "file:vendor/extract-zip"),
    ("image-size", "file:vendor/image-size"),
)
VENDOR_MARKERS = {
    "vendor/extract-zip/package.json": (
        '"name": "extract-zip"',
        '"version": "2.0.2-hugr.0"',
    ),
    "vendor/extract-zip/index.js": (
        "validateSymlinkTarget",
        "async function assertSafeParent(root, parent)",
        "resolveInside(root, path.relative(root, canonicalParent))",
        "flags: 'wx'",
    ),
    "vendor/image-size/package.json": (
        '"name": "image-size"',
        '"version": "2.0.3-hugr.0"',
    ),
    "vendor/image-size/index.cjs": (
        "MAX_INPUT_BYTES",
        "function png(input)",
        "function svg(input)",
    ),
}


class CensusError(RuntimeError):
    """The truth source could not be safely evaluated."""


def _flatten_pages(payload: Any) -> list[dict[str, Any]]:
    """Flatten ``gh --paginate --slurp`` output and reject bad shapes."""
    pages = payload if isinstance(payload, list) else None
    if pages is None:
        raise CensusError("Dependabot API response is not a JSON array")
    if pages and all(isinstance(item, dict) for item in pages):
        alerts = pages
    elif all(isinstance(page, list) for page in pages):
        alerts = [alert for page in pages for alert in page]
    else:
        raise CensusError("Dependabot API response contains a malformed page")
    if any(not isinstance(alert, dict) for alert in alerts):
        raise CensusError("Dependabot API response contains a non-object alert")
    return alerts


def read_alerts(repo: str, fixture: Path | None) -> list[dict[str, Any]]:
    if fixture is not None:
        try:
            payload = json.loads(fixture.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CensusError(f"cannot read alerts fixture: {exc}") from exc
        return _flatten_pages(payload)

    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"/repos/{repo}/dependabot/alerts"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().replace("\n", " ")[:400]
        raise CensusError(
            "Dependabot alerts census unavailable; authentication or API failure "
            f"is not an empty census ({detail or 'gh exited non-zero'})"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CensusError(f"Dependabot API returned invalid JSON: {exc}") from exc
    return _flatten_pages(payload)


def _summary(alert: dict[str, Any]) -> tuple[int, str, str, str]:
    try:
        number = int(alert["number"])
        state = alert["state"]
        package = alert["dependency"]["package"]["name"]
        advisory = alert["security_advisory"]
        ghsa = advisory["ghsa_id"]
        severity = advisory["severity"]
    except (KeyError, TypeError, ValueError) as exc:
        raise CensusError(f"malformed alert record: {exc}") from exc
    if not isinstance(state, str) or not isinstance(package, str):
        raise CensusError(f"malformed alert #{number}: state/package is not text")
    if not isinstance(ghsa, str) or not isinstance(severity, str):
        raise CensusError(f"malformed alert #{number}: advisory fields are not text")
    return number, package, ghsa, severity


def verify_alerts(
    alerts: list[dict[str, Any]],
    expected: dict[int, tuple[str, str, str]] | None = None,
) -> list[tuple[int, str, str, str]]:
    open_alerts: dict[int, tuple[str, str, str]] = {}
    for alert in alerts:
        number, package, ghsa, severity = _summary(alert)
        if alert.get("state") != "open":
            continue
        if number in open_alerts:
            raise CensusError(f"duplicate open Dependabot alert number #{number}")
        open_alerts[number] = (package, ghsa, severity)

        advisory = alert.get("security_advisory") or {}
        vulnerabilities = advisory.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise CensusError(f"open alert #{number} has no vulnerability details")
        if any(
            not isinstance(v, dict) or "first_patched_version" not in v
            for v in vulnerabilities
        ):
            raise CensusError(f"open alert #{number} has malformed vulnerability details")

    actual = {number: value for number, value in sorted(open_alerts.items())}
    expected_census = dict(sorted((EXPECTED_RESIDUALS if expected is None else expected).items()))
    if actual != expected_census:
        raise CensusError(f"open alert census drifted: expected {expected_census}, got {actual}")
    return [(number, *values) for number, values in sorted(open_alerts.items())]


def verify_baseline_snapshot(root: Path) -> None:
    path = root / POST_MERGE_SNAPSHOT
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CensusError(f"B-028 baseline snapshot unavailable or invalid: {exc}") from exc
    if snapshot.get("default_branch_commit") != "cdd6a671484a378e443bd8b4c4b7b5e0948dcb8b":
        raise CensusError("B-028 snapshot is not anchored to the refreshed default branch")
    if snapshot.get("candidate_commit") != "8796799192daf00aa98c99a60e0bd4d790ec1ce9":
        raise CensusError("B-028 snapshot lost the reviewed remediation candidate anchor")
    if snapshot.get("post_merge_refresh_required") is not False:
        raise CensusError("B-028 snapshot still claims a post-merge refresh is required")
    if snapshot.get("open_alert_count") != 0:
        raise CensusError("B-028 snapshot does not record an empty open-alert census")
    records = snapshot.get("alerts")
    if not isinstance(records, list):
        raise CensusError("B-028 snapshot alerts must be a list")
    actual = {}
    for record in records:
        if not isinstance(record, dict):
            raise CensusError("B-028 snapshot contains a malformed alert")
        try:
            number = int(record["number"])
            actual[number] = (record["package"], record["ghsa"], record["severity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CensusError(f"B-028 snapshot contains a malformed alert: {exc}") from exc
        expected_classification = (
            "old-main-open-candidate-contained"
            if number in CANDIDATE_CONTAINED
            else "old-main-open-candidate-patched"
        )
        if record.get("classification") != expected_classification:
            raise CensusError(
                f"B-028 snapshot alert #{number} has wrong candidate classification"
            )
    if actual:
        raise CensusError(
            f"B-028 post-merge snapshot must contain no open alerts, got {actual}"
        )


def verify_lockfile(root: Path) -> None:
    package_path = root / "package.json"
    lock_path = root / "pnpm-lock.yaml"
    try:
        package = package_path.read_text(encoding="utf-8")
        lock = lock_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CensusError(f"dependency manifest/lockfile unavailable: {exc}") from exc

    def lock_package_key(entry: str) -> bool:
        return re.search(rf"(?m)^  {re.escape(entry)}:\s*$", lock) is not None

    missing = [entry for entry in REQUIRED_LOCK_ENTRIES if not lock_package_key(entry)]
    stale = [entry for entry in FORBIDDEN_LOCK_ENTRIES if lock_package_key(entry)]
    if missing or stale:
        raise CensusError(
            "lockfile security patch mismatch: "
            f"missing={missing or 'none'} stale={stale or 'none'}"
        )

    for key, value in REQUIRED_OVERRIDES:
        # JSON and YAML quote these keys differently, so check key/value as a
        # pair without requiring one particular serializer's whitespace.
        pattern = re.compile(rf"[\"']?{re.escape(key)}[\"']?\s*:\s*[\"']?{re.escape(value)}[\"']?")
        if not pattern.search(package):
            raise CensusError(f"package.json is missing override {key}: {value}")
        if not pattern.search(lock):
            raise CensusError(f"pnpm-lock.yaml is missing override {key}: {value}")

    for key, value in LOCAL_OVERRIDES:
        pattern = re.compile(rf"[\"']?{re.escape(key)}[\"']?\s*:\s*[\"']?{re.escape(value)}[\"']?")
        if not pattern.search(package):
            raise CensusError(f"package.json is missing local override {key}: {value}")
        if not lock_package_key(f"{key}@{value}"):
            raise CensusError(f"pnpm-lock.yaml is missing local package {key}: {value}")

    if '"ignoreGhsas"' in package or "ignoreGhsas:" in lock:
        raise CensusError("audit ignoreGhsas masking must not be present")

    for relative, markers in VENDOR_MARKERS.items():
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CensusError(f"required B-028 containment file unavailable: {path}: {exc}") from exc
        missing_markers = [marker for marker in markers if marker not in text]
        if missing_markers:
            raise CensusError(
                f"B-028 containment marker missing in {relative}: {missing_markers}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--alerts-file", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        # Offline fixtures do not address GitHub. Every live API call resolves
        # the server by numeric repository ID or an exact authorized name.
        repo = resolve_server_repository(args.repo) if args.alerts_file is None else ""
        alerts = read_alerts(repo, args.alerts_file)
        # ``--alerts-file`` is a focused-test compatibility path for the
        # retained pre-merge fixture.  The authenticated live API is always
        # adjudicated against the post-merge empty census.
        census = verify_alerts(
            alerts,
            expected=EXPECTED_RESIDUALS if args.alerts_file is not None else EXPECTED_POST_MERGE_ALERTS,
        )
        verify_baseline_snapshot(args.root)
        verify_lockfile(args.root)
    except CensusError as exc:
        print(f"FAIL: B-028 verifier is fail-closed: {exc}", file=sys.stderr)
        return 2

    print("B-028 Dependabot census verified: " + ", ".join(
        f"#{number} {package} {ghsa} {severity}" for number, package, ghsa, severity in census
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
