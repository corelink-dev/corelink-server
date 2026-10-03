#!/usr/bin/env python3
"""Fail-closed candidate/post-merge verifier for Dependabot alerts #39-57.

Candidate mode deliberately expects the authenticated pre-merge open census and
proves that the candidate lockfile contains a fix for every affected package.
Use ``--post-merge`` only after the candidate is on the default branch; that
mode requires the authenticated live census to be empty. Once B-373 is marked
done, its unchanged backlog ``verify:`` command must also prove this live zero;
the historical candidate fixture alone cannot verify a done declaration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO: str | None = None
try:
    from server_repository import resolve_server_repository
except ModuleNotFoundError:  # imported as scripts.verify_b373_dependabot
    from scripts.server_repository import resolve_server_repository
BASE = "b7c6a165de0d456b6679c9662a1ffc8babc6ace8"
DELIVERED_MERGE_SHA = "6be19a2e525dad045ad8404d722905afde7ad7bd"
SNAPSHOT = "docs/security/b373-dependabot-census-2026-09-09.json"
EXPECTED: dict[int, tuple[str, str, str]] = {
    39: ("vitest", "GHSA-82fw-gwwq-j7x9", "medium"),
    40: ("next", "GHSA-p293-qw3h-jr36", "critical"),
    41: ("next", "GHSA-2xp9-vwfh-vxw4", "critical"),
    42: ("vitest", "GHSA-82fw-gwwq-j7x9", "medium"),
    43: ("baseline-browser-mapping", "GHSA-w5vr-8v7q-w6rv", "medium"),
    44: ("@vitest/mocker", "GHSA-82fw-gwwq-j7x9", "medium"),
    45: ("vitest", "GHSA-82fw-gwwq-j7x9", "medium"),
    46: ("joi", "GHSA-gg4h-3hg2-grpc", "low"),
    47: ("next", "GHSA-p293-qw3h-jr36", "critical"),
    48: ("colord", "GHSA-2wm5-q62r-hmrv", "medium"),
    49: ("joi", "GHSA-6w3j-5fw6-r9vr", "low"),
    50: ("svgo", "GHSA-4vpr-x523-8j87", "medium"),
    51: ("svgo", "GHSA-w27v-7q3p-w38r", "high"),
    52: ("adm-zip", "GHSA-vwc7-r8mq-g2x9", "medium"),
    53: ("next", "GHSA-2xp9-vwfh-vxw4", "critical"),
    54: ("js-yaml", "GHSA-2883-xcg3-v3hh", "high"),
    55: ("js-yaml", "GHSA-2883-xcg3-v3hh", "high"),
    56: ("sharp", "GHSA-rgj7-g3m4-5g8c", "high"),
    57: ("vitest", "GHSA-82fw-gwwq-j7x9", "medium"),
}
PATCHED = (
    "@vitest/mocker@4.1.11", "vitest@4.1.11", "next@16.3.3",
    "eslint-config-next@16.3.3",
    "baseline-browser-mapping@2.11.20", "baseline-browser-mapping@2.11.21",
    "joi@17.13.7", "colord@2.10.0", "svgo@3.3.5", "js-yaml@3.15.2",
    "js-yaml@4.3.2", "sharp@0.35.4",
)
STALE = (
    "@vitest/mocker@4.1.10", "vitest@4.1.10", "vitest@3.2.7",
    "next@16.2.11", "baseline-browser-mapping@2.10.43", "joi@17.13.4",
    "eslint-config-next@16.2.10",
    "colord@2.9.3", "svgo@3.3.4", "js-yaml@3.15.1", "js-yaml@4.3.1",
    "sharp@0.35.3",
)
OVERRIDES = (
    ("baseline-browser-mapping@<2.11.0", ">=2.11.0 <3"),
    ("colord@<2.9.4", ">=2.9.4 <3"),
    ("joi@<17.13.6", ">=17.13.6 <18"),
    ("js-yaml@<3.15.2", ">=3.15.2 <4"),
    ("js-yaml@>=4.0.0 <4.3.2", ">=4.3.2 <5"),
    ("sharp@<0.35.4", ">=0.35.4 <0.36.0"),
    ("svgo@>=1.0.0 <2.8.4", ">=2.8.4 <3"),
    ("svgo@>=3.0.0 <3.3.5", ">=3.3.5 <4"),
    ("svgo@>=4.0.0 <4.1.0", ">=4.1.0 <5"),
)
DEPENDENCY_PATHS = ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml")


class CensusError(RuntimeError):
    pass


def dependency_tree_digest(root: Path) -> str:
    """Hash every authored package manifest and the resolved workspace tree.

    The snapshot is deliberately bound to bytes, not merely to version
    markers: a candidate cannot substitute a different lockfile or manifest
    while retaining the same advisory census.
    """
    paths = {Path(path) for path in DEPENDENCY_PATHS}
    paths.update(path.relative_to(root) for path in root.rglob("package.json")
                 if "node_modules" not in path.parts)
    digest = hashlib.sha256()
    for relative in sorted(paths, key=lambda value: value.as_posix()):
        path = root / relative
        try:
            file_stat = path.lstat()
            if not stat.S_ISREG(file_stat.st_mode) or path.is_symlink():
                raise CensusError(f"dependency tree path is not a regular file: {relative}")
            content = path.read_bytes()
        except OSError as exc:
            raise CensusError(f"dependency tree path unavailable: {relative}: {exc}") from exc
        name = relative.as_posix().encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise CensusError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def api_json(endpoint: str) -> dict[str, Any]:
    """Read GitHub control-plane facts without writing a git credential to disk."""
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, check=False)
    if result.returncode:
        raise CensusError(f"authenticated GitHub API failed for {endpoint}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CensusError(f"GitHub API returned invalid JSON for {endpoint}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CensusError(f"GitHub API returned non-object response for {endpoint}")
    return payload


def live_main_sha() -> str:
    if REPO is None:
        raise CensusError("live server repository identity was not resolved")
    payload = api_json(f"/repos/{REPO}/git/ref/heads/main")
    sha = (payload.get("object") or {}).get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise CensusError("GitHub main ref has no valid commit SHA")
    return sha.lower()


def verify_post_merge_ref(root: Path, merged_sha: str | None) -> None:
    """Require a clean checkout whose commit and tree are the delivered ref."""
    if merged_sha:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", merged_sha):
            raise CensusError("--merged-sha must be a full 40-character commit SHA")
        expected_ref = merged_sha
    else:
        expected_ref = live_main_sha()
    expected_commit = git(root, "rev-parse", "--verify", f"{expected_ref}^{{commit}}")
    expected_tree = git(root, "rev-parse", "--verify", f"{expected_ref}^{{tree}}")
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}")
    head_tree = git(root, "rev-parse", "--verify", "HEAD^{tree}")
    if head != expected_commit or head_tree != expected_tree:
        raise CensusError("current HEAD and tree do not equal delivered origin/main/merged SHA")
    for arguments in (("diff", "--quiet", "HEAD", "--"), ("diff", "--cached", "--quiet", "HEAD", "--")):
        result = subprocess.run(["git", *arguments], cwd=root, capture_output=True, text=True, check=False)
        if result.returncode:
            raise CensusError("working tree is dirty; post-merge verification requires the delivered tree")


def verify_delivered_main_for_candidate(root: Path) -> None:
    """A done declaration may be checked on a descendant before it is merged.

    The exact-tree requirement above belongs only to ``--post-merge``. Here the
    delivered merge must be an ancestor of both live main and the checked-out
    candidate. The live ref and comparison come from the authenticated API;
    private-repository git fetch would require persisting checkout credentials.
    """
    main_sha = live_main_sha()
    shallow = git(root, "rev-parse", "--is-shallow-repository")
    if shallow != "false":
        raise CensusError("B-373 closure requires a full-history trusted checkout")
    comparison = api_json(f"/repos/{REPO}/compare/{DELIVERED_MERGE_SHA}...{main_sha}")
    if comparison.get("status") not in {"ahead", "identical"}:
        raise CensusError("live main is not descended from the B-373 delivered merge")
    if live_main_sha() != main_sha:
        raise CensusError("main moved during B-373 closure check")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", DELIVERED_MERGE_SHA, "HEAD"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise CensusError("trusted HEAD is not descended from the B-373 delivered merge")


def flatten(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise CensusError("Dependabot response is not an array")
    pages = payload if not payload or isinstance(payload[0], list) else [payload]
    if any(not isinstance(page, list) for page in pages):
        raise CensusError("Dependabot response has malformed pagination")
    alerts = [alert for page in pages for alert in page]
    if any(not isinstance(alert, dict) for alert in alerts):
        raise CensusError("Dependabot response contains a non-object alert")
    return alerts


def read_alerts(repo: str, fixture: Path | None) -> list[dict[str, Any]]:
    if fixture:
        try:
            return flatten(json.loads(fixture.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise CensusError(f"cannot read alert fixture: {exc}") from exc
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"/repos/{repo}/dependabot/alerts"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise CensusError("authenticated Dependabot API failed; this is not zero")
    try:
        return flatten(json.loads(result.stdout))
    except json.JSONDecodeError as exc:
        raise CensusError(f"Dependabot API returned invalid JSON: {exc}") from exc


def census(alerts: list[dict[str, Any]]) -> dict[int, tuple[str, str, str]]:
    result: dict[int, tuple[str, str, str]] = {}
    for alert in alerts:
        if alert.get("state") != "open":
            continue
        try:
            number = int(alert["number"])
            value = (
                alert["dependency"]["package"]["name"],
                alert["security_advisory"]["ghsa_id"],
                alert["security_advisory"]["severity"],
            )
            vulnerabilities = alert["security_advisory"]["vulnerabilities"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CensusError(f"malformed open alert: {exc}") from exc
        if number in result or not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise CensusError(f"duplicate or incomplete open alert #{number}")
        result[number] = value
    return dict(sorted(result.items()))


def verify_snapshot(root: Path) -> None:
    try:
        data = json.loads((root / SNAPSHOT).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CensusError(f"B-373 snapshot unavailable: {exc}") from exc
    if data.get("candidate_base_commit") != BASE:
        raise CensusError("snapshot is not anchored to the reviewed base")
    if data.get("candidate_contained") is not True or data.get("post_merge_refresh_required") is not True:
        raise CensusError("snapshot must distinguish candidate containment from post-merge refresh")
    if data.get("dependency_tree_sha256") != dependency_tree_digest(root):
        raise CensusError("candidate snapshot is not bound to the current dependency tree")
    if data.get("open_alert_count") != len(EXPECTED):
        raise CensusError("candidate snapshot must retain the non-zero live census")
    records = data.get("alerts")
    if not isinstance(records, list):
        raise CensusError("candidate snapshot alerts must be a list")
    actual: dict[int, tuple[str, str, str]] = {}
    for record in records:
        try:
            number = int(record["number"])
            value = (record["package"], record["ghsa"], record["severity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CensusError(f"candidate snapshot has malformed alert: {exc}") from exc
        if number in actual:
            raise CensusError(f"candidate snapshot duplicates alert #{number}")
        actual[number] = value
    if actual != EXPECTED:
        raise CensusError("candidate snapshot alert population drifted")


def verify_lockfile(root: Path) -> None:
    try:
        package = (root / "package.json").read_text(encoding="utf-8")
        lock = (root / "pnpm-lock.yaml").read_text(encoding="utf-8")
    except OSError as exc:
        raise CensusError(f"manifest or lockfile unavailable: {exc}") from exc
    def has_lock_entry(entry: str) -> bool:
        return re.search(rf"(?m)^  ['\"]?{re.escape(entry)}['\"]?(?::|\s)", lock) is not None

    for entry in PATCHED:
        if not has_lock_entry(entry):
            raise CensusError(f"patched lock entry missing: {entry}")
    stale = [entry for entry in STALE if has_lock_entry(entry)]
    if stale:
        raise CensusError(f"stale vulnerable lock entries remain: {stale}")
    for key, value in OVERRIDES:
        if key not in package or value not in package or key not in lock or value not in lock:
            raise CensusError(f"override missing from manifest/lock: {key}")
    if '"ignoreGhsas"' in package or "ignoreGhsas:" in lock:
        raise CensusError("advisory masking is forbidden")
    if "adm-zip" in package or "adm-zip" in lock or "chromedriver" in lock or "@axe-core/cli" in lock:
        raise CensusError("obsolete axe CLI/chromedriver/adm-zip path remains")


def backlog_b373_done(root: Path) -> bool:
    """Read the single canonical B-373 declaration without trusting a fixture."""
    try:
        backlog = (root / "BACKLOG.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise CensusError(f"BACKLOG.md unavailable: {exc}") from exc
    sections = re.findall(r"(?ms)^### B-373\b[^\n]*\n(.*?)(?=^### B-\d+\b|\Z)", backlog)
    if len(sections) != 1:
        raise CensusError("expected exactly one B-373 backlog section")
    blocks = re.findall(r"(?ms)^```backlog\n(.*?)^```\s*$", sections[0])
    if len(blocks) != 1:
        raise CensusError("expected exactly one B-373 backlog block")
    statuses = re.findall(r"(?m)^status: ([a-z]+)$", blocks[0])
    if len(statuses) != 1 or statuses[0] not in {"open", "done"}:
        raise CensusError("B-373 backlog status is missing or malformed")
    return statuses[0] == "done"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="exact authorized repo; default resolves the configured server repository ID")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--alerts-file", type=Path)
    parser.add_argument("--post-merge", action="store_true")
    parser.add_argument("--merged-sha", help="full delivered merge commit SHA (skips fetching origin/main)")
    args = parser.parse_args(argv)
    try:
        global REPO
        if args.post_merge and args.alerts_file is not None:
            raise CensusError(
                "--post-merge requires an authenticated GitHub API census; "
                "--alerts-file fixtures are forbidden"
            )
        snapshot_fixture = args.alerts_file and args.alerts_file.name == Path(SNAPSHOT).name
        if snapshot_fixture:
            exact_snapshot = args.alerts_file.resolve() == (args.root / SNAPSHOT).resolve() and not args.alerts_file.is_symlink()
            if not exact_snapshot:
                raise CensusError("alerts fixture with the snapshot name must use the exact repository path")
        # Local fixtures stay offline and byte-bound. Live census and closure
        # paths require the current ID-backed repo or an exact source/dest name.
        if not args.alerts_file or args.post_merge:
            REPO = resolve_server_repository(args.repo)
        elif args.repo:
            REPO = resolve_server_repository(args.repo)
        if snapshot_fixture and not args.post_merge:
            verify_snapshot(args.root)
            actual = EXPECTED.copy()
        else:
            actual = census(read_alerts(REPO or "", args.alerts_file))
        expected = {} if args.post_merge else EXPECTED
        if actual != expected:
            mode = "post-merge zero" if args.post_merge else "pre-merge candidate census"
            raise CensusError(f"{mode} drifted: expected {expected}, got {actual}")
        closure_required = snapshot_fixture and not args.post_merge and backlog_b373_done(args.root)
        if args.post_merge:
            verify_post_merge_ref(args.root, args.merged_sha)
        verify_lockfile(args.root)
        if not args.post_merge and not snapshot_fixture:
            verify_snapshot(args.root)
        if closure_required:
            verify_delivered_main_for_candidate(args.root)
            if REPO is None:
                REPO = resolve_server_repository(args.repo)
            if census(read_alerts(REPO, None)) != {}:
                raise CensusError("B-373 done requires an authenticated post-merge live zero")
    except CensusError as exc:
        print(f"FAIL: B-373 fail-closed Dependabot verifier: {exc}", file=sys.stderr)
        return 2
    mode = "post-merge live zero" if args.post_merge else "19-alert candidate census contained"
    if closure_required:
        mode += " and post-merge live zero"
    print("B-373 verified: " + mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
