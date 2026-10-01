#!/usr/bin/env python3
"""Resolve and validate a cross-repository CLI release by its stable API ID.

GitHub's tag lookup endpoint does not return unpublished draft releases. This
helper resolves a draft from the paginated release collection, then reads it
again by immutable release ID. Callers may instead provide an ID they already
captured from a create response. It deliberately distinguishes a verified
absence during pre-create inspection from API failures or missing IDs later.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any


MAX_RELEASES = 10_000
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_RE = re.compile(r"^cli-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")
ID_RE = re.compile(r"^[1-9][0-9]*$")


class ReleaseApiError(RuntimeError):
    """Raised when the authenticated release API cannot prove one exact state."""


def gh_json(*args: str) -> Any:
    result = subprocess.run(
        ["gh", "api", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        # Do not echo headers, tokens, or the full response body into CI logs.
        raise ReleaseApiError(f"GitHub release API request failed (gh exit {result.returncode})")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseApiError("GitHub release API returned malformed JSON") from error


def gh_json_input(*args: str, payload: dict[str, Any]) -> Any:
    result = subprocess.run(
        ["gh", "api", *args],
        input=json.dumps(payload),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise ReleaseApiError(f"GitHub release API request failed (gh exit {result.returncode})")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseApiError("GitHub release API returned malformed JSON") from error


def list_releases(repository: str) -> list[dict[str, Any]]:
    pages = gh_json(
        "--paginate",
        "--slurp",
        f"repos/{repository}/releases?per_page=100",
    )
    if not isinstance(pages, list):
        raise ReleaseApiError("paginated release response was not a page array")
    releases: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise ReleaseApiError("paginated release response contained a malformed page")
        releases.extend(page)
        if len(releases) > MAX_RELEASES:
            raise ReleaseApiError("release listing exceeded the bounded pagination limit")
    return releases


def validate_release(
    release: Any,
    *,
    repository: str,
    tag: str,
    expected_state: str,
    release_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(release, dict):
        raise ReleaseApiError("release API response was not an object")
    identifier = release.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
        raise ReleaseApiError("release response has no valid numeric ID")
    if release_id is not None and identifier != int(release_id):
        raise ReleaseApiError("release ID changed during resolution")
    if release.get("tag_name") != tag:
        raise ReleaseApiError("release tag does not match the requested tag")
    if release.get("prerelease") is not False:
        raise ReleaseApiError("release is prerelease or has malformed prerelease state")

    draft = release.get("draft")
    published_at = release.get("published_at")
    if expected_state == "draft":
        if draft is not True or published_at is not None:
            raise ReleaseApiError("expected the exact unpublished draft release")
    elif expected_state == "published":
        if draft is not False or not isinstance(published_at, str) or not published_at:
            raise ReleaseApiError("expected the exact published release")
    else:  # argparse protects callers; retain a fail-closed internal invariant.
        raise ReleaseApiError("unsupported expected release state")

    if release.get("html_url") is None or release.get("upload_url") is None:
        raise ReleaseApiError("release response lacks expected API URLs")
    if not isinstance(release.get("assets"), list):
        raise ReleaseApiError("release response lacks an asset inventory")
    return release


def resolve_release(
    *,
    repository: str,
    tag: str,
    expected_state: str,
    release_id: str | None,
    allow_absent: bool,
) -> dict[str, Any] | None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseApiError("repository must be a plain owner/name value")
    if not TAG_RE.fullmatch(tag):
        raise ReleaseApiError("tag is outside the canonical CLI release format")
    if expected_state not in {"draft", "published"}:
        raise ReleaseApiError("unsupported expected release state")
    if release_id is not None and not ID_RE.fullmatch(release_id):
        raise ReleaseApiError("release ID must be a positive decimal integer")
    if allow_absent and (release_id is not None or expected_state != "draft"):
        raise ReleaseApiError("absence is allowed only during draft pre-create inspection")

    if release_id is None:
        matches = [item for item in list_releases(repository) if item.get("tag_name") == tag]
        if not matches and allow_absent:
            return None
        if len(matches) != 1:
            raise ReleaseApiError("release collection did not contain exactly one matching tag")
        candidate = matches[0]
        identifier = candidate.get("id")
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
            raise ReleaseApiError("matching release collection item has no valid numeric ID")
        release_id = str(identifier)

    release = gh_json(f"repos/{repository}/releases/{release_id}")
    return validate_release(
        release,
        repository=repository,
        tag=tag,
        expected_state=expected_state,
        release_id=release_id,
    )


def create_or_reuse_empty_draft(
    *,
    repository: str,
    tag: str,
    title: str,
    body: str,
) -> dict[str, Any]:
    """Create a draft by REST, retaining the ID in the create response.

    A previously created exact empty draft is reusable after a failed run. A
    populated draft is never overwritten or treated as a fresh candidate.
    """
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseApiError("repository must be a plain owner/name value")
    if not TAG_RE.fullmatch(tag):
        raise ReleaseApiError("tag is outside the canonical CLI release format")
    if not title:
        raise ReleaseApiError("release title must not be empty")

    matches = [item for item in list_releases(repository) if item.get("tag_name") == tag]
    if len(matches) > 1:
        raise ReleaseApiError("release collection contains duplicate matching tags")
    if matches:
        candidate = matches[0]
        identifier = candidate.get("id")
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
            raise ReleaseApiError("matching release collection item has no valid numeric ID")
        release = resolve_release(
            repository=repository,
            tag=tag,
            expected_state="draft",
            release_id=str(identifier),
            allow_absent=False,
        )
        assert release is not None
        if release["assets"]:
            raise ReleaseApiError("existing draft is non-empty; refusing overwrite or resume")
        return release

    created = gh_json_input(
        "--method", "POST", "--input", "-", f"repos/{repository}/releases",
        payload={
            "tag_name": tag,
            "name": title,
            "body": body,
            "draft": True,
            "prerelease": False,
        },
    )
    release = validate_release(
        created,
        repository=repository,
        tag=tag,
        expected_state="draft",
    )
    if release.get("name") != title:
        raise ReleaseApiError("created release title does not match the request")
    if release["assets"]:
        raise ReleaseApiError("new draft unexpectedly contains assets")
    return release


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-state", required=True, choices=("draft", "published"))
    parser.add_argument("--release-id")
    parser.add_argument("--allow-absent", action="store_true")
    parser.add_argument("--create-or-reuse-empty-draft", action="store_true")
    parser.add_argument("--title")
    parser.add_argument("--notes-file")
    parser.add_argument("--format", choices=("json", "id", "state"), default="json")
    args = parser.parse_args(argv)

    try:
        if args.create_or_reuse_empty_draft:
            if (args.expected_state != "draft" or args.release_id is not None
                    or not args.allow_absent or not args.title or not args.notes_file):
                raise ReleaseApiError(
                    "create-or-reuse requires draft state, allowed pre-create inspection, title, and notes"
                )
            try:
                body = open(args.notes_file, encoding="utf-8").read()
            except OSError as error:
                raise ReleaseApiError("release notes file could not be read") from error
            release = create_or_reuse_empty_draft(
                repository=args.repo,
                tag=args.tag,
                title=args.title,
                body=body,
            )
        else:
            if args.title is not None or args.notes_file is not None:
                raise ReleaseApiError("title and notes are only valid when creating or reusing a draft")
            release = resolve_release(
                repository=args.repo,
                tag=args.tag,
                expected_state=args.expected_state,
                release_id=args.release_id,
                allow_absent=args.allow_absent,
            )
    except ReleaseApiError as error:
        print(f"release resolution failed: {error}", file=sys.stderr)
        return 2

    if release is None:
        print("absent" if args.format == "state" else "")
        return 0
    if args.format == "id":
        print(release["id"])
    elif args.format == "state":
        print("draft" if release["draft"] else "published")
    else:
        print(json.dumps(release, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
