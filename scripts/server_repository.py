#!/usr/bin/env python3
"""Resolve CoreLink's live GitHub repositories from ``config/github-identity.json``.

That file is the single source of truth for the GitHub owner, the repository
names and their numeric IDs. The org was recreated rather than transferred, so
every repository has a new numeric ID and no ID carries over.

Rules this module enforces:

* An ID of ``0`` means "not read back yet". :func:`load_identity` refuses it,
  so nothing can authorize against a guessed or placeholder ID.
* The current owner can never be one of ``historical_server_owners``, and a
  current ID can never be one of ``retired_repository_ids``. Those lists exist
  only to verify artifacts made before the recreate; they never authorize a
  live run.
* A GitHub Actions context is accepted only when both ``GITHUB_REPOSITORY_ID``
  and ``GITHUB_REPOSITORY`` equal the configured values. A matching name alone
  is not enough.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_PATH = ROOT / "config" / "github-identity.json"
SCHEMA_VERSION = 1
REPOSITORY_KEYS = ("server", "runners", "workspaces")

_TOP_KEYS = frozenset(
    {
        "schema",
        "comment",
        "current",
        "distribution",
        "github_app",
        "historical_server_owners",
        "retired_repository_ids",
    }
)
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_APP_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_DECIMAL_ID = re.compile(r"[1-9][0-9]*")


class IdentityError(ValueError):
    """The identity file is malformed, unread, or does not match the context."""


@dataclass(frozen=True)
class Repository:
    key: str
    owner: str
    name: str
    id: int

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class GitHubIdentity:
    owner: str
    owner_id: int
    repositories: tuple[Repository, ...]
    distribution: tuple[tuple[str, str], ...]
    github_app_owner: str
    github_app_slug: str
    github_app_id: int
    historical_server_owners: tuple[str, ...]
    retired_repository_ids: frozenset[int]

    def repository(self, key: str) -> Repository:
        for repository in self.repositories:
            if repository.key == key:
                return repository
        raise IdentityError(f"unknown repository key: {key!r}")

    def unread(self) -> tuple[str, ...]:
        """Name every ID that still holds the "not read back yet" value 0."""
        fields = ["current.owner_id"] if self.owner_id == 0 else []
        fields.extend(
            f"current.repos.{repository.key}.id"
            for repository in self.repositories
            if repository.id == 0
        )
        return tuple(fields)

    def require_read_back(self) -> GitHubIdentity:
        unread = self.unread()
        if unread:
            raise IdentityError(
                "GitHub identity not read back yet (0 = unread): " + ", ".join(unread)
            )
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise IdentityError(f"duplicate key in identity file: {key!r}")
        document[key] = value
    return document


def _object(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise IdentityError(f"{label} must be an object")
    if set(value) != keys:
        raise IdentityError(f"{label} must have exactly the keys {sorted(keys)}")
    return value


def _owner(value: object, label: str) -> str:
    if not isinstance(value, str) or not _OWNER.fullmatch(value):
        raise IdentityError(f"{label} is not a GitHub owner name")
    return value


def _repository_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REPOSITORY_NAME.fullmatch(value) or value in {".", ".."}:
        raise IdentityError(f"{label} is not a GitHub repository name")
    return value


def _identifier(value: object, label: str, *, allow_unread: bool) -> int:
    # bool is an int subclass; a JSON true must never pass as ID 1.
    if type(value) is not int or value < 0 or (value == 0 and not allow_unread):
        lower = "a non-negative" if allow_unread else "a positive"
        raise IdentityError(f"{label} must be {lower} integer")
    return value


def _full_name(value: object, label: str) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise IdentityError(f"{label} must be an owner/repository name")
    owner, name = value.split("/")
    _owner(owner, label)
    _repository_name(name, label)
    return value


def parse_identity(document: object) -> GitHubIdentity:
    """Validate the identity document's shape. IDs of 0 are kept as unread."""
    root = _object(document, "identity", _TOP_KEYS)
    if type(root["schema"]) is not int or root["schema"] != SCHEMA_VERSION:
        raise IdentityError(f"identity schema must be {SCHEMA_VERSION}")
    if not isinstance(root["comment"], str) or not root["comment"].strip():
        raise IdentityError("identity comment must explain the file")

    current = _object(root["current"], "current", frozenset({"owner", "owner_id", "repos"}))
    owner = _owner(current["owner"], "current.owner")
    owner_id = _identifier(current["owner_id"], "current.owner_id", allow_unread=True)
    repos = _object(current["repos"], "current.repos", frozenset(REPOSITORY_KEYS))
    repositories = []
    for key in REPOSITORY_KEYS:
        entry = _object(repos[key], f"current.repos.{key}", frozenset({"name", "id"}))
        repositories.append(
            Repository(
                key=key,
                owner=owner,
                name=_repository_name(entry["name"], f"current.repos.{key}.name"),
                id=_identifier(entry["id"], f"current.repos.{key}.id", allow_unread=True),
            )
        )
    names = [repository.name.casefold() for repository in repositories]
    if len(set(names)) != len(names):
        raise IdentityError("current repository names must be distinct")
    read_ids = [repository.id for repository in repositories if repository.id]
    if len(set(read_ids)) != len(read_ids):
        raise IdentityError("current repository IDs must be distinct")

    historical = root["historical_server_owners"]
    if not isinstance(historical, list) or not historical:
        raise IdentityError("historical_server_owners must be a non-empty list")
    historical_owners = tuple(
        _owner(value, "historical_server_owners[]") for value in historical
    )
    folded = [value.casefold() for value in historical_owners]
    if len(set(folded)) != len(folded):
        raise IdentityError("historical_server_owners must be distinct")
    if owner.casefold() in folded:
        raise IdentityError("current.owner must not be a historical server owner")

    retired = root["retired_repository_ids"]
    if not isinstance(retired, list) or not retired:
        raise IdentityError("retired_repository_ids must be a non-empty list")
    retired_ids = [
        _identifier(value, "retired_repository_ids[]", allow_unread=False) for value in retired
    ]
    if len(set(retired_ids)) != len(retired_ids):
        raise IdentityError("retired_repository_ids must be distinct")
    if set(read_ids) & set(retired_ids):
        raise IdentityError("a current repository ID is a retired ID; read it back from the live repository")

    distribution = root["distribution"]
    if not isinstance(distribution, dict) or not distribution:
        raise IdentityError("distribution must be a non-empty object")
    distribution_pairs = tuple(
        (str(key), _full_name(value, f"distribution.{key}")) for key, value in sorted(distribution.items())
    )

    app = _object(root["github_app"], "github_app", frozenset({"owner", "slug", "id"}))
    app_slug = app["slug"]
    if not isinstance(app_slug, str) or not _APP_SLUG.fullmatch(app_slug):
        raise IdentityError("github_app.slug is not a GitHub App slug")

    return GitHubIdentity(
        owner=owner,
        owner_id=owner_id,
        repositories=tuple(repositories),
        distribution=distribution_pairs,
        github_app_owner=_owner(app["owner"], "github_app.owner"),
        github_app_slug=app_slug,
        github_app_id=_identifier(app["id"], "github_app.id", allow_unread=False),
        historical_server_owners=historical_owners,
        retired_repository_ids=frozenset(retired_ids),
    )


def read_identity_document(path: Path | None = None) -> dict[str, object]:
    """Return the raw identity JSON after a shape check (IDs may still be 0)."""
    source = IDENTITY_PATH if path is None else path
    try:
        document = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except OSError as exc:
        raise IdentityError(f"cannot read GitHub identity file {source.name}") from exc
    except json.JSONDecodeError as exc:
        raise IdentityError(f"GitHub identity file {source.name} is not JSON") from exc
    parse_identity(document)
    return document


def read_identity(path: Path | None = None) -> GitHubIdentity:
    """Parse the identity file without requiring read-back IDs (shape checks only)."""
    return parse_identity(read_identity_document(path))


def load_identity(path: Path | None = None) -> GitHubIdentity:
    """Parse the identity file and refuse any ID that was not read back (0)."""
    return read_identity(path).require_read_back()


def current_repository(key: str = "server", *, identity: GitHubIdentity | None = None) -> Repository:
    """Return a configured repository; an unread identity is refused even when passed in."""
    return (identity or load_identity()).require_read_back().repository(key)


def validate_server_repository(repository: str, *, identity: GitHubIdentity | None = None) -> str:
    """Accept only the exact configured server repository name, never lookalikes."""
    if repository != current_repository("server", identity=identity).full_name:
        raise ValueError("not an authorized CoreLink server repository")
    return repository


def require_repository_context(
    repository: str | None,
    repository_id: str | None,
    *,
    key: str = "server",
    identity: GitHubIdentity | None = None,
) -> str:
    """Require an exact (name, numeric ID) pair for the configured repository."""
    expected = current_repository(key, identity=identity)
    if (
        not isinstance(repository_id, str)
        or not _DECIMAL_ID.fullmatch(repository_id)
        or int(repository_id) != expected.id
        or repository != expected.full_name
    ):
        raise ValueError(f"GitHub context is not the configured CoreLink {key} repository")
    return repository


def require_github_context(
    environ: Mapping[str, str] | None = None,
    *,
    key: str = "server",
    identity: GitHubIdentity | None = None,
) -> str:
    """Check the Actions context; caller overrides are deliberately ignored."""
    values = os.environ if environ is None else environ
    return require_repository_context(
        values.get("GITHUB_REPOSITORY"),
        values.get("GITHUB_REPOSITORY_ID"),
        key=key,
        identity=identity,
    )


def resolve_server_repository(
    explicit: str | None = None, *, identity: GitHubIdentity | None = None
) -> str:
    """Use an exact caller identity, the Actions context, or a gh readback by ID."""
    identity = (identity or load_identity()).require_read_back()
    selected = (
        explicit
        or os.environ.get("CORELINK_SERVER_REPOSITORY")
        or os.environ.get("CORELINK_EXPECTED_REPOSITORY")
    )
    if selected:
        validate_server_repository(selected, identity=identity)

    # Actions already knows both values. Validate the stable ID before trusting
    # the context name; a matching name alone is not sufficient.
    if os.environ.get("GITHUB_REPOSITORY_ID") is not None or os.environ.get("GITHUB_REPOSITORY") is not None:
        return require_github_context(identity=identity)
    if selected:
        return selected

    repository_id = current_repository("server", identity=identity).id
    try:
        result = subprocess.run(
            ["gh", "api", f"repositories/{repository_id}", "--jq", ".full_name"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("repository ID lookup timed out after 15 seconds") from exc
    if result.returncode:
        raise ValueError(f"cannot resolve CoreLink server repository ID (gh exit {result.returncode})")
    return validate_server_repository(result.stdout.strip(), identity=identity)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--repo",
        help="exact authorized server repo; otherwise resolve the configured repository ID",
    )
    mode.add_argument(
        "--require-github-context",
        action="store_true",
        help="exit 0 only when GITHUB_REPOSITORY and GITHUB_REPOSITORY_ID are the configured server",
    )
    args = parser.parse_args(argv)
    try:
        if args.require_github_context:
            print(require_github_context())
        else:
            print(resolve_server_repository(args.repo))
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
