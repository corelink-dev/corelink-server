#!/usr/bin/env python3
"""Collect only signed deployment context for the owner-only evidence lane.

This intentionally does not mint/use a PAT or run production traffic.  The
workflow keeps those credentials in its process environment and hands the
owner a context file plus an explicit packet template; no credential or raw
provider response is written to the artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    from server_repository import require_repository_context
except ModuleNotFoundError:  # imported as scripts.collect_b102_b108_context
    from scripts.server_repository import require_repository_context

SHA = re.compile(r"^[0-9a-f]{40}$")


def is_server_repository(repository: str, repository_id: str) -> bool:
    """Match only the configured server repository: exact name AND numeric ID.

    Both come from config/github-identity.json via scripts/server_repository.py.
    """
    try:
        require_repository_context(repository, repository_id)
    except ValueError:
        return False
    return True


def read(path: Path) -> tuple[object, str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not JSON") from exc
    return value, hashlib.sha256(raw).hexdigest()


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"missing GitHub context variable {name}")
    return value


def provider_records(value: object):
    """Yield only provider objects carrying their own commit and ID.

    A commit found in one deployment and an ID found in another are not an
    identity join.  Keep the record boundary intact so the verifier cannot be
    tricked by unrelated nested values.
    """
    if isinstance(value, dict):
        commits = [value[key] for key in ("commit", "sha", "commit_hash", "version_sha") if key in value]
        ids = [value[key] for key in ("deployment_id", "id", "version_id") if key in value]
        for commit in commits:
            for deployment_id in ids:
                yield str(commit), str(deployment_id)
        for child in value.values():
            yield from provider_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from provider_records(child)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-deployment", type=Path, required=True)
    parser.add_argument("--provider-deployment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        repo = required("GITHUB_REPOSITORY")
        repo_id = required("GITHUB_REPOSITORY_ID")
        sha = required("GITHUB_SHA").lower()
        event = required("GITHUB_EVENT_NAME")
        run_id = required("GITHUB_RUN_ID")
        run_attempt = required("GITHUB_RUN_ATTEMPT")
        run_started_at = required("GITHUB_RUN_STARTED_AT")
        github_ref = required("GITHUB_REF")
        if not is_server_repository(repo, repo_id) or not SHA.fullmatch(sha) or not run_id.isdigit():
            raise ValueError("invalid canonical GitHub context")
        if not run_attempt.isdigit() or int(run_attempt) < 1:
            raise ValueError("invalid GitHub run attempt")
        try:
            started = dt.datetime.fromisoformat(run_started_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid GitHub run start timestamp") from exc
        if started.tzinfo is None:
            raise ValueError("GitHub run start timestamp must include a timezone")
        if event not in {"workflow_dispatch", "workflow_run"}:
            raise ValueError("lane must be owner-triggered")
        if not github_ref.startswith("refs/"):
            raise ValueError("invalid full Git ref")
        github, github_digest = read(args.github_deployment)
        provider, provider_digest = read(args.provider_deployment)
        if isinstance(github, dict):
            deployments = github.get("deployments", [])
        elif isinstance(github, list):
            deployments = [entry for page in github if isinstance(page, list) for entry in page]
        else:
            deployments = []
        if not isinstance(deployments, list):
            raise ValueError("GitHub deployment response has no deployments list")
        candidates = [d for d in deployments if isinstance(d, dict) and d.get("sha") == sha and d.get("environment") == "production"]
        if not candidates:
            raise ValueError("no GitHub production deployment is bound to GITHUB_SHA")
        deployment_id = str(candidates[0].get("id", ""))
        if not deployment_id.isdigit():
            raise ValueError("GitHub deployment id is invalid")
        matches = [(commit, provider_id) for commit, provider_id in provider_records(provider) if commit == sha and provider_id and provider_id != deployment_id]
        if len(matches) != 1:
            raise ValueError("provider deployment must contain exactly one record bound to GITHUB_SHA")
        provider_commit, provider_id = matches[0]
        result = {
            "schema": "corelink.performance-evidence.context.v1",
            "repository": repo,
            "environment": "production",
            "source_head": sha,
            "github_event": event,
            "github_run_id": run_id,
            "github_run_attempt": run_attempt,
            "github_run_started_at": run_started_at,
            "github_ref": github_ref,
            "github_actor": required("GITHUB_ACTOR"),
            # Provider and GitHub IDs are distinct namespaces; both are kept
            # so a reviewer can join the records without trusting a label.
            "deployment_id": provider_id,
            "github_deployment_id": deployment_id,
            "provider": "cloudflare",
            "provider_commit": provider_commit,
            "provider_record": {"provider": "cloudflare", "environment": "production", "commit": provider_commit, "deployment_id": provider_id},
            "provider_blob_sha256": "sha256:" + provider_digest,
            "github_response_sha256": "sha256:" + github_digest,
        }
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"context collection failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
