#!/usr/bin/env python3
"""Verify an exact unpublished draft release and its final-byte attestations."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    from .cli_release_draft_manifest import (
        EXPECTED_GPG_FINGERPRINT, METADATA_ASSETS, SHA, SHA256, TAG,
        _slsa_subjects, digest, safe_name, verify_manifest,
    )
except ImportError:  # script execution from `python3 scripts/verify_cli_release_draft.py`
    from cli_release_draft_manifest import (
        EXPECTED_GPG_FINGERPRINT, METADATA_ASSETS, SHA, SHA256, TAG,
        _slsa_subjects, digest, safe_name, verify_manifest,
    )


def verify(api_path: Path, directory: Path, manifest: Path, provenance: Path, bundle: Path,
           public_key: Path, tag: str, source_sha: str, manifest_sha256: str,
           expected_gpg_fingerprint: str = EXPECTED_GPG_FINGERPRINT) -> None:
    if not TAG.fullmatch(tag) or not SHA.fullmatch(source_sha) or not SHA256.fullmatch(manifest_sha256):
        raise ValueError("draft tag/source/manifest digest are not canonical")
    try:
        api = json.loads(api_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("draft release API response is invalid") from error
    if (not isinstance(api, dict) or api.get("tag_name") != tag or api.get("draft") is not True
            or api.get("published_at") is not None or api.get("prerelease") is not False):
        raise ValueError("release is not the exact unpublished draft candidate")
    assets = api.get("assets")
    if not isinstance(assets, list):
        raise ValueError("draft API asset list is invalid")
    api_assets: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("draft API asset record is invalid")
        name = safe_name(asset.get("name"))
        if name in api_assets or not isinstance(asset.get("id"), int) or asset["id"] <= 0:
            raise ValueError("draft API has a duplicate asset or invalid asset ID")
        api_assets[name] = asset
    if "staging-manifest.json" in api_assets:
        raise ValueError("private staging manifest remains attached to the draft")
    expected = verify_manifest(
        directory, manifest, public_key, tag, source_sha, manifest_sha256,
        include_provenance=True, expected_gpg_fingerprint=expected_gpg_fingerprint,
    )
    if (set(api_assets) != set(expected) | METADATA_ASSETS
            or {path.name for path in directory.iterdir()} != set(expected) | METADATA_ASSETS):
        raise ValueError("draft asset inventory is not closed-world")
    for name, asset in api_assets.items():
        remote_digest = asset.get("digest")
        if remote_digest is not None and remote_digest != f"sha256:{digest(directory / name)}":
            raise ValueError(f"draft API digest differs from downloaded bytes: {name}")
    if _slsa_subjects(provenance, bundle) != expected:
        raise ValueError("draft SLSA subjects are not exactly bound to every final artifact")


def main() -> int:
    parser = argparse.ArgumentParser()
    for flag in ("api-json", "directory", "manifest", "provenance", "bundle", "public-key"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        verify(args.api_json, args.directory, args.manifest, args.provenance, args.bundle,
               args.public_key, args.tag, args.source_sha, args.manifest_sha256)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"verify-cli-release-draft: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
