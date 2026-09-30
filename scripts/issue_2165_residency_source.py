#!/usr/bin/env python3
"""Produce one archive-compatible row from the protected D1 metadata GET.

The live request is performed in the protected workflow; caller-supplied URLs
and physical-placement attestations are not accepted as evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import issue_2165_residency_receipt as validator


class SourceError(ValueError):
    """The validated receipt cannot be safely projected into the audit row."""


def archive_row(manifest: Any, sources: Any, raw_evidence: Any, env: dict[str, str]) -> dict[str, Any]:
    """Validate protected inputs and return exactly one safe residency row."""
    validator._validate_environment_binding(manifest, env)
    result = validator.validate(manifest, sources, raw_evidence)
    rows = result.get("rows") if isinstance(result, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("step") != "residency" or rows[0].get("status") != "verified":
        raise SourceError("existing residency validator did not produce exactly one verified row")
    source_bundle = sources.get("d1_control_plane") if isinstance(sources, dict) else None
    target = manifest.get("cloudflare", {}) if isinstance(manifest, dict) else {}
    account = target.get("account_id")
    d1 = target.get("d1", {})
    database = d1.get("database_id") if isinstance(d1, dict) else None
    if not isinstance(source_bundle, dict) or source_bundle.get("method") != "authenticated-get":
        raise SourceError("authenticated D1 metadata GET source is missing")
    if (not isinstance(account, str) or not validator.ACCOUNT_ID_RE.fullmatch(account)
            or not isinstance(database, str) or not validator.D1_DATABASE_UUID_RE.fullmatch(database)):
        raise SourceError("protected D1 target is missing")
    ref = f"https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}"
    if source_bundle.get("endpoint") != ref:
        raise SourceError("D1 metadata GET endpoint is not the exact protected account/database path")
    verified_sources = rows[0].get("source", {})
    digest = verified_sources.get("digest") if isinstance(verified_sources, dict) else None
    occurred = rows[0].get("occurred_at_utc")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise SourceError("validated provider source digest is missing")
    if not isinstance(occurred, str):
        raise SourceError("validated UTC observation time is missing")
    return {"step": "residency", "occurred_at_utc": occurred,
            "source": {"kind": "d1", "event_ref": ref, "digest": digest}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--raw-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        temp = os.environ.get("RUNNER_TEMP")
        inputs = (args.manifest, args.sources, args.raw_evidence)
        if not temp or any(path.resolve().parent != Path(temp).resolve() for path in inputs):
            raise SourceError("protected inputs must be directly under RUNNER_TEMP")
        if args.output.resolve().parent != Path(temp).resolve():
            raise SourceError("output must be directly under RUNNER_TEMP")
        manifest = validator._private_json(args.manifest, "manifest")
        sources = validator._private_json(args.sources, "sources")
        raw = validator._private_json(args.raw_evidence, "raw evidence")
        row = archive_row(manifest, sources, raw, dict(os.environ))
        validator._write_private(args.output, row)
    except (SourceError, validator.ResidencyError, OSError) as exc:
        print(f"residency source: blocked ({exc})", file=sys.stderr)
        return 2
    print("residency source: verified")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
