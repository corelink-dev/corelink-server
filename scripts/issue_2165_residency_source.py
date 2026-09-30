#!/usr/bin/env python3
"""Produce one archive-compatible residency row from protected readbacks.

The script is credentialless and makes no provider calls. It delegates target
and raw-response validation to issue_2165_residency_receipt, then emits only a
redacted archive row. A Cloudflare provider URL is required as the physical
placement event reference; a local digest or synthetic identifier is rejected.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
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
    source_bundle = sources.get("d1_physical_placement") if isinstance(sources, dict) else None
    source = source_bundle.get("source") if isinstance(source_bundle, dict) else None
    ref = source.get("provider_ref") if isinstance(source, dict) else None
    target = manifest.get("cloudflare", {}) if isinstance(manifest, dict) else {}
    account = target.get("account_id")
    d1 = target.get("d1", {})
    database = d1.get("database_id") if isinstance(d1, dict) else None
    if not isinstance(ref, str):
        raise SourceError("physical-placement provider reference is missing")
    parsed = urlsplit(ref)
    hostname = (parsed.hostname or "").casefold()
    cloudflare_owned = hostname == "cloudflare.com" or hostname.endswith(".cloudflare.com")
    if (parsed.scheme != "https" or not cloudflare_owned
            or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.path
            or not isinstance(account, str) or not account
            or not isinstance(database, str) or not database
            or re.search(r"(?:sha-?256|digest|hash)[:=/.-]?[a-f0-9]{16,}", ref, re.IGNORECASE)):
        raise SourceError("physical-placement event_ref must be a direct Cloudflare-owned HTTPS provider reference")
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
