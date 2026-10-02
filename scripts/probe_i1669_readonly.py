#!/usr/bin/env python3
"""Run the bounded, read-only production evidence lane for issue #1669.

The lane has no SQL input.  It sends only the three aggregate statements in
``QUERY_ALLOWLIST`` to Cloudflare D1, retains no row payload, and emits a
redacted receipt containing counts and SHA-256 bindings.  It never performs a
backfill or changes D1, DSR, or audit data.

Exit status: 0 when the full non-empty population is provably satisfied
(``COMPLIANT``) or its only non-satisfied rows are erased lineage under the
#1669 policy B documented exception (``DOCUMENTED_EXCEPTION``; the receipt
status names which); 1 when a known mismatch or unevaluable row is found; 2
when evidence is absent, empty, partial, or malformed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_ID = re.compile(r"^[0-9a-fA-F]{32}$")
DATABASE_ID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
MAX_RESPONSE_BYTES = 1_048_576


def _load_residency_module() -> Any:
    path = ROOT / "scripts" / "verify_audit_residency.py"
    spec = importlib.util.spec_from_file_location("verify_audit_residency", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("residency verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RESIDENCY = _load_residency_module()
POPULATION_SQL = """
SELECT
    COUNT(*) AS audit_rows,
    COUNT(DISTINCT tenant_id) AS audit_tenants,
    SUM(CASE WHEN tenant_id IS NULL OR tenant_id = '' THEN 1 ELSE 0 END)
        AS blank_tenant_rows
FROM audit_outbox
""".strip()
BACKFILL_COMPLETENESS_SQL = """
SELECT
    COUNT(*) AS audit_rows,
    SUM(CASE WHEN t.tenant_id IS NULL AND a.tenant_id <> '_public'
        THEN 1 ELSE 0 END) AS orphan_rows,
    SUM(CASE WHEN t.tenant_id IS NOT NULL AND a.tenant_id <> '_public'
        THEN 1 ELSE 0 END) AS joinable_rows,
    SUM(CASE WHEN a.tenant_id = '_public'
                  AND a.region = 'wnam'
                  AND a.event_type IN ({public_events})
        THEN 1 ELSE 0 END)
        AS reserved_public_rows,
    SUM(CASE WHEN a.tenant_id = '_public'
                  AND (a.region IS NULL OR a.region <> 'wnam'
                       OR a.event_type IS NULL
                       OR a.event_type NOT IN ({public_events}))
        THEN 1 ELSE 0 END) AS invalid_public_rows,
    SUM(CASE WHEN t.tenant_id IS NULL AND a.tenant_id <> '_public' AND EXISTS (
        SELECT 1 FROM dsr_erasure_log AS d WHERE d.tenant_id = a.tenant_id
    ) THEN 1 ELSE 0 END) AS erased_orphan_rows
FROM audit_outbox AS a
LEFT JOIN tenant AS t ON t.tenant_id = a.tenant_id
""".format(public_events=RESIDENCY._PUBLIC_EVENTS_SQL).strip()

# Do not accept a caller-provided SQL string.  Every request must be one of
# these exact aggregate SELECTs; the write verbs are absent by construction.
QUERY_ALLOWLIST = {
    "residency": RESIDENCY.RESIDENCY_SQL,
    "population": POPULATION_SQL,
    "backfill_completeness": BACKFILL_COMPLETENESS_SQL,
}
POPULATION_FIELDS = ("audit_rows", "audit_tenants", "blank_tenant_rows")
BACKFILL_FIELDS = (
    "audit_rows",
    "orphan_rows",
    "joinable_rows",
    "reserved_public_rows",
    "invalid_public_rows",
    "erased_orphan_rows",
)


class ProbeError(RuntimeError):
    """Evidence is absent, unsafe, partial, or malformed."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_allowlist() -> None:
    for name, query in QUERY_ALLOWLIST.items():
        normalized = re.sub(r"\s+", " ", query).strip().lower()
        if query not in QUERY_ALLOWLIST.values() or not (
            normalized.startswith("select ") or normalized.startswith("with ")
        ):
            raise ProbeError(f"query allowlist entry {name} is not a SELECT")
        if re.search(r"\b(insert|update|delete|replace|alter|drop|create|pragma|attach)\b", normalized):
            raise ProbeError(f"query allowlist entry {name} contains a write or control verb")


def _request(account_id: str, token: str, database_id: str, query: str) -> tuple[object, str]:
    if query not in QUERY_ALLOWLIST.values():
        raise ProbeError("refusing a query outside the allowlist")
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{database_id}/query",
        data=json.dumps({"sql": query}).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        raise ProbeError("D1 read unavailable") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProbeError("D1 response exceeded the bounded evidence size")
    try:
        return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError("D1 response was not valid JSON") from exc


def _aggregate(payload: object, fields: tuple[str, ...]) -> dict[str, int]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ProbeError("D1 response is not successful")
    result = payload.get("result")
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ProbeError("D1 response is partial")
    result_set = result[0]
    if result_set.get("success") is not True:
        raise ProbeError("D1 result set is not successful")
    rows = result_set.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ProbeError("D1 aggregate row is missing or partial")
    row = rows[0]
    if set(row) != set(fields):
        raise ProbeError("D1 aggregate schema is incomplete or unexpected")
    values: dict[str, int] = {}
    for field in fields:
        value = row[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProbeError(f"D1 aggregate field {field} is invalid")
        values[field] = value
    return values


def _write(path: Path, receipt: dict[str, object]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ProbeError("receipt output must be a regular non-symlink file")
    path.parent.mkdir(parents=True, exist_ok=True)
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _hash(unsigned)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def run(account_id: str, database_id: str, token: str, output: Path) -> int:
    if not ACCOUNT_ID.fullmatch(account_id) or not DATABASE_ID.fullmatch(database_id):
        raise ProbeError("account ID or D1 UUID is malformed")
    if not token:
        raise ProbeError("Cloudflare API token is missing")
    _validate_allowlist()
    receipt: dict[str, object] = {
        "schema": "corelink.issue-1669.read-only-residency.v1",
        "issue": 1669,
        "mode": "production_read_only",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "account_id_sha256": hashlib.sha256(account_id.encode()).hexdigest(),
        "database_id_sha256": hashlib.sha256(database_id.encode()).hexdigest(),
        "queries": [],
    }
    try:
        observations: dict[str, dict[str, int]] = {}
        for name, query in QUERY_ALLOWLIST.items():
            payload, payload_hash = _request(account_id, token, database_id, query)
            fields = tuple(RESIDENCY.COUNT_FIELDS) if name == "residency" else POPULATION_FIELDS if name == "population" else BACKFILL_FIELDS
            observations[name] = _aggregate(payload, fields)
            receipt["queries"].append({"name": name, "query_sha256": _hash(query), "response_sha256": payload_hash, "row_count": 1})
        # Preserve aggregate-only diagnostics even when a reconciliation gate
        # fails below.  No row payload or tenant identifier is retained.
        receipt["counts"] = observations
        counts = RESIDENCY.Counts(**observations["residency"])
        state, reason = RESIDENCY.assess(counts, environment="production")
        population = observations["population"]
        completeness = observations["backfill_completeness"]
        if population["audit_rows"] == 0 or population["audit_rows"] != counts.total_rows:
            raise ProbeError("historical audit population is empty or inconsistent")
        if population["blank_tenant_rows"]:
            raise ProbeError("historical audit population contains blank tenant IDs")
        if completeness["audit_rows"] != counts.total_rows:
            raise ProbeError("backfill completeness denominator is inconsistent")
        if (
            completeness["orphan_rows"]
            + completeness["joinable_rows"]
            + completeness["reserved_public_rows"]
            + completeness["invalid_public_rows"]
            != counts.total_rows
        ):
            raise ProbeError("backfill completeness partition is partial")
        if (
            completeness["orphan_rows"] != counts.orphan_rows
            or completeness["reserved_public_rows"] != counts.reserved_public_rows
            or completeness["invalid_public_rows"] != counts.invalid_public_rows
            or completeness["erased_orphan_rows"] != counts.erased_orphan_rows
        ):
            raise ProbeError("backfill completeness does not reconcile with residency")
        receipt.update({"status": state, "reason": reason})
        _write(output, receipt)
        return 0 if state in RESIDENCY.PASSING_STATES else 1
    except (ProbeError, RESIDENCY.Indeterminate) as exc:
        receipt.update({"status": "INDETERMINATE", "reason": str(exc)})
        _write(output, receipt)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--database-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args.account_id, args.database_id, os.environ.get("CLOUDFLARE_API_TOKEN", ""), args.output)
    except (ProbeError, OSError) as exc:
        print(f"issue-1669 read-only probe failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
