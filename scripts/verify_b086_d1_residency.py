#!/usr/bin/env python3
"""Fail-closed source verifier for the B-086 shared-D1 launch posture.

B-086 verifies the selected source posture: five production bindings use one
shared D1 database, and the pending DPA accurately scopes D1 as a global
control plane instead of a tenant-pinned service. It does not establish an
executed transfer mechanism or counsel approval.

The verifier uses TOML and a bounded Markdown-table parser instead of grep.
That keeps comments and quoted/string bait inert, while URLs containing
hyphens remain ordinary table content rather than breaking the claim check.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRANGLER = ROOT / "wrangler.toml"
DPA = ROOT / "legal/dpa-residency-amendment.md"
BACKLOG = ROOT / "BACKLOG.md"
MANIFEST = ROOT / "evidence/i1654/d1-residency-contract-manifest.json"
RESOLUTION = ROOT / "evidence/owner-actions/B-086/d1-residency-resolution.json"

PRODUCTION_ENVS = ("prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
EXPECTED_JURISDICTION_KEYS = (
    ("prod-lhr", "r2_buckets", "CAS_BUCKET", "eu"),
    ("prod-lhr", "r2_buckets", "AC_BUCKET_LHR", "eu"),
)
EXPECTED_ROLE = "Infrastructure: Workers, R2, D1, KV, Durable Objects, Custom Domains"
EXPECTED_SCOPE = (
    "R2/DO source paths are tenant-pinned; shared D1 is global without a D1 jurisdiction binding. "
    "A read-only 2026-09-30 Wrangler readback of `corelink-prod-d1` reported ENAM metadata and `jurisdiction=null`; that is not a physical-location guarantee or legal approval."
)
EXPECTED_D1_ID = "d64742ea-e102-40b2-a844-ff02e3f94562"
EXPECTED_D1_NAME = "corelink-prod-d1"
EXPECTED_ACTIVE_WORKERS = {
    "prod": "corelink-prod",
    "prod-sam": "corelink-prod-sam",
    "prod-lhr": "corelink-prod-lhr",
    "prod-nrt": "corelink-prod-nrt",
    "prod-syd": "corelink-prod-syd",
}


class VerificationError(RuntimeError):
    """A source contract is missing or has drifted."""


def _load_toml(text: str) -> dict[str, object]:
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise VerificationError(f"wrangler.toml is not valid TOML: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("wrangler.toml did not decode to a table")
    return value


def _load_manifest() -> dict[str, object]:
    try:
        import json

        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise VerificationError(f"contract manifest is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("contract manifest must be a JSON object")
    required = {
        "schema",
        "issue",
        "backlog_id",
        "credentialless",
        "network_calls",
        "mutating_actions",
        "status",
        "sources",
        "acceptance",
        "external_blocker",
        "prohibited",
    }
    if set(value) != required:
        raise VerificationError("contract manifest has unexpected or missing fields")
    if value["schema"] != "corelink.d1.residency-contract-manifest.v1":
        raise VerificationError("unsupported contract manifest schema")
    if value["issue"] != 1654 or value["backlog_id"] != "B-086":
        raise VerificationError("contract manifest issue identity drifted")
    if value["credentialless"] is not True or value["network_calls"] is not False or value["mutating_actions"] is not False:
        raise VerificationError("contract manifest must be credentialless, network-free, and read-only")
    if value["status"] != "open_external_counsel_signoff_pending":
        raise VerificationError("contract manifest must keep B-086 open pending counsel sign-off")
    sources = value["sources"]
    if sources != {
        "wrangler": "wrangler.toml",
        "legal_instrument": "legal/dpa-residency-amendment.md",
        "backlog": "BACKLOG.md",
        "verifier": "scripts/verify_b086_d1_residency.py",
    }:
        raise VerificationError("contract manifest source paths drifted")
    acceptance = value["acceptance"]
    if not isinstance(acceptance, dict) or acceptance.get("production_environments") != list(PRODUCTION_ENVS):
        raise VerificationError("contract manifest production environment set drifted")
    if acceptance.get("d1_binding") != "CONFIG_DB" or acceptance.get("distinct_database_ids") != 1:
        raise VerificationError("contract manifest shared-D1 contract drifted")
    blocker = value["external_blocker"]
    if not isinstance(blocker, dict) or blocker.get("owner") != "counsel" or blocker.get("decision") != "approve the applicable transfer basis and effective customer-facing terms for the selected shared-D1 posture":
        raise VerificationError("contract manifest counsel boundary drifted")
    return value


def _production_d1(doc: dict[str, object]) -> list[tuple[str, str]]:
    envs = doc.get("env")
    if not isinstance(envs, dict):
        raise VerificationError("wrangler.toml has no active [env.*] table")

    rows: list[tuple[str, str]] = []
    for env_name in PRODUCTION_ENVS:
        env = envs.get(env_name)
        if not isinstance(env, dict):
            raise VerificationError(f"missing production environment: {env_name}")
        d1 = env.get("d1_databases")
        if not isinstance(d1, list) or len(d1) != 1:
            raise VerificationError(
                f"{env_name}: expected exactly one active production D1 binding"
            )
        row = d1[0]
        if not isinstance(row, dict) or row.get("binding") != "CONFIG_DB":
            raise VerificationError(f"{env_name}: active D1 binding is not CONFIG_DB")
        database_id = row.get("database_id")
        if not isinstance(database_id, str) or not UUID.fullmatch(database_id):
            raise VerificationError(f"{env_name}: CONFIG_DB database_id is not a UUID")
        if "jurisdiction" in row:
            raise VerificationError(f"{env_name}: D1 binding has an unexpected jurisdiction key")
        rows.append((env_name, database_id.lower()))

    if len(rows) != len(PRODUCTION_ENVS):
        raise VerificationError("production D1 population is incomplete")
    return rows


def verify_readback_record(record: dict[str, object], wrangler_text: str) -> None:
    """Fail closed unless fresh provider and exact active-version reads match source."""
    if not isinstance(record, dict):
        raise VerificationError("B-086 D1 readback receipt is missing or malformed")
    provider = record.get("provider_readback")
    deployed = record.get("deployed_active_readback")
    if not isinstance(provider, dict) or not isinstance(deployed, dict):
        raise VerificationError("B-086 exact-target or active-version readback is missing")
    if provider.get("schema") != "corelink.cloudflare.d1-target-readback.v1" or deployed.get("schema") != "corelink.cloudflare.workers-active-d1-bindings.v1":
        raise VerificationError("B-086 readback receipt schema is missing or unsupported")
    try:
        captured = dt.datetime.fromisoformat(str(provider["captured_at"]).replace("Z", "+00:00"))
        active_captured = dt.datetime.fromisoformat(str(deployed["captured_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        raise VerificationError("B-086 readback timestamps are missing or invalid") from None
    now = dt.datetime.now(dt.timezone.utc)
    if any(value.tzinfo is None or value > now or now - value > dt.timedelta(hours=24) for value in (captured, active_captured)):
        raise VerificationError("B-086 exact-target or active-version readback is stale (24-hour limit)")
    if provider.get("method") != "npx wrangler@latest d1 info corelink-prod-d1 (read-only)" or provider.get("wrangler_version") != "4.145.0":
        raise VerificationError("B-086 D1 readback method/version changed; refresh and review")
    if (
        provider.get("target_name") != EXPECTED_D1_NAME
        or provider.get("database_id") != EXPECTED_D1_ID
        or provider.get("num_tables") != 162
        or provider.get("running_in_region") != "ENAM"
        or provider.get("jurisdiction") is not None
        or provider.get("read_replication_mode") != "auto"
        or provider.get("physical_location_conclusion") != "NOT_INFERRED_FROM_PROVIDER_METADATA"
        or provider.get("mutations_performed") != []
    ):
        raise VerificationError("B-086 exact-target metadata or physical-location boundary changed")
    if deployed.get("wrangler_version") != "4.145.0" or deployed.get("d1_database_id") != EXPECTED_D1_ID:
        raise VerificationError("B-086 active-version readback is bound to a different database or Wrangler version")
    if deployed.get("mutations_performed") != [] or deployed.get("secrets_or_variable_values_recorded") is not False:
        raise VerificationError("B-086 active-version receipt violates read-only/redaction boundary")
    rows = deployed.get("active_workers")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_ACTIVE_WORKERS):
        raise VerificationError("B-086 active-version receipt does not contain exactly five production Workers")
    try:
        config = _load_toml(wrangler_text)
        envs = config["env"]
    except (KeyError, TypeError):
        raise VerificationError("B-086 source Worker environment config is malformed") from None
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise VerificationError("B-086 active Worker entry is malformed")
        env = row.get("environment")
        if env not in EXPECTED_ACTIVE_WORKERS or env in seen:
            raise VerificationError("B-086 active Worker environment is missing, duplicate, or unexpected")
        seen.add(env)
        expected_worker = EXPECTED_ACTIVE_WORKERS[env]
        source_env = envs.get(env) if isinstance(envs, dict) else None
        source_bindings = source_env.get("d1_databases", []) if isinstance(source_env, dict) else []
        source_d1 = [binding for binding in source_bindings if isinstance(binding, dict) and binding.get("binding") == "CONFIG_DB"]
        if row.get("worker") != expected_worker or not isinstance(source_env, dict) or source_env.get("name") != expected_worker:
            raise VerificationError(f"B-086 active Worker {env} does not match source config")
        if len(source_d1) != 1 or source_d1[0].get("database_id") != EXPECTED_D1_ID:
            raise VerificationError(f"B-086 source CONFIG_DB for {env} no longer matches exact target")
        if row.get("active_percentage") != 100 or row.get("CONFIG_DB_binding_count") != 1 or row.get("CONFIG_DB_database_id") != EXPECTED_D1_ID:
            raise VerificationError(f"B-086 active version for {env} does not prove the exact CONFIG_DB binding")
        for field in ("deployment_id", "version_id"):
            value = row.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value, re.I):
                raise VerificationError(f"B-086 {env} {field} is missing or malformed")
        if row.get("deployment_active_version_id") != row.get("version_id"):
            raise VerificationError(f"B-086 {env} active deployment and detailed version readback disagree")
        if not isinstance(row.get("version_number"), int) or row["version_number"] < 1:
            raise VerificationError(f"B-086 {env} version number is missing")
        for field in ("deployment_created_on", "version_created_on"):
            try:
                value = dt.datetime.fromisoformat(str(row[field]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                raise VerificationError(f"B-086 {env} {field} is missing or invalid") from None
            if value.tzinfo is None:
                raise VerificationError(f"B-086 {env} {field} lacks timezone")
        if not isinstance(row.get("script_etag"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["script_etag"], re.I):
            raise VerificationError(f"B-086 {env} deployed script etag is missing or malformed")
    if seen != set(EXPECTED_ACTIVE_WORKERS):
        raise VerificationError("B-086 active-version readback omits a production Worker")


def _jurisdiction_keys(doc: dict[str, object]) -> list[tuple[str, str, int, str, str]]:
    envs = doc.get("env")
    if not isinstance(envs, dict):
        raise VerificationError("wrangler.toml has no active [env.*] table")

    found: list[tuple[str, str, int, str, str]] = []

    def visit(value: object, env_name: str, section_name: str, index: int) -> None:
        if isinstance(value, dict):
            if "jurisdiction" in value:
                binding = value.get("binding", "")
                jurisdiction = value.get("jurisdiction")
                if not isinstance(binding, str) or not isinstance(jurisdiction, str):
                    raise VerificationError(
                        f"{env_name}.{section_name}[{index}]: malformed jurisdiction key"
                    )
                found.append((env_name, section_name, index, binding, jurisdiction))
            for nested in value.values():
                visit(nested, env_name, section_name, index)
        elif isinstance(value, list):
            for nested_index, nested in enumerate(value):
                visit(nested, env_name, section_name, nested_index)

    for env_name, env in envs.items():
        if not isinstance(env, dict):
            continue
        for section_name, value in env.items():
            visit(value, env_name, section_name, -1)
    return found


def _table_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    # The targeted row has no escaped pipes.  Keep this split deliberately
    # narrow: links and hyphens are cell content, not syntax to be filtered.
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def _dpa_shared_global_claim_count(text: str) -> int:
    start_marker = "### 8.1 Authorised Sub-processors"
    start = text.find(start_marker)
    if start < 0:
        raise VerificationError("DPA Section 8.1 is missing")
    end_match = re.search(r"^###\s+", text[start + len(start_marker) :], re.MULTILINE)
    end = start + len(start_marker) + end_match.start() if end_match else len(text)
    section = text[start:end]

    rows: list[list[str]] = []
    in_fence = False
    in_html_comment = False
    for line in section.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if in_html_comment:
            if "-->" not in line:
                continue
            line = line.split("-->", 1)[1]
            in_html_comment = False
        if "<!--" in line:
            before, after = line.split("<!--", 1)
            if "-->" not in after:
                line = before
                in_html_comment = True
            else:
                line = before + after.split("-->", 1)[1]
        cells = _table_cells(line)
        if cells is None or len(cells) != 5:
            continue
        if cells[0] != "**Cloudflare, Inc.**":
            continue
        rows.append(cells)

    claims = [
        row
        for row in rows
        if row[1] == EXPECTED_ROLE and row[4] == EXPECTED_SCOPE
    ]
    if len(rows) != 1:
        raise VerificationError(
            f"DPA Section 8.1 must contain exactly one active Cloudflare row; found {len(rows)}"
        )
    if len(claims) != 1:
        raise VerificationError(
            "DPA Section 8.1 Cloudflare row does not make the exact shared-global D1 disclosure"
        )
    return len(claims)


def assess(
    wrangler_text: str, dpa_text: str, backlog_text: str | None = None
) -> tuple[int, int, int, int]:
    _load_manifest()
    doc = _load_toml(wrangler_text)
    d1_rows = _production_d1(doc)
    jurisdiction_keys = _jurisdiction_keys(doc)
    expected = list(EXPECTED_JURISDICTION_KEYS)
    actual = [
        (env, section, binding, value)
        for env, section, _, binding, value in jurisdiction_keys
    ]
    if actual != expected:
        raise VerificationError(
            "active jurisdiction keys drifted: "
            f"expected {expected!r}, found {actual!r}"
        )
    dpa_claims = _dpa_shared_global_claim_count(dpa_text)

    if backlog_text is not None:
        match = re.search(r"^### B-086 .*?(?=^### |\Z)", backlog_text, re.MULTILINE | re.DOTALL)
        if not match:
            raise VerificationError("B-086 backlog section is missing")
        section = match.group(0)
        if "status: open" not in section:
            raise VerificationError("B-086 must remain open pending counsel sign-off")
        if "Counsel: aprovar a base de transferência" not in section:
            raise VerificationError("B-086 counsel sign-off boundary is missing")

    return (
        len(d1_rows),
        len({database_id for _, database_id in d1_rows}),
        dpa_claims,
        len(jurisdiction_keys),
    )


def _mutate_dpa_row(text: str, replacement: str) -> str:
    needle = "| **Cloudflare, Inc.** |"
    line = next((line for line in text.splitlines() if line.startswith(needle)), None)
    if line is None:
        raise VerificationError("self-test DPA row fixture did not match")
    return text.replace(line, replacement, 1)


def self_test(wrangler_text: str, dpa_text: str, readback_record: dict[str, object]) -> None:
    cloudflare_line = next(
        (line for line in dpa_text.splitlines() if line.startswith("| **Cloudflare, Inc.** |")),
        None,
    )
    if cloudflare_line is None:
        raise VerificationError("self-test DPA row fixture did not match")
    url_shape = dpa_text.replace(
        "https://www.cloudflare.com/cloudflare-customer-dpa/",
        "https://www.cloudflare.com/cloudflare-customer-dpa-v1-0-0/",
        1,
    )
    if assess(wrangler_text, url_shape)[2] != 1:
        raise VerificationError("hyphenated DPA URL shape caused a false negative")
    mutations = (
        (
            "DPA comment-wrap",
            _mutate_dpa_row(dpa_text, "<!-- " + cloudflare_line + " -->"),
        ),
        (
            "DPA quoted scope",
            _mutate_dpa_row(
                dpa_text,
                cloudflare_line.replace(
                    "| " + EXPECTED_SCOPE + " |", '| "' + EXPECTED_SCOPE + '" |', 1
                ),
            ),
        ),
        (
            "tenant-pinned D1 claim",
            _mutate_dpa_row(
                dpa_text,
                cloudflare_line.replace(EXPECTED_SCOPE, "tenant-pinned D1 in each selected region", 1),
            ),
        ),
        (
            "DPA URL-only decoy",
            _mutate_dpa_row(
                dpa_text,
                cloudflare_line.replace(
                    "**Cloudflare, Inc.**",
                    "**Cloudflare, Inc.** (https://example.invalid/dpa-with-hyphens)",
                    1,
                ),
            ),
        ),
        (
            "commented D1 binding",
            wrangler_text.replace(
                'database_id = "d64742ea-e102-40b2-a844-ff02e3f94562"',
                '# database_id = "d64742ea-e102-40b2-a844-ff02e3f94562"',
                1,
            ),
        ),
        (
            "physical-location guarantee",
            _mutate_dpa_row(
                dpa_text,
                cloudflare_line.replace(
                    "not a physical-location guarantee", "is a physical-location guarantee", 1
                ),
            ),
        ),
        (
            "approved transfer assertion",
            _mutate_dpa_row(
                dpa_text,
                cloudflare_line.replace(
                    "or legal approval", "with approved transfer basis and legal approval", 1
                ),
            ),
        ),
        (
            "jurisdiction string bait",
            re.sub(
                r'(?m)^jurisdiction = "eu"$',
                '# jurisdiction = "eu"',
                wrangler_text,
                count=1,
            ),
        ),
    )
    for label, mutated in mutations:
        try:
            if label in {"commented D1 binding", "jurisdiction string bait"}:
                assess(mutated, dpa_text)
            else:
                assess(wrangler_text, mutated)
        except (VerificationError, tomllib.TOMLDecodeError):
            continue
        raise VerificationError(f"mutation unexpectedly passed: {label}")

    receipt_mutations: list[tuple[str, dict[str, object]]] = []
    missing = json.loads(json.dumps(readback_record))
    missing.pop("provider_readback", None)
    receipt_mutations.append(("missing exact-target readback", missing))
    stale = json.loads(json.dumps(readback_record))
    stale["provider_readback"]["captured_at"] = "2000-01-01T00:00:00Z"
    receipt_mutations.append(("stale exact-target readback", stale))
    stale_active = json.loads(json.dumps(readback_record))
    stale_active["deployed_active_readback"]["captured_at"] = "2000-01-01T00:00:00Z"
    receipt_mutations.append(("stale active-version readback", stale_active))
    physical = json.loads(json.dumps(readback_record))
    physical["provider_readback"]["physical_location_conclusion"] = "PHYSICAL_LOCATION_GUARANTEED"
    receipt_mutations.append(("physical-location overclaim in receipt", physical))
    wrong_id = json.loads(json.dumps(readback_record))
    wrong_id["deployed_active_readback"]["active_workers"][0]["CONFIG_DB_database_id"] = "00000000-0000-4000-8000-000000000000"
    receipt_mutations.append(("active CONFIG_DB target mismatch", wrong_id))
    for label, mutated in receipt_mutations:
        try:
            verify_readback_record(mutated, wrangler_text)
        except VerificationError:
            continue
        raise VerificationError(f"readback mutation unexpectedly passed: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test", action="store_true", help="run comment/string/shape mutations"
    )
    args = parser.parse_args()
    try:
        wrangler_text = WRANGLER.read_text(encoding="utf-8")
        dpa_text = DPA.read_text(encoding="utf-8")
        backlog_text = BACKLOG.read_text(encoding="utf-8")
        readback_record = json.loads(RESOLUTION.read_text(encoding="utf-8"))
        verify_readback_record(readback_record, wrangler_text)
        source_hashes = readback_record.get("source_sha256", {})
        if not isinstance(source_hashes, dict) or source_hashes.get("wrangler.toml") != hashlib.sha256(wrangler_text.encode("utf-8")).hexdigest():
            raise VerificationError("B-086 source hash does not bind the readback to wrangler.toml")
        d1_count, distinct_ids, dpa_claims, jurisdiction_count = assess(
            wrangler_text, dpa_text, backlog_text
        )
        if args.self_test:
            self_test(wrangler_text, dpa_text, readback_record)
    except (OSError, VerificationError) as exc:
        print(f"FAIL: B-086 verifier: {exc}", file=sys.stderr)
        return 1
    print(
        "B-086 source posture aligned; external counsel sign-off remains pending: "
        f"production_d1_bindings={d1_count}, distinct_database_ids={distinct_ids}, "
        "fresh_provider_target_readback=1, fresh_active_worker_version_bindings=5, "
        f"active_dpa_d1_shared_global_claims={dpa_claims}, "
        f"jurisdiction_keys={jurisdiction_count} (R2 only); "
        "no executed transfer term is asserted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
