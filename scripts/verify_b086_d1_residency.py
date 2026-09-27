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
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRANGLER = ROOT / "wrangler.toml"
DPA = ROOT / "legal/dpa-residency-amendment.md"
BACKLOG = ROOT / "BACKLOG.md"
MANIFEST = ROOT / "evidence/i1654/d1-residency-contract-manifest.json"

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
    "R2/DO tenant-pinned; shared D1 control plane is global "
    "(primary reported ENAM, no D1 jurisdiction)"
)


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


def self_test(wrangler_text: str, dpa_text: str) -> None:
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
        d1_count, distinct_ids, dpa_claims, jurisdiction_count = assess(
            wrangler_text, dpa_text, backlog_text
        )
        if args.self_test:
            self_test(wrangler_text, dpa_text)
    except (OSError, VerificationError) as exc:
        print(f"FAIL: B-086 verifier: {exc}", file=sys.stderr)
        return 1
    print(
        "B-086 source posture aligned; external counsel sign-off remains pending: "
        f"production_d1_bindings={d1_count}, distinct_database_ids={distinct_ids}, "
        f"active_dpa_d1_shared_global_claims={dpa_claims}, "
        f"jurisdiction_keys={jurisdiction_count} (R2 only); "
        "no executed transfer term is asserted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
