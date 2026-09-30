#!/usr/bin/env python3
"""Apply only the two B-216 DSR receipt migrations to the fixed staging D1."""

from __future__ import annotations

import hashlib
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_NAME = "corelink-config-staging"
DB_ID = "d72a6b39-6a48-4338-bfda-1111dda98604"
ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
TOKEN_ENV_NAMES = (
    "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
    "CF_API_EMAIL", "STAGING_CF_WORKER_API_TOKEN", "STAGING_CF_API_TOKEN",
    "STAGING_CF_ROUTE_READ_TOKEN",
)
MIGRATIONS = {
    "0138_dsr_dlq_delivery_receipts.sql": "64c4f0dbe43019ccaf1c10b4325b4ea66492e56b875d6a78530f9b6c1eaadff0",
    "0145_dsr_dlq_redrive_authority.sql": "aa963c3525b0637e51f637c785e7b6bcf8057152827e0cbb9416e1875a5901d0",
}
SCHEMA_OBJECTS = {
    "0138_dsr_dlq_delivery_receipts.sql": {"dsr_dlq_delivery_receipts", "idx_dsr_dlq_delivery_receipts_status_updated"},
    "0145_dsr_dlq_redrive_authority.sql": {"dsr_dlq_redrive_envelopes", "dsr_dlq_redrive_audit"},
}


def require_topology_target() -> None:
    topology = json.loads((ROOT / "infra/staging/topology.json").read_text())
    d1 = [item for item in topology["cloudflare"]["d1"] if item.get("database_name") == DB_NAME]
    if len(d1) != 1 or d1[0].get("database_id") != DB_ID:
        raise RuntimeError("B-216 fixed staging D1 target differs from the reviewed topology")


def require_target() -> None:
    require_topology_target()


def validate_migration_files() -> None:
    migration_root = ROOT / "migrations/d1"
    for name, expected_hash in MIGRATIONS.items():
        path = migration_root / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise RuntimeError(f"reviewed B-216 migration bytes changed: {name}")


def prepare_isolated_config(temp: Path) -> Path:
    migration_root = ROOT / "migrations/d1"
    migration_dir = temp / "migrations"
    migration_dir.mkdir(mode=0o700)
    for name in MIGRATIONS:
        shutil.copyfile(migration_root / name, migration_dir / name)
    config = temp / "wrangler.toml"
    config.write_text(
        'name = "b216-staging-dsr-schema-operator"\n'
        'compatibility_date = "2026-09-30"\n'
        f'account_id = "{ACCOUNT_ID}"\n'
        '[[d1_databases]]\n'
        'binding = "CONFIG_DB"\n'
        f'database_name = "{DB_NAME}"\n'
        f'database_id = "{DB_ID}"\n'
        'migrations_dir = "migrations"\n',
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    return config


def read_rows(command: list[str], config: Path, sql: str) -> list[dict[str, object]]:
    result = subprocess.run(
        [*command, "d1", "execute", "CONFIG_DB", "--remote", "--config", str(config), "--command", sql, "--json"],
        cwd=ROOT, check=True, text=True, capture_output=True,
    )
    try:
        payload = json.loads(result.stdout)
        rows = payload[0]["results"]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError
        return rows
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("cannot parse fixed staging D1 schema preimage") from error


def readback_d1_identity(command: list[str], config: Path) -> None:
    result = subprocess.run(
        [*command, "d1", "list", "--json", "--config", str(config)],
        cwd=ROOT, check=True, text=True, capture_output=True,
    )
    try:
        payload = json.loads(result.stdout)
        rows = payload.get("result") if isinstance(payload, dict) else payload
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError
        candidates = [
            (
                row.get("uuid", row.get("id", row.get("database_id"))),
                row.get("name", row.get("database_name")),
            )
            for row in rows
        ]
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("cannot parse Wrangler D1 identity readback") from error
    exact = [(uuid, name) for uuid, name in candidates if uuid == DB_ID and name == DB_NAME]
    collisions = [
        (uuid, name) for uuid, name in candidates
        if (uuid == DB_ID or name == DB_NAME) and (uuid, name) != (DB_ID, DB_NAME)
    ]
    if len(exact) != 1 or collisions:
        raise RuntimeError("Wrangler D1 identity readback is not exactly the fixed staging target")
    print(f"B-216 staging D1 identity readback: {DB_NAME} {DB_ID}")


def validate_preimage(names: set[str], objects: set[str]) -> None:
    if not names.issubset(MIGRATIONS):
        raise RuntimeError("fixed staging D1 migration ledger contains unexpected B-216 names")
    for migration, required_objects in SCHEMA_OBJECTS.items():
        present = required_objects & objects
        recorded = migration in names
        if bool(present) != recorded or (recorded and present != required_objects):
            raise RuntimeError(f"fixed staging D1 preimage is partial or inconsistent for {migration}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-contract", action="store_true")
    args = parser.parse_args()
    validate_migration_files()
    if args.check_contract:
        require_topology_target()
        print("B-216 staging schema contract is exact; no provider was contacted.")
        return 0

    require_target()
    if any(name in os.environ for name in TOKEN_ENV_NAMES):
        raise RuntimeError("token environment variables are not accepted; use the verified Wrangler OAuth profile")
    command = ["npx", "--yes", "wrangler@4.145.0"]
    child_env = os.environ.copy()
    child_env["B216_DSR_SCHEMA_WRANGLER_VERSION"] = "4.145.0"
    with tempfile.TemporaryDirectory(prefix="b216-staging-d1-") as temp_name:
        temp = Path(temp_name)
        config = prepare_isolated_config(temp)
        identity = subprocess.run([*command, "whoami"], cwd=ROOT, env=child_env, check=True, text=True, capture_output=True)
        if ACCOUNT_ID not in identity.stdout:
            raise RuntimeError("Wrangler OAuth readback does not include the fixed staging account")
        print(f"Wrangler OAuth account readback: {ACCOUNT_ID}")
        readback_d1_identity(command, config)
        object_rows = read_rows(
            command, config,
            "SELECT type, name FROM sqlite_master WHERE name IN ('d1_migrations', 'dsr_dlq_delivery_receipts', 'idx_dsr_dlq_delivery_receipts_status_updated', 'dsr_dlq_redrive_envelopes', 'dsr_dlq_redrive_audit') ORDER BY type, name",
        )
        objects = {str(row["name"]) for row in object_rows if isinstance(row.get("name"), str)}
        if "d1_migrations" in objects:
            migration_rows = read_rows(
                command, config,
                "SELECT name FROM d1_migrations WHERE name IN ('0138_dsr_dlq_delivery_receipts.sql', '0145_dsr_dlq_redrive_authority.sql') ORDER BY name",
            )
            names = {str(row["name"]) for row in migration_rows if isinstance(row.get("name"), str)}
        else:
            names = set()
        expected_all_objects = set().union(*SCHEMA_OBJECTS.values())
        validate_preimage(names, objects & expected_all_objects)
        print("B-216 staging D1 preimage:", ",".join(sorted(names)) if names else "neither B-216 migration recorded")
        present_objects = objects & expected_all_objects
        print("B-216 staging D1 receipt/redrive objects:", ",".join(sorted(present_objects)) if present_objects else "none")
        subprocess.run(
            [*command, "d1", "migrations", "apply", "CONFIG_DB", "--remote", "--config", str(config)],
            cwd=ROOT, check=True,
        )
        verifier = ROOT / "scripts/verify-signup-worker-dsr-redrive-schema.sh"
        subprocess.run(["bash", str(verifier), "--config", str(config)], cwd=ROOT, env=child_env, check=True)
    print("B-216 staging schema applied and verified for fixed staging D1 with Wrangler OAuth; no other migrations were supplied.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"B-216 staging schema operation failed: {error.__class__.__name__}", file=sys.stderr)
        raise SystemExit(1)
