#!/usr/bin/env python3
"""Static contract checks for #2576's authenticated atomic admission seam."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "crates/corelink-container/src/storage/staging_load_test_admission.rs"
V2_MIGRATION = ROOT / "migrations/d1/0152_staging_load_test_request_nonces.sql"
WORKER = ROOT / "worker/src/durable_object_start.ts"
MATRIX = ROOT / "docs/internal/secrets-checklist.md"
DEPLOY = ROOT / ".github/workflows/cf-deploy-prod.yml"
FORBIDDEN_INDEX = re.compile(r"\b(?:nonce|nonce_bytes|input|output|digest|encoded)\s*\[")
ADMISSION_ENVS = (
    "CORELINK_ENVIRONMENT",
    "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY",
)


def env_parity_errors(worker: str, matrix: str, deploy: str) -> list[str]:
    missing = []
    for name in ADMISSION_ENVS:
        if not re.search(rf"^\s*{name}:\s*ctx\.env\.{name}\b", worker, re.MULTILINE):
            missing.append(f"Worker forward list: {name}")
        if f"`{name}`" not in matrix:
            missing.append(f"secrets checklist: {name}")
    checklist_gate = deploy.find("./scripts/secrets-checklist-verify.sh")
    forwarding_gate = deploy.find("python3 scripts/check-env-contract.py")
    deploy_job = deploy.find("\n  deploy:")
    if checklist_gate < 0 or forwarding_gate < 0 or deploy_job < 0:
        missing.append("production deploy gate must run both drift checks before deploy")
    elif not checklist_gate < forwarding_gate < deploy_job:
        missing.append("production deploy drift checks must precede deploy")
    return missing


def main() -> int:
    source = MODULE.read_text(encoding="utf-8")
    required = (
        'const AUTH_DOMAIN_V1: &[u8] = b"corelink/staging-load-admission-auth/v1\\0";',
        'const AUTH_DOMAIN_V2: &[u8] = b"corelink/staging-load-admission-auth/v2\\0";',
        'const NONCE_DOMAIN_V1: &[u8] = b"corelink/staging-load-admission-nonce/v1\\0";',
        'const NONCE_DOMAIN_V2: &[u8] = b"corelink/staging-load-admission-nonce/v2\\0";',
        "mac.verify_slice(&tag)",
        "fn decode_nonce(",
        "fn nonce_digest_hex(",
        "StagingLoadTestAdmissionVersion::V2 => (SQL_INSERT_RUN_V2, SQL_INSERT_REQUEST_NONCE)",
        "ON CONFLICT(run_id, scenario) DO NOTHING",
        "for byte in nonce_bytes.iter().copied()",
        "for byte in bytes",
        'write!(&mut encoded, "{byte:02x}")',
        ".batch(vec![",
        "StagingLoadTestAdmissionVersion::V1 => (SQL_INSERT_RUN, SQL_INSERT_NONCE)",
        "D1BatchStatement::new(run_sql, run_params)",
        "D1BatchStatement::new(nonce_sql, nonce_params)",
        '.field("key", &"[REDACTED]")',
        '.field("nonce_digest", &"[REDACTED]")',
    )
    missing = [fragment for fragment in required if fragment not in source]
    if missing:
        print(f"missing #2576 contract fragments: {missing!r}", file=sys.stderr)
        return 1
    migration = V2_MIGRATION.read_text(encoding="utf-8")
    migration_required = (
        "CREATE TABLE IF NOT EXISTS staging_load_test_request_nonces",
        "PRIMARY KEY (nonce_digest)",
        "trg_staging_load_test_request_nonce_requires_exact_open_run",
        "AND state = 'open'",
        "trg_staging_load_test_request_nonce_no_update",
        "trg_staging_load_test_request_nonce_no_delete",
    )
    missing_migration = [fragment for fragment in migration_required if fragment not in migration]
    if missing_migration or "UNIQUE (run_id, scenario)" in migration:
        print(f"missing or unsafe #2576 v2 migration fragments: {missing_migration!r}", file=sys.stderr)
        return 1
    if FORBIDDEN_INDEX.search(source):
        print("nonce/digest indexing or slicing is forbidden", file=sys.stderr)
        return 1
    mutated = source.replace(
        'for byte in bytes {\n        write!(&mut encoded, "{byte:02x}")',
        'for byte in bytes {\n        let byte = digest[0];\n        write!(&mut encoded, "{byte:02x}")',
        1,
    )
    if mutated == source or not FORBIDDEN_INDEX.search(mutated):
        print("indexing negative fixture is ineffective", file=sys.stderr)
        return 1
    worker = WORKER.read_text(encoding="utf-8")
    matrix = MATRIX.read_text(encoding="utf-8")
    deploy = DEPLOY.read_text(encoding="utf-8")
    missing_env = env_parity_errors(worker, matrix, deploy)
    if missing_env:
        print(f"#2576 runtime/deploy parity drift: {missing_env!r}", file=sys.stderr)
        return 1
    if not env_parity_errors(worker.replace(ADMISSION_ENVS[0], "REMOVED", 1), matrix, deploy):
        print("Worker-forwarding negative fixture is ineffective", file=sys.stderr)
        return 1
    if not env_parity_errors(worker, matrix.replace(ADMISSION_ENVS[1], "REMOVED", 1), deploy):
        print("secrets-matrix negative fixture is ineffective", file=sys.stderr)
        return 1
    if not env_parity_errors(worker, matrix, deploy.replace("python3 scripts/check-env-contract.py", "", 1)):
        print("production deploy-gate negative fixture is ineffective", file=sys.stderr)
        return 1
    print("#2576 verifier contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
