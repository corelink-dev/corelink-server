#!/usr/bin/env python3
"""Small structural guard for #2708's narrow staging seal surface."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
route = (ROOT / "crates/corelink-container/src/routes/staging_load_test_seal.rs").read_text()
storage = (ROOT / "crates/corelink-container/src/storage/staging_load_test_seal.rs").read_text()
main = (ROOT / "crates/corelink-container/src/main.rs").read_text()

required = {
    route: ["verify_staging_load_test_teardown_request", "StatusCode::UNAUTHORIZED", "StagingLoadTestSealIdentity::from_admission"],
    storage: ["corelink.staging-load-test-seal-receipt.v1", "STAGING_LOAD_TEST_RESOURCE_CLASSES", "MAX_RESOURCES: i64 = 256", "self.d1.batch(statements)", "SQL_READ_SCANS"],
    main: ["staging_load_test_seal::build_router_from_env", "seal route NOT mounted (fail-CLOSED)"],
}
for source, needles in required.items():
    for needle in needles:
        assert needle in source, f"missing required seal guard: {needle}"

for forbidden in ("Json<", "delete(", "R2_"):
    assert forbidden not in route, f"route must not accept or perform {forbidden}"

print("#2708 staging seal structural contract: PASS")
