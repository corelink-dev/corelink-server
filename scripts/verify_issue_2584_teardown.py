"""Static contract guard for #2584's bounded exact-run teardown surface."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def verify() -> None:
    ownership = (ROOT / "crates/corelink-container/src/storage/staging_load_test_ownership.rs").read_text()
    route = (ROOT / "crates/corelink-container/src/routes/staging_load_test_teardown.rs").read_text()
    routes = (ROOT / "crates/corelink-container/src/routes.rs").read_text()
    validator = (ROOT / "scripts/validate_load_teardown_receipt.py").read_text()
    classes = ["CasReference", "WebhookInbox", "WebhookEffect", "DsrArtifact", "DsrObligation", "AuditEvidence", "BillingAudit", "SignupArtifact", "ByokArtifact"]
    assert all(name in ownership for name in classes)
    assert "STAGING_LOAD_TEST_RESOURCE_CLASSES" in ownership
    assert "TruncatedScan" in ownership and "OverBudget" in ownership and "CountMismatch" in ownership
    assert "reconcile_staging_load_test_teardown" in ownership
    assert "StagingLoadTestDisposition::Retained" in ownership
    assert "cross_run_deletions: 0" in ownership
    assert '"[REDACTED]"' in ownership
    assert "admit_staging_load_test_request" in route
    assert "StagingLoadTestTeardownIdentity::from_admission" in route
    assert "POST /_internal/staging/load-tests/:scenario/teardown" in route
    assert "pub mod staging_load_test_teardown;" in routes
    assert "corelink.staging-load-test-teardown-receipt.v2" in validator
    assert "REQUIRED_RESOURCE_CLASSES" in validator and "RETAINED_RESOURCE_CLASSES" in validator
    assert "FORBIDDEN_REDACTION_TERMS" in validator

if __name__ == "__main__":
    verify()
    print("#2584 teardown contract guard passed")
