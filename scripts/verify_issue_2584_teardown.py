"""Static contract guard for #2584's bounded exact-run teardown surface."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def verify_atomic_locator_registration(webhook: str, signup: str) -> None:
    """Require every owned D1 writer to keep its locator in the write batch."""
    locator_sql = "INSERT INTO staging_load_test_teardown_locators"
    assert webhook.count(locator_sql) >= 1
    assert signup.count(locator_sql) >= 1
    assert 'json!({ "event_id": event.event_id })' in webhook
    assert 'json!({ "event_id": event.event_id, "effect_key": effect_key })' in webhook
    assert 'json!({ "signup_id": signup_id }).to_string()' in signup
    assert '"webhook_inbox_v1"' in webhook
    assert '"webhook_effect_v1"' in webhook
    assert "'signup_pilot_v1'" in signup
    assert "receive,\n                D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]),\n                registration,\n                locator,\n                unique_guard,\n                verify," in webhook
    assert "effect_insert,\n                D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]),\n                registration,\n                locator,\n                unique_guard,\n                verify," in webhook
    assert "D1BatchStatement::new(SQL_INSERT, insert_binds),\n                ownership,\n                locator," in signup

def verify() -> None:
    ownership = (ROOT / "crates/corelink-container/src/storage/staging_load_test_ownership.rs").read_text()
    admission = (ROOT / "crates/corelink-container/src/storage/staging_load_test_admission.rs").read_text()
    route = (ROOT / "crates/corelink-container/src/routes/staging_load_test_teardown.rs").read_text()
    routes = (ROOT / "crates/corelink-container/src/routes.rs").read_text()
    main = (ROOT / "crates/corelink-container/src/main.rs").read_text()
    validator = (ROOT / "scripts/validate_load_teardown_receipt.py").read_text()
    webhook = (ROOT / "crates/corelink-container/src/webhook_inbox_d1.rs").read_text()
    signup = (ROOT / "crates/corelink-container/src/signup_d1_http.rs").read_text()
    classes = ["CasReference", "WebhookInbox", "WebhookEffect", "DsrArtifact", "DsrObligation", "AuditEvidence", "BillingAudit", "SignupArtifact", "ByokArtifact"]
    assert all(name in ownership for name in classes)
    assert "STAGING_LOAD_TEST_RESOURCE_CLASSES" in ownership
    assert "TruncatedScan" in ownership and "OverBudget" in ownership and "CountMismatch" in ownership
    assert "reconcile_staging_load_test_teardown" in ownership
    assert "StagingLoadTestDisposition::Retained" in ownership
    assert "cross_run_deletions: 0" in ownership
    assert '"[REDACTED]"' in ownership
    assert "verify_staging_load_test_teardown_request" in route
    assert "verify_for_teardown" in admission and "teardown_context_from_verified" in admission
    assert "StagingLoadTestTeardownIdentity::from_admission" in route
    assert "POST /_internal/staging/load-tests/{scenario}/teardown" in route
    assert "build_router_from_env" in route and "StagingLoadTestAdmissionGate::from_env" in route
    assert "StagingLoadTestPhysicalTeardown" in ownership
    assert "prior_reconciled_receipt" in ownership and "persist_reconciled" in ownership
    assert "MAX_STAGING_LOAD_TEST_TEARDOWN_RESOURCES" in ownership
    assert "build_router_from_env().await" in main
    assert "exact staging load-test teardown route NOT mounted (fail-CLOSED)" in main
    assert "pub mod staging_load_test_teardown;" in routes
    assert "corelink.staging-load-test-teardown-receipt.v2" in validator
    assert "REQUIRED_RESOURCE_CLASSES" in validator and "RETAINED_RESOURCE_CLASSES" in validator
    assert "FORBIDDEN_REDACTION_TERMS" in validator
    verify_atomic_locator_registration(webhook, signup)

if __name__ == "__main__":
    verify()
    print("#2584 teardown contract guard passed")
