#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "loopback D1 fixture setup and assertions"
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde_json::{json, Value};
use sha2::Sha256;

use super::*;
use crate::{
    customer_d1::{ByokCryptoMode, ByokMode},
    storage::{
        d1_http::D1HttpClient,
        staging_load_test_admission::{
            admit_staging_load_test_request, StagingLoadTestAdmissionGate,
            StagingLoadTestAdmissionStore, StagingLoadTestAdmissionVerifier,
            STAGING_LOAD_TEST_ADMISSION_HEADER,
        },
        staging_load_test_ownership::StagingLoadTestScenario,
        StorageEnv,
    },
};

type HmacSha256 = Hmac<Sha256>;

const TENANT: &str = "0192f0c1-2345-7890-abcd-ef0123456789";
const DEPLOYMENT_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: &[u8] = b"01234567890123456789012345678901";
const NONCE_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NONCE_B: &str = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixture {
    db: Arc<Mutex<Connection>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    endpoint: String,
}

impl Fixture {
    fn new() -> Self {
        let db = Arc::new(Mutex::new(Connection::open_in_memory().expect("sqlite")));
        {
            let db = db.lock().expect("sqlite lock");
            db.execute_batch(
                "CREATE TABLE tenant (
                    tenant_id TEXT PRIMARY KEY,
                    primary_region TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );",
            )
            .expect("base tenant schema");
            for migration in [
                "0031_byok_tenant_status.sql",
                "0081_byok_tenant_config.sql",
                "0118_byok_transition_fence.sql",
                "0119_byok_control_transition_guard.sql",
                "0120_byok_backfill_run.sql",
                "0121_byok_activation_pipeline.sql",
                "0147_staging_load_test_run_ownership.sql",
                "0148_staging_load_test_admission_nonce.sql",
                "0149_staging_load_test_r2_intents.sql",
                "0151_staging_load_test_teardown_receipts.sql",
            ] {
                let path = format!(
                    "{}/../../migrations/d1/{migration}",
                    env!("CARGO_MANIFEST_DIR")
                );
                db.execute_batch(&std::fs::read_to_string(path).expect("migration read"))
                    .expect("migration apply");
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_db, thread_stop) = (Arc::clone(&db), Arc::clone(&stop));
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => respond(&mut stream, &thread_db),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            db,
            stop,
            worker: Some(worker),
            endpoint,
        }
    }

    fn d1(&self) -> D1HttpClient {
        let env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        D1HttpClient::new_for_loopback_test(&env, &self.endpoint).expect("loopback D1 client")
    }

    fn gate(&self) -> StagingLoadTestAdmissionGate {
        let verifier = StagingLoadTestAdmissionVerifier::new("staging", KEY).expect("test key");
        StagingLoadTestAdmissionGate::from_parts_for_test(
            verifier,
            StagingLoadTestAdmissionStore::from_d1_client_for_test(self.d1()),
        )
    }

    fn seed_ownership_failure(&self, run_id: &str) {
        self.db
            .lock()
            .expect("sqlite lock")
            .execute_batch(&format!(
                "CREATE TRIGGER reject_byok_ownership BEFORE INSERT ON staging_load_test_resources \
                 WHEN NEW.run_id='{run_id}' BEGIN SELECT RAISE(ABORT,'ownership registration rejected'); END;"
            ))
            .expect("ownership failure trigger");
    }

    fn seed_tenant(&self, tenant_id: &str) {
        self.db
            .lock()
            .expect("sqlite lock")
            .execute(
                "INSERT INTO tenant (tenant_id,primary_region,created_at_ms,updated_at_ms,byok_status) \
                 VALUES (?1,'wnam',1,1,'active')",
                [tenant_id],
            )
            .expect("seed tenant");
    }

    fn seed_synthetic_tenant(&self, run_id: &str, tenant_id: &str) {
        self.seed_tenant(tenant_id);
        self.seed_synthetic_marker(run_id, tenant_id);
    }

    fn seed_synthetic_marker(&self, run_id: &str, tenant_id: &str) {
        self.db
            .lock()
            .expect("sqlite lock")
            .execute(
                "INSERT INTO staging_load_test_synthetic_tenants \
             (run_id,scenario,tenant_id,baseline_marker,marked_at_ms) \
             VALUES (?1,'byok',?2,'generation_zero_empty',1)",
                rusqlite::params![run_id, tenant_id],
            )
            .expect("seed exact-run synthetic marker");
    }

    fn begin_teardown(&self, run_id: &str) {
        let db = self.db.lock().expect("sqlite lock");
        for resource_class in [
            "cas_reference",
            "webhook_inbox",
            "webhook_effect",
            "dsr_artifact",
            "dsr_obligation",
            "audit_evidence",
            "billing_audit",
            "signup_artifact",
            "byok_artifact",
        ] {
            let observed_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM staging_load_test_resources \
                     WHERE run_id=?1 AND scenario='byok' AND resource_class=?2",
                    rusqlite::params![run_id, resource_class],
                    |row| row.get(0),
                )
                .expect("resource class count");
            db.execute(
                "INSERT INTO staging_load_test_resource_scans \
                 (run_id,scenario,resource_class,state,observed_count,scanned_at_ms) \
                 VALUES (?1,'byok',?2,'complete',?3,1)",
                rusqlite::params![run_id, resource_class, observed_count],
            )
            .expect("complete class scan");
        }
        db.execute(
            "UPDATE staging_load_test_runs SET state='sealed' WHERE run_id=?1 AND scenario='byok'",
            [run_id],
        )
        .expect("seal complete inventory");
        db.execute(
            "UPDATE staging_load_test_runs SET state='teardown_started' \
             WHERE run_id=?1 AND scenario='byok'",
            [run_id],
        )
        .expect("begin exact-run teardown");
        db.execute(
            "UPDATE staging_load_test_resources SET state='delete_started' \
             WHERE run_id=?1 AND scenario='byok' AND resource_class='byok_artifact'",
            [run_id],
        )
        .expect("start disposable resource deletion");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .expect("worker")
            .join()
            .expect("join worker");
    }
}

fn activation() -> ByokActivation {
    ByokActivation {
        tenant_id: TENANT.to_owned(),
        mode: ByokMode::Byok,
        crypto_mode: ByokCryptoMode::Convergent,
        cmk_provider: "aws".to_owned(),
        cmk_key_id: "arn:aws:kms:us-east-1:123456789012:key/example".to_owned(),
        cmk_region: Some("us-east-1".to_owned()),
        tcs_wrapped: b"synthetic-wrapped-secret".to_vec(),
    }
}

fn staging_activation() -> ByokActivation {
    let mut activation = activation();
    activation.tenant_id.clear();
    activation
}

fn issue_credential(run_id: &str, nonce: &str) -> String {
    issue_credential_for_scenario(run_id, StagingLoadTestScenario::Byok, nonce)
}

fn issue_credential_for_scenario(
    run_id: &str,
    scenario: StagingLoadTestScenario,
    nonce: &str,
) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let issued = now_ms - 1_000;
    let expires = now_ms + 60_000;
    let scenario = match scenario {
        StagingLoadTestScenario::Byok => "byok",
        StagingLoadTestScenario::Cas => "cas",
        _ => panic!("unsupported test scenario"),
    };
    let payload =
        format!("v1.{run_id}.{scenario}.staging.{DEPLOYMENT_SHA}.{issued}.{expires}.{nonce}");
    let mut mac = HmacSha256::new_from_slice(KEY).expect("HMAC key");
    mac.update(b"corelink/staging-load-admission-auth/v1\0");
    mac.update(payload.as_bytes());
    format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()))
}

async fn admitted_context(
    gate: &StagingLoadTestAdmissionGate,
    run_id: &str,
    nonce: &str,
) -> Arc<crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext> {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        STAGING_LOAD_TEST_ADMISSION_HEADER,
        issue_credential(run_id, nonce)
            .parse()
            .expect("credential header"),
    );
    admit_staging_load_test_request(Some(gate), &headers, StagingLoadTestScenario::Byok)
        .await
        .expect("verified durable admission")
        .expect("synthetic admission context")
}

async fn pending_synthetic_activation(
    fixture: &Fixture,
    run_id: &str,
    nonce: &str,
) -> (D1ByokControl, StagingByokPendingTeardownLocator) {
    let context = admitted_context(&fixture.gate(), run_id, nonce).await;
    fixture.seed_synthetic_tenant(run_id, TENANT);
    let tenant_ref = staging_synthetic_tenant_ref(run_id, "byok", DEPLOYMENT_SHA, TENANT);
    let control = D1ByokControl::new(Arc::new(fixture.d1()));
    control
        .prepare_staging_synthetic_activation(&staging_activation(), 10_007, &context, &tenant_ref)
        .await
        .expect("pending synthetic activation");
    let (tenant_id, intent_id): (String, String) = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row(
            "SELECT json_extract(locator_json,'$.tenant_id'),json_extract(locator_json,'$.intent_id') \
             FROM staging_load_test_teardown_locators WHERE run_id=?1 AND scenario='byok'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exact-run sealed intent");
    (
        control,
        StagingByokPendingTeardownLocator {
            tenant_id,
            intent_id,
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synthetic_activation_is_registered_atomically_and_replay_fails_closed() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        STAGING_LOAD_TEST_ADMISSION_HEADER,
        issue_credential("123", NONCE_A)
            .parse()
            .expect("credential header"),
    );
    let context =
        admit_staging_load_test_request(Some(&gate), &headers, StagingLoadTestScenario::Byok)
            .await
            .expect("verified durable admission")
            .expect("synthetic context");
    let control = D1ByokControl::new(Arc::new(fixture.d1()));
    assert!(control
        .prepare_activation_with_context(&staging_activation(), 9_999, Some(&context))
        .await
        .is_err());
    fixture.seed_synthetic_tenant("123", TENANT);
    let tenant_ref = staging_synthetic_tenant_ref("123", "byok", DEPLOYMENT_SHA, TENANT);

    control
        .prepare_staging_synthetic_activation(&staging_activation(), 10_000, &context, &tenant_ref)
        .await
        .expect("activation, ownership row, and teardown locator");

    {
        let db = fixture.db.lock().expect("sqlite lock");
        let (run_id, scenario, resource_class, handle, disposition, receipt): (
            String,
            String,
            String,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT run_id,scenario,resource_class,opaque_handle,disposition,receipt_ref \
                 FROM staging_load_test_resources",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("one ownership row");
        assert_eq!((run_id.as_str(), scenario.as_str()), ("123", "byok"));
        assert_eq!(resource_class, "byok_artifact");
        assert_eq!(disposition, "disposable");
        assert!(handle.starts_with("byok-activation:"));
        assert!(!handle.contains(TENANT));
        assert_eq!(receipt.len(), 64);
        assert!(!handle.contains("synthetic-wrapped-secret"));
        let registrations: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM staging_load_test_resources",
                [],
                |row| row.get(0),
            )
            .expect("registration count");
        let intents: i64 = db
            .query_row("SELECT COUNT(*) FROM byok_activation_intent", [], |row| {
                row.get(0)
            })
            .expect("intent count");
        assert_eq!((registrations, intents), (1, 1));
        let locator: (String, String, String, String, String) = db
            .query_row(
                "SELECT locator_kind,locator_json,receipt_ref,resource_class,scenario \
                 FROM staging_load_test_teardown_locators",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("one typed locator");
        assert_eq!(locator.0, "byok_pending_synthetic_v1");
        assert_eq!(locator.2, receipt);
        assert_eq!(
            (locator.3.as_str(), locator.4.as_str()),
            ("byok_artifact", "byok")
        );
        let stored: Value = serde_json::from_str(&locator.1).expect("locator JSON");
        assert_eq!(stored["tenant_id"], TENANT);
        assert_eq!(
            stored["intent_id"],
            handle.trim_start_matches("byok-activation:")
        );
        assert_eq!(stored["tenant_ref"], tenant_ref);
    }

    let replay =
        admit_staging_load_test_request(Some(&gate), &headers, StagingLoadTestScenario::Byok).await;
    assert!(replay.is_err(), "replayed credential must fail closed");
    let mut forged_headers = axum::http::HeaderMap::new();
    forged_headers.insert(
        STAGING_LOAD_TEST_ADMISSION_HEADER,
        "forged".parse().expect("forged credential header"),
    );
    assert!(admit_staging_load_test_request(
        Some(&gate),
        &forged_headers,
        StagingLoadTestScenario::Byok,
    )
    .await
    .is_err());
    let resources: i64 = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row(
            "SELECT COUNT(*) FROM staging_load_test_resources",
            [],
            |row| row.get(0),
        )
        .expect("registration count");
    assert_eq!(resources, 1);
}

#[test]
fn synthetic_tenant_ref_matches_worker_fixture_vector() {
    assert_eq!(
        staging_synthetic_tenant_ref(
            "123456",
            "byok",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "11111111-1111-4111-8111-111111111111",
        ),
        "0106591dc8ab4f03e23dc578aeb3e20fb7436e93284540e0d457e448e92959f0"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_scenario_and_registration_failure_cannot_commit_activation() {
    let fixture = Fixture::new();
    let control = D1ByokControl::new(Arc::new(fixture.d1()));
    let gate = fixture.gate();

    let mut wrong_headers = axum::http::HeaderMap::new();
    let cas_credential =
        issue_credential_for_scenario("124", StagingLoadTestScenario::Cas, NONCE_A);
    wrong_headers.insert(
        STAGING_LOAD_TEST_ADMISSION_HEADER,
        cas_credential.parse().expect("credential header"),
    );
    let verifier = StagingLoadTestAdmissionVerifier::new("staging", KEY).expect("test key");
    let wrong_gate = StagingLoadTestAdmissionGate::from_parts_for_test(
        verifier,
        StagingLoadTestAdmissionStore::from_d1_client_for_test(fixture.d1()),
    );
    let wrong_context = admit_staging_load_test_request(
        Some(&wrong_gate),
        &wrong_headers,
        StagingLoadTestScenario::Cas,
    )
    .await
    .expect("valid CAS admission")
    .expect("context");
    assert!(control
        .prepare_staging_synthetic_activation(
            &staging_activation(),
            10_000,
            &wrong_context,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await
        .is_err());
    let config_rows: i64 = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row("SELECT COUNT(*) FROM tenant_byok_config", [], |row| {
            row.get(0)
        })
        .expect("config count");
    assert_eq!(config_rows, 0, "scenario mismatch precedes BYOK writes");

    let good_context = admitted_context(&gate, "125", NONCE_B).await;
    fixture.seed_synthetic_tenant("125", TENANT);
    let tenant_ref = staging_synthetic_tenant_ref("125", "byok", DEPLOYMENT_SHA, TENANT);
    fixture.seed_ownership_failure("125");
    assert!(control
        .prepare_staging_synthetic_activation(
            &staging_activation(),
            10_001,
            &good_context,
            &tenant_ref,
        )
        .await
        .is_err());
    let db = fixture.db.lock().expect("sqlite lock");
    let configs: i64 = db
        .query_row("SELECT COUNT(*) FROM tenant_byok_config", [], |row| {
            row.get(0)
        })
        .expect("config count");
    let intents: i64 = db
        .query_row("SELECT COUNT(*) FROM byok_activation_intent", [], |row| {
            row.get(0)
        })
        .expect("intent count");
    let resources: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM staging_load_test_resources",
            [],
            |row| row.get(0),
        )
        .expect("registration count");
    assert_eq!((configs, intents, resources), (0, 0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_pending_synthetic_activation_cancels_and_reads_back_empty_baseline() {
    let fixture = Fixture::new();
    let context = admitted_context(&fixture.gate(), "126", NONCE_A).await;
    fixture.seed_synthetic_tenant("126", TENANT);
    let tenant_ref = staging_synthetic_tenant_ref("126", "byok", DEPLOYMENT_SHA, TENANT);
    let control = D1ByokControl::new(Arc::new(fixture.d1()));
    control
        .prepare_staging_synthetic_activation(&staging_activation(), 10_002, &context, &tenant_ref)
        .await
        .expect("synthetic activation");
    let (tenant_id, intent_id): (String, String) = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row(
            "SELECT json_extract(locator_json,'$.tenant_id'),json_extract(locator_json,'$.intent_id') \
             FROM staging_load_test_teardown_locators WHERE scenario='byok'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("sealed activation intent");
    fixture.begin_teardown("126");
    let locator = StagingByokPendingTeardownLocator {
        tenant_id: tenant_id.clone(),
        intent_id: intent_id.clone(),
    };
    let wrong_tenant = StagingByokPendingTeardownLocator {
        tenant_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        intent_id: intent_id.clone(),
    };
    let error = control
        .cancel_staging_pending_activation_and_readback(&wrong_tenant)
        .await
        .expect_err("wrong tenant cannot resolve the exact locator");
    assert_eq!(error, StagingByokTeardownError::InvalidLocator);
    control
        .cancel_staging_pending_activation_and_readback(&locator)
        .await
        .expect("cancel and exact readback");

    {
        let db = fixture.db.lock().expect("sqlite lock");
        let (phase, state, generation, wrapped, key_id): (String, String, i64, Option<String>, Option<String>) = db
            .query_row(
                "SELECT a.phase,c.state,g.current_generation,s.tcs_wrapped,s.cmk_key_id \
                 FROM byok_activation_intent a JOIN tenant_byok_config c ON c.tenant_id=a.tenant_id \
                 JOIN byok_tenant_gate g ON g.tenant_id=a.tenant_id \
                 JOIN tenant_byok_secret s ON s.tenant_id=a.tenant_id \
                 WHERE a.tenant_id=?1 AND a.intent_id=?2",
                rusqlite::params![tenant_id, intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("terminal activation state");
        assert_eq!(
            (phase.as_str(), state.as_str(), generation),
            ("aborted", "inactive", 0)
        );
        assert_eq!((wrapped, key_id), (None, None));
        let wrapped_history: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM tenant_byok_secret_history \
                 WHERE tenant_id=?1 AND tcs_wrapped IS NOT NULL",
                [tenant_id.as_str()],
                |row| row.get(0),
            )
            .expect("no wrapped history");
        let (generations, publications, purges): (i64, i64, i64) = db
            .query_row(
                "SELECT \
                 (SELECT COUNT(*) FROM byok_logical_object_generation WHERE tenant_id=?1), \
                 (SELECT COUNT(*) FROM byok_logical_object_publication WHERE tenant_id=?1), \
                 (SELECT COUNT(*) FROM byok_object_purge_item WHERE tenant_id=?1)",
                [tenant_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("no generation publication or purge residue");
        assert_eq!(
            (wrapped_history, generations, publications, purges),
            (0, 0, 0, 0)
        );
    }
    let replay = control
        .cancel_staging_pending_activation_and_readback(&locator)
        .await
        .expect_err("replayed cancellation cannot claim a new success");
    assert_eq!(replay, StagingByokTeardownError::InvalidLocator);
    assert!(!replay.to_string().contains(TENANT));
    assert!(!replay.to_string().contains(&intent_id));
    assert!(!replay.to_string().contains("synthetic-wrapped-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synthetic_activation_rejects_wrong_reference_and_preexisting_byok_state() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let context = admitted_context(&gate, "127", NONCE_A).await;
    fixture.seed_synthetic_tenant("127", TENANT);
    let control = D1ByokControl::new(Arc::new(fixture.d1()));
    let good_ref = staging_synthetic_tenant_ref("127", "byok", DEPLOYMENT_SHA, TENANT);
    let wrong_ref = staging_synthetic_tenant_ref("128", "byok", DEPLOYMENT_SHA, TENANT);
    assert!(control
        .prepare_staging_synthetic_activation(&staging_activation(), 10_003, &context, &wrong_ref)
        .await
        .is_err());
    let mut mismatched_activation = activation();
    mismatched_activation.tenant_id = "11111111-1111-4111-8111-111111111111".to_owned();
    assert!(control
        .prepare_staging_synthetic_activation(&mismatched_activation, 10_004, &context, &good_ref,)
        .await
        .is_err());
    let no_wrong_id_intents: i64 = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row("SELECT COUNT(*) FROM byok_activation_intent", [], |row| {
            row.get(0)
        })
        .expect("intent count after mismatched caller identity");
    assert_eq!(no_wrong_id_intents, 0);
    assert!(control
        .prepare_staging_synthetic_activation(&staging_activation(), 10_005, &context, &good_ref)
        .await
        .is_ok());
    let intents: i64 = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row("SELECT COUNT(*) FROM byok_activation_intent", [], |row| {
            row.get(0)
        })
        .expect("single valid activation");
    assert_eq!(intents, 1);

    let existing = Fixture::new();
    existing.seed_tenant(TENANT);
    let existing_control = D1ByokControl::new(Arc::new(existing.d1()));
    existing_control
        .prepare_activation(&activation(), 10_005)
        .await
        .expect("ordinary pending activation");
    let existing_context = admitted_context(&existing.gate(), "129", NONCE_B).await;
    existing.seed_synthetic_marker("129", TENANT);
    let existing_ref = staging_synthetic_tenant_ref("129", "byok", DEPLOYMENT_SHA, TENANT);
    assert!(existing_control
        .prepare_staging_synthetic_activation(
            &staging_activation(),
            10_006,
            &existing_context,
            &existing_ref,
        )
        .await
        .is_err());
    let (existing_intents, owned_resources, locators): (i64, i64, i64) = existing
        .db
        .lock()
        .expect("sqlite lock")
        .query_row(
            "SELECT \
             (SELECT COUNT(*) FROM byok_activation_intent WHERE tenant_id=?1), \
             (SELECT COUNT(*) FROM staging_load_test_resources WHERE scenario='byok'), \
             (SELECT COUNT(*) FROM staging_load_test_teardown_locators WHERE scenario='byok')",
            [TENANT],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("prior-state rejection is atomic");
    assert_eq!((existing_intents, owned_resources, locators), (1, 0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_partial_synthetic_activation_is_not_cancelled_as_pending() {
    let fixture = Fixture::new();
    let (control, locator) = pending_synthetic_activation(&fixture, "130", NONCE_A).await;
    {
        let db = fixture.db.lock().expect("sqlite lock");
        db.execute_batch("DROP TRIGGER trg_byok_activation_intent_forward_only;")
            .expect("allow construction of adversarial published state");
        db.execute(
            "UPDATE tenant_byok_config SET state='partial',config_version=config_version+1 \
             WHERE tenant_id=?1",
            [locator.tenant_id.as_str()],
        )
        .expect("published partial config fixture");
        db.execute(
            "UPDATE byok_tenant_gate SET current_generation=1,gate_epoch=gate_epoch+1 \
             WHERE tenant_id=?1",
            [locator.tenant_id.as_str()],
        )
        .expect("published generation fixture");
        db.execute(
            "UPDATE byok_activation_intent SET phase='published_partial', \
                 publication_gate_epoch=observed_gate_epoch+1, \
                 published_config_version=config_version+1,cas_complete=1,ac_complete=1, \
                 state_version=state_version+1 WHERE intent_id=?1",
            [&locator.intent_id],
        )
        .expect("published partial activation fixture");
    }
    fixture.begin_teardown("130");
    let result = control
        .cancel_staging_pending_activation_and_readback(&locator)
        .await
        .expect_err("published partial state cannot use pending cancellation");
    assert_eq!(result, StagingByokTeardownError::InvalidLocator);
    let db = fixture.db.lock().expect("sqlite lock");
    let (phase, state, generation, purges): (String, String, i64, i64) = db
        .query_row(
            "SELECT a.phase,c.state,g.current_generation, \
             (SELECT COUNT(*) FROM byok_object_purge_item p WHERE p.tenant_id=a.tenant_id) \
             FROM byok_activation_intent a JOIN tenant_byok_config c ON c.tenant_id=a.tenant_id \
             JOIN byok_tenant_gate g ON g.tenant_id=a.tenant_id WHERE a.intent_id=?1",
            [&locator.intent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("published partial remains untouched");
    assert_eq!(
        (phase.as_str(), state.as_str(), generation, purges),
        ("published_partial", "partial", 1, 0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_batch_failure_rolls_back_without_success_or_purge() {
    let fixture = Fixture::new();
    let (control, locator) = pending_synthetic_activation(&fixture, "131", NONCE_B).await;
    let pre_cancel_side_effects: (i64, i64) = fixture
        .db
        .lock()
        .expect("sqlite lock")
        .query_row(
            "SELECT \
             (SELECT COUNT(*) FROM byok_control_outcome o WHERE o.tenant_id=?1), \
             (SELECT COUNT(*) FROM byok_object_purge_item p WHERE p.tenant_id=?1)",
            [locator.tenant_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("pre-cancellation side-effect baseline");
    fixture.begin_teardown("131");
    fixture
        .db
        .lock()
        .expect("sqlite lock")
        .execute_batch(
            "CREATE TRIGGER reject_staging_byok_cancel BEFORE UPDATE OF phase ON byok_activation_intent \
             WHEN NEW.phase='aborted' BEGIN SELECT RAISE(ABORT,'injected cancellation failure'); END;",
        )
        .expect("inject cancellation batch failure");
    let result = control
        .cancel_staging_pending_activation_and_readback(&locator)
        .await
        .expect_err("failed cancellation transaction cannot report success");
    assert_eq!(result, StagingByokTeardownError::StorageUnavailable);
    let db = fixture.db.lock().expect("sqlite lock");
    let (phase, state, wrapped, outcomes, purges): (String, String, Option<String>, i64, i64) = db
        .query_row(
            "SELECT a.phase,c.state,s.tcs_wrapped, \
             (SELECT COUNT(*) FROM byok_control_outcome o WHERE o.tenant_id=a.tenant_id), \
             (SELECT COUNT(*) FROM byok_object_purge_item p WHERE p.tenant_id=a.tenant_id) \
             FROM byok_activation_intent a JOIN tenant_byok_config c ON c.tenant_id=a.tenant_id \
             JOIN tenant_byok_secret s ON s.tenant_id=a.tenant_id WHERE a.intent_id=?1",
            [&locator.intent_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("failed cancellation leaves pending state");
    assert_eq!((phase.as_str(), state.as_str()), ("copy", "pending"));
    assert!(wrapped.is_some());
    assert_eq!(
        (outcomes, purges),
        pre_cancel_side_effects,
        "failed cancellation cannot add an outcome or purge"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_readback_residue_cannot_return_success() {
    let fixture = Fixture::new();
    let (control, locator) = pending_synthetic_activation(&fixture, "132", NONCE_A).await;
    fixture.begin_teardown("132");
    fixture
        .db
        .lock()
        .expect("sqlite lock")
        .execute_batch(
            "CREATE TRIGGER inject_staging_byok_readback_residue AFTER INSERT ON byok_activation_postcondition \
             WHEN NEW.expected_phase='aborted' BEGIN \
               UPDATE byok_tenant_gate SET current_generation=1 \
                WHERE tenant_id=(SELECT tenant_id FROM byok_activation_intent WHERE intent_id=NEW.intent_id); \
             END;",
        )
        .expect("inject readback residue after cancellation postcondition");
    let result = control
        .cancel_staging_pending_activation_and_readback(&locator)
        .await
        .expect_err("post-cancellation residue must fail exact readback");
    assert_eq!(result, StagingByokTeardownError::UnsafeState);
    let db = fixture.db.lock().expect("sqlite lock");
    let (phase, state, generation): (String, String, i64) = db
        .query_row(
            "SELECT a.phase,c.state,g.current_generation FROM byok_activation_intent a \
             JOIN tenant_byok_config c ON c.tenant_id=a.tenant_id \
             JOIN byok_tenant_gate g ON g.tenant_id=a.tenant_id WHERE a.intent_id=?1",
            [&locator.intent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("readback residue remains visible");
    assert_eq!(
        (phase.as_str(), state.as_str(), generation),
        ("aborted", "inactive", 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_activation_preserves_none_compatibility_without_registration() {
    let fixture = Fixture::new();
    fixture.seed_tenant(TENANT);
    let control = D1ByokControl::new(Arc::new(fixture.d1()));

    control
        .prepare_activation(&activation(), 10_000)
        .await
        .expect("ordinary activation without a staging context");

    let db = fixture.db.lock().expect("sqlite lock");
    let intents: i64 = db
        .query_row("SELECT COUNT(*) FROM byok_activation_intent", [], |row| {
            row.get(0)
        })
        .expect("intent count");
    let resources: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM staging_load_test_resources",
            [],
            |row| row.get(0),
        )
        .expect("registration count");
    assert_eq!((intents, resources), (1, 0));
}

fn respond(stream: &mut TcpStream, db: &Arc<Mutex<Connection>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0_u8; 4096];
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(_) => return,
        };
        bytes.extend_from_slice(&buffer[..read]);
        let Some(headers_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&bytes[..headers_end]);
        let Some(length) = headers.lines().find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        }) else {
            continue;
        };
        let Ok(length) = length.parse::<usize>() else {
            return;
        };
        if bytes.len() >= headers_end + 4 + length {
            break;
        }
    }
    let body_start = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("headers")
        + 4;
    let headers_end = body_start - 4;
    let headers = String::from_utf8_lossy(&bytes[..headers_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        })
        .expect("content length")
        .parse::<usize>()
        .expect("content length number");
    let request: Value = serde_json::from_slice(&bytes[body_start..body_start + content_length])
        .expect("request JSON");

    let response = if let Some(batch) = request.get("batch").and_then(Value::as_array) {
        let mut db = db.lock().expect("sqlite lock");
        let transaction = db.transaction().expect("batch transaction");
        let mut results = Vec::with_capacity(batch.len());
        let mut failure = None;
        for (index, statement) in batch.iter().enumerate() {
            let sql = statement["sql"].as_str().expect("batch SQL");
            let params = sql_params(&statement["params"]);
            match run_statement(&transaction, sql, params) {
                Ok(rows) => results.push(json!({"results": rows, "success": true})),
                Err(error) => {
                    results.push(json!({"results": [], "success": false}));
                    failure = Some((index, error));
                    break;
                }
            }
        }
        match failure {
            Some((_, error)) => {
                json!({"result": results, "success": false, "errors": [{"message": error}]})
            }
            None => {
                transaction.commit().expect("batch commit");
                json!({"result": results, "success": true, "errors": []})
            }
        }
    } else {
        let sql = request["sql"].as_str().expect("query SQL");
        let params = sql_params(&request["params"]);
        match run_statement(&db.lock().expect("sqlite lock"), sql, params) {
            Ok(rows) => {
                json!({"result": [{"results": rows, "success": true}], "success": true, "errors": []})
            }
            Err(error) => {
                json!({"result": [{"results": [], "success": false}], "success": false, "errors": [{"message": error}]})
            }
        }
    };
    let body = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("response write");
}

fn sql_params(value: &Value) -> Vec<SqlValue> {
    value
        .as_array()
        .expect("parameter array")
        .iter()
        .map(|value| match value {
            Value::Null => SqlValue::Null,
            Value::Bool(value) => SqlValue::Integer(if *value { 1 } else { 0 }),
            Value::Number(value) => value
                .as_i64()
                .map(SqlValue::Integer)
                .or_else(|| value.as_f64().map(SqlValue::Real))
                .expect("numeric parameter"),
            Value::String(value) => SqlValue::Text(value.clone()),
            _ => panic!("unexpected D1 parameter"),
        })
        .collect()
}

fn run_statement(
    connection: &Connection,
    sql: &str,
    params: Vec<SqlValue>,
) -> Result<Vec<Value>, String> {
    if sql.trim_start().starts_with("SELECT") || sql.contains("RETURNING") {
        let mut statement = connection.prepare(sql).map_err(|error| error.to_string())?;
        let columns = statement
            .column_names()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let mut rows = statement
            .query(params_from_iter(params))
            .map_err(|error| error.to_string())?;
        let mut output = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let mut object = serde_json::Map::new();
            for (index, column) in columns.iter().enumerate() {
                let value = match row.get_ref(index).map_err(|error| error.to_string())? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(value) => json!(value),
                    rusqlite::types::ValueRef::Real(value) => json!(value),
                    rusqlite::types::ValueRef::Text(value) => {
                        Value::String(String::from_utf8_lossy(value).into_owned())
                    }
                    rusqlite::types::ValueRef::Blob(value) => json!(value),
                };
                object.insert(column.clone(), value);
            }
            output.push(Value::Object(object));
        }
        Ok(output)
    } else {
        connection
            .execute(sql, params_from_iter(params))
            .map_err(|error| error.to_string())?;
        Ok(Vec::new())
    }
}
