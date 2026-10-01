//! Atomic, exact-run inventory sealing for staging load tests.
//!
//! This adapter owns only the durable census-to-seal transition.  It never
//! creates a run, accepts caller inventory, contacts a provider, or deletes a
//! resource.  Its caller must supply an already verified admission context.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::json;

use super::{
    d1_http::{D1BatchStatement, D1HttpClient},
    staging_load_test_admission::StagingLoadTestAdmissionContext,
    staging_load_test_ownership::{
        StagingLoadTestResourceClass, StagingLoadTestScenario, STAGING_LOAD_TEST_RESOURCE_CLASSES,
    },
};

const MAX_RESOURCES: i64 = 256;
const RECEIPT_SCHEMA: &str = "corelink.staging-load-test-seal-receipt.v1";
const SQL_RUN_STATE: &str = "SELECT state FROM staging_load_test_runs WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 LIMIT 2";
const SQL_SEAL: &str = "UPDATE staging_load_test_runs SET state=CASE WHEN (SELECT count(*) FROM staging_load_test_resources WHERE run_id=?1 AND scenario=?2) <= ?4 THEN 'sealed' ELSE 'over_budget' END WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 AND state='open'";
const SQL_READ_SCANS: &str = "SELECT scan.resource_class, scan.observed_count FROM staging_load_test_resource_scans AS scan JOIN staging_load_test_runs AS run ON run.run_id=scan.run_id AND run.scenario=scan.scenario WHERE scan.run_id=?1 AND scan.scenario=?2 AND run.target_environment='staging' AND run.target_deployment_sha=?3 AND run.state='sealed' ORDER BY scan.resource_class LIMIT 10";

/// Identity derived exclusively from a verified admission context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StagingLoadTestSealIdentity {
    run_id: String,
    scenario: StagingLoadTestScenario,
    target_deployment_sha: String,
}

impl StagingLoadTestSealIdentity {
    #[must_use]
    pub(crate) fn from_admission(context: &StagingLoadTestAdmissionContext) -> Self {
        Self {
            run_id: context.run_id().to_owned(),
            scenario: context.scenario(),
            target_deployment_sha: context.target_deployment_sha().to_owned(),
        }
    }
}

/// The only successful seal response. Resource handles and admission material
/// are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct StagingLoadTestSealReceipt {
    schema: &'static str,
    run_id: String,
    scenario: &'static str,
    target_deployment_sha: String,
    state: &'static str,
    resources: BTreeMap<&'static str, i64>,
}

impl StagingLoadTestSealReceipt {
    fn from_identity(
        identity: &StagingLoadTestSealIdentity,
        resources: BTreeMap<&'static str, i64>,
    ) -> Self {
        Self {
            schema: RECEIPT_SCHEMA,
            run_id: identity.run_id.clone(),
            scenario: identity.scenario.as_str(),
            target_deployment_sha: identity.target_deployment_sha.clone(),
            state: "sealed",
            resources,
        }
    }
}

/// Narrow D1 implementation for the staging-only seal endpoint.
pub(crate) struct StagingLoadTestSealStore {
    d1: Arc<D1HttpClient>,
}

impl StagingLoadTestSealStore {
    pub(crate) fn from_env() -> Result<Self, ()> {
        D1HttpClient::for_staging_load_test_ownership_writes()
            .map(|d1| Self { d1: Arc::new(d1) })
            .map_err(|_| ())
    }

    #[cfg(test)]
    fn from_d1_client_for_test(d1: D1HttpClient) -> Self {
        Self { d1: Arc::new(d1) }
    }

    /// Seal an exact open run, or replay an already sealed validated receipt.
    /// Any malformed, short, ambiguous, or unavailable D1 result fails closed.
    pub(crate) async fn seal(
        &self,
        identity: StagingLoadTestSealIdentity,
    ) -> Result<StagingLoadTestSealReceipt, ()> {
        match self.run_state(&identity).await?.as_deref() {
            Some("sealed") => return self.read_receipt(&identity).await,
            Some("open") => {}
            _ => return Err(()),
        }

        let now_ms = unix_time_ms()?;
        let mut statements = STAGING_LOAD_TEST_RESOURCE_CLASSES
            .iter()
            .map(|class| scan_statement(&identity, *class, now_ms))
            .collect::<Vec<_>>();
        // The state expression deliberately becomes an invalid state above the
        // capacity. SQLite rejects it, so D1 rolls every earlier scan write
        // back with the batch. Existing 0147/0149 triggers then enforce the
        // complete-census and unresolved-R2 predicates for the sealed branch.
        statements.push(D1BatchStatement::new(
            SQL_SEAL,
            vec![
                json!(identity.run_id),
                json!(identity.scenario.as_str()),
                json!(identity.target_deployment_sha),
                json!(MAX_RESOURCES),
            ],
        ));
        self.d1.batch(statements).await.map_err(|_| ())?;
        self.read_receipt(&identity).await
    }

    async fn run_state(
        &self,
        identity: &StagingLoadTestSealIdentity,
    ) -> Result<Option<String>, ()> {
        let rows = self
            .d1
            .query(SQL_RUN_STATE, &identity_params(identity))
            .await
            .map_err(|_| ())?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => row
                .get("state")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(())
                .map(Some),
            _ => Err(()),
        }
    }

    async fn read_receipt(
        &self,
        identity: &StagingLoadTestSealIdentity,
    ) -> Result<StagingLoadTestSealReceipt, ()> {
        if self.run_state(identity).await?.as_deref() != Some("sealed") {
            return Err(());
        }
        let rows = self
            .d1
            .query(SQL_READ_SCANS, &identity_params(identity))
            .await
            .map_err(|_| ())?;
        if rows.len() != STAGING_LOAD_TEST_RESOURCE_CLASSES.len() {
            return Err(());
        }
        let mut resources = BTreeMap::new();
        for row in rows {
            let class = row
                .get("resource_class")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let count = row
                .get("observed_count")
                .and_then(serde_json::Value::as_i64)
                .filter(|value| *value >= 0)
                .ok_or(())?;
            if !canonical_class(class)
                || resources
                    .insert(canonical_class_name(class).ok_or(())?, count)
                    .is_some()
            {
                return Err(());
            }
        }
        if resources.len() != STAGING_LOAD_TEST_RESOURCE_CLASSES.len() {
            return Err(());
        }
        Ok(StagingLoadTestSealReceipt::from_identity(
            identity, resources,
        ))
    }
}

fn scan_statement(
    identity: &StagingLoadTestSealIdentity,
    class: StagingLoadTestResourceClass,
    now_ms: i64,
) -> D1BatchStatement {
    // Each count is calculated inside the same D1 batch, from the ownership
    // ledger, and the open-run predicate makes a stale/racing request a no-op.
    D1BatchStatement::new(
        "INSERT INTO staging_load_test_resource_scans (run_id, scenario, resource_class, state, observed_count, scanned_at_ms) SELECT ?1, ?2, ?4, 'complete', (SELECT count(*) FROM staging_load_test_resources WHERE run_id=?1 AND scenario=?2 AND resource_class=?4), ?5 WHERE EXISTS (SELECT 1 FROM staging_load_test_runs WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 AND state='open') ON CONFLICT(run_id, scenario, resource_class) DO UPDATE SET state=excluded.state, observed_count=excluded.observed_count, scanned_at_ms=excluded.scanned_at_ms",
        vec![json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha), json!(class.as_str()), json!(now_ms)],
    )
}

fn identity_params(identity: &StagingLoadTestSealIdentity) -> [serde_json::Value; 3] {
    [
        json!(identity.run_id),
        json!(identity.scenario.as_str()),
        json!(identity.target_deployment_sha),
    ]
}

fn canonical_class(value: &str) -> bool {
    STAGING_LOAD_TEST_RESOURCE_CLASSES
        .iter()
        .any(|class| class.as_str() == value)
}

fn canonical_class_name(value: &str) -> Option<&'static str> {
    STAGING_LOAD_TEST_RESOURCE_CLASSES
        .iter()
        .find_map(|class| (class.as_str() == value).then_some(class.as_str()))
}

fn unix_time_ms() -> Result<i64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis()
        .try_into()
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn identity() -> StagingLoadTestSealIdentity {
        StagingLoadTestSealIdentity {
            run_id: "123".to_owned(),
            scenario: StagingLoadTestScenario::Cas,
            target_deployment_sha: SHA.to_owned(),
        }
    }

    fn client(endpoint: &str) -> D1HttpClient {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        D1HttpClient::new_for_loopback_test(&env, endpoint).expect("loopback D1 client")
    }

    fn serve(stream: &mut std::net::TcpStream, body: String) {
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).expect("request read");
            bytes.extend_from_slice(&buffer[..read]);
            if bytes
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .is_some_and(|end| {
                    let headers = std::str::from_utf8(&bytes[..end]).expect("headers");
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .expect("content length")
                        .parse::<usize>()
                        .expect("length");
                    bytes.len() >= end + 4 + length
                })
            {
                break;
            }
        }
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).expect("response write");
    }

    fn request_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).expect("request read");
            bytes.extend_from_slice(&buffer[..read]);
            if bytes
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .is_some_and(|end| {
                    let headers = std::str::from_utf8(&bytes[..end]).expect("headers");
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .expect("content length")
                        .parse::<usize>()
                        .expect("length");
                    bytes.len() >= end + 4 + length
                })
            {
                return bytes;
            }
        }
    }

    fn respond(stream: &mut std::net::TcpStream, body: String) {
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).expect("response write");
    }

    fn d1(result: serde_json::Value) -> String {
        serde_json::json!({"result": result, "success": true, "errors": []}).to_string()
    }

    #[test]
    fn receipt_has_all_nine_canonical_classes() {
        let classes = STAGING_LOAD_TEST_RESOURCE_CLASSES
            .iter()
            .map(|class| class.as_str())
            .collect::<Vec<_>>();
        assert_eq!(classes.len(), 9);
        assert!(classes.iter().all(|class| canonical_class(class)));
        assert!(!canonical_class("caller_supplied"));
    }

    #[tokio::test]
    async fn loopback_adapter_seals_then_returns_a_valid_nine_class_receipt() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = std::thread::spawn(move || {
            let responses = [
                d1(serde_json::json!([{ "results": [{"state":"open"}], "success": true }])),
                d1(serde_json::Value::Array(
                    (0..10)
                        .map(|_| serde_json::json!({"results":[], "success":true}))
                        .collect(),
                )),
                d1(serde_json::json!([{ "results": [{"state":"sealed"}], "success": true }])),
                d1(
                    serde_json::json!([{ "results": STAGING_LOAD_TEST_RESOURCE_CLASSES.iter().map(|class| serde_json::json!({"resource_class":class.as_str(), "observed_count":0})).collect::<Vec<_>>(), "success": true }]),
                ),
            ];
            for body in responses {
                let (mut stream, _) = listener.accept().expect("connection");
                serve(&mut stream, body);
            }
        });
        let receipt = StagingLoadTestSealStore::from_d1_client_for_test(client(&endpoint))
            .seal(identity())
            .await
            .expect("receipt");
        assert_eq!(receipt.schema, RECEIPT_SCHEMA);
        assert_eq!(receipt.resources.len(), 9);
        server.join().expect("server");
    }

    #[tokio::test]
    async fn short_d1_response_fails_closed_before_any_batch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            serve(&mut stream, d1(serde_json::json!([])));
        });
        assert!(
            StagingLoadTestSealStore::from_d1_client_for_test(client(&endpoint))
                .seal(identity())
                .await
                .is_err()
        );
        server.join().expect("server");
    }

    #[tokio::test]
    async fn concurrent_seals_allow_one_receipt_and_fail_close_the_racing_batch() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let opens = Arc::new(Barrier::new(2));
        let batches = Arc::new(AtomicUsize::new(0));
        let server_batches = Arc::clone(&batches);
        let server = std::thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().expect("connection");
                let opens = Arc::clone(&opens);
                let batches = Arc::clone(&server_batches);
                workers.push(std::thread::spawn(move || {
                    let request = request_body(&mut stream);
                    let request = String::from_utf8(request).expect("request utf8");
                    let body = if request.contains("\"batch\"") {
                        if batches.fetch_add(1, Ordering::SeqCst) == 0 { d1(serde_json::Value::Array((0..10).map(|_| serde_json::json!({"results":[], "success":true})).collect())) } else { serde_json::json!({"result":[], "success":false, "errors":[{"message":"race lost"}]}).to_string() }
                    } else if request.contains(SQL_READ_SCANS) {
                        d1(serde_json::json!([{ "results": STAGING_LOAD_TEST_RESOURCE_CLASSES.iter().map(|class| serde_json::json!({"resource_class":class.as_str(), "observed_count":0})).collect::<Vec<_>>(), "success": true }]))
                    } else if batches.load(Ordering::SeqCst) == 0 {
                        opens.wait(); d1(serde_json::json!([{ "results": [{"state":"open"}], "success": true }]))
                    } else { d1(serde_json::json!([{ "results": [{"state":"sealed"}], "success": true }])) };
                    respond(&mut stream, body);
                }));
            }
            for worker in workers {
                worker.join().expect("worker");
            }
        });
        let store = Arc::new(StagingLoadTestSealStore::from_d1_client_for_test(client(
            &endpoint,
        )));
        let (first, second) = tokio::join!(store.seal(identity()), store.seal(identity()));
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(batches.load(Ordering::SeqCst), 2);
        server.join().expect("server");
    }
}
