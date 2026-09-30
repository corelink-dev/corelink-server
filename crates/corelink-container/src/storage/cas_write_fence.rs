//! D1-backed write lease for the native R2 CAS path.
//!
//! GC's `gc_purge_intent` row is a durable reader/writer fence, but a D1
//! request cannot remain open while the container waits for R2.  The native
//! CAS writer therefore claims a short-lived `cas_write_intent` row before
//! the first R2 mutation.  GC acquisition excludes that row, and the guarded
//! metadata commit consumes only the exact request token.  The owner then
//! releases that token; a crashed writer is reclaimed only after the bounded
//! lease, and its old token cannot commit after a newer writer takes over.

use std::sync::Arc;

use corelink_handler_cas::CasWriteOperationContext;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    d1_http::{D1BatchStatement, D1HttpClient},
    staging_load_test_admission::StagingLoadTestAdmissionContext,
    staging_load_test_ownership::{
        StagingLoadTestDisposition, StagingLoadTestOwnershipError, StagingLoadTestResourceClass,
        StagingLoadTestScenario,
    },
};

/// Typed request authority carried from a successful staging admission through
/// the shared CAS write context bundle.
#[derive(Clone, Debug)]
pub(crate) struct StagingCasWriteContext(Arc<StagingLoadTestAdmissionContext>);

impl StagingCasWriteContext {
    pub(crate) fn new(context: Arc<StagingLoadTestAdmissionContext>) -> Self {
        Self(context)
    }

    pub(crate) fn admission(&self) -> &StagingLoadTestAdmissionContext {
        &self.0
    }
}

impl CasWriteOperationContext for StagingCasWriteContext {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Recover only the request slot from the shared bundle. A data-plane-only
/// BYOK pin has no ownership context and leaves ordinary writes unchanged.
pub(crate) fn staging_admission_context(
    context: Option<&dyn CasWriteOperationContext>,
) -> Result<Option<&StagingLoadTestAdmissionContext>, StagingLoadTestOwnershipError> {
    let Some(context) = context else {
        return Ok(None);
    };
    let request_context = context
        .as_any()
        .downcast_ref::<corelink_handler_cas::CasWriteContextBundle>()
        .map_or(Some(context), |bundle| bundle.request());
    let Some(request_context) = request_context else {
        return Ok(None);
    };
    request_context
        .as_any()
        .downcast_ref::<StagingCasWriteContext>()
        .map(|context| Some(context.admission()))
        .ok_or(StagingLoadTestOwnershipError::InvalidIdentifier)
}

/// Build the stable run-owned reference identity used by Cargo and native CAS.
pub(crate) fn cas_reference_registration<'a>(
    context: &'a StagingLoadTestAdmissionContext,
    opaque_handle: &'a str,
) -> Result<
    super::staging_load_test_ownership::StagingLoadTestResourceRegistration<'a>,
    StagingLoadTestOwnershipError,
> {
    match context.scenario() {
        StagingLoadTestScenario::Cas | StagingLoadTestScenario::B103CargoWrite => {}
        _ => return Err(StagingLoadTestOwnershipError::ScenarioMismatch),
    }
    context.ownership_registration(
        StagingLoadTestResourceClass::CasReference,
        StagingLoadTestDisposition::Retained,
        opaque_handle,
    )
}

pub(crate) fn cas_reference_handle(
    context: &StagingLoadTestAdmissionContext,
    tenant_id: &str,
    digest: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"corelink/staging-cas-reference/v1\0");
    for value in [
        context.scenario().as_str().as_bytes(),
        context.run_id().as_bytes(),
        tenant_id.as_bytes(),
        digest.as_bytes(),
    ] {
        hasher.update(value);
        hasher.update([0]);
    }
    let mut opaque = String::with_capacity(14 + 64);
    opaque.push_str("cas-reference:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(opaque, "{byte:02x}");
    }
    opaque
}

/// Maximum interval a crashed native writer can hold the D1 lease.
pub const CAS_WRITE_LEASE_MS: u64 = 15 * 60 * 1000;

/// A D1 lease authorising one tenant/digest CAS write attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CasWriteLease {
    tenant_id: String,
    digest: String,
    request_id: String,
    ownership_operation_id: Option<String>,
    ownership_intent_committed: bool,
}

impl CasWriteLease {
    /// Tenant scope bound into every subsequent lease operation.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Plain canonical digest bound into every subsequent lease operation.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Opaque lease token used to fence stale writers.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

/// Result of committing the metadata side of a fenced CAS write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CasWriteCommit {
    /// A new `blob_meta` row was inserted with `refcount = 1`.
    Inserted,
    /// An existing live row was re-referenced atomically.
    Referenced,
}

/// Explicit dependency required by the live R2 CAS writer.
pub trait CasWriteFence: Send + Sync + core::fmt::Debug {
    /// Claim the tenant/digest write lease before touching R2.
    fn begin(
        &self,
        tenant_id: &str,
        digest: &str,
        now_ms: u64,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<CasWriteLease, String>;

    /// Commit/re-reference `blob_meta` while consuming the exact lease token.
    fn commit(
        &self,
        lease: &CasWriteLease,
        size_bytes: u64,
        now_ms: u64,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<CasWriteCommit, String>;

    /// Release a lease after an R2 or pre-commit failure. Lease expiry is the
    /// recovery fallback if this cleanup request itself cannot reach D1.
    fn abort(&self, lease: &CasWriteLease) -> Result<(), String>;
}

/// Production implementation over the same D1 client used by GC.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct D1CasWriteFence {
    d1: Arc<D1HttpClient>,
}

impl D1CasWriteFence {
    /// Construct a fence over a shared D1 HTTP client.
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    fn query_sync(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<super::d1_http::D1Row>, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "CAS write fence requires a running Tokio runtime".to_owned())?;
        tokio::task::block_in_place(|| handle.block_on(self.d1.query(sql, params)))
    }

    fn batch_sync(
        &self,
        statements: Vec<D1BatchStatement>,
    ) -> Result<Vec<Vec<super::d1_http::D1Row>>, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "CAS write fence requires a running Tokio runtime".to_owned())?;
        tokio::task::block_in_place(|| handle.block_on(self.d1.batch(statements)))
            .map_err(|_| "CAS write fence ownership batch failed".to_owned())
    }

    fn reusable_staging_operation_id(
        &self,
        context: &StagingLoadTestAdmissionContext,
        opaque_handle: &str,
    ) -> Result<Option<(String, bool)>, String> {
        let rows = self.query_sync(
            "SELECT operation_id, state FROM staging_load_test_r2_intents
             WHERE run_id = ?1 AND scenario = ?2 AND target_deployment_sha = ?3
               AND resource_class = 'cas_reference' AND opaque_handle = ?4
               AND disposition = 'retained' AND state IN ('prepared', 'committed')
             LIMIT 1",
            &[
                json!(context.run_id()),
                json!(context.scenario().as_str()),
                json!(context.target_deployment_sha()),
                json!(opaque_handle),
            ],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let operation_id = row
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| "CAS write staging recovery identity is invalid".to_owned())?;
        let committed = match row.get("state").and_then(serde_json::Value::as_str) {
            Some("prepared") => false,
            Some("committed") => true,
            _ => return Err("CAS write staging recovery state is invalid".to_owned()),
        };
        Ok(Some((operation_id.to_owned(), committed)))
    }

    fn validate_scope(tenant_id: &str, digest: &str) -> Result<(), String> {
        Uuid::parse_str(tenant_id)
            .map_err(|_| "CAS write fence requires a canonical tenant UUID".to_owned())?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("CAS write fence received a non-canonical digest".to_owned());
        }
        Ok(())
    }
}

impl CasWriteFence for D1CasWriteFence {
    fn begin(
        &self,
        tenant_id: &str,
        digest: &str,
        now_ms: u64,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<CasWriteLease, String> {
        Self::validate_scope(tenant_id, digest)?;
        // A timed-out owner is reclaimed by the GC acquisition transaction;
        // this writer-side claim remains conservative and refuses any existing
        // lease so a stale completion can never overwrite a newer owner.
        if let Some(context) = context {
            cas_reference_registration(context, &cas_reference_handle(context, tenant_id, digest))
                .map_err(|_| "CAS write staging context is invalid".to_owned())?;
        }
        let request_id = format!("cas-write:{tenant_id}:{digest}:{now_ms}");
        let rows = self.query_sync(
            "INSERT INTO cas_write_intent
                 (tenant_id, digest, request_id, state, started_at, updated_at)
             SELECT ?1, ?2, ?3, 'writing', ?4, ?4
             WHERE NOT EXISTS (
                 SELECT 1 FROM gc_purge_intent AS pi
                 WHERE pi.tenant_id = ?1 AND pi.digest = ?2
                   AND pi.state IN ('purging', 'r2_deleted', 'retry')
             )
               AND NOT EXISTS (
                 SELECT 1 FROM blob_meta AS bm
                 WHERE bm.tenant_id = ?1 AND bm.digest = ?2
                   AND bm.deleted_at IS NOT NULL
               )
               AND NOT EXISTS (
                 SELECT 1 FROM cas_write_intent AS wi
                 WHERE wi.tenant_id = ?1 AND wi.digest = ?2
                   AND wi.state = 'writing'
               )
             RETURNING request_id",
            &[
                json!(tenant_id),
                json!(digest),
                json!(request_id),
                json!(now_ms),
            ],
        )?;
        if rows.is_empty() {
            return Err(
                "CAS write refused: active GC purge or another writer owns the D1 fence".to_owned(),
            );
        }
        let ownership_operation_id = if let Some(context) = context {
            let opaque_handle = cas_reference_handle(context, tenant_id, digest);
            let operation_result: Result<(String, bool), String> = (|| {
                let registration = cas_reference_registration(context, &opaque_handle)
                    .map_err(|_| "CAS write staging context is invalid".to_owned())?;
                if let Some((operation_id, committed)) =
                    self.reusable_staging_operation_id(context, &opaque_handle)?
                {
                    return Ok((operation_id, committed));
                }
                let operation_id =
                    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
                let intent = registration
                    .r2_intent(&operation_id)
                    .map_err(|_| "CAS write staging context is invalid".to_owned())?;
                let prepared_at_ms = i64::try_from(now_ms)
                    .map_err(|_| "CAS write timestamp is out of range".to_owned())?;
                self.batch_sync(vec![intent.prepare_statement(prepared_at_ms)])?;
                Ok((operation_id, false))
            })();
            if operation_result.is_err() {
                let _ = self.abort(&CasWriteLease {
                    tenant_id: tenant_id.to_owned(),
                    digest: digest.to_owned(),
                    request_id: request_id.clone(),
                    ownership_operation_id: None,
                    ownership_intent_committed: false,
                });
                return Err("CAS write staging intent could not be prepared".to_owned());
            }
            operation_result.ok()
        } else {
            None
        };
        Ok(CasWriteLease {
            tenant_id: tenant_id.to_owned(),
            digest: digest.to_owned(),
            request_id,
            ownership_operation_id: ownership_operation_id.as_ref().map(|(id, _)| id.clone()),
            ownership_intent_committed: ownership_operation_id
                .is_some_and(|(_, committed)| committed),
        })
    }

    fn commit(
        &self,
        lease: &CasWriteLease,
        size_bytes: u64,
        now_ms: u64,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<CasWriteCommit, String> {
        if size_bytes == 0 {
            return Err("CAS write metadata rejects an empty blob".to_owned());
        }
        let existing = self.query_sync(
            "SELECT deleted_at FROM blob_meta
             WHERE tenant_id = ?1 AND digest = ?2 LIMIT 1",
            &[json!(lease.tenant_id()), json!(lease.digest())],
        )?;
        if existing
            .first()
            .and_then(|row| row.get("deleted_at"))
            .is_some_and(|v| !v.is_null())
        {
            return Err("CAS write refused: blob metadata is tombstoned".to_owned());
        }
        let metadata_sql = "INSERT INTO blob_meta
                 (tenant_id, digest, size_bytes, refcount, created_at,
                  last_accessed_at, region)
             SELECT ?1, ?2, ?3, 1, ?4, ?4,
                    (SELECT primary_region FROM tenant WHERE tenant_id = ?1)
             WHERE EXISTS (
                 SELECT 1 FROM cas_write_intent AS wi
                 WHERE wi.tenant_id = ?1 AND wi.digest = ?2
                   AND wi.request_id = ?5 AND wi.state = 'writing'
             )
               AND NOT EXISTS (
                 SELECT 1 FROM gc_purge_intent AS pi
                 WHERE pi.tenant_id = ?1 AND pi.digest = ?2
                   AND pi.state IN ('purging', 'r2_deleted', 'retry')
             )
             ON CONFLICT (tenant_id, digest) DO UPDATE SET
                 refcount = blob_meta.refcount + 1,
                 last_accessed_at = excluded.last_accessed_at
             WHERE blob_meta.deleted_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM gc_purge_intent AS pi
                 WHERE pi.tenant_id = blob_meta.tenant_id
                   AND pi.digest = blob_meta.digest
                   AND pi.state IN ('purging', 'r2_deleted', 'retry')
               )
             RETURNING refcount";
        let metadata_params = vec![
            json!(lease.tenant_id()),
            json!(lease.digest()),
            json!(size_bytes),
            json!(now_ms),
            json!(lease.request_id()),
        ];
        let rows = match (context, lease.ownership_operation_id.as_deref()) {
            (None, None) => self.query_sync(metadata_sql, &metadata_params)?,
            (Some(context), Some(operation_id)) => {
                let opaque_handle =
                    cas_reference_handle(context, lease.tenant_id(), lease.digest());
                let registration = cas_reference_registration(context, &opaque_handle)
                    .map_err(|_| "CAS write staging context is invalid".to_owned())?;
                let intent = registration
                    .r2_intent(operation_id)
                    .map_err(|_| "CAS write staging context is invalid".to_owned())?;
                let committed_at_ms = i64::try_from(now_ms)
                    .map_err(|_| "CAS write timestamp is out of range".to_owned())?;
                let [register_resource, close_intent] = intent.commit_statements(committed_at_ms);
                let intent_finalizer = if lease.ownership_intent_committed {
                    D1BatchStatement::new("SELECT 1", Vec::new())
                } else {
                    close_intent
                };
                let mut results = self.batch_sync(vec![
                    D1BatchStatement::new(metadata_sql, metadata_params),
                    // An unsuccessful or stale metadata write aborts this batch
                    // before the ownership row or R2 intent can commit.
                    D1BatchStatement::new(
                        "INSERT INTO cas_write_intent \
                         (tenant_id, digest, request_id, state, started_at, updated_at) \
                         SELECT ?1, ?2, ?3, 'invalid', ?4, ?4 \
                         WHERE changes() = 0 OR NOT EXISTS (SELECT 1 FROM cas_write_intent \
                           WHERE tenant_id = ?1 AND digest = ?2 AND request_id = ?3 AND state = 'writing')",
                        vec![
                            json!(lease.tenant_id()),
                            json!(lease.digest()),
                            json!(lease.request_id()),
                            json!(now_ms),
                        ],
                    ),
                    register_resource,
                    intent_finalizer,
                    D1BatchStatement::new(
                        "INSERT INTO cas_write_intent \
                         (tenant_id, digest, request_id, state, started_at, updated_at) \
                         SELECT ?1, ?2, ?3, 'invalid', ?4, ?4 \
                         WHERE NOT EXISTS (SELECT 1 FROM staging_load_test_r2_intents \
                           WHERE operation_id = ?5 AND run_id = ?6 AND scenario = ?7 \
                             AND resource_class = 'cas_reference' AND opaque_handle = ?8 \
                             AND disposition = 'retained' AND state = 'committed')",
                        vec![
                            json!(lease.tenant_id()),
                            json!(lease.digest()),
                            json!(lease.request_id()),
                            json!(now_ms),
                            json!(operation_id),
                            json!(context.run_id()),
                            json!(context.scenario().as_str()),
                            json!(opaque_handle),
                        ],
                    ),
                    D1BatchStatement::new(
                        "UPDATE staging_load_test_r2_intents \
                         SET state = 'committed', committed_at_ms = ?1 \
                         WHERE run_id = ?2 AND scenario = ?3 AND resource_class = 'cas_reference' \
                           AND opaque_handle = ?4 AND state = 'prepared'",
                        vec![
                            json!(committed_at_ms),
                            json!(context.run_id()),
                            json!(context.scenario().as_str()),
                            json!(opaque_handle),
                        ],
                    ),
                ])?;
                if results.first().is_none_or(Vec::is_empty) {
                    return Err("CAS write metadata commit lost its D1 fence".to_owned());
                }
                results.remove(0)
            }
            _ => {
                return Err("CAS write staging context did not match its durable intent".to_owned())
            }
        };
        if rows.is_empty() {
            return Err("CAS write metadata commit lost its D1 fence".to_owned());
        }
        if existing.is_empty() {
            Ok(CasWriteCommit::Inserted)
        } else {
            Ok(CasWriteCommit::Referenced)
        }
    }

    fn abort(&self, lease: &CasWriteLease) -> Result<(), String> {
        let _ = self.query_sync(
            "DELETE FROM cas_write_intent
             WHERE tenant_id = ?1 AND digest = ?2
               AND request_id = ?3 AND state = 'writing'",
            &[
                json!(lease.tenant_id()),
                json!(lease.digest()),
                json!(lease.request_id()),
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CasWriteFence, D1CasWriteFence};
    use crate::storage::{
        d1_http::D1HttpClient,
        staging_load_test_admission::{
            admit_staging_load_test_request, StagingLoadTestAdmissionGate,
            StagingLoadTestAdmissionStore, StagingLoadTestAdmissionVerifier,
            STAGING_LOAD_TEST_ADMISSION_HEADER,
        },
        staging_load_test_ownership::StagingLoadTestScenario,
        StorageEnv,
    };
    use hmac::{Hmac, KeyInit, Mac};
    use serde_json::json;
    use sha2::Sha256;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    type HmacSha256 = Hmac<Sha256>;

    fn signed_credential(key: &[u8], issued_at_ms: i64, nonce: &str) -> String {
        let expires_at_ms = issued_at_ms + 60_000;
        let payload = format!(
            "v1.123.cas.staging.{}.{}.{}.{}",
            "a".repeat(40),
            issued_at_ms,
            expires_at_ms,
            nonce,
        );
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("fixed test key");
        mac.update(b"corelink/staging-load-admission-auth/v1\0");
        mac.update(payload.as_bytes());
        let tag = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{payload}.{tag}")
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> serde_json::Value {
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).expect("D1 request read");
            assert_ne!(read, 0, "D1 request closed before its body completed");
            bytes.extend_from_slice(&buffer[..read]);
            let Some(headers_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&bytes[..headers_end]).expect("headers UTF-8");
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .expect("content length")
                .parse::<usize>()
                .expect("content length number");
            if bytes.len() >= headers_end + 4 + length {
                return serde_json::from_slice(&bytes[headers_end + 4..headers_end + 4 + length])
                    .expect("D1 JSON request");
            }
        }
    }

    fn respond(stream: &mut std::net::TcpStream, results: Vec<serde_json::Value>) {
        let body = json!({
            "result": [{"results": results, "success": true}],
            "success": true,
            "errors": []
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("D1 response write");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_after_r2_failure_reuses_verified_durable_handle_intent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let server = std::thread::spawn(move || {
            let mut prepared_operation_id: Option<String> = None;
            let mut reusable_reads = 0;
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().expect("loopback D1 request");
                let request = read_http_request(&mut stream);
                if let Some(batch) = request.get("batch").and_then(serde_json::Value::as_array) {
                    if batch.len() == 2 {
                        assert!(batch[0]["sql"]
                            .as_str()
                            .unwrap_or_default()
                            .contains("staging_load_test_runs"));
                        assert!(batch[1]["sql"]
                            .as_str()
                            .unwrap_or_default()
                            .contains("admission_nonces"));
                        let body = json!({
                            "result": [
                                {"results": [], "success": true},
                                {"results": [], "success": true}
                            ],
                            "success": true,
                            "errors": []
                        })
                        .to_string();
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).expect("admission response");
                        continue;
                    }
                    assert_eq!(batch.len(), 1);
                    let statement = &batch[0];
                    assert!(statement["sql"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("staging_load_test_r2_intents"));
                    prepared_operation_id = statement["params"][0].as_str().map(str::to_owned);
                    respond(&mut stream, Vec::new());
                    continue;
                }

                let sql = request["sql"].as_str().unwrap_or_default();
                if sql.starts_with("INSERT INTO cas_write_intent") {
                    let request_id = request["params"][2].as_str().expect("write lease token");
                    respond(&mut stream, vec![json!({"request_id": request_id})]);
                } else if sql
                    .contains("SELECT operation_id, state FROM staging_load_test_r2_intents")
                {
                    assert!(sql.contains("resource_class = 'cas_reference'"));
                    assert!(sql.contains("state IN ('prepared', 'committed')"));
                    reusable_reads += 1;
                    match prepared_operation_id.as_deref() {
                        Some(operation_id) => respond(
                            &mut stream,
                            vec![json!({
                                "operation_id": operation_id,
                                "state": "prepared"
                            })],
                        ),
                        None => respond(&mut stream, Vec::new()),
                    }
                } else if sql.starts_with("DELETE FROM cas_write_intent") {
                    respond(&mut stream, Vec::new());
                } else {
                    panic!("unexpected D1 query: {sql}");
                }
            }
            assert_eq!(reusable_reads, 2);
            prepared_operation_id.expect("first attempt durably prepared its intent")
        });

        let env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let key = b"01234567890123456789012345678901";
        let verifier =
            StagingLoadTestAdmissionVerifier::new("staging", key).expect("test verifier");
        let admission_store = StagingLoadTestAdmissionStore::from_d1_client_for_test(
            D1HttpClient::new_for_loopback_test(&env, &endpoint).expect("admission D1 client"),
        );
        let gate = StagingLoadTestAdmissionGate::from_parts_for_test(verifier, admission_store);
        let issued_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis();
        let issued_at_ms = i64::try_from(issued_at_ms).expect("test timestamp range");
        let credential = signed_credential(key, issued_at_ms - 1, &"b".repeat(64));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            STAGING_LOAD_TEST_ADMISSION_HEADER,
            credential.parse().expect("credential header"),
        );
        let context =
            admit_staging_load_test_request(Some(&gate), &headers, StagingLoadTestScenario::Cas)
                .await
                .expect("verified admission and durable consume")
                .expect("admitted context");

        let fence = D1CasWriteFence::new(Arc::new(
            D1HttpClient::new_for_loopback_test(&env, &endpoint).expect("CAS fence D1 client"),
        ));
        let now_ms = u64::try_from(issued_at_ms).expect("positive test timestamp");
        let first = fence
            .begin(
                "11111111-1111-4111-8111-111111111111",
                &"c".repeat(64),
                now_ms,
                Some(&context),
            )
            .expect("first lease prepares durable ownership intent");
        let operation_id = first
            .ownership_operation_id
            .clone()
            .expect("owned operation");
        fence
            .abort(&first)
            .expect("simulate post-prepare R2 failure cleanup");

        let retry = fence
            .begin(
                "11111111-1111-4111-8111-111111111111",
                &"c".repeat(64),
                now_ms + 1,
                Some(&context),
            )
            .expect("retry reuses the matching prepared intent");
        assert_eq!(
            retry.ownership_operation_id.as_deref(),
            Some(operation_id.as_str())
        );
        fence.abort(&retry).expect("release retry lease");
        assert_eq!(server.join().expect("D1 server").as_str(), operation_id);
    }
}
