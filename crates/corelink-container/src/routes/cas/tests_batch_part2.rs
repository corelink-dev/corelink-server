/// Companion: a `/batch-read` BELOW the limit succeeds and RELEASES its read
/// slot (read pool back to empty), pinning the RAII release on the read axis.
#[tokio::test]
async fn batch_read_below_limit_releases_slot() {
    let state = fixture();
    let app = router(state.clone());
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/cas/{TEST_TENANT}/batch-read"))
        .header("x-corelink-tenant-id", TEST_TENANT)
        .header(crate::scope::SCOPE_HEADER, "cas:r")
        .header(axum::http::header::CONTENT_TYPE, NDJSON_CONTENT_TYPE)
        .body(Body::from(format!(
            "{}\n",
            serde_json::json!({ "hash": fake_hash(b"absent-blob") })
        )))
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    // The slot is deliberately still held while the response body is
    // outstanding; consuming the stream is the release boundary.
    {
        let g = state.read_inflight.lock().expect("lock");
        assert_eq!(g.get(TEST_TENANT), Some(&1));
    }
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let g = state.read_inflight.lock().expect("lock");
    assert_eq!(
        g.get(TEST_TENANT),
        None,
        "the batch-read's read-concurrency slot must be released after its stream is consumed"
    );
}

/// Batch admission is one-at-a-time because one envelope plus one full object
/// peak is the safe 220 MiB bound. The admission permit must remain held while
/// the response stream is outstanding, then become available again after the
/// stream is consumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_read_admission_is_released_after_response_consumed() {
    let state = fixture();
    let bytes = b"concurrent-batch-read".to_vec();
    let hash = fake_hash(&bytes);
    state
        .write
        .write(CasWriteRequest::new(
            TEST_TENANT,
            hash.clone(),
            bytes,
            format!("anon@{TEST_TENANT}"),
            TEST_TENANT,
            0,
        ))
        .expect("seed CAS object");

    let request = || {
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/cas/{TEST_TENANT}/batch-read"))
            .header("x-corelink-tenant-id", TEST_TENANT)
            .header(crate::scope::SCOPE_HEADER, "cas:r")
            .header(axum::http::header::CONTENT_TYPE, NDJSON_CONTENT_TYPE)
            .body(Body::from(format!(
                "{}\n",
                serde_json::json!({ "hash": hash })
            )))
            .expect("request")
    };
    let first = router(state.clone())
        .oneshot(request())
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::OK);

    // The first response has not been consumed, so its batch envelope and
    // admission permit are still live. A second batch is bounded backpressure,
    // not a weighted-budget deadlock or an unbounded queue.
    let blocked = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        router(state.clone()).oneshot(request()),
    )
    .await
    .expect("admission timeout must be bounded")
    .expect("second response");
    assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);

    let _ = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .expect("first body");

    let recovered = router(state)
        .oneshot(request())
        .await
        .expect("recovered response");
    assert_eq!(recovered.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(recovered.into_body(), usize::MAX)
        .await
        .expect("recovered body");
}

#[derive(Debug)]
struct BatchReadTrackingHandler {
    active: Arc<std::sync::atomic::AtomicUsize>,
    max_active: Arc<std::sync::atomic::AtomicUsize>,
    started: Option<Arc<std::sync::atomic::AtomicUsize>>,
    first_started: Option<Arc<tokio::sync::Notify>>,
    saw_max_bytes: Arc<std::sync::atomic::AtomicBool>,
    response_len: usize,
    fail_hash: Option<String>,
    read_delay: std::time::Duration,
}

impl CasReadHandler for BatchReadTrackingHandler {
    fn read(&self, req: CasReadRequest) -> Result<CasReadResponse, CasHandlerError> {
        use std::sync::atomic::Ordering;

        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(started) = self.started.as_ref() {
            started.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(first_started) = self.first_started.as_ref() {
            first_started.notify_one();
        }
        let mut observed = self.max_active.load(Ordering::SeqCst);
        while active > observed {
            match self.max_active.compare_exchange(
                observed,
                active,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(next) => observed = next,
            }
        }
        if req.max_bytes == Some(BATCH_MAX_BYTES as u64) {
            self.saw_max_bytes.store(true, Ordering::SeqCst);
        }
        // Give the other window tasks time to enter the storage seam. This
        // makes the >1 concurrency assertion deterministic on multi-thread
        // test runtimes while the production window remains budget-derived.
        std::thread::sleep(self.read_delay);
        let result = if self.fail_hash.as_deref() == Some(req.hash.as_str()) {
            Err(CasHandlerError::Internal(
                "tracked batch read failure".into(),
            ))
        } else {
            Ok(CasReadResponse::new(vec![0; self.response_len], req.hash))
        };
        self.active.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

fn tracking_state(read: Arc<dyn CasReadHandler>) -> CasRouteState {
    let audit = Arc::new(InMemoryAuditSink::new());
    let sli = Arc::new(InMemorySliObserver::new());
    let shared = Arc::new(InMemoryCasHandler::new(audit, sli));
    let write: Arc<dyn CasWriteHandler> = shared.clone();
    let delete: Arc<dyn CasDeleteHandler> = shared.clone();
    let list: Arc<dyn CasListHandler> = shared;
    CasRouteState {
        read,
        write,
        delete,
        list,
        tombstones: None,
        quota: None,
        pat_gate: None,
        put_inflight: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        read_inflight: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        read_budget: test_read_budget(),
        batch_read_admission: test_batch_read_admission(),
        usage_meter: std::sync::Arc::new(crate::usage_meter::UsageMeter::new(None, || 0)),
    }
}

fn batch_read_request(hashes: &[String]) -> Request<Body> {
    let body = hashes
        .iter()
        .map(|hash| format!("{}\n", serde_json::json!({"hash": hash})))
        .collect::<String>();
    Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/cas/{TEST_TENANT}/batch-read"))
        .header("x-corelink-tenant-id", TEST_TENANT)
        .header(crate::scope::SCOPE_HEADER, "cas:r")
        .header(axum::http::header::CONTENT_TYPE, NDJSON_CONTENT_TYPE)
        .body(Body::from(body))
        .expect("request")
}

/// A post-header R2 body stall must surface as a terminal read error, and the
/// route must release both sides of [`BatchReadLease`] after that timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_read_post_header_timeout_releases_admission_and_tenant_lease() {
    use crate::storage::r2_s3::{R2CasHandler, R2S3Client};
    use crate::storage::StorageEnv;

    let env = StorageEnv {
        r2_endpoint: "https://localhost:1".to_owned(),
        r2_access_key_id: "test".to_owned(),
        r2_secret_access_key: "test".to_owned(),
        r2_session_token: None,
        cloudflare_account_id: "test".to_owned(),
        cf_api_token: "test".to_owned(),
        d1_database_id: "test".to_owned(),
    };
    let client = R2S3Client::new(&env, "test-bucket")
        .await
        .expect("test R2 client");
    let audit = Arc::new(InMemoryAuditSink::new());
    let sli = Arc::new(InMemorySliObserver::new());
    let handler = Arc::new(
        R2CasHandler::new(client, "iad", None, audit, sli)
            .with_test_post_header_body_timeout(),
    );
    let mut state = tracking_state(handler);
    let admission = Arc::new(tokio::sync::Semaphore::new(CAS_READ_BATCH_MAX_IN_FLIGHT));
    state.batch_read_admission = Arc::clone(&admission);
    let admission_before = admission.available_permits();
    assert!(admission_before > 0, "batch admission must be available");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        router(state.clone()).oneshot(batch_read_request(&[
            fake_hash(b"post-header-stall"),
        ])),
    )
        .await
        .expect("body timeout must terminate the batch")
        .expect("batch route response");
    assert!(response.status().is_server_error());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state
                .read_inflight
                .lock()
                .expect("read tracker")
                .get(TEST_TENANT)
                .is_none()
                && admission.available_permits() == admission_before
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tenant and global leases must release after body timeout");
}

/// A full structured window reaches concurrency >1 but never exceeds the
/// budget-derived eight object tasks. The request ceiling is observed by the
/// read handler, not merely checked after the response is materialised.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn batch_read_window_is_bounded_and_passes_object_ceiling() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let saw_max_bytes = Arc::new(AtomicBool::new(false));
    let read = Arc::new(BatchReadTrackingHandler {
        active: active.clone(),
        max_active: max_active.clone(),
        started: None,
        first_started: None,
        saw_max_bytes: saw_max_bytes.clone(),
        response_len: 1,
        fail_hash: None,
        read_delay: std::time::Duration::from_millis(10),
    });
    let hashes: Vec<String> = (0..BATCH_READ_FANOUT)
        .map(|i| fake_hash(format!("window-{i}").as_bytes()))
        .collect();
    let response = router(tracking_state(read))
        .oneshot(batch_read_request(&hashes))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert!(saw_max_bytes.load(Ordering::SeqCst));
    let observed = max_active.load(Ordering::SeqCst);
    assert!(observed > 1, "structured batch reads must overlap");
    assert!(
        observed <= BATCH_READ_FANOUT,
        "fanout exceeded derived bound"
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

/// A read failure aborts and drains every later task before the route returns;
/// no storage task remains active after the terminal response is selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn batch_read_failure_drains_all_active_tasks_before_return() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let saw_max_bytes = Arc::new(AtomicBool::new(false));
    let hashes: Vec<String> = (0..(BATCH_READ_FANOUT + 1))
        .map(|i| fake_hash(format!("failure-{i}").as_bytes()))
        .collect();
    let read = Arc::new(BatchReadTrackingHandler {
        active: active.clone(),
        max_active: max_active.clone(),
        started: None,
        first_started: None,
        saw_max_bytes: saw_max_bytes.clone(),
        response_len: 1,
        fail_hash: Some(hashes[0].clone()),
        read_delay: std::time::Duration::from_millis(10),
    });
    let response = router(tracking_state(read))
        .oneshot(batch_read_request(&hashes))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(saw_max_bytes.load(Ordering::SeqCst));
    assert!(max_active.load(Ordering::SeqCst) > 1);
    assert!(max_active.load(Ordering::SeqCst) <= BATCH_READ_FANOUT);
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "all spawned storage tasks must be drained before failure returns"
    );
}

/// Aggregate payload overflow is terminal, but all already-spawned reads are
/// still drained before the 413 reaches the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn batch_read_overflow_drains_all_active_tasks_before_return() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let saw_max_bytes = Arc::new(AtomicBool::new(false));
    let read = Arc::new(BatchReadTrackingHandler {
        active: active.clone(),
        max_active: max_active.clone(),
        started: None,
        first_started: None,
        saw_max_bytes: saw_max_bytes.clone(),
        response_len: BATCH_MAX_BYTES / 2 + 1,
        fail_hash: None,
        read_delay: std::time::Duration::from_millis(10),
    });
    let hashes: Vec<String> = (0..(BATCH_READ_FANOUT + 1))
        .map(|i| fake_hash(format!("overflow-{i}").as_bytes()))
        .collect();
    let response = router(tracking_state(read))
        .oneshot(batch_read_request(&hashes))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(saw_max_bytes.load(Ordering::SeqCst));
    assert!(max_active.load(Ordering::SeqCst) > 1);
    assert!(max_active.load(Ordering::SeqCst) <= BATCH_READ_FANOUT);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

/// B-077 HOLD: the single GET keeps its tenant slot until its response
/// stream is consumed, not merely until the handler returns.
#[tokio::test]
async fn single_read_keeps_slot_until_response_consumed() {
    let state = fixture();
    let bytes = b"stream-lifetime".to_vec();
    let hash = fake_hash(&bytes);
    state
        .write
        .write(CasWriteRequest::new(
            TEST_TENANT,
            hash.clone(),
            bytes,
            format!("anon@{TEST_TENANT}"),
            TEST_TENANT,
            0,
        ))
        .expect("seed CAS object");
    let app = router(state.clone());
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/cas/{TEST_TENANT}/{hash}"))
        .header("x-corelink-tenant-id", TEST_TENANT)
        .header(crate::scope::SCOPE_HEADER, "cas:r")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    {
        let g = state.read_inflight.lock().expect("lock");
        assert_eq!(g.get(TEST_TENANT), Some(&1));
    }
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(&body[..], b"stream-lifetime");
    let g = state.read_inflight.lock().expect("lock");
    assert_eq!(g.get(TEST_TENANT), None);
}
