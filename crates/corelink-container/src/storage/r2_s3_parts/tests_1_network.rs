    /// The production durable sink shape (`audit_async` wired) remains
    /// strictly serial: when the D1 write fails, `list()` returns
    /// `AuditFailed` before the R2 enumeration is dispatched. The audit phase
    /// is present and the storage phase is absent.
    ///
    /// Gated behind `#[ignore]` like the `d1_audit_sink.rs` async-phase
    /// test it mirrors — needs outbound reachability to
    /// `api.cloudflare.com` (not live credentials: a 401 still proves the
    /// audit gate ran). Run manually with:
    ///
    /// ```bash
    /// cargo test -p corelink-server r2_cas_list_durable_audit_failure_precedes_storage -- --ignored
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires outbound network reachability to api.cloudflare.com"]
    async fn r2_cas_list_durable_audit_failure_precedes_storage() {
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let client = R2S3Client::new(&stub_env, "test-bucket")
            .await
            .expect("stub client");
        let audit_concrete = cas_audit_sink_from_d1_concrete(D1HttpClient::new(&stub_env))
            .expect("D1HttpClient constructs over the stub env (network call happens lazily)");
        let audit: Arc<dyn AuditSink> = audit_concrete.clone();
        let sli = Arc::new(InMemorySliObserver::new());
        let handler = std::sync::Arc::new(
            R2CasHandler::new(client, "iad", None, audit, sli).with_async_audit(audit_concrete),
        );

        let app = axum::Router::new()
            .route(
                "/x",
                axum::routing::get(move || {
                    let handler = std::sync::Arc::clone(&handler);
                    async move {
                        let req = corelink_handler_cas::CasListRequest::new(
                            "tenant-x",
                            "caller@tenant-x",
                            "tenant-x",
                            10,
                            None,
                            1,
                        );
                        let result = CasListHandler::list(&*handler, req);
                        // FAIL-CLOSED: a rejected D1 credential must surface
                        // as AuditFailed, never as a "success" that could
                        // have served R2 rows.
                        assert!(
                            matches!(result, Err(CasHandlerError::AuditFailed(_))),
                            "bad D1 creds must fail CLOSED as AuditFailed, got: {result:?}"
                        );
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .layer(axum::middleware::from_fn(
                crate::origin_timing::origin_timing_layer,
            ));

        let resp = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .uri("/x")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let header = resp
            .headers()
            .get("server-timing")
            .expect("origin_timing_layer must stamp Server-Timing")
            .to_str()
            .unwrap()
            .to_owned();
        let parsed = parse_server_timing(&header);
        assert!(
            parsed.contains_key("oaudit"),
            "durable audit failure must be attributed to Phase::Audit. Header: {header}"
        );
        assert!(
            !parsed.contains_key("ostore"),
            "R2 list must not dispatch after durable audit failure. Header: {header}"
        );
    }

    // ---------------------------------------------------------------
    // Integration round-trip test (requires live R2 creds)
    // ---------------------------------------------------------------

    /// PUT bytes → GET → bytes match.
    ///
    /// Gated behind `#[ignore]` so the CI green path does not require
    /// live R2 credentials. Run manually with:
    ///
    /// ```bash
    /// R2_S3_ACCESS_KEY_ID=<id> R2_S3_SECRET_ACCESS_KEY=<sec> \
    ///   R2_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com \
    ///   CLOUDFLARE_ACCOUNT_ID=<acc> CF_API_TOKEN=<tok> \
    ///   D1_DATABASE_ID=<id> \
    ///   R2_TEST_BUCKET=corelink-cas-staging \
    ///   cargo test -p corelink-server storage_r2_round_trip -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "requires live R2 credentials (R2_S3_ACCESS_KEY_ID etc.)"]
    async fn storage_r2_round_trip() {
        let env = StorageEnv::from_env().expect("all R2 env vars must be set to run this test");
        let bucket = std::env::var("R2_TEST_BUCKET").expect("R2_TEST_BUCKET must be set");
        assert!(
            bucket.ends_with("-staging"),
            "live R2 probes require a dedicated *-staging bucket"
        );
        let client = R2S3Client::new(&env, &bucket).await.expect("client");

        // Use a timestamped key so parallel test runs don't collide.
        let key = format!(
            "test/round-trip/{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let payload = b"corelink-wp-s1-storage-round-trip".to_vec();

        // Collect every operation before asserting so a failed read or
        // mismatch still reaches the exact-key cleanup below.
        let put = client.put(&key, payload.clone()).await;
        let got = if put.is_ok() {
            client.get(&key).await
        } else {
            Err("put failed; get not attempted".to_owned())
        };
        let missing = client.get("__no_such_key__").await;
        let cleanup = client.delete_if_present(&key).await;

        cleanup.expect("round-trip exact-key cleanup");
        put.expect("put");
        let got = got.expect("get").expect("present");
        assert_eq!(got, payload, "round-trip bytes must match");
        let missing = missing.expect("get missing key");
        assert!(missing.is_none(), "missing key must return None");
    }

    /// rt-nuclear #13 regression (live R2): the FIRST CAS write of a content hash
    /// returns `durable=true` (a real PUT); an idempotent re-write of the SAME
    /// content returns `durable=false` (HEAD hit → no re-PUT), so the
    /// `AccountingCasHandler` decorator rolls the reservation back and does NOT
    /// double-charge the bytes. Gated behind `#[ignore]` like `storage_r2_round_trip`.
    #[tokio::test]
    #[ignore = "requires live R2 credentials (R2_S3_ACCESS_KEY_ID etc.)"]
    async fn cas_idempotent_rewrite_reports_durable_false() {
        let env = StorageEnv::from_env().expect("all R2 env vars must be set to run this test");
        let bucket = std::env::var("R2_TEST_BUCKET").expect("R2_TEST_BUCKET must be set");
        assert!(
            bucket.ends_with("-staging"),
            "live R2 probes require a dedicated *-staging bucket"
        );
        let client = R2S3Client::new(&env, &bucket).await.expect("client");
        let audit = Arc::new(InMemoryAuditSink::new());
        let sli = Arc::new(InMemorySliObserver::new());
        let cleanup_client = R2S3Client::new(&env, &bucket)
            .await
            .expect("cleanup client");
        let handler = R2CasHandler::new(client, "iad", None, audit, sli);

        // Unique content per run so parallel runs / prior state don't collide.
        let payload = format!(
            "rt-nuclear-13-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
        .into_bytes();
        let tenant = "t-rt13";
        let claimed = Digest::compute(&payload).to_hex();

        let first = handler
            .write(CasWriteRequest::new(
                tenant,
                claimed.clone(),
                payload.clone(),
                "p",
                tenant,
                1,
            ));
        let second = if first.is_ok() {
            handler.write(CasWriteRequest::new(
                tenant,
                claimed.clone(),
                payload,
                "p",
                tenant,
                2,
            ))
        } else {
            Err(CasHandlerError::Internal(
                "first write failed; second not attempted".to_owned(),
            ))
        };
        let cleanup_key = R2S3Client::blob_key(
            "iad",
            &raw_padded_prefix(tenant),
            &claimed,
            DigestAlgo::Blake3,
        );
        cleanup_client
            .delete_if_present(&cleanup_key)
            .await
            .expect("idempotent rewrite exact-key cleanup");
        let first = first.expect("first write");
        assert!(
            first.durable,
            "first write of a fresh hash must be durable=true"
        );

        let second = second.expect("second write");
        assert!(
            !second.durable,
            "an idempotent re-write must report durable=false (HEAD hit → no re-PUT, no re-charge)"
        );
    }

    /// rt-nuclear #6/#10/#14 regression (live R2): `delete_if_present` returns the
    /// reclaimed size to the FIRST delete and `None` (release 0) to the SECOND —
    /// two deletes of the same key can never both credit the same bytes. Run with
    /// the same live-R2 env as `storage_r2_round_trip`.
    #[tokio::test]
    #[ignore = "requires live R2 credentials (R2_S3_ACCESS_KEY_ID etc.)"]
    async fn delete_if_present_credits_size_once_then_none() {
        let env = StorageEnv::from_env().expect("all R2 env vars must be set to run this test");
        let bucket = std::env::var("R2_TEST_BUCKET").expect("R2_TEST_BUCKET must be set");
        assert!(
            bucket.ends_with("-staging"),
            "live R2 probes require a dedicated *-staging bucket"
        );
        let client = R2S3Client::new(&env, &bucket).await.expect("client");

        let key = format!(
            "test/delete-once/{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let payload = b"rt-nuclear-6-10-14".to_vec();
        let size = payload.len() as u64;
        let put = client.put(&key, payload).await;

        // If a PUT times out after the provider committed the object, still
        // attempt exact-key cleanup before asserting the write result. On a
        // failed PUT, the delete-count assertions are skipped, but cleanup is
        // still observed and the original PUT failure remains a test failure.
        let (first, second) = if put.is_ok() {
            // Collect both delete results before asserting. If either request
            // fails, the final exact-key cleanup still runs.
            (
                client.delete_if_present(&key).await,
                client.delete_if_present(&key).await,
            )
        } else {
            (
                Err("PUT failed; delete-count assertions were skipped".to_owned()),
                Err("PUT failed; delete-count assertions were skipped".to_owned()),
            )
        };
        let cleanup = client.delete_if_present(&key).await;
        match (put, cleanup) {
            (Ok(()), Ok(_)) => {}
            (Ok(()), Err(cleanup_err)) => {
                panic!("exact-key cleanup failed: {cleanup_err}");
            }
            (Err(put_err), Ok(_)) => {
                panic!("PUT failed after exact-key cleanup attempt: {put_err}");
            }
            (Err(put_err), Err(cleanup_err)) => {
                panic!(
                    "PUT failed ({put_err}); exact-key cleanup also failed ({cleanup_err})"
                );
            }
        }
        let first = first.expect("first delete");
        assert_eq!(
            first,
            Some(size),
            "the first delete must credit the reclaimed size"
        );
        let second = second.expect("second delete");
        assert_eq!(
            second, None,
            "a second delete must credit 0 (no double-release)"
        );
    }

    // ---------------------------------------------------------------
    // Helper
    // ---------------------------------------------------------------

    /// Build an `R2CasHandler` backed by an unavailable (stub) S3
    /// client. Only the key-derivation and audit paths are exercised
    /// in these tests; any S3 I/O would fail.
    ///
    /// This is an `async fn` so it can be called from within a
    /// `#[tokio::test]` context without nested-runtime conflicts.
    async fn make_test_handler(region: &str) -> R2CasHandler {
        // Build a stub env pointing at localhost (won't connect).
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };

        let client = R2S3Client::new(&stub_env, "test-bucket")
            .await
            .expect("stub client");

        let audit = Arc::new(InMemoryAuditSink::new());
        let sli = Arc::new(InMemorySliObserver::new());
        R2CasHandler::new(client, region, None, audit, sli)
    }

    /// The latency SLI must observe a REAL window, not a literal zero.
    ///
    /// B-057 regression pin. `emit_sli` used to pass `0` for both the
    /// availability and the latency SLI at every CAS/AC call site, so
    /// `LatencyCasGetP99` was a stream of zeroes — not a loose
    /// measurement, an absent one. Reverting `emit_sli` to the old
    /// `SliObservation::new(lat, is_error, 0)` reds this test.
    ///
    /// Driven through the cross-tenant denial arm of `read()` on
    /// purpose: it emits and returns WITHOUT touching R2, so the pin
    /// needs no credentials and cannot flake on the network.
    #[tokio::test]
    async fn cas_read_emits_a_nonzero_latency_sli() {
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let client = R2S3Client::new(&stub_env, "test-bucket")
            .await
            .expect("stub client");
        let audit = Arc::new(InMemoryAuditSink::new());
        let sli = Arc::new(InMemorySliObserver::new());
        let observer: Arc<dyn SliObserver> = Arc::clone(&sli) as Arc<dyn SliObserver>;
        let handler = R2CasHandler::new(client, "iad", None, audit, observer);

        let req = CasReadRequest::new("tenant-a", "a".repeat(64), "p", "tenant-b", 1);
        let out = tokio::task::spawn_blocking(move || handler.read(req))
            .await
            .expect("join");
        assert!(out.is_err(), "cross-tenant read must be refused");

        let obs = sli.snapshot().expect("sli");
        let lat: Vec<_> = obs
            .iter()
            .filter(|o| o.sli == corelink_handler_cas::observer::Sli::LatencyCasGetP99)
            .collect();
        assert_eq!(lat.len(), 1, "exactly one latency observation: {obs:?}");
        assert!(
            lat[0].latency_us > 0,
            "the latency SLI must carry the measured window, got {} us",
            lat[0].latency_us
        );
        let avail: Vec<_> = obs
            .iter()
            .filter(|o| o.sli == corelink_handler_cas::observer::Sli::AvailCasGet)
            .collect();
        assert_eq!(avail.len(), 1, "exactly one availability observation");
        assert!(avail[0].is_error, "a refused read is an error observation");
    }

    // ---------------------------------------------------------------
    // `exists_batch` — the findMissingBlobs seam
    // ---------------------------------------------------------------

    /// Without the async audit seam wired, the handler advertises NO batch
    /// capability, so `find_missing` keeps the unchanged per-digest
    /// `exists()` loop. This is the regression pin for "the serial fallback
    /// stayed byte-identical".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exists_batch_is_absent_without_the_async_audit_seam() {
        let handler = make_test_handler("iad").await;
        let req = CasReadRequest::new(
            "tenant-x",
            "deadbeef00000000000000000000000000000000000000000000000000000001",
            "caller@tenant-x",
            "tenant-x",
            1,
        );
        assert!(
            CasReadHandler::exists_batch(&handler, &[req]).is_none(),
            "no durable async sink -> no batch capability -> serial fallback"
        );
    }

    /// Cross-tenant denial is evaluated STRICTLY FIRST — before the audit
    /// batch or any R2 probe is dispatched — and still emits its own
    /// `ReadDenied` row through the sync sink.
    ///
    /// The proof that nothing was dispatched is that this test is fully
    /// hermetic: the S3 client points at `localhost:1` and the D1 sink
    /// carries stub credentials, so ANY dispatch would have to fail against
    /// an unreachable endpoint rather than return a clean denial.
    ///
    /// It deliberately wires an in-memory `audit` alongside a D1
    /// `audit_async` — a combination `with_async_audit`'s doc forbids in
    /// production (the two must be the same sink) — purely so the denial
    /// row can be READ BACK without a network call. The denial path only
    /// ever touches `audit`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exists_batch_denies_cross_tenant_before_dispatching_anything() {
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let client = R2S3Client::new(&stub_env, "test-bucket")
            .await
            .expect("stub client");
        let recorder = Arc::new(InMemoryAuditSink::new());
        let audit: Arc<dyn AuditSink> = recorder.clone();
        let audit_concrete = cas_audit_sink_from_d1_concrete(D1HttpClient::new(&stub_env))
            .expect("D1 client constructs (the network call happens lazily)");
        let sli = Arc::new(InMemorySliObserver::new());
        let handler =
            R2CasHandler::new(client, "iad", None, audit, sli).with_async_audit(audit_concrete);

        // A legitimate digest FIRST, the poisoned one second: the scan must
        // still refuse the whole batch before the good one touches R2.
        let ok = CasReadRequest::new(
            "victim",
            "deadbeef00000000000000000000000000000000000000000000000000000001",
            "attacker",
            "victim",
            1,
        );
        let poisoned = CasReadRequest::new(
            "victim",
            "deadbeef00000000000000000000000000000000000000000000000000000002",
            "attacker",
            "attacker-tenant",
            1,
        );

        let result = CasReadHandler::exists_batch(&handler, &[ok, poisoned])
            .expect("batch capability is wired");
        match result {
            Err(CasHandlerError::CrossTenantDenied {
                caller,
                requested_tenant,
            }) => {
                assert_eq!(caller, "attacker-tenant");
                assert_eq!(requested_tenant, "victim");
            }
            other => panic!("expected CrossTenantDenied, got {other:?}"),
        }

        let rows = recorder.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1, "exactly one denial row: {rows:?}");
        assert_eq!(rows[0].kind, AuditEventKind::ReadDenied);
        assert_eq!(rows[0].tenant, "victim");
    }
