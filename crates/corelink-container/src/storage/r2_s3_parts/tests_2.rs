    /// The production batch shape: when the durable-audit D1 write fails
    /// (reachable-but-wrong credentials), `exists_batch` returns
    /// `AuditFailed` before any probe dispatch, and the audit phase is
    /// present while storage is absent. Mirrors
    /// `r2_cas_list_durable_audit_failure_precedes_storage`.
    ///
    /// `#[ignore]` for the same reason as that test: needs outbound
    /// reachability to `api.cloudflare.com` (a 401 still proves the audit
    /// gate ran). Run manually with:
    ///
    /// ```bash
    /// cargo test -p corelink-server r2_cas_exists_batch_fails_closed_on_bad_audit_creds -- --ignored
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires outbound network reachability to api.cloudflare.com"]
    async fn r2_cas_exists_batch_fails_closed_on_bad_audit_creds() {
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
            .expect("D1HttpClient constructs over the stub env");
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
                        let reqs: Vec<CasReadRequest> = (0..4u8)
                            .map(|i| {
                                CasReadRequest::new(
                                    "tenant-x",
                                    format!("{i:064x}"),
                                    "caller@tenant-x",
                                    "tenant-x",
                                    1,
                                )
                            })
                            .collect();
                        let result = CasReadHandler::exists_batch(&*handler, &reqs)
                            .expect("batch capability is wired");
                        assert!(
                            matches!(result, Err(CasHandlerError::AuditFailed(_))),
                            "a rejected D1 credential must surface as AuditFailed, \
                             never as probe results: {result:?}"
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
            "the durable batch audit must be attributed to oaudit. Header: {header}"
        );
        assert!(
            !parsed.contains_key("ostore"),
            "ostore must be absent when audit fails before probes. Header: {header}"
        );
    }

    /// A non-zero fake 32-byte TDK for tests that must exercise the
    /// PRODUCTION always-HMAC prefix path (`Some(tdk)` arm).
    fn fake_tdk() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([0x5au8; 32])
    }

    /// Build an `R2CasHandler` with a real (fake) TDK over a stub S3
    /// client — exercises the production `Some(tdk)` key-derivation arm.
    async fn make_test_handler_with_tdk(region: &str) -> R2CasHandler {
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
        R2CasHandler::new(client, region, Some(fake_tdk()), audit, sli)
    }

    /// Build an `R2AcHandler` over a stub S3 client (no TDK → test
    /// raw-pad prefix; only the divergent-body/region logic is
    /// exercised here, any S3 I/O fails against the stub).
    async fn make_test_ac_handler(region: &str) -> R2AcHandler {
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
        let audit = Arc::new(corelink_handler_ac::InMemoryAuditSink::new());
        let sli = Arc::new(corelink_handler_ac::InMemorySliObserver::new());
        R2AcHandler::new(client, region, None, audit, sli)
    }

    // ---------------------------------------------------------------
    // F1/F2 — production path ALWAYS HMACs the full tenant id
    // ---------------------------------------------------------------

    /// With a TDK configured (the production posture), a canonical UUID
    /// tenant resolves to the secret-keyed `derive_prefix` HMAC — NOT
    /// the public raw-padded prefix of the tenant string. This is the
    /// regression pin for F1/F2: the predictable public prefix must
    /// never appear on the TDK path for a UUID tenant.
    #[tokio::test]
    async fn r2_cas_tdk_path_uses_hmac_prefix_not_raw_tenant() {
        let handler = make_test_handler_with_tdk("iad").await;
        // A canonical UUIDv7-shaped tenant id.
        let tenant = "0190abcd-1234-75ab-8def-0123456789ab";
        let key = handler
            .r2_key(tenant, &"d".repeat(64), DigestAlgo::Blake3)
            .unwrap();
        let parts: Vec<&str> = key.split('/').collect();
        assert_eq!(parts.len(), 3, "key: {key}");
        let prefix = parts[1];
        assert_eq!(prefix.len(), 16, "prefix must be 16 chars: {key}");
        // The HMAC prefix must NOT be the predictable public prefix of
        // the tenant string (the F1 raw-padded fallback).
        let raw_public = &tenant[..16];
        assert_ne!(
            prefix, raw_public,
            "production prefix leaked the public tenant-id prefix (F1/F2)"
        );
        // And it must equal the canonical secret-keyed derivation.
        let expected = derive_prefix(
            &TenantDerivationKey::from_bytes(fake_tdk()),
            Uuid::try_parse(tenant).unwrap(),
        )
        .to_string();
        assert_eq!(prefix, expected, "prefix must be derive_prefix(tdk, uuid)");
    }

    // ---------------------------------------------------------------
    // F2 — production prefix derivation FAILS CLOSED for a non-derivable
    // tenant (never an empty `<region>//<digest>` SHARED keyspace).
    // ---------------------------------------------------------------

    /// The production-strict derivation (`derive_tenant_prefix_strict`,
    /// the authority the live `tenant_prefix` path delegates to) MUST
    /// refuse a non-UUID tenant and a missing TDK — there is NO public/
    /// empty fallback. This is the regression pin for finding #2/#8: a
    /// non-derivable tenant on the prod path errors out instead of
    /// keying under `<region>//<digest>` (a SHARED, cross-tenant
    /// keyspace).
    #[test]
    fn prod_strict_prefix_fails_closed_for_non_derivable_tenant() {
        let tdk = TenantDerivationKey::from_bytes(fake_tdk());

        // Non-UUID tenant under a present TDK → Err (no raw-padded
        // fallback on the prod path).
        let err = derive_tenant_prefix_strict(Some(&tdk), "tenant-abc")
            .expect_err("non-UUID tenant must fail closed on the prod path");
        assert!(
            err.contains("INV-TENANT-ISOLATION"),
            "error must cite the isolation invariant: {err}"
        );

        // Missing TDK → Err (the production builders fail closed before
        // this, but the derivation itself must not produce a prefix).
        assert!(
            derive_tenant_prefix_strict(None, "0190abcd-1234-75ab-8def-0123456789ab").is_err(),
            "absent TDK must fail closed"
        );

        // Sanity: a canonical UUID under a present TDK IS derivable and
        // is exactly the secret-keyed prefix (never empty).
        let ok = derive_tenant_prefix_strict(Some(&tdk), "0190abcd-1234-75ab-8def-0123456789ab")
            .expect("a canonical UUID tenant must derive a prefix");
        assert_eq!(ok.len(), 16, "derived prefix must be 16 chars, got {ok:?}");
        assert!(!ok.is_empty(), "derived prefix must never be empty");
    }

    #[test]
    fn public_namespace_resolves_a_stable_isolated_derived_prefix() {
        // The brew-502 root cause: `_public` (the shared cross-tenant dedup
        // namespace) is not a UUID, so the prod path failed CLOSED on it. It MUST
        // instead resolve a stable, secret-keyed prefix — public content is shared
        // by design, but every caller must dedup the same blob to the same key.
        let tdk = TenantDerivationKey::from_bytes(fake_tdk());
        let p = tenant_prefix(Some(&tdk), crate::adapter_cache::PUBLIC_NAMESPACE)
            .expect("_public must resolve a prefix (not fail closed)");
        assert_eq!(p.len(), 16, "prefix must be 16 chars: {p:?}");
        // Secret-keyed reserved-sentinel HMAC (NOT a predictable raw prefix).
        assert_eq!(p, derive_prefix(&tdk, PUBLIC_NAMESPACE_UUID).to_string());
        // Deterministic across calls (so cross-tenant dedup actually dedups).
        assert_eq!(
            p,
            tenant_prefix(Some(&tdk), crate::adapter_cache::PUBLIC_NAMESPACE).unwrap()
        );
        // Reserved: it never collides with a real (UUID) tenant's prefix.
        let real = tenant_prefix(Some(&tdk), "0190abcd-1234-75ab-8def-0123456789ab").unwrap();
        assert_ne!(
            p, real,
            "_public must not collide with a real tenant prefix"
        );
    }

    // ---------------------------------------------------------------
    // F7 — CAS storage is residency-aware: keyed by the handler's
    // region, never a process-global. A regional handler MUST prefix
    // its keys with that region.
    // ---------------------------------------------------------------

    /// Each regional CAS handler keys objects under its OWN region — an
    /// `lhr` handler must never write into the `iad` key space. This is
    /// the invariant that makes per-env `R2_CAS_REGION` (the frozen
    /// contract) load-bearing rather than cosmetic. If a regional env
    /// fails to thread its region through, this fails.
    #[tokio::test]
    async fn r2_cas_keys_are_residency_scoped_per_region() {
        for region in ["iad", "lhr", "sam", "nrt", "syd"] {
            let handler = make_test_handler_with_tdk(region).await;
            let key = handler
                .r2_key(
                    "0190abcd-1234-75ab-8def-0123456789ab",
                    &"a".repeat(64),
                    DigestAlgo::Blake3,
                )
                .unwrap();
            assert!(
                key.starts_with(&format!("{region}/")),
                "CAS key for region {region} must be region-scoped (residency): {key}"
            );
        }
        // A non-iad region must NOT collapse to the iad default.
        let lhr = make_test_handler_with_tdk("lhr").await;
        let key = lhr
            .r2_key(
                "0190abcd-1234-75ab-8def-0123456789ab",
                &"a".repeat(64),
                DigestAlgo::Blake3,
            )
            .unwrap();
        assert!(
            !key.starts_with("iad/"),
            "EU (lhr) CAS write fell back to the US (iad) key space: {key}"
        );
    }

    // ---------------------------------------------------------------
    // F5 — AC update divergent-body invariant (no silent overwrite)
    // ---------------------------------------------------------------

    #[test]
    fn ac_storage_key_rejects_noncanonical_digest() {
        assert!(is_canonical_ac_digest(&"a".repeat(64)));
        assert!(!is_canonical_ac_digest(&"A".repeat(64)));
        assert!(!is_canonical_ac_digest(&"a".repeat(63)));
        assert!(!is_canonical_ac_digest("../poison"));
    }

    #[tokio::test]
    async fn ac_generation_key_validates_components_and_preserves_namespace() {
        let handler = make_test_ac_handler("iad").await;
        let digest = "a".repeat(64);
        let key = handler
            .generation_r2_key("tenant-abc", 7, "allocation-1", &digest)
            .expect("valid generation key");
        assert!(key.ends_with(&format!("generation/7/allocation-1/{digest}")));
        assert!(handler
            .generation_r2_key("tenant-abc", 7, "../escape", &digest)
            .is_err());
        assert!(handler
            .generation_r2_key("tenant-abc", 7, "allocation-1", "not-a-digest")
            .is_err());
    }

    /// On an AMBIGUOUS pre-PUT GET (the stub endpoint is unreachable, so
    /// GET errors), `R2AcHandler::update` MUST fail closed with
    /// `Internal` and NEVER fall through to a blind PUT that could
    /// overwrite a proven AC result. This pins the F5 fail-closed branch
    /// (a proven result is never overwritten on unknown prior state).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn r2_ac_update_fails_closed_on_ambiguous_get() {
        use corelink_handler_ac::{AcHandlerError, AcUpdateHandler, AcUpdateRequest};
        let handler = make_test_ac_handler("iad").await;
        let req = AcUpdateRequest::new("t1", "d".repeat(64), b"payload".to_vec(), "p@t1", "t1", 1);
        let err = handler
            .update(req)
            .expect_err("ambiguous GET against stub must fail closed");
        assert!(
            matches!(err, AcHandlerError::Internal(_)),
            "update must fail closed (Internal) on an ambiguous pre-PUT GET, \
             never blind-overwrite — got {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // BYOK Wave 3a — handler-level encrypt/decrypt hooks + Option-gating
    // + fail-closed (the data-plane integration, minus the R2 I/O which
    // is unchanged plumbing). These exercise `R2CasHandler`'s own
    // `byok_encrypt_for_write` / `byok_decrypt_for_read` /
    // `resolve_byok_ctx`; the convergent crypto + caches themselves are
    // covered in `storage::byok_cas::tests`.
    // ---------------------------------------------------------------

    use crate::customer_d1::{
        ByokConfigError, ByokCryptoMode, ByokMode, ByokState, TenantByokConfig,
    };
    use crate::storage::byok_cas::{
        ByokConfigCache, ByokConfigSource, ByokEnvelopeRow, ByokEnvelopeStore, ByokSecretSource,
        ModeBEncryptor, TcsResolver, WrappedTcsRow,
    };
    use corelink_byok::{
        BYOKError, Dek, KmsAccessStatus, KmsKeyId, KmsProvider, KmsProviderKind, WrappedDek,
    };
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    /// Hermetic in-memory `byok_envelope` store for the Mode-B handler tests.
    /// `fail_delete` injects a reclaim (`delete_envelope`) failure for the Wave-4a
    /// safe-fail test.
    #[derive(Debug, Default)]
    struct MemEnvStore {
        inner: StdMutex<StdHashMap<(String, String), ByokEnvelopeRow>>,
        fail_delete: bool,
    }
    impl MemEnvStore {
        fn failing_delete() -> Self {
            Self {
                inner: StdMutex::default(),
                fail_delete: true,
            }
        }
        fn len(&self) -> usize {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        }
        fn contains(&self, tenant: &str, blob_key: &str) -> bool {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&(tenant.to_owned(), blob_key.to_owned()))
        }
        fn wrapped_dek(&self, tenant: &str, blob_key: &str) -> Option<Vec<u8>> {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&(tenant.to_owned(), blob_key.to_owned()))
                .map(|r| r.wrapped_dek.clone())
        }
    }
    #[async_trait::async_trait]
    impl ByokEnvelopeStore for MemEnvStore {
        async fn get_envelope(
            &self,
            tenant: &str,
            blob_key: &str,
        ) -> Result<Option<ByokEnvelopeRow>, String> {
            Ok(self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&(tenant.to_owned(), blob_key.to_owned()))
                .cloned())
        }
        async fn put_envelope_if_absent(
            &self,
            tenant: &str,
            blob_key: &str,
            row: &ByokEnvelopeRow,
            _created_at_ms: i64,
        ) -> Result<(), String> {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry((tenant.to_owned(), blob_key.to_owned()))
                .or_insert_with(|| row.clone());
            Ok(())
        }
        async fn delete_envelope(&self, tenant: &str, blob_key: &str) -> Result<(), String> {
            if self.fail_delete {
                return Err("mem env store: injected delete failure".to_owned());
            }
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&(tenant.to_owned(), blob_key.to_owned()));
            Ok(())
        }

        async fn record_reconciliation_intent(
            &self,
            _tenant: &str,
            _digest: &str,
            _physical_r2_key: &str,
            _reason: &str,
            _created_at_ms: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    const BYOK_TENANT: &str = "byok-tenant-x";
