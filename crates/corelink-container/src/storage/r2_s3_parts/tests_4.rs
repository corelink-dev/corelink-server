    /// Use the production no-provider attachment and successful R2 seam so a
    /// missing config check would return a successful listing, not an I/O error.
    async fn recorded_unarmed_list_handlers(
        tenant: &'static str,
        mut config: Result<Option<TenantByokConfig>, ByokConfigError>,
    ) -> (R2CasHandler, R2AcHandler, Arc<StorageDispatchRecorder>) {
        if let Ok(Some(cfg)) = config.as_mut() {
            cfg.tenant_id = tenant.to_owned();
        }
        let byok = crate::storage::byok_cas::DataPlaneByok::unarmed(Arc::new(PerTenantCfgSrc(
            std::collections::HashMap::from([(tenant, config)]),
        )));
        let recorder = StorageDispatchRecorder::successful(Vec::new());
        let cas = crate::routes::cas::attach_byok_to_r2_handler(
            R2CasHandler::new(
                make_recorded_client(Arc::clone(&recorder)).await,
                "iad",
                None,
                Arc::new(GatedAuditSink {
                    recorder: Arc::clone(&recorder),
                    fail: false,
                }),
                Arc::new(InMemorySliObserver::new()),
            ),
            Some(&byok),
        );
        let ac = crate::routes::ac::attach_byok_to_r2_handler(
            R2AcHandler::new(
                make_recorded_client(Arc::clone(&recorder)).await,
                "iad",
                None,
                Arc::new(GatedAuditSink {
                    recorder: Arc::clone(&recorder),
                    fail: false,
                }),
                Arc::new(corelink_handler_ac::InMemorySliObserver::new()),
            ),
            Some(&byok),
        );
        (cas, ac, recorder)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unarmed_lists_refuse_engaged_and_unreadable_config_before_r2() {
        let mut cases = Vec::new();
        for mode in [ByokCryptoMode::Convergent, ByokCryptoMode::Random] {
            for state in [
                ByokState::Active,
                ByokState::Partial,
                ByokState::Pending,
                ByokState::Shredded,
            ] {
                cases.push((Ok(Some(byok_cfg(mode, state))), UNARMED_REFUSAL));
            }
        }
        cases.push((
            Err(ByokConfigError::Parse("state missing".to_owned())),
            "byok config read",
        ));
        cases.push((
            Err(ByokConfigError::Transport(
                "snapshot unavailable".to_owned(),
            )),
            "byok config read",
        ));

        for (config, reason) in cases {
            for cursor in [None, Some("opaque-next-page".to_owned())] {
                let (cas, ac, recorder) =
                    recorded_unarmed_list_handlers("tenant-a", config.clone()).await;
                let err = CasListHandler::list(
                    &cas,
                    corelink_handler_cas::CasListRequest::new(
                        "tenant-a",
                        "p",
                        "tenant-a",
                        10,
                        cursor.clone(),
                        1,
                    ),
                )
                .expect_err("unarmed CAS list must refuse before R2");
                assert!(matches!(err, CasHandlerError::Internal(ref why) if why.contains(reason)));
                assert_eq!(
                    recorder.calls.load(Ordering::SeqCst),
                    0,
                    "CAS dispatched R2"
                );

                let err = corelink_handler_ac::AcListHandler::list(
                    &ac,
                    corelink_handler_ac::AcListRequest::new(
                        "tenant-a", "p", "tenant-a", 10, cursor, 1,
                    ),
                )
                .expect_err("unarmed AC list must refuse before R2");
                assert!(
                    matches!(err, corelink_handler_ac::AcHandlerError::Internal(ref why) if why.contains(reason))
                );
                assert_eq!(recorder.calls.load(Ordering::SeqCst), 0, "AC dispatched R2");
                assert!(recorder.audit_committed.load(Ordering::SeqCst));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unarmed_lists_allow_missing_inactive_and_public_config() {
        for (tenant, config) in [
            ("tenant-a", Ok(None)),
            (
                "tenant-a",
                Ok(Some(byok_cfg(
                    ByokCryptoMode::Convergent,
                    ByokState::Inactive,
                ))),
            ),
            (
                crate::adapter_cache::PUBLIC_NAMESPACE,
                Err(ByokConfigError::Transport(
                    "snapshot unavailable".to_owned(),
                )),
            ),
        ] {
            let (cas, ac, recorder) = recorded_unarmed_list_handlers(tenant, config).await;
            let cas_response = CasListHandler::list(
                &cas,
                corelink_handler_cas::CasListRequest::new(tenant, "p", tenant, 10, None, 1),
            )
            .expect("permitted CAS listing");
            assert!(cas_response.blobs.is_empty());
            assert_eq!(cas_response.next_cursor, None);
            let ac_response = corelink_handler_ac::AcListHandler::list(
                &ac,
                corelink_handler_ac::AcListRequest::new(tenant, "p", tenant, 10, None, 1),
            )
            .expect("permitted AC listing");
            assert!(ac_response.refs.is_empty());
            assert_eq!(ac_response.next_cursor, None);
            assert_eq!(recorder.calls.load(Ordering::SeqCst), 2);
            assert!(!recorder.premature.load(Ordering::SeqCst));
        }
    }

    #[derive(Debug)]
    struct GatedAuditSink {
        recorder: Arc<StorageDispatchRecorder>,
        fail: bool,
    }

    impl AuditSink for GatedAuditSink {
        fn emit(&self, _event: AuditEvent) -> Result<(), String> {
            if self.fail {
                return Err("audit gate closed".to_owned());
            }
            self.recorder
                .audit_committed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    impl corelink_handler_ac::AuditSink for GatedAuditSink {
        fn emit(&self, _event: corelink_handler_ac::AuditEvent) -> Result<(), String> {
            if self.fail {
                return Err("audit gate closed".to_owned());
            }
            self.recorder
                .audit_committed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    async fn make_recorded_client(recorder: Arc<StorageDispatchRecorder>) -> R2S3Client {
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        R2S3Client::new(&stub_env, "test-bucket")
            .await
            .expect("stub client")
            .with_test_storage_recorder(recorder)
    }

    /// Native CAS/AC reads and lists must not dispatch storage until the
    /// durable attempted audit succeeds. The recorder sits immediately before
    /// each AWS SDK call, making the zero-call assertion independent of network
    /// behavior and the positive case deterministic even with a stub endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attempted_audit_is_a_hard_storage_dispatch_gate() {
        let cas_digest = "a".repeat(64);

        let storage_body = b"gated storage success".to_vec();
        let storage_digest = Digest::compute(&storage_body).to_hex();
        let recorder = StorageDispatchRecorder::new();
        let audit: Arc<dyn AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: true,
        });
        let cas = R2CasHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(InMemorySliObserver::new()),
        );
        let err = CasReadHandler::read(
            &cas,
            CasReadRequest::new("tenant-a", cas_digest.clone(), "p", "tenant-a", 1),
        )
        .expect_err("failed attempted audit");
        assert!(matches!(err, CasHandlerError::AuditFailed(_)));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);

        let recorder = StorageDispatchRecorder::new();
        let audit: Arc<dyn corelink_handler_ac::AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: true,
        });
        let ac = R2AcHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(corelink_handler_ac::InMemorySliObserver::new()),
        );
        let err = corelink_handler_ac::AcLookupHandler::lookup(
            &ac,
            corelink_handler_ac::AcLookupRequest::new(
                "tenant-a", "b".repeat(64), "p", "tenant-a", 1,
            ),
        )
        .expect_err("failed attempted audit");
        assert!(matches!(err, corelink_handler_ac::AcHandlerError::AuditFailed(_)));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);

        let recorder = StorageDispatchRecorder::new();
        let audit: Arc<dyn AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: true,
        });
        let cas = R2CasHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(InMemorySliObserver::new()),
        );
        let err = CasListHandler::list(
            &cas,
            corelink_handler_cas::CasListRequest::new(
                "tenant-a",
                "p",
                "tenant-a",
                10,
                None,
                1,
            ),
        )
        .expect_err("failed attempted audit");
        assert!(matches!(err, CasHandlerError::AuditFailed(_)));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);

        let recorder = StorageDispatchRecorder::new();
        let audit: Arc<dyn corelink_handler_ac::AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: true,
        });
        let ac = R2AcHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(corelink_handler_ac::InMemorySliObserver::new()),
        );
        let err = corelink_handler_ac::AcListHandler::list(
            &ac,
            corelink_handler_ac::AcListRequest::new("tenant-a", "p", "tenant-a", 10, None, 1),
        )
        .expect_err("failed attempted audit");
        assert!(matches!(err, corelink_handler_ac::AcHandlerError::AuditFailed(_)));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);

        let recorder = StorageDispatchRecorder::successful(storage_body.clone());
        let audit: Arc<dyn AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: false,
        });
        let cas = R2CasHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(InMemorySliObserver::new()),
        );
        let response = CasReadHandler::read(
            &cas,
            CasReadRequest::new("tenant-a", storage_digest, "p", "tenant-a", 1),
        )
        .expect("successful attempted audit and storage");
        assert_eq!(response.bytes, storage_body);
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);
        assert!(!recorder.premature.load(Ordering::SeqCst));
    }

    /// Batch-exists must await its durable audit before creating any HEAD
    /// probe. The loopback D1 endpoint is intentionally not served, making
    /// the audit failure deterministic while the storage recorder proves that
    /// no backend dispatch occurred.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn batch_audit_failure_precedes_all_storage_probes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback port");
        let port = listener.local_addr().expect("loopback address").port();
        drop(listener);
        let stub_env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let d1 = D1HttpClient::new_for_loopback_test(
            &stub_env,
            &format!("http://127.0.0.1:{port}"),
        )
        .expect("loopback D1 client");
        let audit_concrete = Arc::new(
            crate::storage::d1_audit_sink::D1AuditOutboxSink::new(
                Arc::new(d1),
                "corelink/cas",
            ),
        );
        let recorder = StorageDispatchRecorder::new();
        let client = make_recorded_client(Arc::clone(&recorder)).await;
        let audit: Arc<dyn AuditSink> = audit_concrete.clone();
        let handler = R2CasHandler::new(
            client,
            "iad",
            None,
            audit,
            Arc::new(InMemorySliObserver::new()),
        )
        .with_async_audit(audit_concrete);
        let reqs: Vec<_> = (0..3u8)
            .map(|i| {
                CasReadRequest::new(
                    "tenant-a",
                    format!("{i:064x}"),
                    "p",
                    "tenant-a",
                    1,
                )
            })
            .collect();

        let result = CasReadHandler::exists_batch(&handler, &reqs)
            .expect("durable batch audit seam is wired");
        assert!(matches!(result, Err(CasHandlerError::AuditFailed(_))));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);
        assert!(!recorder.premature.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_tenant_reads_are_denied_before_storage_dispatch() {
        let recorder = StorageDispatchRecorder::new();
        let audit: Arc<dyn AuditSink> = Arc::new(GatedAuditSink {
            recorder: Arc::clone(&recorder),
            fail: false,
        });
        let cas = R2CasHandler::new(
            make_recorded_client(Arc::clone(&recorder)).await,
            "iad",
            None,
            audit,
            Arc::new(InMemorySliObserver::new()),
        );
        let err = CasReadHandler::read(
            &cas,
            CasReadRequest::new("victim", "c".repeat(64), "attacker", "attacker", 1),
        )
        .expect_err("cross-tenant request");
        assert!(matches!(err, CasHandlerError::CrossTenantDenied { .. }));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 0);
    }
