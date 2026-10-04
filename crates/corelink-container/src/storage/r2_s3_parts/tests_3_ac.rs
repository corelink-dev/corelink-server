use crate::storage::byok_cas::BYOK_CLB1_OVERHEAD;

    // ---------------------------------------------------------------
    // BYOK Wave 3b — AC handler encrypt/decrypt hooks (surface="ac"),
    // Option-gating, fail-closed, + surface separation from CAS (H1).
    // Exercise `R2AcHandler::byok_encrypt_for_update` /
    // `byok_decrypt_for_lookup` / `resolve_byok_ctx`; the crypto itself
    // is covered in `storage::byok_cas::tests`.
    // ---------------------------------------------------------------

    /// Wire an `R2AcHandler` with BYOK collaborators (mirrors `handler_with_byok`).
    async fn ac_handler_with_byok(cfg: Option<TenantByokConfig>, kms_fail: bool) -> R2AcHandler {
        let base = make_test_ac_handler("iad").await;
        let cache = Arc::new(ByokConfigCache::new(Arc::new(CfgSrc(cfg)), 60));
        let resolver = Arc::new(
            TcsResolver::new(Arc::new(SecSrc), Arc::new(Kms { fail: kms_fail }), 300).unwrap(),
        );
        base.with_byok(cache, resolver)
    }

    /// Wire an `R2AcHandler` with the Mode-B encryptor over a shared envelope
    /// store (mirrors `handler_with_byok_random_store`).
    async fn ac_handler_with_byok_random_store(
        cfg: Option<TenantByokConfig>,
        store: Arc<MemEnvStore>,
    ) -> R2AcHandler {
        let base = make_test_ac_handler("iad").await;
        let cache = Arc::new(ByokConfigCache::new(Arc::new(CfgSrc(cfg)), 60));
        let resolver = Arc::new(
            TcsResolver::new(Arc::new(SecSrc), Arc::new(Kms { fail: false }), 300).unwrap(),
        );
        let kms: Arc<dyn KmsProvider> = Arc::new(Kms { fail: false });
        let store_dyn: Arc<dyn ByokEnvelopeStore> = store;
        let mode_b = Arc::new(ModeBEncryptor::new(kms, store_dyn, 300).unwrap());
        base.with_byok(cache, resolver).with_byok_random(mode_b)
    }

    fn ac_update_req(tenant: &str, payload: Vec<u8>) -> corelink_handler_ac::AcUpdateRequest {
        corelink_handler_ac::AcUpdateRequest::new(tenant, "a".repeat(64), payload, "p", tenant, 1)
    }

    /// Per-tenant config answers for the unarmed attachment test.
    #[derive(Debug)]
    struct PerTenantCfgSrc(
        std::collections::HashMap<&'static str, Result<Option<TenantByokConfig>, ByokConfigError>>,
    );

    #[async_trait::async_trait]
    impl ByokConfigSource for PerTenantCfgSrc {
        async fn get_byok_config(
            &self,
            tenant: &str,
        ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
            self.0.get(tenant).cloned().unwrap_or(Ok(None))
        }
    }

    /// #1648: the shipped no-provider image attaches an UNARMED data plane.
    /// Through the exact production attachment helpers, CAS and AC must refuse
    /// every engaged tenant on write and read (never store or serve plaintext
    /// for it) and keep every other tenant on the unchanged plaintext path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn router_factory_unarmed_attachment_refuses_engaged_tenants_only() {
        let mut cfgs = std::collections::HashMap::new();
        cfgs.insert(
            BYOK_TENANT,
            Ok(Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active))),
        );
        cfgs.insert(
            "tenant-random-active",
            Ok(Some(byok_cfg(ByokCryptoMode::Random, ByokState::Active))),
        );
        cfgs.insert(
            "tenant-pending",
            Ok(Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Pending))),
        );
        cfgs.insert(
            "tenant-shredded",
            Ok(Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Shredded))),
        );
        cfgs.insert(
            "tenant-unreadable",
            Err(ByokConfigError::Parse("state missing".to_owned())),
        );
        cfgs.insert(
            "tenant-inactive",
            Ok(Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Inactive))),
        );
        let byok = crate::storage::byok_cas::DataPlaneByok::unarmed(Arc::new(PerTenantCfgSrc(cfgs)));
        assert!(!byok.is_armed());
        let cas = crate::routes::cas::attach_byok_to_r2_handler(
            make_test_handler_with_tdk("iad").await,
            Some(&byok),
        );
        let ac = crate::routes::ac::attach_byok_to_r2_handler(
            make_test_ac_handler("iad").await,
            Some(&byok),
        );
        assert!(Arc::ptr_eq(
            &byok.config_cache(),
            cas.byok_config_cache_for_test().expect("CAS config view")
        ));
        assert!(Arc::ptr_eq(
            &byok.config_cache(),
            ac.byok_config_cache_for_test().expect("AC config view")
        ));

        for tenant in [
            BYOK_TENANT,
            "tenant-random-active",
            "tenant-pending",
            "tenant-shredded",
            "tenant-unreadable",
        ] {
            let write = write_req(tenant, b"cas payload".to_vec());
            assert!(
                cas.byok_encrypt_for_write(&write).await.is_err(),
                "{tenant}: CAS write must fail closed"
            );
            let read = CasReadRequest::new(tenant, &write.claimed_hash, "p", tenant, 1);
            assert!(
                cas.byok_decrypt_for_read(&read, b"CLB1stored".to_vec()).await.is_err(),
                "{tenant}: CAS read must fail closed, never serve stored bytes"
            );
            let update = ac_update_req(tenant, b"ac payload".to_vec());
            assert!(
                ac.byok_encrypt_for_update(&update).await.is_err(),
                "{tenant}: AC update must fail closed"
            );
            assert!(
                ac.byok_decrypt_for_lookup(tenant, &update.action_digest, b"CLB1".to_vec())
                    .await
                    .is_err(),
                "{tenant}: AC lookup must fail closed"
            );
        }

        for tenant in [
            "tenant-inactive",
            "tenant-without-row",
            crate::adapter_cache::PUBLIC_NAMESPACE,
        ] {
            let write = write_req(tenant, b"cas payload".to_vec());
            assert!(cas.byok_encrypt_for_write(&write).await.unwrap().is_none());
            let read = CasReadRequest::new(tenant, &write.claimed_hash, "p", tenant, 1);
            assert_eq!(
                cas.byok_decrypt_for_read(&read, b"cas payload".to_vec())
                    .await
                    .unwrap(),
                b"cas payload"
            );
            let update = ac_update_req(tenant, b"ac payload".to_vec());
            assert!(ac.byok_encrypt_for_update(&update).await.unwrap().is_none());
            assert_eq!(
                ac.byok_decrypt_for_lookup(tenant, &update.action_digest, b"ac payload".to_vec())
                    .await
                    .unwrap(),
                b"ac payload"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_mode_b_delete_reclaims_envelope_row_ac_surface() {
        // Wave 4a: an AC Mode-B delete reclaims the `ac:<digest>` envelope row —
        // surface-correct (a CAS row for the same digest would be `cas:<digest>`).
        let store = Arc::new(MemEnvStore::default());
        let h = ac_handler_with_byok_random_store(
            Some(byok_cfg(ByokCryptoMode::Random, ByokState::Active)),
            Arc::clone(&store),
        )
        .await;
        let req = ac_update_req(BYOK_TENANT, b"ac mode-b payload".to_vec());
        h.byok_encrypt_for_update(&req).await.unwrap().unwrap();
        let ac_key = format!("ac:{}", req.action_digest);
        assert!(
            store.contains(BYOK_TENANT, &ac_key),
            "write minted the ac: envelope row"
        );
        assert!(
            !store.contains(BYOK_TENANT, &format!("cas:{}", req.action_digest)),
            "no cas: row"
        );
        h.byok_reclaim_for_delete(BYOK_TENANT, &req.action_digest)
            .await
            .unwrap();
        assert!(
            !store.contains(BYOK_TENANT, &ac_key),
            "AC delete reclaimed the ac: row"
        );
        assert_eq!(store.len(), 0, "no orphan AC envelope row lingers");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_mode_a_delete_touches_no_envelope_row() {
        // Mode A on the AC surface writes no envelope row; reclaim is a no-op.
        let store = Arc::new(MemEnvStore::default());
        let h = ac_handler_with_byok_random_store(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            Arc::clone(&store),
        )
        .await;
        let req = ac_update_req(BYOK_TENANT, b"ac convergent".to_vec());
        h.byok_encrypt_for_update(&req).await.unwrap().unwrap();
        assert_eq!(store.len(), 0, "Mode A writes no AC envelope row");
        h.byok_reclaim_for_delete(BYOK_TENANT, &req.action_digest)
            .await
            .unwrap();
        assert_eq!(store.len(), 0, "Mode-A AC delete touches no envelope row");
    }

    #[derive(Debug)]
    struct TransitionCfgSrc {
        result: std::sync::Mutex<Result<Option<TenantByokConfig>, ByokConfigError>>,
    }

    #[async_trait::async_trait]
    impl ByokConfigSource for TransitionCfgSrc {
        async fn get_byok_config(
            &self,
            _tenant: &str,
        ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
            self.result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn router_factory_attachments_share_cache_across_storage_and_accounting() {
        // Exercise the four helpers called by router assembly with controlled
        // R2/KMS seams. A second cache in any attachment breaks pointer identity
        // and would observe this transition independently.
        let source = Arc::new(TransitionCfgSrc {
            result: std::sync::Mutex::new(Ok(Some(byok_cfg(
                ByokCryptoMode::Convergent,
                ByokState::Inactive,
            )))),
        });
        let cache = Arc::new(ByokConfigCache::new(source.clone(), 0));
        let resolver = Arc::new(
            TcsResolver::new(Arc::new(SecSrc), Arc::new(Kms { fail: false }), 300).unwrap(),
        );
        let mode_b = Arc::new(
            ModeBEncryptor::new(
                Arc::new(Kms { fail: false }) as Arc<dyn KmsProvider>,
                Arc::new(MemEnvStore::default()) as Arc<dyn ByokEnvelopeStore>,
                300,
            )
            .unwrap(),
        );
        let byok = crate::storage::byok_cas::DataPlaneByok::new(cache.clone(), resolver, mode_b);
        let cas = Arc::new(crate::routes::cas::attach_byok_to_r2_handler(
            make_test_handler_with_tdk("iad").await,
            Some(&byok),
        ));
        let ac = Arc::new(crate::routes::ac::attach_byok_to_r2_handler(
            make_test_ac_handler("iad").await,
            Some(&byok),
        ));
        let byte_store = Arc::new(crate::byte_accounting::testing::InMemoryByteStore::new());
        let accountant = Arc::new(crate::byte_accounting::ByteAccountant::new(
            byte_store as Arc<dyn crate::byte_accounting::ByteStore>,
            "iad".to_owned(),
        ));
        let cas_accounting = crate::routes::build::attach_byok_to_cas_accounting(
            crate::byte_accounting::AccountingCasHandler::new(
                cas.clone() as Arc<dyn CasWriteHandler>,
                cas.clone() as Arc<dyn CasDeleteHandler>,
                accountant.clone(),
            ),
            Some(&byok),
        );
        let ac_accounting = crate::routes::build::attach_byok_to_ac_accounting(
            crate::byte_accounting::AccountingAcHandler::new(
                ac.clone() as Arc<dyn corelink_handler_ac::AcUpdateHandler>,
                ac.clone() as Arc<dyn corelink_handler_ac::AcDeleteHandler>,
                accountant,
            ),
            Some(&byok),
        );
        for attached in [
            cas.byok_config_cache_for_test().expect("CAS cache"),
            ac.byok_config_cache_for_test().expect("AC cache"),
        ] {
            assert!(Arc::ptr_eq(&cache, attached));
        }
        let cas_accounting_cache = cas_accounting
            .byok_for_test()
            .expect("CAS accounting data plane")
            .config_cache();
        let ac_accounting_cache = ac_accounting
            .byok_for_test()
            .expect("AC accounting data plane")
            .config_cache();
        assert!(Arc::ptr_eq(&cache, &cas_accounting_cache));
        assert!(Arc::ptr_eq(&cache, &ac_accounting_cache));

        let cas_request = write_req(BYOK_TENANT, b"factory transition".to_vec());
        assert!(cas.byok_encrypt_for_write(&cas_request).await.unwrap().is_none());
        assert_eq!(
            crate::byte_accounting::byok_committed_len_for_test(
                Some(&cas_accounting_cache),
                BYOK_TENANT,
                cas_request.bytes.len() as i64,
            )
            .unwrap(),
            cas_request.bytes.len() as i64,
        );

        *source
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Ok(Some(byok_cfg(
            ByokCryptoMode::Convergent,
            ByokState::Active,
        )));
        assert!(cas.byok_encrypt_for_write(&cas_request).await.unwrap().is_some());
        assert_eq!(
            crate::byte_accounting::byok_committed_len_for_test(
                Some(&ac_accounting_cache),
                BYOK_TENANT,
                cas_request.bytes.len() as i64,
            )
            .unwrap(),
            cas_request.bytes.len() as i64 + BYOK_CLB1_OVERHEAD as i64,
        );

        *source
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Err(ByokConfigError::Transport(
            "injected control-plane failure".to_owned(),
        ));
        assert!(cas.byok_encrypt_for_write(&cas_request).await.is_err());
        assert!(crate::byte_accounting::byok_committed_len_for_test(
            Some(&cas_accounting_cache),
            BYOK_TENANT,
            cas_request.bytes.len() as i64,
        )
        .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_inactive_handler_is_plaintext_passthrough() {
        // No `with_byok` ⇒ AC plaintext path, byte-identical to today.
        let h = make_test_ac_handler("iad").await;
        let req = ac_update_req(BYOK_TENANT, b"ac-result".to_vec());
        assert!(
            h.byok_encrypt_for_update(&req).await.unwrap().is_none(),
            "no BYOK collaborators ⇒ store the AC payload plaintext (None)"
        );
        let out = h
            .byok_decrypt_for_lookup(BYOK_TENANT, &req.action_digest, b"ac-result".to_vec())
            .await
            .unwrap();
        assert_eq!(
            out, b"ac-result",
            "lookup must return the stored bytes unchanged"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_active_encrypts_then_round_trips() {
        let h = ac_handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            false,
        )
        .await;
        let payload = b"proven action result metadata".to_vec();
        let req = ac_update_req(BYOK_TENANT, payload.clone());
        let stored = h
            .byok_encrypt_for_update(&req)
            .await
            .unwrap()
            .expect("active tenant must encrypt the AC payload");
        assert_ne!(stored, payload, "AC stored bytes must be ciphertext");
        // Convergent ⇒ identical payload yields byte-identical stored bytes — this
        // is what keeps the divergent-body GET-and-compare idempotent for an
        // active tenant (ciphertext-vs-ciphertext).
        let stored2 = h.byok_encrypt_for_update(&req).await.unwrap().unwrap();
        assert_eq!(stored, stored2, "convergent ⇒ idempotent AC stored bytes");
        let out = h
            .byok_decrypt_for_lookup(BYOK_TENANT, &req.action_digest, stored)
            .await
            .unwrap();
        assert_eq!(out, payload, "decrypt must recover the AC plaintext");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_active_write_fails_closed_when_kms_down() {
        let h = ac_handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            true,
        )
        .await;
        let req = ac_update_req(BYOK_TENANT, b"secret".to_vec());
        assert!(
            matches!(
                h.byok_encrypt_for_update(&req).await,
                Err(corelink_handler_ac::AcHandlerError::Internal(_))
            ),
            "active tenant + failing KMS must fail closed on AC write (never plaintext)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_active_read_fails_closed_when_kms_down() {
        let h = ac_handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            true,
        )
        .await;
        assert!(
            matches!(
                h.byok_decrypt_for_lookup(BYOK_TENANT, &"a".repeat(64), b"CLB1raw".to_vec())
                    .await,
                Err(corelink_handler_ac::AcHandlerError::Internal(_))
            ),
            "active tenant + failing KMS must fail closed on AC read (raw bytes never served)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_mode_b_and_partial_fail_closed() {
        for (mode, state) in [
            (ByokCryptoMode::Random, ByokState::Active),
            (ByokCryptoMode::Convergent, ByokState::Partial),
        ] {
            let h = ac_handler_with_byok(Some(byok_cfg(mode, state)), false).await;
            let req = ac_update_req(BYOK_TENANT, b"x".to_vec());
            assert!(
                matches!(
                    h.byok_encrypt_for_update(&req).await,
                    Err(corelink_handler_ac::AcHandlerError::Internal(_))
                ),
                "Mode B / partial AC write must fail closed, never plaintext ({mode:?},{state:?})"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_byok_public_namespace_never_encrypts() {
        let h = ac_handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            false,
        )
        .await;
        let req = ac_update_req(crate::adapter_cache::PUBLIC_NAMESPACE, b"shared".to_vec());
        assert!(
            h.byok_encrypt_for_update(&req).await.unwrap().is_none(),
            "_public AC entries must never be encrypted (dedup)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ac_blob_does_not_decrypt_under_cas_and_vice_versa() {
        // Frozen policy H1 at the HANDLER level: an AC-encrypted blob must NOT be
        // decryptable by the CAS read hook, and a CAS blob must NOT be decryptable
        // by the AC lookup hook — even for the SAME tenant + digest + tcs (same
        // SecSrc/Kms). Domain separation by `surface` makes an AC↔CAS blob swap
        // fail closed end-to-end.
        let digest = "a".repeat(64);
        let payload = b"cross-surface".to_vec();
        let ac = ac_handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            false,
        )
        .await;
        let cas = handler_with_byok(
            Some(byok_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            false,
        )
        .await;

        let ac_req = corelink_handler_ac::AcUpdateRequest::new(
            BYOK_TENANT,
            digest.clone(),
            payload.clone(),
            "p",
            BYOK_TENANT,
            1,
        );
        let ac_blob = ac.byok_encrypt_for_update(&ac_req).await.unwrap().unwrap();
        let cas_rreq = CasReadRequest::new(BYOK_TENANT, &digest, "p", BYOK_TENANT, 1);
        assert!(
            cas.byok_decrypt_for_read(&cas_rreq, ac_blob).await.is_err(),
            "an AC blob must NOT decrypt under the CAS surface"
        );

        let cas_wreq =
            CasWriteRequest::new(BYOK_TENANT, digest.clone(), payload, "p", BYOK_TENANT, 1);
        let cas_blob = cas
            .byok_encrypt_for_write(&cas_wreq)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ac.byok_decrypt_for_lookup(BYOK_TENANT, &digest, cas_blob)
                .await
                .is_err(),
            "a CAS blob must NOT decrypt under the AC surface"
        );
    }
