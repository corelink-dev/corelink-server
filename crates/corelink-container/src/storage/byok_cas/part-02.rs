#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed these primitives"
)]
mod tests {
    use super::*;
    use crate::customer_d1::ByokMode;
    use corelink_byok::{Dek, KmsAccessStatus, KmsKeyId, KmsProviderKind};

    const TENANT: &str = "tenant-byok-a";

    fn active_cfg(crypto_mode: ByokCryptoMode, state: ByokState) -> TenantByokConfig {
        TenantByokConfig {
            tenant_id: TENANT.to_owned(),
            mode: ByokMode::Byok,
            crypto_mode,
            cmk_provider: Some("aws".to_owned()),
            cmk_key_id: Some("arn:aws:kms:iad:1:key/cmk".to_owned()),
            cmk_region: Some("iad".to_owned()),
            state,
        }
    }

    /// Gate fake for the operation-pin seam. It deliberately returns a fresh
    /// snapshot on every acquisition so a test can model a rotation occurring
    /// while an earlier write is still reserved.
    #[derive(Debug)]
    struct PinGate {
        config: Mutex<TenantByokConfig>,
        releases: Mutex<usize>,
    }

    #[async_trait]
    impl ByokRuntimeGate for PinGate {
        async fn acquire_data(
            &self,
            tenant_id: &str,
            _operation: crate::byok_transition_fence::DataOperation,
        ) -> Result<crate::storage::byok_generation_catalog::RuntimeDataIntent, String> {
            Ok(crate::storage::byok_generation_catalog::RuntimeDataIntent::for_test(
                tenant_id,
                Some(lock(&self.config).clone()),
                Some(1),
            ))
        }

        async fn release_data(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
        ) -> Result<(), String> {
            *lock(&self.releases) += 1;
            Ok(())
        }

        async fn validate_for_return(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn resolve_catalog(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
            _kind: crate::storage::byok_generation_catalog::ByokObjectKind,
            _logical_key: &str,
        ) -> Result<Option<crate::storage::byok_generation_catalog::PublishedObject>, String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn begin_purge_attempt(
            &self,
            _plan: &mut crate::storage::byok_generation_catalog::ByokPurgePlan,
        ) -> Result<(), String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn finish_purge_attempt(
            &self,
            _plan: &crate::storage::byok_generation_catalog::ByokPurgePlan,
            _head_absent: bool,
            _error: Option<&str>,
            _envelope_reclaimed: bool,
        ) -> Result<(), String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn allocate_catalog(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
            _kind: crate::storage::byok_generation_catalog::ByokObjectKind,
            _logical_key: &str,
            _allocation_id: &str,
            _physical_key: &str,
            _size_bytes: u64,
        ) -> Result<crate::storage::byok_generation_catalog::StagedObject, String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn publish_catalog(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
            _staged: &crate::storage::byok_generation_catalog::StagedObject,
        ) -> Result<bool, String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn tombstone_catalog(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
            _kind: crate::storage::byok_generation_catalog::ByokObjectKind,
            _logical_key: &str,
        ) -> Result<Option<crate::storage::byok_generation_catalog::ByokPurgePlan>, String> {
            Err("not used by operation-pin sizing test".to_owned())
        }

        async fn list_catalog(
            &self,
            _intent: &crate::storage::byok_generation_catalog::RuntimeDataIntent,
            _kind: crate::storage::byok_generation_catalog::ByokObjectKind,
            _limit: u32,
            _after_logical_key: Option<&str>,
        ) -> Result<Vec<crate::storage::byok_generation_catalog::PublishedObject>, String> {
            Err("not used by operation-pin sizing test".to_owned())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operation_pin_keeps_rotation_snapshot_and_rejects_cross_tenant_reuse() {
        let gate = Arc::new(PinGate {
            config: Mutex::new(active_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            releases: Mutex::new(0),
        });
        let data_plane = DataPlaneByok::new(
            Arc::new(ByokConfigCache::new(Arc::new(MockConfigSource::ok(None)), 60)),
            Arc::new(
                TcsResolver::new(
                    Arc::new(MockSecretSource { row: None }),
                    Arc::new(MockKms::ok()),
                    300,
                )
                .unwrap(),
            ),
            Arc::new(mode_b_enc(Arc::new(MemEnvelopeStore::default()), false)),
        )
        .with_runtime_gate(gate.clone() as Arc<dyn ByokRuntimeGate>);
        let pin = data_plane.pin_write(TENANT, 1000).unwrap().unwrap();
        assert_eq!(pin.committed_len(), 1000 + BYOK_CLB1_OVERHEAD as i64);

        // A rotation concurrently visible to a later acquisition cannot change
        // the already-reserved operation's overhead or config identity.
        lock(&gate.config).crypto_mode = ByokCryptoMode::Random;
        assert_eq!(pin.committed_len(), 1000 + BYOK_CLB1_OVERHEAD as i64);
        assert!(pin.take_guard("other-tenant").is_err());

        let mut guard = pin.take_guard(TENANT).unwrap();
        guard.finish(false).await.unwrap();
        assert!(pin.take_guard(TENANT).is_err(), "a pin is single-use");
        assert_eq!(*lock(&gate.releases), 1, "the exact pin is released once");
    }

    // ── Mock config source ──────────────────────────────────────────────────

    #[derive(Debug)]
    struct MockConfigSource {
        cfg: Option<TenantByokConfig>,
        calls: Mutex<usize>,
        fail: bool,
    }
    impl MockConfigSource {
        fn ok(cfg: Option<TenantByokConfig>) -> Self {
            Self {
                cfg,
                calls: Mutex::new(0),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                cfg: None,
                calls: Mutex::new(0),
                fail: true,
            }
        }
        fn call_count(&self) -> usize {
            *lock(&self.calls)
        }
    }
    #[async_trait]
    impl ByokConfigSource for MockConfigSource {
        async fn get_byok_config(
            &self,
            _tenant: &str,
        ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
            *lock(&self.calls) += 1;
            if self.fail {
                return Err(ByokConfigError::Transport("mock down".to_owned()));
            }
            Ok(self.cfg.clone())
        }
    }

    // ── Mock secret source + KMS provider ───────────────────────────────────

    #[derive(Debug)]
    struct MockSecretSource {
        row: Option<WrappedTcsRow>,
    }
    #[async_trait]
    impl ByokSecretSource for MockSecretSource {
        async fn get_wrapped_tcs(&self, _tenant: &str) -> Result<Option<WrappedTcsRow>, String> {
            Ok(self.row.clone())
        }
    }

    /// A mock KMS that "unwraps" by treating the wrapped ciphertext as the raw
    /// 32-byte secret (good enough to exercise the resolution + round-trip).
    #[derive(Debug)]
    struct MockKms {
        fail: bool,
        calls: Mutex<usize>,
    }
    impl MockKms {
        fn ok() -> Self {
            Self {
                fail: false,
                calls: Mutex::new(0),
            }
        }
        fn failing() -> Self {
            Self {
                fail: true,
                calls: Mutex::new(0),
            }
        }
        fn unwrap_count(&self) -> usize {
            *lock(&self.calls)
        }
    }
    #[async_trait]
    impl KmsProvider for MockKms {
        fn provider_kind(&self) -> KmsProviderKind {
            KmsProviderKind::AwsKms
        }
        fn region(&self) -> &str {
            "iad"
        }
        fn fips_level(&self) -> corelink_byok::FipsLevel {
            corelink_byok::FipsLevel::Fips140_3_L1
        }
        async fn wrap_dek(
            &self,
            dek: &Dek,
            key_id: &KmsKeyId,
            encryption_context: Option<&Value>,
        ) -> Result<WrappedDek, BYOKError> {
            Ok(WrappedDek {
                provider: KmsProviderKind::AwsKms,
                key_id: key_id.clone(),
                ciphertext: dek.bytes.to_vec(),
                encryption_context: encryption_context.cloned(),
            })
        }
        async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, BYOKError> {
            *lock(&self.calls) += 1;
            if self.fail {
                return Err(BYOKError::Provider("mock kms down".to_owned()));
            }
            if wrapped.ciphertext.len() != 32 {
                return Err(BYOKError::DekLengthInvalid {
                    got: wrapped.ciphertext.len(),
                });
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&wrapped.ciphertext);
            Ok(Dek { bytes })
        }
        async fn check_access(&self, _key_id: &KmsKeyId) -> Result<KmsAccessStatus, BYOKError> {
            Ok(KmsAccessStatus::Ok)
        }
    }

    fn wrapped_tcs() -> WrappedTcsRow {
        WrappedTcsRow {
            tcs_wrapped: vec![7u8; 32],
            cmk_key_id: Some("arn:aws:kms:iad:1:key/cmk".to_owned()),
            tcs_version: 1,
        }
    }

    // ── ByokConfigCache ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn config_cache_hit_does_one_d1_read() {
        let src = Arc::new(MockConfigSource::ok(Some(active_cfg(
            ByokCryptoMode::Convergent,
            ByokState::Active,
        ))));
        let cache = ByokConfigCache::new(src.clone(), 60);
        let a = cache.get(TENANT).await.unwrap();
        let b = cache.get(TENANT).await.unwrap();
        assert!(a.is_some());
        assert_eq!(a, b);
        assert_eq!(src.call_count(), 1, "second get must be an in-memory HIT");
    }

    #[tokio::test]
    async fn config_cache_does_not_cache_plaintext_none_across_activation() {
        // A negative result may become active at any time. Caching it would
        // allow a successful activation to leave a plaintext window.
        let src = Arc::new(MockConfigSource::ok(None));
        let cache = ByokConfigCache::new(src.clone(), 60);
        assert!(cache.get(TENANT).await.unwrap().is_none());
        assert!(cache.get(TENANT).await.unwrap().is_none());
        assert_eq!(
            src.call_count(),
            2,
            "not-configured answers must be re-read before choosing plaintext"
        );
    }

    #[tokio::test]
    async fn config_cache_propagates_source_error_fail_closed() {
        let src = Arc::new(MockConfigSource::failing());
        let cache = ByokConfigCache::new(src, 60);
        assert!(matches!(
            cache.get(TENANT).await,
            Err(ByokConfigError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn config_cache_zero_ttl_refetches() {
        let src = Arc::new(MockConfigSource::ok(None));
        let cache = ByokConfigCache::new(src.clone(), 0);
        cache.get(TENANT).await.unwrap();
        cache.get(TENANT).await.unwrap();
        assert_eq!(src.call_count(), 2, "a 0s TTL entry is always expired");
    }

    // ── TcsResolver ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tcs_resolver_unwraps_then_caches() {
        let kms = Arc::new(MockKms::ok());
        let resolver = TcsResolver::new(
            Arc::new(MockSecretSource {
                row: Some(wrapped_tcs()),
            }),
            kms.clone(),
            300,
        )
        .unwrap();
        let cfg = active_cfg(ByokCryptoMode::Convergent, ByokState::Active);
        let t1 = resolver.resolve(&cfg).await.unwrap();
        let t2 = resolver.resolve(&cfg).await.unwrap();
        assert_eq!(t1.bytes, [7u8; 32]);
        assert_eq!(t1.bytes, t2.bytes);
        assert_eq!(
            kms.unwrap_count(),
            1,
            "the unwrapped Tcs must be cached (≤300s)"
        );
    }

    #[tokio::test]
    async fn tcs_resolver_fail_closed_when_secret_missing() {
        let resolver = TcsResolver::new(
            Arc::new(MockSecretSource { row: None }),
            Arc::new(MockKms::ok()),
            300,
        )
        .unwrap();
        let cfg = active_cfg(ByokCryptoMode::Convergent, ByokState::Active);
        assert!(resolver.resolve(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn tcs_resolver_fail_closed_when_kms_down() {
        let resolver = TcsResolver::new(
            Arc::new(MockSecretSource {
                row: Some(wrapped_tcs()),
            }),
            Arc::new(MockKms::failing()),
            300,
        )
        .unwrap();
        let cfg = active_cfg(ByokCryptoMode::Convergent, ByokState::Active);
        assert!(resolver.resolve(&cfg).await.is_err());
    }

    #[test]
    fn tcs_cache_rejects_ttl_over_300() {
        assert!(TcsCache::new(301).is_err());
        assert!(TcsCache::new(300).is_ok());
    }

    // ── engagement_for ────────────────────────────────────────────────────────

    #[test]
    fn engagement_truth_table() {
        // Wave 3c: an active tenant now engages BOTH modes (Random no longer
        // fail-closed); the caller dispatches on the carried mode.
        assert_eq!(
            engagement_for(&active_cfg(ByokCryptoMode::Convergent, ByokState::Active)),
            ByokEngagement::Encrypt(ByokCryptoMode::Convergent)
        );
        assert_eq!(
            engagement_for(&active_cfg(ByokCryptoMode::Random, ByokState::Active)),
            ByokEngagement::Encrypt(ByokCryptoMode::Random)
        );
        // Partial/backfill dual-read stays deferred (Wave 4) → fail-closed.
        assert!(matches!(
            engagement_for(&active_cfg(ByokCryptoMode::Convergent, ByokState::Partial)),
            ByokEngagement::FailClosed(_)
        ));
        assert!(matches!(
            engagement_for(&active_cfg(ByokCryptoMode::Random, ByokState::Partial)),
            ByokEngagement::FailClosed(_)
        ));
        for s in [ByokState::Inactive, ByokState::Pending] {
            assert_eq!(
                engagement_for(&active_cfg(ByokCryptoMode::Convergent, s)),
                ByokEngagement::Plaintext
            );
        }
        assert!(matches!(
            engagement_for(&active_cfg(
                ByokCryptoMode::Convergent,
                ByokState::Shredded
            )),
            ByokEngagement::FailClosed(_)
        ));
    }

    // ── §4 key-hardening (audit H-4) ──────────────────────────────────────────

    #[test]
    fn harden_digest_is_not_the_raw_digest_and_is_deterministic() {
        let tcs = Tcs::from_bytes([4u8; 32]);
        let digest = "a".repeat(64);
        let h1 = harden_digest(&tcs, &digest);
        let h2 = harden_digest(&tcs, &digest);
        assert_ne!(h1, digest, "hardened key must not reveal the raw digest");
        assert_eq!(
            h1, h2,
            "deterministic per (TCS, digest) ⇒ intra-tenant dedup hits"
        );
        // HMAC-SHA256 ⇒ 32 bytes ⇒ 64 hex chars (same shape as a digest slot).
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn harden_digest_differs_per_tcs_and_per_digest() {
        let digest = "a".repeat(64);
        let other = "b".repeat(64);
        let a = harden_digest(&Tcs::from_bytes([1u8; 32]), &digest);
        let b = harden_digest(&Tcs::from_bytes([2u8; 32]), &digest);
        assert_ne!(
            a, b,
            "different TCS ⇒ different hardened key (no cross-tenant correlation)"
        );
        let c = harden_digest(&Tcs::from_bytes([1u8; 32]), &other);
        assert_ne!(a, c, "different digest ⇒ different hardened key");
    }

    #[test]
    fn convergent_ctx_keeps_the_real_digest_after_hardening() {
        // The storage key uses the hardened digest, but the AAD-bound context
        // digest stays the REAL digest so the post-decrypt integrity re-verify
        // (on the plaintext) still checks the true content hash.
        let tcs = Tcs::from_bytes([7u8; 32]);
        let digest = "c".repeat(64);
        let hardened = harden_digest(&tcs, &digest);
        let ctx = cas_crypto_context(TENANT, &digest, DigestAlgo::Blake3, "arn:cmk");
        assert_eq!(
            ctx.plaintext_digest, digest,
            "ctx must bind the REAL digest"
        );
        assert_ne!(
            ctx.plaintext_digest, hardened,
            "ctx digest is NOT the storage key"
        );
        // Round-trip still works with the real-digest context.
        let pt = b"payload".to_vec();
        let stored = encrypt_cas_blob(&pt, &tcs, &ctx).unwrap();
        assert_eq!(decrypt_cas_blob(&stored, &tcs, &ctx).unwrap(), pt);
    }

    // ── blob round-trip + convergent dedup + tamper ──────────────────────────

    fn ctx() -> CryptoContext {
        cas_crypto_context(TENANT, &"a".repeat(64), DigestAlgo::Blake3, "arn:cmk")
    }

    fn ac_ctx() -> CryptoContext {
        ac_crypto_context(TENANT, &"a".repeat(64), "arn:cmk")
    }

    #[test]
    fn blob_roundtrip_and_ciphertext_differs_from_plaintext() {
        let tcs = Tcs::from_bytes([3u8; 32]);
        let pt = b"sensitive build artifact bytes".to_vec();
        let stored = encrypt_cas_blob(&pt, &tcs, &ctx()).unwrap();
        assert_ne!(stored, pt, "stored bytes must be ciphertext, not plaintext");
        assert_eq!(&stored[..4], BLOB_MAGIC);
        let out = decrypt_cas_blob(&stored, &tcs, &ctx()).unwrap();
        assert_eq!(out, pt, "round-trip must recover the plaintext");
    }

    #[test]
    fn convergent_dedup_same_content_same_ciphertext() {
        let tcs = Tcs::from_bytes([9u8; 32]);
        let pt = b"identical content".to_vec();
        let a = encrypt_cas_blob(&pt, &tcs, &ctx()).unwrap();
        let b = encrypt_cas_blob(&pt, &tcs, &ctx()).unwrap();
        assert_eq!(
            a, b,
            "convergent ⇒ identical stored bytes (dedup-idempotent)"
        );
    }

    #[test]
    fn decrypt_rejects_non_magic_bytes_fail_closed() {
        // A plaintext object served to an active tenant must NOT be returned raw.
        let tcs = Tcs::from_bytes([1u8; 32]);
        assert!(decrypt_cas_blob(b"raw plaintext, no magic", &tcs, &ctx()).is_err());
        assert!(decrypt_cas_blob(b"", &tcs, &ctx()).is_err());
    }

    #[test]
    fn decrypt_wrong_tcs_fails_closed() {
        let stored = encrypt_cas_blob(b"x", &Tcs::from_bytes([1u8; 32]), &ctx()).unwrap();
        assert!(decrypt_cas_blob(&stored, &Tcs::from_bytes([2u8; 32]), &ctx()).is_err());
    }

    #[test]
    fn decode_blob_accepts_array_and_base64() {
        assert_eq!(decode_blob(&json!([1, 2, 3])).unwrap(), vec![1u8, 2, 3]);
        let b64 = base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]);
        assert_eq!(decode_blob(&json!(b64)).unwrap(), vec![4u8, 5, 6]);
        assert!(decode_blob(&json!(true)).is_err());
        assert!(decode_blob(&json!([1, 999])).is_err());
    }

    #[test]
    fn namespace_is_algo_separated() {
        assert_ne!(
            namespace_for(DigestAlgo::Blake3),
            namespace_for(DigestAlgo::Sha256)
        );
    }

    // ── AC surface (Wave 3b) ──────────────────────────────────────────────────

    #[test]
    fn ac_blob_roundtrips_under_ac_context() {
        // The AC payload encrypts + decrypts cleanly under an `"ac"`-surface ctx.
        let tcs = Tcs::from_bytes([5u8; 32]);
        let pt = b"action-result-metadata payload".to_vec();
        let stored = encrypt_cas_blob(&pt, &tcs, &ac_ctx()).unwrap();
        assert_ne!(stored, pt, "AC stored bytes must be ciphertext");
        assert_eq!(&stored[..4], BLOB_MAGIC);
        assert_eq!(decrypt_cas_blob(&stored, &tcs, &ac_ctx()).unwrap(), pt);
    }

    #[test]
    fn ac_and_cas_surfaces_are_domain_separated() {
        // Frozen policy H1: an AC blob must NOT decrypt under a CAS context, and
        // a CAS blob must NOT decrypt under an AC context — `surface` is bound
        // into the derived key + AEAD AAD, so swapping surfaces fails closed even
        // for the identical (tenant, digest, tcs).
        let tcs = Tcs::from_bytes([6u8; 32]);
        let pt = b"swap-me".to_vec();
        let ac_blob = encrypt_cas_blob(&pt, &tcs, &ac_ctx()).unwrap();
        let cas_blob = encrypt_cas_blob(&pt, &tcs, &ctx()).unwrap();
        // Different surface ⇒ different ciphertext for identical input.
        assert_ne!(ac_blob, cas_blob, "surface must perturb the derivation");
        // Cross-surface decrypt must fail (never returns plaintext).
        assert!(
            decrypt_cas_blob(&ac_blob, &tcs, &ctx()).is_err(),
            "AC blob must not decrypt as CAS"
        );
        assert!(
            decrypt_cas_blob(&cas_blob, &tcs, &ac_ctx()).is_err(),
            "CAS blob must not decrypt as AC"
        );
    }

    #[test]
    fn clb1_overhead_matches_the_wire_format() {
        // Single-source check: the stored blob is exactly plaintext + 32 (4 magic
        // + 12 nonce + 16 GCM tag), so the accounting const can never drift.
        assert_eq!(BYOK_CLB1_OVERHEAD, 32);
        let tcs = Tcs::from_bytes([8u8; 32]);
        for pt_len in [0usize, 1, 17, 4096] {
            let pt = vec![b'z'; pt_len];
            let stored = encrypt_cas_blob(&pt, &tcs, &ctx()).unwrap();
            assert_eq!(
                stored.len() as u64,
                pt_len as u64 + BYOK_CLB1_OVERHEAD,
                "stored len must be plaintext + CLB1 overhead for pt_len={pt_len}"
            );
        }
    }

    #[test]
    fn data_plane_exposes_clones_of_one_authoritative_config_cache() {
        let cache = Arc::new(ByokConfigCache::new(
            Arc::new(MockConfigSource::ok(None)),
            60,
        ));
        let resolver = Arc::new(
            TcsResolver::new(
                Arc::new(MockSecretSource { row: None }),
                Arc::new(MockKms::ok()),
                300,
            )
            .unwrap(),
        );
        let mode_b = Arc::new(mode_b_enc(Arc::new(MemEnvelopeStore::default()), false));
        let data_plane = DataPlaneByok::new(Arc::clone(&cache), resolver, mode_b);
        assert!(
            Arc::ptr_eq(&cache, &data_plane.config_cache()),
            "composition consumers must receive clones of the one cache Arc"
        );
    }

    #[test]
    fn unprovisioned_kms_boots_only_while_no_tenant_is_engaged() {
        assert_eq!(unprovisioned_provider_boot(false), Ok(()));
        let refused = unprovisioned_provider_boot(true).unwrap_err();
        assert!(refused.contains("refusing to boot"), "{refused}");
    }

    #[test]
    fn engagement_probe_covers_every_state_that_needs_keys() {
        for state in [ByokState::Active, ByokState::Partial, ByokState::Shredded] {
            let quoted = format!("'{}'", state.as_str());
            assert!(
                BYOK_ENGAGED_STATES_SQL.contains(&quoted),
                "{quoted} must keep an unprovisioned boot refused"
            );
        }
        for state in [ByokState::Inactive, ByokState::Pending] {
            let quoted = format!("'{}'", state.as_str());
            assert!(
                !BYOK_ENGAGED_STATES_SQL.contains(&quoted),
                "{quoted} is plaintext in every build and must not block boot"
            );
        }
        assert!(BYOK_ENGAGED_STATES_SQL.contains("FROM tenant_byok_config"));
        assert!(BYOK_ENGAGED_STATES_SQL.trim_start().starts_with("SELECT"));
    }

    #[test]
    fn engagement_flag_accepts_only_an_exact_zero_or_one() {
        assert_eq!(engaged_flag(Some(&json!(0))), Ok(false));
        assert_eq!(engaged_flag(Some(&json!(1))), Ok(true));
        for unreadable in [json!(2), json!(-1), json!("0"), json!(null), json!(0.5)] {
            assert!(
                engaged_flag(Some(&unreadable)).is_err(),
                "{unreadable} must refuse boot, not read as \"no tenant engaged\""
            );
        }
        assert!(engaged_flag(None).is_err());
    }

    include!("part-02-tail.rs");
}
