impl core::fmt::Debug for R2AcHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("R2AcHandler")
            .field("ac_region", &self.ac_region)
            .finish_non_exhaustive()
    }
}

impl R2AcHandler {
    /// Construct an `R2AcHandler`. See [`R2CasHandler::new`] for the
    /// `tdk_bytes` semantics (pass `None` in tests with a dev/zero TDK).
    #[must_use]
    pub fn new(
        client: R2S3Client,
        ac_region: impl Into<String>,
        tdk_bytes: Option<Zeroizing<[u8; 32]>>,
        audit: Arc<dyn corelink_handler_ac::AuditSink>,
        sli: Arc<dyn corelink_handler_ac::SliObserver>,
    ) -> Self {
        let tdk = tdk_bytes.map(TenantDerivationKey::from_bytes);
        Self {
            client,
            ac_region: ac_region.into(),
            tdk,
            audit,
            audit_async: None,
            sli,
            byok_config_cache: None,
            tcs_resolver: None,
            byok_mode_b: None,
            byok_runtime_gate: None,
        }
    }

    /// Retained for builder compatibility with the CAS batch-exists wiring.
    /// AC reads and lists do not use this seam: their durable attempted audit
    /// is always committed synchronously before storage dispatch.
    #[must_use]
    pub fn with_async_audit(
        mut self,
        audit_async: Arc<crate::storage::d1_audit_sink::D1AuditOutboxSink>,
    ) -> Self {
        self.audit_async = Some(audit_async);
        self
    }

    /// Attach the BYOK Wave-3b collaborators (config cache + Tcs resolver),
    /// enabling convergent encryption-at-rest of the AC `result_payload` for
    /// `active` tenants. Mirrors [`R2CasHandler::with_byok`].
    ///
    /// GATED-INERT: encryption engages ONLY for a tenant whose
    /// `tenant_byok_config.state == 'active'`; every other tenant (and the
    /// `_public` namespace) keeps the exact plaintext path. Production router
    /// assembly calls this only after it has constructed the one real-provider
    /// [`DataPlaneByok`](crate::storage::byok_cas::DataPlaneByok) set.
    #[must_use]
    pub fn with_byok(
        mut self,
        byok_config_cache: Arc<ByokConfigCache>,
        tcs_resolver: Arc<TcsResolver>,
    ) -> Self {
        self.byok_config_cache = Some(byok_config_cache);
        self.tcs_resolver = Some(tcs_resolver);
        self
    }

    /// Attach the BYOK Wave-3c Mode-B (random-DEK) encryptor for the AC surface.
    /// Mirrors [`R2CasHandler::with_byok_random`].
    #[must_use]
    pub fn with_byok_random(mut self, mode_b: Arc<ModeBEncryptor>) -> Self {
        self.byok_mode_b = Some(mode_b);
        self
    }

    /// Attach only the config view of an UNARMED (no-provider) data plane.
    /// Mirrors [`R2CasHandler::with_byok_unarmed`] (#1648).
    #[must_use]
    pub fn with_byok_unarmed(mut self, byok_config_cache: Arc<ByokConfigCache>) -> Self {
        self.byok_config_cache = Some(byok_config_cache);
        self.tcs_resolver = None;
        self.byok_mode_b = None;
        self
    }

    #[cfg(test)]
    pub(crate) fn byok_config_cache_for_test(&self) -> Option<&Arc<ByokConfigCache>> {
        self.byok_config_cache.as_ref()
    }

    /// Attach the mandatory production data-plane gate/catalog pair.
    #[must_use]
    pub fn with_byok_runtime_gate(mut self, gate: Arc<dyn ByokRuntimeGate>) -> Self {
        self.byok_runtime_gate = Some(gate);
        self
    }

    fn acquire_byok_data(
        &self,
        tenant: &str,
        operation: DataOperation,
        context: Option<&dyn corelink_handler_ac::AcUpdateOperationContext>,
    ) -> Result<Option<ByokDataGuard>, corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        check_unarmed_byok_access(
            self.byok_config_cache.as_deref(),
            self.tcs_resolver.is_some(),
            tenant,
        )
        .map_err(AcHandlerError::Internal)?;
        if let Some(context) = context {
            let pin = context
                .as_any()
                .downcast_ref::<crate::storage::byok_cas::ByokOperationPin>()
                .ok_or_else(|| {
                    AcHandlerError::Internal(
                        "unsupported AC operation context on R2 BYOK update".to_owned(),
                    )
                })?;
            return pin
                .take_guard(tenant)
                .map(Some)
                .map_err(|error| AcHandlerError::Internal(format!("BYOK operation pin: {error}")));
        }
        if tenant == crate::adapter_cache::PUBLIC_NAMESPACE {
            return Ok(None);
        }
        let Some(gate) = self.byok_runtime_gate.as_ref() else {
            return Ok(None);
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            handle.block_on(ByokDataGuard::acquire(Arc::clone(gate), tenant, operation))
        })
        .map(Some)
        .map_err(|error| AcHandlerError::Internal(format!("BYOK data gate: {error}")))
    }

    fn validate_byok_return(
        &self,
        guard: Option<&mut ByokDataGuard>,
    ) -> Result<(), corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        let Some(guard) = guard else {
            return Ok(());
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(guard.finish(true)))
            .map_err(|error| AcHandlerError::Internal(format!("BYOK return validation: {error}")))
    }

    fn finish_byok_mutation(
        &self,
        guard: Option<&mut ByokDataGuard>,
    ) -> Result<(), corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        let Some(guard) = guard else {
            return Ok(());
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(guard.finish(false)))
            .map_err(|error| AcHandlerError::Internal(format!("BYOK data release: {error}")))
    }

    /// Resolve the BYOK plan for an AC `(tenant, action_digest)`: the §4-hardened
    /// physical key digest (audit H-4) + the body crypto plan, binding the
    /// `"ac"` surface ([`ac_crypto_context`]) so an AC blob is domain-separated
    /// from CAS. Mirrors [`R2CasHandler::resolve_byok`].
    async fn resolve_byok_with_guard(
        &self,
        tenant: &str,
        action_digest: &str,
        guard: Option<&ByokDataGuard>,
    ) -> Result<ByokResolved, corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        let plaintext = || ByokResolved {
            physical_digest: action_digest.to_owned(),
            plan: ByokBodyPlan::Plaintext,
        };
        let Some(cache) = self.byok_config_cache.as_ref() else {
            return Ok(plaintext());
        };
        // `_public` is deterministic public content — never encrypted (dedup).
        if tenant == crate::adapter_cache::PUBLIC_NAMESPACE {
            return Ok(plaintext());
        }
        let authoritative = match guard {
            Some(guard) => Some(guard.intent().map_err(AcHandlerError::Internal)?),
            None => None,
        };
        let cfg = match authoritative {
            Some(intent) => intent.config.clone(),
            None => cache
                .get(tenant)
                .await
                .map_err(|e| AcHandlerError::Internal(format!("byok config read: {e}")))?,
        };
        let Some(cfg) = cfg else {
            return Ok(plaintext());
        };
        // An UNARMED (no-provider) process has the config view only: it serves
        // an `inactive` tenant in plaintext and refuses every other one.
        let Some(resolver) = self.tcs_resolver.as_ref() else {
            return match unarmed_engagement(&cfg) {
                ByokEngagement::Plaintext => Ok(plaintext()),
                ByokEngagement::FailClosed(why) => Err(AcHandlerError::Internal(format!(
                    "byok {why} (fail-closed)"
                ))),
                ByokEngagement::Encrypt(_) => Err(AcHandlerError::Internal(format!(
                    "byok {UNARMED_REFUSAL} (fail-closed)"
                ))),
            };
        };
        match engagement_for(&cfg) {
            ByokEngagement::Plaintext => Ok(plaintext()),
            ByokEngagement::FailClosed(why) => Err(AcHandlerError::Internal(format!(
                "byok active but {why}; refusing to fall back to plaintext (fail-closed)"
            ))),
            ByokEngagement::Encrypt(mode) => {
                let key_id = cfg.cmk_key_id.clone().unwrap_or_default();
                let tcs = resolver
                    .resolve_at_version(&cfg, authoritative.and_then(|intent| intent.tcs_version))
                    .await
                    .map_err(|e| AcHandlerError::Internal(format!("byok tcs resolve: {e}")))?;
                let physical_digest = harden_digest(&tcs, action_digest);
                let plan = match mode {
                    ByokCryptoMode::Convergent => ByokBodyPlan::Convergent {
                        tcs,
                        ctx: ac_crypto_context(tenant, action_digest, &key_id),
                    },
                    ByokCryptoMode::Random => {
                        if self.byok_mode_b.is_none() {
                            return Err(AcHandlerError::Internal(
                                "byok active Mode B (random) but the random-mode encryptor is \
                                 not wired; refusing to fall back to plaintext (fail-closed)"
                                    .to_owned(),
                            ));
                        }
                        ByokBodyPlan::Random {
                            ctx: ac_crypto_context_for(
                                tenant,
                                action_digest,
                                &key_id,
                                CryptoMode::Random,
                            ),
                        }
                    }
                };
                Ok(ByokResolved {
                    physical_digest,
                    plan,
                })
            }
        }
    }

    #[cfg(test)]
    async fn resolve_byok(
        &self,
        tenant: &str,
        action_digest: &str,
    ) -> Result<ByokResolved, corelink_handler_ac::AcHandlerError> {
        self.resolve_byok_with_guard(tenant, action_digest, None)
            .await
    }

    /// Encrypt the AC body for a resolved plan (`None` ⇒ store plaintext). See
    /// [`R2CasHandler::encrypt_body`].
    async fn encrypt_body(
        &self,
        plan: &ByokBodyPlan,
        payload: &[u8],
        allocation_id: Option<&str>,
    ) -> Result<Option<Vec<u8>>, corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        match plan {
            ByokBodyPlan::Plaintext => Ok(None),
            ByokBodyPlan::Convergent { tcs, ctx } => {
                let stored = encrypt_cas_blob(payload, tcs, ctx)
                    .map_err(|e| AcHandlerError::Internal(format!("byok ac encrypt: {e}")))?;
                Ok(Some(stored))
            }
            ByokBodyPlan::Random { ctx } => {
                let mode_b = self.byok_mode_b.as_ref().ok_or_else(|| {
                    AcHandlerError::Internal("byok mode-b encryptor missing".to_owned())
                })?;
                let stored = match allocation_id {
                    Some(allocation_id) => {
                        mode_b
                            .encrypt_for_allocation(payload, ctx, allocation_id)
                            .await
                    }
                    None => mode_b.encrypt(payload, ctx).await,
                }
                .map_err(|e| AcHandlerError::Internal(format!("byok ac mode-b encrypt: {e}")))?;
                Ok(Some(stored))
            }
        }
    }

    /// Decrypt the stored AC body for a resolved plan. See
    /// [`R2CasHandler::decrypt_body`].
    async fn decrypt_body(
        &self,
        plan: &ByokBodyPlan,
        stored: Vec<u8>,
        allocation_id: Option<&str>,
    ) -> Result<Vec<u8>, corelink_handler_ac::AcHandlerError> {
        use corelink_handler_ac::AcHandlerError;
        match plan {
            ByokBodyPlan::Plaintext => Ok(stored),
            ByokBodyPlan::Convergent { tcs, ctx } => decrypt_cas_blob(&stored, tcs, ctx)
                .map_err(|e| AcHandlerError::Internal(format!("byok ac decrypt: {e}"))),
            ByokBodyPlan::Random { ctx } => {
                let mode_b = self.byok_mode_b.as_ref().ok_or_else(|| {
                    AcHandlerError::Internal("byok mode-b encryptor missing".to_owned())
                })?;
                match allocation_id {
                    Some(allocation_id) => {
                        mode_b
                            .decrypt_for_allocation(&stored, ctx, allocation_id)
                            .await
                    }
                    None => mode_b.decrypt(&stored, ctx).await,
                }
                .map_err(|e| AcHandlerError::Internal(format!("byok ac mode-b decrypt: {e}")))
            }
        }
    }

    /// BYOK Wave 4a — reclaim the Mode-B `byok_envelope` row for the AC surface
    /// after the R2 object is deleted. Mirrors [`R2CasHandler::reclaim_byok_envelope`]
    /// (only `Random` writes a row; same R2-first ordering + warn-on-failure
    /// safe-fail rationale). The plan's `ctx` carries `AC_SURFACE`, so the
    /// reclaimed key is `ac:<digest>` (surface-correct).
    async fn reclaim_byok_envelope(
        &self,
        plan: &ByokBodyPlan,
        allocation_id: Option<&str>,
    ) -> Result<(), String> {
        if let ByokBodyPlan::Random { ctx } = plan {
            if let Some(mode_b) = self.byok_mode_b.as_ref() {
                return match allocation_id {
                    Some(allocation_id) => mode_b.reclaim_for_allocation(ctx, allocation_id).await,
                    None => mode_b.reclaim(ctx).await,
                };
            }
        }
        Ok(())
    }

    /// BYOK AC write hook (test-facing): resolve + encrypt the body. The
    /// production `update` path resolves ONCE and calls [`Self::encrypt_body`].
    #[cfg(test)]
    async fn byok_encrypt_for_update(
        &self,
        req: &corelink_handler_ac::AcUpdateRequest,
    ) -> Result<Option<Vec<u8>>, corelink_handler_ac::AcHandlerError> {
        let resolved = self.resolve_byok(&req.tenant, &req.action_digest).await?;
        self.encrypt_body(&resolved.plan, &req.result_payload, None)
            .await
    }

    /// BYOK AC read hook (test-facing): resolve + decrypt the stored body. The
    /// production `lookup` path resolves ONCE and calls [`Self::decrypt_body`].
    #[cfg(test)]
    async fn byok_decrypt_for_lookup(
        &self,
        tenant: &str,
        action_digest: &str,
        stored: Vec<u8>,
    ) -> Result<Vec<u8>, corelink_handler_ac::AcHandlerError> {
        let resolved = self.resolve_byok(tenant, action_digest).await?;
        self.decrypt_body(&resolved.plan, stored, None).await
    }

    /// BYOK AC delete-reclaim hook (test-facing): resolve + reclaim the Mode-B
    /// `byok_envelope` row (surface = `ac`), mirroring the post-R2-delete step in
    /// the production AC `delete` path.
    #[cfg(test)]
    async fn byok_reclaim_for_delete(
        &self,
        tenant: &str,
        action_digest: &str,
    ) -> Result<(), String> {
        let resolved = self
            .resolve_byok(tenant, action_digest)
            .await
            .map_err(|e| format!("resolve: {e}"))?;
        self.reclaim_byok_envelope(&resolved.plan, None).await
    }

    /// Derive the R2 key for a (tenant, action_digest) pair. Mirrors
    /// `R2CasHandler::r2_key`; the AC bucket uses the same layout and
    /// the same always-HMAC tenant prefix (F1/F2). The handler cannot
    /// be built without a TDK on the production path (see
    /// [`build_r2_ac_handler_from_env`]).
    fn r2_key(&self, tenant: &str, action_digest: &str) -> Result<String, String> {
        if !is_canonical_ac_digest(action_digest) {
            return Err("non-canonical AC action digest (lowercase 64-hex required)".to_owned());
        }
        let prefix = tenant_prefix(self.tdk.as_ref(), tenant)?;
        // AC keys are native (BLAKE3) keyspace — REAPI AC action digests are
        // stored under the same scheme as native CAS (no `bazel/sha256/` tag).
        Ok(R2S3Client::blob_key(
            &self.ac_region,
            &prefix,
            action_digest,
            DigestAlgo::Blake3,
        ))
    }

    /// Derive an immutable generation-qualified AC key while validating each
    /// caller-controlled component before joining path segments.
    fn generation_r2_key(
        &self,
        tenant: &str,
        generation: i64,
        allocation_id: &str,
        action_digest: &str,
    ) -> Result<String, String> {
        if !is_canonical_ac_digest(action_digest) {
            return Err("non-canonical AC action digest (lowercase 64-hex required)".to_owned());
        }
        let qualified = crate::storage::byok_generation_catalog::generation_qualified_digest(
            generation,
            allocation_id,
            action_digest,
        )?;
        let prefix = tenant_prefix(self.tdk.as_ref(), tenant)?;
        Ok(R2S3Client::blob_key(
            &self.ac_region,
            &prefix,
            &qualified,
            DigestAlgo::Blake3,
        ))
    }

    /// Emit the (avail, latency) SLI pair for the lookup path. The
    /// update path folds availability into `AvailAcLookup` per the
    /// canonical-15 metric registry discipline (see
    /// `InMemoryAcHandler::update`).
    fn emit_lookup_sli(&self, is_error: bool, latency_us: u64) {
        use corelink_handler_ac::{Sli, SliObservation};
        self.sli.observe(SliObservation::new(
            Sli::AvailAcLookup,
            is_error,
            latency_us,
        ));
        self.sli.observe(SliObservation::new(
            Sli::LatencyAcHitP99,
            is_error,
            latency_us,
        ));
    }

    /// LIST has a customer-visible availability/latency window, but it is not
    /// an AC lookup hit. Keep the hit-latency catalog honest by excluding list
    /// operations from `LatencyAcHitP99`.
    fn emit_list_sli(&self, is_error: bool, latency_us: u64) {
        use corelink_handler_ac::{Sli, SliObservation};
        self.sli.observe(SliObservation::new(
            Sli::AvailAcLookup,
            is_error,
            latency_us,
        ));
    }

    fn emit_update_sli(&self, is_error: bool, latency_us: u64) {
        use corelink_handler_ac::{Sli, SliObservation};
        self.sli.observe(SliObservation::new(
            Sli::AvailAcLookup,
            is_error,
            latency_us,
        ));
    }
}
