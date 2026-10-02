/// A sync `CasReadHandler` + `CasWriteHandler` backed by [`R2S3Client`].
///
/// Wraps the async S3 operations with
/// `tokio::runtime::Handle::current().block_on(...)` so the sync
/// handler traits can drive async I/O from within a tokio runtime.
#[non_exhaustive]
pub struct R2CasHandler {
    client: R2S3Client,
    /// The R2 region string (e.g. `"iad"`) used as key prefix.
    cas_region: String,
    /// Tenant derivation key for `derive_prefix`. Wrapped in
    /// `Option<...>` because tests construct without a TDK.
    tdk: Option<TenantDerivationKey>,
    audit: Arc<dyn AuditSink>,
    /// Concrete durable sink used only by the explicit batch-exists
    /// throughput exception. Single-object reads and lists always use the
    /// synchronous `audit` trait object and serialize audit success before
    /// storage dispatch.
    audit_async: Option<Arc<crate::storage::d1_audit_sink::D1AuditOutboxSink>>,
    /// D1 lease that fences the live CAS write path against GC purge epochs.
    /// `None` is retained only for in-memory/unit-test constructors; the
    /// production builder refuses to mount R2 without this dependency.
    cas_write_fence: Option<Arc<dyn crate::storage::cas_write_fence::CasWriteFence>>,
    sli: Arc<dyn SliObserver>,
    /// BYOK Wave 3a (GATED-INERT): per-tenant BYOK config cache. `None` on the
    /// non-BYOK build / tests → the plaintext path runs unchanged. When `Some`
    /// AND a tenant is `active`, the CAS write/read path encrypts at rest.
    byok_config_cache: Option<Arc<ByokConfigCache>>,
    /// BYOK Wave 3a: the Tcs resolver (CMK-unwrap → convergence secret). `None`
    /// → plaintext path. Both this and `byok_config_cache` must be `Some` for
    /// encryption to engage (frozen policy §3).
    tcs_resolver: Option<Arc<TcsResolver>>,
    /// BYOK Wave 3c: the Mode-B (random-DEK) encryptor + `byok_envelope` store.
    /// `None` → a tenant configured for `crypto_mode='random'` fails CLOSED on
    /// the data plane (never plaintext); Mode A (convergent) is unaffected.
    byok_mode_b: Option<Arc<ModeBEncryptor>>,
    /// Tenant-wide transition exclusion plus authoritative generation catalog.
    byok_runtime_gate: Option<Arc<dyn ByokRuntimeGate>>,
    #[cfg(test)]
    test_post_header_body_timeout: bool,
}

impl core::fmt::Debug for R2CasHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("R2CasHandler")
            .field("cas_region", &self.cas_region)
            .finish_non_exhaustive()
    }
}

impl R2CasHandler {
    /// Construct an `R2CasHandler`.
    ///
    /// `tdk_bytes` is a 32-byte secret key loaded from env/KMS. Pass
    /// `None` only in tests that use a dev/zero TDK.
    #[must_use]
    pub fn new(
        client: R2S3Client,
        cas_region: impl Into<String>,
        tdk_bytes: Option<Zeroizing<[u8; 32]>>,
        audit: Arc<dyn AuditSink>,
        sli: Arc<dyn SliObserver>,
    ) -> Self {
        let tdk = tdk_bytes.map(TenantDerivationKey::from_bytes);
        Self {
            client,
            cas_region: cas_region.into(),
            tdk,
            audit,
            audit_async: None,
            cas_write_fence: None,
            sli,
            byok_config_cache: None,
            tcs_resolver: None,
            byok_mode_b: None,
            byok_runtime_gate: None,
            #[cfg(test)]
            test_post_header_body_timeout: false,
        }
    }

    /// Test-only seam that sends the real R2 body collector timeout through
    /// this production `CasReadHandler` implementation.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_test_post_header_body_timeout(mut self) -> Self {
        self.test_post_header_body_timeout = true;
        self
    }

    /// Attach the concurrent-list async audit seam: `audit_async` MUST be
    /// the SAME sink as the `audit` passed to [`Self::new`] (the production
    /// builder enforces this by cloning one `Arc<D1AuditOutboxSink>` into
    /// both places — see [`build_r2_cas_handler_from_env`]). Passing a
    /// DIFFERENT sink here would let `list()` write its audit row to one
    /// sink while every other call writes to another — never do that.
    ///
    /// Optional: a handler with `audit_async` left `None` keeps every path
    /// fully serial. The production builder wires the same durable sink into
    /// both audit interfaces.
    #[must_use]
    pub fn with_async_audit(
        mut self,
        audit_async: Arc<crate::storage::d1_audit_sink::D1AuditOutboxSink>,
    ) -> Self {
        self.audit_async = Some(audit_async);
        self
    }

    /// Attach the D1-backed CAS write fence.
    ///
    /// The production builder wires this to the same D1 database used by GC.
    /// A handler with storage credentials but without this dependency is not
    /// constructed; test-only handlers may omit it to keep their hermetic
    /// in-memory behavior.
    #[must_use]
    pub fn with_cas_write_fence(
        mut self,
        fence: Arc<dyn crate::storage::cas_write_fence::CasWriteFence>,
    ) -> Self {
        self.cas_write_fence = Some(fence);
        self
    }

    /// Attach the BYOK Wave-3a collaborators (config cache + Tcs resolver),
    /// enabling convergent encryption-at-rest for `active` tenants.
    ///
    /// GATED-INERT: encryption engages ONLY for a tenant whose
    /// `tenant_byok_config.state == 'active'`; every other tenant (and the
    /// `_public` namespace) keeps the exact plaintext path. Production router
    /// assembly calls this only after it has constructed the one real-provider
    /// [`DataPlaneByok`](crate::storage::byok_cas::DataPlaneByok) set; the
    /// default build has no such provider and remains plaintext.
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

    /// Attach the BYOK Wave-3c Mode-B (random-DEK) encryptor. GATED-INERT: only
    /// engaged for an `active` tenant whose `crypto_mode='random'`. Without it,
    /// such a tenant fails CLOSED on the data plane (never plaintext); Mode A is
    /// unaffected. Chains after [`Self::with_byok`].
    #[must_use]
    pub fn with_byok_random(mut self, mode_b: Arc<ModeBEncryptor>) -> Self {
        self.byok_mode_b = Some(mode_b);
        self
    }

    /// Attach only the config view of an UNARMED (no-provider) data plane.
    ///
    /// Such a process cannot encrypt or decrypt, so a tenant whose BYOK state
    /// is anything but `inactive` is refused fail-closed wherever the handler
    /// resolves its BYOK plan (reads, existence probes and writes), and every
    /// other tenant keeps the plaintext path (#1648).
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
        context: Option<&dyn corelink_handler_cas::CasWriteOperationContext>,
    ) -> Result<Option<ByokDataGuard>, CasHandlerError> {
        if let Some(context) = context {
            let context = match context
                .as_any()
                .downcast_ref::<corelink_handler_cas::CasWriteContextBundle>()
            {
                Some(bundle) => match bundle.data_plane() {
                    Some(context) => context,
                    None => return Ok(None),
                },
                None => context,
            };
            let pin = context
                .as_any()
                .downcast_ref::<crate::storage::byok_cas::ByokOperationPin>()
                .ok_or_else(|| {
                    CasHandlerError::Internal(
                        "unsupported CAS operation context on R2 BYOK write".to_owned(),
                    )
                })?;
            return pin
                .take_guard(tenant)
                .map(Some)
                .map_err(|error| CasHandlerError::Internal(format!("BYOK operation pin: {error}")));
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
        .map_err(|error| CasHandlerError::Internal(format!("BYOK data gate: {error}")))
    }

    fn validate_byok_return(
        &self,
        guard: Option<&mut ByokDataGuard>,
    ) -> Result<(), CasHandlerError> {
        let Some(guard) = guard else {
            return Ok(());
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(guard.finish(true)))
            .map_err(|error| CasHandlerError::Internal(format!("BYOK return validation: {error}")))
    }

    fn finish_byok_mutation(
        &self,
        guard: Option<&mut ByokDataGuard>,
    ) -> Result<(), CasHandlerError> {
        let Some(guard) = guard else {
            return Ok(());
        };
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(guard.finish(false)))
            .map_err(|error| CasHandlerError::Internal(format!("BYOK data release: {error}")))
    }

    /// Resolve the BYOK plan for a (tenant, digest, algo): the **physical R2 key
    /// digest** (§4-hardened for an active tenant — audit H-4) plus the body
    /// crypto plan. Single source of truth for the read/write/exists/delete
    /// paths.
    ///
    /// - `Plaintext` — BYOK not wired / not configured / inactive / `_public`:
    ///   the physical digest is the RAW digest (byte-identical to today).
    /// - `Convergent` / `Random` — active: the physical digest is
    ///   `harden_digest(tcs, digest)`; the body plan carries the real-digest
    ///   [`CryptoContext`].
    /// - `Err(..)` — active-but-unresolvable (KMS/Tcs down, Mode-B unwired,
    ///   partial): FAIL CLOSED (5xx); NEVER plaintext.
    async fn resolve_byok_with_guard(
        &self,
        tenant: &str,
        digest: &str,
        algo: DigestAlgo,
        guard: Option<&ByokDataGuard>,
    ) -> Result<ByokResolved, CasHandlerError> {
        let plaintext = || ByokResolved {
            physical_digest: digest.to_owned(),
            plan: ByokBodyPlan::Plaintext,
        };
        // No BYOK collaborators at all (dev/CI, no durable storage): the
        // existing plaintext path runs unchanged — no D1 hop, no behaviour change.
        let Some(cache) = self.byok_config_cache.as_ref() else {
            return Ok(plaintext());
        };
        // `_public` is deterministic public content with no secret — it MUST stay
        // plaintext (raw key) so cross-tenant dedup is preserved (plan §3).
        if tenant == crate::adapter_cache::PUBLIC_NAMESPACE {
            return Ok(plaintext());
        }
        // ONE D1 read on a cache miss; cached (incl. the not-configured answer).
        // A config error fails closed — never a silent plaintext downgrade.
        let authoritative = match guard {
            Some(guard) => Some(guard.intent().map_err(CasHandlerError::Internal)?),
            None => None,
        };
        let cfg = match authoritative {
            Some(intent) => intent.config.clone(),
            None => cache
                .get(tenant)
                .await
                .map_err(|e| CasHandlerError::Internal(format!("byok config read: {e}")))?,
        };
        let Some(cfg) = cfg else {
            return Ok(plaintext());
        };
        // An UNARMED (no-provider) process has the config view only: it serves
        // an `inactive` tenant in plaintext and refuses every other one.
        let Some(resolver) = self.tcs_resolver.as_ref() else {
            return match unarmed_engagement(&cfg) {
                ByokEngagement::Plaintext => Ok(plaintext()),
                ByokEngagement::FailClosed(why) => Err(CasHandlerError::Internal(format!(
                    "byok {why} (fail-closed)"
                ))),
                ByokEngagement::Encrypt(_) => Err(CasHandlerError::Internal(format!(
                    "byok {UNARMED_REFUSAL} (fail-closed)"
                ))),
            };
        };
        match engagement_for(&cfg) {
            ByokEngagement::Plaintext => Ok(plaintext()),
            ByokEngagement::FailClosed(why) => Err(CasHandlerError::Internal(format!(
                "byok active but {why}; refusing to fall back to plaintext (fail-closed)"
            ))),
            ByokEngagement::Encrypt(mode) => {
                let key_id = cfg.cmk_key_id.clone().unwrap_or_default();
                // The Tcs is resolved for BOTH modes — Mode A uses it for the
                // convergent DEK, and BOTH modes use it to §4-harden the physical
                // R2 key (audit H-4: the on-disk key reveals nothing without it).
                let tcs = resolver
                    .resolve_at_version(&cfg, authoritative.and_then(|intent| intent.tcs_version))
                    .await
                    .map_err(|e| CasHandlerError::Internal(format!("byok tcs resolve: {e}")))?;
                let physical_digest = harden_digest(&tcs, digest);
                let plan = match mode {
                    ByokCryptoMode::Convergent => ByokBodyPlan::Convergent {
                        tcs,
                        ctx: cas_crypto_context(tenant, digest, algo, &key_id),
                    },
                    ByokCryptoMode::Random => {
                        if self.byok_mode_b.is_none() {
                            return Err(CasHandlerError::Internal(
                                "byok active Mode B (random) but the random-mode encryptor is \
                                 not wired; refusing to fall back to plaintext (fail-closed)"
                                    .to_owned(),
                            ));
                        }
                        ByokBodyPlan::Random {
                            ctx: cas_crypto_context_for(
                                tenant,
                                digest,
                                algo,
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
        digest: &str,
        algo: DigestAlgo,
    ) -> Result<ByokResolved, CasHandlerError> {
        self.resolve_byok_with_guard(tenant, digest, algo, None)
            .await
    }

    /// Derive the R2 key for a (tenant, digest) pair.
    ///
    /// The tenant prefix is ALWAYS `derive_prefix(tdk, tenant_uuid)` —
    /// an unpredictable, secret-keyed HMAC namespace (layer 5 of
    /// `INV-TENANT-ISOLATION`). The handler cannot be constructed
    /// without a TDK on the production path (see
    /// [`build_r2_cas_handler_from_env`], which fails closed when
    /// `R2_TDK_HEX` is unset) — so the raw-padded public-prefix
    /// fallback used by simple non-UUID test fixtures is gated behind
    /// `#[cfg(test)]` and is unreachable in production (F1/F2).
    fn r2_key(&self, tenant: &str, digest: &str, algo: DigestAlgo) -> Result<String, String> {
        let prefix = tenant_prefix(self.tdk.as_ref(), tenant)?;
        Ok(R2S3Client::blob_key(
            &self.cas_region,
            &prefix,
            digest,
            algo,
        ))
    }

    /// Emit both SLI observations (availability + latency).
    /// Emit the availability + latency pair for one handler entry.
    ///
    /// `latency_us` is the wall-clock the handler entry took, which is
    /// what [`SliObservation`]'s field has always been documented as
    /// carrying. Every CAS/AC call site used to pass a literal `0`
    /// here, which made `LatencyCasGetP99` / `LatencyCasPutP99` /
    /// `LatencyAcHitP99` samples of nothing — a latency SLI whose every
    /// sample is zero is not a loose measurement (B-057). The callers
    /// now start an `Instant` at handler entry and pass the elapsed
    /// microseconds, so the latency SLIs observe the same window the
    /// availability SLIs count.
    fn emit_sli(
        &self,
        avail: corelink_handler_cas::observer::Sli,
        lat: corelink_handler_cas::observer::Sli,
        is_error: bool,
        latency_us: u64,
    ) {
        self.sli
            .observe(SliObservation::new(avail, is_error, latency_us));
        self.sli
            .observe(SliObservation::new(lat, is_error, latency_us));
    }

    /// Read one CAS object through the B-051 pre-materialisation ceiling.
    /// Every production and test read path MUST use this helper; keeping the
    /// capped storage read in one place prevents
    /// a path-specific `get()` from bypassing the B-077 process-wide envelope.
    /// `max_bytes` is supplied by the request so batch-read can use its tighter
    /// 8 MiB object ceiling while single reads retain the ordinary ceiling.
    async fn get_capped_for_read(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, CasHandlerError> {
        match self.client.get_capped(key, max_bytes).await {
            Ok(CappedGet::Found(bytes)) => Ok(Some(bytes)),
            Ok(CappedGet::Missing) => Ok(None),
            Ok(CappedGet::TooLarge { actual_bytes }) => {
                warn!(
                    key,
                    actual_bytes = ?actual_bytes,
                    limit_bytes = max_bytes,
                    "R2CasHandler::read refused an over-size object"
                );
                Err(CasHandlerError::ObjectTooLarge {
                    actual_bytes: actual_bytes.unwrap_or(0),
                    limit_bytes: max_bytes,
                })
            }
            Err(e) => {
                warn!(error = %e, key, "R2CasHandler::read error");
                Err(CasHandlerError::Internal(e))
            }
        }
    }
}
