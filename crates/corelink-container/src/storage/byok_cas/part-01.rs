/// Async store for the per-blob Mode-B `byok_envelope` rows (the wrapped DEK +
/// nonce). The production impl is [`D1ByokEnvelopeStore`]; tests supply a mock.
#[async_trait]
pub trait ByokEnvelopeStore: Send + Sync + core::fmt::Debug {
    /// Load the envelope row for `(tenant, blob_key)` (`Ok(None)` ⇒ absent).
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a D1 transport / decode failure is `Err(String)` — never
    /// coerced into "no row".
    async fn get_envelope(
        &self,
        tenant: &str,
        blob_key: &str,
    ) -> Result<Option<ByokEnvelopeRow>, String>;

    /// Insert the envelope row IFF absent (`INSERT … ON CONFLICT DO NOTHING`).
    /// MUST NOT overwrite an existing row (audit C2: a fresh random DEK over an
    /// existing row orphans the stored ciphertext). The caller re-reads the
    /// authoritative row afterwards to converge on the winner of any race.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on any D1 transport / encode failure.
    async fn put_envelope_if_absent(
        &self,
        tenant: &str,
        blob_key: &str,
        row: &ByokEnvelopeRow,
        created_at_ms: i64,
    ) -> Result<(), String>;

    /// Reclaim (delete) the envelope row for `(tenant, blob_key)` — the inverse
    /// of [`Self::put_envelope_if_absent`], called on blob DELETE so a deleted
    /// Mode-B blob does not leave its wrapped-DEK row lingering (BYOK Wave 4a
    /// crypto-shred reclaim). Idempotent: deleting an absent row is a no-op.
    /// `blob_key` is the SURFACE-QUALIFIED key ([`envelope_blob_key`]), matching
    /// exactly the key the write path used.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on any D1 transport / encode failure. The caller
    /// treats this as a reclaim failure (warn + continue), NEVER a delete
    /// failure — the R2 object is already gone, so an orphaned envelope row
    /// wraps nothing (the safe-fail direction).
    async fn delete_envelope(&self, tenant: &str, blob_key: &str) -> Result<(), String>;

    /// Persist a recoverable reconciliation intent when the R2 object exists
    /// but the metadata commit did not.  Mode B must not delete an ambiguous
    /// object: a later reconciler needs the tenant, plain digest, physical R2
    /// key, and the authoritative envelope row to finish or quarantine it.
    async fn record_reconciliation_intent(
        &self,
        tenant: &str,
        digest: &str,
        physical_r2_key: &str,
        reason: &str,
        created_at_ms: u64,
    ) -> Result<(), String>;
}

/// Production [`ByokEnvelopeStore`] over the async D1 row seam (reuses
/// [`ByokConfigRows`], which [`D1HttpClient`] already implements — the
/// `query_rows` seam runs both the `SELECT` and the idempotent `INSERT`).
#[derive(Debug)]
#[non_exhaustive]
pub struct D1ByokEnvelopeStore<R = D1HttpClient> {
    rows: Arc<R>,
}

impl<R: ByokConfigRows> D1ByokEnvelopeStore<R> {
    /// Wire the store over an async row source.
    #[must_use]
    pub fn new(rows: Arc<R>) -> Self {
        Self { rows }
    }
}

#[async_trait]
impl<R: ByokConfigRows + core::fmt::Debug + 'static> ByokEnvelopeStore for D1ByokEnvelopeStore<R> {
    async fn get_envelope(
        &self,
        tenant: &str,
        blob_key: &str,
    ) -> Result<Option<ByokEnvelopeRow>, String> {
        let rows = self
            .rows
            .query_rows(
                "SELECT wrapped_dek, kms_provider, kms_key_id, kms_region, \
                 encryption_context, aes_gcm_nonce \
                 FROM byok_envelope WHERE tenant_id = ?1 AND blob_hash = ?2 LIMIT 1",
                vec![json!(tenant), json!(blob_key)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let wrapped_dek = decode_blob(
            row.get("wrapped_dek")
                .ok_or("byok_envelope.wrapped_dek missing")?,
        )?;
        let kms_provider = parse_provider_kind(
            row.get("kms_provider")
                .and_then(Value::as_str)
                .ok_or("byok_envelope.kms_provider missing")?,
        )?;
        let kms_key_id = row
            .get("kms_key_id")
            .and_then(Value::as_str)
            .ok_or("byok_envelope.kms_key_id missing")?
            .to_owned();
        let kms_region = row
            .get("kms_region")
            .and_then(Value::as_str)
            .ok_or("byok_envelope.kms_region missing")?
            .to_owned();
        let enc_ctx_str = row
            .get("encryption_context")
            .and_then(Value::as_str)
            .ok_or("byok_envelope.encryption_context missing")?;
        let encryption_context: Value = serde_json::from_str(enc_ctx_str)
            .map_err(|e| format!("byok_envelope.encryption_context JSON: {e}"))?;
        let nonce_vec = decode_blob(
            row.get("aes_gcm_nonce")
                .ok_or("byok_envelope.aes_gcm_nonce missing")?,
        )?;
        if nonce_vec.len() != 12 {
            return Err(format!(
                "byok_envelope.aes_gcm_nonce must be 12 bytes, got {}",
                nonce_vec.len()
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);
        Ok(Some(ByokEnvelopeRow {
            wrapped_dek,
            kms_provider,
            kms_key_id,
            kms_region,
            encryption_context,
            nonce,
        }))
    }

    async fn put_envelope_if_absent(
        &self,
        tenant: &str,
        blob_key: &str,
        row: &ByokEnvelopeRow,
        created_at_ms: i64,
    ) -> Result<(), String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let enc_ctx_str = serde_json::to_string(&row.encryption_context)
            .map_err(|e| format!("byok_envelope.encryption_context encode: {e}"))?;
        self.rows
            .query_rows(
                "INSERT INTO byok_envelope \
                 (tenant_id, blob_hash, wrapped_dek, kms_provider, kms_key_id, kms_region, \
                  encryption_context, aes_gcm_nonce, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(tenant_id, blob_hash) DO NOTHING",
                vec![
                    json!(tenant),
                    json!(blob_key),
                    json!(b64.encode(&row.wrapped_dek)),
                    json!(provider_kind_str(row.kms_provider)),
                    json!(row.kms_key_id),
                    json!(row.kms_region),
                    json!(enc_ctx_str),
                    json!(b64.encode(row.nonce)),
                    json!(created_at_ms),
                ],
            )
            .await?;
        Ok(())
    }

    async fn delete_envelope(&self, tenant: &str, blob_key: &str) -> Result<(), String> {
        // `blob_key` is the surface-qualified PK component (`cas:<digest>` /
        // `ac:<digest>`) — byte-for-byte the key the write path persisted.
        self.rows
            .query_rows(
                "DELETE FROM byok_envelope WHERE tenant_id = ?1 AND blob_hash = ?2",
                vec![json!(tenant), json!(blob_key)],
            )
            .await?;
        Ok(())
    }

    async fn record_reconciliation_intent(
        &self,
        tenant: &str,
        digest: &str,
        physical_r2_key: &str,
        reason: &str,
        created_at_ms: u64,
    ) -> Result<(), String> {
        // This row is the durable hand-off for a Mode-B object whose R2 PUT
        // won but whose metadata commit failed.  Migration 0115's trigger
        // emits the matching audit_outbox event in the same D1 transaction.
        self.rows
            .query_rows(
                "INSERT INTO cas_reconciliation_intent \
                 (tenant_id, digest, surface, physical_r2_key, state, reason, \
                  attempts, created_at_ms, updated_at_ms) \
                 VALUES (?1, ?2, 'cas', ?3, 'pending', ?4, 0, ?5, ?5) \
                 ON CONFLICT(tenant_id, digest, surface) DO UPDATE SET \
                   physical_r2_key = excluded.physical_r2_key, \
                   state = 'pending', reason = excluded.reason, \
                   updated_at_ms = excluded.updated_at_ms",
                vec![
                    json!(tenant),
                    json!(digest),
                    json!(physical_r2_key),
                    json!(reason),
                    json!(created_at_ms),
                ],
            )
            .await?;
        Ok(())
    }
}

/// Mode B (random, max-isolation) encryptor — random per-blob DEK + random
/// nonce, wrapped by the customer CMK and persisted in `byok_envelope` (plan
/// §2). NO dedup (each blob a unique DEK), so the caller MUST NOT apply the
/// convergent HEAD-skip to a Mode-B write.
///
/// Idempotency / atomicity (audit C2): the authoritative `(DEK, nonce)` is the
/// PERSISTED envelope row. On a fresh write a random `(DEK, nonce)` is minted,
/// `INSERT … ON CONFLICT DO NOTHING`-ed, then the row is re-read; the stored
/// ciphertext is ALWAYS derived from the authoritative row via
/// [`EnvelopeEncryptor::encrypt_body_with_wrapped`]. Because AES-GCM is
/// deterministic given `(key, nonce, plaintext, aad)`, every writer (a race
/// loser, a re-PUT of the same `blob_hash`) produces byte-identical ciphertext —
/// the envelope row is never orphaned and the R2 PUT is idempotent.
#[non_exhaustive]
pub struct ModeBEncryptor {
    kms: Arc<dyn KmsProvider>,
    enc: EnvelopeEncryptor<Arc<dyn KmsProvider>>,
    store: Arc<dyn ByokEnvelopeStore>,
}

impl core::fmt::Debug for ModeBEncryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModeBEncryptor").finish_non_exhaustive()
    }
}

impl ModeBEncryptor {
    /// Build over a KMS provider + an envelope store with an explicit DEK-cache
    /// TTL (seconds, ≤300 — INV-BYOK-CRYPTO-SOVEREIGNTY).
    ///
    /// # Errors
    ///
    /// Returns [`BYOKError::DekCacheTtlViolation`] if `dek_ttl_seconds > 300`.
    pub fn new(
        kms: Arc<dyn KmsProvider>,
        store: Arc<dyn ByokEnvelopeStore>,
        dek_ttl_seconds: u64,
    ) -> Result<Self, BYOKError> {
        let cache = DekCache::new(dek_ttl_seconds)?;
        let enc = EnvelopeEncryptor::new(Arc::clone(&kms), cache);
        Ok(Self { kms, enc, store })
    }

    /// Build with the canonical [`BYOK_TCS_TTL_SECONDS`] (300 s) DEK-cache TTL.
    ///
    /// # Errors
    ///
    /// Mirrors [`Self::new`] (infallible in practice at 300 s).
    pub fn with_default_ttl(
        kms: Arc<dyn KmsProvider>,
        store: Arc<dyn ByokEnvelopeStore>,
    ) -> Result<Self, BYOKError> {
        Self::new(kms, store, BYOK_TCS_TTL_SECONDS)
    }

    /// Rebind a decoder to the exact source-generation KMS provider while
    /// preserving the authoritative envelope store.
    pub fn with_provider(&self, kms: Arc<dyn KmsProvider>) -> Result<Self, BYOKError> {
        Self::with_default_ttl(kms, Arc::clone(&self.store))
    }

    /// The CMK identity for a context — the injected KMS provider is the custody
    /// authority (its kind + region), keyed by the context's CMK ARN.
    fn key_id(&self, ctx: &CryptoContext) -> KmsKeyId {
        KmsKeyId {
            provider: self.kms.provider_kind(),
            key_arn_or_id: ctx.key_id.clone(),
            region: self.kms.region().to_owned(),
        }
    }

    /// Mode-B encrypt: return the on-disk bytes to STORE
    /// (`MODE_B_MAGIC ‖ ciphertext`). Writes (idempotently) the `byok_envelope`
    /// row BEFORE deriving the ciphertext, so the wrapped DEK is durable before
    /// any R2 PUT. See the type docs for the idempotency proof.
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: any envelope read/write or KMS wrap/unwrap failure is
    /// `Err(String)` — the caller refuses the write (never stores plaintext).
    pub async fn encrypt(&self, plaintext: &[u8], ctx: &CryptoContext) -> Result<Vec<u8>, String> {
        let blob_key = envelope_blob_key(&ctx.surface, &ctx.plaintext_digest);
        self.encrypt_with_blob_key(plaintext, ctx, &blob_key).await
    }

    /// Encrypt a generation-catalog allocation under its own envelope row.
    ///
    /// The allocation only qualifies the envelope-store identity. `ctx` is
    /// passed unchanged to KMS and AES-GCM, preserving the raw plaintext
    /// digest in the encryption context and AAD.
    pub async fn encrypt_for_allocation(
        &self,
        plaintext: &[u8],
        ctx: &CryptoContext,
        allocation_id: &str,
    ) -> Result<Vec<u8>, String> {
        let blob_key =
            allocation_envelope_blob_key(&ctx.surface, &ctx.plaintext_digest, allocation_id)?;
        self.encrypt_with_blob_key(plaintext, ctx, &blob_key).await
    }

    async fn encrypt_with_blob_key(
        &self,
        plaintext: &[u8],
        ctx: &CryptoContext,
        blob_key: &str,
    ) -> Result<Vec<u8>, String> {
        let tenant = ctx.tenant_id.as_str();

        // The authoritative envelope row (a pre-existing one, OR one we mint +
        // persist + re-read so every racer converges on the same DEK).
        let row = match self.store.get_envelope(tenant, blob_key).await? {
            Some(existing) => existing,
            None => {
                let key_id = self.key_id(ctx);
                let blob = self
                    .enc
                    .encrypt_with_ctx(plaintext, &key_id, ctx)
                    .await
                    .map_err(|e| format!("mode-b wrap: {e}"))?;
                let new_row = ByokEnvelopeRow {
                    wrapped_dek: blob.wrapped_dek.ciphertext.clone(),
                    kms_provider: blob.wrapped_dek.provider,
                    kms_key_id: blob.wrapped_dek.key_id.key_arn_or_id.clone(),
                    kms_region: blob.wrapped_dek.key_id.region.clone(),
                    encryption_context: blob
                        .wrapped_dek
                        .encryption_context
                        .clone()
                        .unwrap_or_else(|| ctx.kms_encryption_context()),
                    nonce: blob.nonce,
                };
                self.store
                    .put_envelope_if_absent(tenant, blob_key, &new_row, now_ms())
                    .await?;
                self.store
                    .get_envelope(tenant, blob_key)
                    .await?
                    .ok_or_else(|| {
                        "mode-b envelope row vanished after insert (fail-closed)".to_owned()
                    })?
            }
        };

        // Deterministic ciphertext under the PERSISTED (DEK, nonce).
        let wrapped = row.to_wrapped_dek();
        let ciphertext = self
            .enc
            .encrypt_body_with_wrapped(plaintext, &wrapped, &row.nonce, ctx)
            .await
            .map_err(|e| format!("mode-b encrypt: {e}"))?;
        let mut out = Vec::with_capacity(MODE_B_MAGIC.len() + ciphertext.len());
        out.extend_from_slice(MODE_B_MAGIC);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Mode-B decrypt: fetch the `byok_envelope` row → unwrap the DEK → AES-GCM
    /// decrypt the body. `stored` is `MODE_B_MAGIC ‖ ciphertext`.
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a non-magic object, a missing envelope row, or any KMS /
    /// AEAD failure is `Err(String)` — the raw stored bytes are NEVER served.
    pub async fn decrypt(&self, stored: &[u8], ctx: &CryptoContext) -> Result<Vec<u8>, String> {
        let blob_key = envelope_blob_key(&ctx.surface, &ctx.plaintext_digest);
        self.decrypt_with_blob_key(stored, ctx, &blob_key).await
    }

    /// Decrypt bytes published by [`Self::encrypt_for_allocation`].
    pub async fn decrypt_for_allocation(
        &self,
        stored: &[u8],
        ctx: &CryptoContext,
        allocation_id: &str,
    ) -> Result<Vec<u8>, String> {
        let blob_key =
            allocation_envelope_blob_key(&ctx.surface, &ctx.plaintext_digest, allocation_id)?;
        self.decrypt_with_blob_key(stored, ctx, &blob_key).await
    }

    /// Decrypt a published allocation while asserting the source envelope's
    /// immutable KMS identity. Rotation callers must use this boundary rather
    /// than the current tenant policy: a missing or mismatched provider, key,
    /// or region is a hard error.
    pub async fn decrypt_for_allocation_with_identity(
        &self,
        stored: &[u8],
        ctx: &CryptoContext,
        allocation_id: &str,
        provider: KmsProviderKind,
        key_id: &str,
        region: &str,
    ) -> Result<Vec<u8>, String> {
        let blob_key =
            allocation_envelope_blob_key(&ctx.surface, &ctx.plaintext_digest, allocation_id)?;
        self.decrypt_with_blob_key_checked(stored, ctx, &blob_key, Some((provider, key_id, region)))
            .await
    }

    async fn decrypt_with_blob_key(
        &self,
        stored: &[u8],
        ctx: &CryptoContext,
        blob_key: &str,
    ) -> Result<Vec<u8>, String> {
        self.decrypt_with_blob_key_checked(stored, ctx, blob_key, None)
            .await
    }

    async fn decrypt_with_blob_key_checked(
        &self,
        stored: &[u8],
        ctx: &CryptoContext,
        blob_key: &str,
        expected_identity: Option<(KmsProviderKind, &str, &str)>,
    ) -> Result<Vec<u8>, String> {
        let magic = stored
            .get(..MODE_B_MAGIC.len())
            .ok_or_else(|| "stored Mode-B blob too short for magic".to_owned())?;
        if magic != MODE_B_MAGIC {
            return Err("stored object is not a BYOK Mode-B blob (bad magic)".to_owned());
        }
        let ciphertext = stored
            .get(MODE_B_MAGIC.len()..)
            .ok_or_else(|| "stored Mode-B blob missing ciphertext".to_owned())?
            .to_vec();
        let row = self
            .store
            .get_envelope(&ctx.tenant_id, blob_key)
            .await?
            .ok_or_else(|| "mode-b envelope row missing (fail-closed)".to_owned())?;
        if let Some((provider, key_id, region)) = expected_identity {
            if row.kms_provider != provider || row.kms_key_id != key_id || row.kms_region != region
            {
                return Err(
                    "mode-b envelope KMS identity differs from published source identity"
                        .to_owned(),
                );
            }
        }
        let blob = EncryptedBlob {
            wrapped_dek: row.to_wrapped_dek(),
            ciphertext,
            nonce: row.nonce,
        };
        self.enc
            .decrypt_with_ctx(&blob, ctx)
            .await
            .map_err(|e| format!("mode-b decrypt: {e}"))
    }

    /// Reclaim the `byok_envelope` row for a deleted Mode-B blob (BYOK Wave 4a
    /// crypto-shred). Resolves the SAME surface-qualified key the write path
    /// minted (`envelope_blob_key(ctx.surface, ctx.plaintext_digest)`) and
    /// deletes the row, so a deleted blob's wrapped DEK does not linger as an
    /// orphan key-material row (a small info-leak + storage leak).
    ///
    /// MUST be called only AFTER the R2 object has been removed: the persisted
    /// wrapped DEK protects the now-deleted ciphertext, so reclaiming it after
    /// the body is gone leaves nothing readable. Idempotent (deleting an absent
    /// row is a no-op).
    ///
    /// # Errors
    ///
    /// Propagates any [`ByokEnvelopeStore::delete_envelope`] failure as
    /// `Err(String)`. The caller treats this as a reclaim failure (warn +
    /// continue), NOT a delete failure — the R2 object is already gone.
    pub async fn reclaim(&self, ctx: &CryptoContext) -> Result<(), String> {
        let blob_key = envelope_blob_key(&ctx.surface, &ctx.plaintext_digest);
        self.store
            .delete_envelope(ctx.tenant_id.as_str(), &blob_key)
            .await
    }

    /// Reclaim the exact envelope selected by a catalog publication.
    pub async fn reclaim_for_allocation(
        &self,
        ctx: &CryptoContext,
        allocation_id: &str,
    ) -> Result<(), String> {
        let blob_key =
            allocation_envelope_blob_key(&ctx.surface, &ctx.plaintext_digest, allocation_id)?;
        self.store
            .delete_envelope(ctx.tenant_id.as_str(), &blob_key)
            .await
    }

    /// Persist a Mode-B orphan/reconciliation intent after an R2 PUT succeeds
    /// but the CAS metadata commit fails.  The caller deliberately keeps the
    /// object and envelope: only the durable reconciler may decide whether to
    /// finalize metadata or quarantine both sides.
    pub async fn record_reconciliation_intent(
        &self,
        ctx: &CryptoContext,
        physical_r2_key: &str,
        reason: &str,
        created_at_ms: u64,
    ) -> Result<(), String> {
        self.store
            .record_reconciliation_intent(
                ctx.tenant_id.as_str(),
                &ctx.plaintext_digest,
                physical_r2_key,
                reason,
                created_at_ms,
            )
            .await
    }
}

/// The engagement decision for a tenant's `state` (Wave 3a/3b/3c).
///
/// `active` engages encryption in the tenant's configured [`ByokCryptoMode`]
/// (Mode A convergent OR Mode B random — both wired as of Wave 3c). `partial`
/// (backfill dual-read — audit H7) is deferred to Wave 4 and fail-closed here.
/// `shredded` is terminal and also fail-closed: treating it as plaintext would
/// let a crypto-shredded tenant create new unencrypted objects. Only tenants
/// with no BYOK lifecycle underway (`inactive`/`pending`) use plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByokEngagement {
    /// Run the plaintext path unchanged (not configured / inactive).
    Plaintext,
    /// Engage encryption in this crypto mode (state `active`).
    Encrypt(ByokCryptoMode),
    /// Active-but-unsupported here → caller must FAIL CLOSED (never plaintext).
    FailClosed(&'static str),
}

/// Decide engagement for a resolved config (single source of truth shared by
/// the write and read paths).
#[must_use]
pub fn engagement_for(cfg: &TenantByokConfig) -> ByokEngagement {
    match cfg.state {
        // Both Mode A (convergent) and Mode B (random) encrypt for an active
        // tenant; the caller dispatches on the carried mode.
        ByokState::Active => ByokEngagement::Encrypt(cfg.crypto_mode),
        // Backfill dual-read (audit H7) deferred to Wave 4 — never plaintext.
        ByokState::Partial => ByokEngagement::FailClosed(
            "BYOK partial/backfill dual-read not wired (deferred to Wave 4)",
        ),
        ByokState::Shredded => ByokEngagement::FailClosed(
            "BYOK tenant is crypto-shredded; storage access is permanently disabled",
        ),
        ByokState::Inactive | ByokState::Pending => ByokEngagement::Plaintext,
    }
}

// ─── Unarmed (no-provider) data plane, #1648 ─────────────────────────────────

/// Why an unarmed process refuses a tenant. A fixed text: it reaches logs and
/// the 5xx body, so it must never carry tenant or key material.
pub const UNARMED_REFUSAL: &str = "this image links no KMS provider, and the tenant's BYOK \
     state is not inactive; refusing to serve it without its keys";

/// Engagement for a process with NO KMS provider compiled in.
///
/// Such a process can never encrypt or decrypt, so only `inactive` is served
/// (in plaintext, exactly like a tenant with no row). Every other state is
/// refused fail-closed, including `pending`: a pending rotation can keep an
/// encrypted source generation, and the cancel path can restore `active`
/// without KMS. An unparseable or NULL state never reaches this function: the
/// config read fails, and the caller refuses the tenant on that error.
#[must_use]
pub fn unarmed_engagement(cfg: &TenantByokConfig) -> ByokEngagement {
    match cfg.state {
        ByokState::Inactive => ByokEngagement::Plaintext,
        ByokState::Pending | ByokState::Active | ByokState::Partial | ByokState::Shredded => {
            ByokEngagement::FailClosed(UNARMED_REFUSAL)
        }
    }
}

/// Every `tenant_byok_config` row an unarmed process must refuse. `<>` alone
/// would drop a NULL state, so NULL is named explicitly.
const UNARMED_ENGAGED_ROWS_SQL: &str = "SELECT tenant_id, mode, crypto_mode, cmk_provider, \
     cmk_key_id, cmk_region, state FROM tenant_byok_config \
     WHERE state IS NULL OR state <> 'inactive'";

/// Engaged-tenant set: tenant id to its parsed row, or to the parse error for
/// a row that cannot be read (that tenant is refused).
type UnarmedEngagedSet = HashMap<String, Result<TenantByokConfig, String>>;

/// The config view of an UNARMED data plane.
///
/// It reads the engaged rows ONCE, on first use, and then answers from
/// memory. So a no-provider process pays no D1 read per request, and booting
/// never touches D1. A failed load is not cached: the request that hit it is
/// refused, and the next use retries. The set is not refreshed afterwards,
/// and that is safe here. With no provider, activation answers 501 before any
/// D1 write. The only KMS-free transitions (cancel, deactivate, an idempotent
/// activation retry) start from a row that is already in the set, so the set
/// can only be stale toward refusing. Arming is an image change, and its
/// rollout replaces this process.
#[derive(Debug)]
pub struct UnarmedByokSnapshot<R = D1HttpClient> {
    rows: Arc<R>,
    engaged: tokio::sync::OnceCell<UnarmedEngagedSet>,
}

impl<R: ByokConfigRows> UnarmedByokSnapshot<R> {
    /// Wire the snapshot over an async row source (production: D1).
    #[must_use]
    pub fn new(rows: Arc<R>) -> Self {
        Self {
            rows,
            engaged: tokio::sync::OnceCell::new(),
        }
    }

    async fn engaged(&self) -> Result<&UnarmedEngagedSet, ByokConfigError> {
        self.engaged
            .get_or_try_init(|| load_unarmed_engaged(&*self.rows))
            .await
    }
}

async fn load_unarmed_engaged<R: ByokConfigRows>(
    rows: &R,
) -> Result<UnarmedEngagedSet, ByokConfigError> {
    let rows = rows
        .query_rows(UNARMED_ENGAGED_ROWS_SQL, Vec::new())
        .await
        .map_err(ByokConfigError::Transport)?;
    let mut engaged = HashMap::with_capacity(rows.len());
    for row in &rows {
        // A row that cannot name its tenant cannot be refused per tenant, so
        // the whole load fails and every private tenant is refused instead.
        let tenant = row
            .get("tenant_id")
            .and_then(Value::as_str)
            .filter(|tenant| !tenant.is_empty())
            .ok_or_else(|| {
                ByokConfigError::Parse("engaged tenant_byok_config row has no tenant_id".to_owned())
            })?;
        let parsed =
            crate::customer_d1::parse_byok_config_row(row).map_err(|error| error.to_string());
        engaged.insert(tenant.to_owned(), parsed);
    }
    Ok(engaged)
}

#[async_trait]
impl<R: ByokConfigRows + core::fmt::Debug + 'static> ByokConfigSource for UnarmedByokSnapshot<R> {
    async fn get_byok_config(
        &self,
        tenant: &str,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        match self.engaged().await?.get(tenant) {
            None => Ok(None),
            Some(Ok(cfg)) => Ok(Some(cfg.clone())),
            Some(Err(error)) => Err(ByokConfigError::Parse(error.clone())),
        }
    }
}
