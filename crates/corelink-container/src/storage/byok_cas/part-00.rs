// BYOK Wave 3a — convergent encryption-at-rest wiring for the **native CAS
// data plane**.
//
// This module is the glue between the Wave-1 crypto primitives
// ([`corelink_byok`]: [`encrypt_convergent`] / [`decrypt_convergent`] /
// [`CryptoContext`] / [`Tcs`] / [`KmsProvider`]) and the Wave-2 control-plane
// read model ([`crate::customer_d1`]: [`TenantByokConfig`] / [`ByokState`]).
// It is consumed by [`crate::storage::r2_s3::R2CasHandler`] on the CAS
// write/read path.
//
// # FEATURE-GATED (the safety envelope)
//
// Per the audited plan `docs/design/2026-06-28-byok-encryption-at-rest-plan.md`
// (§7.2, §11 C1/C2), encryption engages **only** for a tenant whose
// `tenant_byok_config.state == 'active'`. The shipped real-provider image
// attaches every collaborator in the production CAS/AC builders; the default
// no-provider build leaves them absent and its activation route returns 501.
// This makes activation and data-plane engagement one compile-time boundary.
//
// # FAIL-CLOSED (plan §6 — mandatory)
//
// For an **active** tenant, an unavailable config/KMS/Tcs MUST surface as an
// `Err` (5xx) on both write and read — it must NEVER fall back to storing or
// serving plaintext. Every error arm in this module and its callers preserves
// that invariant.
//
// # Scope (Wave 3a) and deferrals
//
// - **In scope:** the native CAS single-shot write+read path, Mode A
//   (convergent), state `active`.
// - **Wave 3b (wired here):** the AC (`R2AcHandler`) path —
//   the action cache encrypts its `result_payload` at rest under
//   [`ac_crypto_context`] (surface `"ac"`, domain-separated from CAS; audit
//   H1), and the ciphertext-size accounting reconciliation (audit C3) is
//   single-sourced via [`BYOK_CLB1_OVERHEAD`].
// - **Wave 3c (wired here):** §4 HMAC'd-digest key hardening and Mode B
//   (`crypto_mode = 'random'`) through the durable envelope store.
// - **Deferred to Wave 4 (documented, never silently skipped):**
//   - The `partial`/backfill dual-read state (audit H7) — fail-closed here
//     (Wave 4).
//   - Migration of pre-existing plaintext objects after a tenant becomes active.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use base64::Engine as _;
use corelink_byok::{
    decrypt_convergent, encrypt_convergent, BYOKError, ConvergentBlob, CryptoAlgo, CryptoContext,
    CryptoMode, DekCache, EncryptedBlob, EnvelopeEncryptor, KmsKeyId, KmsProvider, KmsProviderKind,
    Tcs, WrappedDek,
};
use corelink_handler_cas::DigestAlgo;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::customer_d1::{
    ByokConfigError, ByokConfigRows, ByokCryptoMode, ByokState, D1ByokConfigReader,
    TenantByokConfig,
};
use crate::storage::d1_http::D1HttpClient;
use crate::storage::byok_generation_catalog::{
    runtime_gate_after_rollout_probe, ByokDataGuard, ByokRuntimeGate,
};

/// The CAS surface tag bound into the convergent [`CryptoContext`] — domain
/// separation from other cache surfaces (e.g. the AC surface, [`AC_SURFACE`]).
const CAS_SURFACE: &str = "cas";

/// The AC (action-cache) surface tag bound into the convergent
/// [`CryptoContext`] — domain separation from the CAS surface (Wave 3b, closes
/// audit H1 silent-plaintext). Because `surface` is bound into the JCS bytes
/// that feed BOTH the HKDF `info` and the AEAD AAD (see
/// [`corelink_byok::CryptoContext`]), an AC blob produced under this tag CANNOT
/// be decrypted under a `"cas"` context (and vice-versa) even for the same
/// `(tenant, digest)` — so an AC ciphertext can never be swapped for a CAS one.
const AC_SURFACE: &str = "ac";

/// 4-byte magic prefixing a stored convergent CAS blob (`CoreLink Blob v1`).
///
/// Constant ⇒ does not perturb convergent determinism (identical content still
/// serialises to byte-identical stored bytes ⇒ dedup preserved). Its purpose is
/// fail-closed robustness: on read for an active tenant, a stored object that
/// lacks this magic is NOT a ciphertext blob (e.g. a legacy plaintext object
/// from before activation — a `partial`/backfill concern deferred to Wave 4),
/// so [`decrypt_cas_blob`] refuses it rather than risk mis-decoding.
const BLOB_MAGIC: &[u8; 4] = b"CLB1";

/// On-disk byte overhead of the stored `CLB1` convergent blob over its
/// plaintext — **single-sourced here with the [`encrypt_cas_blob`] format** so
/// quota accounting (audit C3) can never drift from the wire layout.
///
/// Breakdown: `MAGIC ‖ nonce ‖ ciphertext` where `ciphertext = plaintext ‖
/// GCM-tag`, i.e. **4** (magic `CLB1`) + **12** (AES-256-GCM nonce) + **16**
/// (GCM authentication tag) = **32** bytes. The plaintext length is unchanged
/// (AES-GCM is length-preserving), so `stored_len == plaintext_len +
/// BYOK_CLB1_OVERHEAD`. The CAS and AC surfaces share the identical format, so
/// the AC plane (Wave 3b) reuses this same const.
pub const BYOK_CLB1_OVERHEAD: u64 = BLOB_MAGIC.len() as u64 + 12 + 16;

/// Config-cache default TTL — 60 s. After warm-up the non-BYOK hot path adds no
/// D1 hop (a HIT is in-memory; a MISS does ONE D1 read and caches the result,
/// including the "not configured / inactive" answer).
pub const BYOK_CONFIG_TTL_SECONDS: u64 = 60;

/// Tcs-cache default TTL — 300 s (the [`corelink_byok::DekCache`] hard ceiling;
/// the unwrapped Tcs is the convergence secret and lives only inside this
/// window). INV-BYOK-CRYPTO-SOVEREIGNTY.
pub const BYOK_TCS_TTL_SECONDS: u64 = 300;

/// Memory bound for the in-process per-tenant caches (mirrors `DekCache`).
const MAX_CACHE_ENTRIES: usize = 10_000;

/// The one BYOK collaborator set for a native data-plane process.
///
/// Router assembly creates this value once and hands clones to the CAS and AC
/// storage handlers and to both byte-accounting decorators.  Keeping the
/// config cache here is deliberate: a config transition must be observed
/// consistently by the encryption decision and by the reservation size for
/// the same physical object.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DataPlaneByok {
    config_cache: Arc<ByokConfigCache>,
    tcs_resolver: Arc<TcsResolver>,
    mode_b: Arc<ModeBEncryptor>,
    /// The one transition gate which mints operation pins for both accounting
    /// and storage. `None` is only permitted for an explicitly plaintext
    /// rollout; a private write refuses to proceed without a pin.
    runtime_gate: Option<Arc<dyn ByokRuntimeGate>>,
}

impl DataPlaneByok {
    /// Assemble an explicit collaborator set.  This is primarily the
    /// test/integration seam; production uses [`Self::from_env`].
    #[must_use]
    pub fn new(
        config_cache: Arc<ByokConfigCache>,
        tcs_resolver: Arc<TcsResolver>,
        mode_b: Arc<ModeBEncryptor>,
    ) -> Self {
        Self {
            config_cache,
            tcs_resolver,
            mode_b,
            runtime_gate: None,
        }
    }

    /// Attach the process's sole data-plane transition gate.
    #[must_use]
    pub fn with_runtime_gate(mut self, runtime_gate: Arc<dyn ByokRuntimeGate>) -> Self {
        self.runtime_gate = Some(runtime_gate);
        self
    }

    /// Build the production collaborator set once at boot.
    ///
    /// A binary with no compiled real provider has no BYOK data plane and
    /// returns `Ok(None)`.  A real-provider binary with durable storage must
    /// construct every collaborator or refuse boot; it never mounts a second
    /// cache or silently leaves encryption half-wired. This constructor does
    /// not migrate legacy plaintext objects: `partial` remains fail-closed and
    /// the existing Mode-B reconciliation-intent path remains the recovery
    /// authority for an ambiguous R2/D1 commit.
    ///
    /// One state is not "half-wired": a real-provider binary deployed where
    /// the operator has not provisioned KMS credentials at all. No tenant can
    /// become BYOK-active there (the activation route needs the same provider
    /// and returns 501 before any D1 write), so when no tenant is already
    /// engaged the process serves exactly like the no-provider build. If any
    /// tenant IS engaged, boot is still refused. Before #1648 this case also
    /// refused boot, and every production container exited with code 1.
    pub async fn from_env() -> Result<Option<Self>, String> {
        if crate::byok_orchestrator::active_provider()
            == crate::byok_orchestrator::ActiveProvider::Unavailable
        {
            return Ok(None);
        }
        let Some(env) = crate::storage::StorageEnv::from_env() else {
            return Ok(None);
        };
        if !crate::byok_orchestrator::provider_credentials_configured() {
            let d1 = D1HttpClient::new(&env)
                .map_err(|error| format!("BYOK D1 client init failed: {error}"))?;
            let engaged = byok_tenants_engaged(&d1)
                .await
                .map_err(|error| format!("BYOK engagement probe failed: {error}"))?;
            unprovisioned_provider_boot(engaged)?;
            tracing::warn!(
                event = "byok_data_plane_unarmed",
                provider = crate::byok_orchestrator::active_provider().as_str(),
                reason = "kms_credentials_unprovisioned",
                "BYOK KMS credentials are not provisioned and no tenant has BYOK engaged; \
                 serving without the BYOK data plane (activation returns 501 until provisioned)"
            );
            return Ok(None);
        }
        let provider = crate::byok_orchestrator::make_provider()
            .await
            .map_err(|error| format!("BYOK provider init failed: {error}"))?;
        let d1 = Arc::new(
            D1HttpClient::new(&env)
                .map_err(|error| format!("BYOK D1 client init failed: {error}"))?,
        );
        let runtime_gate = runtime_gate_after_rollout_probe(Arc::clone(&d1))
            .await
            .map_err(|error| format!("BYOK runtime gate init failed: {error}"))?;
        let config_source: Arc<dyn ByokConfigSource> =
            Arc::new(D1ByokConfigReader::new(Arc::clone(&d1)));
        let secret_source: Arc<dyn ByokSecretSource> =
            Arc::new(D1ByokSecretReader::new(Arc::clone(&d1)));
        let envelope_store: Arc<dyn ByokEnvelopeStore> =
            Arc::new(D1ByokEnvelopeStore::new(d1));
        let config_cache = Arc::new(ByokConfigCache::with_default_ttl(config_source));
        let tcs_resolver = Arc::new(
            TcsResolver::with_default_ttl(secret_source, Arc::clone(&provider))
                .map_err(|error| format!("BYOK Tcs resolver init failed: {error}"))?,
        );
        let mode_b = Arc::new(
            ModeBEncryptor::with_default_ttl(provider, envelope_store)
                .map_err(|error| format!("BYOK Mode-B init failed: {error}"))?,
        );
        let data_plane = Self::new(config_cache, tcs_resolver, mode_b);
        Ok(Some(match runtime_gate {
            Some(runtime_gate) => data_plane.with_runtime_gate(runtime_gate),
            None => data_plane,
        }))
    }

    /// The authoritative per-tenant config cache shared by storage and accounting.
    #[must_use]
    pub fn config_cache(&self) -> Arc<ByokConfigCache> {
        Arc::clone(&self.config_cache)
    }

    /// The process-wide Tcs resolver for Mode A.
    #[must_use]
    pub fn tcs_resolver(&self) -> Arc<TcsResolver> {
        Arc::clone(&self.tcs_resolver)
    }

    /// The process-wide envelope encryptor for Mode B.
    #[must_use]
    pub fn mode_b(&self) -> Arc<ModeBEncryptor> {
        Arc::clone(&self.mode_b)
    }

    /// The shared transition gate used by storage and operation-pinned
    /// accounting. The returned Arc is a clone of one process-owned authority.
    #[must_use]
    pub fn runtime_gate(&self) -> Option<Arc<dyn ByokRuntimeGate>> {
        self.runtime_gate.as_ref().map(Arc::clone)
    }

    /// Freeze one private-write configuration and transition capability before
    /// accounting reserves bytes. The resulting pin is consumed by the inner
    /// R2 handler, so reservation, encryption, CMK/config version, and physical
    /// overhead all derive from one authoritative operation snapshot.
    pub fn pin_write(
        &self,
        tenant: &str,
        plaintext_len: i64,
    ) -> Result<Option<Arc<ByokOperationPin>>, String> {
        if tenant == crate::adapter_cache::PUBLIC_NAMESPACE {
            return Ok(None);
        }
        let gate = self.runtime_gate().ok_or_else(|| {
            "BYOK runtime gate unavailable; refusing private write without an operation pin"
                .to_owned()
        })?;
        let handle = tokio::runtime::Handle::current();
        let guard = tokio::task::block_in_place(|| {
            handle.block_on(ByokDataGuard::acquire(
                gate,
                tenant,
                crate::byok_transition_fence::DataOperation::Write,
            ))
        })?;
        ByokOperationPin::new(tenant, plaintext_len, guard).map(|pin| Some(Arc::new(pin)))
    }
}

/// Tenant states whose objects need the BYOK collaborators: ciphertext is
/// being written or read (`active`, `partial`), or reads must fail closed
/// after a crypto-shred (`shredded`). `inactive` and `pending` tenants are
/// served in plaintext by the data plane in every build.
const BYOK_ENGAGED_STATES_SQL: &str = "SELECT EXISTS(SELECT 1 FROM tenant_byok_config \
     WHERE state IN ('active','partial','shredded')) AS engaged";

/// Whether any tenant currently needs the BYOK collaborators (see
/// [`BYOK_ENGAGED_STATES_SQL`]). An unreadable answer is an error, never "no".
async fn byok_tenants_engaged(d1: &D1HttpClient) -> Result<bool, String> {
    let rows = d1.query(BYOK_ENGAGED_STATES_SQL, &[]).await?;
    let row = rows
        .first()
        .ok_or_else(|| "BYOK engagement probe returned no row".to_owned())?;
    engaged_flag(row.get("engaged"))
}

/// Decode the engagement probe's `EXISTS` column. Only an exact 0 or 1 is an
/// answer; anything else refuses boot.
fn engaged_flag(value: Option<&Value>) -> Result<bool, String> {
    match value.and_then(Value::as_i64) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err("BYOK engagement probe returned an invalid flag".to_owned()),
    }
}

/// Boot decision for a real-provider binary whose KMS credentials are not
/// provisioned. Serving an engaged tenant without its keys would either store
/// plaintext for it or skip its shred fence, so that case still refuses boot.
fn unprovisioned_provider_boot(engaged: bool) -> Result<(), String> {
    if engaged {
        Err(
            "BYOK KMS credentials are not provisioned while a tenant has BYOK \
             active, partial or shredded; refusing to boot without its keys"
                .to_owned(),
        )
    } else {
        Ok(())
    }
}

/// One non-cloneable BYOK data authority carried from an accounting decorator
/// into the concrete R2 mutation. It is scoped to an individual request and is
/// never stored in a process-global registry.
#[derive(Debug)]
pub struct ByokOperationPin {
    tenant: String,
    committed_len: i64,
    guard: Mutex<Option<ByokDataGuard>>,
}

impl ByokOperationPin {
    fn new(tenant: &str, plaintext_len: i64, guard: ByokDataGuard) -> Result<Self, String> {
        let config = guard.intent()?.config.clone();
        let committed_len = committed_len_for_config(config.as_ref(), plaintext_len)?;
        Ok(Self {
            tenant: tenant.to_owned(),
            committed_len,
            guard: Mutex::new(Some(guard)),
        })
    }

    /// Exact stored byte count derived from this pin's immutable config.
    #[must_use]
    pub const fn committed_len(&self) -> i64 {
        self.committed_len
    }

    /// Consume the guard only for its original tenant. A context cannot be
    /// replayed into another tenant's storage operation.
    pub(crate) fn take_guard(&self, tenant: &str) -> Result<ByokDataGuard, String> {
        if self.tenant != tenant {
            return Err("BYOK operation pin tenant mismatch".to_owned());
        }
        lock(&self.guard)
            .take()
            .ok_or_else(|| "BYOK operation pin was already consumed".to_owned())
    }
}

impl corelink_handler_cas::CasWriteOperationContext for ByokOperationPin {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl corelink_handler_ac::AcUpdateOperationContext for ByokOperationPin {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

fn committed_len_for_config(
    config: Option<&TenantByokConfig>,
    plaintext_len: i64,
) -> Result<i64, String> {
    let Some(config) = config else {
        return Ok(plaintext_len);
    };
    match engagement_for(config) {
        ByokEngagement::Plaintext => Ok(plaintext_len),
        ByokEngagement::Encrypt(ByokCryptoMode::Convergent) => Ok(plaintext_len
            .saturating_add(i64::try_from(BYOK_CLB1_OVERHEAD).unwrap_or(i64::MAX))),
        ByokEngagement::Encrypt(ByokCryptoMode::Random) => Ok(plaintext_len
            .saturating_add(i64::try_from(BYOK_CLB2_OVERHEAD).unwrap_or(i64::MAX))),
        ByokEngagement::FailClosed(why) => Err(format!(
            "BYOK configuration is not writable ({why}); refusing to reserve plaintext"
        )),
    }
}

/// Lock a std `Mutex` without ever panicking on poison (charter: no `unwrap`).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ─── Config source seam + cache ────────────────────────────────────────────

/// Async source of the per-tenant BYOK config read model. The production impl
/// is [`D1ByokConfigReader`] over D1; tests supply a hermetic mock.
#[async_trait]
pub trait ByokConfigSource: Send + Sync + core::fmt::Debug {
    /// Load the tenant's BYOK config (`Ok(None)` ⇒ not configured).
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a transport / parse failure is a [`ByokConfigError`] —
    /// NEVER coerced into "encryption off".
    async fn get_byok_config(
        &self,
        tenant: &str,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError>;

    /// Load the immutable source policy snapshot for an exact config version.
    /// The default is fail-closed so a current-row reader cannot serve a
    /// rotated ciphertext under the wrong CMK/TCS policy.
    async fn get_byok_config_at_version(
        &self,
        tenant: &str,
        config_version: i64,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        let _ = (tenant, config_version);
        Err(ByokConfigError::Transport(
            "versioned BYOK config history reader is unavailable".to_owned(),
        ))
    }
}

#[async_trait]
impl<R: ByokConfigRows + core::fmt::Debug + 'static> ByokConfigSource for D1ByokConfigReader<R> {
    async fn get_byok_config(
        &self,
        tenant: &str,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        D1ByokConfigReader::get_byok_config(self, tenant).await
    }

    async fn get_byok_config_at_version(
        &self,
        tenant: &str,
        config_version: i64,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        D1ByokConfigReader::get_byok_config_at_version(self, tenant, config_version).await
    }
}

/// One positive/security-relevant config-cache entry plus its expiry.
#[derive(Debug, Clone)]
struct ConfigEntry {
    cfg: Option<TenantByokConfig>,
    expires_at: Instant,
}

/// In-memory, per-tenant cache over [`ByokConfigSource`] with a ~60 s TTL.
///
/// A cache MISS does ONE D1 read; a HIT is in-memory. Negative, `inactive`, and
/// `pending` answers are deliberately not cached: otherwise ordinary traffic
/// can prime a plaintext answer immediately before activation and keep writing
/// plaintext for the cache TTL after the control plane reports success.
#[non_exhaustive]
pub struct ByokConfigCache {
    source: Arc<dyn ByokConfigSource>,
    inner: Mutex<HashMap<String, ConfigEntry>>,
    ttl: Duration,
}

impl core::fmt::Debug for ByokConfigCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ByokConfigCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl ByokConfigCache {
    /// Build over an async config source with an explicit TTL (seconds).
    #[must_use]
    pub fn new(source: Arc<dyn ByokConfigSource>, ttl_seconds: u64) -> Self {
        Self {
            source,
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Build with the canonical [`BYOK_CONFIG_TTL_SECONDS`] TTL.
    #[must_use]
    pub fn with_default_ttl(source: Arc<dyn ByokConfigSource>) -> Self {
        Self::new(source, BYOK_CONFIG_TTL_SECONDS)
    }

    /// Return the tenant's cached config, doing at most ONE D1 read on a miss.
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a source error is propagated (the caller refuses to
    /// downgrade an active tenant to plaintext on an undetermined config).
    pub async fn get(&self, tenant: &str) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        let now = Instant::now();
        {
            let guard = lock(&self.inner);
            if let Some(entry) = guard.get(tenant) {
                if entry.expires_at > now {
                    return Ok(entry.cfg.clone());
                }
            }
        }
        // Miss / expired: ONE D1 read (no lock held across the await).
        let cfg = self.source.get_byok_config(tenant).await?;
        {
            let mut guard = lock(&self.inner);
            // Opportunistically drop expired entries before inserting so the
            // map stays bounded without a full LRU.
            if guard.len() >= MAX_CACHE_ENTRIES {
                let cutoff = Instant::now();
                guard.retain(|_, e| e.expires_at > cutoff);
            }
            let cacheable = matches!(
                cfg.as_ref().map(|value| value.state),
                Some(ByokState::Active | ByokState::Partial | ByokState::Shredded)
            );
            if cacheable {
                guard.insert(
                    tenant.to_owned(),
                    ConfigEntry {
                        cfg: cfg.clone(),
                        expires_at: now + self.ttl,
                    },
                );
            } else {
                guard.remove(tenant);
            }
        }
        Ok(cfg)
    }
}

// ─── Tcs secret source seam + resolver (Mode A, TCS resolution) ─────────────

/// The decoded `tenant_byok_secret` row needed to unwrap the Tcs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WrappedTcsRow {
    /// CMK-wrapped Tenant Convergence Secret ciphertext (provider-opaque).
    pub tcs_wrapped: Vec<u8>,
    /// CMK identity used to wrap (echoes `tenant_byok_config.cmk_key_id`).
    pub cmk_key_id: Option<String>,
    /// Tcs version (bumped on rotation; bound into the unwrap AAD).
    pub tcs_version: i64,
}

/// Async source of the CMK-wrapped Tcs (`tenant_byok_secret`). Production impl
/// is [`D1ByokSecretReader`]; tests supply a mock.
#[async_trait]
pub trait ByokSecretSource: Send + Sync + core::fmt::Debug {
    /// Load the tenant's wrapped-Tcs row (`Ok(None)` ⇒ not wrapped yet).
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on any D1 transport / decode failure.
    async fn get_wrapped_tcs(&self, tenant: &str) -> Result<Option<WrappedTcsRow>, String>;

    /// Load an exact historical TCS version. Implementations MUST NOT fall
    /// back to the current row: a missing history record is a hard rotation
    /// failure because decrypting with the current TCS can yield ambiguity.
    async fn get_wrapped_tcs_at_version(
        &self,
        tenant: &str,
        tcs_version: i64,
    ) -> Result<Option<WrappedTcsRow>, String> {
        let _ = (tenant, tcs_version);
        Err("versioned TCS history reader is unavailable".to_owned())
    }
}

/// Production [`ByokSecretSource`] over the async D1 row seam (reuses
/// [`ByokConfigRows`], which [`D1HttpClient`] already implements).
#[derive(Debug)]
#[non_exhaustive]
pub struct D1ByokSecretReader<R = D1HttpClient> {
    rows: Arc<R>,
}

impl<R: ByokConfigRows> D1ByokSecretReader<R> {
    /// Wire the reader over an async row source.
    #[must_use]
    pub fn new(rows: Arc<R>) -> Self {
        Self { rows }
    }
}

#[async_trait]
impl<R: ByokConfigRows + core::fmt::Debug + 'static> ByokSecretSource for D1ByokSecretReader<R> {
    async fn get_wrapped_tcs(&self, tenant: &str) -> Result<Option<WrappedTcsRow>, String> {
        let rows = self
            .rows
            .query_rows(
                "SELECT tcs_wrapped, cmk_key_id, tcs_version \
                 FROM tenant_byok_secret WHERE tenant_id = ?1 LIMIT 1",
                vec![json!(tenant)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let Some(wrapped_val) = row.get("tcs_wrapped") else {
            return Ok(None);
        };
        if wrapped_val.is_null() {
            // Row exists but the Tcs is not wrapped yet (onboarding incomplete).
            return Ok(None);
        }
        let tcs_wrapped = decode_blob(wrapped_val)?;
        let cmk_key_id = row
            .get("cmk_key_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let tcs_version = row.get("tcs_version").and_then(Value::as_i64).unwrap_or(1);
        Ok(Some(WrappedTcsRow {
            tcs_wrapped,
            cmk_key_id,
            tcs_version,
        }))
    }

    async fn get_wrapped_tcs_at_version(
        &self,
        tenant: &str,
        tcs_version: i64,
    ) -> Result<Option<WrappedTcsRow>, String> {
        if tcs_version <= 0 {
            return Err("TCS version must be positive".to_owned());
        }
        let rows = self
            .rows
            .query_rows(
                "SELECT tcs_wrapped, cmk_key_id, tcs_version \
                 FROM tenant_byok_secret_history \
                 WHERE tenant_id = ?1 AND tcs_version = ?2 LIMIT 1",
                vec![json!(tenant), json!(tcs_version)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let wrapped = row
            .get("tcs_wrapped")
            .ok_or_else(|| "historical tcs_wrapped is missing".to_owned())?;
        if wrapped.is_null() {
            return Ok(None);
        }
        let tcs_wrapped = decode_blob(wrapped)?;
        let cmk_key_id = row
            .get("cmk_key_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let found_version = row
            .get("tcs_version")
            .and_then(Value::as_i64)
            .ok_or_else(|| "historical tcs_version is missing".to_owned())?;
        if found_version != tcs_version {
            return Err("historical TCS version identity mismatch".to_owned());
        }
        Ok(Some(WrappedTcsRow {
            tcs_wrapped,
            cmk_key_id,
            tcs_version: found_version,
        }))
    }
}

/// Decode a D1-over-HTTP BLOB JSON value into raw bytes. D1 surfaces a BLOB as
/// either an array of byte integers or a base64 string; both are accepted.
fn decode_blob(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let n = it
                    .as_u64()
                    .ok_or_else(|| "tcs_wrapped: non-numeric byte in BLOB array".to_owned())?;
                out.push(u8::try_from(n).map_err(|_| "tcs_wrapped: byte out of range".to_owned())?);
            }
            Ok(out)
        }
        Value::String(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("tcs_wrapped base64 decode: {e}")),
        _ => Err("tcs_wrapped: unsupported BLOB JSON encoding".to_owned()),
    }
}

/// One Tcs-cache entry — the unwrapped 32-byte secret + expiry. The bytes are
/// held in [`Zeroizing`] so eviction / drop clears them.
struct TcsEntry {
    version: i64,
    bytes: Zeroizing<[u8; 32]>,
    expires_at: Instant,
}

/// In-memory per-tenant cache of the UNWRAPPED Tcs, ≤300 s TTL (mirrors the
/// [`corelink_byok::DekCache`] discipline; this is the only place the plaintext
/// Tcs lives, transiently).
struct TcsCache {
    inner: Mutex<HashMap<String, TcsEntry>>,
    ttl: Duration,
}

impl TcsCache {
    /// Build a cache with `ttl_seconds` ≤ 300 (INV-BYOK-CRYPTO-SOVEREIGNTY).
    fn new(ttl_seconds: u64) -> Result<Self, BYOKError> {
        if ttl_seconds > BYOK_TCS_TTL_SECONDS {
            return Err(BYOKError::DekCacheTtlViolation {
                attempted_seconds: ttl_seconds,
            });
        }
        Ok(Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
        })
    }

    fn get(&self, tenant: &str, version: i64) -> Option<[u8; 32]> {
        let now = Instant::now();
        let mut guard = lock(&self.inner);
        match guard.get(tenant) {
            Some(entry) if entry.expires_at > now && entry.version == version => Some(*entry.bytes),
            Some(_) => {
                guard.remove(tenant);
                None
            }
            None => None,
        }
    }

    fn put(&self, tenant: &str, version: i64, bytes: [u8; 32]) {
        let mut guard = lock(&self.inner);
        if guard.len() >= MAX_CACHE_ENTRIES {
            let cutoff = Instant::now();
            guard.retain(|_, e| e.expires_at > cutoff);
        }
        guard.insert(
            tenant.to_owned(),
            TcsEntry {
                version,
                bytes: Zeroizing::new(bytes),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

/// Resolves the per-tenant Tcs (Mode A convergence secret): read
/// `tenant_byok_secret.tcs_wrapped` → [`KmsProvider::unwrap_dek`] → [`Tcs`],
/// cached for ≤300 s.
///
/// This is the only place the plaintext Tcs is materialised, and only inside
/// the bounded cache window.
#[non_exhaustive]
pub struct TcsResolver {
    secrets: Arc<dyn ByokSecretSource>,
    kms: Arc<dyn KmsProvider>,
    cache: TcsCache,
}

impl core::fmt::Debug for TcsResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcsResolver").finish_non_exhaustive()
    }
}

impl TcsResolver {
    /// Build a resolver over a secret source + a KMS provider with an explicit
    /// Tcs-cache TTL (seconds).
    ///
    /// # Errors
    ///
    /// Returns [`BYOKError::DekCacheTtlViolation`] if `ttl_seconds > 300`.
    pub fn new(
        secrets: Arc<dyn ByokSecretSource>,
        kms: Arc<dyn KmsProvider>,
        ttl_seconds: u64,
    ) -> Result<Self, BYOKError> {
        Ok(Self {
            secrets,
            kms,
            cache: TcsCache::new(ttl_seconds)?,
        })
    }

    /// Build with the canonical [`BYOK_TCS_TTL_SECONDS`] TTL.
    ///
    /// # Errors
    ///
    /// Infallible in practice (300 s is within bounds); the `Result` mirrors
    /// [`Self::new`].
    pub fn with_default_ttl(
        secrets: Arc<dyn ByokSecretSource>,
        kms: Arc<dyn KmsProvider>,
    ) -> Result<Self, BYOKError> {
        Self::new(secrets, kms, BYOK_TCS_TTL_SECONDS)
    }

    /// Rebind this resolver to an exact source-generation KMS provider while
    /// retaining the same versioned secret reader. No current provider is
    /// silently reused for a rotated source.
    pub fn with_provider(&self, kms: Arc<dyn KmsProvider>) -> Result<Self, BYOKError> {
        Self::with_default_ttl(Arc::clone(&self.secrets), kms)
    }

    /// Resolve the tenant's plaintext Tcs (cached). On a miss: read the wrapped
    /// Tcs, unwrap it via the customer CMK, cache, and return.
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a missing secret row, a D1 error, or a KMS unwrap failure
    /// is a [`BYOKError`] — the caller turns this into a 5xx and never stores /
    /// serves plaintext for an active tenant.
    pub async fn resolve(&self, cfg: &TenantByokConfig) -> Result<Tcs, BYOKError> {
        self.resolve_at_version(cfg, None).await
    }

    /// Resolve only the exact TCS version observed by the authoritative data
    /// intent. A stale process-cache entry or rotated D1 row fails closed.
    pub async fn resolve_at_version(
        &self,
        cfg: &TenantByokConfig,
        expected_version: Option<i64>,
    ) -> Result<Tcs, BYOKError> {
        let version = expected_version.unwrap_or(1);
        if let Some(bytes) = self.cache.get(&cfg.tenant_id, version) {
            return Ok(Tcs::from_bytes(bytes));
        }
        let row = if let Some(expected) = expected_version {
            self.secrets
                .get_wrapped_tcs_at_version(&cfg.tenant_id, expected)
                .await
        } else {
            self.secrets.get_wrapped_tcs(&cfg.tenant_id).await
        }
        .map_err(BYOKError::Provider)?
        .ok_or_else(|| {
            BYOKError::Provider(format!(
                "tenant_byok_secret.tcs_wrapped missing for active tenant {}",
                cfg.tenant_id
            ))
        })?;
        if expected_version.is_some_and(|expected| row.tcs_version != expected) {
            return Err(BYOKError::Provider(format!(
                "tenant TCS version changed: expected {version}, found {}",
                row.tcs_version
            )));
        }

        // The injected KMS provider IS the custody authority — use its kind for
        // the wrapped-DEK envelope (the cfg.cmk_provider string was validated at
        // onboarding; the provider matches it by construction).
        let provider = self.kms.provider_kind();
        let key_arn = cfg.cmk_key_id.clone().or(row.cmk_key_id).ok_or_else(|| {
            BYOKError::Provider(format!("no CMK key id for active tenant {}", cfg.tenant_id))
        })?;
        let key_id = KmsKeyId {
            provider,
            key_arn_or_id: key_arn,
            region: cfg.cmk_region.clone().unwrap_or_default(),
        };
        let wrapped = WrappedDek {
            provider,
            key_id,
            ciphertext: row.tcs_wrapped,
            encryption_context: Some(tcs_encryption_context(&cfg.tenant_id, row.tcs_version)),
        };
        let dek = self.kms.unwrap_dek(&wrapped).await?;
        let bytes = dek.bytes;
        self.cache.put(&cfg.tenant_id, row.tcs_version, bytes);
        Ok(Tcs::from_bytes(bytes))
    }
}

/// The KMS `encryption_context` (AAD) bound when wrapping a tenant's Tcs.
///
/// The onboarding wave (the wrapper) MUST bind the IDENTICAL context. Mirrors
/// the `{tenant_id, blob_hash}` shape the providers + `DekCache` expect, with
/// the Tcs version standing in for `blob_hash`.
fn tcs_encryption_context(tenant: &str, version: i64) -> Value {
    json!({ "tenant_id": tenant, "blob_hash": format!("tcs:v{version}") })
}
include!("part-00-tail.rs");
