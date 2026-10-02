// ─── BYOK config read model (Wave 2 — read seam only, NOT yet wired) ──────────
//
// The per-tenant key-custody + crypto-mode read model over migration 0081
// (`tenant_byok_config`). This is a READ seam landed for Wave 3 (data-plane
// wiring) to consume — NO handler / hot-path calls it yet, and nothing here
// writes the config tables (the signup-worker / control-plane is the sole
// writer, a later wave — audit finding H5). Placed AFTER the handler impls so
// it shifts no OKF-cited line range in this file.
//
// FAIL-CLOSED invariant: an unknown / unparseable mode, crypto_mode, or state
// is an ERROR, never a permissive default. An unrecognised custody rung must
// NEVER silently degrade to "encryption off".

/// Failure reading or parsing the BYOK config read model. Fail-CLOSED:
/// callers MUST treat any variant as "custody undetermined" and refuse to
/// downgrade to plaintext — never coerce an error into "encryption off".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByokConfigError {
    /// D1 transport / decode failure (the underlying row source errored).
    Transport(String),
    /// A column held an unknown / unparseable enum value, or a `NOT NULL`
    /// column was absent from the row.
    Parse(String),
}

impl core::fmt::Display for ByokConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "byok config transport error: {e}"),
            Self::Parse(e) => write!(f, "byok config parse error: {e}"),
        }
    }
}

impl std::error::Error for ByokConfigError {}

/// Key-custody rung of a tenant's BYOK configuration
/// (`tenant_byok_config.mode`, plan §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByokMode {
    /// CoreLink-held key (no customer KMS).
    Managed,
    /// Customer CMK wraps the per-tenant Tenant Convergence Secret (Tcs).
    Byok,
    /// Hold-your-own-key — strongest custody.
    Hyok,
}

impl ByokMode {
    /// Canonical D1 string (matches the `mode` CHECK constraint).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Byok => "byok",
            Self::Hyok => "hyok",
        }
    }
}

impl core::str::FromStr for ByokMode {
    type Err = ByokConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "managed" => Ok(Self::Managed),
            "byok" => Ok(Self::Byok),
            "hyok" => Ok(Self::Hyok),
            other => Err(ByokConfigError::Parse(format!(
                "unknown byok mode: {other:?}"
            ))),
        }
    }
}

/// Crypto mode — Mode A vs Mode B (`tenant_byok_config.crypto_mode`, plan §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByokCryptoMode {
    /// Mode A — convergent encryption keyed by the Tcs; preserves cross-blob
    /// dedup.
    Convergent,
    /// Mode B — per-write random keys; maximises isolation, no dedup.
    Random,
}

impl ByokCryptoMode {
    /// Canonical D1 string (matches the `crypto_mode` CHECK constraint).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Convergent => "convergent",
            Self::Random => "random",
        }
    }
}

impl core::str::FromStr for ByokCryptoMode {
    type Err = ByokConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "convergent" => Ok(Self::Convergent),
            "random" => Ok(Self::Random),
            other => Err(ByokConfigError::Parse(format!(
                "unknown byok crypto_mode: {other:?}"
            ))),
        }
    }
}

/// Onboarding state machine (`tenant_byok_config.state`). Monotonic +
/// audited; written only by the control-plane authority (signup-worker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByokState {
    /// Not configured (no encryption).
    Inactive,
    /// Onboarding in progress (key referenced, not yet active).
    Pending,
    /// Fully active — all writes encrypted.
    Active,
    /// Active for NEW writes while a backfill re-encrypts historical blobs.
    Partial,
    /// Crypto-shredded — CMK/Tcs destroyed; ciphertext unrecoverable.
    Shredded,
}

impl ByokState {
    /// Canonical D1 string (matches the `state` CHECK constraint).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Partial => "partial",
            Self::Shredded => "shredded",
        }
    }
}

impl core::str::FromStr for ByokState {
    type Err = ByokConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "inactive" => Ok(Self::Inactive),
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "partial" => Ok(Self::Partial),
            "shredded" => Ok(Self::Shredded),
            other => Err(ByokConfigError::Parse(format!(
                "unknown byok state: {other:?}"
            ))),
        }
    }
}

/// The per-tenant BYOK configuration read model (one `tenant_byok_config`
/// row, migration 0081). `cmk_*` are `None` until a BYOK/HYOK tenant is
/// onboarded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TenantByokConfig {
    /// Tenant id (PK).
    pub tenant_id: String,
    /// Key-custody rung.
    pub mode: ByokMode,
    /// Convergent (dedup-preserving) vs random (max-isolation).
    pub crypto_mode: ByokCryptoMode,
    /// CMK provider (`aws` / `gcp` / `azure` / `vault` / `corelink_managed`).
    pub cmk_provider: Option<String>,
    /// CMK identity: ARN / GCP resource name / Azure URI / Vault path.
    pub cmk_key_id: Option<String>,
    /// CMK region.
    pub cmk_region: Option<String>,
    /// Onboarding state.
    pub state: ByokState,
}

/// `true` when the tenant's at-rest encryption is LIVE. `Partial` counts as
/// active because it still encrypts NEW writes while a backfill re-encrypts
/// historical blobs (only `Inactive`/`Pending`/`Shredded` are not "encrypt
/// new writes").
#[must_use]
pub fn is_encryption_active(cfg: &TenantByokConfig) -> bool {
    matches!(cfg.state, ByokState::Active | ByokState::Partial)
}

/// Parse one `tenant_byok_config` D1 row into the read model. Fail-CLOSED: a
/// missing `NOT NULL` column or an unparseable enum is a
/// [`ByokConfigError::Parse`], never a permissive default.
pub(crate) fn parse_byok_config_row(row: &D1Row) -> Result<TenantByokConfig, ByokConfigError> {
    let tenant_id = col_opt_str(row, "tenant_id")
        .ok_or_else(|| ByokConfigError::Parse("tenant_byok_config.tenant_id missing".to_owned()))?;
    let mode = col_opt_str(row, "mode")
        .ok_or_else(|| ByokConfigError::Parse("tenant_byok_config.mode missing".to_owned()))?
        .parse::<ByokMode>()?;
    let crypto_mode = col_opt_str(row, "crypto_mode")
        .ok_or_else(|| ByokConfigError::Parse("tenant_byok_config.crypto_mode missing".to_owned()))?
        .parse::<ByokCryptoMode>()?;
    let state = col_opt_str(row, "state")
        .ok_or_else(|| ByokConfigError::Parse("tenant_byok_config.state missing".to_owned()))?
        .parse::<ByokState>()?;
    Ok(TenantByokConfig {
        tenant_id,
        mode,
        crypto_mode,
        cmk_provider: col_opt_str(row, "cmk_provider"),
        cmk_key_id: col_opt_str(row, "cmk_key_id"),
        cmk_region: col_opt_str(row, "cmk_region"),
        state,
    })
}

/// Async D1 row-source seam for the BYOK config read model. The production
/// impl is [`D1HttpClient`]; tests supply a hermetic mock. Generic (not
/// `dyn`) so the native `async fn` needs no boxing on the data-plane read.
pub trait ByokConfigRows: Send + Sync {
    /// Run one parameterised statement; return the result rows.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on any D1 transport / HTTP / decode failure.
    fn query_rows(
        &self,
        sql: &str,
        binds: Vec<Value>,
    ) -> impl core::future::Future<Output = Result<Vec<D1Row>, String>> + Send;
}

impl ByokConfigRows for D1HttpClient {
    async fn query_rows(&self, sql: &str, binds: Vec<Value>) -> Result<Vec<D1Row>, String> {
        self.query(sql, &binds).await
    }
}

/// Read-only loader for the per-tenant BYOK configuration (migration 0081).
///
/// **Wave 2 read seam** — landed for Wave 3 (data-plane wiring) to consume;
/// NO handler / hot-path calls it yet. Read-only by construction: it never
/// writes the config tables (the control-plane authority is the sole writer).
#[derive(Debug)]
#[non_exhaustive]
pub struct D1ByokConfigReader<R = D1HttpClient> {
    /// Async row source (production: [`D1HttpClient`]).
    rows: Arc<R>,
}

impl<R: ByokConfigRows> D1ByokConfigReader<R> {
    /// Wire the reader over an async row source.
    #[must_use]
    pub fn new(rows: Arc<R>) -> Self {
        Self { rows }
    }

    /// Load the tenant's BYOK config.
    ///
    /// `Ok(None)` when no row exists — BYOK is NOT configured, i.e. today's
    /// (unencrypted) behaviour. Fully parameterised + tenant-scoped
    /// (INV-TENANT-ISOLATION).
    ///
    /// # Errors
    ///
    /// Fail-CLOSED: a transport failure is [`ByokConfigError::Transport`] and
    /// an unparseable enum / missing `NOT NULL` column is
    /// [`ByokConfigError::Parse`] — NEVER a silent "encryption off".
    pub async fn get_byok_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        let rows = self
            .rows
            .query_rows(
                "SELECT tenant_id, mode, crypto_mode, cmk_provider, cmk_key_id, \
                        cmk_region, state \
                 FROM tenant_byok_config WHERE tenant_id = ?1 LIMIT 1",
                vec![json!(tenant_id)],
            )
            .await
            .map_err(ByokConfigError::Transport)?;
        match rows.first() {
            None => Ok(None),
            Some(row) => parse_byok_config_row(row).map(Some),
        }
    }

    /// Load the immutable configuration snapshot for an exact historical
    /// version. Rotation readers must use this seam rather than current config.
    pub async fn get_byok_config_at_version(
        &self,
        tenant_id: &str,
        config_version: i64,
    ) -> Result<Option<TenantByokConfig>, ByokConfigError> {
        if config_version <= 0 {
            return Err(ByokConfigError::Parse(
                "config_version must be positive".to_owned(),
            ));
        }
        let rows = self
            .rows
            .query_rows(
                "SELECT tenant_id, mode, crypto_mode, cmk_provider, cmk_key_id, \
                        cmk_region, state \
                 FROM tenant_byok_config_history \
                 WHERE tenant_id = ?1 AND config_version = ?2 LIMIT 1",
                vec![json!(tenant_id), json!(config_version)],
            )
            .await
            .map_err(ByokConfigError::Transport)?;
        rows.first().map(parse_byok_config_row).transpose()
    }
}
