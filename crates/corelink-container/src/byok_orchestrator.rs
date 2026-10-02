//! BYOK orchestrator — feature-gated production dispatch over
//! [`corelink_byok::KmsProvider`] trait objects.
//!
//! # Responsibility
//!
//! Construct the single `Arc<dyn KmsProvider>` that the server boot
//! path threads through every BYOK-aware code path (envelope encrypt /
//! decrypt, kill-switch poller, erasure attestation). Exactly one of
//! the four production providers is wired per binary; multiple-provider
//! deployments are out of scope and rejected at compile time.
//!
//! # Feature-flag dispatch
//!
//! | Flag set | Concrete type | Audit target |
//! |---|---|---|
//! | (none) | no provider (fail-closed) | `corelink.byok.orchestrator.audit` |
//! | `byok-aws-real` | `corelink_byok::aws::AwsKmsRealProvider` | `corelink.byok.aws.audit` |
//! | `byok-gcp-real` | `corelink_byok::gcp::GcpKmsRealProvider` | `corelink.byok.gcp.audit` |
//! | `byok-azure-real` | `corelink_byok::azure::AzureKeyVaultRealProvider` | `corelink.byok.azure.audit` |
//! | `byok-vault-real` | `corelink_byok::vault::VaultRealProvider` | `corelink.byok.vault.audit` |
//!
//! Setting two or more `byok-*-real` flags simultaneously is a HARD
//! compile error — only one production provider may be linked into the
//! singleton trait-object surface (see the `compile_error!` block at
//! the bottom of this file).
//!
//! # Audit wiring
//!
//! Each concrete provider emits structured `tracing` events with
//! `target = "corelink.byok.<provider>.audit"` and `audit = true` at
//! every error site (audit fail-CLOSED). The orchestrator does NOT
//! transform those events — they flow through the server's global
//! `tracing` subscriber to the audit sink. See
//! `specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §5` for the
//! closed `reason` vocabulary.
//!
//! # Configuration via environment
//!
//! Provider constructors read the following environment variables when
//! the matching feature is enabled. Missing vars fail CLOSED with
//! [`BYOKError::Provider`].
//!
//! | Feature | Variable | Purpose |
//! |---|---|---|
//! | `byok-aws-real` | `AWS_REGION` | KMS region (default `us-east-1`) |
//! | `byok-gcp-real` | `GCP_REGION` | Cloud KMS region (default `us-east1`) |
//! | `byok-azure-real` | `CORELINK_BYOK_AZURE_VAULT_URL` | Premium / Managed HSM base URL |
//! | `byok-azure-real` | `CORELINK_BYOK_AZURE_REGION` | Azure region (default `eastus2`) |
//! | `byok-vault-real` | `VAULT_ADDR` | Vault cluster URL (consumed by `VaultRealProvider::from_env`) |
//! | `byok-vault-real` | `CORELINK_BYOK_VAULT_REGION` | Logical region label (default `customer-hosted`) |
//!
//! AWS credentials are explicit `CORELINK_BYOK_KMS_*` (or standard AWS)
//! environment variables, while GCP ADC, Entra ID, and Vault auth are
//! resolved by their provider-specific constructors. Missing owner
//! credentials fail closed; see the provider crate docs.
//!
//! # Pattern reference
//!
//! `specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7`.

#![forbid(unsafe_code)]

use std::sync::Arc;

use corelink_byok::{BYOKError, KmsProvider};
use tracing::info;

// ── Multi-flag guard ─────────────────────────────────────────────────
//
// Only one production provider may be linked into the trait-object
// singleton. We expand a `compile_error!` for every pairwise overlap so
// the diagnostic names the exact two flags in conflict — easier to
// triage than a generic "more than one set" message.

#[cfg(all(feature = "byok-aws-real", feature = "byok-gcp-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-aws-real` AND `byok-gcp-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time (the orchestrator is a singleton trait object). \
     See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

#[cfg(all(feature = "byok-aws-real", feature = "byok-azure-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-aws-real` AND `byok-azure-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time. See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

#[cfg(all(feature = "byok-aws-real", feature = "byok-vault-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-aws-real` AND `byok-vault-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time. See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

#[cfg(all(feature = "byok-gcp-real", feature = "byok-azure-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-gcp-real` AND `byok-azure-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time. See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

#[cfg(all(feature = "byok-gcp-real", feature = "byok-vault-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-gcp-real` AND `byok-vault-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time. See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

#[cfg(all(feature = "byok-azure-real", feature = "byok-vault-real"))]
compile_error!(
    "BYOK orchestrator: features `byok-azure-real` AND `byok-vault-real` are \
     mutually exclusive — only one BYOK real provider may be enabled at \
     a time. See specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7."
);

// ── Active-provider label (used for telemetry / readiness probes) ────

/// Compile-time discriminator for the active orchestrator dispatch.
///
/// Surfaced via [`active_provider`] so readiness / `/healthz` reflect
/// the binary's real BYOK wiring rather than a runtime guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActiveProvider {
    /// No real provider compiled in. BYOK operations are unavailable and
    /// fail closed; plaintext fallback is never permitted.
    Unavailable,
    /// `byok-aws-real` enabled.
    AwsKms,
    /// `byok-gcp-real` enabled.
    GcpKms,
    /// `byok-azure-real` enabled.
    AzureKeyVault,
    /// `byok-vault-real` enabled.
    HashicorpVault,
}

impl ActiveProvider {
    /// Canonical lowercase label (for logs / audit / metrics).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::AwsKms => "aws",
            Self::GcpKms => "gcp",
            Self::AzureKeyVault => "azure",
            Self::HashicorpVault => "vault",
        }
    }
}

/// Compile-time-constant active-provider label.
#[must_use]
pub const fn active_provider() -> ActiveProvider {
    #[cfg(feature = "byok-aws-real")]
    {
        ActiveProvider::AwsKms
    }
    #[cfg(feature = "byok-gcp-real")]
    {
        ActiveProvider::GcpKms
    }
    #[cfg(feature = "byok-azure-real")]
    {
        ActiveProvider::AzureKeyVault
    }
    #[cfg(feature = "byok-vault-real")]
    {
        ActiveProvider::HashicorpVault
    }
    #[cfg(not(any(
        feature = "byok-aws-real",
        feature = "byok-gcp-real",
        feature = "byok-azure-real",
        feature = "byok-vault-real",
    )))]
    {
        ActiveProvider::Unavailable
    }
}

// ── Provisioning check ───────────────────────────────────────────────

/// Whether the operator has provisioned the compiled provider's credentials.
///
/// `false` is a configuration state: the deployment never supplied the
/// credential pair. It is distinct from a provisioned but broken provider
/// (bad values, SDK init failure), which [`make_provider`] still reports as
/// an error. Only the AWS provider's credentials can be checked here without
/// I/O, using the same names and the same empty-is-absent rule as
/// `corelink_byok::aws::AwsKmsRealProvider::with_fips`. Every other real
/// provider reports `true`, so its constructor keeps deciding.
#[must_use]
pub fn provider_credentials_configured() -> bool {
    provider_credentials_configured_with(active_provider(), |name| std::env::var(name).ok())
}

/// Pure core of [`provider_credentials_configured`]; `lookup` reads one
/// environment variable.
#[must_use]
pub fn provider_credentials_configured_with<F>(provider: ActiveProvider, lookup: F) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    let present = |primary: &str, fallback: &str| {
        [primary, fallback]
            .into_iter()
            .any(|name| lookup(name).is_some_and(|value| !value.is_empty()))
    };
    match provider {
        ActiveProvider::Unavailable => false,
        ActiveProvider::AwsKms => {
            present("CORELINK_BYOK_KMS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
                && present(
                    "CORELINK_BYOK_KMS_SECRET_ACCESS_KEY",
                    "AWS_SECRET_ACCESS_KEY",
                )
        }
        ActiveProvider::GcpKms | ActiveProvider::AzureKeyVault | ActiveProvider::HashicorpVault => {
            true
        }
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Construct the singleton BYOK provider for this binary.
///
/// Returns an `Arc<dyn KmsProvider>` whose concrete type is selected at
/// compile time by which (single) `byok-*-real` feature flag is set.
/// With no flag set, construction fails closed. There is deliberately no
/// in-process crypto fallback: a binary without a real KMS provider cannot
/// claim BYOK protection or persist a tenant as active.
///
/// # Errors
///
/// - [`BYOKError::Provider`] if the active provider's constructor fails
///   (missing required env var, SDK init failure, FIPS endpoint
///   resolution failure, etc.).
///
/// # Audit
///
/// On the success path, emits one `info` event at
/// `target = "corelink.byok.orchestrator.audit"` with `audit = true` and
/// `provider = <label>` so the audit chain records the binary's active
/// BYOK wiring at boot. Per-operation audit events are emitted by the
/// concrete provider crates with `target = "corelink.byok.<provider>.audit"`.
pub async fn make_provider() -> Result<Arc<dyn KmsProvider>, BYOKError> {
    let label = active_provider().as_str();
    let provider: Arc<dyn KmsProvider> = build_active().await?;
    info!(
        target: "corelink.byok.orchestrator.audit",
        audit = true,
        op = "boot",
        provider = label,
        "BYOK orchestrator: active provider selected"
    );
    Ok(provider)
}

/// Compile-time dispatch helper — exactly one of the cfg branches is
/// active per build. Returns the trait object directly.
async fn build_active() -> Result<Arc<dyn KmsProvider>, BYOKError> {
    #[cfg(feature = "byok-aws-real")]
    {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let p = corelink_byok::aws::AwsKmsRealProvider::new(&region).await?;
        Ok(Arc::new(p))
    }
    #[cfg(feature = "byok-gcp-real")]
    {
        let region = std::env::var("GCP_REGION").unwrap_or_else(|_| "us-east1".to_string());
        let p = corelink_byok::gcp::GcpKmsRealProvider::new(&region).await?;
        Ok(Arc::new(p))
    }
    #[cfg(feature = "byok-azure-real")]
    {
        let vault_url = std::env::var("CORELINK_BYOK_AZURE_VAULT_URL").map_err(|_| {
            tracing::warn!(
                target: "corelink.byok.orchestrator.audit",
                audit = true,
                op = "boot",
                provider = "azure",
                reason = "azure_vault_url_unset",
                "BYOK orchestrator: CORELINK_BYOK_AZURE_VAULT_URL unset"
            );
            BYOKError::Provider(
                "CORELINK_BYOK_AZURE_VAULT_URL unset (required for byok-azure-real)".to_string(),
            )
        })?;
        let region =
            std::env::var("CORELINK_BYOK_AZURE_REGION").unwrap_or_else(|_| "eastus2".to_string());
        let p = corelink_byok::azure::AzureKeyVaultRealProvider::new(&region, &vault_url)?;
        Ok(Arc::new(p))
    }
    #[cfg(feature = "byok-vault-real")]
    {
        let region = std::env::var("CORELINK_BYOK_VAULT_REGION")
            .unwrap_or_else(|_| "customer-hosted".to_string());
        let p = corelink_byok::vault::VaultRealProvider::from_env(&region)?;
        Ok(Arc::new(p))
    }
    #[cfg(not(any(
        feature = "byok-aws-real",
        feature = "byok-gcp-real",
        feature = "byok-azure-real",
        feature = "byok-vault-real",
    )))]
    {
        tracing::warn!(
            target: "corelink.byok.orchestrator.audit",
            audit = true,
            op = "boot",
            provider = "unavailable",
            reason = "no_real_provider_compiled",
            "BYOK orchestrator: no real KMS provider compiled; refusing crypto operations"
        );
        Err(BYOKError::Provider(
            "no real KMS provider compiled (enable exactly one byok-*-real feature)".to_string(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "tests are allowed to use these primitives")]
mod tests {
    use super::{provider_credentials_configured_with, ActiveProvider};

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn aws_needs_both_halves_of_the_dedicated_pair() {
        let both = [
            ("CORELINK_BYOK_KMS_ACCESS_KEY_ID", "access-id"),
            ("CORELINK_BYOK_KMS_SECRET_ACCESS_KEY", "secret"),
        ];
        assert!(provider_credentials_configured_with(
            ActiveProvider::AwsKms,
            env(&both)
        ));
        for half in [&both[..1], &both[1..]] {
            assert!(
                !provider_credentials_configured_with(ActiveProvider::AwsKms, env(half)),
                "one half of the pair is not a provisioned provider: {half:?}"
            );
        }
    }

    #[test]
    fn aws_accepts_the_generic_fallback_names_like_the_provider_does() {
        let generic = [
            ("AWS_ACCESS_KEY_ID", "access-id"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
        ];
        assert!(provider_credentials_configured_with(
            ActiveProvider::AwsKms,
            env(&generic)
        ));
        let mixed = [
            ("CORELINK_BYOK_KMS_ACCESS_KEY_ID", ""),
            ("AWS_ACCESS_KEY_ID", "access-id"),
            ("CORELINK_BYOK_KMS_SECRET_ACCESS_KEY", "secret"),
        ];
        assert!(provider_credentials_configured_with(
            ActiveProvider::AwsKms,
            env(&mixed)
        ));
    }

    #[test]
    fn aws_treats_forwarded_empty_strings_as_unprovisioned() {
        // The Worker forwards every unset secret as "" (durable_object_start.ts).
        let forwarded_unset = [
            ("CORELINK_BYOK_KMS_ACCESS_KEY_ID", ""),
            ("CORELINK_BYOK_KMS_SECRET_ACCESS_KEY", ""),
            ("CORELINK_BYOK_KMS_SESSION_TOKEN", ""),
        ];
        assert!(!provider_credentials_configured_with(
            ActiveProvider::AwsKms,
            env(&forwarded_unset)
        ));
        assert!(!provider_credentials_configured_with(
            ActiveProvider::AwsKms,
            env(&[])
        ));
    }

    #[test]
    fn other_providers_keep_constructor_authority() {
        for provider in [
            ActiveProvider::GcpKms,
            ActiveProvider::AzureKeyVault,
            ActiveProvider::HashicorpVault,
        ] {
            assert!(provider_credentials_configured_with(provider, env(&[])));
        }
        assert!(!provider_credentials_configured_with(
            ActiveProvider::Unavailable,
            env(&[
                ("AWS_ACCESS_KEY_ID", "access-id"),
                ("AWS_SECRET_ACCESS_KEY", "s")
            ])
        ));
    }
}
