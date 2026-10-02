// R2 storage adapter using the AWS S3-compatible API.
//
// This module provides:
//
// - [`R2S3Client`] — low-level async `put_object` / `get_object`
//   wrapper over `aws-sdk-s3` pointed at the R2 S3 endpoint.
// - [`R2CasHandler`] — a sync `CasReadHandler` + `CasWriteHandler`
//   implementation that uses [`R2S3Client`] for durable storage and
//   `derive_prefix` for tenant-scoped R2 keys.
//
// # Key scheme
//
// ```text
// <region>/<tenant_prefix_16>/<digest>
// ```
//
// The `tenant_prefix_16` is derived via
// `corelink_tenant_path::derive_prefix` so cross-tenant key
// co-residence is impossible (layer 5 of `INV-TENANT-ISOLATION`).
//
// # Sync wrapper
//
// The `CasReadHandler` / `CasWriteHandler` traits are synchronous
// (they exist in the pre-async R-prep layer). `R2CasHandler` bridges
// the async S3 SDK into the sync trait surface by using
// `tokio::runtime::Handle::current().block_on(...)`. The server runs
// inside a tokio runtime, so a handle is always available.
//
// # Security charter compliance
//
// - No credentials in code; constructed from [`StorageEnv`].
// - No secrets logged; tracing events contain bucket + key only.
// - No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.

use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::Client;
use corelink_byok::{CryptoContext, CryptoMode, Tcs};
use corelink_handler_cas::{
    AuditEvent, AuditEventKind, AuditSink, CasDeleteHandler, CasHandlerError, CasListHandler,
    CasReadHandler, CasReadRequest, CasReadResponse, CasWriteHandler, CasWriteRequest,
    CasWriteResponse, DigestAlgo, SliObservation, SliObserver,
};
// `InMemoryAuditSink` is now used only by tests (the deployed builder wires the
// durable D1 sink); gate the import so the non-test build stays warning-clean.
#[cfg(test)]
use corelink_handler_cas::InMemoryAuditSink;
// Same reason: the capture-everything SLI observer is a TEST fixture now that
// the deployed builders wire the constant-memory `CountingSliObserver` (B-057).
#[cfg(test)]
use corelink_handler_cas::InMemorySliObserver;
use corelink_hash::Digest;
use corelink_tenant_path::{derive_prefix, TenantDerivationKey};

use crate::byok_transition_fence::DataOperation;
use crate::storage::byok_generation_catalog::{ByokDataGuard, ByokRuntimeGate};
use crate::storage::d1_audit_sink::{
    ac_audit_sink_from_d1_concrete, cas_audit_sink_from_d1_concrete,
};
use crate::storage::d1_http::D1HttpClient;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::byok_cas::{
    ac_crypto_context, ac_crypto_context_for, cas_crypto_context, cas_crypto_context_for,
    decrypt_cas_blob, encrypt_cas_blob, engagement_for, harden_digest, unarmed_engagement,
    ByokConfigCache, ByokEngagement, ModeBEncryptor, TcsResolver, UNARMED_REFUSAL,
};
use super::StorageEnv;
use crate::customer_d1::ByokCryptoMode;

/// Low-level async R2/S3 client.
///
/// Wraps `aws-sdk-s3` with a custom endpoint set to the R2
/// S3-compatible URL. Credentials are taken from [`StorageEnv`] and
/// never logged.
#[derive(Debug)]
#[non_exhaustive]
pub struct R2S3Client {
    inner: Client,
    /// Default bucket for CAS blobs (e.g. `corelink-cas-prod`).
    bucket: String,
    /// Per-key serialization locks for [`Self::delete_if_present`] (rt-nuclear
    /// #6/#10/#14 — concurrent double-DELETE over-release). HEAD-then-DELETE is
    /// non-atomic and S3 `DeleteObject` neither reports prior size nor supports a
    /// "delete-and-return-size" op, so two racing deletes of the same key both
    /// HEAD the size and both report it reclaimed → the byte accountant releases
    /// it twice → free headroom. We serialize the measure-and-delete per key in
    /// this process so AT MOST ONE racer observes the object present (HEAD ⇒
    /// `Some(size)`) and removes it; every other racer HEADs absent AFTER the
    /// delete and returns `None` (releases 0). The map is pruned on release so it
    /// does not grow without bound.
    delete_locks:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    /// Test-only dispatch recorder used to prove audit gating without a live
    /// R2 endpoint. It is absent from production builds.
    #[cfg(test)]
    storage_recorder: Option<Arc<StorageDispatchRecorder>>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct StorageDispatchRecorder {
    pub calls: AtomicUsize,
    pub premature: AtomicBool,
    pub audit_committed: AtomicBool,
    successful: AtomicBool,
    body: std::sync::Mutex<Option<Vec<u8>>>,
}

#[cfg(test)]
impl StorageDispatchRecorder {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            premature: AtomicBool::new(false),
            audit_committed: AtomicBool::new(false),
            successful: AtomicBool::new(false),
            body: std::sync::Mutex::new(None),
        })
    }

    pub(crate) fn successful(body: Vec<u8>) -> Arc<Self> {
        let recorder = Self::new();
        recorder.successful.store(true, Ordering::SeqCst);
        if let Ok(mut stored) = recorder.body.lock() {
            *stored = Some(body);
        }
        recorder
    }

    fn record(&self) {
        if !self.audit_committed.load(Ordering::SeqCst) {
            self.premature.store(true, Ordering::SeqCst);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn should_succeed(&self) -> bool {
        self.successful.load(Ordering::SeqCst)
    }

    fn body(&self) -> Vec<u8> {
        self.body
            .lock()
            .ok()
            .and_then(|stored| stored.clone())
            .unwrap_or_default()
    }
}

/// Outcome of [`R2S3Client::get_capped`].
///
/// Three states, not two: "absent" and "present but refused" are different
/// answers and the caller must not be able to conflate them — a 404 for an
/// object that exists would tell the client to re-upload bytes we already hold.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CappedGet {
    /// The object exists and is within the ceiling.
    Found(Vec<u8>),
    /// No such key.
    Missing,
    /// The object exists but is over the ceiling and was NOT read.
    /// `actual_bytes` is `None` when the storage layer reported no content
    /// length at all — refused for the same reason, since the size that would
    /// have been buffered is unknown.
    TooLarge {
        /// Size the storage layer reported, when it reported one.
        actual_bytes: Option<u64>,
    },
}

/// The narrow body interface keeps the bounded collector testable with a
/// deterministic stream while the production adapter wraps AWS's
/// `ByteStream` below.
type R2BodyChunkFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Option<Result<bytes::Bytes, String>>> + Send + 'a>,
>;

trait R2BodyChunkStream {
    fn next_chunk<'a>(&'a mut self) -> R2BodyChunkFuture<'a>;
}

struct R2SdkBodyStream(aws_sdk_s3::primitives::ByteStream);

impl R2BodyChunkStream for R2SdkBodyStream {
    fn next_chunk<'a>(&'a mut self) -> R2BodyChunkFuture<'a> {
        Box::pin(async move {
            self.0
                .next()
                .await
                .map(|chunk| chunk.map_err(|error| error.to_string()))
        })
    }
}

#[cfg(test)]
struct R2TestStalledAfterHeaders {
    emitted: bool,
}

#[cfg(test)]
impl R2BodyChunkStream for R2TestStalledAfterHeaders {
    fn next_chunk<'a>(&'a mut self) -> R2BodyChunkFuture<'a> {
        Box::pin(async move {
            if !self.emitted {
                self.emitted = true;
                Some(Ok(bytes::Bytes::from_static(b"headers-arrived")))
            } else {
                std::future::pending::<Option<Result<bytes::Bytes, String>>>().await
            }
        })
    }
}

impl R2S3Client {
    /// Bound the three phases that can otherwise leave a synchronous CAS
    /// reader parked forever when R2 stops making progress. The operation
    /// timeout is deliberately longer than the per-read timeout because a
    /// large object may legitimately need several read windows, while still
    /// giving cancellation a finite unwind point.
    pub(crate) const R2_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    pub(crate) const R2_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    pub(crate) const R2_OPERATION_ATTEMPT_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(30);
    pub(crate) const R2_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    /// Body-level deadlines remain necessary after `GetObject` headers arrive:
    /// the SDK operation timeout does not reliably cover a stalled stream.
    pub(crate) const R2_BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    pub(crate) const R2_BODY_TOTAL_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(60);

    #[cfg(test)]
    pub(crate) fn test_post_header_body_timeout() -> Result<CappedGet, String> {
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            handle.block_on(Self::collect_capped_body_with_deadlines(
                "batch-post-header-stall",
                1024,
                R2TestStalledAfterHeaders { emitted: false },
                std::time::Duration::from_millis(10),
                std::time::Duration::from_millis(50),
            ))
        })
    }

    async fn collect_capped_body<S: R2BodyChunkStream>(
        key: &str,
        max_bytes: u64,
        body: S,
    ) -> Result<CappedGet, String> {
        Self::collect_capped_body_with_deadlines(
            key,
            max_bytes,
            body,
            Self::R2_BODY_IDLE_TIMEOUT,
            Self::R2_BODY_TOTAL_TIMEOUT,
        )
        .await
    }

    async fn collect_capped_body_with_deadlines<S: R2BodyChunkStream>(
        key: &str,
        max_bytes: u64,
        mut body: S,
        idle_timeout: std::time::Duration,
        total_timeout: std::time::Duration,
    ) -> Result<CappedGet, String> {
        let collect = async {
            let mut bytes = Vec::new();
            let mut actual_bytes = 0_u64;
            loop {
                let next = tokio::time::timeout(idle_timeout, body.next_chunk())
                    .await
                    .map_err(|_| format!("R2 body idle timeout for key {key}"))?;
                let Some(chunk) = next else {
                    return Ok(CappedGet::Found(bytes));
                };
                let chunk =
                    chunk.map_err(|error| format!("R2 body read failed for key {key}: {error}"))?;
                actual_bytes = actual_bytes.saturating_add(chunk.len() as u64);
                if actual_bytes > max_bytes {
                    return Ok(CappedGet::TooLarge {
                        actual_bytes: Some(actual_bytes),
                    });
                }
                bytes.extend_from_slice(&chunk);
            }
        };
        tokio::time::timeout(total_timeout, collect)
            .await
            .map_err(|_| format!("R2 body total timeout for key {key}"))?
    }
}
