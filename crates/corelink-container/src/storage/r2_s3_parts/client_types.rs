/// The body-crypto plan for a CAS/AC object under a resolved BYOK config
/// (surface-neutral — shared by [`R2CasHandler`] and [`R2AcHandler`]). The
/// physical R2 key digest is resolved alongside it (see [`ByokResolved`]).
enum ByokBodyPlan {
    /// Store/serve `req.bytes` unchanged (non-BYOK / `_public` / inactive).
    Plaintext,
    /// Mode A — convergent: body keyed by the Tcs-derived DEK (dedup-preserving).
    Convergent { tcs: Tcs, ctx: CryptoContext },
    /// Mode B — random: body keyed by a random per-blob DEK persisted in
    /// `byok_envelope` (no dedup). The crypto material is held by the handler's
    /// [`ModeBEncryptor`]; only the (real-digest) context travels in the plan.
    Random { ctx: CryptoContext },
}

/// The full BYOK resolution for a CAS op: the **physical** R2 key digest (the
/// §4-hardened HMAC for an active tenant, audit H-4; the raw digest otherwise)
/// plus the body crypto [`ByokBodyPlan`].
struct ByokResolved {
    physical_digest: String,
    plan: ByokBodyPlan,
}

/// How many CAS existence probes (`HeadObject`) [`R2CasHandler::exists_batch`]
/// keeps in flight at once.
///
/// Deliberately small. The container runs on a Cloudflare Containers `basic`
/// instance — **0.25 vCPU** — so the ceiling has to stay well under what would
/// make TLS/HTTP bookkeeping for the in-flight requests contend for that
/// quarter-core; the probes themselves are pure I/O wait (~60 ms per R2 HEAD
/// measured from IAD), so a small window already recovers nearly all of the
/// serial loss. R2 request rate limits are also shared across tenants on the
/// account, so one tenant's 4096-digest `findMissingBlobs` must not be able to
/// open a wide burst against the bucket every other tenant reads through.
///
/// 16 turns the 4096-digest worst case from 4096 serial HEADs into 256 waves
/// (~15 s of HEAD time instead of ~246 s) and a typical 100-digest Bazel call
/// into 7 waves (~0.42 s instead of ~6 s) — the linear term is broken without
/// betting the shared bucket budget or the quarter-core on a large number.
/// Raise it only against a measurement, never on intuition.
const MAX_CONCURRENT_EXISTS_PROBES: usize = 16;

/// The no-provider image has no runtime gate. Consult its shared config
/// snapshot before any private operation, even a list with no body crypto plan
/// or a write with an operation context. Armed handlers use their existing
/// authoritative gate; public and unattached dev handlers need no config read.
fn check_unarmed_byok_access(
    cache: Option<&ByokConfigCache>,
    armed: bool,
    tenant: &str,
) -> Result<(), String> {
    if armed || tenant == crate::adapter_cache::PUBLIC_NAMESPACE {
        return Ok(());
    }
    let Some(cache) = cache else {
        return Ok(());
    };
    let handle = tokio::runtime::Handle::current();
    let cfg = tokio::task::block_in_place(|| handle.block_on(cache.get(tenant)))
        .map_err(|error| format!("byok config read: {error}"))?;
    let Some(cfg) = cfg else {
        return Ok(());
    };
    match unarmed_engagement(&cfg) {
        ByokEngagement::Plaintext => Ok(()),
        ByokEngagement::FailClosed(why) => Err(format!("byok {why} (fail-closed)")),
        ByokEngagement::Encrypt(_) => Err(format!("byok {UNARMED_REFUSAL} (fail-closed)")),
    }
}

impl R2S3Client {
    /// List ONE page of objects under `prefix`, returning per-object
    /// metadata + an opaque continuation token for the next page.
    ///
    /// Used by the D-7 / D-8 paginated enumeration routes. Unlike
    /// [`Self::list_objects_v2`] (which drains every page for erasure),
    /// this returns a single S3 `ListObjectsV2` page so the HTTP route
    /// can stream pages back to the client under its own cursor. The
    /// S3 V2 continuation token IS the route's opaque `next_cursor`.
    ///
    /// `max_keys` is clamped into `1..=1000` (the S3 hard cap). Each
    /// returned tuple is `(full_key, size_bytes, rfc3339_last_modified)`;
    /// the caller strips the `<region>/<tenant_prefix>/` segments to
    /// recover the bare digest.
    ///
    /// # Errors
    /// Returns `Err(String)` on any transport/service error.
    pub async fn list_objects_page(
        &self,
        prefix: &str,
        max_keys: u32,
        cursor: Option<&str>,
    ) -> Result<(Vec<(String, u64, String)>, Option<String>), String> {
        #[cfg(test)]
        {
            self.record_storage_dispatch();
            if let Some(recorder) = self.storage_recorder.as_ref() {
                if recorder.should_succeed() {
                    return Ok((Vec::new(), None));
                }
            }
        }
        let max_keys = max_keys.clamp(1, 1000) as i32;
        let mut req = self
            .inner
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .max_keys(max_keys);
        if let Some(token) = cursor {
            req = req.continuation_token(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("R2 list-page failed for prefix {prefix}: {e}"))?;

        let mut out = Vec::new();
        for obj in resp.contents() {
            let Some(key) = obj.key() else { continue };
            let size = u64::try_from(obj.size().unwrap_or(0)).unwrap_or(0);
            // RFC-3339 last-modified; absent ⇒ unix epoch (deterministic
            // fallback rather than a panic / skipped row).
            let last_modified = obj
                .last_modified()
                .and_then(|dt| {
                    dt.fmt(aws_sdk_s3::primitives::DateTimeFormat::DateTime)
                        .ok()
                })
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
            out.push((key.to_owned(), size, last_modified));
        }

        // Only surface a next cursor when S3 says the listing is
        // truncated AND hands back a token (fail-safe: a missing token
        // on a truncated page ends pagination rather than looping).
        let next = if resp.is_truncated().unwrap_or(false) {
            resp.next_continuation_token().map(str::to_owned)
        } else {
            None
        };
        Ok((out, next))
    }

    /// Compute the R2 object key for a blob, surface-partitioned by the
    /// keyspace's content-addressing function ([`DigestAlgo`]).
    ///
    /// - **`Blake3`** (native CAS + sccache): `<region>/<tenant_prefix_16>/<digest>`.
    /// - **`Sha256`** (Bazel REAPI v2): `<region>/<tenant_prefix_16>/bazel/sha256/<digest>`.
    ///
    /// The `bazel/sha256/` segment sits AFTER the tenant prefix so the
    /// secret-keyed HMAC tenant isolation (layer 5 of `INV-TENANT-ISOLATION`)
    /// is fully preserved; the sub-prefix only partitions the digest function
    /// WITHIN a tenant's namespace. Each keyspace is single-function: a
    /// SHA-256 blob is never co-resident with a BLAKE3 blob under one key,
    /// so the durable gate's read-path re-verification always applies the
    /// blob's own function (Option A, ADR-0044).
    ///
    /// The `tenant_prefix` is computed by the caller; on the production path
    /// it is always `derive_prefix(secret_tdk, tenant_uuid)` (the handlers
    /// fail closed without a TDK — F1/F2). `region` is the handler's
    /// residency region (F7), so each regional env keys under its own region.
    #[must_use]
    pub fn blob_key(region: &str, tenant_prefix: &str, digest: &str, algo: DigestAlgo) -> String {
        match algo {
            DigestAlgo::Blake3 => format!("{region}/{tenant_prefix}/{digest}"),
            DigestAlgo::Sha256 => format!("{region}/{tenant_prefix}/bazel/sha256/{digest}"),
        }
    }
}
