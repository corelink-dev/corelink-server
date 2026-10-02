//! RFC 9331 RateLimit + RateLimit-Policy header builder + the canonical
//! 5-arm `XRateLimitTypeKind` response-code taxonomy + `RateLimitHeaders`
//! payload (the typed shape the production Tower middleware writes onto
//! every 429 response — and informationally onto 200 responses for
//! customer SDK pre-emptive backoff).
//!
//! ## RFC 9331 IETF stable canonical
//!
//! Per sprint contract §14.s08.5, the canonical IETF format is
//! `RateLimit: limit=N, remaining=M, reset=S` (where `S` is
//! seconds-until-refill); the policy disclosure header is
//! `RateLimit-Policy: <limit>;w=<window>` (multiple policies allowed via
//! comma-separation, e.g. `100;w=60, 1000;w=3600`). Legacy custom
//! `X-RateLimit-*` headers are **NOT emitted** to avoid customer SDK
//! ambiguity; vendors (Bazel / Buck2 / Stripe / GitHub) consume RFC 9331
//! directly so adopting the IETF canonical = customer SDK works without
//! per-vendor adaptation.
//!
//! ## 5-arm `XRateLimitTypeKind` taxonomy
//!
//! Per sprint contract §5 R-S08-8, every 429 response carries a typed
//! discriminator (`X-Rate-Limit-Type`) signalling which camada layer
//! denied the request:
//!
//! - `tenant_quota` (camada 1; per-tenant DO; WI-S08-001) — within-plan
//!   429; SLI failure (bug nosso; counted in SLO-AVAIL-CAS-GET
//!   denominator per sprint contract §7.10.s08.1).
//! - `per_ip` (camada 2; CF edge; WI-S08-002) — adversarial IP flood;
//!   legitimate edge defense; NOT in SLI denominator.
//! - `per_pat` (camada 3; PAT misuse; WI-S08-003) — compromised
//!   credential signal; legitimate; NOT in SLI denominator.
//! - `over_quota` (camada 3; storage / bandwidth 100% boundary;
//!   WI-S08-003) — tenant exceeded plan; legitimate over-plan; NOT in
//!   SLI denominator (sprint contract §7.10.s08.1 critical SLI
//!   correctness fix).
//! - `global_circuit_open` (camada 0; THIS WI camada-0 emergency) —
//!   system-wide overload; 429 all requests; SLI failure (counted in
//!   SLI denominator EXCEPT when trip reason is ManualOverride; sprint
//!   contract §7.10.s08.1 + Lote 10.8bis P1-3 ManualOverride exclusion
//!   for planned drills).
//!
//! ## SLI distinction critical (sprint contract §7.10.s08.1)
//!
//! [`XRateLimitTypeKind::counts_against_sli`] returns the canonical
//! within-quota vs over-quota distinction the SLO numerator depends on.
//! Without this, error budget exhausts on legitimate over-plan paths +
//! obscures real failures (`tenant_quota` 429s being counted as bug
//! nosso). The corresponding metrics emit through
//! [`crate::metrics::CircuitMetricsObserver::record_within_quota`]
//! (counts in SLI) vs `record_over_quota` (legitimate; NOT counted).

/// Canonical 5-arm response-code taxonomy per sprint contract §5 R-S08-8.
///
/// Carried in the `X-Rate-Limit-Type` HTTP header on every 429 response;
/// the tower middleware in production wiring derives the kind from the
/// camada that denied the request.
///
/// `#[non_exhaustive]` reserves additive growth for follow-on WIs (e.g.
/// per-region scoping; cross-region federation deferred S-14 per sprint
/// contract §10 anti-scope).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum XRateLimitTypeKind {
    /// Camada 1; per-tenant DO; WI-S08-001 within-plan 429.
    TenantQuota,
    /// Camada 2; CF edge; WI-S08-002 adversarial IP flood.
    PerIp,
    /// Camada 3; per-PAT misuse signal; WI-S08-003.
    PerPat,
    /// Camada 3; storage / bandwidth 100% boundary; WI-S08-003.
    OverQuota,
    /// Camada 0; this WI emergency global circuit open.
    GlobalCircuitOpen,
}

impl XRateLimitTypeKind {
    /// Canonical `X-Rate-Limit-Type` header string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantQuota => "tenant_quota",
            Self::PerIp => "per_ip",
            Self::PerPat => "per_pat",
            Self::OverQuota => "over_quota",
            Self::GlobalCircuitOpen => "global_circuit_open",
        }
    }

    /// SLI distinction predicate (sprint contract §7.10.s08.1):
    /// returns `true` when this 429 type counts in the
    /// SLO-AVAIL-CAS-GET denominator (within-quota; bug nosso) and
    /// `false` when it is legitimate over-plan / edge defense (NOT
    /// counted; per sprint contract §7.10.s08.1 SLI correctness fix).
    ///
    /// `is_manual_override` (per Lote 10.8bis P1-3 R5 fix) excludes
    /// planned-drill ManualOverride trips from the denominator — those
    /// are intentional load-shed actions, not system overload bugs.
    /// Callers MUST pass `true` only when the underlying trip reason is
    /// `ManualOverride`.
    #[must_use]
    pub const fn counts_against_sli(self, is_manual_override: bool) -> bool {
        match self {
            Self::TenantQuota => true,
            Self::GlobalCircuitOpen => !is_manual_override,
            Self::PerIp | Self::PerPat | Self::OverQuota => false,
        }
    }
}

impl core::fmt::Display for XRateLimitTypeKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical 5-arm enumeration for cross-component regression tests +
/// dashboard widget configuration. The order mirrors sprint contract
/// §5 R-S08-8 textual listing.
#[must_use]
pub const fn canonical_kind_list() -> [XRateLimitTypeKind; 5] {
    [
        XRateLimitTypeKind::TenantQuota,
        XRateLimitTypeKind::PerIp,
        XRateLimitTypeKind::PerPat,
        XRateLimitTypeKind::OverQuota,
        XRateLimitTypeKind::GlobalCircuitOpen,
    ]
}

/// One RFC 9331 `RateLimit-Policy` policy entry.
///
/// Format: `<limit>;w=<window>` (e.g. `100;w=60` = 100 requests per 60s
/// window). Multiple policies serialise as comma-separated tuples per
/// RFC 9331 §3 (e.g. `100;w=60, 1000;w=3600`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RateLimitPolicy {
    /// Token-bucket capacity ceiling (the `<limit>` field).
    pub limit: u64,
    /// Refill window in seconds (the `w=<window>` parameter).
    pub window_secs: u64,
}

impl RateLimitPolicy {
    /// Construct a policy with explicit fields.
    #[must_use]
    pub const fn new(limit: u64, window_secs: u64) -> Self {
        Self { limit, window_secs }
    }

    /// Render as the canonical RFC 9331 textual entry
    /// (`<limit>;w=<window>`).
    #[must_use]
    pub fn render(&self) -> String {
        format!("{};w={}", self.limit, self.window_secs)
    }
}

/// Canonical CoreLink customer-facing pricing URL — value of the
/// `X-CoreLink-Tier-Upgrade-URL` header and the `tier_upgrade_url`
/// field of the canonical 429 JSON body (`RateLimitErrorBody`).
///
/// Frozen at `https://corelink-docs.humangr.com/pricing` (live flat
/// `corelink-*.humangr.com` hostname; serves the Pricing page with a final
/// 200 after the docs-worker's deep-path-preserving redirect) per the audit
/// `specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` §2.
pub const TIER_UPGRADE_URL: &str = "https://corelink-docs.humangr.com/pricing";

/// Canonical customer-facing rate-limit docs URL — value of the
/// `docs_url` field of the canonical 429 JSON body (`RateLimitErrorBody`).
///
/// Frozen at `https://corelink-docs.humangr.com/explanation/rate-limits`
/// (live flat `corelink-*.humangr.com` hostname; serves the rate-limits page
/// with a final 200 after the docs-worker's deep-path-preserving redirect)
/// per the audit `specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` §2;
/// matches the Diátaxis Explanation quadrant doc at
/// `apps/docs/docs/explanation/rate-limits.mdx`.
pub const DOCS_URL: &str = "https://corelink-docs.humangr.com/explanation/rate-limits";

/// Typed RFC 9331 + Retry-After + X-Rate-Limit-Type +
/// CoreLink-vendor-extension header payload.
///
/// The production Tower middleware writes these onto the `http::Response`
/// builder; the in-memory crate exposes the typed shape so tests can
/// assert against fields rather than string-grep across the rendered
/// header bytes.
///
/// Vendor-extension headers (`X-CoreLink-Tier`,
/// `X-CoreLink-Quota-Reset-UTC`, `X-CoreLink-Tier-Upgrade-URL`) are
/// **informational additions** alongside (NOT replacements for) the
/// IETF canonical RFC 9331 + RFC 6585 pair per the audit
/// `specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` §3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RateLimitHeaders {
    /// RFC 9331 `RateLimit: limit=…` field.
    pub limit: u64,
    /// RFC 9331 `RateLimit: remaining=…` field. Per the IETF draft this
    /// is the integer floor of available tokens at the boundary.
    pub remaining: u64,
    /// RFC 9331 `RateLimit: reset=…` field — seconds-until-refill.
    pub reset_secs: u64,
    /// RFC 9331 `RateLimit-Policy` policies (≥ 1; production wiring
    /// emits one entry per active camada the caller is subject to).
    pub policies: Vec<RateLimitPolicy>,
    /// RFC 6585 §4 `Retry-After` (always present per sprint contract
    /// §5 R-S08-9).
    pub retry_after_secs: u64,
    /// CoreLink-specific `X-Rate-Limit-Type` discriminator (5-arm).
    pub x_rate_limit_type: XRateLimitTypeKind,
    /// CoreLink-vendor `X-CoreLink-Tier` informational header — the
    /// customer's current rate-limit tier in snake_case (e.g. `free`,
    /// `solo`, `team`, `business`, `enterprise`). Empty string is the
    /// degraded fallback when the camada that emitted the 429 cannot
    /// resolve the tier (e.g. `per_ip` adversarial drop pre-auth).
    pub corelink_tier: String,
    /// CoreLink-vendor `X-CoreLink-Quota-Reset-UTC` informational header
    /// — absolute RFC 3339 timestamp companion to the RFC 9331 `reset=`
    /// seconds-form. Empty string is the degraded fallback when the
    /// camada cannot resolve the absolute reset (e.g. global circuit
    /// hysteresis sample interval).
    pub corelink_quota_reset_utc: String,
    /// CoreLink-vendor `X-CoreLink-Tier-Upgrade-URL` informational
    /// header — frozen at [`TIER_UPGRADE_URL`] for SDK CTA convenience.
    /// SDKs that want to print "click here to upgrade" read this header
    /// rather than hard-coding the URL.
    pub corelink_tier_upgrade_url: &'static str,
}

impl RateLimitHeaders {
    /// Render the canonical `RateLimit:` value (no header name; the
    /// production wiring prepends `RateLimit:` via the `http::Response`
    /// builder).
    ///
    /// Format: `limit=N, remaining=M, reset=S` (RFC 9331 §2 stable).
    #[must_use]
    pub fn render_rate_limit(&self) -> String {
        format!(
            "limit={}, remaining={}, reset={}",
            self.limit, self.remaining, self.reset_secs
        )
    }

    /// Render the canonical `RateLimit-Policy:` value (no header name).
    ///
    /// Format: `<limit>;w=<window>, <limit>;w=<window>, …` (RFC 9331 §3).
    /// Returns the empty string when `policies` is empty (the production
    /// wiring SHOULD always emit ≥ 1 policy; the empty case is a
    /// degraded fallback for the carrier-doesn't-know-the-policy edge).
    #[must_use]
    pub fn render_rate_limit_policy(&self) -> String {
        let mut out = String::new();
        let mut first = true;
        for p in &self.policies {
            if !first {
                out.push_str(", ");
            }
            first = false;
            out.push_str(&p.render());
        }
        out
    }

    /// Render the `X-Rate-Limit-Type` value.
    #[must_use]
    pub const fn render_x_rate_limit_type(&self) -> &'static str {
        self.x_rate_limit_type.as_str()
    }

    /// Render the `Retry-After` value (RFC 6585 §4 seconds form).
    #[must_use]
    pub fn render_retry_after(&self) -> String {
        self.retry_after_secs.to_string()
    }
}

/// RFC 9331 + Retry-After header builder.
///
/// Composes [`RateLimitHeaders`] from per-camada bucket state +
/// per-request decision context. The canonical entry is
/// [`RateLimitHeaderBuilder::build`] which renders the full
/// 5-tuple typed payload. The render-stage helpers
/// ([`RateLimitHeaders::render_rate_limit`] etc.) ship the canonical
/// strings the production Tower middleware writes.
///
/// Per WI §6.1.4 Retry-After is type-specific:
///
/// - `tenant_quota`: from WI-S08-001 RateLimitResult.retry_after_seconds
///   (canonical `(amount_needed - tokens_remaining) / refill_rate`).
/// - `per_ip`: 60s canonical (CF Ruleset mitigation_timeout).
/// - `per_pat`: from WI-S08-003 PatRateResult.retry_after_seconds.
/// - `over_quota` (storage): days-until-month-reset (canonical per
///   ADR-0020 FROZEN; emitted by `corelink-quota-cas`).
/// - `over_quota` (bandwidth): seconds-until-next-month-1st-UTC.
/// - `global_circuit_open`: 60s canonical (hysteresis sample interval).
#[derive(Clone, Copy, Debug, Default)]
pub struct RateLimitHeaderBuilder;

/// Canonical Retry-After for the `per_ip` camada (CF Ruleset
/// mitigation_timeout per WI §6.1.4).
pub const PER_IP_RETRY_AFTER_SECS: u64 = 60;

/// Canonical Retry-After for the `global_circuit_open` camada (hysteresis
/// sample interval per WI §6.1.4 + the canonical 2min HalfOpen dwell
/// floor — 60s is the SAMPLE interval, NOT the dwell; the SDK SHOULD
/// retry at 60s where it has another chance to land in HalfOpen sample).
pub const GLOBAL_CIRCUIT_RETRY_AFTER_SECS: u64 = 60;

/// Hard upper bound on Retry-After across all camadas (sprint contract
/// §6 DoD: < 30 days). Headers builder clamps so `over_quota` storage
/// never emits > 30 days even if the days-until-month-reset arithmetic
/// glitches at the month boundary.
pub const RETRY_AFTER_HARD_CEILING_SECS: u64 = 30 * 24 * 60 * 60;

impl RateLimitHeaderBuilder {
    /// Build a typed [`RateLimitHeaders`] payload from the per-camada
    /// decision context.
    ///
    /// `limit` is the bucket capacity (RFC 9331 `limit=`).
    /// `remaining` is `available_tokens.floor()` (RFC 9331 `remaining=`).
    /// `reset_secs` is seconds-until-refill (RFC 9331 `reset=`).
    /// `policies` is one entry per active camada (≥ 1).
    /// `retry_after_secs` is the type-specific value per WI §6.1.4
    /// (clamped to [`RETRY_AFTER_HARD_CEILING_SECS`]).
    /// `kind` is the 5-arm taxonomy discriminator.
    #[must_use]
    pub fn build(
        limit: u64,
        remaining: u64,
        reset_secs: u64,
        policies: Vec<RateLimitPolicy>,
        retry_after_secs: u64,
        kind: XRateLimitTypeKind,
    ) -> RateLimitHeaders {
        Self::build_with_vendor(
            limit,
            remaining,
            reset_secs,
            policies,
            retry_after_secs,
            kind,
            String::new(),
            String::new(),
        )
    }

    /// Build a typed [`RateLimitHeaders`] payload including the
    /// CoreLink-vendor extension headers (`X-CoreLink-Tier`,
    /// `X-CoreLink-Quota-Reset-UTC`, `X-CoreLink-Tier-Upgrade-URL`).
    ///
    /// `tier` is the customer's rate-limit tier (snake_case;
    /// `corelink-ratelimit` vocabulary — `free` / `solo` / `team` /
    /// `business` / `enterprise`); empty string is the degraded
    /// fallback for camadas that cannot resolve a tier (e.g. `per_ip`
    /// pre-auth adversarial drop).
    ///
    /// `quota_reset_utc` is an absolute RFC 3339 timestamp companion
    /// to the RFC 9331 `reset=` seconds form; empty string is the
    /// degraded fallback when the camada cannot resolve an absolute
    /// reset (e.g. `global_circuit_open` hysteresis sample interval).
    ///
    /// The tier-upgrade URL is always [`TIER_UPGRADE_URL`].
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "8-tuple mirrors the canonical RFC 9331 + RFC 6585 + \
                  CoreLink-vendor header set per audit §2-3; refactoring \
                  into a builder is deferred to the production Tower \
                  middleware (trait-abstraction-defer charter)"
    )]
    pub fn build_with_vendor(
        limit: u64,
        remaining: u64,
        reset_secs: u64,
        policies: Vec<RateLimitPolicy>,
        retry_after_secs: u64,
        kind: XRateLimitTypeKind,
        tier: String,
        quota_reset_utc: String,
    ) -> RateLimitHeaders {
        let clamped_retry_after = retry_after_secs.min(RETRY_AFTER_HARD_CEILING_SECS);
        // remaining is structurally clamped to ≤ limit per RFC 9331 §2.
        let clamped_remaining = remaining.min(limit);
        RateLimitHeaders {
            limit,
            remaining: clamped_remaining,
            reset_secs,
            policies,
            retry_after_secs: clamped_retry_after,
            x_rate_limit_type: kind,
            corelink_tier: tier,
            corelink_quota_reset_utc: quota_reset_utc,
            corelink_tier_upgrade_url: TIER_UPGRADE_URL,
        }
    }

    /// Convenience for the global-circuit `429 GlobalCircuitOpen` arm:
    /// limit + remaining are both 0 (system-wide reject); reset = 60s
    /// (canonical hysteresis sample interval); retry_after = 60s.
    #[must_use]
    pub fn for_global_circuit_open(policies: Vec<RateLimitPolicy>) -> RateLimitHeaders {
        Self::build(
            0,
            0,
            GLOBAL_CIRCUIT_RETRY_AFTER_SECS,
            policies,
            GLOBAL_CIRCUIT_RETRY_AFTER_SECS,
            XRateLimitTypeKind::GlobalCircuitOpen,
        )
    }
}

/// Canonical 429 response JSON body schema (per audit
/// `specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` §2).
///
/// Customer SDKs pattern-match against `error.code` (the 5-arm stable
/// taxonomy mirroring [`XRateLimitTypeKind`]); humans read
/// `error.message`; retry loops honour
/// `error.retry_after_seconds`; upgrade CTAs link to
/// `error.tier_upgrade_url`; long-deferred retries use
/// `error.reset_utc` (absolute RFC 3339 timestamp robust against
/// clock skew).
///
/// The crate ships the typed shape + a deterministic JSON renderer
/// without taking a `serde` dependency — the production Tower
/// middleware (deferred) is the only consumer and prefers to render
/// directly via the minimal serialiser here to keep the wasm32-clean
/// dependency closure tight.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RateLimitErrorBody {
    /// Stable string enum — one of `rate_limit_exceeded` (the only
    /// value at GA; reserved as a single point of stability for SDKs
    /// that pattern-match `error.code`). Discrimination between
    /// camadas is via `kind`.
    pub code: &'static str,
    /// 5-arm taxonomy mirror — copy of the `X-Rate-Limit-Type` header.
    pub kind: XRateLimitTypeKind,
    /// Human-readable English sentence (localisation deferred S-22).
    pub message: String,
    /// Mirror of the `Retry-After` header.
    pub retry_after_seconds: u64,
    /// Customer's current rate-limit tier (snake_case; empty when
    /// pre-auth `per_ip` cannot resolve).
    pub tier: String,
    /// Frozen [`TIER_UPGRADE_URL`].
    pub tier_upgrade_url: &'static str,
    /// Frozen [`DOCS_URL`].
    pub docs_url: &'static str,
    /// UUIDv7 request-id (empty when caller doesn't have one to stamp).
    pub request_id: String,
    /// Mirror of RFC 9331 `RateLimit: limit=…`.
    pub limit: u64,
    /// Mirror of RFC 9331 `RateLimit: remaining=…`.
    pub remaining: u64,
    /// Mirror of RFC 9331 `RateLimit: reset=…` (seconds).
    pub reset_seconds: u64,
    /// Absolute reset (RFC 3339); empty when the camada cannot resolve.
    pub reset_utc: String,
}

/// Stable `error.code` value at GA (the only value SDKs see; the
/// camada discriminator is carried by `kind`).
pub const ERROR_CODE_RATE_LIMIT_EXCEEDED: &str = "rate_limit_exceeded";

impl RateLimitErrorBody {
    /// Compose a canonical body from a [`RateLimitHeaders`] payload +
    /// the per-request `message` + `request_id`.
    ///
    /// The body's `code` is always [`ERROR_CODE_RATE_LIMIT_EXCEEDED`];
    /// `kind / retry_after_seconds / tier / limit / remaining /
    /// reset_seconds / reset_utc` mirror the headers byte-for-byte;
    /// `tier_upgrade_url / docs_url` are the frozen canonical URLs.
    #[must_use]
    pub fn from_headers(headers: &RateLimitHeaders, message: String, request_id: String) -> Self {
        Self {
            code: ERROR_CODE_RATE_LIMIT_EXCEEDED,
            kind: headers.x_rate_limit_type,
            message,
            retry_after_seconds: headers.retry_after_secs,
            tier: headers.corelink_tier.clone(),
            tier_upgrade_url: TIER_UPGRADE_URL,
            docs_url: DOCS_URL,
            request_id,
            limit: headers.limit,
            remaining: headers.remaining,
            reset_seconds: headers.reset_secs,
            reset_utc: headers.corelink_quota_reset_utc.clone(),
        }
    }

    /// Render the canonical JSON envelope per audit §2.
    ///
    /// Deterministic field order (matches the audit document table).
    /// No `serde` dependency — keeps the wasm32 closure tight; the
    /// production Tower middleware writes these bytes verbatim.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str("{\"error\":{");
        push_json_string_field(&mut out, "code", self.code, true);
        push_json_string_field(&mut out, "kind", self.kind.as_str(), false);
        push_json_string_field(&mut out, "message", &self.message, false);
        push_json_u64_field(
            &mut out,
            "retry_after_seconds",
            self.retry_after_seconds,
            false,
        );
        push_json_string_field(&mut out, "tier", &self.tier, false);
        push_json_string_field(&mut out, "tier_upgrade_url", self.tier_upgrade_url, false);
        push_json_string_field(&mut out, "docs_url", self.docs_url, false);
        push_json_string_field(&mut out, "request_id", &self.request_id, false);
        push_json_u64_field(&mut out, "limit", self.limit, false);
        push_json_u64_field(&mut out, "remaining", self.remaining, false);
        push_json_u64_field(&mut out, "reset_seconds", self.reset_seconds, false);
        push_json_string_field(&mut out, "reset_utc", &self.reset_utc, false);
        out.push_str("}}");
        out
    }
}

/// Append a `"key":"value"` JSON field with optional leading comma.
/// Performs the minimal RFC 8259 escaping required for the value:
/// `"` `\` `\n` `\r` `\t` and control chars < 0x20.
fn push_json_string_field(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Canonical 6-char `\u00XX` escape for control chars.
                let code = c as u32;
                let hi = ((code >> 4) & 0xF) as u8;
                let lo = (code & 0xF) as u8;
                let to_hex = |n: u8| -> char {
                    if n < 10 {
                        (b'0' + n) as char
                    } else {
                        (b'a' + (n - 10)) as char
                    }
                };
                out.push_str("\\u00");
                out.push(to_hex(hi));
                out.push(to_hex(lo));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append a `"key":N` JSON numeric field with optional leading comma.
fn push_json_u64_field(out: &mut String, key: &str, value: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    // u64 -> decimal via `format!` is sound + non-allocating-on-stack.
    out.push_str(&value.to_string());
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_unique_canonical_string() {
        let v = canonical_kind_list();
        let mut set = std::collections::HashSet::new();
        for k in v {
            assert!(set.insert(k.as_str()));
        }
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn canonical_strings_match_sprint_contract_taxonomy() {
        assert_eq!(XRateLimitTypeKind::TenantQuota.as_str(), "tenant_quota");
        assert_eq!(XRateLimitTypeKind::PerIp.as_str(), "per_ip");
        assert_eq!(XRateLimitTypeKind::PerPat.as_str(), "per_pat");
        assert_eq!(XRateLimitTypeKind::OverQuota.as_str(), "over_quota");
        assert_eq!(
            XRateLimitTypeKind::GlobalCircuitOpen.as_str(),
            "global_circuit_open"
        );
    }

    #[test]
    fn sli_distinction_per_kind_canonical_5_arm() {
        // Within-quota 429 (counted in SLI denominator):
        assert!(XRateLimitTypeKind::TenantQuota.counts_against_sli(false));
        assert!(XRateLimitTypeKind::TenantQuota.counts_against_sli(true));
        // Over-quota / edge / PAT (NOT counted):
        assert!(!XRateLimitTypeKind::PerIp.counts_against_sli(false));
        assert!(!XRateLimitTypeKind::PerPat.counts_against_sli(false));
        assert!(!XRateLimitTypeKind::OverQuota.counts_against_sli(false));
        // GlobalCircuitOpen: counted UNLESS ManualOverride (Lote 10.8bis
        // P1-3 R5 planned-drill exclusion):
        assert!(XRateLimitTypeKind::GlobalCircuitOpen.counts_against_sli(false));
        assert!(!XRateLimitTypeKind::GlobalCircuitOpen.counts_against_sli(true));
    }

    #[test]
    fn render_rate_limit_canonical_format() {
        let h = RateLimitHeaderBuilder::build(
            100,
            42,
            60,
            vec![RateLimitPolicy::new(100, 60)],
            5,
            XRateLimitTypeKind::TenantQuota,
        );
        assert_eq!(h.render_rate_limit(), "limit=100, remaining=42, reset=60");
    }

    #[test]
    fn render_rate_limit_policy_single() {
        let h = RateLimitHeaderBuilder::build(
            100,
            0,
            60,
            vec![RateLimitPolicy::new(100, 60)],
            60,
            XRateLimitTypeKind::TenantQuota,
        );
        assert_eq!(h.render_rate_limit_policy(), "100;w=60");
    }

    #[test]
    fn render_rate_limit_policy_multiple() {
        let h = RateLimitHeaderBuilder::build(
            100,
            0,
            60,
            vec![
                RateLimitPolicy::new(100, 60),
                RateLimitPolicy::new(1000, 3600),
            ],
            60,
            XRateLimitTypeKind::TenantQuota,
        );
        assert_eq!(h.render_rate_limit_policy(), "100;w=60, 1000;w=3600");
    }

    #[test]
    fn render_x_rate_limit_type_returns_canonical() {
        let h = RateLimitHeaderBuilder::build(100, 0, 60, vec![], 60, XRateLimitTypeKind::PerIp);
        assert_eq!(h.render_x_rate_limit_type(), "per_ip");
    }

    #[test]
    fn render_retry_after_seconds_form() {
        let h =
            RateLimitHeaderBuilder::build(100, 0, 60, vec![], 42, XRateLimitTypeKind::TenantQuota);
        assert_eq!(h.render_retry_after(), "42");
    }

    #[test]
    fn build_clamps_retry_after_to_hard_ceiling() {
        let h = RateLimitHeaderBuilder::build(
            100,
            0,
            60,
            vec![],
            u64::MAX,
            XRateLimitTypeKind::OverQuota,
        );
        assert_eq!(h.retry_after_secs, RETRY_AFTER_HARD_CEILING_SECS);
    }

    #[test]
    fn build_clamps_remaining_to_limit() {
        let h =
            RateLimitHeaderBuilder::build(100, 500, 60, vec![], 5, XRateLimitTypeKind::TenantQuota);
        assert_eq!(h.remaining, 100);
    }

    #[test]
    fn for_global_circuit_open_canonical_60s() {
        let h =
            RateLimitHeaderBuilder::for_global_circuit_open(vec![RateLimitPolicy::new(100, 60)]);
        assert_eq!(h.limit, 0);
        assert_eq!(h.remaining, 0);
        assert_eq!(h.reset_secs, 60);
        assert_eq!(h.retry_after_secs, 60);
        assert_eq!(h.x_rate_limit_type, XRateLimitTypeKind::GlobalCircuitOpen);
    }

    #[test]
    fn rate_limit_policy_render_format() {
        let p = RateLimitPolicy::new(200, 60);
        assert_eq!(p.render(), "200;w=60");
    }

    #[test]
    fn empty_policies_render_to_empty_string() {
        let h =
            RateLimitHeaderBuilder::build(100, 0, 60, vec![], 5, XRateLimitTypeKind::TenantQuota);
        assert_eq!(h.render_rate_limit_policy(), "");
    }

    #[test]
    fn display_kind_matches_as_str() {
        assert_eq!(
            format!("{}", XRateLimitTypeKind::TenantQuota),
            "tenant_quota"
        );
    }

    // ---- Vendor-extension header coverage (audit §3) -----------------

    #[test]
    fn build_default_vendor_fields_empty() {
        // `build` (legacy entrypoint) defaults the vendor fields to
        // empty strings + the frozen upgrade URL.
        let h =
            RateLimitHeaderBuilder::build(100, 0, 60, vec![], 5, XRateLimitTypeKind::TenantQuota);
        assert_eq!(h.corelink_tier, "");
        assert_eq!(h.corelink_quota_reset_utc, "");
        assert_eq!(h.corelink_tier_upgrade_url, TIER_UPGRADE_URL);
    }

    #[test]
    fn build_with_vendor_populates_all_three_vendor_headers() {
        let h = RateLimitHeaderBuilder::build_with_vendor(
            10,
            0,
            5,
            vec![RateLimitPolicy::new(10, 1)],
            5,
            XRateLimitTypeKind::TenantQuota,
            String::from("free"),
            String::from("2026-05-15T14:30:25Z"),
        );
        assert_eq!(h.corelink_tier, "free");
        assert_eq!(h.corelink_quota_reset_utc, "2026-05-15T14:30:25Z");
        assert_eq!(
            h.corelink_tier_upgrade_url,
            "https://corelink-docs.humangr.com/pricing"
        );
    }

    #[test]
    fn tier_upgrade_url_frozen_canonical_value() {
        assert_eq!(
            TIER_UPGRADE_URL,
            "https://corelink-docs.humangr.com/pricing"
        );
    }

    #[test]
    fn docs_url_frozen_canonical_value() {
        assert_eq!(
            DOCS_URL,
            "https://corelink-docs.humangr.com/explanation/rate-limits"
        );
    }

    /// Regression guard: the 429-body URLs must stay on the live flat docs
    /// host. An allowlist, not a denylist: it refuses the unprovisioned dotted
    /// `corelink.` / `docs.corelink.` subdomains (both NXDOMAIN) and any other.
    #[test]
    fn urls_use_live_flat_hosts_not_dotted_subdomains() {
        for url in [TIER_UPGRADE_URL, DOCS_URL] {
            assert!(
                url.starts_with("https://corelink-docs.humangr.com/"),
                "429-body URL left the live flat docs host: {url}"
            );
            assert!(url.starts_with("https://"), "non-https URL: {url}");
        }
    }

    // ---- 429 JSON body coverage (audit §2) ---------------------------

    #[test]
    fn body_from_headers_mirrors_every_field() {
        let h = RateLimitHeaderBuilder::build_with_vendor(
            10,
            0,
            5,
            vec![RateLimitPolicy::new(10, 1)],
            5,
            XRateLimitTypeKind::TenantQuota,
            String::from("free"),
            String::from("2026-05-15T14:30:25Z"),
        );
        let body = RateLimitErrorBody::from_headers(
            &h,
            String::from("Request rate exceeded"),
            String::from("01HFXYZABC"),
        );
        assert_eq!(body.code, "rate_limit_exceeded");
        assert_eq!(body.kind, XRateLimitTypeKind::TenantQuota);
        assert_eq!(body.message, "Request rate exceeded");
        assert_eq!(body.retry_after_seconds, h.retry_after_secs);
        assert_eq!(body.tier, "free");
        assert_eq!(body.tier_upgrade_url, TIER_UPGRADE_URL);
        assert_eq!(body.docs_url, DOCS_URL);
        assert_eq!(body.request_id, "01HFXYZABC");
        assert_eq!(body.limit, h.limit);
        assert_eq!(body.remaining, h.remaining);
        assert_eq!(body.reset_seconds, h.reset_secs);
        assert_eq!(body.reset_utc, "2026-05-15T14:30:25Z");
    }

    #[test]
    fn body_render_json_canonical_shape() {
        let h = RateLimitHeaderBuilder::build_with_vendor(
            10,
            0,
            5,
            vec![],
            5,
            XRateLimitTypeKind::TenantQuota,
            String::from("free"),
            String::from("2026-05-15T14:30:25Z"),
        );
        let body = RateLimitErrorBody::from_headers(
            &h,
            String::from("Request rate exceeded"),
            String::from("01HFXYZABC"),
        );
        let json = body.render_json();
        // Structural assertions (the audit document §2 pins shape;
        // ordering is canonical: code → kind → message → retry_after
        // → tier → upgrade → docs → request_id → limit → remaining
        // → reset_seconds → reset_utc).
        assert!(json.starts_with("{\"error\":{\"code\":\"rate_limit_exceeded\""));
        assert!(json.ends_with("}}"));
        assert!(json.contains("\"kind\":\"tenant_quota\""));
        assert!(json.contains("\"retry_after_seconds\":5"));
        assert!(json.contains("\"tier\":\"free\""));
        assert!(json.contains("\"tier_upgrade_url\":\"https://corelink-docs.humangr.com/pricing\""));
        assert!(json.contains(
            "\"docs_url\":\"https://corelink-docs.humangr.com/explanation/rate-limits\""
        ));
        assert!(json.contains("\"request_id\":\"01HFXYZABC\""));
        assert!(json.contains("\"limit\":10"));
        assert!(json.contains("\"remaining\":0"));
        assert!(json.contains("\"reset_seconds\":5"));
        assert!(json.contains("\"reset_utc\":\"2026-05-15T14:30:25Z\""));
    }

    #[test]
    fn body_render_json_escapes_user_message() {
        // Audit §2: `message` is human-readable; an adversarial message
        // containing `"` `\` `\n` MUST NOT break the JSON envelope.
        let h = RateLimitHeaderBuilder::build(10, 0, 5, vec![], 5, XRateLimitTypeKind::TenantQuota);
        let body = RateLimitErrorBody::from_headers(
            &h,
            String::from("oops \"quotes\" and \\ and \nnewlines"),
            String::new(),
        );
        let json = body.render_json();
        assert!(json.contains("\"message\":\"oops \\\"quotes\\\" and \\\\ and \\nnewlines\""));
        // Envelope still parses-shaped.
        assert!(json.starts_with("{\"error\":{"));
        assert!(json.ends_with("}}"));
    }

    #[test]
    fn body_per_ip_arm_has_empty_tier_acceptable() {
        // `per_ip` is pre-auth; tier may legitimately be empty.
        let h = RateLimitHeaderBuilder::build(0, 0, 60, vec![], 60, XRateLimitTypeKind::PerIp);
        let body = RateLimitErrorBody::from_headers(
            &h,
            String::from("IP rate limit exceeded"),
            String::new(),
        );
        assert_eq!(body.tier, "");
        assert_eq!(body.kind, XRateLimitTypeKind::PerIp);
        // Still emits the upgrade URL — useful for legit users behind
        // a corporate NAT who hit per_ip; clicking through gets them
        // to an authed Starter+ tier with a higher per-PAT ceiling.
        assert_eq!(body.tier_upgrade_url, TIER_UPGRADE_URL);
    }

    #[test]
    fn body_kind_matches_x_rate_limit_type_header() {
        // The body's `kind` MUST mirror the header's discriminator,
        // for ALL 5 arms (the audit §6 property test pins this at
        // 10k iterations; here we pin the 5 deterministic cases).
        for kind in canonical_kind_list() {
            let h = RateLimitHeaderBuilder::build(10, 0, 5, vec![], 5, kind);
            let body = RateLimitErrorBody::from_headers(&h, String::from("denied"), String::new());
            assert_eq!(body.kind, kind);
            assert_eq!(body.kind.as_str(), h.render_x_rate_limit_type());
        }
    }
}
