//! Cloudflare D1 HTTP API client for native-container metadata reads.
//!
//! D1 is accessible outside a CF Worker via the Cloudflare REST API:
//! `https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{db_id}/query`
//! In staging, the same path is sent to the reserved `.invalid` hostname and
//! intercepted by the Worker before the internet-enabled container starts.
//!
//! This module provides [`D1HttpClient`] — an async `reqwest`-based
//! client for running parameterised SQL queries against a D1 database
//! from the native Firecracker container.
//!
//! # Security charter compliance
//!
//! - CF API token is loaded from env via [`StorageEnv`] and never
//!   logged.
//! - The query URL is never configuration text. The account and database
//!   ids must each be 1-64 characters from `[0-9A-Za-z_-]`; they are parsed
//!   into symbol codes when the client is built, and the URL is re-rendered
//!   for every request from fixed literals plus characters looked up from a
//!   fixed table. No configured byte is copied into the URL (#1674,
//!   `rust/request-forgery`).
//! - No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.
//! - `#![forbid(unsafe_code)]` inherited from crate root.
//!
//! # Usage pattern
//!
//! ```ignore
//! let client = D1HttpClient::new(&env);
//! let rows = client.query("SELECT * FROM blob_meta WHERE digest = ?1",
//!                         &[serde_json::json!("abc123")]).await?;
//! ```

use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr};
use tracing::{debug, warn};

use super::StorageEnv;

fn runtime_d1_credential() -> Result<String, String> {
    if super::staging_d1_binding_proxy_enabled()? {
        if super::non_empty_env("CF_API_TOKEN").is_some() {
            return Err("CF_API_TOKEN must be absent in D1 binding proxy mode".to_owned());
        }
        return Ok(String::new());
    }
    super::non_empty_env("CF_API_TOKEN").ok_or_else(|| "CF_API_TOKEN is required".to_owned())
}

/// Async D1 HTTP API client.
///
/// `Debug` is a manual redacting impl (NOT `#[derive(Debug)]`) so a `{:?}` of
/// the root client can never print the CF API bearer token. Wrapper structs
/// (`D1HttpCustomerDb` etc.) already redact, but the root type must too.
pub struct D1HttpClient {
    http: reqwest::Client,
    /// Parsed query target. The URL
    /// (`https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{db_id}/query`)
    /// is rendered from it per request by [`D1Endpoint::query_url`].
    endpoint: D1Endpoint,
    /// Bearer token for the `Authorization` header (CF API token).
    /// Never logged — stored as a plain `String` but treated as a secret.
    api_token: String,
    /// Reject every non-SELECT statement before it reaches D1.
    read_only: bool,
}

impl core::fmt::Debug for D1HttpClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("D1HttpClient")
            .field("query_url", &self.endpoint.query_url())
            .field("api_token", &"[REDACTED]")
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

/// A single row returned from D1: a map of column name → JSON value.
pub type D1Row = serde_json::Map<String, serde_json::Value>;

/// Wire shape of a D1 query response.
#[derive(Debug, Deserialize)]
struct D1Response {
    result: Vec<D1QueryResult>,
    success: bool,
    errors: Vec<D1Error>,
}

/// Per-statement result inside a [`D1Response`].
#[derive(Debug, Deserialize)]
struct D1QueryResult {
    results: Vec<D1Row>,
    #[serde(default)]
    success: Option<bool>,
}

/// A Cloudflare API error object.
#[derive(Debug, Deserialize)]
struct D1Error {
    message: String,
}

/// Request body for the D1 query endpoint.
#[derive(Debug, Serialize)]
struct D1QueryRequest<'a> {
    sql: &'a str,
    params: Vec<serde_json::Value>,
}

/// One parameterised statement in the crate-private transactional primitive.
/// Domain adapters expose typed operations instead of arbitrary SQL batches.
#[derive(Debug, Serialize)]
pub(crate) struct D1BatchStatement {
    sql: String,
    params: Vec<serde_json::Value>,
}

impl D1BatchStatement {
    pub(crate) fn new(sql: impl Into<String>, params: Vec<serde_json::Value>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }
}

#[derive(Debug, Serialize)]
struct D1BatchRequest {
    batch: Vec<D1BatchStatement>,
}

#[derive(Debug)]
pub(crate) struct D1BatchError {
    pub(crate) statement: Option<usize>,
    pub(crate) message: String,
}

impl D1HttpClient {
    /// Construct a D1-only client from the native process environment.
    ///
    /// This intentionally does not require the R2 S3 credentials carried by
    /// [`StorageEnv`]. Read-only operators such as the production GC
    /// observation path must not receive an unused object-delete credential.
    ///
    /// # Errors
    ///
    /// Returns an error when any D1 scope/credential is absent, an id is
    /// malformed (see [`D1HttpClient::new`]), or the HTTP client cannot be
    /// built.
    pub fn from_d1_env() -> Result<Self, String> {
        let account_id = super::non_empty_env("CLOUDFLARE_ACCOUNT_ID")
            .ok_or_else(|| "CLOUDFLARE_ACCOUNT_ID is required".to_owned())?;
        let database_id = super::non_empty_env("D1_DATABASE_ID")
            .ok_or_else(|| "D1_DATABASE_ID is required".to_owned())?;
        let api_token = runtime_d1_credential()?;
        Self::from_d1_parts(&account_id, &database_id, api_token, true)
    }

    /// Construct a writable D1 client from the D1-only integration inputs.
    ///
    /// Test-only so live D1 integration tests do not require an unrelated R2
    /// credential tuple. Production code should use the scoped constructors.
    #[cfg(test)]
    pub(crate) fn from_d1_env_for_integration_tests() -> Result<Self, String> {
        let account_id = super::non_empty_env("CLOUDFLARE_ACCOUNT_ID")
            .ok_or_else(|| "CLOUDFLARE_ACCOUNT_ID is required".to_owned())?;
        let database_id = super::non_empty_env("D1_DATABASE_ID")
            .ok_or_else(|| "D1_DATABASE_ID is required".to_owned())?;
        let api_token = runtime_d1_credential()?;
        Self::from_d1_parts(&account_id, &database_id, api_token, false)
    }

    /// Construct the narrow staging load-test ledger writer without requiring
    /// or loading any R2 credentials. This is crate-private; callers receive
    /// the typed append-only adapter rather than an unrestricted public D1
    /// write client.
    pub(crate) fn for_staging_load_test_ownership_writes() -> Result<Self, String> {
        let account_id = super::non_empty_env("CLOUDFLARE_ACCOUNT_ID")
            .ok_or_else(|| "CLOUDFLARE_ACCOUNT_ID is required".to_owned())?;
        let database_id = super::non_empty_env("D1_DATABASE_ID")
            .ok_or_else(|| "D1_DATABASE_ID is required".to_owned())?;
        let api_token = runtime_d1_credential()?;
        Self::from_d1_parts(&account_id, &database_id, api_token, false)
    }

    /// Construct a new [`D1HttpClient`] from a validated [`StorageEnv`].
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `CLOUDFLARE_ACCOUNT_ID` or `D1_DATABASE_ID`
    /// is not 1-64 characters from `[0-9A-Za-z_-]`, or if `reqwest::Client`
    /// cannot be built (in practice this only fails on platforms that lack
    /// TLS support). A refused id never yields a client, so no request can be
    /// sent with it.
    pub fn new(env: &StorageEnv) -> Result<Self, String> {
        Self::from_d1_parts(
            &env.cloudflare_account_id,
            &env.d1_database_id,
            env.cf_api_token.clone(),
            false,
        )
    }

    fn from_d1_parts(
        account_id: &str,
        database_id: &str,
        api_token: String,
        read_only: bool,
    ) -> Result<Self, String> {
        // Parse both ids before anything else. Only their symbol codes
        // survive; the configured text is dropped here and never reaches a URL.
        let scope = D1Scope::parse(account_id, database_id)?;
        let endpoint = if api_token.is_empty() {
            D1Endpoint::StagingBindingProxy(scope)
        } else {
            D1Endpoint::CloudflareApi(scope)
        };
        // Bound EVERY D1-over-HTTP call. A single erase drives ~15 serial D1
        // round-trips (legitimacy + idempotency ledger + audit envelope + the
        // D1/R2 adapters), and the CF D1 REST API rate-limits + slows under a
        // burst (e.g. a bulk DSR backlog drain). A reqwest client built with NO
        // timeout lets a slowed/stuck call hold its container worker
        // INDEFINITELY; under sustained load those held workers accrete until the
        // tokio executor is saturated and the whole container stops responding
        // (observed: the `_system` container hanging after ~35-45 DSR ops, only a
        // recycle restoring it). Explicit connect + total timeouts convert a slow
        // backend into a fast, retryable error that RELEASES the worker, so the
        // container degrades gracefully instead of wedging. `pool_idle_timeout`
        // keeps the idle-connection set from lingering across a long drain.
        let http = build_http_client()?;
        Ok(Self {
            http,
            endpoint,
            api_token,
            read_only,
        })
    }

    /// Construct a D1 client for an explicitly supplied loopback endpoint.
    ///
    /// This seam is intentionally named and constrained for integration tests:
    /// it cannot redirect requests to a hostname, a non-loopback address, or
    /// an URL carrying credentials or hidden query/fragment components. Its
    /// path must be empty (`/`) or `/d1`, the only two its tests use.
    pub fn new_for_loopback_test(env: &StorageEnv, query_url: &str) -> Result<Self, String> {
        let endpoint = D1Endpoint::Loopback(parse_loopback_query_url(query_url)?);
        let http = build_http_client()?;
        Ok(Self {
            http,
            endpoint,
            api_token: env.cf_api_token.clone(),
            read_only: false,
        })
    }

    /// Execute a parameterised SQL query against the D1 database.
    ///
    /// `params` must be positional (D1 uses `?1`, `?2`, … syntax for
    /// CF Workers; the HTTP API accepts a JSON array of values in
    /// order).
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on HTTP failure, JSON parse error, or
    /// a D1-level error returned in the `errors` array.
    pub async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<D1Row>, String> {
        if self.read_only && !is_select_statement(sql) {
            return Err("D1 read-only client rejected a non-SELECT statement".to_owned());
        }
        debug!(sql = %sql, params = params.len(), "D1HttpClient::query");

        let body = D1QueryRequest {
            sql,
            params: params.to_vec(),
        };

        let mut request = self.http.post(self.endpoint.query_url()).json(&body);
        if !self.api_token.is_empty() {
            request = request.bearer_auth(&self.api_token);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| format!("D1 HTTP request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            return Err(format!("D1 HTTP {status}: {text}"));
        }

        let parsed: D1Response = resp
            .json()
            .await
            .map_err(|e| format!("D1 response JSON parse failed: {e}"))?;
        validate_query_response(parsed, sql)
    }

    /// Execute a parameterised D1 REST batch. Cloudflare runs statements
    /// sequentially in one transaction and rolls the complete batch back if
    /// any statement fails. Kept crate-private to avoid arbitrary SQL batch
    /// exposure at domain seams.
    pub(crate) async fn batch(
        &self,
        statements: Vec<D1BatchStatement>,
    ) -> Result<Vec<Vec<D1Row>>, D1BatchError> {
        if self.read_only {
            return Err(D1BatchError {
                statement: None,
                message: "D1 read-only client rejected a batch request".to_owned(),
            });
        }
        let expected = statements.len();
        if expected == 0 {
            return Err(D1BatchError {
                statement: None,
                message: "D1 batch must contain at least one statement".to_owned(),
            });
        }
        debug!(statements = expected, "D1HttpClient::batch");
        let body = D1BatchRequest { batch: statements };
        let mut request = self.http.post(self.endpoint.query_url()).json(&body);
        if !self.api_token.is_empty() {
            request = request.bearer_auth(&self.api_token);
        }
        let resp = request.send().await.map_err(|e| D1BatchError {
            statement: None,
            message: format!("D1 HTTP batch request failed: {e}"),
        })?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            return Err(D1BatchError {
                statement: None,
                message: format!("D1 HTTP {status}: {text}"),
            });
        }
        let parsed: D1Response = resp.json().await.map_err(|e| D1BatchError {
            statement: None,
            message: format!("D1 batch response JSON parse failed: {e}"),
        })?;
        validate_batch_response(parsed, expected)
    }
}

fn is_select_statement(sql: &str) -> bool {
    let sql = sql.trim();
    let statement = sql.strip_suffix(';').unwrap_or(sql).trim_end();
    if statement.contains(';') {
        return false;
    }
    statement
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("select"))
        && statement
            .as_bytes()
            .get(6)
            .is_some_and(u8::is_ascii_whitespace)
}

/// Validate the complete response for the single-statement query endpoint.
/// Top-level success alone is insufficient: a missing, duplicate, or
/// indeterminate nested result would make an empty row set indistinguishable
/// from a transport/schema failure.
fn validate_query_response(parsed: D1Response, sql: &str) -> Result<Vec<D1Row>, String> {
    let message = parsed
        .errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if !parsed.success {
        warn!(sql = %sql, errors = %message, "D1 query returned errors");
        return Err(format!("D1 query errors: {message}"));
    }
    if !parsed.errors.is_empty() {
        warn!(
            sql = %sql,
            errors = %message,
            "D1 query response reported success with errors"
        );
        return Err(format!(
            "D1 query response reported success with errors: {message}"
        ));
    }
    if parsed.result.len() != 1 {
        return Err(format!(
            "D1 query response result count {} != submitted statement count 1",
            parsed.result.len()
        ));
    }
    let mut results = parsed.result.into_iter();
    let result = results
        .next()
        .ok_or_else(|| "D1 query response omitted its result".to_owned())?;
    if result.success != Some(true) {
        return Err("D1 query response nested success was not explicitly true".to_owned());
    }
    Ok(result.results)
}

/// Validate a single response without a caller-provided SQL label.
///
/// The focused response-shape tests use this helper directly; production
/// queries retain the real SQL in their fail-closed warning context through
/// [`validate_query_response`].
#[cfg(test)]
fn validate_single_response(parsed: D1Response) -> Result<Vec<D1Row>, String> {
    validate_query_response(parsed, "<single-statement>")
}

/// Validate the complete D1 REST batch response before exposing any rows to a
/// caller. A top-level `success: true` is insufficient: a malformed response,
/// missing/extra statement result, or omitted/false nested success flag must
/// fail closed because the transaction outcome is otherwise indeterminate.
fn validate_batch_response(
    parsed: D1Response,
    expected: usize,
) -> Result<Vec<Vec<D1Row>>, D1BatchError> {
    if !parsed.success {
        let message = parsed
            .errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(D1BatchError {
            statement: parsed.result.iter().position(|r| r.success != Some(true)),
            message: format!("D1 batch errors: {message}"),
        });
    }
    if !parsed.errors.is_empty() {
        let message = parsed
            .errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(D1BatchError {
            statement: None,
            message: format!("D1 batch response reported success with errors: {message}"),
        });
    }
    if parsed.result.len() != expected {
        return Err(D1BatchError {
            statement: None,
            message: format!(
                "D1 batch response result count {} != submitted statement count {expected}",
                parsed.result.len()
            ),
        });
    }
    if let Some(statement) = parsed
        .result
        .iter()
        .position(|result| result.success != Some(true))
    {
        return Err(D1BatchError {
            statement: Some(statement),
            message: format!("D1 batch statement {statement} did not report success=true"),
        });
    }
    Ok(parsed.result.into_iter().map(|r| r.results).collect())
}

fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| format!("D1HttpClient: reqwest build failed: {e}"))
}

/// Origin of the Cloudflare D1 REST API: the only HTTPS host a D1 query goes to.
const CLOUDFLARE_API_ORIGIN: &str = "https://api.cloudflare.com";
/// Origin of the staging D1 binding proxy. RFC 2606 reserves `.invalid`, so a
/// request that the Worker does not intercept fails DNS instead of reaching a
/// provider.
const STAGING_D1_PROXY_ORIGIN: &str = "http://corelink-d1-proxy.invalid";

/// Where a [`D1HttpClient`] sends its queries.
///
/// The query URL is never stored as text. [`D1Endpoint::query_url`] renders
/// it for each request from fixed origin and path literals plus characters
/// looked up from fixed tables ([`segment_char`], [`decimal_digit`]). No byte
/// of configuration text is copied into it, so no configured value can add a
/// host, userinfo, query, fragment, path segment, dot segment or percent
/// escape. This is the property CodeQL's `rust/request-forgery` asks for
/// (#1674): no character of a configured or request-derived string is copied
/// into the URL.
#[derive(Clone, Copy)]
enum D1Endpoint {
    /// `https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}/query`.
    CloudflareApi(D1Scope),
    /// The same path on [`STAGING_D1_PROXY_ORIGIN`] (tokenless staging mode).
    StagingBindingProxy(D1Scope),
    /// An explicitly supplied loopback endpoint (integration tests only).
    Loopback(LoopbackEndpoint),
}

impl D1Endpoint {
    /// Render the request URL. Every accepted id produces the same bytes as
    /// the former
    /// `format!("{scheme}://{host}/client/v4/accounts/{account_id}/d1/database/{database_id}/query")`.
    fn query_url(self) -> String {
        match self {
            Self::CloudflareApi(scope) => scope.render(CLOUDFLARE_API_ORIGIN),
            Self::StagingBindingProxy(scope) => scope.render(STAGING_D1_PROXY_ORIGIN),
            Self::Loopback(endpoint) => endpoint.render(),
        }
    }
}

/// The account and database a client is bound to.
#[derive(Clone, Copy)]
struct D1Scope {
    /// `CLOUDFLARE_ACCOUNT_ID`.
    account: IdSegment,
    /// `D1_DATABASE_ID`.
    database: IdSegment,
}

impl D1Scope {
    /// Parse both ids or refuse. The error names the variable but never echoes
    /// its value (`StorageEnv` redacts both ids, and a hostile value could
    /// carry a newline into the log).
    fn parse(account_id: &str, database_id: &str) -> Result<Self, String> {
        let account = IdSegment::parse(account_id).ok_or_else(|| {
            "CLOUDFLARE_ACCOUNT_ID must be 1-64 characters from [0-9A-Za-z_-]".to_owned()
        })?;
        let database = IdSegment::parse(database_id).ok_or_else(|| {
            "D1_DATABASE_ID must be 1-64 characters from [0-9A-Za-z_-]".to_owned()
        })?;
        Ok(Self { account, database })
    }

    fn render(self, origin: &'static str) -> String {
        // origin + "/client/v4/accounts/" (20) + account + "/d1/database/"
        // (13) + database + "/query" (6).
        let mut url = String::with_capacity(origin.len() + 39 + 2 * MAX_ID_LEN);
        url.push_str(origin);
        url.push_str("/client/v4/accounts/");
        self.account.push_to(&mut url);
        url.push_str("/d1/database/");
        self.database.push_to(&mut url);
        url.push_str("/query");
        url
    }
}

/// The longest id accepted. Cloudflare account ids are 32 characters and D1
/// database ids 36.
const MAX_ID_LEN: usize = 64;

/// One id, held as codes into the 64-symbol table of [`segment_char`].
///
/// The table is RFC 3986's unreserved set without `.` and `~`, so a rendered
/// id is always exactly one path segment and never a dot segment, a percent
/// escape, a delimiter or a control character. Cloudflare account ids (32 hex
/// digits) and D1 database ids (hyphenated UUIDs) both fit.
#[derive(Clone, Copy)]
struct IdSegment {
    len: usize,
    symbols: [u8; MAX_ID_LEN],
}

impl IdSegment {
    /// Accept 1-[`MAX_ID_LEN`] bytes, each from `[0-9A-Za-z_-]`.
    fn parse(text: &str) -> Option<Self> {
        let len = text.len();
        if len == 0 || len > MAX_ID_LEN {
            return None;
        }
        let mut symbols = [0_u8; MAX_ID_LEN];
        for (slot, byte) in symbols.iter_mut().zip(text.bytes()) {
            *slot = segment_symbol(byte)?;
        }
        Some(Self { len, symbols })
    }

    fn push_to(&self, out: &mut String) {
        for &symbol in self.symbols.iter().take(self.len) {
            out.push(segment_char(symbol));
        }
    }
}

/// The code of an id byte in [`segment_char`]'s table, or `None` for any
/// byte outside `[0-9A-Za-z_-]`.
fn segment_symbol(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'Z' => Some(byte - b'A' + 10),
        b'a'..=b'z' => Some(byte - b'a' + 36),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// The character for the low six bits of `symbol`, taken from a fixed table
/// (never from the input). Inverse of [`segment_symbol`].
const fn segment_char(symbol: u8) -> char {
    match symbol & 0x3f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'A',
        11 => 'B',
        12 => 'C',
        13 => 'D',
        14 => 'E',
        15 => 'F',
        16 => 'G',
        17 => 'H',
        18 => 'I',
        19 => 'J',
        20 => 'K',
        21 => 'L',
        22 => 'M',
        23 => 'N',
        24 => 'O',
        25 => 'P',
        26 => 'Q',
        27 => 'R',
        28 => 'S',
        29 => 'T',
        30 => 'U',
        31 => 'V',
        32 => 'W',
        33 => 'X',
        34 => 'Y',
        35 => 'Z',
        36 => 'a',
        37 => 'b',
        38 => 'c',
        39 => 'd',
        40 => 'e',
        41 => 'f',
        42 => 'g',
        43 => 'h',
        44 => 'i',
        45 => 'j',
        46 => 'k',
        47 => 'l',
        48 => 'm',
        49 => 'n',
        50 => 'o',
        51 => 'p',
        52 => 'q',
        53 => 'r',
        54 => 's',
        55 => 't',
        56 => 'u',
        57 => 'v',
        58 => 'w',
        59 => 'x',
        60 => 'y',
        61 => 'z',
        62 => '-',
        // The mask leaves exactly 63 here.
        _ => '_',
    }
}

/// Write `value` in decimal without leading zeros.
fn push_decimal(out: &mut String, value: u16) {
    let mut started = false;
    for divisor in [10_000_u16, 1_000, 100, 10, 1] {
        let digit = (value / divisor) % 10;
        if started || digit != 0 || divisor == 1 {
            started = true;
            out.push(decimal_digit(digit));
        }
    }
}

/// The decimal digit for `digit % 10`, taken from a fixed table.
const fn decimal_digit(digit: u16) -> char {
    match digit % 10 {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        // `% 10` leaves exactly 9 here.
        _ => '9',
    }
}

/// A validated loopback test endpoint: `http://{loopback ip}:{port}{path}`.
#[derive(Clone, Copy)]
struct LoopbackEndpoint {
    host: LoopbackHost,
    port: u16,
    path: LoopbackPath,
}

#[derive(Clone, Copy)]
enum LoopbackHost {
    /// An address in `127.0.0.0/8`.
    V4([u8; 4]),
    /// `::1`, the only IPv6 loopback address.
    V6,
}

#[derive(Clone, Copy)]
enum LoopbackPath {
    /// `/` (also the path of a URL written without one).
    Root,
    /// `/d1`.
    D1,
}

impl LoopbackEndpoint {
    fn render(self) -> String {
        let mut url = String::with_capacity(32);
        url.push_str("http://");
        match self.host {
            LoopbackHost::V4(octets) => {
                for (index, octet) in octets.into_iter().enumerate() {
                    if index > 0 {
                        url.push('.');
                    }
                    push_decimal(&mut url, u16::from(octet));
                }
            }
            LoopbackHost::V6 => url.push_str("[::1]"),
        }
        url.push(':');
        push_decimal(&mut url, self.port);
        url.push_str(match self.path {
            LoopbackPath::Root => "/",
            LoopbackPath::D1 => "/d1",
        });
        url
    }
}

fn parse_loopback_query_url(query_url: &str) -> Result<LoopbackEndpoint, String> {
    let parsed =
        reqwest::Url::parse(query_url).map_err(|e| format!("D1 loopback URL parse failed: {e}"))?;
    if parsed.scheme() != "http" {
        return Err("D1 loopback URL must use http".to_owned());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("D1 loopback URL must not contain userinfo".to_owned());
    }
    if parsed.query().is_some() {
        return Err("D1 loopback URL must not contain a query".to_owned());
    }
    if parsed.fragment().is_some() {
        return Err("D1 loopback URL must not contain a fragment".to_owned());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "D1 loopback URL must contain an IP literal host".to_owned())?;
    // `url::Url::host_str` preserves brackets around IPv6 literals, while
    // `IpAddr::from_str` expects the unbracketed address.
    let ip_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let ip = IpAddr::from_str(ip_literal)
        .map_err(|_| "D1 loopback URL host must be an IP literal".to_owned())?;
    if !ip.is_loopback() {
        return Err("D1 loopback URL host must be loopback".to_owned());
    }
    let host = match ip {
        IpAddr::V4(v4) => LoopbackHost::V4(v4.octets()),
        IpAddr::V6(_) => LoopbackHost::V6,
    };
    let port = parsed
        .port()
        .ok_or_else(|| "D1 loopback URL must contain an explicit port".to_owned())?;
    let path = match parsed.path() {
        "/" => LoopbackPath::Root,
        "/d1" => LoopbackPath::D1,
        _ => return Err("D1 loopback URL path must be / or /d1".to_owned()),
    };
    Ok(LoopbackEndpoint { host, port, path })
}

/// Metadata record for a CAS blob, sourced from D1.
///
/// Mirrors the `blob_meta` D1 table shape. Fields are `#[non_exhaustive]`
/// so new columns can be added without breaking existing code.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CasMetaRecord {
    /// BLAKE3 digest of the blob.
    pub digest: String,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Size in bytes.
    pub size_bytes: i64,
}

impl D1HttpClient {
    /// Look up a CAS metadata record by tenant + digest.
    ///
    /// Returns `Ok(Some(record))` when found, `Ok(None)` when the row
    /// does not exist, and `Err(String)` on query error.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors.
    pub async fn cas_meta_lookup(
        &self,
        tenant_id: &str,
        digest: &str,
    ) -> Result<Option<CasMetaRecord>, String> {
        let rows = self
            .query(
                "SELECT digest, tenant_id, size_bytes FROM blob_meta WHERE tenant_id = ?1 AND digest = ?2 LIMIT 1",
                &[
                    serde_json::Value::String(tenant_id.to_owned()),
                    serde_json::Value::String(digest.to_owned()),
                ],
            )
            .await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = rows.into_iter().next().ok_or("D1: empty result set")?;

        let record_digest = row
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or("D1 blob_meta: missing `digest` column")?
            .to_owned();

        let record_tenant = row
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .ok_or("D1 blob_meta: missing `tenant_id` column")?
            .to_owned();

        let size_bytes = row
            .get("size_bytes")
            .and_then(|v| v.as_i64())
            .ok_or("D1 blob_meta: missing or non-integer `size_bytes` column")?;

        Ok(Some(CasMetaRecord {
            digest: record_digest,
            tenant_id: record_tenant,
            size_bytes,
        }))
    }
}

/// Tenant admin record sourced from the `tier_selections` D1 table.
///
/// Mirrors the operational tier+subscription columns used by the
/// admin plane (`migrations/d1/0039_tier_selection.sql`). Fields are
/// `#[non_exhaustive]` so additive column changes don't break callers.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct TenantAdminRecord {
    /// Opaque tenant id (matches `tenant.tenant_id`).
    pub tenant_id: String,
    /// Selected tier: free | starter | team | pro | enterprise.
    pub tier: String,
    /// Canonical subscription state.
    pub subscription_state: String,
    /// Stripe customer id (mapped atomically with the tier write).
    pub stripe_customer_id: Option<String>,
}

impl D1HttpClient {
    /// Look up a tenant admin record by tenant id.
    ///
    /// Returns `Ok(Some(record))` when found, `Ok(None)` when the row
    /// does not exist, and `Err(String)` on query error.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors.
    pub async fn tenant_admin_lookup(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantAdminRecord>, String> {
        let rows = self
            .query(
                "SELECT tenant_id, tier, subscription_state, stripe_customer_id \
                 FROM tier_selections WHERE tenant_id = ?1 LIMIT 1",
                &[serde_json::Value::String(tenant_id.to_owned())],
            )
            .await?;

        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let tenant_id = row
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .ok_or("D1 tier_selections: missing `tenant_id` column")?
            .to_owned();
        let tier = row
            .get("tier")
            .and_then(|v| v.as_str())
            .ok_or("D1 tier_selections: missing `tier` column")?
            .to_owned();
        let subscription_state = row
            .get("subscription_state")
            .and_then(|v| v.as_str())
            .ok_or("D1 tier_selections: missing `subscription_state` column")?
            .to_owned();
        let stripe_customer_id = row
            .get("stripe_customer_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        Ok(Some(TenantAdminRecord {
            tenant_id,
            tier,
            subscription_state,
            stripe_customer_id,
        }))
    }

    /// Set the tier for a tenant in `tier_selections`.
    ///
    /// Returns `Ok(true)` if a row was updated, `Ok(false)` if no row
    /// matched (tenant does not exist), or `Err(String)` on D1 error.
    /// The write is additive — `subscription_state` is preserved.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors.
    pub async fn tenant_set_tier(&self, tenant_id: &str, tier: &str) -> Result<bool, String> {
        // First confirm the row exists — D1 HTTP `success` does not
        // discriminate "0 rows updated" from "1 row updated".
        let pre = self.tenant_admin_lookup(tenant_id).await?;
        if pre.is_none() {
            return Ok(false);
        }
        let _ = self
            .query(
                "UPDATE tier_selections SET tier = ?1 WHERE tenant_id = ?2",
                &[
                    serde_json::Value::String(tier.to_owned()),
                    serde_json::Value::String(tenant_id.to_owned()),
                ],
            )
            .await?;
        Ok(true)
    }
}

/// Outcome of [`D1HttpClient::admin_approval_verify_consume`] (finding H5).
/// Mirrors the reject taxonomy of `corelink-handler-admin`'s
/// `ApprovalRejection`; the container's `D1ApprovalLedger` maps it across.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdminApprovalConsume {
    /// Verified + atomically consumed; carries the recorded approver.
    Consumed {
        /// The authenticated approver recorded at approval-creation time.
        approver: String,
    },
    /// No approval row exists for the id (forged / absent).
    Unknown,
    /// The row was recorded for a different `resource`.
    ScopeMismatch,
    /// The recorded approver equals the initiator (self-approval).
    SelfApproval {
        /// The recorded approver that collided with the initiator.
        approver: String,
    },
    /// The approval was already spent (single-use replay / lost race).
    AlreadyConsumed,
}

impl D1HttpClient {
    /// Record ("create") an admin dual-approval row (migration 0091,
    /// finding H5). Idempotent on an UNCONSUMED `approval_id`; refuses to
    /// overwrite a consumed one (a spent approval can never be resurrected).
    ///
    /// `approver` MUST be the independently-authenticated approver identity
    /// from the approve endpoint's own auth gate — never a client-body value.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on a D1 error or an attempt to re-record a
    /// consumed approval.
    pub async fn admin_approval_create(
        &self,
        approval_id: &str,
        approver: &str,
        resource: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        // Guard: never resurrect a consumed approval.
        let existing = self
            .query(
                "SELECT consumed FROM admin_approvals WHERE approval_id = ?1 LIMIT 1",
                &[serde_json::json!(approval_id)],
            )
            .await?;
        if let Some(row) = existing.first() {
            let consumed = row
                .get("consumed")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            if consumed != 0 {
                return Err(format!(
                    "approval_id={approval_id} already consumed; cannot re-record"
                ));
            }
        }
        let _ = self
            .query(
                "INSERT INTO admin_approvals \
                   (approval_id, approver, resource, consumed, created_at_ms) \
                 VALUES (?1, ?2, ?3, 0, ?4) \
                 ON CONFLICT(approval_id) DO UPDATE SET \
                   approver = excluded.approver, resource = excluded.resource \
                 WHERE admin_approvals.consumed = 0",
                &[
                    serde_json::json!(approval_id),
                    serde_json::json!(approver),
                    serde_json::json!(resource),
                    serde_json::json!(now_ms),
                ],
            )
            .await?;
        Ok(())
    }

    /// Verify an admin approval against `initiator` + `resource`, then
    /// ATOMICALLY consume it (single-use). The recorded approver — not any
    /// request-body value — is the authority for the distinct-approver check.
    ///
    /// The consume is a conditional `UPDATE ... WHERE consumed = 0 RETURNING`
    /// so two concurrent spends of the same approval cannot both succeed.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on a D1 error or a malformed row. A malformed /
    /// unreachable ledger is fail-CLOSED at the caller (no mutation commits).
    pub async fn admin_approval_verify_consume(
        &self,
        approval_id: &str,
        initiator: &str,
        resource: &str,
        now_ms: i64,
    ) -> Result<AdminApprovalConsume, String> {
        let rows = self
            .query(
                "SELECT approver, resource, consumed FROM admin_approvals \
                 WHERE approval_id = ?1 LIMIT 1",
                &[serde_json::json!(approval_id)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(AdminApprovalConsume::Unknown);
        };
        let rec_approver = row
            .get("approver")
            .and_then(|v| v.as_str())
            .ok_or("D1 admin_approvals: missing `approver` column")?
            .to_owned();
        let rec_resource = row
            .get("resource")
            .and_then(|v| v.as_str())
            .ok_or("D1 admin_approvals: missing `resource` column")?
            .to_owned();
        let consumed = row
            .get("consumed")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        // Ordering mirrors the in-memory ledger: self-approval, then scope,
        // then already-consumed.
        if rec_approver == initiator {
            return Ok(AdminApprovalConsume::SelfApproval {
                approver: rec_approver,
            });
        }
        if rec_resource != resource {
            return Ok(AdminApprovalConsume::ScopeMismatch);
        }
        if consumed != 0 {
            return Ok(AdminApprovalConsume::AlreadyConsumed);
        }
        // Atomic single-use consume — only one racer flips 0 -> 1.
        let consumed_rows = self
            .query(
                "UPDATE admin_approvals SET consumed = 1, consumed_at_ms = ?2 \
                 WHERE approval_id = ?1 AND consumed = 0 RETURNING approver",
                &[serde_json::json!(approval_id), serde_json::json!(now_ms)],
            )
            .await?;
        if consumed_rows.is_empty() {
            // Lost the race to a concurrent consume.
            return Ok(AdminApprovalConsume::AlreadyConsumed);
        }
        Ok(AdminApprovalConsume::Consumed {
            approver: rec_approver,
        })
    }
}

impl D1HttpClient {
    /// Read a tenant's `tenant_quota` row (migration 0066).
    ///
    /// Returns `Ok(Some(state))` when the row exists, `Ok(None)` when it
    /// does not (a fresh tenant), and `Err(String)` on D1 transport /
    /// decode error. Backs [`crate::tenant_quota::D1QuotaStore::get`];
    /// the quota guard fail-CLOSES on the `Err` arm.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors or a malformed
    /// row (missing / non-integer column).
    pub async fn tenant_quota_lookup(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::tenant_quota::QuotaState>, String> {
        let rows = self
            .query(
                "SELECT monthly_budget_usd_micros, accrued_usd_micros, cycle_anchor_ms \
                 FROM tenant_quota WHERE tenant_id = ?1 LIMIT 1",
                &[serde_json::Value::String(tenant_id.to_owned())],
            )
            .await?;

        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let monthly_budget_usd_micros = row
            .get("monthly_budget_usd_micros")
            .and_then(serde_json::Value::as_i64)
            .ok_or("D1 tenant_quota: missing or non-integer `monthly_budget_usd_micros`")?;
        let accrued_usd_micros = row
            .get("accrued_usd_micros")
            .and_then(serde_json::Value::as_i64)
            .ok_or("D1 tenant_quota: missing or non-integer `accrued_usd_micros`")?;
        let cycle_anchor_ms = row
            .get("cycle_anchor_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or("D1 tenant_quota: missing or non-integer `cycle_anchor_ms`")?;

        Ok(Some(crate::tenant_quota::QuotaState {
            monthly_budget_usd_micros,
            accrued_usd_micros,
            cycle_anchor_ms,
        }))
    }

    /// **Absolute** upsert of a tenant's `tenant_quota` row (migration
    /// 0066). Backs [`crate::tenant_quota::D1QuotaStore::put`] — used ONLY
    /// to seed a fresh tenant and to roll the cycle, where the new
    /// `accrued_usd_micros` is a computed value (the op's cost on a fresh
    /// cycle), NOT a delta over the prior row.
    ///
    /// Idempotent on `tenant_id` (PRIMARY KEY) via
    /// `INSERT … ON CONFLICT … DO UPDATE`. The `monthly_budget_usd_micros`
    /// ceiling is preserved on conflict (only the operator tunes it); the
    /// accrued counter + cycle anchor + `updated_at_ms` are overwritten
    /// with the guard-computed values. This is a deliberate BLIND
    /// overwrite — correct for the seed/roll path, where the prior accrued
    /// value is being intentionally discarded. The hot-path accrual uses
    /// the atomic [`Self::tenant_quota_accrue`] instead.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors.
    pub async fn tenant_quota_upsert(
        &self,
        tenant_id: &str,
        state: crate::tenant_quota::QuotaState,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        let _ = self
            .query(
                "INSERT INTO tenant_quota \
                   (tenant_id, monthly_budget_usd_micros, accrued_usd_micros, \
                    cycle_anchor_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(tenant_id) DO UPDATE SET \
                   accrued_usd_micros = excluded.accrued_usd_micros, \
                   cycle_anchor_ms    = excluded.cycle_anchor_ms, \
                   updated_at_ms      = excluded.updated_at_ms",
                &[
                    serde_json::Value::String(tenant_id.to_owned()),
                    serde_json::Value::from(state.monthly_budget_usd_micros),
                    serde_json::Value::from(state.accrued_usd_micros),
                    serde_json::Value::from(state.cycle_anchor_ms),
                    serde_json::Value::from(updated_at_ms),
                ],
            )
            .await?;
        Ok(())
    }

    /// **Atomic increment** of a tenant's accrued cost (migration 0066).
    /// Backs [`crate::tenant_quota::D1QuotaStore::accrue`] — the hot-path
    /// accrual after a served billable op.
    ///
    /// The increment is done by the DB inside `ON CONFLICT … DO UPDATE`:
    ///
    /// ```sql
    /// accrued_usd_micros = tenant_quota.accrued_usd_micros + excluded.accrued_usd_micros
    /// ```
    ///
    /// i.e. the bound `?3` carries the per-op **delta** (`cost`), and the
    /// add happens in SQLite, not in the application. This closes the
    /// TOCTOU lost-update window: a blind `SET accrued = excluded.accrued`
    /// (read total in app, write total back) loses one op's spend when two
    /// requests interleave; letting the DB compute `accrued + delta` makes
    /// concurrent accruals sum. On the INSERT (fresh-row) path the row is
    /// seeded at the default tripwire with `accrued = delta` and
    /// `cycle_anchor_ms = seed_anchor_ms`; an existing row keeps its anchor
    /// and budget (only the operator tunes the budget).
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on D1 communication errors.
    pub async fn tenant_quota_accrue(
        &self,
        tenant_id: &str,
        delta_micros: i64,
        seed_anchor_ms: i64,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        let _ = self
            .query(
                // Explicitly seed `monthly_budget_usd_micros` with the
                // effectively-unlimited default (ADR-0068 2026-07-09) on the
                // INSERT path. Omitting it made a fresh tenant's first accrual
                // fall to the table's stale `DEFAULT 5000000` ($5) — the
                // miscalibrated placeholder the reconciliation retired. ON
                // CONFLICT never touches the budget, so an existing tenant's
                // operator-set ceiling is preserved.
                "INSERT INTO tenant_quota \
                   (tenant_id, monthly_budget_usd_micros, accrued_usd_micros, cycle_anchor_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(tenant_id) DO UPDATE SET \
                   accrued_usd_micros = tenant_quota.accrued_usd_micros \
                                        + excluded.accrued_usd_micros, \
                   updated_at_ms      = excluded.updated_at_ms",
                &[
                    serde_json::Value::String(tenant_id.to_owned()),
                    serde_json::Value::from(crate::tenant_quota::DEFAULT_MONTHLY_BUDGET_USD_MICROS),
                    serde_json::Value::from(delta_micros),
                    serde_json::Value::from(seed_anchor_ms),
                    serde_json::Value::from(updated_at_ms),
                ],
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;
    use crate::storage::StorageEnv;
    use proptest::prelude::*;

    /// The staging ids the Worker's D1 binding proxy accepts
    /// (`worker/src/staging_d1_binding_proxy.ts`).
    const STAGING_ACCOUNT: &str = "6a1fc1c626fc2628823e60b9db01f5cd";
    const STAGING_DATABASE: &str = "d72a6b39-6a48-4338-bfda-1111dda98604";
    /// The production CONFIG_DB id (`wrangler.toml`).
    const PROD_DATABASE: &str = "d64742ea-e102-40b2-a844-ff02e3f94562";

    /// The exact URL expression `from_d1_parts` used before #1674.
    fn former_query_url(scheme: &str, host: &str, account_id: &str, database_id: &str) -> String {
        format!(
            "{scheme}://{host}/client/v4/accounts/{}/d1/database/{}/query",
            account_id, database_id,
        )
    }

    fn storage_env(account_id: &str, database_id: &str) -> StorageEnv {
        StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: account_id.to_owned(),
            cf_api_token: "tok".to_owned(),
            d1_database_id: database_id.to_owned(),
        }
    }

    #[test]
    fn accepted_ids_render_the_same_query_url_as_before() {
        for (account, database) in [
            // Deployed values.
            (STAGING_ACCOUNT, STAGING_DATABASE),
            (STAGING_ACCOUNT, PROD_DATABASE),
            // Case is preserved, not normalized.
            (
                "6A1FC1C626FC2628823E60B9DB01F5CD",
                "D72A6B39-6A48-4338-BFDA-1111DDA98604",
            ),
            // Placeholder ids the crate's test fixtures pass to `new`.
            ("acct123", "db456"),
            ("account", "database"),
            ("test-account", "test-db"),
            ("test-account-id", "test-database-id"),
            ("definitely-not-a-real-account", "definitely-not-a-real-db"),
            ("a", "_"),
        ] {
            let cloudflare =
                D1HttpClient::from_d1_parts(account, database, "token".to_owned(), false)
                    .expect("accepted ids build a Cloudflare client");
            assert_eq!(
                cloudflare.endpoint.query_url(),
                former_query_url("https", "api.cloudflare.com", account, database)
            );
            let proxy = D1HttpClient::from_d1_parts(account, database, String::new(), false)
                .expect("accepted ids build a staging proxy client");
            assert_eq!(
                proxy.endpoint.query_url(),
                former_query_url("http", "corelink-d1-proxy.invalid", account, database)
            );
        }
        // The one path the staging Worker proxy admits, byte for byte.
        let staging =
            D1HttpClient::from_d1_parts(STAGING_ACCOUNT, STAGING_DATABASE, String::new(), true)
                .expect("staging ids build");
        assert_eq!(
            staging.endpoint.query_url(),
            "http://corelink-d1-proxy.invalid/client/v4/accounts/6a1fc1c626fc2628823e60b9db01f5cd/d1/database/d72a6b39-6a48-4338-bfda-1111dda98604/query"
        );
    }

    /// Values that would change the URL's host, userinfo, path, query or
    /// fragment, add a dot segment or percent escape, or inject a header line,
    /// if they reached it as text. Each one is refused as either id.
    const HOSTILE_IDS: &[&str] = &[
        "",
        ".",
        "..",
        "../",
        "@evil.com",
        "%2F",
        "%2e%2e",
        "evil.com",
        "api.cloudflare.com@evil.com",
        "//evil.com/",
        "https://evil.com/",
        "\\evil",
        "\n",
        "\r\n",
        "a b",
        "a\tb",
        "~",
        "x:y",
        "\u{0}",
        "é",
        "6a1fc1c626fc2628823e60b9db01f5cd\n",
        "6a1fc1c626fc2628823e60b9db01f5cd/../../evil",
        "6a1fc1c626fc2628823e60b9db01f5cd@evil.com",
        "6a1fc1c626fc2628823e60b9db01f5cd%2F",
        "6a1fc1c626fc2628823e60b9db01f5cd?x=1",
        "6a1fc1c626fc2628823e60b9db01f5cd#fragment",
        "6a1fc1c626fc2628823e60b9db01f5cd.",
        "6a1fc1c626fc2628\r\nHost: evil.com",
        "d72a6b39/6a48-4338-bfda-1111dda98604",
        "d72a6b39-6a48-4338-bfda-1111dda98604\n",
        "../../evil.com/client/v4/accounts/x",
        // 65 bytes: one past the length cap.
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    #[test]
    fn hostile_d1_ids_are_refused_before_a_client_exists() {
        for &hostile in HOSTILE_IDS {
            for (account, database) in [(hostile, STAGING_DATABASE), (STAGING_ACCOUNT, hostile)] {
                for token in ["token", ""] {
                    let error =
                        D1HttpClient::from_d1_parts(account, database, token.to_owned(), false)
                            .expect_err("a hostile id must not build a client");
                    assert!(
                        error.contains("CLOUDFLARE_ACCOUNT_ID") || error.contains("D1_DATABASE_ID"),
                        "refusal must name the variable: {error}"
                    );
                    if hostile.len() > 1 {
                        assert!(
                            !error.contains(hostile),
                            "refusal must not echo the value: {error:?}"
                        );
                    }
                }
                // The StorageEnv constructor every route uses refuses it too.
                assert!(D1HttpClient::new(&storage_env(account, database)).is_err());
            }
        }
    }

    #[test]
    fn id_segment_accepts_exactly_the_unreserved_subset_and_round_trips() {
        for byte in 0_u8..=0x7f {
            let text = char::from(byte).to_string();
            let allowed = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
            match IdSegment::parse(&text) {
                Some(segment) => {
                    assert!(allowed, "accepted byte {byte:#04x}");
                    let mut rendered = String::new();
                    segment.push_to(&mut rendered);
                    assert_eq!(rendered, text);
                }
                None => assert!(!allowed, "refused byte {byte:#04x}"),
            }
        }
        let longest = "a".repeat(MAX_ID_LEN);
        assert!(IdSegment::parse(&longest).is_some());
        assert!(IdSegment::parse(&format!("{longest}a")).is_none());
        for &hostile in HOSTILE_IDS {
            assert!(IdSegment::parse(hostile).is_none(), "accepted {hostile:?}");
        }
    }

    proptest! {
        /// Every Cloudflare-shaped id pair (32 hex digits, hyphenated UUID)
        /// renders exactly the former URL.
        #[test]
        fn cloudflare_shaped_ids_render_the_former_url(account in any::<u128>(), database in any::<u128>()) {
            let account_text = format!("{account:032x}");
            let database_text = format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                database >> 96,
                (database >> 80) & 0xffff,
                (database >> 64) & 0xffff,
                (database >> 48) & 0xffff,
                database & 0xffff_ffff_ffff,
            );
            let scope = D1Scope::parse(&account_text, &database_text).expect("Cloudflare ids parse");
            prop_assert_eq!(
                D1Endpoint::CloudflareApi(scope).query_url(),
                former_query_url("https", "api.cloudflare.com", &account_text, &database_text)
            );
        }

        /// Whatever text is offered as an account id, a client exists only
        /// for 1-64 characters of `[0-9A-Za-z_-]`, and its URL keeps the fixed
        /// origin and path shape with the id as exactly one segment.
        #[test]
        fn only_unreserved_ids_are_accepted(account in "\\PC{0,70}|[0-9A-Za-z_-]{1,64}|[0-9A-Za-z_./@%?#:~-]{1,70}") {
            let allowed = (1..=MAX_ID_LEN).contains(&account.len())
                && account.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            match D1Scope::parse(&account, STAGING_DATABASE) {
                Ok(scope) => {
                    prop_assert!(allowed, "accepted {account:?}");
                    let url = reqwest::Url::parse(&D1Endpoint::CloudflareApi(scope).query_url())
                        .expect("rendered URL parses");
                    prop_assert_eq!(url.scheme(), "https");
                    prop_assert_eq!(url.host_str(), Some("api.cloudflare.com"));
                    prop_assert_eq!(url.username(), "");
                    prop_assert_eq!(url.query(), None);
                    prop_assert_eq!(url.fragment(), None);
                    let segments: Vec<&str> = url.path_segments().expect("path").collect();
                    prop_assert_eq!(
                        segments,
                        vec!["client", "v4", "accounts", account.as_str(), "d1", "database", STAGING_DATABASE, "query"]
                    );
                }
                Err(_) => prop_assert!(!allowed, "refused {account:?}"),
            }
        }
    }

    #[test]
    fn read_only_sql_gate_accepts_one_select_and_rejects_mutation_or_stacking() {
        assert!(is_select_statement("SELECT 1"));
        assert!(is_select_statement("  select value FROM rows;  "));
        assert!(!is_select_statement("UPDATE rows SET value = 1"));
        assert!(!is_select_statement("SELECT 1; DELETE FROM rows"));
        assert!(!is_select_statement("/* hidden */ SELECT 1"));
        assert!(!is_select_statement("SELECTED value FROM rows"));
    }

    #[tokio::test]
    async fn read_only_client_rejects_mutations_before_network_io() {
        let client = D1HttpClient::from_d1_parts("account", "database", "token".to_owned(), true)
            .expect("build read-only client");
        let err = client
            .query("DELETE FROM gc_candidates", &[])
            .await
            .expect_err("mutation must be rejected locally");
        assert!(err.contains("read-only client rejected"));
        let err = client
            .batch(vec![D1BatchStatement::new("SELECT 1", vec![])])
            .await
            .expect_err("batch must be rejected locally");
        assert!(err.message.contains("read-only client rejected"));
    }

    fn query_response(result: Vec<D1QueryResult>) -> D1Response {
        D1Response {
            result,
            success: true,
            errors: vec![],
        }
    }

    #[test]
    fn single_query_response_requires_one_explicitly_successful_result() {
        let valid = query_response(vec![D1QueryResult {
            results: vec![D1Row::new()],
            success: Some(true),
        }]);
        assert_eq!(
            validate_query_response(valid, "SELECT 1")
                .expect("one successful result")
                .len(),
            1
        );

        assert!(validate_query_response(query_response(vec![]), "SELECT 1").is_err());
        assert!(validate_query_response(
            query_response(vec![
                D1QueryResult {
                    results: vec![],
                    success: Some(true),
                },
                D1QueryResult {
                    results: vec![],
                    success: Some(true),
                },
            ]),
            "SELECT 1"
        )
        .is_err());
        for success in [None, Some(false)] {
            let response = query_response(vec![D1QueryResult {
                results: vec![],
                success,
            }]);
            assert!(validate_query_response(response, "SELECT 1").is_err());
        }
    }

    #[test]
    fn d1_http_client_new_fails_gracefully_without_env() {
        // Simulate the env not being set — StorageEnv::from_env()
        // returns None so this path never constructs D1HttpClient;
        // here we construct directly with stub values to test the URL
        // format only.
        let stub_env = storage_env("acct123", "db456");
        let client = D1HttpClient::new(&stub_env).expect("build client");
        assert_eq!(
            client.endpoint.query_url(),
            "https://api.cloudflare.com/client/v4/accounts/acct123/d1/database/db456/query",
        );
    }

    #[test]
    fn empty_runtime_token_selects_non_routable_proxy_host() {
        let client = D1HttpClient::from_d1_parts("account", "database", String::new(), false)
            .expect("build tokenless staging proxy client");
        assert_eq!(
            client.endpoint.query_url(),
            "http://corelink-d1-proxy.invalid/client/v4/accounts/account/d1/database/database/query",
        );
        assert!(client.api_token.is_empty());
    }

    #[tokio::test]
    async fn tokenless_proxy_client_sends_no_authorization_header() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request_bytes = [0_u8; 4096];
            let read = stream
                .read(&mut request_bytes)
                .expect("read request headers");
            let headers =
                String::from_utf8_lossy(request_bytes.get(..read).expect("read fits the buffer"))
                    .to_ascii_lowercase();
            assert!(!headers.contains("authorization:"));
            assert!(headers.starts_with("post /d1 http/1.1"));
            let body = r#"{"result":[{"results":[{"value":1}],"success":true}],"success":true,"errors":[]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write response");
        });
        let env = StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "account".to_owned(),
            cf_api_token: String::new(),
            d1_database_id: "database".to_owned(),
        };
        let client = D1HttpClient::new_for_loopback_test(&env, &format!("http://{address}/d1"))
            .expect("build tokenless proxy test client");
        let rows = client.query("SELECT 1", &[]).await.expect("query succeeds");
        assert_eq!(rows.len(), 1);
        server.join().expect("server assertions");
    }

    #[tokio::test]
    async fn missing_staging_interceptor_cannot_fall_back_to_cloudflare() {
        let client = D1HttpClient::from_d1_parts("account", "database", String::new(), false)
            .expect("build tokenless staging proxy client");
        assert!(client
            .endpoint
            .query_url()
            .starts_with("http://corelink-d1-proxy.invalid/"));
        // RFC 2606 reserves .invalid; with no Container host interception the
        // request must fail DNS rather than reach Cloudflare over the internet.
        let error = client
            .query("SELECT 1", &[])
            .await
            .expect_err("unintercepted .invalid request must not reach a provider");
        assert!(error.contains("D1 HTTP request failed"));
    }

    #[test]
    fn loopback_query_url_validation_accepts_explicit_loopback_endpoint() {
        for (input, rendered) in [
            ("http://127.0.0.1:8787/d1", "http://127.0.0.1:8787/d1"),
            ("http://[::1]:8787/d1", "http://[::1]:8787/d1"),
            ("http://127.0.0.1:41000", "http://127.0.0.1:41000/"),
            ("http://127.0.0.1:41000/", "http://127.0.0.1:41000/"),
            (
                "http://127.10.200.3:65535/d1",
                "http://127.10.200.3:65535/d1",
            ),
            ("http://127.0.0.1:1", "http://127.0.0.1:1/"),
        ] {
            let endpoint = parse_loopback_query_url(input)
                .unwrap_or_else(|e| panic!("loopback URL {input} refused: {e}"));
            assert_eq!(endpoint.render(), rendered);
            // The rendered URL addresses exactly what the caller configured.
            assert_eq!(
                reqwest::Url::parse(&endpoint.render()).expect("rendered URL parses"),
                reqwest::Url::parse(input).expect("input URL parses"),
            );
        }
    }

    #[test]
    fn loopback_query_url_validation_rejects_unsafe_endpoints() {
        for url in [
            "http://localhost:8787/d1",
            "http://192.0.2.1:8787/d1",
            "http://0.0.0.0:8787/d1",
            "http://[::ffff:127.0.0.1]:8787/d1",
            "https://127.0.0.1:8787/d1",
            "http://127.0.0.1/d1",
            "http://user:pass@127.0.0.1:8787/d1",
            "http://evil.com@127.0.0.1:8787/d1",
            "http://127.0.0.1:8787@evil.com/d1",
            "http://127.0.0.1:8787/d1?query=hidden",
            "http://127.0.0.1:8787/d1#fragment",
            "http://127.0.0.1:8787/../evil",
            "http://127.0.0.1:8787/d1/../../evil",
            "http://127.0.0.1:8787/%2F",
            "http://127.0.0.1:8787/d1%2F..",
            "http://127.0.0.1:8787/@evil.com",
            "http://127.0.0.1:8787/d1/",
            "http://127.0.0.1:8787/client/v4/accounts/x/d1/database/y/query",
            "",
        ] {
            assert!(
                parse_loopback_query_url(url).is_err(),
                "unsafe D1 loopback URL accepted: {url}"
            );
            let env = storage_env(STAGING_ACCOUNT, STAGING_DATABASE);
            assert!(D1HttpClient::new_for_loopback_test(&env, url).is_err());
        }
    }

    fn batch_response(success: bool, results: Vec<D1QueryResult>) -> D1Response {
        D1Response {
            result: results,
            success,
            errors: Vec::new(),
        }
    }

    fn successful_result() -> D1QueryResult {
        D1QueryResult {
            results: Vec::new(),
            success: Some(true),
        }
    }

    #[test]
    fn batch_response_requires_exact_explicitly_successful_results() {
        let parsed = batch_response(true, vec![successful_result(), successful_result()]);
        assert!(validate_batch_response(parsed, 2).is_ok());

        for results in [
            Vec::new(),
            vec![successful_result()],
            vec![
                successful_result(),
                successful_result(),
                successful_result(),
            ],
            vec![
                D1QueryResult {
                    results: Vec::new(),
                    success: None,
                },
                successful_result(),
            ],
            vec![
                D1QueryResult {
                    results: Vec::new(),
                    success: Some(false),
                },
                successful_result(),
            ],
        ] {
            let err = validate_batch_response(batch_response(true, results), 2)
                .expect_err("malformed nested batch result must fail closed");
            assert!(err.message.contains("D1 batch"));
        }
    }

    #[test]
    fn batch_response_rejects_top_level_failure_even_when_nested_shape_is_complete() {
        let err = validate_batch_response(
            D1Response {
                result: vec![successful_result(), successful_result()],
                success: false,
                errors: vec![D1Error {
                    message: "transaction rolled back".to_owned(),
                }],
            },
            2,
        )
        .expect_err("top-level failure must fail closed");
        assert!(err.message.contains("rolled back"));
    }

    #[test]
    fn batch_response_rejects_empty_result_when_statement_was_submitted() {
        let err = validate_batch_response(batch_response(true, Vec::new()), 1)
            .expect_err("empty result must not represent a submitted statement");
        assert!(err.message.contains("result count"));
    }

    #[test]
    fn single_response_requires_one_explicit_success_and_no_errors() {
        assert!(validate_single_response(batch_response(true, vec![successful_result()])).is_ok());

        for parsed in [
            batch_response(true, Vec::new()),
            batch_response(true, vec![successful_result(), successful_result()]),
            batch_response(
                true,
                vec![D1QueryResult {
                    results: Vec::new(),
                    success: None,
                }],
            ),
            batch_response(
                true,
                vec![D1QueryResult {
                    results: Vec::new(),
                    success: Some(false),
                }],
            ),
            D1Response {
                result: vec![successful_result()],
                success: true,
                errors: vec![D1Error {
                    message: "contradictory error".to_owned(),
                }],
            },
        ] {
            assert!(validate_single_response(parsed).is_err());
        }
    }

    /// Live D1 query test — requires real credentials.
    ///
    /// Run manually:
    ///
    /// ```bash
    /// CLOUDFLARE_ACCOUNT_ID=<acc> CF_API_TOKEN=<tok> D1_DATABASE_ID=<id> \
    ///   ... other vars ...
    ///   cargo test -p corelink-server d1_http_blob_meta_round_trip -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "requires live CF D1 credentials"]
    async fn d1_http_blob_meta_round_trip() {
        let client = D1HttpClient::from_d1_env_for_integration_tests().expect("D1 credentials");
        // Query a definitely-absent record — should return Ok(None).
        let result = client
            .cas_meta_lookup("00000000-0000-0000-0000-000000000000", "__no_such_digest__")
            .await
            .expect("query");
        assert!(result.is_none());
    }

    /// Live D1 tenant admin lookup — requires real credentials.
    /// WP-S1 Phase 2 (Admin half) acceptance probe.
    #[tokio::test]
    #[ignore = "requires live CF D1 credentials"]
    async fn d1_http_tenant_admin_lookup_round_trip() {
        let client = D1HttpClient::from_d1_env_for_integration_tests().expect("D1 credentials");
        let result = client
            .tenant_admin_lookup("00000000-0000-0000-0000-000000000000")
            .await
            .expect("query");
        // No such tenant — Ok(None).
        assert!(result.is_none());
    }
}
