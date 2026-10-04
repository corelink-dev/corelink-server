//! Protected one-shot proof for the staging native-container D1 binding proxy.
//!
//! This route is mounted only when the process is explicitly in staging binding
//! proxy mode. Its caller is the staging-only Cron→DO path, which invokes the
//! container port directly; `CoreLinkServer::fetch` rejects the route so it is
//! not reachable through ordinary public request forwarding.

use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use crate::storage::{
    d1_http::{D1BatchStatement, D1HttpClient, D1Row},
    StorageEnv,
};

#[derive(Deserialize)]
struct ProbeWindow {
    cron: String,
    starts_ms: u64,
    last_entry_ms: u64,
    expires_ms: u64,
    nonce: String,
}

fn probe_window() -> ProbeWindow {
    serde_json::from_str(include_str!("staging_d1_probe_window.json"))
        .expect("compiled staging probe window")
}

const EXPECTED_ACCOUNT: &str = "6a1fc1c626fc2628823e60b9db01f5cd";
const EXPECTED_DATABASE: &str = "d72a6b39-6a48-4338-bfda-1111dda98604";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    cron: String,
    probe_nonce: String,
    scheduled_time_ms: u64,
    worker_release: String,
}

#[derive(Debug, Serialize)]
struct ProbeReceipt {
    contract: &'static str,
    outcome: &'static str,
    probe_nonce: String,
    worker_release: String,
    scheduled_time_ms: u64,
    parameterized_select: bool,
    failed_batch_observed: bool,
    rollback_absence_verified: bool,
    probe_table_dropped: bool,
    d1_binding_intercepted: bool,
    authorization_absent: bool,
    cf_api_token_absent: bool,
}

/// True only for the single staging process configuration authorized here.
pub fn enabled() -> bool {
    std::env::var("ENVIRONMENT").ok().as_deref() == Some("staging")
        && std::env::var("D1_BINDING_PROXY").ok().as_deref() == Some("1")
        && std::env::var("CF_API_TOKEN")
            .unwrap_or_default()
            .trim()
            .is_empty()
        && std::env::var("CLOUDFLARE_ACCOUNT_ID").ok().as_deref() == Some(EXPECTED_ACCOUNT)
        && std::env::var("D1_DATABASE_ID").ok().as_deref() == Some(EXPECTED_DATABASE)
}

/// Internal endpoint; do not mount unless [`enabled`] is true.
pub fn router() -> Router {
    Router::new().route(
        "/_internal/staging/d1-binding-runtime-probe",
        post(run_probe),
    )
}

async fn run_probe(headers: HeaderMap, Json(input): Json<ProbeRequest>) -> impl IntoResponse {
    let now = now_ms();
    let lifetime = ProbeLifetime::from_env(now);
    if !enabled()
        || headers.contains_key("authorization")
        || headers.contains_key("cookie")
        || !valid_request(&input, now)
        || lifetime.is_none()
    {
        return (StatusCode::NOT_FOUND, Json(json!({"outcome":"rejected"})));
    }

    let Some(lifetime) = lifetime else {
        return (StatusCode::NOT_FOUND, Json(json!({"outcome":"rejected"})));
    };
    let result = execute_probe(&input, lifetime).await;
    if lifetime.remaining().is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"outcome":"failed"})),
        );
    }
    match result {
        Ok(receipt) => (
            StatusCode::OK,
            Json(serde_json::to_value(receipt).unwrap_or(Value::Null)),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"outcome":"failed"})),
        ),
    }
}

fn valid_request(input: &ProbeRequest, now: u64) -> bool {
    let window = probe_window();
    input.cron == window.cron
        && input.probe_nonce == window.nonce
        && input.scheduled_time_ms % 60_000 == 0
        && (window.starts_ms..=window.last_entry_ms).contains(&input.scheduled_time_ms)
        && (window.starts_ms..window.expires_ms).contains(&now)
        && input.worker_release.len() == 40
        && input
            .worker_release
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

const MAX_SAFE_UNIX_MS: u64 = 9_007_199_254_740_991;

/// A validated, request-local deadline. Wall clock inputs are checked once at
/// admission; the monotonic deadline prevents a wall-clock adjustment from
/// extending this request's execution budget.
#[derive(Clone, Copy)]
struct ProbeLifetime {
    execution_at_ms: u64,
    execution_deadline: Instant,
}

impl ProbeLifetime {
    fn from_env(now: u64) -> Option<Self> {
        let window = probe_window();
        let execute = parse_lifetime(
            &std::env::var("CORELINK_STAGING_PROBE_STARTED_MS").ok()?,
            &std::env::var("CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS").ok()?,
            &std::env::var("CORELINK_STAGING_PROBE_KILL_AT_MS").ok()?,
            now,
            &window,
        )?;
        let remaining = execute.checked_sub(now)?;
        Some(Self {
            execution_at_ms: execute,
            execution_deadline: Instant::now().checked_add(Duration::from_millis(remaining))?,
        })
    }

    fn remaining(self) -> Result<Duration, ()> {
        if now_ms() >= self.execution_at_ms {
            return Err(());
        }
        self.execution_deadline
            .checked_duration_since(Instant::now())
            .ok_or(())
    }

    async fn query<C: ProbeD1>(
        self,
        client: &C,
        sql: &str,
        params: &[Value],
    ) -> Result<Vec<D1Row>, ()> {
        let budget = self.remaining()?;
        // A timeout bounds this await. Dropping the local future does not mean
        // an already submitted Cloudflare D1 request was cancelled remotely.
        let result = tokio::time::timeout(budget, client.query(sql, params))
            .await
            .map_err(|_| ())?;
        self.remaining()?;
        result.map_err(|_| ())
    }

    async fn batch<C: ProbeD1>(
        self,
        client: &C,
        statements: Vec<D1BatchStatement>,
    ) -> Result<Result<Vec<Vec<D1Row>>, ()>, ()> {
        let budget = self.remaining()?;
        let result = tokio::time::timeout(budget, client.batch(statements))
            .await
            .map_err(|_| ())?;
        self.remaining()?;
        Ok(result)
    }
}

fn strict_timestamp(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let timestamp = value.parse::<u64>().ok()?;
    (timestamp <= MAX_SAFE_UNIX_MS).then_some(timestamp)
}

fn parse_lifetime(
    start: &str,
    execute: &str,
    kill: &str,
    now: u64,
    window: &ProbeWindow,
) -> Option<u64> {
    let start = strict_timestamp(start)?;
    let execute = strict_timestamp(execute)?;
    let kill = strict_timestamp(kill)?;
    let expected_execute = start.checked_add(600_000)?.min(window.expires_ms);
    let expected_kill = start.checked_add(1_200_000)?.min(window.expires_ms);
    (start >= window.starts_ms
        && start <= window.last_entry_ms
        && start < window.expires_ms
        && execute == expected_execute
        && kill == expected_kill
        && execute <= kill
        && now >= start
        && now < execute)
        .then_some(execute)
}

type QueryFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<D1Row>, ()>> + Send + 'a>>;
type BatchFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Vec<D1Row>>, ()>> + Send + 'a>>;

/// Narrow seam for exercising late D1 awaits without changing the shared D1
/// client or its behavior for any other route.
trait ProbeD1 {
    fn query<'a>(&'a self, sql: &'a str, params: &'a [Value]) -> QueryFuture<'a>;
    fn batch<'a>(&'a self, statements: Vec<D1BatchStatement>) -> BatchFuture<'a>;
}

impl ProbeD1 for D1HttpClient {
    fn query<'a>(&'a self, sql: &'a str, params: &'a [Value]) -> QueryFuture<'a> {
        Box::pin(async move { D1HttpClient::query(self, sql, params).await.map_err(|_| ()) })
    }

    fn batch<'a>(&'a self, statements: Vec<D1BatchStatement>) -> BatchFuture<'a> {
        Box::pin(async move { D1HttpClient::batch(self, statements).await.map_err(|_| ()) })
    }
}

async fn execute_probe(input: &ProbeRequest, lifetime: ProbeLifetime) -> Result<ProbeReceipt, ()> {
    if std::env::var("CF_API_TOKEN")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(());
    }
    let storage = StorageEnv::from_env().ok_or(())?;
    let client = D1HttpClient::new(&storage).map_err(|_| ())?;
    let table = format!(
        "corelink_staging_d1_probe_{}_{}",
        &input.worker_release[..16],
        input.scheduled_time_ms
    );
    let probe_id = format!("{}:{}", input.worker_release, input.scheduled_time_ms);
    let mut table_created = false;
    let outcome = execute_probe_operations(
        &client,
        lifetime,
        input,
        &table,
        &probe_id,
        &mut table_created,
    )
    .await;
    let outcome = if lifetime.remaining().is_ok() {
        outcome
    } else {
        Err(())
    };

    // Cleanup is a normal deadline-governed D1 request. If an earlier await
    // exhausts the budget, this is skipped and no subsequent SQL is submitted.
    let cleanup = cleanup_probe_table(&client, lifetime, &table, table_created).await;
    let cleanup = if lifetime.remaining().is_ok() {
        cleanup
    } else {
        Err(())
    };
    outcome?;
    cleanup?;

    Ok(ProbeReceipt {
        contract: "corelink-staging-d1-binding-runtime-v1",
        outcome: "pass",
        probe_nonce: input.probe_nonce.clone(),
        worker_release: input.worker_release.clone(),
        scheduled_time_ms: input.scheduled_time_ms,
        parameterized_select: true,
        failed_batch_observed: true,
        rollback_absence_verified: true,
        probe_table_dropped: table_created,
        d1_binding_intercepted: true,
        authorization_absent: true,
        cf_api_token_absent: true,
    })
}

async fn cleanup_probe_table<C: ProbeD1>(
    client: &C,
    lifetime: ProbeLifetime,
    table: &str,
    table_created: bool,
) -> Result<(), ()> {
    if !table_created {
        return Ok(());
    }
    lifetime
        .query(client, &format!("DROP TABLE IF EXISTS {table}"), &[])
        .await?;
    lifetime.remaining()?;
    Ok(())
}

async fn execute_probe_operations<C: ProbeD1>(
    client: &C,
    lifetime: ProbeLifetime,
    input: &ProbeRequest,
    table: &str,
    probe_id: &str,
    table_created: &mut bool,
) -> Result<(), ()> {
    let select = lifetime
        .query(
            client,
            "SELECT ?1 AS value",
            &[json!(input.scheduled_time_ms)],
        )
        .await?;
    if select.len() != 1 || select[0].get("value") != Some(&json!(input.scheduled_time_ms)) {
        return Err(());
    }

    lifetime.query(client, &format!("CREATE TABLE IF NOT EXISTS {table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)"), &[]).await?;
    *table_created = true;
    let baseline = lifetime
        .query(
            client,
            &format!("SELECT COUNT(*) AS count FROM {table}"),
            &[],
        )
        .await?;
    if baseline.len() != 1 || baseline[0].get("count").and_then(Value::as_i64) != Some(0) {
        return Err(());
    }

    let insert = format!("INSERT INTO {table} (probe_id, value) VALUES (?1, ?2)");
    let batch_result = lifetime
        .batch(
            client,
            vec![
                D1BatchStatement::new(insert.clone(), vec![json!(probe_id), json!("probe")]),
                // Duplicate the primary key to force an actual D1 statement failure.
                D1BatchStatement::new(insert, vec![json!(probe_id), json!("intentional-failure")]),
            ],
        )
        .await;
    // The staging Worker binding proxy returns a bounded generic failure
    // envelope for a rolled-back D1Database.batch error. The transport
    // deliberately does not expose provider exception text or infer which
    // statement failed; the following read proves the first insert rolled
    // back atomically.
    if batch_result?.is_ok() {
        return Err(());
    }

    let after = lifetime
        .query(
            client,
            &format!("SELECT COUNT(*) AS count FROM {table} WHERE probe_id = ?1"),
            &[json!(probe_id)],
        )
        .await?;
    if after.len() != 1 || after[0].get("count").and_then(Value::as_i64) != Some(0) {
        return Err(());
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    const RELEASE: &str = "0123456789abcdef0123456789abcdef01234567";
    const TIME: u64 = 1790975280000;

    fn input() -> ProbeRequest {
        ProbeRequest {
            cron: probe_window().cron,
            probe_nonce: probe_window().nonce,
            scheduled_time_ms: TIME,
            worker_release: RELEASE.to_owned(),
        }
    }

    #[test]
    fn accepts_only_exact_timed_staging_probe_contract() {
        let window = probe_window();
        assert_eq!(window.cron, "*/2 * * * *");
        assert_eq!(window.starts_ms, 1790975160000);
        assert_eq!(window.last_entry_ms, 1790982360000);
        assert_eq!(window.expires_ms, 1790986860000);
        assert_eq!(window.nonce, "issue-1700-recovery-20261002-v16");
        assert!(valid_request(&input(), TIME));
        let mut last_valid = input();
        last_valid.scheduled_time_ms = probe_window().last_entry_ms;
        assert!(valid_request(&last_valid, probe_window().last_entry_ms));
        assert!(valid_request(&last_valid, probe_window().last_entry_ms + 1));
        let mut after_cutoff = input();
        after_cutoff.scheduled_time_ms = probe_window().last_entry_ms + 60_000;
        assert!(!valid_request(
            &after_cutoff,
            probe_window().last_entry_ms + 1
        ));
        assert!(!valid_request(&last_valid, probe_window().expires_ms));
        let mut bad = input();
        bad.probe_nonce = "old-probe".to_owned();
        assert!(!valid_request(&bad, TIME));
        let mut bad = input();
        bad.cron = "0 0 * * *".to_owned();
        assert!(!valid_request(&bad, TIME));
        let mut bad = input();
        bad.worker_release.push('x');
        assert!(!valid_request(&bad, TIME));
        let mut bad = input();
        bad.scheduled_time_ms += 1;
        assert!(!valid_request(&bad, TIME));
    }

    #[test]
    fn probe_table_identifier_is_derived_only_from_hex_release_and_time() {
        assert_eq!(
            format!("corelink_staging_d1_probe_{}_{}", &RELEASE[..16], TIME),
            "corelink_staging_d1_probe_0123456789abcdef_1790975280000"
        );
    }

    struct LateBatchD1 {
        queries: AtomicUsize,
        batches: AtomicUsize,
    }

    impl ProbeD1 for LateBatchD1 {
        fn query<'a>(&'a self, sql: &'a str, _params: &'a [Value]) -> QueryFuture<'a> {
            Box::pin(async move {
                self.queries.fetch_add(1, Ordering::SeqCst);
                if sql.starts_with("SELECT ?1") {
                    let mut row = D1Row::new();
                    row.insert("value".into(), json!(TIME));
                    Ok(vec![row])
                } else if sql.starts_with("SELECT COUNT(*)") {
                    let mut row = D1Row::new();
                    row.insert("count".into(), json!(0));
                    Ok(vec![row])
                } else {
                    Ok(Vec::new())
                }
            })
        }

        fn batch<'a>(&'a self, _statements: Vec<D1BatchStatement>) -> BatchFuture<'a> {
            Box::pin(async move {
                self.batches.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(10)).await;
                Err(())
            })
        }
    }

    #[tokio::test]
    async fn late_batch_blocks_followup_query_and_final_drop() {
        let client = Arc::new(LateBatchD1 {
            queries: AtomicUsize::new(0),
            batches: AtomicUsize::new(0),
        });
        let lifetime = ProbeLifetime {
            execution_at_ms: now_ms().saturating_add(2_000),
            execution_deadline: Instant::now() + Duration::from_secs(2),
        };
        let mut table_created = false;
        let outcome = execute_probe_operations(
            client.as_ref(),
            lifetime,
            &input(),
            "probe_table",
            "probe_id",
            &mut table_created,
        )
        .await;
        assert!(outcome.is_err());
        assert!(table_created);
        assert_eq!(client.batches.load(Ordering::SeqCst), 1);
        assert_eq!(client.queries.load(Ordering::SeqCst), 3);

        let cleanup =
            cleanup_probe_table(client.as_ref(), lifetime, "probe_table", table_created).await;
        assert!(cleanup.is_err());
        // SELECT, CREATE, baseline SELECT ran; the post-batch read and DROP
        // were both rejected before reaching the client.
        assert_eq!(client.queries.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn lifetime_timestamp_parser_rejects_noncanonical_or_unsafe_values() {
        assert_eq!(strict_timestamp("1790856000000"), Some(1_790_856_000_000));
        for bad in [
            "",
            " 1790856000000",
            "+1790856000000",
            "0179",
            "1.0",
            "9007199254740992",
        ] {
            assert_eq!(strict_timestamp(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn deadline_contract_rejects_wrong_arithmetic_and_boundary_times() {
        let window = probe_window();
        let start = window.starts_ms;
        let execute = start + 600_000;
        let kill = start + 1_200_000;
        assert_eq!(
            parse_lifetime(
                &start.to_string(),
                &execute.to_string(),
                &kill.to_string(),
                start,
                &window
            ),
            Some(execute)
        );
        assert_eq!(
            parse_lifetime(
                &start.to_string(),
                &execute.to_string(),
                &kill.to_string(),
                execute - 1,
                &window
            ),
            Some(execute)
        );
        let last_execute = (window.last_entry_ms + 600_000).min(window.expires_ms);
        let last_kill = (window.last_entry_ms + 1_200_000).min(window.expires_ms);
        assert_eq!(
            parse_lifetime(
                &window.last_entry_ms.to_string(),
                &last_execute.to_string(),
                &last_kill.to_string(),
                window.last_entry_ms,
                &window,
            ),
            Some(last_execute)
        );

        for (bad_start, bad_execute, bad_kill, now) in [
            (start - 1, execute, kill, start),
            (
                window.last_entry_ms + 1,
                window.last_entry_ms + 600_001,
                window.last_entry_ms + 1_200_001,
                window.last_entry_ms + 1,
            ),
            (start, execute - 1, kill, start),
            (start, execute, kill - 1, start),
            (start, execute, kill, start - 1),
            (start, execute, kill, execute),
            (
                window.last_entry_ms,
                window.expires_ms,
                window.expires_ms,
                window.last_entry_ms,
            ),
        ] {
            assert!(parse_lifetime(
                &bad_start.to_string(),
                &bad_execute.to_string(),
                &bad_kill.to_string(),
                now,
                &window
            )
            .is_none());
        }
        assert!(parse_lifetime(
            "01790856000000",
            &execute.to_string(),
            &kill.to_string(),
            start,
            &window
        )
        .is_none());
        assert!(parse_lifetime(
            &start.to_string(),
            "9007199254740992",
            &kill.to_string(),
            start,
            &window
        )
        .is_none());
    }
}
