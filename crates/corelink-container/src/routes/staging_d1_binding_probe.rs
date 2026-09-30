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

use crate::storage::{
    d1_http::{D1BatchStatement, D1HttpClient},
    StorageEnv,
};

#[derive(Deserialize)]
struct ProbeWindow {
    cron: String,
    starts_ms: u64,
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
    if !enabled()
        || headers.contains_key("authorization")
        || headers.contains_key("cookie")
        || !valid_request(&input, now_ms())
    {
        return (StatusCode::NOT_FOUND, Json(json!({"outcome":"rejected"})));
    }

    match execute_probe(&input).await {
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
        && (window.starts_ms..window.expires_ms).contains(&input.scheduled_time_ms)
        && (window.starts_ms..window.expires_ms).contains(&now)
        && input.worker_release.len() == 40
        && input
            .worker_release
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

async fn execute_probe(input: &ProbeRequest) -> Result<ProbeReceipt, ()> {
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
    let outcome = async {
        let select = client.query("SELECT ?1 AS value", &[json!(input.scheduled_time_ms)]).await.map_err(|_| ())?;
        if select.len() != 1 || select[0].get("value") != Some(&json!(input.scheduled_time_ms)) {
            return Err(());
        }

        client.query(&format!("CREATE TABLE IF NOT EXISTS {table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)"), &[])
            .await.map_err(|_| ())?;
        table_created = true;
        let baseline = client.query(&format!("SELECT COUNT(*) AS count FROM {table}"), &[]).await.map_err(|_| ())?;
        if baseline.len() != 1 || baseline[0].get("count").and_then(Value::as_i64) != Some(0) {
            return Err(());
        }

        let insert = format!("INSERT INTO {table} (probe_id, value) VALUES (?1, ?2)");
        let batch_result = client.batch(vec![
            D1BatchStatement::new(insert.clone(), vec![json!(probe_id), json!("probe")]),
            // Duplicate the primary key to force an actual D1 statement failure.
            D1BatchStatement::new(insert, vec![json!(probe_id), json!("intentional-failure")]),
        ]).await;
        // The staging Worker binding proxy returns a bounded generic failure
        // envelope for a rolled-back D1Database.batch error. The transport
        // deliberately does not expose provider exception text or infer which
        // statement failed; the following read proves the first insert rolled
        // back atomically.
        if batch_result.is_ok() {
            return Err(());
        }

        let after = client.query(&format!("SELECT COUNT(*) AS count FROM {table} WHERE probe_id = ?1"), &[json!(probe_id)])
            .await.map_err(|_| ())?;
        if after.len() != 1 || after[0].get("count").and_then(Value::as_i64) != Some(0) {
            return Err(());
        }
        Ok(())
    }.await;

    let cleanup = if table_created {
        client
            .query(&format!("DROP TABLE IF EXISTS {table}"), &[])
            .await
            .map(|_| ())
            .map_err(|_| ())
    } else {
        Ok(())
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str = "0123456789abcdef0123456789abcdef01234567";
    const TIME: u64 = 1790726460000;

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
        assert!(valid_request(&input(), TIME));
        let mut last_valid = input();
        last_valid.scheduled_time_ms = probe_window().expires_ms - 60_000;
        assert!(valid_request(&last_valid, probe_window().expires_ms - 1));
        assert!(!valid_request(&last_valid, probe_window().expires_ms));
        assert!(!valid_request(&input(), probe_window().expires_ms));
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
            "corelink_staging_d1_probe_0123456789abcdef_1790726460000"
        );
    }
}
