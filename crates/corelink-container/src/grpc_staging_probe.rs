//! Staging-only native gRPC transport diagnostic.
//!
//! The service is deliberately inert until the serial listener mount is added.
//! It has no cache, resource, tenant, customer, or external dependencies. Each
//! RPC independently authenticates the original `authorization` metadata so a
//! Worker/DO hop that drops or changes it cannot reach the service body.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::Stream;
use subtle::ConstantTimeEq;
use tonic::{Code, Request, Response, Status};

use crate::staging_transport_probe::{
    transport_probe_server::TransportProbe, TransportProbeRequest, TransportProbeResponse,
};

/// Exact literal payload for every successful diagnostic response.
pub const PROBE_PAYLOAD: [u8; 5] = [0x00, 0x01, 0x7f, 0x80, 0xff];
/// Fixed non-secret response metadata proving the native probe service ran.
pub const PROBE_RESPONSE_METADATA_KEY: &str = "x-corelink-staging-probe";
/// Value emitted for every successful probe RPC.
pub const PROBE_RESPONSE_METADATA_VALUE: &str = "v1";
/// The service returns precisely these three stream sequence values.
pub const STREAM_SEQUENCE_COUNT: u32 = 3;
/// A bounded interval gives a client a chance to cancel after a frame.
pub const INTERFRAME_DELAY: Duration = Duration::from_millis(25);
const MAX_BINDING_LIFETIME_MS: u64 = 900_000;
const MIN_TOKEN_BYTES: usize = 32;
const STAGING_ACCOUNT_ID: &str = "6a1fc1c626fc2628823e60b9db01f5cd";
const STAGING_WORKER_NAME: &str = "corelink-staging";

/// Validated staging binding used only to construct the diagnostic service.
///
/// The constructor reads process configuration once at listener setup; every
/// call still checks the original Authorization metadata against its token.
#[derive(Clone)]
pub struct StagingProbeConfig {
    token: Arc<str>,
    expires_at_ms: u64,
}

impl fmt::Debug for StagingProbeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagingProbeConfig")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl StagingProbeConfig {
    /// Read and validate the protected staging binding without logging values.
    #[must_use]
    pub fn from_environment_at(now_ms: u64) -> Option<Self> {
        let token = std::env::var("CORELINK_STAGING_GRPC_PROBE_TOKEN").ok()?;
        let expires_at_ms =
            parse_canonical_ms(&std::env::var("CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS").ok()?)?;
        let deployment_sha = std::env::var("CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA").ok()?;
        let corelink_environment = std::env::var("CORELINK_ENVIRONMENT").ok()?;
        let environment = std::env::var("ENVIRONMENT").ok()?;
        let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID").ok()?;
        let worker_name = std::env::var("CORELINK_STAGING_GRPC_PROBE_WORKER_NAME").ok()?;
        Self::from_parts(
            token,
            expires_at_ms,
            deployment_sha,
            corelink_environment,
            environment,
            account_id,
            worker_name,
            now_ms,
        )
    }

    fn from_parts(
        token: String,
        expires_at_ms: u64,
        deployment_sha: String,
        corelink_environment: String,
        environment: String,
        account_id: String,
        worker_name: String,
        now_ms: u64,
    ) -> Option<Self> {
        let lifetime_ms = expires_at_ms.checked_sub(now_ms)?;
        if token.as_bytes().len() < MIN_TOKEN_BYTES
            || lifetime_ms == 0
            || lifetime_ms > MAX_BINDING_LIFETIME_MS
            || !is_lower_hex_sha(&deployment_sha)
            || corelink_environment != "staging"
            || environment != "staging"
            || account_id != STAGING_ACCOUNT_ID
            || worker_name != STAGING_WORKER_NAME
        {
            return None;
        }
        Some(Self {
            token: Arc::from(token),
            expires_at_ms,
        })
    }

    fn binding_is_live(&self) -> bool {
        now_ms().is_some_and(|now| now < self.expires_at_ms)
    }

    #[cfg(test)]
    fn test_config() -> Self {
        Self::from_parts(
            "a".repeat(MIN_TOKEN_BYTES),
            now_ms().expect("test clock") + MAX_BINDING_LIFETIME_MS,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            now_ms().expect("test clock"),
        )
        .expect("valid test binding")
    }
}

/// The unmounted gRPC service. Mounting it requires the separate protected
/// listener composition owned by the serial integration step.
#[derive(Clone, Debug)]
pub struct StagingTransportProbe {
    config: StagingProbeConfig,
    #[cfg(test)]
    emitted_frames: Arc<std::sync::atomic::AtomicUsize>,
}

impl StagingTransportProbe {
    /// Construct the service from a previously validated staging binding.
    #[must_use]
    pub fn new(config: StagingProbeConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            emitted_frames: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    fn emitted_frames_for_test(&self) -> usize {
        self.emitted_frames
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if !self.config.binding_is_live() {
            return Err(unauthenticated());
        }
        let mut values = request.metadata().get_all("authorization").iter();
        let original = values
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(unauthenticated)?;
        if values.next().is_some() {
            return Err(unauthenticated());
        }
        let token = original
            .strip_prefix("Bearer ")
            .filter(|value| !value.is_empty())
            .ok_or_else(unauthenticated)?;
        if constant_time_secret_equal(self.config.token.as_bytes(), token.as_bytes()) {
            Ok(())
        } else {
            Err(unauthenticated())
        }
    }
}

#[tonic::async_trait]
impl TransportProbe for StagingTransportProbe {
    type StreamStream = ProbeStream;

    async fn unary(
        &self,
        request: Request<TransportProbeRequest>,
    ) -> Result<Response<TransportProbeResponse>, Status> {
        self.authorize(&request)?;
        Ok(probe_response_with_metadata(probe_response(0)))
    }

    async fn stream(
        &self,
        request: Request<TransportProbeRequest>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        self.authorize(&request)?;
        Ok(probe_response_with_metadata({
            #[cfg(test)]
            let stream = probe_stream(Arc::clone(&self.emitted_frames));
            #[cfg(not(test))]
            let stream = probe_stream();
            stream
        }))
    }
}

/// Stream generation retains no application state. Dropping the RPC response
/// drops this future, including a pending bounded delay, on client cancellation.
pub type ProbeStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<TransportProbeResponse, Status>> + Send>>;

#[cfg(not(test))]
fn probe_stream() -> ProbeStream {
    Box::pin(futures::stream::unfold(0_u32, |sequence| async move {
        if sequence == STREAM_SEQUENCE_COUNT {
            return None;
        }
        if sequence != 0 {
            tokio::time::sleep(INTERFRAME_DELAY).await;
        }
        Some((Ok(probe_response(sequence)), sequence + 1))
    }))
}

#[cfg(test)]
fn probe_stream(emitted_frames: Arc<std::sync::atomic::AtomicUsize>) -> ProbeStream {
    Box::pin(futures::stream::unfold(
        (0_u32, emitted_frames),
        |(sequence, emitted_frames)| async move {
            if sequence == STREAM_SEQUENCE_COUNT {
                return None;
            }
            if sequence != 0 {
                tokio::time::sleep(INTERFRAME_DELAY).await;
            }
            emitted_frames.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some((Ok(probe_response(sequence)), (sequence + 1, emitted_frames)))
        },
    ))
}

fn probe_response(sequence: u32) -> TransportProbeResponse {
    TransportProbeResponse {
        sequence,
        payload: PROBE_PAYLOAD.to_vec(),
    }
}

fn probe_response_with_metadata<T>(body: T) -> Response<T> {
    let mut response = Response::new(body);
    response.metadata_mut().insert(
        PROBE_RESPONSE_METADATA_KEY,
        tonic::metadata::MetadataValue::from_static(PROBE_RESPONSE_METADATA_VALUE),
    );
    response
}

fn unauthenticated() -> Status {
    Status::new(
        Code::Unauthenticated,
        "staging probe authentication required",
    )
}

/// Compare equal-length buffers in constant time, padding/truncating the
/// presented value before the compare so a wrong length does not short-circuit.
fn constant_time_secret_equal(expected: &[u8], provided: &[u8]) -> bool {
    let mut padded = vec![0_u8; expected.len()];
    let copied = expected.len().min(provided.len());
    padded[..copied].copy_from_slice(&provided[..copied]);
    let content_ok = expected.ct_eq(&padded).unwrap_u8();
    let length_ok = u8::from(expected.len() == provided.len());
    (content_ok & length_ok) == 1
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parse the protected expiry value in canonical unsigned-decimal form.
/// Leading zeroes, signs, whitespace, and non-ASCII digits are rejected before
/// integer conversion so equivalent textual values cannot bind differently.
fn parse_canonical_ms(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staging_transport_probe::{
        transport_probe_client::TransportProbeClient, transport_probe_server::TransportProbeServer,
    };
    use axum::{routing::get, Router};
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic::transport::Endpoint;

    async fn spawn_same_app(
        probe: Option<StagingTransportProbe>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let mut app = Router::new().route("/legacy", get(|| async { "legacy" }));
        if let Some(probe) = probe {
            app = app.merge(
                tonic::service::Routes::new(TransportProbeServer::new(probe)).into_axum_router(),
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("same-app server");
        });
        (address, task)
    }

    async fn h1_get(address: std::net::SocketAddr, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect H1 client");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write H1 request");
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_string(&mut response),
        )
        .await
        .expect("H1 response timeout")
        .expect("read H1 response");
        response
    }

    fn authorized_request() -> Request<TransportProbeRequest> {
        let mut request = Request::new(TransportProbeRequest {});
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", "a".repeat(MIN_TOKEN_BYTES))
                .parse()
                .expect("valid metadata"),
        );
        request
    }

    #[tokio::test]
    async fn unary_is_fixed_and_needs_the_original_authorization() {
        let service = StagingTransportProbe::new(StagingProbeConfig::test_config());
        let response = service
            .unary(authorized_request())
            .await
            .expect("authorized");
        assert_eq!(
            response
                .metadata()
                .get(PROBE_RESPONSE_METADATA_KEY)
                .and_then(|value| value.to_str().ok()),
            Some(PROBE_RESPONSE_METADATA_VALUE)
        );
        let response = response.into_inner();
        assert_eq!(response.sequence, 0);
        assert_eq!(response.payload, PROBE_PAYLOAD);
        assert_eq!(
            service
                .unary(Request::new(TransportProbeRequest {}))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        let mut altered = authorized_request();
        altered.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", "b".repeat(MIN_TOKEN_BYTES))
                .parse()
                .expect("valid metadata"),
        );
        assert_eq!(
            service.unary(altered).await.unwrap_err().code(),
            Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn stream_has_three_fixed_frames_and_is_droppable_after_first_frame() {
        let service = StagingTransportProbe::new(StagingProbeConfig::test_config());
        let response = service
            .stream(authorized_request())
            .await
            .expect("authorized");
        assert_eq!(
            response
                .metadata()
                .get(PROBE_RESPONSE_METADATA_KEY)
                .and_then(|value| value.to_str().ok()),
            Some(PROBE_RESPONSE_METADATA_VALUE)
        );
        let mut stream = response.into_inner();
        let first = stream.next().await.expect("first frame").expect("ok frame");
        assert_eq!(first.sequence, 0);
        assert_eq!(first.payload, PROBE_PAYLOAD);
        drop(stream);

        let mut stream = service
            .stream(authorized_request())
            .await
            .expect("authorized")
            .into_inner();
        let mut seen = Vec::new();
        while let Some(response) = stream.next().await {
            let response = response.expect("ok frame");
            assert_eq!(response.payload, PROBE_PAYLOAD);
            seen.push(response.sequence);
        }
        assert_eq!(seen, [0, 1, 2]);
    }

    #[test]
    fn binding_rejects_expired_far_future_or_non_staging_values() {
        let now = 1_000_u64;
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            now
        )
        .is_none());
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now + MAX_BINDING_LIFETIME_MS + 1,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            now
        )
        .is_none());
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now + 1,
            "A".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            now
        )
        .is_none());
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now + 1,
            "a".repeat(40),
            "production".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            now
        )
        .is_none());
    }

    #[test]
    fn binding_rejects_other_staging_target_or_noncanonical_expiry() {
        let now = 1_000_u64;
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now + 1,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            "another-account".into(),
            STAGING_WORKER_NAME.into(),
            now
        )
        .is_none());
        assert!(StagingProbeConfig::from_parts(
            "a".repeat(32),
            now + 1,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            "other-worker".into(),
            now
        )
        .is_none());
        for invalid in ["", "01", "+1", "1 ", " 1", "١"] {
            assert!(parse_canonical_ms(invalid).is_none(), "{invalid:?}");
        }
        assert_eq!(parse_canonical_ms("900001"), Some(900_001));
    }

    #[test]
    fn config_debug_redacts_the_bearer_token() {
        let token = "bearer-secret-must-not-appear-in-debug-output";
        let config = StagingProbeConfig::from_parts(
            token.into(),
            1_001,
            "a".repeat(40),
            "staging".into(),
            "staging".into(),
            STAGING_ACCOUNT_ID.into(),
            STAGING_WORKER_NAME.into(),
            1_000,
        )
        .expect("valid binding");
        let output = format!("{config:?}");
        assert!(!output.contains(token));
        assert!(output.contains("expires_at_ms"));
    }

    #[tokio::test]
    async fn same_axum_app_serves_h2c_probe_and_h1_legacy_route() {
        let probe = StagingTransportProbe::new(StagingProbeConfig::test_config());
        let (address, task) = spawn_same_app(Some(probe.clone())).await;
        let mut client = TransportProbeClient::connect(
            Endpoint::from_shared(format!("http://{address}")).expect("endpoint"),
        )
        .await
        .expect("h2c tonic connection");

        let unary = client
            .unary(authorized_request())
            .await
            .expect("h2c unary grpc-status=0");
        assert_eq!(
            unary
                .metadata()
                .get(PROBE_RESPONSE_METADATA_KEY)
                .and_then(|value| value.to_str().ok()),
            Some(PROBE_RESPONSE_METADATA_VALUE)
        );
        assert_eq!(unary.into_inner().payload, PROBE_PAYLOAD);

        let stream_response = client
            .stream(authorized_request())
            .await
            .expect("h2c stream grpc-status=0");
        assert_eq!(
            stream_response
                .metadata()
                .get(PROBE_RESPONSE_METADATA_KEY)
                .and_then(|value| value.to_str().ok()),
            Some(PROBE_RESPONSE_METADATA_VALUE)
        );
        let mut stream = stream_response.into_inner();
        let first = stream
            .message()
            .await
            .expect("stream status")
            .expect("first frame");
        assert_eq!(first.sequence, 0);
        assert_eq!(first.payload, PROBE_PAYLOAD);
        drop(stream);
        tokio::time::sleep(INTERFRAME_DELAY + INTERFRAME_DELAY).await;
        assert_eq!(probe.emitted_frames_for_test(), 1);

        let mut full_stream = client
            .stream(authorized_request())
            .await
            .expect("second h2c stream grpc-status=0")
            .into_inner();
        let mut sequences = Vec::new();
        while let Some(frame) = full_stream.message().await.expect("stream status") {
            assert_eq!(frame.payload, PROBE_PAYLOAD);
            sequences.push(frame.sequence);
        }
        assert_eq!(sequences, [0, 1, 2]);
        assert_eq!(probe.emitted_frames_for_test(), 4);

        let legacy = h1_get(address, "/legacy").await;
        assert!(legacy.starts_with("HTTP/1.1 200"));
        assert!(legacy.ends_with("legacy"));
        task.abort();
    }

    #[tokio::test]
    async fn unmounted_probe_path_is_denied_and_probe_auth_fails_closed() {
        let (address, task) = spawn_same_app(None).await;
        let unmounted = h1_get(address, "/corelink.staging.v1.TransportProbe/Unary").await;
        assert!(unmounted.starts_with("HTTP/1.1 404"));
        task.abort();

        let (address, task) = spawn_same_app(Some(StagingTransportProbe::new(
            StagingProbeConfig::test_config(),
        )))
        .await;
        let mut client = TransportProbeClient::connect(format!("http://{address}"))
            .await
            .expect("h2c tonic connection");
        assert_eq!(
            client
                .unary(Request::new(TransportProbeRequest {}))
                .await
                .expect_err("missing authorization denied")
                .code(),
            Code::Unauthenticated
        );
        let mut wrong = authorized_request();
        wrong.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", "b".repeat(MIN_TOKEN_BYTES))
                .parse()
                .expect("valid metadata"),
        );
        assert_eq!(
            client
                .unary(wrong)
                .await
                .expect_err("wrong authorization denied")
                .code(),
            Code::Unauthenticated
        );
        task.abort();
    }
}
