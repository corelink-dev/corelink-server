//! Authenticated staging inventory-seal route.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};

use crate::storage::{
    staging_load_test_admission::{
        verify_staging_load_test_teardown_request, StagingLoadTestAdmissionGate,
    },
    staging_load_test_ownership::StagingLoadTestScenario,
    staging_load_test_seal::{
        StagingLoadTestSealIdentity, StagingLoadTestSealReceipt, StagingLoadTestSealStore,
    },
};

#[async_trait]
pub(crate) trait StagingLoadTestSealService: Send + Sync {
    async fn seal(
        &self,
        identity: StagingLoadTestSealIdentity,
    ) -> Result<StagingLoadTestSealReceipt, ()>;
}

#[async_trait]
impl StagingLoadTestSealService for StagingLoadTestSealStore {
    async fn seal(
        &self,
        identity: StagingLoadTestSealIdentity,
    ) -> Result<StagingLoadTestSealReceipt, ()> {
        StagingLoadTestSealStore::seal(self, identity).await
    }
}

#[derive(Clone)]
pub(crate) struct StagingLoadTestSealRouteState {
    pub(crate) admission: Option<StagingLoadTestAdmissionGate>,
    pub(crate) service: Arc<dyn StagingLoadTestSealService>,
}

impl core::fmt::Debug for StagingLoadTestSealRouteState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagingLoadTestSealRouteState")
            .field("admission", &self.admission.is_some())
            .field("service", &"StagingLoadTestSealService")
            .finish()
    }
}

pub(crate) fn router(state: StagingLoadTestSealRouteState) -> Router {
    Router::new()
        .route(
            "/_internal/staging/load-tests/{scenario}/seal",
            post(handle_seal),
        )
        .with_state(state)
}

/// Mount only when both staging admission and the narrow D1 writer are usable.
pub async fn build_router_from_env() -> Option<Router> {
    let admission = StagingLoadTestAdmissionGate::from_env().ok()?;
    let service = StagingLoadTestSealStore::from_env().ok()?;
    Some(router(StagingLoadTestSealRouteState {
        admission: Some(admission),
        service: Arc::new(service),
    }))
}

async fn handle_seal(
    State(state): State<StagingLoadTestSealRouteState>,
    Path(scenario): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(expected_scenario) = parse_scenario(&scenario) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let context = match verify_staging_load_test_teardown_request(
        state.admission.as_ref(),
        &headers,
        expected_scenario,
    ) {
        Ok(context) => context,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    match state
        .service
        .seal(StagingLoadTestSealIdentity::from_admission(&context))
        .await
    {
        Ok(receipt) => (StatusCode::OK, Json(receipt)).into_response(),
        Err(()) => StatusCode::CONFLICT.into_response(),
    }
}

fn parse_scenario(value: &str) -> Option<StagingLoadTestScenario> {
    [
        StagingLoadTestScenario::Signup,
        StagingLoadTestScenario::Webhook,
        StagingLoadTestScenario::Dsr,
        StagingLoadTestScenario::Cas,
        StagingLoadTestScenario::Byok,
        StagingLoadTestScenario::Endurance2h,
        StagingLoadTestScenario::B103CargoWrite,
    ]
    .into_iter()
    .find(|scenario| scenario.as_str() == value)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test assertions intentionally surface failures"
)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    struct RejectingService;
    #[async_trait]
    impl StagingLoadTestSealService for RejectingService {
        async fn seal(
            &self,
            _: StagingLoadTestSealIdentity,
        ) -> Result<StagingLoadTestSealReceipt, ()> {
            Err(())
        }
    }

    #[tokio::test]
    async fn route_denies_missing_admission_before_the_service() {
        let app = router(StagingLoadTestSealRouteState {
            admission: None,
            service: Arc::new(RejectingService),
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_internal/staging/load-tests/cas/seal")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn scenario_parser_is_closed_to_the_admission_allowlist() {
        assert_eq!(parse_scenario("cas"), Some(StagingLoadTestScenario::Cas));
        assert_eq!(parse_scenario("production"), None);
    }
}
