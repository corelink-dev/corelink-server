//! Authenticated, composition-ready staging load-test teardown route.
//!
//! Router assembly is deliberately owned elsewhere.  This module exposes the
//! route and its narrow service seam without acquiring provider credentials or
//! mounting itself from an unrelated composition file.

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
    staging_load_test_admission::{admit_staging_load_test_request, StagingLoadTestAdmissionGate},
    staging_load_test_ownership::{
        StagingLoadTestScenario, StagingLoadTestTeardownIdentity, StagingLoadTestTeardownReceipt,
    },
};

/// Bounded server-side teardown service.  Implementations must derive every
/// inventory row from the admitted identity and return only a terminal receipt.
#[async_trait]
pub(crate) trait StagingLoadTestTeardownService: Send + Sync {
    async fn teardown(
        &self,
        identity: StagingLoadTestTeardownIdentity,
    ) -> Result<StagingLoadTestTeardownReceipt, ()>;
}

/// State for the dedicated teardown endpoint.
#[derive(Clone)]
pub(crate) struct StagingLoadTestTeardownRouteState {
    pub(crate) admission: Option<StagingLoadTestAdmissionGate>,
    pub(crate) service: Arc<dyn StagingLoadTestTeardownService>,
}

impl core::fmt::Debug for StagingLoadTestTeardownRouteState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagingLoadTestTeardownRouteState")
            .field("admission", &self.admission.is_some())
            .field("service", &"StagingLoadTestTeardownService")
            .finish()
    }
}

/// Build the route at `POST /_internal/staging/load-tests/:scenario/teardown`.
/// It has no route for a free-form run ID or deployment SHA: both coordinates
/// are taken only from the durable, authenticated admission context.
pub(crate) fn router(state: StagingLoadTestTeardownRouteState) -> Router {
    Router::new()
        .route(
            "/_internal/staging/load-tests/:scenario/teardown",
            post(handle_teardown),
        )
        .with_state(state)
}

async fn handle_teardown(
    State(state): State<StagingLoadTestTeardownRouteState>,
    Path(scenario): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(expected_scenario) = parse_scenario(&scenario) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let context = match admit_staging_load_test_request(
        state.admission.as_ref(),
        &headers,
        expected_scenario,
    )
    .await
    {
        Ok(Some(context)) => context,
        // Unlike write routes, a teardown request is never ordinary traffic:
        // missing, malformed, replayed, or unconfigured admission all deny.
        Ok(None) | Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    match state
        .service
        .teardown(StagingLoadTestTeardownIdentity::from_admission(&context))
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
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    struct RejectingService;

    #[async_trait]
    impl StagingLoadTestTeardownService for RejectingService {
        async fn teardown(
            &self,
            _: StagingLoadTestTeardownIdentity,
        ) -> Result<StagingLoadTestTeardownReceipt, ()> {
            Err(())
        }
    }

    #[tokio::test]
    async fn route_requires_admission_before_it_calls_the_service() {
        let app = router(StagingLoadTestTeardownRouteState {
            admission: None,
            service: Arc::new(RejectingService),
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_internal/staging/load-tests/cas/teardown")
                    .body(Body::empty())
                    .expect("test request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn scenario_parser_is_closed_to_the_admission_allowlist() {
        assert_eq!(parse_scenario("cas"), Some(StagingLoadTestScenario::Cas));
        assert_eq!(parse_scenario("production"), None);
    }
}
