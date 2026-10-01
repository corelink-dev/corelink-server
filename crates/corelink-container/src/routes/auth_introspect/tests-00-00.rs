
    use std::collections::HashMap;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{self, Request};
    use corelink_pat::{
        mint, PatEnv, PatScopes, PatSigningKey, PrincipalId, TenantId, SCOPE_CACHE_RW,
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::adapter_pat::{PatRow, PatRowLookup};

    const TEST_AUTH_KEY: &str = "fabric-introspect-test-key-32-chars!";

    /// A fake `PatRowLookup` that returns a pre-seeded row (or a forced backend
    /// error) — drives the real crypto pipeline without a network.
    struct FakeLookup {
        rows: HashMap<String, PatRow>,
        backend_err: Option<String>,
    }

    impl FakeLookup {
        fn with_row(token_id: &str, row: PatRow) -> Self {
            let mut rows = HashMap::new();
            rows.insert(token_id.to_owned(), row);
            Self {
                rows,
                backend_err: None,
            }
        }
        fn backend(err: &str) -> Self {
            Self {
                rows: HashMap::new(),
                backend_err: Some(err.to_owned()),
            }
        }
    }

    #[async_trait]
    impl PatRowLookup for FakeLookup {
        async fn lookup(&self, token_id: &str) -> Result<Option<PatRow>, String> {
            if let Some(e) = &self.backend_err {
                return Err(e.clone());
            }
            Ok(self.rows.get(token_id).cloned())
        }
    }

    fn test_key() -> Arc<PatSigningKey> {
        Arc::new(PatSigningKey::from_bytes(vec![0x42u8; 32]).unwrap())
    }

    /// Mint a real PAT → `(plaintext, token_id, pat_hash, tenant_string)`.
    fn mint_pat(key: &PatSigningKey, tenant: u128) -> (String, String, String, String) {
        let tenant_id = TenantId(Uuid::from_u128(tenant));
        let (plaintext, pat) = mint(
            PatEnv::Pat,
            tenant_id,
            PrincipalId(Uuid::from_u128(tenant + 1000)),
            PatScopes::from_u64(SCOPE_CACHE_RW),
            None,
            key,
            1,
        )
        .unwrap();
        (
            plaintext.into_string(),
            pat.token_id.as_str().to_owned(),
            pat.hash.as_str().to_owned(),
            pat.tenant_id.0.to_string(),
        )
    }

    /// A `PatRow` for a freshly-minted PAT.
    fn row_for(hash: &str, tenant: &str) -> PatRow {
        PatRow {
            tenant_id: tenant.to_owned(),
            pat_hash: hash.to_owned(),
            scope: "cas:rw".to_owned(),
            find_only: false,
            runner_job: false,
        }
    }

    /// A D1 client that points at an unroutable host — every `query` fails,
    /// modelling a D1 backend fault for the 503 tier-query path.
    fn unreachable_d1() -> Arc<D1HttpClient> {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "http://127.0.0.1:1".to_owned(),
            r2_access_key_id: "x".to_owned(),
            r2_secret_access_key: "x".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "acct".to_owned(),
            cf_api_token: "tok".to_owned(),
            d1_database_id: "db".to_owned(),
        };
        Arc::new(D1HttpClient::new(&env).unwrap())
    }

    fn state_with(verifier: Arc<PatVerifier>, d1: Arc<D1HttpClient>) -> AuthIntrospectRouteState {
        AuthIntrospectRouteState::new(Arc::from(TEST_AUTH_KEY), verifier, d1)
    }

    fn introspect_request(auth: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri("/internal/v1/auth/introspect")
            .header("content-type", "application/json");
        if let Some(a) = auth {
            b = b.header("x-corelink-internal-auth", a);
        }
        b.body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        if bytes.is_empty() {
            return serde_json::Value::Null;
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Caller auth ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_service_secret_returns_401() {
        let verifier = Arc::new(PatVerifier::new(
            Arc::new(FakeLookup::with_row("x", row_for("h", "t"))),
            test_key(),
        ));
        let app = router(state_with(verifier, unreachable_d1()));
        let req = introspect_request(None, serde_json::json!({ "token": "corelink_pat_x" }));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_service_secret_returns_401() {
        let verifier = Arc::new(PatVerifier::new(
            Arc::new(FakeLookup::backend("unused")),
            test_key(),
        ));
        let app = router(state_with(verifier, unreachable_d1()));
        let req = introspect_request(
            Some("wrong-secret-which-is-also-32-chars!!"),
            serde_json::json!({ "token": "corelink_pat_x" }),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn additional_consumer_key_passes_gate_and_unknown_key_rejected() {
        // The HuGR toolkits fleet authenticates with its OWN introspect key (not
        // the runners' primary `FABRIC_INTROSPECT_AUTH_KEY`). Both configured
        // consumer keys must pass the auth gate; an unconfigured key must 401.
        // We assert the GATE outcome only (!= 401 = passed), independent of the
        // downstream PAT pipeline, so the test isolates the multi-key gate.
        const HUGR_KEY: &str = "hugr-fabric-introspect-key-32-chars!";
        let mk_app = || {
            let verifier = Arc::new(PatVerifier::new(
                Arc::new(FakeLookup::with_row("x", row_for("h", "t"))),
                test_key(),
            ));
            let state =
                AuthIntrospectRouteState::new(Arc::from(TEST_AUTH_KEY), verifier, unreachable_d1())
                    .with_auth_key(Arc::from(HUGR_KEY));
            router(state)
        };
        let body = serde_json::json!({ "token": "corelink_pat_x" });

        // Primary (runners) key → gate passes.
        let resp = mk_app()
            .oneshot(introspect_request(Some(TEST_AUTH_KEY), body.clone()))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "primary runners key must pass the gate"
        );

        // HuGR consumer key → gate passes identically (own secret).
        let resp = mk_app()
            .oneshot(introspect_request(Some(HUGR_KEY), body.clone()))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "HuGR consumer key must pass the gate"
        );

        // An unconfigured key (right length, wrong value) → still 401.
        let resp = mk_app()
            .oneshot(introspect_request(
                Some("some-other-unconfigured-32char-key!!"),
                body,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unconfigured key must be rejected"
        );
    }

    // ── Valid PAT → {valid, tenant_id, plan} ─────────────────────────────────

    #[tokio::test]
    async fn valid_pat_then_d1_fault_returns_503_failclosed() {
        // A PAT that VERIFIES (the Ok(tenant) arm) but whose plan cannot be
        // resolved (D1 unreachable) must 503 — never a guessed plan.
        let key = test_key();
        let (pt, tid, hash, tenant) = mint_pat(&key, 42);
        let lookup = Arc::new(FakeLookup::with_row(&tid, row_for(&hash, &tenant)));
        let verifier = Arc::new(PatVerifier::new(lookup, key));
        let app = router(state_with(verifier, unreachable_d1()));
        let req = introspect_request(Some(TEST_AUTH_KEY), serde_json::json!({ "token": pt }));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "verified PAT + D1 tier-query fault must 503 (never serve a guessed plan)"
        );
    }

    #[test]
    fn valid_response_shape_serialises() {
        // The cache-only 200 success shape: { valid:true, tenant_id, plan } with
        // the cap fields OMITTED (skip_serializing_if; no Runners entitlement).
        let resp = IntrospectResponse::valid(
            "11111111-1111-1111-1111-111111111111".to_owned(),
            "pro".to_owned(),
            None,
            None,
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["valid"], serde_json::json!(true));
        assert_eq!(
            v["tenant_id"],
            serde_json::json!("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(v["plan"], serde_json::json!("pro"));
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("max_concurrency"),
            "cache-only: max_concurrency must be omitted"
        );
        assert!(
            !obj.contains_key("max_vcpu_h"),
            "cache-only: max_vcpu_h must be omitted"
        );
        assert!(
            !obj.contains_key("rate_ceiling_per_min"),
            "M1: cap field must be omitted"
        );
    }

    #[test]
    fn valid_response_with_entitlement_serialises_max_concurrency() {
        // The runners-entitlement 200 shape: max_concurrency present as a
        // top-level integer (the exact shape the runners CoreLinkPlanStore parses).
        let resp = IntrospectResponse::valid(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            "pro".to_owned(),
            Some(40),
            None,
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["valid"], serde_json::json!(true));
        assert_eq!(v["plan"], serde_json::json!("pro"));
        assert_eq!(
            v["max_concurrency"],
            serde_json::json!(40),
            "max_concurrency must be a top-level integer when entitled"
        );
        // max_vcpu_h stays omitted when None (the asymmetric wall-off default).
        assert!(
            !v.as_object().unwrap().contains_key("max_vcpu_h"),
            "max_vcpu_h must be omitted when None"
        );
        // rate_ceiling_per_min stays omitted (still M1).
        assert!(!v.as_object().unwrap().contains_key("rate_ceiling_per_min"));
    }

    #[test]
    fn valid_response_with_vcpu_h_serialises_max_vcpu_h() {
        // The full runners-entitlement 200 shape: both caps present as top-level
        // integers — the exact byte-shape pinned in conformance/corelink-introspect.json
        // (pro/40 → max_vcpu_h 240) and mirrored by the runners CoreLinkPlanStore.
        let resp = IntrospectResponse::valid(
            "11111111-1111-4111-8111-111111111111".to_owned(),
            "pro".to_owned(),
            Some(40),
            Some(240),
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["valid"], serde_json::json!(true));
        assert_eq!(v["max_concurrency"], serde_json::json!(40));
        assert_eq!(
            v["max_vcpu_h"],
            serde_json::json!(240),
            "max_vcpu_h must be a top-level integer (vCPU-hours) when provisioned"
        );
        assert!(!v.as_object().unwrap().contains_key("rate_ceiling_per_min"));
    }

    /// Build a one-row `runners_entitlement` result set carrying the given
    /// `max_concurrency` JSON value (mirrors what `D1HttpClient::query` returns
    /// for `SELECT max_concurrency, max_vcpu_h ...`). The `max_vcpu_h` column is
    /// omitted from the row, modelling a pre-0072 / NULL-vCPU-h row.
    fn entitlement_rows(max_concurrency: serde_json::Value) -> Vec<crate::storage::d1_http::D1Row> {
        let mut row = serde_json::Map::new();
        row.insert("max_concurrency".to_owned(), max_concurrency);
        vec![row]
    }

    /// Build a one-row `runners_entitlement` result set carrying BOTH columns
    /// (mirrors a post-0072 row with a provisioned `max_vcpu_h`).
    fn entitlement_rows_with_vcpu_h(
        max_concurrency: serde_json::Value,
        max_vcpu_h: serde_json::Value,
    ) -> Vec<crate::storage::d1_http::D1Row> {
        let mut row = serde_json::Map::new();
        row.insert("max_concurrency".to_owned(), max_concurrency);
        row.insert("max_vcpu_h".to_owned(), max_vcpu_h);
        vec![row]
    }

    #[test]
    fn decode_runner_cap_present_row_yields_some() {
        // A `runners_entitlement` row → Some(cap), read from the TABLE value
        // (the separate entitlement axis), not any plan ladder.
        assert_eq!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(40))).unwrap(),
            Some(40),
            "an entitlement row must yield the stored cap"
        );
        // Any positive cap passes through verbatim — it is NOT clamped to a
        // ladder. A bespoke per-tenant value is honoured.
        assert_eq!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(7))).unwrap(),
            Some(7)
        );
    }

    #[test]
    fn decode_runner_cap_absent_row_yields_none() {
        // Empty result set (no entitlement) → None → field omitted → cache-only.
        assert_eq!(
            decode_runner_cap(&[]).unwrap(),
            None,
            "no entitlement row must yield None (cache-only; field omitted)"
        );
    }

    #[test]
    fn decode_runner_cap_out_of_contract_row_fails_closed() {
        // The table CHECK forbids these, but if one ever appears the decode
        // fails CLOSED (Err → 503), never a guessed/truncated cap.
        assert!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(0))).is_err(),
            "zero cap is out-of-contract → Err"
        );
        assert!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(-5))).is_err(),
            "negative cap is out-of-contract → Err"
        );
        assert!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(
                u64::from(u32::MAX) + 1
            )))
            .is_err(),
            "cap beyond u32 range is out-of-contract → Err"
        );
        assert!(
            decode_runner_cap(&entitlement_rows(serde_json::json!("forty"))).is_err(),
            "non-integer cap is out-of-contract → Err"
        );
    }

    #[test]
    fn decode_runner_cap_accepts_u32_max() {
        assert_eq!(
            decode_runner_cap(&entitlement_rows(serde_json::json!(u32::MAX))).unwrap(),
            Some(u32::MAX),
            "u32::MAX is the inclusive upper bound and must round-trip"
        );
    }

    // ── decode_runner_vcpu_h (migration 0072) ────────────────────────────────

    #[test]
    fn decode_runner_vcpu_h_present_row_yields_some() {
        // A row WITH max_vcpu_h surfaces the stored ceiling verbatim (vCPU-hours;
        // the separate additive axis — NOT a plan-derived value).
        assert_eq!(
            decode_runner_vcpu_h(&entitlement_rows_with_vcpu_h(
                serde_json::json!(40),
                serde_json::json!(240)
            ))
            .unwrap(),
            Some(240),
            "a row with max_vcpu_h must yield the stored ceiling"
        );
        // A bespoke (Enterprise) value is honoured, not clamped to the ladder.
        assert_eq!(
            decode_runner_vcpu_h(&entitlement_rows_with_vcpu_h(
                serde_json::json!(8),
                serde_json::json!(5000)
            ))
            .unwrap(),
            Some(5000)
        );
    }

    #[test]
    fn decode_runner_vcpu_h_null_column_yields_none_walloff() {
        // A row present but max_vcpu_h SQL NULL → None (field omitted ⇒ wall-off).
        // This is the intentional asymmetry vs max_concurrency: NULL is NOT an
        // error here.
        assert_eq!(
            decode_runner_vcpu_h(&entitlement_rows_with_vcpu_h(
                serde_json::json!(40),
                serde_json::Value::Null
            ))
            .unwrap(),
            None,
            "NULL max_vcpu_h must yield None (wall-off), not Err"
        );
    }

    #[test]
    fn decode_runner_vcpu_h_absent_column_yields_none() {
        // A row WITHOUT the max_vcpu_h column at all (pre-0072 result shape) → None.
        assert_eq!(
            decode_runner_vcpu_h(&entitlement_rows(serde_json::json!(40))).unwrap(),
            None,
            "a row missing the max_vcpu_h column must yield None (wall-off)"
        );
    }

    #[test]
    fn decode_runner_vcpu_h_no_row_yields_none() {
        // No entitlement row at all → None (field omitted).
        assert_eq!(
            decode_runner_vcpu_h(&[]).unwrap(),
            None,
            "no entitlement row must yield None for max_vcpu_h"
        );
    }

    #[test]
    fn decode_runner_vcpu_h_out_of_contract_value_fails_closed() {
        // A PRESENT, non-null value that is out-of-contract fails CLOSED (Err →
        // 503), never a guessed/truncated ceiling. (NULL is wall-off; these are
        // not NULL.)
        for bad in [
            serde_json::json!(0),
            serde_json::json!(-5),
            serde_json::json!(u64::from(u32::MAX) + 1),
            serde_json::json!("lots"),
        ] {
            assert!(
                decode_runner_vcpu_h(&entitlement_rows_with_vcpu_h(serde_json::json!(40), bad))
                    .is_err(),
                "out-of-contract max_vcpu_h must fail closed"
            );
        }
    }

    #[test]
    fn decode_runner_vcpu_h_accepts_u32_max() {
        assert_eq!(
            decode_runner_vcpu_h(&entitlement_rows_with_vcpu_h(
                serde_json::json!(40),
                serde_json::json!(u32::MAX)
            ))
            .unwrap(),
            Some(u32::MAX),
            "u32::MAX is the inclusive upper bound for max_vcpu_h"
        );
    }

include!("fragment-tests-00-00-01.rs");
