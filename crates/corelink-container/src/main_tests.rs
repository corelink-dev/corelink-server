#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{
    build_runners_resolver_from, build_tier_selector_from, byok_revocation_scheduler_enabled,
    cache_tier_price_ids_missing_in_prod, email_hash_salt_missing_in_prod,
    should_fatal_on_missing_gate,
};
use corelink_billing_stripe_materializer::{
    RunnersEntitlement, RunnersEntitlementResolver, TierSelectError, TierSelector,
};
use corelink_tier_selection::tier::TierKind;
use std::collections::HashMap;

/// Finding #7 truth table: the boot guard fails fatal ONLY when prod is
/// detected AND the native PAT gate did not build. Dev/CI (not prod) is
/// never fatal regardless of the gate; a present gate in prod is fine.
#[test]
fn fatal_only_when_prod_and_gate_missing() {
    // prod + gate missing → FATAL (the silent-downgrade case finding #7
    // closes).
    assert!(should_fatal_on_missing_gate(true, false));
    // prod + gate present → OK (the backstop is wired).
    assert!(!should_fatal_on_missing_gate(true, true));
    // dev/CI + gate missing → OK (benign; this is the normal dev posture).
    assert!(!should_fatal_on_missing_gate(false, false));
    // dev/CI + gate present → OK.
    assert!(!should_fatal_on_missing_gate(false, true));
}

/// Regression for the production image outage: compiling a real AWS provider
/// does not itself enable the scheduler. With no credential-bearing opt-in the
/// cache server proceeds to bind; BYOK work remains unavailable rather than
/// falling back to local/plaintext crypto.
#[test]
fn byok_scheduler_requires_explicit_true() {
    for disabled in [
        None,
        Some(""),
        Some("0"),
        Some("false"),
        Some("yes"),
        Some(" true-ish "),
    ] {
        assert!(!byok_revocation_scheduler_enabled(disabled));
    }
    for enabled in [Some("1"), Some(" true "), Some("TRUE")] {
        assert!(byok_revocation_scheduler_enabled(enabled));
    }
}

/// Revenue-path truth table: in prod the boot guard names EXACTLY the
/// cache-tier `STRIPE_PRICE_ID_*` env vars that are unset/empty (the case
/// where a real `price_live_…` would fall back to the un-matchable
/// `plan_{tier}` placeholder → `UnknownPlan` → 422 on a paying customer).
/// Non-prod is never gated (dev/CI + fixture deployments keep the literal
/// fallbacks). A fully-configured prod map arms clean (empty result).
#[test]
fn cache_tier_price_ids_missing_names_exactly_the_unset_tiers_in_prod() {
    fn map_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    // prod + all four set → armed (empty).
    let full = map_of(&[
        ("STRIPE_PRICE_ID_SOLO", "price_live_solo"),
        ("STRIPE_PRICE_ID_STARTER", "price_live_starter"),
        ("STRIPE_PRICE_ID_PRO", "price_live_pro"),
        ("STRIPE_PRICE_ID_MAX", "price_live_max"),
    ]);
    assert!(cache_tier_price_ids_missing_in_prod(true, |n| full.get(n).cloned()).is_empty());

    // prod + Solo unset → names EXACTLY Solo (the primary-tier-unsellable case).
    let no_solo = map_of(&[
        ("STRIPE_PRICE_ID_STARTER", "price_live_starter"),
        ("STRIPE_PRICE_ID_PRO", "price_live_pro"),
        ("STRIPE_PRICE_ID_MAX", "price_live_max"),
    ]);
    assert_eq!(
        cache_tier_price_ids_missing_in_prod(true, |n| no_solo.get(n).cloned()),
        vec!["STRIPE_PRICE_ID_SOLO"]
    );

    // prod + a whitespace-only value counts as unset (trim → empty).
    let blank_pro = map_of(&[
        ("STRIPE_PRICE_ID_SOLO", "price_live_solo"),
        ("STRIPE_PRICE_ID_STARTER", "price_live_starter"),
        ("STRIPE_PRICE_ID_PRO", "   "),
        ("STRIPE_PRICE_ID_MAX", "price_live_max"),
    ]);
    assert_eq!(
        cache_tier_price_ids_missing_in_prod(true, |n| blank_pro.get(n).cloned()),
        vec!["STRIPE_PRICE_ID_PRO"]
    );

    // NON-prod is never gated, even with every price id unset.
    assert!(cache_tier_price_ids_missing_in_prod(false, |_| None).is_empty());
}

/// CAA-360 MEDIUM truth table: the boot guard refuses to boot ONLY when prod
/// is detected AND `EMAIL_HASH_SALT` is unset/empty — the exact case where
/// `email_hash::hash_email` would silently regress to the rainbow-table-
/// reversible unsalted `SHA-256`. Prod + salt present is fine (salted path);
/// non-prod is never fatal regardless of the salt (dev/CI + tests unchanged).
#[test]
fn email_hash_salt_fatal_only_when_prod_and_salt_missing() {
    // prod + salt unset/empty → FATAL (the silent-unsalted-regression case).
    assert!(email_hash_salt_missing_in_prod(true, false));
    // prod + salt present → OK (the salted HMAC path is guaranteed).
    assert!(!email_hash_salt_missing_in_prod(true, true));
    // non-prod + salt unset → OK (no regression: dev/CI + tests run unsalted).
    assert!(!email_hash_salt_missing_in_prod(false, false));
    // non-prod + salt present → OK.
    assert!(!email_hash_salt_missing_in_prod(false, true));
}

/// F-001 regression: when the live `STRIPE_PRICE_ID_*` env values are
/// present, the tier selector MUST classify the real `price_…` ids
/// (the keys a real `customer.subscription.updated` carries) — not
/// the literal `plan_*` placeholders. Before the fix the container
/// map only held `plan_*`, so every real event 422'd (`UnknownPlan`).
#[test]
fn tier_selector_maps_real_price_ids_when_env_set() {
    let env: HashMap<&str, &str> = HashMap::from([
        ("STRIPE_PRICE_ID_SOLO", "price_live_solo_abc"),
        ("STRIPE_PRICE_ID_STARTER", "price_live_starter_def"),
        ("STRIPE_PRICE_ID_PRO", "price_live_pro_ghi"),
        ("STRIPE_PRICE_ID_MAX", "price_live_max_jkl"),
    ]);
    let sel = build_tier_selector_from(|name| env.get(name).map(|s| (*s).to_string()));

    // Real price ids resolve.
    assert_eq!(
        sel.compute_tier("price_live_solo_abc", 1).unwrap(),
        TierKind::Solo
    );
    assert_eq!(
        sel.compute_tier("price_live_starter_def", 3).unwrap(),
        TierKind::Starter
    );
    assert_eq!(
        sel.compute_tier("price_live_pro_ghi", 5).unwrap(),
        TierKind::Pro
    );
    assert_eq!(
        sel.compute_tier("price_live_max_jkl", 1).unwrap(),
        TierKind::Max
    );

    // The literal placeholder is NOT registered once the real id wins
    // (a real Stripe event never carries `plan_solo`).
    assert!(matches!(
        sel.compute_tier("plan_solo", 1),
        Err(TierSelectError::UnknownPlan(_))
    ));
}

/// F-001: an empty/whitespace env value falls back to the literal
/// `plan_{tier}` key so test fixtures + pre-price-id deployments
/// still classify (back-compat, no regression for the old wiring).
#[test]
fn tier_selector_falls_back_to_literal_when_env_unset_or_blank() {
    let env: HashMap<&str, &str> = HashMap::from([
        // SOLO unset entirely; STARTER blank; PRO whitespace-only.
        ("STRIPE_PRICE_ID_MAX", "price_live_max_only"),
        ("STRIPE_PRICE_ID_STARTER", ""),
        ("STRIPE_PRICE_ID_PRO", "   "),
    ]);
    let sel = build_tier_selector_from(|name| env.get(name).map(|s| (*s).to_string()));

    assert_eq!(sel.compute_tier("plan_solo", 1).unwrap(), TierKind::Solo);
    assert_eq!(
        sel.compute_tier("plan_starter", 1).unwrap(),
        TierKind::Starter
    );
    assert_eq!(sel.compute_tier("plan_pro", 1).unwrap(), TierKind::Pro);
    // MAX had a real id → real id wins.
    assert_eq!(
        sel.compute_tier("price_live_max_only", 1).unwrap(),
        TierKind::Max
    );
}

#[test]
fn runners_resolver_dormant_when_no_price_ids_set() {
    // No STRIPE_PRICE_ID_RUNNER_* env → None (Runners seed stays dormant,
    // every subscription routes to the cache tier path).
    let env: HashMap<&str, &str> = HashMap::new();
    let r = build_runners_resolver_from(|name| env.get(name).map(|s| (*s).to_string()));
    assert!(r.is_none());
}

#[test]
fn runners_resolver_maps_set_prices_to_the_ratified_ladder() {
    let env: HashMap<&str, &str> = HashMap::from([
        ("STRIPE_PRICE_ID_RUNNER_STARTER", "price_live_run_starter"),
        ("STRIPE_PRICE_ID_RUNNER_TEAM", "price_live_run_team"),
        ("STRIPE_PRICE_ID_RUNNER_MAX", "price_live_run_max"),
        ("STRIPE_PRICE_ID_RUNNER_PRO", ""), // unset/blank → not wired
    ]);
    let r = build_runners_resolver_from(|name| env.get(name).map(|s| (*s).to_string()))
        .expect("at least one runner price set → Some");
    // Ratified ladder: Starter 20/100, Team 80/600, Max 320/2400.
    assert_eq!(
        r.resolve("price_live_run_starter"),
        Some(RunnersEntitlement {
            max_concurrency: 20,
            max_vcpu_h: 100
        })
    );
    assert_eq!(
        r.resolve("price_live_run_team"),
        Some(RunnersEntitlement {
            max_concurrency: 80,
            max_vcpu_h: 600
        })
    );
    assert_eq!(
        r.resolve("price_live_run_max"),
        Some(RunnersEntitlement {
            max_concurrency: 320,
            max_vcpu_h: 2400
        })
    );
    // Blank PRO was not wired; a cache price is not a runner price.
    assert_eq!(r.resolve("price_live_run_pro"), None);
    assert_eq!(r.resolve("plan_pro"), None);
}

#[test]
fn runners_resolver_maps_every_ratified_price_and_rejects_placeholders() {
    let env: HashMap<&str, &str> = HashMap::from([
        ("STRIPE_PRICE_ID_RUNNER_STARTER", "price_runner_starter"),
        ("STRIPE_PRICE_ID_RUNNER_PRO", "price_runner_pro"),
        ("STRIPE_PRICE_ID_RUNNER_TEAM", "price_runner_team"),
        ("STRIPE_PRICE_ID_RUNNER_SCALE", "price_runner_scale"),
        ("STRIPE_PRICE_ID_RUNNER_MAX", "price_runner_max"),
    ]);
    let resolver = build_runners_resolver_from(|name| env.get(name).map(|v| (*v).to_owned()))
        .expect("all five configured runner prices must arm the resolver");
    let expected = [
        ("price_runner_starter", 20, 100),
        ("price_runner_pro", 40, 240),
        ("price_runner_team", 80, 600),
        ("price_runner_scale", 160, 1200),
        ("price_runner_max", 320, 2400),
    ];
    for (price, max_concurrency, max_vcpu_h) in expected {
        assert_eq!(
            resolver.resolve(price),
            Some(RunnersEntitlement {
                max_concurrency,
                max_vcpu_h
            }),
            "runner entitlement mapping drifted for {price}"
        );
    }
    for placeholder in [
        "plan_runner_starter",
        "plan_runner_pro",
        "plan_runner_team",
        "plan_runner_scale",
        "plan_runner_max",
    ] {
        assert_eq!(
            resolver.resolve(placeholder),
            None,
            "placeholder must not arm {placeholder}"
        );
    }
}

#[test]
fn b126_t1_files_remain_below_the_1000_line_ceiling() {
    const FILES: &[(&str, &str)] = &[
        ("routes/dpa_accept.rs", include_str!("routes/dpa_accept.rs")),
        (
            "routes/public_revoke.rs",
            include_str!("routes/public_revoke.rs"),
        ),
        ("routes/failover.rs", include_str!("routes/failover.rs")),
        (
            "routes/public_mirror.rs",
            include_str!("routes/public_mirror.rs"),
        ),
        ("routes/signup.rs", include_str!("routes/signup.rs")),
        (
            "routes/ratelimit_layer.rs",
            include_str!("routes/ratelimit_layer.rs"),
        ),
        (
            "routes/dsr/adapter_d1.rs",
            include_str!("routes/dsr/adapter_d1.rs"),
        ),
        ("main.rs", include_str!("main.rs")),
        ("main_boot.rs", include_str!("main_boot.rs")),
        ("main_byok.rs", include_str!("main_byok.rs")),
        ("main_runtime.rs", include_str!("main_runtime.rs")),
        ("main_tests.rs", include_str!("main_tests.rs")),
        (
            "routes/signup_support.rs",
            include_str!("routes/signup_support.rs"),
        ),
        (
            "routes/dpa_accept_tests.rs",
            include_str!("routes/dpa_accept_tests.rs"),
        ),
        (
            "routes/public_revoke_tests.rs",
            include_str!("routes/public_revoke_tests.rs"),
        ),
        (
            "routes/failover_tests.rs",
            include_str!("routes/failover_tests.rs"),
        ),
        (
            "routes/public_mirror_tests.rs",
            include_str!("routes/public_mirror_tests.rs"),
        ),
        (
            "routes/signup_tests.rs",
            include_str!("routes/signup_tests.rs"),
        ),
        (
            "routes/ratelimit_layer_tests.rs",
            include_str!("routes/ratelimit_layer_tests.rs"),
        ),
        (
            "routes/dsr/adapter_d1_tests.rs",
            include_str!("routes/dsr/adapter_d1_tests.rs"),
        ),
        (
            "routes/dsr/adapter_d1/classification.rs",
            include_str!("routes/dsr/adapter_d1/classification.rs"),
        ),
    ];
    for (path, source) in FILES {
        assert!(
            source.lines().count() < 1_000,
            "B-126 regression: {path} reached the 1000-line ceiling"
        );
    }
}

#[test]
fn b126_t1_submodule_wiring_is_explicit_and_load_bearing() {
    let main = include_str!("main.rs");
    assert!(main.contains("#[path = \"main_boot.rs\"]\nmod boot;"));
    assert!(main.contains("#[path = \"main_byok.rs\"]\nmod byok;"));
    assert!(main.contains("#[path = \"main_runtime.rs\"]\nmod runtime;"));
    assert!(main.contains("#[path = \"main_tests.rs\"]\nmod tests;"));
    let adapter_d1 = include_str!("routes/dsr/adapter_d1.rs");
    assert!(adapter_d1.contains("mod classification;"));
    for (owner, path) in [
        (
            include_str!("routes/dpa_accept.rs"),
            "#[path = \"dpa_accept_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/public_revoke.rs"),
            "#[path = \"public_revoke_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/failover.rs"),
            "#[path = \"failover_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/public_mirror.rs"),
            "#[path = \"public_mirror_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/signup.rs"),
            "#[path = \"signup_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/ratelimit_layer.rs"),
            "#[path = \"ratelimit_layer_tests.rs\"]\nmod tests;",
        ),
        (
            include_str!("routes/dsr/adapter_d1.rs"),
            "#[path = \"adapter_d1_tests.rs\"]\nmod tests;",
        ),
    ] {
        assert!(owner.contains(path), "B-126 test wiring lost: {path}");
    }
    let signup = include_str!("routes/signup.rs");
    assert!(signup.contains("#[path = \"signup_support.rs\"]\nmod support;"));
    assert!(signup.contains("use support::{extract_client_ip, token_prefix, PRE_AUTH_TENANT};"));
}
