#!/usr/bin/env bash
# Run the explicitly selected real-network integration harnesses.
#
# This script is intentionally a small allow-list, not a generic cargo wrapper.
# It is called only by .github/workflows/real-ignored-harnesses.yml, which is a
# protected workflow_dispatch lane. In particular, the PAT seed harness is not
# an allowed profile: it prints a credential and seed SQL and must never run in
# CI, whether the caller has a secret or not.

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"
readonly PROFILE="${1:-}"
readonly RECEIPT_DIR="${GITHUB_WORKSPACE:-.}/artifacts/real-ignored-harnesses"
readonly RECEIPT_FILE="${RECEIPT_DIR}/receipt.jsonl"
readonly RECEIPT_SHA="${GITHUB_SHA:-}"
RAW_LOGS=()
LAST_DIAGNOSTIC_CLASS=""

usage() {
  printf 'usage: %s {d1|r2|stripe|neon|all}\n' "$SCRIPT_NAME" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

require_env() {
  local name value
  for name in "$@"; do
    value="${!name-}"
    [[ -n "$value" ]] || die "required environment variable is missing: $name"
  done
}

require_https() {
  local name="$1"
  [[ "${!name}" == https://* ]] || die "$name must use https://"
}

record_receipt() {
  # Values are closed selectors/statuses plus GitHub's immutable run SHA;
  # credentials never enter receipts.
  local profile="$1" test_name="$2" status="$3"
  if [[ ( "$status" == "failed" || "$status" == "not-discovered" ) && "$LAST_DIAGNOSTIC_CLASS" =~ ^[A-Za-z0-9_]+$ ]]; then
    printf '{"sha":"%s","profile":"%s","test":"%s","status":"%s","diagnostic_class":"%s"}\n' \
      "$RECEIPT_SHA" "$profile" "$test_name" "$status" "$LAST_DIAGNOSTIC_CLASS" >> "$RECEIPT_FILE"
  else
    printf '{"sha":"%s","profile":"%s","test":"%s","status":"%s"}\n' \
      "$RECEIPT_SHA" "$profile" "$test_name" "$status" >> "$RECEIPT_FILE"
  fi
}

finish_receipt() {
  local rc=$?
  local raw_log
  for raw_log in "${RAW_LOGS[@]}"; do
    rm -f -- "$raw_log" || true
  done
  if [[ "$rc" -eq 0 ]]; then
    record_receipt "$PROFILE" "__profile__" "passed"
  else
    record_receipt "$PROFILE" "__profile__" "failed"
  fi
  trap - EXIT
  exit "$rc"
}

run_cargo() {
  # --locked makes the live lane execute the repository's resolved dependency
  # graph. --ignored is deliberately present only in this allow-listed runner.
  # Keep Cargo/test output in a private ephemeral temp file so provider errors
  # and tenant details never reach Actions logs or uploaded artifacts.
  # Cargo and its toolchain are supplied by the GitHub-hosted runner
  # image. A compromised host/toolchain or same-user TOCTOU is infrastructure
  # outside this repository verifier's trust boundary.
  local profile="$1" expected="$2"
  shift 2
  local log_file="${RECEIPT_DIR}/${profile}-${expected}.log"
  local raw_log
  raw_log="$(mktemp)"
  RAW_LOGS+=("$raw_log")
  record_receipt "$profile" "$expected" "started"
  local cargo_rc=0
  if cargo test --locked "$@" "$expected" -- --ignored --nocapture >"$raw_log" 2>&1; then
    :
  else
    cargo_rc=$?
  fi
  if [[ "$cargo_rc" -ne 0 ]]; then
    # The classifier reads private output but emits only a bounded diagnostic
    # category, never the provider body, source line, URL, or test payload.
    LAST_DIAGNOSTIC_CLASS="$(python3 scripts/verify_real_ignored_harnesses.py --classify-failure "$raw_log")"
    if [[ ! "$LAST_DIAGNOSTIC_CLASS" =~ ^(rustc_E[0-9]{4}|rust_compile_error|provider_http_[1-5][0-9]{2}|network_connection_refused|network_timeout|network_dns_failure|test_panic|test_assertion_failure|unclassified_failure)$ ]]; then
      LAST_DIAGNOSTIC_CLASS="unclassified_failure"
    fi
    record_receipt "$profile" "$expected" "failed"
    printf 'sha=%s profile=%s test=%s status=failed diagnostic_class=%s\n' \
      "$RECEIPT_SHA" "$profile" "$expected" "$LAST_DIAGNOSTIC_CLASS" > "$log_file"
    rm -f -- "$raw_log"
    return "$cargo_rc"
  fi

  # Cargo exits zero for an empty filter. Require exactly one matching `ok`
  # line so a stale selector can never produce a false green receipt.
  local passed
  passed="$(awk -v target="$expected" '$1 == "test" && $NF == "ok" && ($2 == target || $2 ~ ("::" target "$")) { count++ } END { print count + 0 }' "$raw_log")"
  if [[ "$passed" != "1" ]]; then
    LAST_DIAGNOSTIC_CLASS="expected_test_not_discovered"
    record_receipt "$profile" "$expected" "not-discovered"
    printf 'sha=%s profile=%s test=%s status=not-discovered diagnostic_class=%s\n' \
      "$RECEIPT_SHA" "$profile" "$expected" "$LAST_DIAGNOSTIC_CLASS" > "$log_file"
    printf 'error: expected exactly one passing ignored test named %s; observed %s\n' \
      "$expected" "$passed" >&2
    rm -f -- "$raw_log"
    return 3
  fi
  record_receipt "$profile" "$expected" "passed"
  printf 'sha=%s profile=%s test=%s status=passed\n' \
    "$RECEIPT_SHA" "$profile" "$expected" > "$log_file"
  rm -f -- "$raw_log"
}

preflight_d1() {
  # D1 integration tests use only the D1 HTTP adapter and must not depend on
  # credentials or resources owned by the separate R2 profile.
  require_env CLOUDFLARE_ACCOUNT_ID CF_API_TOKEN D1_DATABASE_ID
}

preflight_r2() {
  require_env \
    CLOUDFLARE_ACCOUNT_ID CF_API_TOKEN D1_DATABASE_ID \
    R2_S3_ENDPOINT R2_S3_ACCESS_KEY_ID R2_S3_SECRET_ACCESS_KEY \
    R2_TEST_BUCKET
  require_https R2_S3_ENDPOINT
  [[ "$R2_TEST_BUCKET" == *-staging ]] || \
    die "R2_TEST_BUCKET must be a dedicated *-staging bucket"
}

preflight_stripe() {
  # The Stripe tests route through the HuGR wallet broker. Requiring the
  # test-only reference prevents a manually dispatched run from accidentally
  # pointing at a live-mode wallet credential.
  require_env \
    HUGR_WALLET_BASE HUGR_WALLET_TOKEN HUGR_STRIPE_REF \
    STRIPE_AUTH_MODE STRIPE_PRICE_ID_STARTER GITHUB_RUN_ID
  [[ "$GITHUB_RUN_ID" =~ ^[0-9]{1,20}$ ]] || \
    die "GITHUB_RUN_ID must be a bounded numeric run selector"
  [[ "$GITHUB_RUN_ID" =~ [1-9] ]] || \
    die "GITHUB_RUN_ID must be nonzero"
  require_https HUGR_WALLET_BASE
  [[ "$HUGR_WALLET_TOKEN" == hugrw_* ]] || die "HUGR_WALLET_TOKEN must be a wallet-broker token"
  [[ "$HUGR_STRIPE_REF" == stripe-prod-test ]] || \
    die "HUGR_STRIPE_REF must be the provisioned Stripe test reference"
  [[ "$STRIPE_AUTH_MODE" == wallet-broker ]] || \
    die "STRIPE_AUTH_MODE must be wallet-broker for the real Stripe profile"
  [[ "$STRIPE_PRICE_ID_STARTER" == price_* ]] || \
    die "STRIPE_PRICE_ID_STARTER must be a Stripe price identifier"
}

preflight_neon() {
  require_env NEON_TEST_DSN
  [[ "$NEON_TEST_DSN" == postgresql://* ]] || die "NEON_TEST_DSN must be a PostgreSQL DSN"
}

run_d1() {
  run_cargo d1 d1_acquire_lock_then_held_then_release --package corelink-server --lib
  run_cargo d1 d1_dpa_and_active_subscription_reads --package corelink-server --lib
  run_cargo d1 d1_persist_free_active_does_not_count_as_a_subscription --package corelink-server --lib
  run_cargo d1 d1_http_blob_meta_round_trip --package corelink-server --lib
  run_cargo d1 d1_http_tenant_admin_lookup_round_trip --package corelink-server --lib
  run_cargo d1 d1_audit_write_blocking_records_oaudit_phase --package corelink-server --lib
}

run_r2() {
  run_cargo r2 r2_cas_list_durable_audit_failure_precedes_storage --package corelink-server --lib
  run_cargo r2 storage_r2_round_trip --package corelink-server --lib
  run_cargo r2 cas_idempotent_rewrite_reports_durable_false --package corelink-server --lib
  run_cargo r2 delete_if_present_credits_size_once_then_none --package corelink-server --lib
  run_cargo r2 r2_cas_exists_batch_fails_closed_on_bad_audit_creds --package corelink-server --lib
}

run_stripe() {
  run_cargo stripe live_create_customer --package corelink-stripe-real --features live-integration --test live_integration
  run_cargo stripe live_get_customer_404 --package corelink-stripe-real --features live-integration --test live_integration
  run_cargo stripe live_create_checkout_session_starter --package corelink-stripe-real --features live-integration --test live_integration
  run_cargo stripe live_idempotent_checkout_returns_same_session --package corelink-stripe-real --features live-integration --test live_integration
  run_cargo stripe live_billing_portal_session --package corelink-stripe-real --features live-integration --test live_integration
  run_cargo stripe live_authentication_failure_bad_token --package corelink-stripe-real --features live-integration --test live_integration
  python3 scripts/verify_stripe_harness_cleanup_receipt.py "$RECEIPT_DIR/cleanup.jsonl" "$GITHUB_RUN_ID"
}

run_neon() {
  # The five ignored tests are compiled only with neon-real; no PAT or D1
  # credential is inherited by this profile.
  run_cargo neon sync_chunk_persists_rows_against_live_postgres --package corelink-audit-chain --features neon-real --test neon_shadow_real
  run_cargo neon sync_chunk_is_idempotent_on_replay --package corelink-audit-chain --features neon-real --test neon_shadow_real
  run_cargo neon aggregate_event_count_against_live_postgres --package corelink-audit-chain --features neon-real --test neon_shadow_real
  run_cargo neon aggregate_timeline_against_live_postgres --package corelink-audit-chain --features neon-real --test neon_shadow_real
  run_cargo neon rls_policy_isolates_tenants_against_live_postgres --package corelink-audit-chain --features neon-real --test neon_shadow_real
}

case "$PROFILE" in
  d1|r2|stripe|neon|all) ;;
  *)
    usage
    # An empty/unknown selector must never fall through to a broad
    # `cargo test --ignored` invocation. In particular, `seed` is not a
    # supported selector.
    die "unknown harness profile: ${PROFILE:-<empty>}"
    ;;
esac

[[ "$RECEIPT_SHA" =~ ^[0-9a-f]{40}$ ]] || \
  die "GITHUB_SHA must be the exact 40-character Git commit SHA"

mkdir -p "$RECEIPT_DIR"
: > "$RECEIPT_FILE"
cp scripts/real-ignored-harness-manifest.json "$RECEIPT_DIR/manifest.json"
trap finish_receipt EXIT

case "$PROFILE" in
  d1) preflight_d1; run_d1 ;;
  r2) preflight_r2; run_r2 ;;
  stripe) preflight_stripe; run_stripe ;;
  neon) preflight_neon; run_neon ;;
  all)
    # IMPORTANT: every preflight is side-effect-free. Keep this complete block
    # before the first run_* call: a missing late credential must not allow an
    # earlier real D1/R2/Stripe mutation to happen.
    preflight_d1
    preflight_r2
    preflight_stripe
    preflight_neon
    run_d1
    run_r2
    run_stripe
    run_neon
    ;;
esac
