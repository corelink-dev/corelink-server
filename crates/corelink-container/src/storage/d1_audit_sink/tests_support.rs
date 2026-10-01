//! Shared fixtures for the `d1_audit_sink` test modules.
//!
//! Every sibling test file needs either a sink or the env that builds one.
//! The fixtures live here rather than in one of the siblings so that no test
//! file looks load-bearing for the others when it is only a neighbour.
//!
//! `stub_env` is built by struct literal on purpose: this crate forbids the
//! parallel-test `set_var` race, so no PROCESS ENV is mutated to construct it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]

use super::*;
use crate::storage::StorageEnv;

/// A stub, fully-populated `StorageEnv` — built by struct literal (fields
/// are `pub(crate)`) so no PROCESS ENV is mutated (this crate forbids the
/// parallel-test `set_var` race — see `routes/residency.rs`).
pub(super) fn stub_env() -> StorageEnv {
    StorageEnv {
        r2_endpoint: "https://acct.r2.cloudflarestorage.com".to_owned(),
        r2_access_key_id: "ak".to_owned(),
        r2_secret_access_key: "sk".to_owned(),
        r2_session_token: None,
        cloudflare_account_id: "acct123".to_owned(),
        cf_api_token: "tok".to_owned(),
        d1_database_id: "db456".to_owned(),
    }
}

/// A `D1AuditOutboxSink` over a client built from [`stub_env`]. The
/// credentials are stubs, so any test using this must stay off the network
/// (or assert on a FAILING call — see `tests_phase_attribution`).
pub(super) fn stub_sink() -> D1AuditOutboxSink {
    D1AuditOutboxSink::new(
        Arc::new(D1HttpClient::new(&stub_env()).expect("client builds")),
        "corelink/cas",
    )
}

/// One fixed, well-formed 64-hex CAS digest — the tests that need two rows
/// to collide need them to carry the SAME digest.
pub(super) const DIGEST_A: &str =
    "deadbeef00000000000000000000000000000000000000000000000000000001";
