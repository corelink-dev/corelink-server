//! Fail-closed classification of every tenant-keyed D1 table.
//!
//! Keeping the five classification buckets and their completeness checks in
//! one module makes the erase/retain ownership contract independently
//! reviewable while the adapter implementation owns the D1 operations.

use super::{
    CAS_PLANE_OWNED, NAMESPACE_TABLES, RETAIN_SET, SPECIAL_ERASE_TABLES, TENANT_ID_TABLES,
};

/// The five mutually-exclusive classification buckets every tenant-keyed
/// table must land in exactly once.
pub(super) const CLASSIFICATION_SETS: &[(&str, &[&str])] = &[
    ("erase:tenant_id", TENANT_ID_TABLES),
    ("erase:namespace", NAMESPACE_TABLES),
    ("retain", RETAIN_SET),
    ("cas-plane-owned", CAS_PLANE_OWNED),
    ("special", SPECIAL_ERASE_TABLES),
];

/// Number of classification buckets a table appears in (must be exactly 1).
pub(super) fn classification_count(table: &str) -> usize {
    CLASSIFICATION_SETS
        .iter()
        .filter(|(_, set)| set.contains(&table))
        .count()
}

/// Return every table whose registry classification is not exactly one
/// bucket. Kept parameterized so the fail-closed contract can be exercised
/// with an injected unknown table in a unit test; production passes the
/// compile-time registry below.
fn classification_gaps<'a>(tables: &[&'a str]) -> Vec<(&'a str, usize)> {
    tables
        .iter()
        .map(|t| (*t, classification_count(t)))
        .filter(|(_, count)| *count != 1)
        .collect()
}

/// Fail-closed completeness gate (the load-bearing CF-1 fix): every
/// tenant-keyed table must be classified into EXACTLY ONE bucket. Returns an
/// error for every unclassified (`0`) or ambiguously multi-classified (`>1`)
/// table. This is intentionally always-on: a release build must not erase or
/// verify against a partial registry and then attest success.
pub(super) fn ensure_classification(tables: &[&str]) -> Result<(), String> {
    let gaps = classification_gaps(tables);
    if gaps.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "CF-1: DSR erase-set classification is incomplete/ambiguous; refusing to act: {gaps:?}"
        ))
    }
}

/// Returns `(table, count)` for every gap in the production registry. Empty
/// means the classification is total and disjoint. The runtime gate above is
/// the source of truth; this helper remains available to focused unit tests.
#[cfg(test)]
pub(super) fn unclassified_tenant_keyed_tables() -> Vec<(&'static str, usize)> {
    classification_gaps(super::registry::ALL_TENANT_KEYED_TABLES)
}
