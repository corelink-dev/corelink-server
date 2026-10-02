// Regression net for the reserve→commit→release decorators (cluster C).
use super::testing::{InMemoryByteStore, Row};
use super::*;
use corelink_handler_cas::{
    CasDeleteHandler, CasDeleteRequest, CasHandlerError, CasReadHandler, CasReadRequest,
    CasWriteHandler, CasWriteRequest, CasWriteResponse, InMemoryAuditSink, InMemoryCasHandler,
    InMemorySliObserver,
};

const REGION: &str = "iad";

#[test]
fn cas_lock_shards_avoid_false_serialization_for_220_distinct_keys() {
    use std::collections::HashSet;

    const { assert!(CAS_LOCK_SHARDS >= 32_768) };
    let tenant = "b103-tenant";
    let keys = (1..=220).map(|n| format!("{n:064x}")).collect::<Vec<_>>();
    let first_key = keys.first().expect("the test population is non-empty");
    let shards = keys
        .iter()
        .map(|key| cas_lock_shard_index(tenant, key))
        .collect::<HashSet<_>>();

    assert_eq!(
        cas_lock_shard_index(tenant, first_key),
        cas_lock_shard_index(tenant, first_key),
        "the same tenant/key pair must always serialize on one lock"
    );
    assert!(
        shards.len() >= 210,
        "220 independent content hashes should not collapse onto a small number of locks; got {} unique shards",
        shards.len()
    );
}

/// AC-plane fixtures (rt-nuclear C2 sibling): the AC `update`-vs-`delete`
/// write-vs-delete byte-accounting race, mirroring the CAS suite below.
mod ac {
    use super::{
        ByteAccountant, ByteStore, InMemoryByteStore, MutationLiabilityState, Row, REGION,
    };
    use corelink_handler_ac::{
        AcDeleteHandler, AcDeleteRequest, AcLookupHandler, AcLookupRequest, AcUpdateHandler,
        AcUpdateRequest, InMemoryAcHandler, InMemoryAuditSink, InMemorySliObserver,
    };
    use std::sync::Arc;

    use crate::byte_accounting::AccountingAcHandler;

    /// Build an `AccountingAcHandler` over a fresh InMemory AC backing + a
    /// byte store, returning the decorator, the underlying handler (to inspect
    /// stored entries), and the byte store (to assert the counter). Mirrors
    /// the CAS `cas_fixture` below.
    fn ac_fixture(
        seed: Option<(&str, Row)>,
    ) -> (
        Arc<AccountingAcHandler>,
        Arc<InMemoryAcHandler>,
        Arc<InMemoryByteStore>,
    ) {
        let audit = Arc::new(InMemoryAuditSink::new());
        let sli = Arc::new(InMemorySliObserver::new());
        let inner = Arc::new(InMemoryAcHandler::new(audit, sli));
        let store = Arc::new(InMemoryByteStore::new());
        if let Some((tenant, row)) = seed {
            store.seed(tenant, REGION, row);
        }
        let acc = Arc::new(ByteAccountant::new(
            store.clone() as Arc<dyn ByteStore>,
            REGION.to_owned(),
        ));
        let dec = Arc::new(AccountingAcHandler::new(
            inner.clone() as Arc<dyn AcUpdateHandler>,
            inner.clone() as Arc<dyn AcDeleteHandler>,
            acc,
        ));
        (dec, inner, store)
    }

    /// Is the AC key present on disk in the inner handler?
    fn is_present(inner: &InMemoryAcHandler, tenant: &str, digest: &str) -> bool {
        inner
            .lookup(AcLookupRequest::new(tenant, digest, "p", tenant, 9))
            .is_ok()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_update_vs_delete_same_key_nets_to_truth() {
        // rt-nuclear C2 sibling (AC plane): an AC `delete` of key K (size L)
        // racing a concurrent `update` of the SAME (tenant, action_digest)
        // must leave `bytes_used` EQUAL to the on-disk reality — L when the
        // update wins (entry present), 0 when the delete wins (entry absent).
        // Before the AC-plane lock, the delete's release(L) and the update's
        // independent reserve/release could interleave so the two did NOT net
        // to the true on-disk total, UNDER-counting `bytes_used` by up to L
        // (storage-quota evasion). The per-(tenant, action_digest) decorator
        // lock now serializes the full reserve/commit/release of UPDATE against
        // the full delete/release of DELETE for one key, so the counter always
        // tracks the truth (and never underflows).
        //
        // The InMemory AC handler is content-addressed: re-`update` with the
        // SAME body is an idempotent no-op when the entry is present (durable =
        // false ⇒ the decorator rolls the reservation back) but a durable
        // re-insert once the delete has removed it (⇒ accrues L). Either way
        // the lock makes the (counter == on-disk) invariant hold each race.
        let digest = "a".repeat(64);
        let body = b"ac-race-the-same-key".to_vec();
        let n = body.len() as i64;
        for iter in 0..200u64 {
            // Fresh fixture per iteration with the entry already present + the
            // counter already reflecting it (the on-disk truth at the start).
            let (dec, inner, store) = ac_fixture(Some(("t", Row { used: n, quota: 0 })));
            // Seed the entry on disk so a `delete` actually reclaims `n` bytes.
            dec.update(
                AcUpdateRequest::new("t", digest.clone(), body.clone(), "p", "t", iter)
                    .with_storage_quota_bytes(Some(0)),
            )
            .expect("seed update");
            // The seed update was a fresh insert (durable), so it accrued
            // another `n`; normalise the counter back to the single-copy
            // on-disk truth so the race starts from (counter == on-disk).
            store.seed("t", REGION, Row { used: n, quota: 0 });

            let du = dec.clone();
            let dd = dec.clone();
            let dgu = digest.clone();
            let dgd = digest.clone();
            let bu = body.clone();
            // Concurrent UPDATE and DELETE of the SAME (tenant, action_digest).
            let tu = tokio::spawn(async move {
                let _ = du.update(
                    AcUpdateRequest::new("t", dgu, bu, "p", "t", 1)
                        .with_storage_quota_bytes(Some(0)),
                );
            });
            let td = tokio::spawn(async move {
                let _ = dd.delete(AcDeleteRequest::new("t", dgd, "p", "t", 2));
            });
            tu.await.unwrap();
            td.await.unwrap();

            // The on-disk truth after the race: is the entry present?
            let present = is_present(&inner, "t", &digest);
            let counter = store.used("t", REGION);
            let expected = if present { n } else { 0 };
            assert_eq!(
                    counter, expected,
                    "iter {iter}: bytes_used ({counter}) must equal the on-disk truth \
                     ({expected}; present={present}) — AC update-vs-delete accounting must net exactly"
                );
            assert!(
                counter >= 0,
                "iter {iter}: bytes_used must never underflow below zero"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn distinct_keys_update_and_delete_stay_concurrent() {
        // The lock must serialize only the SAME (tenant, action_digest): an
        // update of key A and a delete of key B must both proceed and account
        // independently (different shards / no false dependency).
        let (dec, _inner, store) = ac_fixture(None);
        let dig_a = "a".repeat(64);
        let dig_b = "b".repeat(64);
        let ba = b"ac-key-a-bytes".to_vec();
        let bb = b"ac-key-b-different".to_vec();
        let na = ba.len() as i64;
        let nb = bb.len() as i64;
        // Pre-seed key B so its delete reclaims real bytes; counter reflects B.
        dec.update(
            AcUpdateRequest::new("t", dig_b.clone(), bb, "p", "t", 1)
                .with_storage_quota_bytes(Some(0)),
        )
        .expect("seed B");
        assert_eq!(store.used("t", REGION), nb, "seed of B accrues B's bytes");

        let du = dec.clone();
        let dd = dec.clone();
        let tu = tokio::spawn(async move {
            du.update(
                AcUpdateRequest::new("t", dig_a, ba, "p", "t", 2).with_storage_quota_bytes(Some(0)),
            )
        });
        let td =
            tokio::spawn(async move { dd.delete(AcDeleteRequest::new("t", dig_b, "p", "t", 3)) });
        tu.await.unwrap().expect("update A");
        td.await.unwrap().expect("delete B");

        // Net effect: +na (A written) and −nb (B deleted) over the seeded nb →
        // exactly na. Distinct keys never block each other and account cleanly.
        assert_eq!(
            store.used("t", REGION),
            na,
            "distinct-key update + delete must account independently (only A's bytes remain)"
        );
    }

    #[derive(Debug)]
    struct PublishedThenAuditFails;

    impl AcUpdateHandler for PublishedThenAuditFails {
        fn update(
            &self,
            _req: AcUpdateRequest,
        ) -> Result<corelink_handler_ac::AcUpdateResponse, corelink_handler_ac::AcHandlerError> {
            Err(corelink_handler_ac::AcHandlerError::AuditFailed(
                "injected post-publish audit failure".to_owned(),
            ))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_publish_ac_error_retains_reconcilable_liability() {
        let store = Arc::new(InMemoryByteStore::new());
        let accountant = Arc::new(ByteAccountant::new(
            store.clone() as Arc<dyn ByteStore>,
            REGION.to_owned(),
        ));
        let delete_inner = Arc::new(InMemoryAcHandler::new(
            Arc::new(InMemoryAuditSink::new()),
            Arc::new(InMemorySliObserver::new()),
        ));
        let decorator = AccountingAcHandler::new(
            Arc::new(PublishedThenAuditFails) as Arc<dyn AcUpdateHandler>,
            delete_inner as Arc<dyn AcDeleteHandler>,
            accountant,
        );
        let digest = "f".repeat(64);
        let body = b"published-before-audit".to_vec();
        assert!(decorator
            .update(
                AcUpdateRequest::new("t", digest.clone(), body.clone(), "p", "t", 1)
                    .with_storage_quota_bytes(Some(1_000_000)),
            )
            .is_err());
        assert_eq!(store.used("t", REGION), body.len() as i64);
        let liability = store
            .liability("t", REGION, &digest)
            .expect("ambiguous AC failure must remain durable for reconciliation");
        assert_eq!(liability.state, MutationLiabilityState::Unknown);
        assert!(liability.intent_id.is_some());
    }
}

/// Build an `AccountingCasHandler` over a fresh InMemory CAS backing + a byte
/// store, returning the decorator, the underlying handler (to inspect stored
/// blobs), and the byte store (to assert the counter).
fn cas_fixture(
    seed: Option<(&str, Row)>,
) -> (
    Arc<AccountingCasHandler>,
    Arc<InMemoryCasHandler>,
    Arc<InMemoryByteStore>,
) {
    let audit = Arc::new(InMemoryAuditSink::new());
    let sli = Arc::new(InMemorySliObserver::new());
    let inner = Arc::new(InMemoryCasHandler::new(audit, sli));
    let store = Arc::new(InMemoryByteStore::new());
    if let Some((tenant, row)) = seed {
        store.seed(tenant, REGION, row);
    }
    let acc = Arc::new(ByteAccountant::new(
        store.clone() as Arc<dyn ByteStore>,
        REGION.to_owned(),
    ));
    let dec = Arc::new(AccountingCasHandler::new(
        inner.clone() as Arc<dyn CasWriteHandler>,
        inner.clone() as Arc<dyn CasDeleteHandler>,
        acc,
    ));
    (dec, inner, store)
}

/// CAA-360 #9 digest validator wants a real content hash; the InMemory
/// handler accepts any (tenant, hash) it is given (it does not hash-verify),
/// so we use an arbitrary 64-hex string.
fn hash_for(bytes: &[u8]) -> String {
    corelink_handler_cas::handler::fake_hash(bytes)
}

#[derive(Debug, Clone, Copy)]
enum EffectfulFailure {
    NotWritten,
    Committed,
    Pending(uuid::Uuid),
    Unknown,
}

#[derive(Debug)]
struct EffectfulCas(EffectfulFailure);

impl CasWriteHandler for EffectfulCas {
    fn write(&self, _req: CasWriteRequest) -> Result<CasWriteResponse, CasHandlerError> { Err(CasHandlerError::Internal("injected write failure".to_owned())) }

    fn write_with_effect(
        &self,
        _req: CasWriteRequest,
    ) -> Result<CasWriteResponse, corelink_handler_cas::CasWriteFailure> {
        match self.0 {
            EffectfulFailure::NotWritten => Err(corelink_handler_cas::CasWriteFailure::not_written(CasHandlerError::Internal("injected write failure".to_owned()))),
            EffectfulFailure::Committed => Err(corelink_handler_cas::CasWriteFailure::committed(CasHandlerError::Internal("injected write failure".to_owned()))),
            EffectfulFailure::Pending(intent_id) => Err(corelink_handler_cas::CasWriteFailure::pending(CasHandlerError::Internal("injected write failure".to_owned()), intent_id)),
            EffectfulFailure::Unknown => Err(corelink_handler_cas::CasWriteFailure::unknown(CasHandlerError::Internal("injected write failure".to_owned()))),
        }
    }
}

fn effectful_fixture_with_accountant(
    effect: EffectfulFailure,
) -> (Arc<AccountingCasHandler>, Arc<InMemoryByteStore>, Arc<ByteAccountant>) {
    let audit = Arc::new(InMemoryAuditSink::new());
    let sli = Arc::new(InMemorySliObserver::new());
    let delete_inner = Arc::new(InMemoryCasHandler::new(audit, sli));
    let store = Arc::new(InMemoryByteStore::new());
    let accountant = Arc::new(ByteAccountant::new(
        store.clone() as Arc<dyn ByteStore>,
        REGION.to_owned(),
    ));
    let dec = Arc::new(AccountingCasHandler::new(
            Arc::new(EffectfulCas(effect)) as Arc<dyn CasWriteHandler>,
            delete_inner as Arc<dyn CasDeleteHandler>,
            accountant.clone(),
        ));
    (dec, store, accountant)
}

fn effectful_fixture(effect: EffectfulFailure) -> (Arc<AccountingCasHandler>, Arc<InMemoryByteStore>) {
    let (dec, store, _accountant) = effectful_fixture_with_accountant(effect);
    (dec, store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_cap_write_returns_402_sentinel_and_leaves_no_blob() {
    // Tenant AT a 4-byte cap; a larger write must be refused at the
    // RESERVATION (BEFORE the inner write), so NO blob is stored.
    let (dec, inner, store) = cas_fixture(Some(("t-cap", Row { used: 4, quota: 4 })));
    let body = b"way-over-the-cap".to_vec();
    let hash = hash_for(&body);
    let err = dec
        .write(
            CasWriteRequest::new("t-cap", hash.clone(), body, "p", "t-cap", 1)
                .with_storage_quota_bytes(Some(4)),
        )
        .expect_err("over-cap write must be refused");
    match err {
        corelink_handler_cas::CasHandlerError::Internal(ref m) => {
            assert!(
                m.starts_with(OVER_CAP_SENTINEL),
                "must carry the over-cap sentinel: {m}"
            );
        }
        other => panic!("expected over-cap Internal, got {other:?}"),
    }
    // The reservation was refused, so the inner store never ran: NO blob.
    let read = inner.read(CasReadRequest::new("t-cap", hash, "p", "t-cap", 2));
    assert!(
        matches!(
            read,
            Err(corelink_handler_cas::CasHandlerError::NotFound { .. })
        ),
        "an over-cap write must leave NO blob in storage (reserve-before-commit)"
    );
    // Counter unchanged (the atomic reservation did not move it).
    assert_eq!(
        store.used("t-cap", REGION),
        4,
        "over-cap reservation must not move the counter"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_namespace_write_uses_authenticated_tenant_quota() {
    // A public physical write must seed and charge the authenticated real
    // tenant, not an `_public` quota row.
    let (dec, inner, store) = cas_fixture(None);
    let body = vec![b'p'; 512];
    let n = body.len() as i64;
    let hash = hash_for(&body);
    dec.write(
        CasWriteRequest::for_public_namespace(
            "tenant-real",
            hash.clone(),
            body,
            "brew-adapter-host",
            1,
        )
        .with_storage_quota_bytes(Some(1024)),
    )
    .expect("a public write within the real tenant cap must succeed");
    assert_eq!(
        store.used("tenant-real", REGION),
        n,
        "public bytes must accrue against the authenticated tenant"
    );
    let stored = inner
        .read(CasReadRequest::new(
            crate::adapter_cache::PUBLIC_NAMESPACE,
            hash,
            "brew-adapter-host",
            crate::adapter_cache::PUBLIC_NAMESPACE,
            2,
        ))
        .expect("public CAS object must round-trip under its physical namespace");
    assert_eq!(stored.bytes, vec![b'p'; 512]);

    let second = vec![b'p'; 512];
    let second_hash = hash_for(&second);
    let response = dec
        .write(
            CasWriteRequest::for_public_namespace(
                "tenant-other",
                second_hash,
                second,
                "pip-adapter-host",
                3,
            )
            .with_storage_quota_bytes(Some(1024)),
        )
        .expect("a second tenant's identical public write must be a dedup no-op");
    assert!(!response.durable, "shared physical key must deduplicate");
    assert_eq!(store.used("tenant-real", REGION), n);
    assert_eq!(
        store.used("tenant-other", REGION),
        0,
        "dedup rollback must release the second tenant's reservation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_namespace_write_respects_authenticated_tenant_quota() {
    // A public physical write cannot bypass a finite cap on the authenticated
    // tenant merely by selecting the shared physical namespace.
    let (dec, _inner, store) = cas_fixture(Some(("tenant-real", Row { used: 0, quota: 1 })));
    let body = vec![b'q'; 4096];
    let hash = hash_for(&body);
    let err = dec
        .write(
            CasWriteRequest::for_public_namespace("tenant-real", hash, body, "npm-adapter-host", 1)
                .with_storage_quota_bytes(Some(1)),
        )
        .expect_err("a public write must be capped for the real tenant");
    assert!(matches!(err, CasHandlerError::Internal(ref m) if m.starts_with(OVER_CAP_SENTINEL)));
    assert_eq!(
        store.used("tenant-real", REGION),
        0,
        "an over-cap public write must not charge or commit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tenant_finite_cap_still_enforced_alongside_public() {
    // Guard: a real tenant's finite cap remains enforced for both private
    // and public physical writes.
    let (dec, inner, store) = cas_fixture(Some(("t-real", Row { used: 4, quota: 4 })));
    let body = b"over-the-real-cap".to_vec();
    let hash = hash_for(&body);
    let err = dec
        .write(
            CasWriteRequest::new("t-real", hash.clone(), body, "p", "t-real", 1)
                .with_storage_quota_bytes(Some(4)),
        )
        .expect_err("a real tenant's over-cap write must still be refused");
    match err {
        corelink_handler_cas::CasHandlerError::Internal(ref m) => {
            assert!(m.starts_with(OVER_CAP_SENTINEL), "over-cap sentinel: {m}");
        }
        other => panic!("expected over-cap Internal, got {other:?}"),
    }
    let read = inner.read(CasReadRequest::new("t-real", hash, "p", "t-real", 2));
    assert!(
        matches!(
            read,
            Err(corelink_handler_cas::CasHandlerError::NotFound { .. })
        ),
        "the real tenant's over-cap write must leave no blob"
    );
    assert_eq!(store.used("t-real", REGION), 4, "counter unchanged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_cap_write_accrues_then_delete_releases() {
    let (dec, _inner, store) = cas_fixture(None);
    let body = b"hello-bytes".to_vec();
    let n = body.len() as i64;
    let hash = hash_for(&body);
    // Fresh tenant with a real resolved cap — seeds the row with the cap.
    dec.write(
        CasWriteRequest::new("t1", hash.clone(), body, "p", "t1", 1)
            .with_storage_quota_bytes(Some(1_000_000)),
    )
    .expect("write");
    assert_eq!(
        store.used("t1", REGION),
        n,
        "a durable write must accrue its bytes"
    );
    // DELETE must RELEASE the reclaimed bytes so the counter drops to 0.
    dec.delete(CasDeleteRequest::new("t1", hash, "p", "t1", 2))
        .expect("delete");
    assert_eq!(
        store.used("t1", REGION),
        0,
        "a delete must decrement bytes_used by the reclaimed size"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_unlimited_tenant_accrues_unbounded() {
    // (c) A genuine unlimited-tier tenant (cap signalled as `Some(0)`)
    // accrues without bound: a fresh row is seeded with the `0` sentinel and
    // a large write far past any finite cap still succeeds + is counted.
    let (dec, _inner, store) = cas_fixture(None);
    let body = vec![b'x'; 4096];
    let n = body.len() as i64;
    let hash = hash_for(&body);
    dec.write(
        CasWriteRequest::new("t-unl", hash, body, "p", "t-unl", 1)
            .with_storage_quota_bytes(Some(0)),
    )
    .expect("unlimited write must succeed");
    assert_eq!(
        store.used("t-unl", REGION),
        n,
        "unlimited tenant still accrues bytes_used"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_tenant_no_cap_header_fails_closed_no_blob() {
    // (d) at the decorator: a fresh tenant whose request carries NO resolved
    // cap (`None`) must be refused (indeterminate → 503 sentinel) with NO
    // blob stored — absence is never treated as unlimited.
    let (dec, inner, store) = cas_fixture(None);
    let body = b"no-cap-known".to_vec();
    let hash = hash_for(&body);
    let err = dec
        .write(CasWriteRequest::new(
            "t-nocap",
            hash.clone(),
            body,
            "p",
            "t-nocap",
            1,
        ))
        .expect_err("indeterminate-cap write must be refused");
    match err {
        corelink_handler_cas::CasHandlerError::Internal(ref m) => {
            assert!(
                m.starts_with(ACCT_UNAVAILABLE_SENTINEL),
                "must carry the accounting-unavailable (fail-closed/503) sentinel: {m}"
            );
        }
        other => panic!("expected fail-closed Internal, got {other:?}"),
    }
    let read = inner.read(CasReadRequest::new("t-nocap", hash, "p", "t-nocap", 2));
    assert!(
        matches!(
            read,
            Err(corelink_handler_cas::CasHandlerError::NotFound { .. })
        ),
        "an indeterminate-cap write must leave NO blob (fail-closed before commit)"
    );
    assert_eq!(
        store.used("t-nocap", REGION),
        0,
        "fail-closed must create no row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotent_rewrite_does_not_double_count() {
    let (dec, _inner, store) = cas_fixture(None);
    let body = b"same-bytes".to_vec();
    let n = body.len() as i64;
    let hash = hash_for(&body);
    dec.write(
        CasWriteRequest::new("t1", hash.clone(), body.clone(), "p", "t1", 1)
            .with_storage_quota_bytes(Some(1_000_000)),
    )
    .expect("first write");
    // Second identical write is idempotent (`durable == false`) → the
    // decorator rolls the reservation back, so the counter stays at n.
    dec.write(
        CasWriteRequest::new("t1", hash, body, "p", "t1", 2)
            .with_storage_quota_bytes(Some(1_000_000)),
    )
    .expect("second write");
    assert_eq!(
        store.used("t1", REGION),
        n,
        "an idempotent re-write must NOT double-count (reservation rolled back)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_inner_write_retains_and_owns_reservation() {
    let (dec, store) = effectful_fixture(EffectfulFailure::Unknown);
    let body = b"abc".to_vec();
    let hash = hash_for(&body);
    let bytes = body.len() as i64;
    let err = dec.write(
        CasWriteRequest::new("t", hash.clone(), body, "p", "t", 1)
            .with_storage_quota_bytes(Some(1_000_000)),
    );
    assert!(err.is_err());
    assert_eq!(
        store.used("t", REGION),
        bytes,
        "unknown write outcome must retain the reservation"
    );
    let liability = store
        .liability("t", REGION, &hash)
        .expect("unknown outcome must be durably owned");
    assert_eq!(liability.state, MutationLiabilityState::Unknown);
    assert!(liability.intent_id.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_written_effect_refunds_reservation() {
    let (dec, store, accountant) = effectful_fixture_with_accountant(EffectfulFailure::NotWritten);
    let body = b"safe-refund".to_vec();
    let hash = hash_for(&body);
    let err = dec.write(
        CasWriteRequest::new("t", hash.clone(), body, "p", "t", 1)
            .with_storage_quota_bytes(Some(1_000_000)),
    );
    assert!(err.is_err());
    assert_eq!(store.used("t", REGION), 0, "only NotWritten refunds");
    assert_eq!(
        store.liability("t", REGION, &hash).expect("liability row").state,
        MutationLiabilityState::Released
    );
    assert_eq!(
        accountant
            .settle_mutation_liability(
                "t",
                &hash,
                MutationLiabilityResolution::NotWritten,
            )
            .await
            .expect("repeat settlement"),
        MutationLiabilitySettlement::AlreadySettled
    );
    assert_eq!(store.used("t", REGION), 0, "repeat settlement must not refund twice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_effect_retains_reservation() {
    let (dec, store) = effectful_fixture(EffectfulFailure::Committed);
    let body = b"already-durable".to_vec();
    let bytes = body.len() as i64;
    let hash = hash_for(&body);
    let failure = dec
        .write_with_effect(
            CasWriteRequest::new("t", hash.clone(), body, "p", "t", 1)
                .with_storage_quota_bytes(Some(1_000_000)),
        )
        .expect_err("committed write failure");
    assert_eq!(failure.effect, corelink_handler_cas::MutationEffect::Committed);
    assert_eq!(store.used("t", REGION), bytes, "committed effect retains bytes");
    assert_eq!(
        store.liability("t", REGION, &hash).expect("committed liability").state,
        MutationLiabilityState::Committed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_effect_persists_exact_intent_and_retains_reservation() {
    let intent_id = uuid::Uuid::new_v4();
    let (dec, store) = effectful_fixture(EffectfulFailure::Pending(intent_id));
    let body = b"pending-liability".to_vec();
    let bytes = body.len() as i64;
    let hash = hash_for(&body);
    let failure = dec
        .write_with_effect(
            CasWriteRequest::new("t", hash.clone(), body, "p", "t", 1)
                .with_storage_quota_bytes(Some(1_000_000)),
        )
        .expect_err("pending write failure");
    assert_eq!(
        failure.effect,
        corelink_handler_cas::MutationEffect::Pending { intent_id }
    );
    assert_eq!(store.used("t", REGION), bytes);
    let liability = store.liability("t", REGION, &hash).expect("pending liability");
    assert_eq!(liability.state, MutationLiabilityState::Pending);
    assert_eq!(liability.intent_id, Some(intent_id));
}

include!("b126_m2_test_3_1_part_02.rs");
