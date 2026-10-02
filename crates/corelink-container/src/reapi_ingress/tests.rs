//! Behavior coverage for the authenticated ingress boundary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panics surface as failures by design"
)]
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Debug)]
struct TestAuth(Result<(String, bool), AuthenticationFailure>);

#[async_trait]
impl IngressAuthenticator for TestAuth {
    async fn authenticate(&self, _bearer: &str) -> Result<(String, bool), AuthenticationFailure> {
        self.0.clone()
    }
}

#[derive(Debug)]
struct TestAdmission {
    result: Result<(), AdmissionFailure>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl IngressAdmission for TestAdmission {
    async fn admit(&self, _tenant_id: &str) -> Result<AdmissionLease, AdmissionFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.map(|()| AdmissionLease::test_only())
    }
}

#[derive(Debug)]
struct TestCapResolver;

#[async_trait]
impl crate::oci_cap::TenantCapResolver for TestCapResolver {
    async fn resolve_storage_cap(&self, _tenant_id: &str) -> Option<i64> {
        Some(0)
    }
}

#[test]
fn canonical_sha256_and_resource_names_are_shared_and_strict() {
    let digest = sha256_digest(b"corelink");
    assert_eq!(digest.len(), 64);
    assert!(validate_digest(&digest, 8).is_ok());
    assert!(validate_digest(&digest.to_ascii_uppercase(), 8).is_err());
    assert!(validate_digest(&digest, -1).is_err());
    let read =
        validate_blob_resource_name(&format!("tenant-a/blobs/{digest}/8"), "tenant-a").unwrap();
    assert_eq!(read.instance_name(), "tenant-a");
    assert_eq!(read.hash(), digest);
    assert_eq!(read.size_bytes(), 8);
    assert_eq!(read.upload_id(), None);
    let write = validate_blob_resource_name(
        &format!("tenant-a/uploads/00000000-0000-0000-0000-000000000001/blobs/{digest}/8"),
        "tenant-a",
    )
    .unwrap();
    assert_eq!(
        write.upload_id(),
        Some("00000000-0000-0000-0000-000000000001")
    );
    assert!(validate_blob_resource_name("_public/blobs/abcd/4", "tenant-a").is_err());
    assert!(validate_blob_resource_name("tenant-a/blobs/abcd/4/extra", "tenant-a").is_err());
    assert!(
        validate_blob_resource_name("tenant-a/uploads/not-a-uuid/blobs/abcd/4", "tenant-a")
            .is_err()
    );
}

#[tokio::test]
async fn denied_write_never_reaches_any_shared_storage_handler() {
    let touched = Arc::new(AtomicUsize::new(0));
    let ingress = ingress_for_test(Ok(("tenant-a".into(), false)), Ok(()), touched.clone());
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer placeholder".parse().unwrap());

    let error = ingress
        .authorize(&metadata, "tenant-a", Access::Write)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(touched.load(Ordering::SeqCst), 0);

    let read_only = ingress_for_test(Ok(("tenant-a".into(), false)), Ok(()), touched.clone());
    let admitted = read_only
        .authorize(&metadata, "tenant-a", Access::Read)
        .await
        .unwrap();
    assert_eq!(
        admitted
            .cas_write(&"a".repeat(64), 0, vec![])
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        admitted
            .ac_update(&"a".repeat(64), 0, vec![])
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(touched.load(Ordering::SeqCst), 0);
    assert!(!format!("{admitted:?}").contains("placeholder"));
}

#[tokio::test]
async fn auth_and_admission_failures_map_to_protocol_statuses() {
    let touched = Arc::new(AtomicUsize::new(0));
    let mut metadata = tonic::metadata::MetadataMap::new();
    let absent = ingress_for_test(Ok(("tenant-a".into(), true)), Ok(()), touched.clone());
    assert_eq!(
        absent
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    metadata.insert("authorization", "Basic placeholder".parse().unwrap());
    assert_eq!(
        absent
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    metadata.insert("authorization", "Bearer placeholder".parse().unwrap());

    let invalid = ingress_for_test(Err(AuthenticationFailure::Invalid), Ok(()), touched.clone());
    assert_eq!(
        invalid
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let backend = ingress_for_test(
        Err(AuthenticationFailure::Unavailable),
        Ok(()),
        touched.clone(),
    );
    assert_eq!(
        backend
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let exhausted = ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Err(AdmissionFailure::Exhausted),
        touched.clone(),
    );
    assert_eq!(
        exhausted
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    let unavailable = ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Err(AdmissionFailure::Unavailable),
        touched.clone(),
    );
    assert_eq!(
        unavailable
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(touched.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reserved_and_mismatched_instances_are_rejected_before_admission() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer placeholder".parse().unwrap());
    let touched = Arc::new(AtomicUsize::new(0));
    let ingress = ingress_for_test(Ok(("tenant-a".into(), true)), Ok(()), touched.clone());
    assert_eq!(
        ingress
            .authorize(&metadata, "_public", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        ingress
            .authorize(&metadata, "tenant-b", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(ingress.admission_calls.load(Ordering::SeqCst), 0);
    assert_eq!(touched.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_authorization_is_rejected_without_storage_access() {
    let touched = Arc::new(AtomicUsize::new(0));
    let ingress = ingress_for_test(Ok(("tenant-a".into(), true)), Ok(()), touched.clone());
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer bad header".parse().unwrap());
    assert_eq!(
        ingress
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(ingress.admission_calls.load(Ordering::SeqCst), 0);
    metadata.insert("authorization", "Bearer placeholder".parse().unwrap());
    metadata.append("authorization", "Bearer placeholder".parse().unwrap());
    assert_eq!(
        ingress
            .authorize(&metadata, "tenant-a", Access::Read)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(touched.load(Ordering::SeqCst), 0);
}

fn ingress_for_test(
    auth: Result<(String, bool), AuthenticationFailure>,
    admission: Result<(), AdmissionFailure>,
    storage_calls: Arc<AtomicUsize>,
) -> ReapiIngress {
    use corelink_handler_ac::{
        AcLookupRequest, AcLookupResponse, AcUpdateHandler, AcUpdateRequest, AcUpdateResponse,
    };
    use corelink_handler_cas::{
        CasReadRequest, CasReadResponse, CasWriteHandler, CasWriteRequest, CasWriteResponse,
    };

    #[derive(Debug)]
    struct CasRead(Arc<AtomicUsize>);
    impl CasReadHandler for CasRead {
        fn read(
            &self,
            _request: CasReadRequest,
        ) -> Result<CasReadResponse, corelink_handler_cas::CasHandlerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("denied ingress reached CAS read")
        }
    }
    #[derive(Debug)]
    struct CasWrite(Arc<AtomicUsize>);
    impl CasWriteHandler for CasWrite {
        fn write(
            &self,
            _request: CasWriteRequest,
        ) -> Result<CasWriteResponse, corelink_handler_cas::CasHandlerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("denied ingress reached CAS write")
        }
    }
    #[derive(Debug)]
    struct AcLookup(Arc<AtomicUsize>);
    impl AcLookupHandler for AcLookup {
        fn lookup(
            &self,
            _request: AcLookupRequest,
        ) -> Result<AcLookupResponse, corelink_handler_ac::AcHandlerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("denied ingress reached AC lookup")
        }
    }
    #[derive(Debug)]
    struct AcUpdate(Arc<AtomicUsize>);
    impl AcUpdateHandler for AcUpdate {
        fn update(
            &self,
            _request: AcUpdateRequest,
        ) -> Result<AcUpdateResponse, corelink_handler_ac::AcHandlerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("denied ingress reached AC update")
        }
    }

    let admission_calls = Arc::new(AtomicUsize::new(0));
    ReapiIngress {
        authenticator: Arc::new(TestAuth(auth)),
        admission: Arc::new(TestAdmission {
            result: admission,
            calls: admission_calls.clone(),
        }),
        cas_read: Arc::new(CasRead(storage_calls.clone())),
        cas_write: Arc::new(CasWrite(storage_calls.clone())),
        ac_lookup: Arc::new(AcLookup(storage_calls.clone())),
        ac_update: Arc::new(AcUpdate(storage_calls)),
        cap_resolver: Arc::new(TestCapResolver),
        admission_calls,
    }
}
#[derive(Debug, Clone)]
enum CasReadSpyOutcome {
    Response(CasReadResponse),
    NotFound {
        tenant: String,
        hash: String,
    },
    HashMismatch {
        claimed: String,
        actual: String,
    },
    CrossTenantDenied {
        caller: String,
        requested_tenant: String,
    },
    AuditFailed(String),
    ObjectTooLarge {
        actual_bytes: u64,
        limit_bytes: u64,
    },
    Internal(String),
}

impl CasReadSpyOutcome {
    fn from_result(result: Result<CasReadResponse, corelink_handler_cas::CasHandlerError>) -> Self {
        match result {
            Ok(response) => Self::Response(response),
            Err(corelink_handler_cas::CasHandlerError::NotFound { tenant, hash }) => {
                Self::NotFound { tenant, hash }
            }
            Err(corelink_handler_cas::CasHandlerError::HashMismatch { claimed, actual }) => {
                Self::HashMismatch { claimed, actual }
            }
            Err(corelink_handler_cas::CasHandlerError::CrossTenantDenied {
                caller,
                requested_tenant,
            }) => Self::CrossTenantDenied {
                caller,
                requested_tenant,
            },
            Err(corelink_handler_cas::CasHandlerError::AuditFailed(message)) => {
                Self::AuditFailed(message)
            }
            Err(corelink_handler_cas::CasHandlerError::ObjectTooLarge {
                actual_bytes,
                limit_bytes,
            }) => Self::ObjectTooLarge {
                actual_bytes,
                limit_bytes,
            },
            Err(corelink_handler_cas::CasHandlerError::Internal(message)) => {
                Self::Internal(message)
            }
            Err(error) => Self::Internal(error.to_string()),
        }
    }

    fn to_result(&self) -> Result<CasReadResponse, corelink_handler_cas::CasHandlerError> {
        match self {
            Self::Response(response) => Ok(response.clone()),
            Self::NotFound { tenant, hash } => {
                Err(corelink_handler_cas::CasHandlerError::NotFound {
                    tenant: tenant.clone(),
                    hash: hash.clone(),
                })
            }
            Self::HashMismatch { claimed, actual } => {
                Err(corelink_handler_cas::CasHandlerError::HashMismatch {
                    claimed: claimed.clone(),
                    actual: actual.clone(),
                })
            }
            Self::CrossTenantDenied {
                caller,
                requested_tenant,
            } => Err(corelink_handler_cas::CasHandlerError::CrossTenantDenied {
                caller: caller.clone(),
                requested_tenant: requested_tenant.clone(),
            }),
            Self::AuditFailed(message) => Err(corelink_handler_cas::CasHandlerError::AuditFailed(
                message.clone(),
            )),
            Self::ObjectTooLarge {
                actual_bytes,
                limit_bytes,
            } => Err(corelink_handler_cas::CasHandlerError::ObjectTooLarge {
                actual_bytes: *actual_bytes,
                limit_bytes: *limit_bytes,
            }),
            Self::Internal(message) => Err(corelink_handler_cas::CasHandlerError::Internal(
                message.clone(),
            )),
        }
    }
}

#[derive(Debug)]
struct CasReadSpy {
    outcome: CasReadSpyOutcome,
    calls: Arc<std::sync::Mutex<Vec<CasReadRequest>>>,
}

impl CasReadHandler for CasReadSpy {
    fn read(
        &self,
        request: CasReadRequest,
    ) -> Result<CasReadResponse, corelink_handler_cas::CasHandlerError> {
        self.calls.lock().unwrap().push(request);
        self.outcome.to_result()
    }
}

#[derive(Debug)]
struct CasWriteSpy {
    calls: Arc<std::sync::Mutex<Vec<CasWriteRequest>>>,
}

impl CasWriteHandler for CasWriteSpy {
    fn write(
        &self,
        request: CasWriteRequest,
    ) -> Result<CasWriteResponse, corelink_handler_cas::CasHandlerError> {
        let hash = request.claimed_hash.clone();
        self.calls.lock().unwrap().push(request);
        Ok(CasWriteResponse::new(hash, true))
    }
}

#[derive(Debug)]
struct UnusedAc;

impl AcLookupHandler for UnusedAc {
    fn lookup(
        &self,
        _request: AcLookupRequest,
    ) -> Result<AcLookupResponse, corelink_handler_ac::AcHandlerError> {
        panic!("CAS tests must not access ActionCache")
    }
}

impl AcUpdateHandler for UnusedAc {
    fn update(
        &self,
        _request: AcUpdateRequest,
    ) -> Result<AcUpdateResponse, corelink_handler_ac::AcHandlerError> {
        panic!("CAS tests must not access ActionCache")
    }
}

/// The requests a recording CAS handler received, in order.
type RecordedCalls<T> = Arc<std::sync::Mutex<Vec<T>>>;

fn cas_ingress_for_test(
    auth: Result<(String, bool), AuthenticationFailure>,
    admission: Result<(), AdmissionFailure>,
    read_result: Result<CasReadResponse, corelink_handler_cas::CasHandlerError>,
) -> (
    ReapiIngress,
    RecordedCalls<CasReadRequest>,
    RecordedCalls<CasWriteRequest>,
) {
    let read_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let write_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ingress = ReapiIngress::from_test_components(
        Arc::new(TestAuth(auth)),
        Arc::new(TestAdmission {
            result: admission,
            calls: Arc::new(AtomicUsize::new(0)),
        }),
        Arc::new(TestCapResolver),
        Arc::new(CasReadSpy {
            outcome: CasReadSpyOutcome::from_result(read_result),
            calls: read_calls.clone(),
        }),
        Arc::new(CasWriteSpy {
            calls: write_calls.clone(),
        }),
        Arc::new(UnusedAc),
        Arc::new(UnusedAc),
    );
    (ingress, read_calls, write_calls)
}

fn cas_metadata() -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer test-pat".parse().unwrap());
    metadata
}

fn cas_digest(bytes: &[u8]) -> corelink_reapi::proto::reapi::Digest {
    corelink_reapi::proto::reapi::Digest {
        hash: sha256_digest(bytes),
        size_bytes: i64::try_from(bytes.len()).unwrap(),
    }
}

#[tokio::test]
async fn cas_unary_writes_use_the_decorated_sha256_handler_once() {
    use crate::reapi_cas::CasUnaryService;
    use corelink_reapi::proto::reapi::content_addressable_storage_server::ContentAddressableStorage;
    use corelink_reapi::proto::reapi::{
        batch_update_blobs_request, digest_function, BatchUpdateBlobsRequest,
    };

    let bytes = b"CAS unary write".to_vec();
    let digest = cas_digest(&bytes);
    let (ingress, _reads, writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Err(corelink_handler_cas::CasHandlerError::NotFound {
            tenant: "tenant-a".into(),
            hash: digest.hash.clone(),
        }),
    );
    let mut request = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-a".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(digest),
            data: bytes,
            compressor: 0,
        }],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *request.metadata_mut() = cas_metadata();

    let response = CasUnaryService::new(ingress)
        .batch_update_blobs(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.responses.len(), 1);
    assert_eq!(
        response.responses[0].status.as_ref().unwrap().code,
        Code::Ok as i32
    );
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].tenant, "tenant-a");
    assert_eq!(writes[0].caller_tenant, "tenant-a");
    assert_eq!(writes[0].algo, DigestAlgo::Sha256);
}

#[tokio::test]
async fn cas_unary_denials_and_invalid_entries_never_reach_storage() {
    use crate::reapi_cas::CasUnaryService;
    use corelink_reapi::proto::reapi::content_addressable_storage_server::ContentAddressableStorage;
    use corelink_reapi::proto::reapi::{
        batch_update_blobs_request, digest_function, BatchUpdateBlobsRequest,
    };

    let bytes = b"denied".to_vec();
    let digest = cas_digest(&bytes);
    let (ingress, _reads, writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), false)),
        Ok(()),
        Err(corelink_handler_cas::CasHandlerError::NotFound {
            tenant: "tenant-a".into(),
            hash: digest.hash.clone(),
        }),
    );
    let mut denied = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-a".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(digest.clone()),
            data: bytes.clone(),
            compressor: 0,
        }],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *denied.metadata_mut() = cas_metadata();
    assert_eq!(
        CasUnaryService::new(ingress)
            .batch_update_blobs(denied)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(writes.lock().unwrap().is_empty());

    let (ingress, _reads, writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Err(corelink_handler_cas::CasHandlerError::NotFound {
            tenant: "tenant-a".into(),
            hash: digest.hash.clone(),
        }),
    );
    let mut invalid = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-a".into(),
        requests: vec![
            batch_update_blobs_request::Request {
                digest: Some(corelink_reapi::proto::reapi::Digest {
                    hash: "0".repeat(64),
                    size_bytes: i64::try_from(bytes.len()).unwrap(),
                }),
                data: bytes.clone(),
                compressor: 0,
            },
            batch_update_blobs_request::Request {
                digest: Some(digest.clone()),
                data: bytes.clone(),
                compressor: 1,
            },
            batch_update_blobs_request::Request {
                digest: Some(digest.clone()),
                data: bytes,
                compressor: 0,
            },
        ],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *invalid.metadata_mut() = cas_metadata();
    let statuses = CasUnaryService::new(ingress)
        .batch_update_blobs(invalid)
        .await
        .unwrap()
        .into_inner()
        .responses;
    assert_eq!(
        statuses[0].status.as_ref().unwrap().code,
        Code::InvalidArgument as i32
    );
    assert!(statuses[1..]
        .iter()
        .all(|entry| entry.status.as_ref().unwrap().code == Code::InvalidArgument as i32));
    // The ingress rejects a body/hash mismatch before handler dispatch.
    // Duplicate/compressor failures are likewise rejected at the REAPI boundary.
    assert!(writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cas_unary_read_masks_cross_tenant_and_fails_closed_for_backend_faults() {
    use crate::reapi_cas::CasUnaryService;
    use corelink_reapi::proto::reapi::content_addressable_storage_server::ContentAddressableStorage;
    use corelink_reapi::proto::reapi::{
        digest_function, BatchReadBlobsRequest, FindMissingBlobsRequest,
    };

    let digest = cas_digest(b"read");
    let cross_tenant = corelink_handler_cas::CasHandlerError::CrossTenantDenied {
        caller: "tenant-a".into(),
        requested_tenant: "tenant-b".into(),
    };
    let (ingress, reads, _writes) =
        cas_ingress_for_test(Ok(("tenant-a".into(), true)), Ok(()), Err(cross_tenant));
    let mut read = tonic::Request::new(BatchReadBlobsRequest {
        instance_name: "tenant-a".into(),
        digests: vec![digest.clone()],
        acceptable_compressors: vec![0],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *read.metadata_mut() = cas_metadata();
    let response = CasUnaryService::new(ingress.clone())
        .batch_read_blobs(read)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.responses[0].status.as_ref().unwrap().code,
        Code::NotFound as i32
    );
    assert_eq!(reads.lock().unwrap().len(), 1);
    assert_eq!(
        reads.lock().unwrap()[0].max_bytes,
        Some(u64::try_from(digest.size_bytes).unwrap()),
        "the decorated reader receives the declared digest ceiling"
    );

    let mut missing = tonic::Request::new(FindMissingBlobsRequest {
        instance_name: "tenant-a".into(),
        blob_digests: vec![digest.clone()],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *missing.metadata_mut() = cas_metadata();
    assert_eq!(
        CasUnaryService::new(ingress)
            .find_missing_blobs(missing)
            .await
            .unwrap()
            .into_inner()
            .missing_blob_digests,
        vec![digest]
    );

    let bytes = vec![7; (corelink_reapi::MAX_BATCH_TOTAL_SIZE_BYTES / 2 + 1) as usize];
    let digest = cas_digest(&bytes);
    let (ingress, reads, _writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Ok(CasReadResponse::new(bytes, digest.hash.clone())),
    );
    let mut aggregate = tonic::Request::new(BatchReadBlobsRequest {
        instance_name: "tenant-a".into(),
        digests: vec![digest.clone(), digest],
        acceptable_compressors: vec![0],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *aggregate.metadata_mut() = cas_metadata();
    let aggregate = CasUnaryService::new(ingress)
        .batch_read_blobs(aggregate)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        aggregate.responses[0].status.as_ref().unwrap().code,
        Code::Ok as i32
    );
    assert_eq!(
        aggregate.responses[1].status.as_ref().unwrap().code,
        Code::FailedPrecondition as i32
    );
    assert_eq!(
        reads.lock().unwrap().len(),
        1,
        "the declared aggregate limit skips the second backend dispatch"
    );

    let (ingress, _reads, _writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Err(corelink_handler_cas::CasHandlerError::AuditFailed(
            "D1 unavailable".into(),
        )),
    );
    let mut backend = tonic::Request::new(FindMissingBlobsRequest {
        instance_name: "tenant-a".into(),
        blob_digests: vec![cas_digest(b"read")],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *backend.metadata_mut() = cas_metadata();
    assert_eq!(
        CasUnaryService::new(ingress)
            .find_missing_blobs(backend)
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
}

#[tokio::test]
async fn cas_unary_rejects_instance_quota_and_declared_size_limits_before_storage() {
    use crate::reapi_cas::CasUnaryService;
    use corelink_reapi::proto::reapi::content_addressable_storage_server::ContentAddressableStorage;
    use corelink_reapi::proto::reapi::{
        batch_update_blobs_request, digest_function, BatchUpdateBlobsRequest, Digest,
    };

    let bytes = b"limits".to_vec();
    let digest = cas_digest(&bytes);
    let (ingress, _reads, writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Err(AdmissionFailure::Exhausted),
        Err(corelink_handler_cas::CasHandlerError::NotFound {
            tenant: "tenant-a".into(),
            hash: digest.hash.clone(),
        }),
    );
    let mut quota = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-a".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(digest.clone()),
            data: bytes.clone(),
            compressor: 0,
        }],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *quota.metadata_mut() = cas_metadata();
    assert_eq!(
        CasUnaryService::new(ingress)
            .batch_update_blobs(quota)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert!(writes.lock().unwrap().is_empty());

    let (ingress, _reads, writes) = cas_ingress_for_test(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Err(corelink_handler_cas::CasHandlerError::NotFound {
            tenant: "tenant-a".into(),
            hash: digest.hash.clone(),
        }),
    );
    let mut invalid = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-b".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(Digest {
                hash: digest.hash,
                size_bytes: corelink_reapi::MAX_CAS_BLOB_SIZE_BYTES + 1,
            }),
            data: bytes,
            compressor: 0,
        }],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *invalid.metadata_mut() = cas_metadata();
    assert_eq!(
        CasUnaryService::new(ingress.clone())
            .batch_update_blobs(invalid)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(writes.lock().unwrap().is_empty());

    let mut oversized = tonic::Request::new(BatchUpdateBlobsRequest {
        instance_name: "tenant-a".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(Digest {
                hash: cas_digest(b"limits").hash,
                size_bytes: corelink_reapi::MAX_CAS_BLOB_SIZE_BYTES + 1,
            }),
            data: b"limits".to_vec(),
            compressor: 0,
        }],
        digest_function: digest_function::Value::Sha256 as i32,
    });
    *oversized.metadata_mut() = cas_metadata();
    let responses = CasUnaryService::new(ingress)
        .batch_update_blobs(oversized)
        .await
        .unwrap()
        .into_inner()
        .responses;
    assert_eq!(
        responses[0].status.as_ref().unwrap().code,
        Code::ResourceExhausted as i32
    );
    assert!(writes.lock().unwrap().is_empty());
}
