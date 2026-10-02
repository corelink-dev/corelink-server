#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test assertions intentionally surface failures"
)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use corelink_handler_ac::{
    AcLookupHandler, AcLookupRequest, AcLookupResponse, AcUpdateHandler, AcUpdateRequest,
    AcUpdateResponse,
};
use corelink_handler_cas::{
    CasHandlerError, CasReadHandler, CasReadRequest, CasReadResponse, CasWriteHandler,
    CasWriteRequest, CasWriteResponse,
};
use corelink_reapi::proto::bytestream::{ReadRequest, WriteRequest};
use futures::{stream, StreamExt};
use tonic::{Code, Status};

use super::*;
use crate::reapi_ingress::{
    AdmissionFailure, AdmissionLease, AuthenticationFailure, IngressAdmission, IngressAuthenticator,
};

#[derive(Debug)]
struct TestAuth(Result<(String, bool), AuthenticationFailure>);

#[async_trait]
impl IngressAuthenticator for TestAuth {
    async fn authenticate(&self, _bearer: &str) -> Result<(String, bool), AuthenticationFailure> {
        self.0.clone()
    }
}

#[derive(Debug)]
struct TestAdmission(Result<(), AdmissionFailure>);

#[async_trait]
impl IngressAdmission for TestAdmission {
    async fn admit(&self, _tenant_id: &str) -> Result<AdmissionLease, AdmissionFailure> {
        self.0.map(|()| AdmissionLease::test_only())
    }
}

#[derive(Debug)]
struct TestCap;

#[async_trait]
impl crate::oci_cap::TenantCapResolver for TestCap {
    async fn resolve_storage_cap(&self, _tenant_id: &str) -> Option<i64> {
        Some(0)
    }
}

#[derive(Debug, Default)]
struct CasSpy {
    reads: AtomicUsize,
    writes: AtomicUsize,
    read_was_bounded: std::sync::atomic::AtomicBool,
    body: Mutex<Vec<u8>>,
    audit_failure: std::sync::atomic::AtomicBool,
    tombstoned: AtomicBool,
    tombstone_authority_failure: AtomicBool,
}

impl CasSpy {
    fn with_body(body: Vec<u8>) -> Self {
        Self {
            body: Mutex::new(body),
            ..Self::default()
        }
    }
}

impl CasReadHandler for CasSpy {
    fn read(&self, request: CasReadRequest) -> Result<CasReadResponse, CasHandlerError> {
        if self.tombstone_authority_failure.load(Ordering::SeqCst) {
            return Err(CasHandlerError::Internal(format!(
                "{}authority fault",
                crate::routes::cas_erase::TOMBSTONE_UNAVAILABLE_SENTINEL
            )));
        }
        if self.tombstoned.load(Ordering::SeqCst) {
            return Err(CasHandlerError::NotFound {
                tenant: request.tenant,
                hash: request.hash,
            });
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.read_was_bounded.store(
            request.max_bytes == Some(self.body.lock().expect("body lock").len() as u64),
            Ordering::SeqCst,
        );
        Ok(CasReadResponse::new(
            self.body.lock().expect("body lock").clone(),
            request.hash,
        ))
    }
}

impl CasWriteHandler for CasSpy {
    fn write(&self, request: CasWriteRequest) -> Result<CasWriteResponse, CasHandlerError> {
        if self.tombstone_authority_failure.load(Ordering::SeqCst) {
            return Err(CasHandlerError::Internal(format!(
                "{}authority fault",
                crate::routes::cas_erase::TOMBSTONE_UNAVAILABLE_SENTINEL
            )));
        }
        if self.tombstoned.load(Ordering::SeqCst) {
            return Err(CasHandlerError::Internal(format!(
                "{}re-PUT of erased blob refused",
                crate::routes::cas_erase::TOMBSTONE_GONE_SENTINEL
            )));
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.audit_failure.load(Ordering::SeqCst) {
            return Err(CasHandlerError::AuditFailed("down".into()));
        }
        *self.body.lock().expect("body lock") = request.bytes;
        Ok(CasWriteResponse::new(request.claimed_hash, true))
    }
}

#[derive(Debug)]
struct UnusedAc;

impl AcLookupHandler for UnusedAc {
    fn lookup(
        &self,
        request: AcLookupRequest,
    ) -> Result<AcLookupResponse, corelink_handler_ac::AcHandlerError> {
        Ok(AcLookupResponse::new(request.action_digest, []))
    }
}

impl AcUpdateHandler for UnusedAc {
    fn update(
        &self,
        request: AcUpdateRequest,
    ) -> Result<AcUpdateResponse, corelink_handler_ac::AcHandlerError> {
        Ok(AcUpdateResponse::new(request.action_digest, true))
    }
}

fn service(
    auth: Result<(String, bool), AuthenticationFailure>,
    admission: Result<(), AdmissionFailure>,
    cas: Arc<CasSpy>,
) -> ReapiByteStreamService {
    let ingress = ReapiIngress::from_test_components(
        Arc::new(TestAuth(auth)),
        Arc::new(TestAdmission(admission)),
        Arc::new(TestCap),
        cas.clone(),
        cas,
        Arc::new(UnusedAc),
        Arc::new(UnusedAc),
    );
    ReapiByteStreamService::new(ingress)
}

fn metadata() -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "authorization",
        "Bearer test-pat".parse().expect("metadata"),
    );
    metadata
}

fn resource(body: &[u8]) -> String {
    format!(
        "tenant-a/uploads/00000000-0000-0000-0000-000000000001/blobs/{}/{}",
        crate::reapi_ingress::sha256_digest(body),
        body.len()
    )
}

#[tokio::test]
async fn valid_write_calls_decorated_handler_once_and_read_honors_range() {
    let body = vec![b'x'; REAPI_BYTESTREAM_CHUNK_BYTES + 7];
    let cas = Arc::new(CasSpy::with_body(Vec::new()));
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    let response = service
        .write_stream(
            &metadata(),
            stream::iter(vec![Ok(WriteRequest {
                resource_name: resource(&body),
                write_offset: 0,
                finish_write: true,
                data: body.clone(),
            })]),
        )
        .await
        .expect("write succeeds");
    assert_eq!(response.committed_size, body.len() as i64);
    assert_eq!(cas.writes.load(Ordering::SeqCst), 1);

    let read_resource = format!(
        "tenant-a/blobs/{}/{}",
        crate::reapi_ingress::sha256_digest(&body),
        body.len()
    );
    let frames = service
        .read_request(
            &metadata(),
            ReadRequest {
                resource_name: read_resource,
                read_offset: 3,
                read_limit: (REAPI_BYTESTREAM_CHUNK_BYTES + 1) as i64,
            },
        )
        .await
        .expect("read succeeds")
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Status>>()
        .expect("read frames");
    let returned: Vec<u8> = frames.into_iter().flat_map(|frame| frame.data).collect();
    assert_eq!(returned, body[3..3 + REAPI_BYTESTREAM_CHUNK_BYTES + 1]);
    assert_eq!(cas.reads.load(Ordering::SeqCst), 1);
    assert!(cas.read_was_bounded.load(Ordering::SeqCst));
}

#[tokio::test]
async fn missing_invalid_read_only_and_tenant_mismatch_never_reach_cas() {
    let body = b"body".to_vec();
    let write = WriteRequest {
        resource_name: resource(&body),
        write_offset: 0,
        finish_write: true,
        data: body.clone(),
    };
    let cas = Arc::new(CasSpy::default());
    let valid = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    assert_eq!(
        valid
            .write_stream(
                &tonic::metadata::MetadataMap::new(),
                stream::iter(vec![Ok(write.clone())]),
            )
            .await
            .expect_err("missing PAT")
            .code(),
        Code::Unauthenticated
    );
    let invalid = service(Err(AuthenticationFailure::Invalid), Ok(()), cas.clone());
    assert_eq!(
        invalid
            .write_stream(&metadata(), stream::iter(vec![Ok(write.clone())]))
            .await
            .expect_err("invalid PAT")
            .code(),
        Code::Unauthenticated
    );
    let read_only = service(Ok(("tenant-a".into(), false)), Ok(()), cas.clone());
    assert_eq!(
        read_only
            .write_stream(&metadata(), stream::iter(vec![Ok(write.clone())]))
            .await
            .expect_err("read-only PAT")
            .code(),
        Code::PermissionDenied
    );
    let mismatch = WriteRequest {
        resource_name: write.resource_name.replacen("tenant-a", "tenant-b", 1),
        ..write
    };
    assert_eq!(
        valid
            .write_stream(&metadata(), stream::iter(vec![Ok(mismatch)]))
            .await
            .expect_err("tenant mismatch")
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        valid
            .write_stream(
                &metadata(),
                stream::iter(vec![Ok(WriteRequest {
                    resource_name: "tenant-a/blobs/not-a-digest/4".into(),
                    write_offset: 0,
                    finish_write: true,
                    data: b"body".to_vec(),
                })]),
            )
            .await
            .expect_err("malformed resource")
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(cas.reads.load(Ordering::SeqCst), 0);
    assert_eq!(cas.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_offsets_incomplete_and_hash_or_size_mismatch_fail_before_persistence() {
    let body = b"streamed-body".to_vec();
    let cas = Arc::new(CasSpy::default());
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    let name = resource(&body);
    for chunks in [
        vec![WriteRequest {
            resource_name: name.clone(),
            write_offset: 1,
            finish_write: true,
            data: body.clone(),
        }],
        vec![WriteRequest {
            resource_name: name.clone(),
            write_offset: 0,
            finish_write: false,
            data: body.clone(),
        }],
        vec![WriteRequest {
            resource_name: name.clone(),
            write_offset: 0,
            finish_write: true,
            data: b"different".to_vec(),
        }],
        vec![WriteRequest {
            resource_name: name.clone(),
            write_offset: 0,
            finish_write: true,
            data: b"bad-different".to_vec(),
        }],
        vec![
            WriteRequest {
                resource_name: name.clone(),
                write_offset: 0,
                finish_write: false,
                data: body[..3].to_vec(),
            },
            WriteRequest {
                resource_name: String::new(),
                write_offset: 0,
                finish_write: true,
                data: body[3..].to_vec(),
            },
        ],
    ] {
        assert_eq!(
            service
                .write_stream(&metadata(), stream::iter(chunks.into_iter().map(Ok)))
                .await
                .expect_err("invalid write")
                .code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(cas.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn read_ranges_and_write_size_ceiling_fail_before_cas() {
    let body = b"bounded-body".to_vec();
    let cas = Arc::new(CasSpy::with_body(body.clone()));
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    let read_name = format!(
        "tenant-a/blobs/{}/{}",
        crate::reapi_ingress::sha256_digest(&body),
        body.len()
    );
    for (offset, limit, code) in [
        (body.len() as i64 + 1, 0, Code::OutOfRange),
        (0, -1, Code::InvalidArgument),
    ] {
        let error = match service
            .read_request(
                &metadata(),
                ReadRequest {
                    resource_name: read_name.clone(),
                    read_offset: offset,
                    read_limit: limit,
                },
            )
            .await
        {
            Ok(_) => panic!("invalid range must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), code);
    }

    let digest = crate::reapi_ingress::sha256_digest(&body);
    let oversized = WriteRequest {
        resource_name: format!(
            "tenant-a/uploads/00000000-0000-0000-0000-000000000001/blobs/{digest}/{}",
            REAPI_BYTESTREAM_MAX_BUFFERED_BYTES + 1
        ),
        write_offset: 0,
        finish_write: true,
        data: Vec::new(),
    };
    assert_eq!(
        service
            .write_stream(&metadata(), stream::iter(vec![Ok(oversized)]))
            .await
            .expect_err("declared size exceeds configured ceiling")
            .code(),
        Code::ResourceExhausted
    );
    let too_much_data = WriteRequest {
        resource_name: format!(
            "tenant-a/uploads/00000000-0000-0000-0000-000000000001/blobs/{digest}/1"
        ),
        write_offset: 0,
        finish_write: true,
        data: body,
    };
    assert_eq!(
        service
            .write_stream(&metadata(), stream::iter(vec![Ok(too_much_data)]))
            .await
            .expect_err("body exceeds its declared size")
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(cas.reads.load(Ordering::SeqCst), 0);
    assert_eq!(cas.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn quota_and_audit_failures_fail_closed() {
    let body = b"body".to_vec();
    let request = WriteRequest {
        resource_name: resource(&body),
        write_offset: 0,
        finish_write: true,
        data: body,
    };
    let cas = Arc::new(CasSpy::default());
    let exhausted = service(
        Ok(("tenant-a".into(), true)),
        Err(AdmissionFailure::Exhausted),
        cas.clone(),
    );
    assert_eq!(
        exhausted
            .write_stream(&metadata(), stream::iter(vec![Ok(request.clone())]))
            .await
            .expect_err("quota denial")
            .code(),
        Code::ResourceExhausted
    );
    cas.audit_failure.store(true, Ordering::SeqCst);
    let audited = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    assert_eq!(
        audited
            .write_stream(&metadata(), stream::iter(vec![Ok(request)]))
            .await
            .expect_err("audit failure")
            .code(),
        Code::Unavailable
    );
    assert_eq!(cas.writes.load(Ordering::SeqCst), 1);
    assert!(cas.body.lock().expect("body lock").is_empty());
}

#[tokio::test]
async fn tombstone_gates_never_serve_or_persist_and_authority_faults_fail_closed() {
    let body = b"erased-body".to_vec();
    let write = WriteRequest {
        resource_name: resource(&body),
        write_offset: 0,
        finish_write: true,
        data: body.clone(),
    };
    let read = ReadRequest {
        resource_name: format!(
            "tenant-a/blobs/{}/{}",
            crate::reapi_ingress::sha256_digest(&body),
            body.len()
        ),
        read_offset: 0,
        read_limit: 0,
    };

    let tombstoned = Arc::new(CasSpy::with_body(body.clone()));
    tombstoned.tombstoned.store(true, Ordering::SeqCst);
    let tombstoned_service = service(Ok(("tenant-a".into(), true)), Ok(()), tombstoned.clone());
    let tombstoned_read = match tombstoned_service
        .read_request(&metadata(), read.clone())
        .await
    {
        Ok(_) => panic!("tombstoned bytes are never served"),
        Err(error) => error,
    };
    assert_eq!(tombstoned_read.code(), Code::NotFound);
    assert_eq!(
        tombstoned_service
            .write_stream(&metadata(), stream::iter(vec![Ok(write.clone())]))
            .await
            .expect_err("tombstoned bytes are never restored")
            .code(),
        Code::Unavailable
    );
    assert_eq!(tombstoned.reads.load(Ordering::SeqCst), 0);
    assert_eq!(tombstoned.writes.load(Ordering::SeqCst), 0);
    assert_eq!(*tombstoned.body.lock().expect("body lock"), body);

    let unavailable = Arc::new(CasSpy::with_body(body.clone()));
    unavailable
        .tombstone_authority_failure
        .store(true, Ordering::SeqCst);
    let unavailable_service = service(Ok(("tenant-a".into(), true)), Ok(()), unavailable.clone());
    let unavailable_read = match unavailable_service.read_request(&metadata(), read).await {
        Ok(_) => panic!("tombstone fault fails closed before a read"),
        Err(error) => error,
    };
    assert_eq!(unavailable_read.code(), Code::Unavailable);
    assert_eq!(
        unavailable_service
            .write_stream(&metadata(), stream::iter(vec![Ok(write)]))
            .await
            .expect_err("tombstone fault fails closed before persistence")
            .code(),
        Code::Unavailable
    );
    assert_eq!(unavailable.reads.load(Ordering::SeqCst), 0);
    assert_eq!(unavailable.writes.load(Ordering::SeqCst), 0);
    assert_eq!(*unavailable.body.lock().expect("body lock"), body);
}

#[tokio::test]
async fn terminal_write_requires_eof_and_rejects_delayed_replay_before_persistence() {
    let body = b"terminal-body".to_vec();
    let request = WriteRequest {
        resource_name: resource(&body),
        write_offset: 0,
        finish_write: true,
        data: body.clone(),
    };
    let cas = Arc::new(CasSpy::default());
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), cas.clone());
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(20),
        service.write_stream(
            &metadata(),
            stream::iter(vec![Ok(request.clone())])
                .chain(stream::pending::<Result<WriteRequest, Status>>()),
        ),
    )
    .await
    .is_err());
    assert_eq!(cas.writes.load(Ordering::SeqCst), 0);

    let replay = WriteRequest {
        resource_name: String::new(),
        write_offset: 0,
        finish_write: false,
        data: Vec::new(),
    };
    let replay_stream = stream::iter(vec![Ok(request)]).chain(stream::once(async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        Ok(replay)
    }));
    assert_eq!(
        service
            .write_stream(&metadata(), replay_stream)
            .await
            .expect_err("delayed replay is rejected")
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(cas.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsupported_resume_never_invents_upload_state() {
    let service = service(
        Ok(("tenant-a".into(), true)),
        Ok(()),
        Arc::new(CasSpy::default()),
    );
    let status = service
        .query_write_status(tonic::Request::new(QueryWriteStatusRequest {
            resource_name: "tenant-a/uploads/00000000-0000-0000-0000-000000000001/blobs/a/0".into(),
        }))
        .await
        .expect_err("resume is unsupported");
    assert_eq!(status.code(), Code::Unimplemented);
}
