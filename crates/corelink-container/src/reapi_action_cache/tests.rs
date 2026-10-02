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
    AcHandlerError, AcLookupHandler, AcLookupRequest, AcLookupResponse, AcUpdateHandler,
    AcUpdateRequest, AcUpdateResponse,
};
use corelink_handler_cas::{
    CasHandlerError, CasReadHandler, CasReadRequest, CasReadResponse, CasWriteHandler,
    CasWriteRequest, CasWriteResponse,
};
use corelink_reapi::proto::reapi::{
    digest_function, Digest, ExecutedActionMetadata, NodeProperties, NodeProperty, OutputDirectory,
    OutputFile, OutputSymlink,
};
use prost::Message;
use tonic::Code;

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
struct AcSpy {
    lookups: AtomicUsize,
    updates: AtomicUsize,
    audit_failure: AtomicBool,
    body: Mutex<Option<Vec<u8>>>,
}

impl AcSpy {
    fn stored(&self) -> Option<Vec<u8>> {
        self.body.lock().expect("AC spy lock").clone()
    }
}

impl AcLookupHandler for AcSpy {
    fn lookup(&self, request: AcLookupRequest) -> Result<AcLookupResponse, AcHandlerError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.audit_failure.load(Ordering::SeqCst) {
            return Err(AcHandlerError::AuditFailed("down".into()));
        }
        let Some(body) = self.stored() else {
            return Err(AcHandlerError::Miss {
                tenant: request.tenant,
                action_digest: request.action_digest,
            });
        };
        Ok(AcLookupResponse::new(request.action_digest, body))
    }
}

impl AcUpdateHandler for AcSpy {
    fn update(&self, request: AcUpdateRequest) -> Result<AcUpdateResponse, AcHandlerError> {
        self.updates.fetch_add(1, Ordering::SeqCst);
        if self.audit_failure.load(Ordering::SeqCst) {
            return Err(AcHandlerError::AuditFailed("down".into()));
        }
        let mut stored = self.body.lock().expect("AC spy lock");
        if stored
            .as_ref()
            .is_some_and(|body| body != &request.result_payload)
        {
            return Err(AcHandlerError::DivergentBody {
                tenant: request.tenant,
                action_digest: request.action_digest,
            });
        }
        let durable = stored.is_none();
        *stored = Some(request.result_payload);
        Ok(AcUpdateResponse::new(request.action_digest, durable))
    }
}

#[derive(Debug)]
struct UnusedCas;

impl CasReadHandler for UnusedCas {
    fn read(&self, _request: CasReadRequest) -> Result<CasReadResponse, CasHandlerError> {
        Err(CasHandlerError::Internal("unused".into()))
    }
}

impl CasWriteHandler for UnusedCas {
    fn write(&self, _request: CasWriteRequest) -> Result<CasWriteResponse, CasHandlerError> {
        Err(CasHandlerError::Internal("unused".into()))
    }
}

fn service(
    auth: Result<(String, bool), AuthenticationFailure>,
    admission: Result<(), AdmissionFailure>,
    ac: Arc<AcSpy>,
) -> ReapiActionCacheService {
    let cas = Arc::new(UnusedCas);
    ReapiActionCacheService::new(ReapiIngress::from_test_components(
        Arc::new(TestAuth(auth)),
        Arc::new(TestAdmission(admission)),
        Arc::new(TestCap),
        cas.clone(),
        cas,
        ac.clone(),
        ac,
    ))
}

fn capabilities_service(
    auth: Result<(String, bool), AuthenticationFailure>,
) -> ReapiCacheCapabilitiesService {
    let ac = Arc::new(AcSpy::default());
    let cas = Arc::new(UnusedCas);
    ReapiCacheCapabilitiesService::new(ReapiIngress::from_test_components(
        Arc::new(TestAuth(auth)),
        Arc::new(TestAdmission(Ok(()))),
        Arc::new(TestCap),
        cas.clone(),
        cas,
        ac.clone(),
        ac,
    ))
}

fn metadata() -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "authorization",
        "Bearer test-pat".parse().expect("metadata"),
    );
    metadata
}

fn action_digest() -> Digest {
    Digest {
        hash: "a".repeat(64),
        size_bytes: 17,
    }
}

#[expect(
    deprecated,
    reason = "the fixture fills the deprecated REAPI v2.0 symlink lists that validation still checks"
)]
fn result() -> ActionResult {
    let contents = b"output".to_vec();
    ActionResult {
        output_files: vec![OutputFile {
            path: "out/result".into(),
            digest: Some(Digest {
                hash: sha256_digest(&contents),
                size_bytes: i64::try_from(contents.len()).expect("size"),
            }),
            is_executable: true,
            contents,
            node_properties: Some(NodeProperties {
                properties: vec![NodeProperty {
                    name: "owner".into(),
                    value: "buck2".into(),
                }],
                ..Default::default()
            }),
        }],
        output_directories: vec![OutputDirectory {
            path: "out/tree".into(),
            tree_digest: Some(Digest {
                hash: "b".repeat(64),
                size_bytes: 17,
            }),
            root_directory_digest: Some(Digest {
                hash: "c".repeat(64),
                size_bytes: 9,
            }),
            ..Default::default()
        }],
        output_file_symlinks: vec![OutputSymlink {
            path: "out/file-link".into(),
            target: "result".into(),
            node_properties: Some(NodeProperties::default()),
        }],
        output_directory_symlinks: vec![OutputSymlink {
            path: "out/dir-link".into(),
            target: "tree".into(),
            node_properties: Some(NodeProperties::default()),
        }],
        output_symlinks: vec![OutputSymlink {
            path: "out/latest".into(),
            target: "result".into(),
            node_properties: Some(NodeProperties::default()),
        }],
        execution_metadata: Some(ExecutedActionMetadata {
            worker: "worker-a".into(),
            ..Default::default()
        }),
        stdout_digest: Some(Digest {
            hash: "d".repeat(64),
            size_bytes: 0,
        }),
        stderr_digest: Some(Digest {
            hash: "e".repeat(64),
            size_bytes: 0,
        }),
        exit_code: 17,
        ..Default::default()
    }
}

#[tokio::test]
async fn authenticated_round_trip_uses_decorated_action_cache_once_per_rpc() {
    let ac = Arc::new(AcSpy::default());
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), ac.clone());
    let written = service
        .update(
            &metadata(),
            UpdateActionResultRequest {
                instance_name: "tenant-a".into(),
                action_digest: Some(action_digest()),
                action_result: Some(result()),
                ..Default::default()
            },
        )
        .await
        .expect("update");
    let read = service
        .get(
            &metadata(),
            GetActionResultRequest {
                instance_name: "tenant-a".into(),
                action_digest: Some(action_digest()),
                inline_stdout: false,
                inline_stderr: false,
                ..Default::default()
            },
        )
        .await
        .expect("lookup");
    assert_eq!(written, result());
    assert_eq!(read, result());
    assert_eq!(ac.updates.load(Ordering::SeqCst), 1);
    assert_eq!(ac.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_authorization_tenant_and_malformed_result_never_touch_action_cache() {
    let ac = Arc::new(AcSpy::default());
    let request = UpdateActionResultRequest {
        instance_name: "tenant-a".into(),
        action_digest: Some(action_digest()),
        action_result: Some(result()),
        ..Default::default()
    };
    let missing = service(Ok(("tenant-a".into(), true)), Ok(()), ac.clone());
    assert_eq!(
        missing
            .update(&tonic::metadata::MetadataMap::new(), request.clone())
            .await
            .expect_err("missing PAT")
            .code(),
        Code::Unauthenticated
    );
    let denied = service(Ok(("tenant-a".into(), false)), Ok(()), ac.clone());
    assert_eq!(
        denied
            .update(&metadata(), request.clone())
            .await
            .expect_err("read only PAT")
            .code(),
        Code::PermissionDenied
    );
    let tenant_mismatch = UpdateActionResultRequest {
        instance_name: "tenant-b".into(),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), tenant_mismatch)
            .await
            .expect_err("tenant mismatch")
            .code(),
        Code::PermissionDenied
    );
    let malformed = UpdateActionResultRequest {
        action_result: Some(ActionResult {
            output_files: vec![OutputFile {
                path: "out/bad".into(),
                digest: None,
                is_executable: false,
                contents: b"unbound".to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), malformed)
            .await
            .expect_err("nested digest")
            .code(),
        Code::InvalidArgument
    );
    let mismatched_inline = UpdateActionResultRequest {
        action_result: Some(ActionResult {
            output_files: vec![OutputFile {
                path: "out/mismatch".into(),
                digest: Some(Digest {
                    hash: "b".repeat(64),
                    size_bytes: 8,
                }),
                is_executable: false,
                contents: b"unbound".to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), mismatched_inline)
            .await
            .expect_err("inline digest mismatch")
            .code(),
        Code::InvalidArgument
    );
    let missing_tree_digest = UpdateActionResultRequest {
        action_result: Some(ActionResult {
            output_directories: vec![OutputDirectory {
                path: "out/tree".into(),
                tree_digest: None,
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), missing_tree_digest)
            .await
            .expect_err("output directory digest")
            .code(),
        Code::InvalidArgument
    );
    let mut escaping_path = result();
    escaping_path.output_symlinks[0].path = "../outside".into();
    assert_eq!(
        missing
            .update(
                &metadata(),
                UpdateActionResultRequest {
                    action_result: Some(escaping_path),
                    ..request.clone()
                },
            )
            .await
            .expect_err("output path")
            .code(),
        Code::InvalidArgument
    );
    let malformed_action = UpdateActionResultRequest {
        action_digest: Some(Digest {
            hash: "not-a-sha256".into(),
            size_bytes: 17,
        }),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), malformed_action)
            .await
            .expect_err("action digest")
            .code(),
        Code::InvalidArgument
    );
    let oversized = UpdateActionResultRequest {
        action_result: Some(ActionResult {
            stdout_raw: vec![0; REAPI_ACTION_RESULT_MAX_SERIALIZED_BYTES + 1],
            ..Default::default()
        }),
        ..request.clone()
    };
    assert_eq!(
        missing
            .update(&metadata(), oversized)
            .await
            .expect_err("serialized result size")
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(ac.updates.load(Ordering::SeqCst), 0);
    assert_eq!(ac.lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn miss_is_not_found_and_immutable_conflict_is_already_exists() {
    let ac = Arc::new(AcSpy::default());
    let service = service(Ok(("tenant-a".into(), true)), Ok(()), ac.clone());
    assert_eq!(
        service
            .get(
                &metadata(),
                GetActionResultRequest {
                    instance_name: "tenant-a".into(),
                    action_digest: Some(action_digest()),
                    inline_stdout: false,
                    inline_stderr: false,
                    ..Default::default()
                },
            )
            .await
            .expect_err("miss")
            .code(),
        Code::NotFound
    );
    service
        .update(
            &metadata(),
            UpdateActionResultRequest {
                instance_name: "tenant-a".into(),
                action_digest: Some(action_digest()),
                action_result: Some(result()),
                ..Default::default()
            },
        )
        .await
        .expect("initial write");
    let divergent = ActionResult {
        exit_code: 18,
        ..result()
    };
    assert_eq!(
        service
            .update(
                &metadata(),
                UpdateActionResultRequest {
                    instance_name: "tenant-a".into(),
                    action_digest: Some(action_digest()),
                    action_result: Some(divergent),
                    ..Default::default()
                },
            )
            .await
            .expect_err("immutable conflict")
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(ac.stored(), Some(result().encode_to_vec()));
}

#[tokio::test]
async fn quota_and_audit_faults_fail_closed_without_disclosure() {
    let ac = Arc::new(AcSpy::default());
    let exhausted = service(
        Ok(("tenant-a".into(), true)),
        Err(AdmissionFailure::Exhausted),
        ac.clone(),
    );
    assert_eq!(
        exhausted
            .update(
                &metadata(),
                UpdateActionResultRequest {
                    instance_name: "tenant-a".into(),
                    action_digest: Some(action_digest()),
                    action_result: Some(result()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("quota")
            .code(),
        Code::ResourceExhausted
    );
    ac.audit_failure.store(true, Ordering::SeqCst);
    let audited = service(Ok(("tenant-a".into(), true)), Ok(()), ac.clone());
    assert_eq!(
        audited
            .update(
                &metadata(),
                UpdateActionResultRequest {
                    instance_name: "tenant-a".into(),
                    action_digest: Some(action_digest()),
                    action_result: Some(result()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("audit")
            .code(),
        Code::Unavailable
    );
    assert_eq!(ac.updates.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn capabilities_are_authenticated_sha256_action_cache_only() {
    let service = capabilities_service(Ok(("tenant-a".into(), false)));
    let capabilities = service
        .get(
            &metadata(),
            GetCapabilitiesRequest {
                instance_name: "tenant-a".into(),
            },
        )
        .await
        .expect("capabilities");
    let cache = capabilities.cache_capabilities.expect("cache capabilities");
    assert_eq!(
        cache.digest_functions,
        vec![digest_function::Value::Sha256 as i32]
    );
    assert!(
        cache
            .action_cache_update_capabilities
            .expect("ActionCache capability")
            .update_enabled
    );
    assert_eq!(capabilities.execution_capabilities, None);
    assert_eq!(
        service
            .get(
                &tonic::metadata::MetadataMap::new(),
                GetCapabilitiesRequest {
                    instance_name: "tenant-a".into(),
                },
            )
            .await
            .expect_err("authentication")
            .code(),
        Code::Unauthenticated
    );
}
