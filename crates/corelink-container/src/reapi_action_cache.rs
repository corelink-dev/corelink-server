//! Unmounted authenticated REAPI ActionCache and cache-only Capabilities.
//!
//! This transport layer owns no cache state. Every accepted ActionCache RPC
//! reaches the route factory's production-decorated ActionCache handlers
//! through [`crate::reapi_ingress::ReapiIngress`]. Public gRPC composition is
//! intentionally deferred to #2183 after the #2176 transport proof.

use corelink_reapi::proto::reapi::action_cache_server::{ActionCache, ActionCacheServer};
use corelink_reapi::proto::reapi::capabilities_server::{Capabilities, CapabilitiesServer};
use corelink_reapi::proto::reapi::{
    digest_function, ActionCacheUpdateCapabilities, ActionResult, CacheCapabilities, Digest,
    GetActionResultRequest, GetCapabilitiesRequest, ServerCapabilities, UpdateActionResultRequest,
};
use prost::Message;
use tonic::{async_trait, Code, Request, Response, Status};

use crate::reapi_ingress::{sha256_digest, validate_digest, Access, ReapiIngress};

/// The shared cache-entry ceiling also bounds one serialized ActionResult.
pub const REAPI_ACTION_RESULT_MAX_SERIALIZED_BYTES: usize = corelink_hash::CACHE_ENTRY_MAX_BYTES;

/// Authenticated cache-only REAPI ActionCache service.
#[derive(Clone, Debug)]
pub struct ReapiActionCacheService {
    ingress: ReapiIngress,
}

impl ReapiActionCacheService {
    /// Bind ActionCache RPCs to the route factory's decorated ingress bundle.
    #[must_use]
    pub fn new(ingress: ReapiIngress) -> Self {
        Self { ingress }
    }

    /// Produce a service for a separately authorized future gRPC mount.
    #[must_use]
    pub fn into_server(self) -> ActionCacheServer<Self> {
        ActionCacheServer::new(self)
    }

    async fn get(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: GetActionResultRequest,
    ) -> Result<ActionResult, Status> {
        let admitted = self
            .ingress
            .authorize(metadata, &request.instance_name, Access::Read)
            .await?;
        let (hash, size_bytes) = validate_action_digest(request.action_digest.as_ref())?;
        let response = admitted.ac_lookup(hash, size_bytes)?;
        let result = ActionResult::decode(response.result_payload.as_slice()).map_err(|_| {
            Status::new(
                Code::Unavailable,
                "ActionCache handler returned invalid result",
            )
        })?;
        validate_action_result(&result).map_err(|_| {
            Status::new(
                Code::Unavailable,
                "ActionCache handler returned invalid result",
            )
        })?;
        Ok(result)
    }

    async fn update(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: UpdateActionResultRequest,
    ) -> Result<ActionResult, Status> {
        let admitted = self
            .ingress
            .authorize(metadata, &request.instance_name, Access::Write)
            .await?;
        let (hash, size_bytes) = validate_action_digest(request.action_digest.as_ref())?;
        let result = request
            .action_result
            .ok_or_else(|| Status::new(Code::InvalidArgument, "ActionCache result is required"))?;
        validate_action_result(&result)?;
        let payload = result.encode_to_vec();
        admitted
            .ac_update(hash, size_bytes, payload)
            .await
            .map_err(map_action_update_status)?;
        Ok(result)
    }
}

#[async_trait]
impl ActionCache for ReapiActionCacheService {
    async fn get_action_result(
        &self,
        request: Request<GetActionResultRequest>,
    ) -> Result<Response<ActionResult>, Status> {
        let metadata = request.metadata().clone();
        Ok(Response::new(
            self.get(&metadata, request.into_inner()).await?,
        ))
    }

    async fn update_action_result(
        &self,
        request: Request<UpdateActionResultRequest>,
    ) -> Result<Response<ActionResult>, Status> {
        let metadata = request.metadata().clone();
        Ok(Response::new(
            self.update(&metadata, request.into_inner()).await?,
        ))
    }
}

/// Authenticated cache-only REAPI capabilities service.
#[derive(Clone, Debug)]
pub struct ReapiCacheCapabilitiesService {
    ingress: ReapiIngress,
}

impl ReapiCacheCapabilitiesService {
    /// Bind capability discovery to the same authenticated ingress boundary.
    #[must_use]
    pub fn new(ingress: ReapiIngress) -> Self {
        Self { ingress }
    }

    /// Produce a service for a separately authorized future gRPC mount.
    #[must_use]
    pub fn into_server(self) -> CapabilitiesServer<Self> {
        CapabilitiesServer::new(self)
    }

    async fn get(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: GetCapabilitiesRequest,
    ) -> Result<ServerCapabilities, Status> {
        let _admitted = self
            .ingress
            .authorize(metadata, &request.instance_name, Access::Read)
            .await?;
        Ok(cache_only_capabilities())
    }
}

#[async_trait]
impl Capabilities for ReapiCacheCapabilitiesService {
    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<ServerCapabilities>, Status> {
        let metadata = request.metadata().clone();
        Ok(Response::new(
            self.get(&metadata, request.into_inner()).await?,
        ))
    }
}

fn validate_action_digest(digest: Option<&Digest>) -> Result<(&str, i64), Status> {
    let digest = digest
        .ok_or_else(|| Status::new(Code::InvalidArgument, "ActionCache digest is required"))?;
    validate_digest(&digest.hash, digest.size_bytes)?;
    if usize::try_from(digest.size_bytes)
        .ok()
        .map_or(true, |size| size > REAPI_ACTION_RESULT_MAX_SERIALIZED_BYTES)
    {
        return Err(Status::new(
            Code::ResourceExhausted,
            "ActionCache digest exceeds the cache entry limit",
        ));
    }
    Ok((&digest.hash, digest.size_bytes))
}

fn validate_action_result(result: &ActionResult) -> Result<(), Status> {
    if result.encoded_len() > REAPI_ACTION_RESULT_MAX_SERIALIZED_BYTES {
        return Err(Status::new(
            Code::ResourceExhausted,
            "ActionCache result exceeds the cache entry limit",
        ));
    }
    for output in &result.output_files {
        validate_output_path(&output.path)?;
        let digest = output
            .digest
            .as_ref()
            .ok_or_else(|| Status::new(Code::InvalidArgument, "output file digest is required"))?;
        validate_digest(&digest.hash, digest.size_bytes)?;
        if !output.contents.is_empty() {
            validate_inline_bytes(&output.contents, digest)?;
        }
    }
    for output in &result.output_directories {
        validate_output_path(&output.path)?;
        let tree_digest = output.tree_digest.as_ref().ok_or_else(|| {
            Status::new(
                Code::InvalidArgument,
                "output directory tree digest is required",
            )
        })?;
        validate_digest(&tree_digest.hash, tree_digest.size_bytes)?;
        if let Some(root_digest) = output.root_directory_digest.as_ref() {
            validate_digest(&root_digest.hash, root_digest.size_bytes)?;
        }
    }
    #[expect(
        deprecated,
        reason = "REAPI v2.1 deprecated these two lists for `output_symlinks`, but v2.0 \
                  clients still send them, so their paths are validated too"
    )]
    let legacy_symlinks = result
        .output_file_symlinks
        .iter()
        .chain(&result.output_directory_symlinks);
    for output in legacy_symlinks.chain(&result.output_symlinks) {
        validate_output_path(&output.path)?;
    }
    validate_stdio(&result.stdout_raw, result.stdout_digest.as_ref(), "stdout")?;
    validate_stdio(&result.stderr_raw, result.stderr_digest.as_ref(), "stderr")?;
    Ok(())
}

fn validate_output_path(path: &str) -> Result<(), Status> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(Status::new(
            Code::InvalidArgument,
            "ActionCache output path must be a normalized relative path",
        ));
    }
    Ok(())
}

fn validate_inline_bytes(bytes: &[u8], digest: &Digest) -> Result<(), Status> {
    let actual_size = i64::try_from(bytes.len())
        .map_err(|_| Status::new(Code::ResourceExhausted, "inline output is too large"))?;
    if actual_size != digest.size_bytes || sha256_digest(bytes) != digest.hash {
        return Err(Status::new(
            Code::InvalidArgument,
            "inline output does not match its digest",
        ));
    }
    Ok(())
}

fn validate_stdio(bytes: &[u8], digest: Option<&Digest>, stream: &str) -> Result<(), Status> {
    if !bytes.is_empty() && digest.is_some() {
        return Err(Status::new(
            Code::InvalidArgument,
            format!("ActionCache {stream} cannot be inline and digest-backed"),
        ));
    }
    if let Some(digest) = digest {
        validate_digest(&digest.hash, digest.size_bytes)?;
    }
    Ok(())
}

fn map_action_update_status(status: Status) -> Status {
    if status.code() == Code::FailedPrecondition {
        Status::new(Code::AlreadyExists, "ActionCache entry already exists")
    } else {
        status
    }
}

fn cache_only_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        cache_capabilities: Some(CacheCapabilities {
            digest_functions: vec![digest_function::Value::Sha256 as i32],
            action_cache_update_capabilities: Some(ActionCacheUpdateCapabilities {
                update_enabled: true,
            }),
            cache_priority_capabilities: None,
            max_batch_total_size_bytes: corelink_reapi::MAX_BATCH_TOTAL_SIZE_BYTES,
            symlink_absolute_path_strategy: 0,
            supported_compressors: Vec::new(),
            supported_batch_update_compressors: Vec::new(),
            max_cas_blob_size_bytes: corelink_reapi::MAX_CAS_BLOB_SIZE_BYTES,
        }),
        execution_capabilities: None,
        deprecated_api_version: None,
        low_api_version: Some(corelink_reapi::proto::semver::SemVer {
            major: 2,
            minor: 12,
            patch: 0,
            prerelease: String::new(),
        }),
        high_api_version: Some(corelink_reapi::proto::semver::SemVer {
            major: 2,
            minor: 12,
            patch: 0,
            prerelease: String::new(),
        }),
    }
}

#[cfg(test)]
#[path = "reapi_action_cache/tests.rs"]
mod tests;
