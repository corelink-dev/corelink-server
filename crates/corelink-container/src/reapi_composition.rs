//! Unmounted composition of the authenticated, cache-only REAPI service set.
//!
//! This module deliberately stops before binding or serving a listener. The
//! caller receives no service router when the route factory could not build
//! its authenticated ingress dependencies. The public Worker gRPC deny stays
//! in force until #2176 proves the deployed transport path.

use corelink_reapi::proto::bytestream::byte_stream_server::ByteStreamServer;
use corelink_reapi::proto::reapi::action_cache_server::ActionCacheServer;
use corelink_reapi::proto::reapi::capabilities_server::CapabilitiesServer;
use tonic::service::Routes;
use tonic::transport::{server::Router, Server};

use crate::reapi_action_cache::{ReapiActionCacheService, ReapiCacheCapabilitiesService};
use crate::reapi_bytestream::ReapiByteStreamService;
use crate::reapi_cas::CasUnaryService;
use crate::reapi_ingress::ReapiIngress;

/// Maximum encoded request size for the cache service set.
///
/// CAS batches and ByteStream chunks are independently bounded by their
/// service contracts. This transport ceiling allows their valid payloads plus
/// protobuf framing while keeping an explicit upper bound on decoding.
pub const REAPI_MAX_DECODING_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Build the inert Tonic router for the complete cache-only service set.
///
/// The router contains CAS unary, ByteStream, ActionCache, and authenticated
/// Capabilities routes. `None` represents the route factory's fail-closed
/// state when authoritative ingress dependencies are unavailable. The
/// returned router does not bind a socket or establish that an external
/// Worker/DO/Container hop preserves native gRPC.
#[must_use]
pub fn build_unmounted_cache_only_router(ingress: Option<ReapiIngress>) -> Option<Router> {
    Some(Server::builder().add_routes(build_unmounted_cache_only_routes(ingress)?))
}

/// Build the exact cache-only route set for a listener that already owns its
/// socket. `None` preserves the authoritative-authentication fail-closed
/// posture of [`build_unmounted_cache_only_router`].
#[must_use]
pub fn build_unmounted_cache_only_routes(ingress: Option<ReapiIngress>) -> Option<Routes> {
    let ingress = ingress?;
    Some(
        Routes::new(
            CasUnaryService::new(ingress.clone())
                .into_server()
                .max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)
                .max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES),
        )
        .add_service(
            ByteStreamServer::new(ReapiByteStreamService::new(ingress.clone()))
                .max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)
                .max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES),
        )
        .add_service(
            ActionCacheServer::new(ReapiActionCacheService::new(ingress.clone()))
                .max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)
                .max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES),
        )
        .add_service(
            CapabilitiesServer::new(ReapiCacheCapabilitiesService::new(ingress))
                .max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)
                .max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES),
        ),
    )
}

/// Adapt the unchanged cache-only route set to the already-bound Axum
/// listener. This creates neither a second listener nor another service set.
#[must_use]
pub fn build_unmounted_cache_only_axum_router(
    ingress: Option<ReapiIngress>,
) -> Option<axum::Router> {
    Some(build_unmounted_cache_only_routes(ingress)?.into_axum_router())
}
