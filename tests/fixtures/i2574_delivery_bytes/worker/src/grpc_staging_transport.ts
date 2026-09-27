/** Diagnostic-only Worker → dedicated staging DO native-gRPC forwarding. */

import type { Env } from "./index_common.js";
import {
  isStagingGrpcDiagnosticRequest,
  verifyStagingGrpcDiagnosticBinding,
} from "./grpc_staging_authorization.js";

const STAGING_GRPC_PROBE_DO = "_staging_grpc_probe_v1";

function unavailable(): Response {
  return new Response(JSON.stringify({ error: "GRPC_TRANSPORT_UNAVAILABLE" }), {
    status: 503,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function hasNativeGrpcMediaType(headers: Headers): boolean {
  const mediaType = headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/grpc" || mediaType === "application/grpc+proto";
}

/**
 * Forwards only a fully authenticated diagnostic request. The original Request
 * and upstream Response are passed through unchanged so bytes, cancellation,
 * authorization metadata and runtime trailer behavior are not reconstructed.
 */
export async function forwardStagingGrpcDiagnostic(
  request: Request,
  env: Env,
  nowMs = Date.now(),
): Promise<Response | null> {
  if (!isStagingGrpcDiagnosticRequest(request)) return null;
  if (verifyStagingGrpcDiagnosticBinding(request, env, nowMs) === null) return unavailable();

  try {
    const id = env.CORELINK_SERVER.idFromName(STAGING_GRPC_PROBE_DO);
    const response = await env.CORELINK_SERVER.get(id).fetch(request);
    return hasNativeGrpcMediaType(response.headers) ? response : unavailable();
  } catch {
    return unavailable();
  }
}
