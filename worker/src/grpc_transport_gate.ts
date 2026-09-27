import {
  isStagingGrpcDiagnosticPath,
  isStagingGrpcDiagnosticRequest,
} from "./grpc_staging_authorization.js";

const GRPC_MEDIA_TYPE_PREFIX = "application/grpc";

/**
 * Refuse every public native-gRPC request at the Fetch boundary. The two
 * exact staging diagnostic paths may proceed only when their structural shape
 * is valid; protected binding verification remains downstream and fails
 * closed before Durable Object selection. This function never reflects
 * request data, including authorization.
 */
export function rejectUnprovenGrpcTransport(request: Request): Response | null {
  if (isStagingGrpcDiagnosticPath(request)) {
    if (isStagingGrpcDiagnosticRequest(request)) return null;
    return unavailable();
  }

  const mediaType = request.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (mediaType === undefined || !mediaType.startsWith(GRPC_MEDIA_TYPE_PREFIX)) return null;

  return unavailable();
}

function unavailable(): Response {
  return new Response(JSON.stringify({ error: "GRPC_TRANSPORT_UNAVAILABLE" }), {
    status: 503,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}
