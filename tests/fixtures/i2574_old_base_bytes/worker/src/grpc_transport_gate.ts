const GRPC_MEDIA_TYPE_PREFIX = "application/grpc";

/**
 * Refuse native-gRPC media types at the public Fetch boundary until a separate
 * protected-environment receipt proves the complete Worker → DO → Container
 * transport. This function reads only the media type and never reflects any
 * request header, including authorization.
 */
export function rejectUnprovenGrpcTransport(request: Request): Response | null {
  const mediaType = request.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (mediaType === undefined || !mediaType.startsWith(GRPC_MEDIA_TYPE_PREFIX)) return null;

  return new Response(JSON.stringify({ error: "GRPC_TRANSPORT_UNAVAILABLE" }), {
    status: 503,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}
