/** Thin request pipeline: each policy domain is independently testable. */
import type { ExecutionContext, ExportedHandler } from "@cloudflare/workers-types";
import type { Env } from "./index_common.js";
import { resolveRequestId } from "./index_auth.js";
import { matchRoute } from "./route_match.js";
import { handlePublicAndInternalRoute } from "./index_public_routes.js";
import { handleSpecialRoute } from "./index_special_routes.js";
import { authenticateRequest } from "./index_auth_stage.js";
import { enforceQuota } from "./index_quota_stage.js";
import { routeTenantRequest } from "./index_routing_stage.js";
import { serveEdgeOptimisations } from "./index_edge_stage.js";
import { finishResponse } from "./index_finish_stage.js";
import { runScheduled } from "./index_schedule.js";
import { rejectUnprovenGrpcTransport } from "./grpc_transport_gate.js";

let requestCounter = 0;

export const baseHandler: ExportedHandler<Env> = {
  scheduled: runScheduled,
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const grpcTransportGate = rejectUnprovenGrpcTransport(request);
    if (grpcTransportGate !== null) return grpcTransportGate;
    const requestStart = Date.now();
    const requestId = resolveRequestId(request);
    requestCounter = (requestCounter + 1) | 0;
    const route = matchRoute(new URL(request.url));

    const publicResponse = await handlePublicAndInternalRoute(request, env, ctx, requestId, route);
    if (publicResponse !== null) return publicResponse;

    const specialResponse = await handleSpecialRoute(
      request, env, ctx, requestId, requestStart, requestCounter, route,
    );
    if (specialResponse !== null) return specialResponse;

    const authStage = await authenticateRequest(request, env, ctx, requestId, route);
    if (authStage instanceof Response) return authStage;

    const quota = await enforceQuota(request, env, ctx, requestId, authStage.resolvedTenantId);
    if (quota instanceof Response) return quota;

    const routing = await routeTenantRequest(
      request,
      env,
      ctx,
      requestId,
      route,
      authStage,
      quota.storageQuotaHeader,
    );
    if (routing instanceof Response) return routing;

    const edgeServed = await serveEdgeOptimisations(
      request,
      env,
      ctx,
      requestId,
      route,
      authStage,
      routing,
    );

    return finishResponse(
      request,
      env,
      ctx,
      requestId,
      requestStart,
      requestCounter,
      route,
      authStage,
      quota,
      routing,
      edgeServed,
    );
  },
};
