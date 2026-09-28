import type { DurableObjectState, DurableObjectStorage } from "@cloudflare/workers-types";

/** Header the tenant DO stamps only after its durable bucket decision. */
export const PAT_ISSUE_AUTHORIZED_HEADER = "x-corelink-pat-issue-authorized";

export const PAT_ISSUE_ENDPOINT_ID = "pat-issue";
export const PAT_ISSUE_BUCKET_KEY = "ratelimit:pat-issue:v1";
const PAT_ISSUE_BUCKET_VERSION = 1;
const PAT_ISSUE_CAPACITY = 10;
const PAT_ISSUE_REFILL_TOKENS = 10;
const PAT_ISSUE_REFILL_WINDOW_MS = 3_600_000;
const PAT_ISSUE_REFILL_PER_MS = PAT_ISSUE_REFILL_TOKENS / PAT_ISSUE_REFILL_WINDOW_MS;
const PAT_ISSUE_EPSILON = 1e-9;
const MAX_TENANT_ID_LENGTH = 256;

interface LifecycleTenantState {
  readonly tenantId: string | null;
}

interface PatIssueBucket {
  readonly version: number;
  readonly endpoint: string;
  readonly tenantId: string;
  readonly availableTokens: number;
  readonly lastRefillAtMs: number;
}

export type PatIssueGateResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly response: Response };

function jsonDoError(status: number, error: string, requestId: string): Response {
  return new Response(JSON.stringify({ error, request_id: requestId }), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
  });
}

function validateBucket(value: unknown, tenantId: string): PatIssueBucket {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as PatIssueBucket).version !== PAT_ISSUE_BUCKET_VERSION ||
    (value as PatIssueBucket).endpoint !== PAT_ISSUE_ENDPOINT_ID ||
    (value as PatIssueBucket).tenantId !== tenantId ||
    !Number.isFinite((value as PatIssueBucket).availableTokens) ||
    (value as PatIssueBucket).availableTokens < 0 ||
    (value as PatIssueBucket).availableTokens > PAT_ISSUE_CAPACITY ||
    !Number.isSafeInteger((value as PatIssueBucket).lastRefillAtMs) ||
    (value as PatIssueBucket).lastRefillAtMs < 0
  ) {
    throw new Error("invalid PAT issue bucket state");
  }
  return value as PatIssueBucket;
}

function validTenantId(tenantId: string | null): tenantId is string {
  return (
    tenantId !== null &&
    tenantId.length > 0 &&
    tenantId.length <= MAX_TENANT_ID_LENGTH &&
    tenantId === tenantId.trim() &&
    tenantId !== "_anonymous" &&
    tenantId !== "_unknown" &&
    tenantId !== "_pending_auth"
  );
}

/**
 * Atomically spend one PAT issuance token in the tenant DO.
 *
 * Durable Object serialization makes this read/refill/decision/write the
 * authority shared across aliases, container instances, cold starts, and
 * restarts. Any malformed or unavailable durable state fails closed.
 */
export async function enforcePatIssueRateLimit(
  state: Pick<DurableObjectState, "blockConcurrencyWhile">,
  storage: DurableObjectStorage,
  currentTenantId: string | null,
  requestId: string,
  tenantId: string | null,
): Promise<PatIssueGateResult> {
  // Compute the response class before the type guard narrows the invalid
  // branch to `null`; the valid branch below is then soundly `string`.
  const tenantMissing = tenantId === null || tenantId.length === 0;
  if (!validTenantId(tenantId)) {
    return {
      allowed: false,
      response: jsonDoError(
        tenantMissing ? 401 : 403,
        tenantMissing ? "UNAUTHENTICATED_TENANT" : "INVALID_TENANT_BINDING",
        requestId,
      ),
    };
  }

  try {
    const decision = await state.blockConcurrencyWhile(async () => {
      // Read the persisted binding inside the same serialized section as the
      // bucket mutation. A new DO may bind once; a recycled DO cannot switch
      // tenants even if a caller presents a conflicting header.
      const lifecycle = await storage.get<LifecycleTenantState>("lifecycle");
      const boundTenant = lifecycle?.tenantId ?? currentTenantId;
      if (boundTenant !== null && boundTenant !== tenantId) {
        return { kind: "tenant-mismatch" as const };
      }

      const nowMs = Date.now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
        throw new Error("rate-limit clock unavailable");
      }

      const stored = await storage.get<unknown>(PAT_ISSUE_BUCKET_KEY);
      const prior = stored === undefined ? null : validateBucket(stored, tenantId);
      const previous: PatIssueBucket = prior ?? {
        version: PAT_ISSUE_BUCKET_VERSION,
        endpoint: PAT_ISSUE_ENDPOINT_ID,
        tenantId,
        availableTokens: PAT_ISSUE_CAPACITY,
        lastRefillAtMs: nowMs,
      };
      // Clock rollback never creates tokens. A forward jump is naturally
      // capped by the bucket capacity.
      const elapsedMs = Math.max(0, nowMs - previous.lastRefillAtMs);
      const availableTokens = Math.min(
        PAT_ISSUE_CAPACITY,
        previous.availableTokens + elapsedMs * PAT_ISSUE_REFILL_PER_MS,
      );

      if (availableTokens + PAT_ISSUE_EPSILON < 1) {
        const retryAfterSecs = Math.max(
          1,
          Math.ceil(((1 - availableTokens) / PAT_ISSUE_REFILL_PER_MS) / 1000 - PAT_ISSUE_EPSILON),
        );
        await storage.put(PAT_ISSUE_BUCKET_KEY, {
          ...previous,
          availableTokens,
          lastRefillAtMs: nowMs,
        } satisfies PatIssueBucket);
        return { kind: "denied" as const, retryAfterSecs };
      }

      await storage.put(PAT_ISSUE_BUCKET_KEY, {
        ...previous,
        availableTokens: availableTokens - 1,
        lastRefillAtMs: nowMs,
      } satisfies PatIssueBucket);
      if (boundTenant === null) {
        await storage.put("lifecycle", {
          ...(lifecycle ?? { tenantId: null }),
          tenantId,
        } satisfies LifecycleTenantState);
      }
      return { kind: "allowed" as const };
    });

    if (decision.kind === "tenant-mismatch") {
      return { allowed: false, response: jsonDoError(403, "TENANT_BINDING_MISMATCH", requestId) };
    }
    if (decision.kind === "denied") {
      const response = jsonDoError(429, "PAT_ISSUE_RATE_LIMITED", requestId);
      response.headers.set("Retry-After", String(decision.retryAfterSecs));
      return { allowed: false, response };
    }
    return { allowed: true };
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message.slice(0, 160) : "unknown error";
    console.error(`[${requestId}] PAT issue rate-limit storage unavailable: ${detail}`);
    return { allowed: false, response: jsonDoError(503, "RATE_LIMIT_UNAVAILABLE", requestId) };
  }
}
