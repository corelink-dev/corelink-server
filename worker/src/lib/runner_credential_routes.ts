import type { DurableObjectStorage, DurableObjectState, DurableObjectNamespace } from "@cloudflare/workers-types";
import type { Env } from "../index.js";
import {
  adoptRunnerOperation,
  prepareRunnerOperation as prepareRunnerOperationMarker,
  type RunnerCredentialOperation,
} from "./runner_credential_obligation.js";
import { requireConsumerAuth } from "./internal_auth.js";
import { isCanonicalTenantUuid } from "./tenant_uuid.js";

const OPERATION_ID = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GENERATION = /^(0|[1-9][0-9]*)$/;
const MAX_GENERATION = 9_223_372_036_854_775_807n;

function response(status: number, requestId: string): Response {
  return new Response(null, { status, headers: { "X-Request-Id": requestId } });
}

async function bounded<T>(work: Promise<T>, ms = 5_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("runner credential dependency timeout")), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function operationBody(value: unknown): RunnerCredentialOperation | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  const operationId = body["operationId"];
  const tenantId = body["tenantId"];
  const jobId = body["jobId"];
  const repo = body["repo"];
  const lifecycleGeneration = body["lifecycleGeneration"];
  if (
    typeof operationId !== "string" || !OPERATION_ID.test(operationId) ||
    !isCanonicalTenantUuid(tenantId) ||
    typeof jobId !== "string" || jobId.length === 0 || jobId !== jobId.trim() ||
    typeof repo !== "string" || repo.length === 0 || repo !== repo.trim() ||
    typeof lifecycleGeneration !== "string" || lifecycleGeneration.length > 19 ||
    !GENERATION.test(lifecycleGeneration) || BigInt(lifecycleGeneration) > MAX_GENERATION
  ) return null;
  return { operationId, tenantId, jobId, repo, lifecycleGeneration };
}

async function json(request: Request): Promise<unknown> {
  return bounded(request.json());
}

/** Worker-side forwarder: issuer prepares the _system DO before minting. */
export async function prepareRunnerCredential(
  env: Env,
  requestId: string,
  operation: RunnerCredentialOperation,
): Promise<boolean> {
  try {
    // Preparation is a credential lifecycle authority call. It must never be
    // widened by the shared internal key fallback used by legacy routes.
    const auth = env.CORELINK_RUNNER_MINT_AUTH_KEY;
    if (typeof auth !== "string" || auth.length < 32) return false;
    const namespace = env.CORELINK_SERVER as DurableObjectNamespace;
    const stub = namespace.get(namespace.idFromName("_system"));
    const request = new Request("https://do/_do/runner-cleanup/prepare", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-request-id": requestId,
        "x-corelink-route-kind": "runner_cleanup_prepare",
        "x-corelink-tenant-id": "_system",
        "x-corelink-internal-auth": auth,
      },
      body: JSON.stringify({
        operationId: operation.operationId,
        tenantId: operation.tenantId,
        jobId: operation.jobId,
        repo: operation.repo,
        lifecycleGeneration: operation.lifecycleGeneration,
      }),
    });
    return (await bounded(stub.fetch(request))).status === 204;
  } catch {
    return false;
  }
}

/** Private _system DO handler; no upstream response body is exposed. */
export async function handleRunnerPrepare(
  request: Request,
  env: Env,
  state: Pick<DurableObjectState, "id">,
  storage: DurableObjectStorage,
  requestId: string,
): Promise<Response> {
  if (typeof env.CORELINK_RUNNER_MINT_AUTH_KEY !== "string" || env.CORELINK_RUNNER_MINT_AUTH_KEY.length < 32) {
    return response(503, requestId);
  }
  const denied = requireConsumerAuth(request, env, "runner_mint", requestId);
  if (denied) return denied;
  if (request.method !== "POST" || !state.id.equals(env.CORELINK_SERVER.idFromName("_system"))) {
    return response(403, requestId);
  }
  try {
    let parsed: unknown;
    try {
      parsed = await json(request);
    } catch {
      return response(400, requestId);
    }
    const operation = operationBody(parsed);
    if (operation === null) return response(400, requestId);
    const ok = await prepareRunnerOperationMarker(storage, env.CONFIG_DB, operation, Date.now());
    return response(ok ? 204 : 503, requestId);
  } catch {
    return response(503, requestId);
  }
}

/** Public dispatcher adoption acknowledgement; only status conveys the result. */
export async function handleRunnerAdopt(
  request: Request,
  env: Env,
  requestId: string,
): Promise<Response> {
  if (typeof env.CORELINK_RUNNER_MINT_AUTH_KEY !== "string" || env.CORELINK_RUNNER_MINT_AUTH_KEY.length < 32) {
    return response(503, requestId);
  }
  const denied = requireConsumerAuth(request, env, "runner_mint", requestId);
  if (denied) return denied;
  if (request.method !== "POST") return response(405, requestId);
  try {
    const body = await json(request);
    if (body === null || typeof body !== "object" || Array.isArray(body)) return response(400, requestId);
    const input = body as Record<string, unknown>;
    const operationId = input["operation_id"];
    const patId = input["pat_id"];
    if (
      typeof operationId !== "string" || !OPERATION_ID.test(operationId) ||
      typeof patId !== "string" || patId.length === 0 || patId !== patId.trim()
    ) return response(400, requestId);
    const adopted = await adoptRunnerOperation(env.CONFIG_DB, operationId, patId);
    return response(adopted ? 204 : 409, requestId);
  } catch {
    return response(503, requestId);
  }
}
