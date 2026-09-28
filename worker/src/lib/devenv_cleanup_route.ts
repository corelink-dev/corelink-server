/** System-only DevEnv credential lifecycle HTTP boundary. */
import type {
  DurableObjectState,
  DurableObjectStorage,
} from "@cloudflare/workers-types";
import type { Env } from "../index.js";
import { requireConsumerAuth } from "./internal_auth.js";
import {
  adoptDevenvOperation,
  bounded as boundedDevenvCleanup,
  drainDevenvOperations,
  prepareDevenvOperation,
  revokeDevenvOperation,
} from "./devenv_cleanup.js";
import { drainRunnerOperations } from "./runner_credential_obligation.js";
import { isCanonicalTenantUuid } from "./tenant_uuid.js";

const DEVENV_CLEANUP_MAX_BODY_BYTES = 16 * 1024;
const DEVENV_CLEANUP_UUID = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DEVENV_CLEANUP_GENERATION = /^(0|[1-9][0-9]*)$/;
const DEVENV_CLEANUP_MAX_GENERATION = 9_223_372_036_854_775_807n;

function validDevenvCleanupOperationId(value: unknown): value is string {
  return typeof value === "string" && DEVENV_CLEANUP_UUID.test(value);
}

function validDevenvCleanupGeneration(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 19 || !DEVENV_CLEANUP_GENERATION.test(value)) return false;
  try { return BigInt(value) <= DEVENV_CLEANUP_MAX_GENERATION; } catch { return false; }
}

/** Drain both credential obligation queues independently; either failure stays pending. */
export async function drainCredentialCleanupObligations(
  storage: DurableObjectStorage,
  db: D1Database,
  kv: { delete(key: string): Promise<void> } | undefined,
  now: number,
): Promise<boolean> {
  let cleanupPending = false;
  try {
    cleanupPending = (await drainDevenvOperations(storage, db, kv, now)) || cleanupPending;
  } catch {
    cleanupPending = true;
  }
  try {
    cleanupPending = (await drainRunnerOperations(storage, db, kv, now)) || cleanupPending;
  } catch {
    cleanupPending = true;
  }
  return cleanupPending;
}

export async function handleDevenvCleanupRequest(
  request: Request,
  env: Env,
  state: Pick<DurableObjectState, "id">,
  storage: DurableObjectStorage,
  requestId: string,
  action: "prepare" | "adopt" | "revoke",
): Promise<Response> {
  if (typeof env.CORELINK_RUNNER_MINT_AUTH_KEY !== "string" || env.CORELINK_RUNNER_MINT_AUTH_KEY.length < 32) {
    return new Response(null, { status: 503, headers: { "X-Request-Id": requestId } });
  }
  const denied = requireConsumerAuth(request, env, "runner_mint", requestId);
  if (denied) return denied;
  if (request.method !== "POST" || !state.id.equals(env.CORELINK_SERVER.idFromName("_system"))) {
    return new Response(null, { status: 403, headers: { "X-Request-Id": requestId } });
  }
  try {
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null && /^(?:0|[1-9][0-9]*)$/.test(contentLength) && Number(contentLength) > DEVENV_CLEANUP_MAX_BODY_BYTES) {
      return new Response(null, { status: 413, headers: { "X-Request-Id": requestId } });
    }
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    if (reader) {
      try {
        for (;;) {
          const part = await boundedDevenvCleanup(reader.read());
          if (part.done) break;
          bytes += part.value.byteLength;
          if (bytes > DEVENV_CLEANUP_MAX_BODY_BYTES) {
            await reader.cancel();
            return new Response(null, { status: 413, headers: { "X-Request-Id": requestId } });
          }
          chunks.push(part.value);
        }
      } finally { reader.releaseLock(); }
    }
    const raw = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength; }
    let body: unknown;
    try { body = JSON.parse(new TextDecoder().decode(raw)); }
    catch { return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } }); }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } });
    }
    const input = body as Record<string, unknown>;
    const expectedKeys = action === "prepare" ? ["lifecycleGeneration", "operationId", "tenantId"] : action === "adopt" ? ["operationId", "patId", "tenantId"] : ["operationId", "tenantId"];
    const actualKeys = Object.keys(input).sort();
    if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys.sort()[index])) {
      return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } });
    }
    const operationId = input["operationId"];
    const tenantId = input["tenantId"];
    if (!validDevenvCleanupOperationId(operationId) || !isCanonicalTenantUuid(tenantId)) {
      return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } });
    }
    let ok: boolean;
    if (action === "prepare") {
      const generation = input["lifecycleGeneration"];
      if (!validDevenvCleanupGeneration(generation)) return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } });
      ok = await prepareDevenvOperation(storage, env.CONFIG_DB, operationId, tenantId, Date.now(), generation);
    } else if (action === "adopt") {
      if (typeof input["patId"] !== "string" || input["patId"].trim() !== input["patId"] || input["patId"].length === 0) {
        return new Response(null, { status: 400, headers: { "X-Request-Id": requestId } });
      }
      ok = await adoptDevenvOperation(env.CONFIG_DB, operationId, tenantId, input["patId"]);
    } else {
      ok = await revokeDevenvOperation(env.CONFIG_DB, env.METADATA_KV, operationId, tenantId);
    }
    return new Response(null, { status: ok ? 204 : action === "prepare" ? 503 : 409, headers: { "X-Request-Id": requestId } });
  } catch {
    return new Response(null, { status: 503, headers: { "X-Request-Id": requestId } });
  }
}
