import type { Env } from "./index_common.js";
import { requireDedicatedAdminAuth } from "./lib/internal_auth.js";
import { isStagingD1HttpStatus, type StagingD1HttpStatus } from "./staging_d1_http_contract.js";
import { STAGING_D1_PROBE_WINDOW, STAGING_D1_RUNTIME_PROBE_DO_PREFIX,
  STAGING_D1_RUNTIME_PROBE_PATH } from "./staging_runtime_d1_probe.js";

interface ProofStub {
  executeStagingD1HttpProof(scheduledTime: number): Promise<StagingD1HttpStatus>;
  readStagingD1HttpProof(): Promise<StagingD1HttpStatus>;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: {
    "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
  } });
}

async function boundedBody(request: Request): Promise<unknown> {
  if (request.headers.get("content-type") !== "application/json" || request.body === null) throw new Error("body rejected");
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > 512)) throw new Error("body rejected");
  const reader = request.body.getReader();
  let total = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.length;
      if (total > 512) throw new Error("body rejected");
      chunks.push(chunk.value);
    }
  } finally {
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) as unknown;
}

/** Existing literal intercepted before generic internal-consumer fallback. */
export async function handleStagingD1HttpProof(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  // Temporary workers.dev reachability exposes only this authenticated proof
  // literal: one POST execution or a read-only GET of persisted status.
  // Canonical-domain routes keep their existing behavior. Preview/alias hosts
  // cannot turn the temporary origin into a second application endpoint.
  if (url.hostname.endsWith(".workers.dev") &&
      (url.origin !== "https://corelink-staging.gmhelmold.workers.dev" ||
       url.pathname !== STAGING_D1_RUNTIME_PROBE_PATH || !["POST", "GET"].includes(request.method))) {
    return json({ error: "NOT_FOUND" }, 404);
  }
  if (url.pathname !== STAGING_D1_RUNTIME_PROBE_PATH) return null;
  if (env.ENVIRONMENT !== "staging") return json({ error: "NOT_FOUND" }, 404);
  const auth = requireDedicatedAdminAuth(request, env, "staging-d1-http-proof");
  if (auth !== null) return auth;
  if (url.search !== "" || url.hash !== "" || request.headers.has("authorization") || request.headers.has("cookie")) {
    return json({ error: "STAGING_D1_PROOF_REQUEST_REJECTED" }, 400);
  }
  if (request.method !== "GET" && request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405);
  const release = env.SENTRY_RELEASE ?? "";
  if (!/^[0-9a-f]{40}$/.test(release) ||
      env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
      env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
      env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com") {
    return json({ error: "STAGING_D1_PROOF_UNAVAILABLE" }, 503);
  }
  let scheduledTime: number | undefined;
  if (request.method === "POST") {
    try {
      const body = await boundedBody(request);
      const now = Date.now();
      if (body === null || typeof body !== "object" || Array.isArray(body) || Reflect.ownKeys(body).length !== 3 ||
          !["worker_release", "probe_nonce", "scheduled_time_ms"].every(key => Object.hasOwn(body, key))) throw new Error("body rejected");
      const fields = body as Record<string, unknown>;
      const at = fields["scheduled_time_ms"];
      if (fields["worker_release"] !== release || fields["probe_nonce"] !== STAGING_D1_PROBE_WINDOW.nonce ||
          typeof at !== "number" || !Number.isSafeInteger(at) || at !== Math.floor(now / 120_000) * 120_000 ||
          at < STAGING_D1_PROBE_WINDOW.starts_ms || at > STAGING_D1_PROBE_WINDOW.last_entry_ms ||
          now < STAGING_D1_PROBE_WINDOW.starts_ms || now > STAGING_D1_PROBE_WINDOW.last_entry_ms) throw new Error("body rejected");
      scheduledTime = at;
    } catch { return json({ error: "STAGING_D1_PROOF_REQUEST_REJECTED" }, 400); }
  } else if (request.body !== null || Number(request.headers.get("content-length") ?? "0") !== 0) {
    return json({ error: "STAGING_D1_PROOF_REQUEST_REJECTED" }, 400);
  }
  try {
    const id = env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`);
    const stub = env.CORELINK_SERVER.get(id) as unknown as ProofStub;
    const status = scheduledTime === undefined
      ? await stub.readStagingD1HttpProof() : await stub.executeStagingD1HttpProof(scheduledTime);
    if (!isStagingD1HttpStatus(status, release, Date.now())) throw new Error("receipt rejected");
    return json(status, status.status === "running" ? 202 : status.status === "unknown" ? 409 : 200);
  } catch {
    // The host must retain UNKNOWN. A lost response never proves server stop.
    return json({ error: "STAGING_D1_PROOF_UNAVAILABLE" }, 503);
  }
}
