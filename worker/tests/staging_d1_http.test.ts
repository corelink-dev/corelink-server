import { afterEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/index_common.js";
import { baseHandler } from "../src/index_fetch.js";
import { handleStagingD1HttpProof } from "../src/staging_d1_http.js";
import { isStagingD1HttpStatus, STAGING_D1_HTTP_CONTRACT } from "../src/staging_d1_http_contract.js";
import { STAGING_D1_PROBE_WINDOW as window, STAGING_D1_RUNTIME_PROBE_PATH as PATH } from "../src/staging_runtime_d1_probe.js";
import { OLD_PROBE_RELEASE, V5_PROBE_RELEASE } from "../src/staging_d1_probe_retirement.js";
import { V8_PROBE_RELEASE, V8_PROBE_NONCE } from "../src/staging_d1_probe_v8_cleanup.js";
import { V9_PROBE_RELEASE, V9_PROBE_NONCE } from "../src/staging_d1_probe_v9_cleanup.js";

const RELEASE = "0123456789abcdef0123456789abcdef01234567";
const SECRET = "dedicated-admin-sentinel-not-for-forwarding-123456789";
const NOW = window.starts_ms + 125_000;
const AT = window.starts_ms + 120_000;
const ORIGIN = "https://corelink-staging.gmhelmold.workers.dev";
const BODY = { worker_release: RELEASE, probe_nonce: window.nonce, scheduled_time_ms: AT };

function cleanup(version: "v8" | "v9") {
  return { contract: `corelink-staging-${version}-cleanup-v1`,
    old_release: version === "v8" ? V8_PROBE_RELEASE : V9_PROBE_RELEASE,
    old_nonce: version === "v8" ? V8_PROBE_NONCE : V9_PROBE_NONCE,
    worker_release: RELEASE, prior_execution: "unknown", prior_admission_present: false,
    container_stopped: true, alarm_absent: true, tables_absent: true, completed_at_ms: NOW };
}

function complete() {
  return { contract: STAGING_D1_HTTP_CONTRACT, carrier: "authenticated_http", worker_release: RELEASE,
    probe_nonce: window.nonce, status: "complete", rollback_safe: true,
    native_receipt: { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
      probe_nonce: window.nonce, worker_release: RELEASE, scheduled_time_ms: AT,
      parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
      probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true,
      cf_api_token_absent: true, v4_probe_catalog_absent: true, old_probe_release: OLD_PROBE_RELEASE,
      old_probe_retired: true, old_probe_tables_absent: true, v5_probe_release: V5_PROBE_RELEASE,
      v5_probe_retired: true, v5_probe_tables_absent: true, v5_prior_execution: "unknown" },
    v8_cleanup: cleanup("v8"), v9_cleanup: cleanup("v9") };
}

function setup(result: unknown = complete()) {
  vi.useFakeTimers(); vi.setSystemTime(NOW);
  const execute = vi.fn().mockResolvedValue(result);
  const read = vi.fn().mockResolvedValue(result);
  const target = { ENVIRONMENT: "staging", SENTRY_RELEASE: RELEASE,
    CORELINK_ADMIN_AUTH_KEY: SECRET, CORELINK_INTERNAL_AUTH_KEY: "shared-fallback-sentinel".repeat(2),
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
    R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
    CORELINK_SERVER: { idFromName: vi.fn((name: string) => ({ name })), get: vi.fn(() => ({
      executeStagingD1HttpProof: execute, readStagingD1HttpProof: read })) },
  } as unknown as Env;
  return { target, execute, read };
}

function request(body: unknown = BODY, headers: Record<string, string> = {}, suffix = "") {
  return new Request(`${ORIGIN}${PATH}${suffix}`, { method: "POST",
    headers: { "x-corelink-internal-auth": SECRET, "content-type": "application/json", ...headers },
    body: JSON.stringify(body) });
}

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("dedicated authenticated HTTP native proof carrier", () => {
  it("intercepts the existing literal in the real Worker before generic auth and passes only the numeric admission tag", async () => {
    const { target, execute } = setup();
    const response = await baseHandler.fetch!(request(), target, {} as never);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual(complete());
    expect(execute).toHaveBeenCalledExactlyOnceWith(AT);
    expect(JSON.stringify(execute.mock.calls)).not.toContain(SECRET);
    expect(target.CORELINK_SERVER.idFromName).toHaveBeenCalledExactlyOnceWith(`_staging_d1_binding_probe_v2:${window.nonce}:${RELEASE}`);
  });

  it("reads persisted status without invoking execution", async () => {
    const { target, execute, read } = setup();
    const response = await handleStagingD1HttpProof(new Request(`${ORIGIN}${PATH}`, {
      headers: { "x-corelink-internal-auth": SECRET } }), target);
    expect(response?.status).toBe(200); expect(read).toHaveBeenCalledExactlyOnceWith();
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([undefined, "", "short"])("has no shared-key fallback when dedicated binding is %s", async key => {
    const { target, execute } = setup(); target.CORELINK_ADMIN_AUTH_KEY = key;
    const response = await handleStagingD1HttpProof(request(BODY, {
      "x-corelink-internal-auth": target.CORELINK_INTERNAL_AUTH_KEY! }), target);
    expect(response?.status).toBe(503); expect(execute).not.toHaveBeenCalled();
  });

  it.each(["", "wrong", "shared-fallback-sentinel".repeat(2)])("rejects missing/invalid/shared authentication", async key => {
    const { target, execute } = setup();
    const response = await handleStagingD1HttpProof(request(BODY, { "x-corelink-internal-auth": key }), target);
    expect(response?.status).toBe(401); expect(execute).not.toHaveBeenCalled();
    expect(await response?.text()).not.toContain(SECRET);
  });

  it.each(["production", "development", undefined])("hides the literal outside staging", async environment => {
    const { target, execute } = setup(); target.ENVIRONMENT = environment as Env["ENVIRONMENT"];
    expect((await handleStagingD1HttpProof(request(), target))?.status).toBe(404);
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([
    { ...BODY, worker_release: "f".repeat(40) }, { ...BODY, probe_nonce: V9_PROBE_NONCE },
    { ...BODY, scheduled_time_ms: AT - 120_000 }, { ...BODY, scheduled_time_ms: AT + 1 },
    { ...BODY, scheduled_time_ms: AT + 120_000 }, { ...BODY, secret: SECRET },
    { worker_release: RELEASE, probe_nonce: window.nonce }, null, [], "x".repeat(513),
  ])("rejects altered or unbounded POST before any DO call", async body => {
    const { target, execute } = setup();
    expect((await handleStagingD1HttpProof(request(body), target))?.status).toBe(400);
    expect(target.CORELINK_SERVER.get).not.toHaveBeenCalled(); expect(execute).not.toHaveBeenCalled();
  });

  it.each([{ authorization: "Bearer secret" }, { cookie: "private=value" }, { "content-type": "text/plain" }])(
    "rejects native credential leakage and unsupported content type", async headers => {
      const { target, execute } = setup();
      expect((await handleStagingD1HttpProof(request(BODY, headers as Record<string, string>), target))?.status).toBe(400);
      expect(execute).not.toHaveBeenCalled();
    });

  it("rejects queries and non-GET/POST methods without RPC side effects", async () => {
    const { target, execute } = setup();
    expect((await handleStagingD1HttpProof(request(BODY, {}, "?operation=execute"), target))?.status).toBe(400);
    expect((await handleStagingD1HttpProof(new Request(`https://staging.corelink.humangr.com${PATH}`, { method: "DELETE",
      headers: { "x-corelink-internal-auth": SECRET } }), target))?.status).toBe(405);
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([
    [ORIGIN, "/", "GET"], [ORIGIN, "/v1/users/me", "GET"], [ORIGIN, "/v1/admin/mutate", "POST"],
    [ORIGIN, "/_health/container/authenticated", "GET"],
    [ORIGIN, PATH, "HEAD"], [ORIGIN, PATH, "OPTIONS"], [ORIGIN, PATH, "DELETE"],
    ["https://preview-corelink-staging.gmhelmold.workers.dev", PATH, "POST"],
    ["http://corelink-staging.gmhelmold.workers.dev", PATH, "POST"],
  ])("denies every other workers.dev path, method and origin even with admin auth", async (origin, path, method) => {
    const { target, execute, read } = setup();
    const response = await baseHandler.fetch!(new Request(`${origin}${path}`, {
      method, headers: { "x-corelink-internal-auth": SECRET },
    }), target, {} as never);
    expect(response.status).toBe(404); expect(execute).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled();
    expect(target.CORELINK_SERVER.get).not.toHaveBeenCalled();
  });

  it("leaves unrelated canonical requests with the normal routing pipeline", async () => {
    const { target } = setup();
    expect(await handleStagingD1HttpProof(new Request("https://staging.corelink.humangr.com/v1/users/me"), target)).toBeNull();
  });

  it.each([window.starts_ms - 1, window.last_entry_ms + 1, window.expires_ms])("rejects entry time boundary %s", async now => {
    const { target, execute } = setup(); vi.setSystemTime(now);
    const body = { ...BODY, scheduled_time_ms: Math.floor(now / 120_000) * 120_000 };
    expect((await handleStagingD1HttpProof(request(body), target))?.status).toBe(400);
    expect(execute).not.toHaveBeenCalled();
  });

  it("never serializes an RPC error or unvalidated provider payload", async () => {
    const { target, execute } = setup(); execute.mockRejectedValueOnce(new Error(SECRET));
    const response = await handleStagingD1HttpProof(request(), target);
    expect(response?.status).toBe(503);
    expect(await response?.text()).toBe('{"error":"STAGING_D1_PROOF_UNAVAILABLE"}');
    execute.mockResolvedValue({ ...complete(), provider_error: SECRET });
    expect((await handleStagingD1HttpProof(request(), target))?.status).toBe(503);
  });

  it.each(["unknown", "running", "not_started"])("never authorizes rollback for %s", async status => {
    const value = { ...complete(), status, rollback_safe: false, native_receipt: null, v8_cleanup: null, v9_cleanup: null };
    const { target } = setup(value);
    expect(isStagingD1HttpStatus(value, RELEASE, NOW)).toBe(true);
    const response = await handleStagingD1HttpProof(request(), target);
    expect(response?.status).toBe(status === "unknown" ? 409 : status === "running" ? 202 : 200);
    expect(isStagingD1HttpStatus({ ...value, rollback_safe: true }, RELEASE, NOW)).toBe(false);
  });

  it("requires exactly native20 and independent exact v8/v9 cleanup10 receipts", () => {
    setup(); const good = complete();
    expect(Object.keys(good).length).toBe(9); expect(Object.keys(good.native_receipt).length).toBe(20);
    expect(Object.keys(good.v8_cleanup).length).toBe(10); expect(Object.keys(good.v9_cleanup).length).toBe(10);
    expect(isStagingD1HttpStatus(good, RELEASE, NOW)).toBe(true);
    for (const field of Object.keys(good.native_receipt)) {
      const native = { ...good.native_receipt } as Record<string, unknown>; delete native[field];
      expect(isStagingD1HttpStatus({ ...good, native_receipt: native }, RELEASE, NOW)).toBe(false);
    }
    for (const mutation of [
      { native_receipt: { ...good.native_receipt, extra: true } },
      { native_receipt: { ...good.native_receipt, worker_release: V9_PROBE_RELEASE } },
      { native_receipt: { ...good.native_receipt, authorization_absent: false } },
      { native_receipt: { ...good.native_receipt, old_probe_release: RELEASE } },
      { v8_cleanup: null }, { v9_cleanup: null }, { v9_cleanup: good.v8_cleanup },
      { v9_cleanup: { ...good.v9_cleanup, prior_execution: "not_executed" } },
      { v9_cleanup: { ...good.v9_cleanup, worker_release: V9_PROBE_RELEASE } },
      { carrier: "cron" }, { rollback_safe: false }, { scheduled: true },
    ]) expect(isStagingD1HttpStatus({ ...good, ...mutation }, RELEASE, NOW)).toBe(false);
  });
});
