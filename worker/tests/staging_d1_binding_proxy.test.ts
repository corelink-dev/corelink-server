import { afterEach, describe, expect, it, vi } from "vitest";
import type { D1Database, D1PreparedStatement } from "@cloudflare/workers-types";
import type { Container, Fetcher } from "@cloudflare/workers-types";
import type { Env } from "../src/index_env.js";
import { handleStagingD1BindingRequest, installD1BindingProxy } from "../src/staging_d1_binding_proxy.js";
import { createHttpLifetime, httpDeadlineContext } from "../src/staging_d1_http_lifetime.js";
import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";

const ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd";
const DB_ID = "d72a6b39-6a48-4338-bfda-1111dda98604";
const URL = `http://corelink-d1-proxy.invalid/client/v4/accounts/${ACCOUNT}/d1/database/${DB_ID}/query`;

function makeEnv(overrides: Partial<Env> = {}) {
  const all = vi.fn(async () => ({ results: [{ ok: 1 }], success: true, meta: {} }));
  const bind = vi.fn(() => ({ all }) as unknown as D1PreparedStatement);
  const prepare = vi.fn(() => ({ bind, all }) as unknown as D1PreparedStatement);
  const batch = vi.fn(async (statements: D1PreparedStatement[]) =>
    statements.map(() => ({ results: [], success: true, meta: {} })),
  );
  const env = {
    CONFIG_DB: { prepare, batch } as unknown as D1Database,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
    D1_DATABASE_ID: DB_ID,
    R2_S3_ENDPOINT: `https://${ACCOUNT}.r2.cloudflarestorage.com`,
    ENVIRONMENT: "staging",
    CORELINK_ENVIRONMENT: "staging",
    ...overrides,
  } as Env;
  return { env, prepare, bind, all, batch };
}

function request(body: unknown, url = URL, headers: HeadersInit = {}) {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json", host: "corelink-d1-proxy.invalid", ...headers },
    body: JSON.stringify(body),
  });
}

describe("staging D1 binding proxy", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each([-1, 0, 1])("enforces execution deadline at T%+d before reading the body", async (offset) => {
    const start = window.starts_ms;
    const context = httpDeadlineContext(createHttpLifetime("a".repeat(40), start));
    vi.spyOn(Date, "now").mockReturnValue(context.execute_deadline_ms + offset);
    const { env, prepare, batch } = makeEnv();
    const req = request({ sql: "SELECT 1", params: [] });
    const read = vi.spyOn(req, "arrayBuffer");
    const response = await handleStagingD1BindingRequest(req, env, context);
    if (offset < 0) {
      expect(response.status).toBe(200);
      expect(read).toHaveBeenCalledOnce();
      expect(prepare).toHaveBeenCalledOnce();
    } else {
      expect(response.status).toBe(502);
      expect(read).not.toHaveBeenCalled();
      expect(prepare).not.toHaveBeenCalled();
    }
    expect(batch).not.toHaveBeenCalled();
  });

  it.each([-1, 0, 1])("checks after delayed body at T%+d", async (offset) => {
    const start = window.starts_ms;
    const context = httpDeadlineContext(createHttpLifetime("a".repeat(40), start));
    let now = start;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const { env, prepare, batch } = makeEnv();
    const req = request({ sql: "SELECT 1", params: [] });
    vi.spyOn(req, "arrayBuffer").mockImplementation(async () => {
      now = context.execute_deadline_ms + offset;
      return new TextEncoder().encode(JSON.stringify({ sql: "SELECT 1", params: [] })).buffer;
    });
    const response = await handleStagingD1BindingRequest(req, env, context);
    if (offset < 0) {
      expect(response.status).toBe(200);
      expect(prepare).toHaveBeenCalledOnce();
    } else {
      expect(response.status).toBe(502);
      expect(prepare).not.toHaveBeenCalled();
    }
    expect(batch).not.toHaveBeenCalled();
  });

  it("fails a late native D1 result without permitting further SQL", async () => {
    const start = window.starts_ms;
    const context = httpDeadlineContext(createHttpLifetime("a".repeat(40), start));
    let now = start;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const { env, prepare, all, batch } = makeEnv();
    all.mockImplementationOnce(async () => {
      now = context.execute_deadline_ms;
      return { results: [], success: true, meta: {} };
    });
    expect((await handleStagingD1BindingRequest(request({ sql: "SELECT 1", params: [] }), env, context)).status).toBe(502);
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(batch).not.toHaveBeenCalled();
  });

  it("fails a late D1 batch result after dispatch", async () => {
    const start = window.starts_ms;
    const context = httpDeadlineContext(createHttpLifetime("a".repeat(40), start));
    let now = start;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const { env, prepare, batch } = makeEnv();
    batch.mockImplementationOnce(async (statements) => {
      now = context.execute_deadline_ms;
      return statements.map(() => ({ results: [], success: true, meta: {} }));
    });
    expect((await handleStagingD1BindingRequest(request({ batch: [
      { sql: "INSERT INTO x VALUES (1)", params: [] },
    ] }), env, context)).status).toBe(502);
    expect(prepare).toHaveBeenCalledOnce();
    expect(batch).toHaveBeenCalledOnce();
  });

  it("installs an exact reserved non-routable hostname interceptor", async () => {
    const interceptOutboundHttp = vi.fn(async () => {});
    const binding = { fetch: vi.fn() } as unknown as Fetcher;
    await installD1BindingProxy({ interceptOutboundHttp } as unknown as Pick<Container, "interceptOutboundHttp">, binding);
    expect(interceptOutboundHttp).toHaveBeenCalledExactlyOnceWith("corelink-d1-proxy.invalid", binding);
  });

  it("rejects an absent Container before installing an interceptor", async () => {
    const fetch = vi.fn();
    await expect(installD1BindingProxy(undefined, { fetch } as unknown as Fetcher))
      .rejects.toThrow("staging D1 Container is unavailable");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    { label: "overlong", bytes: [0xc0, 0xaf] },
    { label: "surrogate", bytes: [0xed, 0xa0, 0x80] },
    { label: "outside Unicode", bytes: [0xf4, 0x90, 0x80, 0x80] },
    { label: "truncated", bytes: [0xe2, 0x82] },
    { label: "continuation", bytes: [0x80] },
  ])("rejects malformed UTF-8 before touching D1 ($label)", async ({ bytes: invalid }) => {
    const { env, prepare, batch } = makeEnv();
    const prefix = new TextEncoder().encode('{"sql":"SELECT ?","params":["');
    const suffix = new TextEncoder().encode('"]}');
    const bytes = new Uint8Array([...prefix, ...invalid, ...suffix]);
    const req = new Request(URL, {
      method: "POST",
      headers: { "content-type": "application/json", host: "corelink-d1-proxy.invalid" },
      body: bytes,
    });
    expect((await handleStagingD1BindingRequest(req, env)).status).toBe(400);
    expect(prepare).not.toHaveBeenCalled();
    expect(batch).not.toHaveBeenCalled();
  });

  it.each([false, true])("preserves valid UTF-8 with optional leading BOM (%s)", async (bom) => {
    const { env, bind } = makeEnv();
    const json = new TextEncoder().encode(JSON.stringify({ sql: "SELECT ?", params: ["ação 🙂"] }));
    const req = new Request(URL, {
      method: "POST",
      headers: { "content-type": "application/json", host: "corelink-d1-proxy.invalid" },
      body: new Uint8Array([...(bom ? [0xef, 0xbb, 0xbf] : []), ...json]),
    });
    expect((await handleStagingD1BindingRequest(req, env)).status).toBe(200);
    expect(bind).toHaveBeenCalledWith("ação 🙂");
  });

  it("executes a parameterized query on the fixed CONFIG_DB binding and returns the REST envelope", async () => {
    const { env, prepare, bind } = makeEnv();
    const response = await handleStagingD1BindingRequest(
      request({ sql: "SELECT ? AS ok", params: [1] }),
      env,
    );
    expect(response.status).toBe(200);
    expect(prepare).toHaveBeenCalledWith("SELECT ? AS ok");
    expect(bind).toHaveBeenCalledWith(1);
    expect(await response.json()).toEqual({
      result: [{ results: [{ ok: 1 }], success: true }],
      success: true,
      errors: [],
    });
  });

  it("dispatches one bounded batch through D1Database.batch", async () => {
    const { env, prepare, batch } = makeEnv();
    const response = await handleStagingD1BindingRequest(
      request({ batch: [
        { sql: "INSERT INTO x VALUES (?)", params: [1] },
        { sql: "INSERT INTO x VALUES (?)", params: [2] },
      ] }),
      env,
    );
    expect(response.status).toBe(200);
    expect(prepare).toHaveBeenCalledTimes(2);
    expect(batch).toHaveBeenCalledTimes(1);
    expect((await response.json()).success).toBe(true);
  });

  it.each([
    ["wrong host", `http://corelink-d1-proxy.invalid.evil/client/v4/accounts/${ACCOUNT}/d1/database/${DB_ID}/query`, {}, 404],
    ["wrong account", URL.replace(ACCOUNT, "0".repeat(32)), {}, 404],
    ["wrong database", URL.replace(DB_ID, "0".repeat(36)), {}, 404],
    ["wrong method", URL, { method: "GET" }, 404],
    ["explicit default HTTP port authority", URL, { host: "corelink-d1-proxy.invalid:80" }, 404],
    ["explicit HTTPS port authority", URL.replace("/client", ":443/client"), { host: "corelink-d1-proxy.invalid:443" }, 404],
    ["explicit alternate port authority", URL.replace("/client", ":8080/client"), { host: "corelink-d1-proxy.invalid:8080" }, 404],
    ["malformed authority", URL, { host: "user@corelink-d1-proxy.invalid" }, 404],
    ["authorization header", URL, { authorization: "Bearer never-forward" }, 400],
  ])("rejects %s before touching D1", async (_case, url, extra, expectedStatus) => {
    const { env, prepare, batch } = makeEnv();
    const req = new Request(url, {
      method: extra.method ?? "POST",
      headers: { "content-type": "application/json", host: "corelink-d1-proxy.invalid", ...extra },
      body: extra.method === "GET" ? undefined : JSON.stringify({ sql: "SELECT 1", params: [] }),
    });
    const response = await handleStagingD1BindingRequest(req, env);
    expect(response.status).toBe(expectedStatus);
    expect(prepare).not.toHaveBeenCalled();
    expect(batch).not.toHaveBeenCalled();
  });

  it("rejects invalid staging identity and malformed or extended request bodies", async () => {
    const invalidTarget = makeEnv({ D1_DATABASE_ID: "0".repeat(36) });
    expect((await handleStagingD1BindingRequest(request({ sql: "SELECT 1", params: [] }), invalidTarget.env)).status).toBe(503);
    const { env, prepare } = makeEnv();
    for (const body of [
      { sql: "SELECT 1", params: [], extra: true },
      { sql: "SELECT 1", params: [{}] },
      { batch: [] },
    ]) {
      expect((await handleStagingD1BindingRequest(request(body), env)).status).toBe(502);
    }
    expect(prepare).not.toHaveBeenCalled();
  });
});
