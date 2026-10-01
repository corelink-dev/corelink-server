import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
  WorkerEntrypoint: class {
    ctx: { props: unknown };
    env: unknown;
    constructor(ctx: { props: unknown }, env: unknown) { this.ctx = ctx; this.env = env; }
  },
}));

import type { D1Database, D1PreparedStatement } from "@cloudflare/workers-types";
import type { Env } from "../src/index_env.js";
import { StagingD1BindingProxy } from "../src/staging_d1_binding_proxy_entrypoint.js";
import { createHttpLifetime, httpDeadlineContext } from "../src/staging_d1_http_lifetime.js";
import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";

const ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd";
const DB_ID = "d72a6b39-6a48-4338-bfda-1111dda98604";
const URL = `http://corelink-d1-proxy.invalid/client/v4/accounts/${ACCOUNT}/d1/database/${DB_ID}/query`;
const RELEASE = "a".repeat(40);

function harness(props: unknown, release = RELEASE) {
  const all = vi.fn(async () => ({ results: [{ ok: 1 }], success: true, meta: {} }));
  const bind = vi.fn(() => ({ all }) as unknown as D1PreparedStatement);
  const prepare = vi.fn(() => ({ bind, all }) as unknown as D1PreparedStatement);
  const batch = vi.fn(async () => []);
  const env = {
    CONFIG_DB: { prepare, batch } as unknown as D1Database,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
    D1_DATABASE_ID: DB_ID,
    R2_S3_ENDPOINT: `https://${ACCOUNT}.r2.cloudflarestorage.com`,
    ENVIRONMENT: "staging",
    SENTRY_RELEASE: release,
  } as Env;
  const entrypoint = new StagingD1BindingProxy({ props } as never, env);
  return { entrypoint, prepare, all, batch };
}

function request(headers: HeadersInit = {}) {
  return new Request(URL, {
    method: "POST",
    headers: { "content-type": "application/json", host: "corelink-d1-proxy.invalid", ...headers },
    body: JSON.stringify({ sql: "SELECT 1", params: [] }),
  });
}

describe("StagingD1BindingProxy entrypoint deadline context", () => {
  afterEach(() => vi.restoreAllMocks());

  it("keeps ordinary exact-empty props working and ignores caller deadline headers", async () => {
    const { entrypoint, prepare } = harness({});
    const response = await entrypoint.fetch(request({
      "x-corelink-operation-started-ms": String(window.starts_ms),
      "x-corelink-execution-deadline-ms": String(window.starts_ms + 1),
    }));
    expect(response.status).toBe(200);
    expect(prepare).toHaveBeenCalledExactlyOnceWith("SELECT 1");
  });

  it.each([
    ["extra property", { ...httpDeadlineContext(createHttpLifetime(RELEASE, window.starts_ms)), extra: true }, RELEASE],
    ["wrong release", httpDeadlineContext(createHttpLifetime("b".repeat(40), window.starts_ms)), RELEASE],
    ["wrong nonce", { ...httpDeadlineContext(createHttpLifetime(RELEASE, window.starts_ms)), probe_nonce: "0".repeat(40) }, RELEASE],
    ["wrong arithmetic", { ...httpDeadlineContext(createHttpLifetime(RELEASE, window.starts_ms)), execute_deadline_ms: window.starts_ms + 1 }, RELEASE],
    ["malformed props", { operation_started_ms: window.starts_ms }, RELEASE],
    ["missing props", undefined, RELEASE],
  ])("denies %s without ordinary fallback", async (_label, props, release) => {
    const { entrypoint, prepare, batch } = harness(props, release);
    expect((await entrypoint.fetch(request())).status).toBe(502);
    expect(prepare).not.toHaveBeenCalled();
    expect(batch).not.toHaveBeenCalled();
  });

  it.each([-1, 0, 1])("passes the private context through at T%+d", async (offset) => {
    const context = httpDeadlineContext(createHttpLifetime(RELEASE, window.starts_ms));
    const { entrypoint, prepare, batch } = harness(context);
    vi.spyOn(Date, "now").mockReturnValue(context.execute_deadline_ms + offset);
    const response = await entrypoint.fetch(request());
    if (offset < 0) {
      expect(response.status).toBe(200);
      expect(prepare).toHaveBeenCalledOnce();
    } else {
      expect(response.status).toBe(502);
      expect(prepare).not.toHaveBeenCalled();
    }
    expect(batch).not.toHaveBeenCalled();
  });
});
