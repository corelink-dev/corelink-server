import { describe, expect, it, vi } from "vitest";

import type { Env } from "../src/index_common.js";
import { STAGING_GRPC_DIAGNOSTIC_PATHS } from "../src/grpc_staging_authorization.js";
import { rejectUnprovenGrpcTransport } from "../src/grpc_transport_gate.js";
import { baseHandler } from "../src/index_fetch.js";
import { STAGING_D1_RUNTIME_PROBE_PATH } from "../src/staging_runtime_d1_probe.js";

describe("rejectUnprovenGrpcTransport", () => {
  it("rejects native gRPC before it can reach the unproved transport bridge", async () => {
    const authorization = "Bearer never-reflect-this-test-token";
    const response = rejectUnprovenGrpcTransport(
      new Request(
        "https://corelink-api.humangr.com/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchReadBlobs",
        {
          headers: {
            authorization,
            "content-type": "application/grpc+proto; charset=utf-8",
          },
        },
      ),
    );

    expect(response).not.toBeNull();
    expect(response?.status).toBe(503);
    expect(response?.headers.get("cache-control")).toBe("no-store");
    expect(response?.headers.get("content-type")).toBe("application/json; charset=utf-8");
    const body = await response?.text();
    expect(body).toBe('{"error":"GRPC_TRANSPORT_UNAVAILABLE"}');
    expect(body).not.toContain(authorization);
  });

  it("does not interfere with a non-gRPC request", () => {
    const response = rejectUnprovenGrpcTransport(
      new Request("https://corelink-api.humangr.com/_health", {
        headers: { "content-type": "application/json" },
      }),
    );

    expect(response).toBeNull();
  });
});

const ADMIN_KEY = "dedicated-admin-sentinel-not-for-forwarding-123456789";
const PROBE_TOKEN = "x".repeat(32);
const CANONICAL = "https://staging.corelink.humangr.com";
const WORKERS_DEV = "https://corelink-staging.gmhelmold.workers.dev";
const DENIED = '{"error":"GRPC_TRANSPORT_UNAVAILABLE"}';

/** A staging env under which both the D1 proof and the diagnostic would reach a DO. */
function pipeline() {
  const proofRead = vi.fn().mockResolvedValue({});
  const proofExecute = vi.fn().mockResolvedValue({});
  const diagnosticFetch = vi.fn(async (_request: Request) => new Response(new Uint8Array([0, 0, 0, 0, 0]), {
    headers: { "content-type": "application/grpc" },
  }));
  const idFromName = vi.fn((name: string) => ({ name }));
  const get = vi.fn(() => ({
    executeStagingD1HttpProof: proofExecute, readStagingD1HttpProof: proofRead, fetch: diagnosticFetch,
  }));
  const env = {
    ENVIRONMENT: "staging", CORELINK_ENVIRONMENT: "staging",
    SENTRY_RELEASE: "0123456789abcdef0123456789abcdef01234567",
    CORELINK_ADMIN_AUTH_KEY: ADMIN_KEY,
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
    R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
    CORELINK_STAGING_GRPC_PROBE_TOKEN: PROBE_TOKEN,
    CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS: String(Date.now() + 60_000),
    CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA: "a".repeat(40),
    CORELINK_STAGING_GRPC_PROBE_WORKER_NAME: "corelink-staging",
    CORELINK_SERVER: { idFromName, get },
  } as unknown as Env;
  return { env, idFromName, get, proofRead, proofExecute, diagnosticFetch };
}

describe("real Fetch pipeline keeps the #2176 deny first", () => {
  it.each([
    [CANONICAL, STAGING_D1_RUNTIME_PROBE_PATH, "GET", "application/grpc"],
    [CANONICAL, STAGING_D1_RUNTIME_PROBE_PATH, "GET", "Application/GRPC+proto; charset=utf-8"],
    [CANONICAL, STAGING_D1_RUNTIME_PROBE_PATH, "POST", "application/grpc+proto"],
    [CANONICAL, STAGING_D1_RUNTIME_PROBE_PATH, "POST", "application/grpc-web+proto"],
    [WORKERS_DEV, STAGING_D1_RUNTIME_PROBE_PATH, "GET", "application/grpc"],
    [WORKERS_DEV, STAGING_D1_RUNTIME_PROBE_PATH, "POST", "application/grpc+proto"],
    [WORKERS_DEV, STAGING_D1_RUNTIME_PROBE_PATH, "POST", "application/grpc-web"],
    [WORKERS_DEV, "/v1/users/me", "GET", "application/grpc"],
  ])("denies gRPC-shaped %s%s %s (%s) with 503 before any Durable Object", async (origin, path, method, contentType) => {
    const { env, idFromName, get, proofRead, proofExecute, diagnosticFetch } = pipeline();
    const response = await baseHandler.fetch!(new Request(`${origin}${path}`, {
      method,
      headers: { "x-corelink-internal-auth": ADMIN_KEY, "content-type": contentType, te: "trailers" },
      body: method === "POST" ? new Uint8Array([0, 0, 0, 0, 0]) : null,
    }), env, {} as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe(DENIED);
    expect(idFromName).not.toHaveBeenCalled();
    expect(get).not.toHaveBeenCalled();
    expect(proofRead).not.toHaveBeenCalled();
    expect(proofExecute).not.toHaveBeenCalled();
    expect(diagnosticFetch).not.toHaveBeenCalled();
  });

  it("still lets the same authenticated non-gRPC proof read reach its Durable Object", async () => {
    const { env, idFromName, proofRead } = pipeline();
    const response = await baseHandler.fetch!(new Request(`${CANONICAL}${STAGING_D1_RUNTIME_PROBE_PATH}`, {
      headers: { "x-corelink-internal-auth": ADMIN_KEY },
    }), env, {} as never);

    // The stub receipt is invalid, so the proof answers its own 503; the
    // point is that this request was not stopped by the gRPC deny.
    expect(await response.text()).toBe('{"error":"STAGING_D1_PROOF_UNAVAILABLE"}');
    expect(idFromName).toHaveBeenCalledOnce();
    expect(proofRead).toHaveBeenCalledOnce();
  });

  it.each(STAGING_GRPC_DIAGNOSTIC_PATHS)("keeps the protected diagnostic exception %s", async (path) => {
    const { env, idFromName, diagnosticFetch, proofRead } = pipeline();
    const original = new Request(`${CANONICAL}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${PROBE_TOKEN}`, "content-type": "application/grpc", te: "trailers" },
      body: new Uint8Array([0, 0, 0, 0, 0]),
    });
    const response = await baseHandler.fetch!(original, env, {} as never);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/grpc");
    expect(idFromName).toHaveBeenCalledExactlyOnceWith("_staging_grpc_probe_v1");
    expect(diagnosticFetch).toHaveBeenCalledExactlyOnceWith(original);
    expect(proofRead).not.toHaveBeenCalled();
  });
});
