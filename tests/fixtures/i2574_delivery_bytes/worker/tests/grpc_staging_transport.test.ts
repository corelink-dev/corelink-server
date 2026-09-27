import { describe, expect, it } from "vitest";

import { type Env } from "../src/index_common.js";
import { rejectUnprovenGrpcTransport } from "../src/grpc_transport_gate.js";
import {
  STAGING_GRPC_DIAGNOSTIC_PATHS,
  verifyStagingGrpcDiagnosticBinding,
} from "../src/grpc_staging_authorization.js";
import { forwardStagingGrpcDiagnostic } from "../src/grpc_staging_transport.js";
import { proxyToContainer } from "../src/durable_object_probes.js";

const NOW = 1_800_000_000_000;
const TOKEN = "x".repeat(32);

function request(init: RequestInit = {}): Request {
  return new Request(
    `https://staging.corelink.humangr.com${STAGING_GRPC_DIAGNOSTIC_PATHS[0]}`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/grpc+proto",
        te: "trailers",
        "x-probe-metadata": "preserve",
      },
      body: new Uint8Array([0, 0, 0, 0, 0]),
      ...init,
    },
  );
}

function environment(response: Response, captured: { name?: string; request?: Request }): Env {
  return {
    CORELINK_SERVER: {
      idFromName(name: string) {
        captured.name = name;
        return { name } as never;
      },
      get() {
        return {
          fetch: async (input: Request) => {
            captured.request = input;
            return response;
          },
        };
      },
    } as unknown as Env["CORELINK_SERVER"],
    CORELINK_ENVIRONMENT: "staging",
    ENVIRONMENT: "staging",
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    CORELINK_STAGING_GRPC_PROBE_TOKEN: TOKEN,
    CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS: String(NOW + 60_000),
    CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA: "a".repeat(40),
    CORELINK_STAGING_GRPC_PROBE_WORKER_NAME: "corelink-staging",
  } as Env;
}

describe("staging gRPC diagnostic boundary", () => {
  it("authenticates then forwards the original request to only the dedicated DO", async () => {
    const upstream = new Response(new Uint8Array([0, 0, 0, 0, 1, 0]), {
      headers: { "content-type": "application/grpc+proto", "x-response-metadata": "preserve" },
    });
    const captured: { name?: string; request?: Request } = {};
    const original = request();

    const actual = await forwardStagingGrpcDiagnostic(original, environment(upstream, captured), NOW);

    expect(captured.name).toBe("_staging_grpc_probe_v1");
    expect(captured.request).toBe(original);
    expect(captured.request?.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(captured.request?.headers.get("x-probe-metadata")).toBe("preserve");
    expect(actual).toBe(upstream);
    expect(actual?.headers.get("x-response-metadata")).toBe("preserve");
  });

  it.each([
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_TOKEN = undefined; },
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_TOKEN = "short"; },
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS = String(NOW); },
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS = String(NOW + 900_001); },
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA = "A".repeat(40); },
    (env: Env) => { env.CORELINK_STAGING_GRPC_PROBE_WORKER_NAME = "corelink-production"; },
    (env: Env) => { env.CLOUDFLARE_ACCOUNT_ID = "production-account"; },
    (env: Env) => { env.CORELINK_ENVIRONMENT = undefined; },
    (env: Env) => { env.CORELINK_ENVIRONMENT = "production"; },
    (env: Env) => { delete (env as Partial<Env>).ENVIRONMENT; },
    (env: Env) => { env.ENVIRONMENT = "production"; },
  ])("fails closed for an invalid protected binding", async (mutate) => {
    const captured: { name?: string; request?: Request } = {};
    const env = environment(new Response(null, { headers: { "content-type": "application/grpc" } }), captured);
    mutate(env);

    const response = await forwardStagingGrpcDiagnostic(request(), env, NOW);

    expect(response?.status).toBe(503);
    expect(captured.request).toBeUndefined();
  });

  it("rejects altered authorization and non-gRPC upstream without exposing either", async () => {
    const captured: { name?: string; request?: Request } = {};
    const env = environment(new Response("not grpc", { headers: { "content-type": "application/json" } }), captured);
    const altered = request({ headers: { authorization: "Bearer altered", "content-type": "application/grpc", te: "trailers" } });

    const authResponse = await forwardStagingGrpcDiagnostic(altered, env, NOW);
    const upstreamResponse = await forwardStagingGrpcDiagnostic(request(), env, NOW);

    expect(authResponse?.status).toBe(503);
    expect(upstreamResponse?.status).toBe(503);
    await expect(upstreamResponse?.text()).resolves.toBe('{"error":"GRPC_TRANSPORT_UNAVAILABLE"}');
  });

  it.each([
    request({ method: "GET", body: undefined }),
    request({ headers: { "content-type": "application/grpc", te: "gzip" } }),
    request({ headers: { "content-type": "application/grpc-web+proto", te: "trailers" } }),
    request({ headers: { "content-type": "application/grpcfoo", te: "trailers" } }),
    request({ headers: { "content-type": "text/plain", te: "trailers" } }),
    new Request(`https://staging.corelink.humangr.com${STAGING_GRPC_DIAGNOSTIC_PATHS[0]}?mode=verified`, { method: "POST", headers: { "content-type": "application/grpc", te: "trailers" } }),
    new Request(`https://corelink.humangr.com${STAGING_GRPC_DIAGNOSTIC_PATHS[0]}`, { method: "POST", headers: { "content-type": "application/grpc", te: "trailers" } }),
    new Request("https://staging.corelink.humangr.com/other.Service/Method", { method: "POST", headers: { "content-type": "application/grpc", te: "trailers" } }),
  ])("keeps unsupported gRPC shapes in the public deny", async (input) => {
    const captured: { name?: string; request?: Request } = {};
    const env = environment(new Response(null, { headers: { "content-type": "application/grpc" } }), captured);

    expect(rejectUnprovenGrpcTransport(input)?.status).toBe(503);
    expect(await forwardStagingGrpcDiagnostic(input, env, NOW)).toBeNull();
    expect(captured.name).toBeUndefined();
    expect(captured.request).toBeUndefined();
  });

  it("constructs a private binding only for a complete authenticated request", () => {
    const env = environment(new Response(null), {});
    expect(verifyStagingGrpcDiagnosticBinding(request(), env, NOW)).not.toBeNull();
    expect(verifyStagingGrpcDiagnosticBinding(request(), env, NOW + 60_000)).toBeNull();
  });

  it("rejects absent environment names and explicit non-staging names", () => {
    const env = environment(new Response(null), {});
    env.CORELINK_ENVIRONMENT = undefined;
    delete (env as Partial<Env>).ENVIRONMENT;

    expect(verifyStagingGrpcDiagnosticBinding(request(), env, NOW)).toBeNull();
    env.ENVIRONMENT = "production";
    expect(verifyStagingGrpcDiagnosticBinding(request(), env, NOW)).toBeNull();
  });

  it("propagates cancellation through the one localhost request reconstruction", async () => {
    const controller = new AbortController();
    const original = new Request("https://staging.corelink.humangr.com/probe", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: new Uint8Array([0, 0, 0, 0, 0]),
      signal: controller.signal,
    });
    let forwarded: Request | undefined;

    await proxyToContainer(
      original,
      {
        fetch: async (input: Request) => {
          forwarded = input;
          return new Response(null);
        },
      } as never,
      { signal: original.signal, redirect: "manual" },
    );
    controller.abort();

    expect(forwarded?.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(forwarded?.redirect).toBe("manual");
    expect(forwarded?.signal.aborted).toBe(true);
  });

  it("keeps the shared normal proxy request behavior unchanged", async () => {
    const controller = new AbortController();
    const original = new Request("https://corelink.humangr.com/v1/normal", {
      method: "POST",
      body: new Uint8Array([1]),
      signal: controller.signal,
    });
    let forwarded: Request | undefined;

    await proxyToContainer(
      original,
      {
        fetch: async (input: Request) => {
          forwarded = input;
          return new Response(null);
        },
      } as never,
    );
    controller.abort();

    expect(forwarded?.redirect).toBe("follow");
    expect(forwarded?.signal.aborted).toBe(false);
  });
});
