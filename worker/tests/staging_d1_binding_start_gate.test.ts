import { describe, expect, it, vi } from "vitest";
import type { Container } from "@cloudflare/workers-types";
import type { Env } from "../src/index.js";
import { createHttpLifetime, httpDeadlineContext } from "../src/staging_d1_http_lifetime.js";
import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
import { startContainer, type StartContainerLifecycleState } from "../src/durable_object_start.js";

describe("staging D1 outbound interception boot gate", () => {
  it("never starts the internet-enabled container if the host interceptor cannot be installed", async () => {
    const calls: string[] = [];
    const container = {
      running: false,
      start: vi.fn(() => calls.push("start")),
    } as unknown as Container;
    const state = {
      containerStatus: "stopped" as const,
      coldStartCount: 0,
      tenantId: null,
      lastHealthCheckMs: 0,
    };
    const destroy = vi.fn(async () => { calls.push("destroy"); });
    const result = await startContainer({
      container,
      env: { ENVIRONMENT: "staging", PAGERDUTY_ROUTING_KEY: "" } as Env,
      doIdHash: "test-do",
      getLifecycleState: () => state,
      setLifecycleState: vi.fn(),
      transitionStatus: vi.fn(async () => {}),
      updateLifecycleState: vi.fn(async () => {}),
      waitForContainerReady: vi.fn(async () => ({ ok: true as const })),
      armInactivityTimeout: vi.fn(async () => {}),
      waitForContainerHealth: vi.fn(async () => true),
      destroyContainer: destroy,
      installStagingD1BindingProxy: vi.fn(async () => {
        calls.push("intercept");
        throw new Error("interceptor install failed");
      }),
      setAlarm: vi.fn(async () => {}),
    }, "staging-d1-proxy-boot");

    expect(result).toEqual({ ok: false, reason: "container_start_threw" });
    expect(calls).toEqual(["intercept", "destroy"]);
    expect(container.start).not.toHaveBeenCalled();
  });

  it("suppresses PagerDuty only for the internal one-shot runtime probe", async () => {
    const originalFetch = globalThis.fetch;
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(null, { status: 202 }));
    globalThis.fetch = fetch;
    const makeContext = (suppressLifecycleTelemetry?: boolean, withDpaSalt = true) => {
      let lifecycle: StartContainerLifecycleState = {
        containerStatus: "stopped" as const,
        coldStartCount: 0,
        tenantId: null,
        lastHealthCheckMs: 0,
      };
      const container = {
        running: false,
        start: vi.fn(() => { Object.assign(container, { running: true }); }),
      } as unknown as Container;
      return {
        context: {
          container,
          env: { ENVIRONMENT: "staging", PAGERDUTY_ROUTING_KEY: "present-only-in-fixture",
            SENTRY_RELEASE: "a".repeat(40),
            CORELINK_ADMIN_AUTH_KEY: "ephemeral-http-admin-sentinel-not-for-native",
            ...(withDpaSalt ? { DPA_ACCEPT_IP_HASH_SALT: "a1".repeat(32) } : {}),
          } as Env,
          doIdHash: "test-do",
          getLifecycleState: () => lifecycle,
          setLifecycleState: (state: StartContainerLifecycleState) => { lifecycle = state; },
          transitionStatus: vi.fn(async () => {}),
          updateLifecycleState: vi.fn(async () => {}),
          waitForContainerReady: vi.fn(async () => ({ ok: true as const })),
          armInactivityTimeout: vi.fn(async () => {}),
          waitForContainerHealth: vi.fn(async () => true),
          destroyContainer: vi.fn(async () => {}),
          installStagingD1BindingProxy: vi.fn(async () => {}),
          setAlarm: vi.fn(async () => {}),
          ...(suppressLifecycleTelemetry === undefined ? {} : { suppressLifecycleTelemetry }),
        },
      };
    };

    try {
      const probe = makeContext(true);
      await expect(startContainer(probe.context, "staging-d1-binding-runtime-probe")).resolves.toEqual({ ok: true });
      expect(fetch).not.toHaveBeenCalled();
      expect(probe.context.container!.start).toHaveBeenCalledOnce();
      expect(vi.mocked(probe.context.container!.start).mock.calls[0]?.[0]?.env?.["CORELINK_ADMIN_AUTH_KEY"]).toBe("");
      expect(vi.mocked(probe.context.container!.start).mock.calls[0]?.[0]?.env)
        .not.toHaveProperty("DPA_ACCEPT_IP_HASH_SALT");

      const ordinary = makeContext();
      await expect(startContainer(ordinary.context, "ordinary-test-start")).resolves.toEqual({ ok: true });
      expect(vi.mocked(ordinary.context.container!.start).mock.calls[0]?.[0]?.env?.["CORELINK_ADMIN_AUTH_KEY"])
        .toBe("ephemeral-http-admin-sentinel-not-for-native");
      expect(vi.mocked(ordinary.context.container!.start).mock.calls[0]?.[0]?.env?.["DPA_ACCEPT_IP_HASH_SALT"])
        .toBe("a1".repeat(32));
      expect(fetch).toHaveBeenCalledTimes(2);
      const events = fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)).event_type);
      expect(events).toEqual(["corelink.do.cold_start.v1", "corelink.do.container_started.v1"]);

      expect(vi.mocked(ordinary.context.container!.start).mock.calls[0]?.[0]?.entrypoint).toEqual(["/usr/local/bin/corelink-server"]);
      for (const name of ["CORELINK_STAGING_PROBE_STARTED_MS", "CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS", "CORELINK_STAGING_PROBE_KILL_AT_MS"]) {
        expect(vi.mocked(ordinary.context.container!.start).mock.calls[0]?.[0]?.env).not.toHaveProperty(name);
      }
      const http = makeContext(true);
      const context = httpDeadlineContext(createHttpLifetime("a".repeat(40), window.starts_ms));
      await expect(startContainer({ ...http.context, httpDeadline: context }, "private-http")).resolves.toEqual({ ok: true });
      expect(vi.mocked(http.context.container!.start).mock.calls[0]?.[0]?.entrypoint).toEqual(["/usr/local/bin/corelink-staging-probe-supervisor"]);
      expect(vi.mocked(http.context.container!.start).mock.calls[0]?.[0]?.env).toMatchObject({
        CORELINK_STAGING_PROBE_STARTED_MS: String(context.operation_started_ms),
        CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS: String(context.execute_deadline_ms),
        CORELINK_STAGING_PROBE_KILL_AT_MS: String(context.kill_at_ms),
      });
      const wrong = makeContext(true);
      await expect(startContainer({ ...wrong.context, httpDeadline: { ...context, worker_release: "b".repeat(40) } }, "wrong-http"))
        .resolves.toEqual({ ok: false, reason: "http_deadline_rejected" });
      expect(wrong.context.container!.start).not.toHaveBeenCalled();
      const ordinaryWithContext = makeContext();
      await expect(startContainer({ ...ordinaryWithContext.context, httpDeadline: context }, "ordinary-with-context"))
        .resolves.toEqual({ ok: false, reason: "http_deadline_rejected" });
      expect(ordinaryWithContext.context.container!.start).not.toHaveBeenCalled();

      const ordinaryWithoutSalt = makeContext(undefined, false);
      await expect(startContainer(ordinaryWithoutSalt.context, "ordinary-without-dpa-salt")).resolves.toEqual({ ok: true });
      expect(vi.mocked(ordinaryWithoutSalt.context.container!.start).mock.calls[0]?.[0]?.env)
        .not.toHaveProperty("DPA_ACCEPT_IP_HASH_SALT");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
