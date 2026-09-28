import { describe, expect, it, vi } from "vitest";
import type { Container } from "@cloudflare/workers-types";
import type { Env } from "../src/index.js";
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
    const makeContext = (suppressLifecycleTelemetry?: boolean) => {
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
          env: { ENVIRONMENT: "staging", PAGERDUTY_ROUTING_KEY: "present-only-in-fixture" } as Env,
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

      const ordinary = makeContext();
      await expect(startContainer(ordinary.context, "ordinary-test-start")).resolves.toEqual({ ok: true });
      expect(fetch).toHaveBeenCalledTimes(2);
      const events = fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)).event_type);
      expect(events).toEqual(["corelink.do.cold_start.v1", "corelink.do.container_started.v1"]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
