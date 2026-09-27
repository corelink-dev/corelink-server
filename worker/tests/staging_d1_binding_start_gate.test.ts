import { describe, expect, it, vi } from "vitest";
import type { Container } from "@cloudflare/workers-types";
import type { Env } from "../src/index.js";
import { startContainer } from "../src/durable_object_start.js";

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
});
