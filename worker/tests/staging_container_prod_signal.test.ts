/**
 * #1700: the staging container must not see the container's independent PROD signal.
 *
 * `crates/corelink-container/src/main.rs` treats any non-empty R2_AC_REGION / R2_CAS_REGION /
 * R2_AC_BUCKET as "this is prod" and then refuses to boot (exit 1) unless every prod control
 * is armed: StorageEnv, PAT_SIGNING_KEY, the native PAT verifier, quota, byte cap and so on.
 * Staging's topology sets those three vars and arms none of those controls, so every staging
 * container exited at boot. The Worker now forwards them EMPTY to the container only when
 * ENVIRONMENT=staging. These tests observe the actual `container.start({ env })` call and
 * derive the signal list from main.rs, so a fourth signal var added there fails here until it
 * is blanked too. Prod, regional prod and every other environment keep byte-for-byte forwarding,
 * and the main.rs guard itself is untouched.
 */
import { describe, expect, it, vi } from "vitest";
import { readFile } from "node:fs/promises";
import type { Container } from "@cloudflare/workers-types";
import type { Env } from "../src/index.js";
import { startContainer, type StartContainerLifecycleState } from "../src/durable_object_start.js";

const MAIN_RS = new URL("../../crates/corelink-container/src/main.rs", import.meta.url);

async function prodSignalVars(): Promise<string[]> {
  const source = await readFile(MAIN_RS, "utf8");
  const match = /let prod_by_independent_signal = \[([^\]]*)\]/.exec(source);
  expect(match, "main.rs no longer declares the independent prod signal").not.toBeNull();
  const names = [...(match?.[1] ?? "").matchAll(/"([A-Z][A-Z0-9_]*)"/g)].map(found => found[1] as string);
  expect(names.length).toBeGreaterThan(0);
  return names;
}

async function forwardedEnv(environment: string): Promise<Record<string, string>> {
  let lifecycle: StartContainerLifecycleState = {
    containerStatus: "stopped" as const, coldStartCount: 0, tenantId: null, lastHealthCheckMs: 0,
  };
  const container = {
    running: false,
    start: vi.fn(() => { Object.assign(container, { running: true }); }),
  } as unknown as Container;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(null, { status: 202 }));
  try {
    const result = await startContainer({
      container,
      env: {
        ENVIRONMENT: environment, PAGERDUTY_ROUTING_KEY: "", SENTRY_RELEASE: "a".repeat(40),
        R2_AC_BUCKET: "corelink-ac-iad-staging", R2_AC_REGION: "iad", R2_CAS_REGION: "iad",
        R2_CAS_BUCKET: "corelink-cas-staging", R2_CHUNK_BUCKET: "corelink-chunk-iad-staging", R2_CHUNK_REGION: "iad",
        R2_S3_ENDPOINT: "https://example.r2.cloudflarestorage.com", D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      } as Env,
      doIdHash: "prod-signal-test",
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
      suppressLifecycleTelemetry: true,
    }, `prod-signal-${environment}`);
    expect(result).toEqual({ ok: true });
  } finally { globalThis.fetch = originalFetch; }
  expect(container.start).toHaveBeenCalledOnce();
  return (vi.mocked(container.start).mock.calls[0]?.[0]?.env ?? {}) as Record<string, string>;
}

// The container's own predicate: any signal var whose value is non-empty after trimming.
const signalled = (env: Record<string, string>, names: string[]) =>
  names.some(name => (env[name] ?? "").trim() !== "");

describe("#1700 staging container never receives the prod-arming signal", () => {
  it("staging forwards every prod-signal var empty, so the boot guard stays off", async () => {
    const names = await prodSignalVars();
    expect(names.sort()).toEqual(["R2_AC_BUCKET", "R2_AC_REGION", "R2_CAS_REGION"]);
    const env = await forwardedEnv("staging");
    for (const name of names) {
      expect(Object.hasOwn(env, name), name).toBe(true); // still forwarded (env contract), just empty
      expect(env[name], name).toBe("");
    }
    expect(signalled(env, names)).toBe(false);
    // Only the signal is withheld: the rest of the staging R2 placement still reaches the container.
    expect(env.R2_CAS_BUCKET).toBe("corelink-cas-staging");
    expect(env.R2_CHUNK_BUCKET).toBe("corelink-chunk-iad-staging");
    expect(env.R2_CHUNK_REGION).toBe("iad");
    expect(env.R2_S3_ENDPOINT).toBe("https://example.r2.cloudflarestorage.com");
  });

  for (const environment of ["prod", "prod-sam", "prod-eu", "dev", "test"]) {
    it(`${environment} keeps byte-for-byte forwarding, so prod still trips the guard when not fully armed`, async () => {
      const names = await prodSignalVars();
      const env = await forwardedEnv(environment);
      expect(env.R2_AC_BUCKET).toBe("corelink-ac-iad-staging");
      expect(env.R2_AC_REGION).toBe("iad");
      expect(env.R2_CAS_REGION).toBe("iad");
      expect(signalled(env, names)).toBe(true);
    });
  }

  it("the main.rs prod-arming guard is unchanged: signal set, fail-fast and exit", async () => {
    const source = await readFile(MAIN_RS, "utf8");
    expect(source).toContain('let prod_by_independent_signal = ["R2_AC_REGION", "R2_CAS_REGION", "R2_AC_BUCKET"]');
    expect(source).toContain('event = "prod_controls_not_fully_armed"');
    expect(source).toContain("corelink_server::storage::StorageEnv::from_env().is_none()");
    // The guard does not consult ENVIRONMENT: the staging exemption lives only at the Worker boundary.
    const guard = source.slice(source.indexOf("let prod_by_independent_signal"), source.indexOf('event = "prod_controls_not_fully_armed"'));
    expect(guard).not.toContain("ENVIRONMENT");
    expect(guard).not.toContain("staging");
  });
});
