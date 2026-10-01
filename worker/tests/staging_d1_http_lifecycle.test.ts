import { afterEach, expect, it, vi } from "vitest";
import { StagingD1HttpLifecycle } from "../src/staging_d1_http_lifecycle.js";

afterEach(() => vi.useRealTimers());

it("uses one execution deadline across sequential operations", async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  const life = new StagingD1HttpLifecycle(Date.now, 2_000_000);
  await life.run(async () => { vi.setSystemTime(599_999); });
  vi.setSystemTime(600_000);
  const next = vi.fn();
  await expect(life.run(next)).rejects.toThrow("execution stopped");
  expect(next).not.toHaveBeenCalled();
});

it("timeout retains pending work and permanently fences late pipeline continuation", async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  const life = new StagingD1HttpLifecycle(Date.now, 2_000_000);
  let finish!: () => void;
  const next = vi.fn();
  const pipeline = (async () => {
    await life.run(() => new Promise<void>(resolve => { finish = resolve; }));
    await life.run(next);
  })();
  const failed = expect(pipeline).rejects.toThrow("execution stopped");
  await vi.advanceTimersByTimeAsync(600_000); await failed;
  expect(life.settled).toBe(false);
  await expect(life.cleanup(next)).rejects.toThrow("operation pending");
  const waiting = life.quiesce();
  finish(); await waiting;
  await life.cleanup(async () => undefined);
  await expect(life.run(next)).rejects.toThrow("execution stopped");
  expect(next).not.toHaveBeenCalled();
  expect(life.settled).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

it("quiescence consumes the same cleanup budget and never authorizes unresolved cleanup", async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  const life = new StagingD1HttpLifecycle(Date.now, 2_000_000);
  const request = life.run(() => new Promise<never>(() => {}));
  const failed = expect(request).rejects.toThrow();
  await vi.advanceTimersByTimeAsync(600_000); await failed;
  const waiting = expect(life.quiesce()).rejects.toThrow("deadline");
  await vi.advanceTimersByTimeAsync(600_000); await waiting;
  const cleanup = vi.fn();
  await expect(life.cleanup(cleanup)).rejects.toThrow();
  expect(cleanup).not.toHaveBeenCalled();
  expect(life.settled).toBe(false);
  expect(vi.getTimerCount()).toBe(0);
});

it("cleanup cannot refresh its budget and provider error text is discarded", async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  const life = new StagingD1HttpLifecycle(Date.now, 2_000_000);
  await expect(life.run(async () => { throw new Error("private-sentinel"); })).rejects.toThrow("http proof execution stopped");
  await life.record(async () => undefined);
  vi.setSystemTime(599_999);
  await life.cleanup(async () => undefined);
  vi.setSystemTime(600_000);
  await expect(life.cleanup(async () => undefined)).rejects.toThrow("deadline");
  expect(vi.getTimerCount()).toBe(0);
});

it("absolute stop latch fences execution without claiming submitted work cancelled", async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  const life = new StagingD1HttpLifecycle(Date.now, 2_000_000);
  let resolve!: () => void;
  const running = life.run(() => new Promise<void>(done => { resolve = done; }));
  const rejected = expect(running).rejects.toThrow("execution stopped");
  await Promise.resolve(); life.halt(); life.halt();
  expect(life.settled).toBe(false);
  const next = vi.fn(); await expect(life.run(next)).rejects.toThrow();
  resolve(); await rejected; expect(next).not.toHaveBeenCalled();
});
