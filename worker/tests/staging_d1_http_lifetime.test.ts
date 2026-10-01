import { describe, expect, it } from "vitest";
import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
import { createHttpLifetime, httpDeadlineContext, isStagingD1HttpLifetime, isStagingD1HttpDeadline, checkHttpExecutionDeadline } from "../src/staging_d1_http_lifetime.js";
const release = "a".repeat(40), start = window.starts_ms;
describe("immutable HTTP lifetime record", () => {
  it("keeps exact bookkeeping/context keys and fixed cumulative deadlines", () => {
    const record = createHttpLifetime(release, start), context = httpDeadlineContext(record);
    expect(Object.keys(record)).toHaveLength(9); expect(Object.keys(context)).toHaveLength(6);
    expect(context.execute_deadline_ms).toBe(start + 600_000); expect(context.kill_at_ms).toBe(start + 1_200_000);
    expect(isStagingD1HttpLifetime(record, release)).toBe(true);
    expect(isStagingD1HttpDeadline(context, release)).toBe(true);
  });
  it.each([-1, 0, 1])("rejects new SQL at execution deadline offset %s", offset => {
    const context = httpDeadlineContext(createHttpLifetime(release, start));
    if (offset < 0) expect(() => checkHttpExecutionDeadline(context, context.execute_deadline_ms + offset)).not.toThrow();
    else expect(() => checkHttpExecutionDeadline(context, context.execute_deadline_ms + offset)).toThrow();
    expect(() => checkHttpExecutionDeadline(context, start - 1)).toThrow();
  });
  it("rejects missing/extended/foreign/deadline-changing context", () => {
    const record = createHttpLifetime(release, start), context = httpDeadlineContext(record);
    for (const value of [undefined, {}, { ...context, extra: true }, { ...context, worker_release: "b".repeat(40) },
      { ...context, probe_nonce: "old" }, { ...context, operation_started_ms: start - 1 },
      { ...context, execute_deadline_ms: context.execute_deadline_ms + 1 }, { ...context, kill_at_ms: Infinity }]) {
      expect(isStagingD1HttpDeadline(value, release)).toBe(false);
    }
    expect(isStagingD1HttpLifetime({ ...record, [Symbol("extra")]: true }, release)).toBe(false);
    expect(() => createHttpLifetime(release, window.last_entry_ms + 1)).toThrow();
  });
  it("a stop attempt has no stopped time and cannot be silently promoted", () => {
    const record = createHttpLifetime(release, start), at = record.kill_at_ms;
    for (const state of ["stop_attempted", "unproven", "stopped"] as const) {
      expect(isStagingD1HttpLifetime({ ...record, state }, release)).toBe(false);
      expect(isStagingD1HttpLifetime({ ...record, state, stop_attempted_at_ms: at - 1 }, release)).toBe(false);
    }
    expect(isStagingD1HttpLifetime({ ...record, state: "stop_attempted", stop_attempted_at_ms: at }, release)).toBe(true);
    expect(isStagingD1HttpLifetime({ ...record, state: "stopped", stop_attempted_at_ms: at, stopped_at_ms: at }, release)).toBe(true);
    expect(isStagingD1HttpLifetime({ ...record, state: "stopped", stop_attempted_at_ms: at + 1, stopped_at_ms: at }, release)).toBe(false);
  });
});
