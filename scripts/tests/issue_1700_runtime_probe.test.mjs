import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { ACCOUNT_ID, normalizeContainerDetail, readContainerDetail, runRuntimeProbe, failureDiagnostic, decodeTailFrame, waitForContainerState, captureDeployImageDigest, captureContainerPreimage, verifyContainerPreimage, verifyContainerImageDigest, verifyContainerState, verifyContainerRollback, CONTAINER_APP_ID, CONTAINER_APP_NAME, PROBE_CRON, PROBE_EXPIRY, PROBE_WINDOW, approvedProbeWindow } from "../issue_1700_runtime_probe.mjs";

const release = "0123456789abcdef0123456789abcdef01234567";
const now = Date.parse("2026-10-01T03:30:00Z");
const imageDigest = `sha256:${"a".repeat(64)}`;
const receipt = {
  contract: "corelink-staging-d1-binding-runtime-v1",
  outcome: "pass",
  probe_nonce: PROBE_WINDOW.nonce,
  worker_release: release,
  scheduled_time_ms: Date.parse("2026-10-01T03:30:00Z"),
  parameterized_select: true,
  failed_batch_observed: true,
  rollback_absence_verified: true,
  probe_table_dropped: true,
  d1_binding_intercepted: true,
  authorization_absent: true,
  cf_api_token_absent: true, old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true,
  v5_probe_release: "cc32b3d819181bf9175e795868f66212aa5456c1", v5_probe_retired: true, v5_probe_tables_absent: true,
  v5_prior_execution: "unknown",
  v4_probe_catalog_absent: true,
};

test("compiled runtime window is the exact approved v8 tuple", () => {
  assert.equal(approvedProbeWindow(), true);
  assert.equal(approvedProbeWindow({ ...PROBE_WINDOW, expires_ms: PROBE_WINDOW.expires_ms + 60_000 }), false);
  assert.equal(approvedProbeWindow({ ...PROBE_WINDOW, nonce: "issue-1700-recovery-20260930-v4" }), false);
});

// Cloudflare workers-sdk TailEventMessage: scheduled event and console log envelope.
function scheduledFrame(value = receipt, timestamp = now) {
  return { outcome: "ok", scriptName: "corelink-staging", exceptions: [],
    eventTimestamp: timestamp, event: { cron: PROBE_CRON, scheduledTime: timestamp },
    logs: [{ level: "info", timestamp,
      message: [`[staging_d1_runtime_probe] receipt=${JSON.stringify(value)}`] }],
  };
}

function harness({ schedules: initial = [], installReadback, sendReceipt = true, driftAfterReceipt = false, emittedReceipt = receipt, emittedEvent, emittedRawFrame, frameKind = "text", openMode = "open", stallReplacementOpen = false, pingDuringInstall = false, acknowledgePong = true, receiptAfterMs = 0, reconnectOnce = false, tailTtlMs = 30 * 60_000, failTailRenewal = false, failTailDelete = false, deferTailRenewal = false, duplicateReceipt = false } = {}) {
  let schedules = initial;
  let socket;
  let tailDeleted = false;
  const puts = [];
  let scheduleReads = 0;
  let initialized = false;
  let heartbeat;
  let pongs = 0;
  let socketsCreated = 0;
  const sockets = [];
  let tailsCreated = 0;
  let releaseTailRenewal;
  const tailIds = new Set();
  const deleteAttempts = [];
  const clock = { value: now };
  const api = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method ?? "GET";
    if (path.endsWith("/schedules") && method === "GET") {
      scheduleReads += 1;
      if (scheduleReads === 2 && installReadback !== undefined) {
        return response({ success: true, result: { schedules: installReadback } });
      }
      if (driftAfterReceipt && scheduleReads === 3) schedules = [{ cron: "0 0 * * *" }];
      return response({ success: true, result: { schedules } });
    }
    if (path.endsWith("/tails") && method === "GET") {
      return response({ success: true, result: [...tailIds].map(id => ({ id })) });
    }
    if (path.endsWith("/tails") && method === "POST") {
      if (failTailRenewal && tailsCreated > 0) return response({ success: false }, false);
      assert.equal(init.headers["content-type"], "application/json");
      assert.deepEqual(JSON.parse(init.body), { filters: [] });
      tailsCreated += 1;
      const id = String(tailsCreated).padStart(32, "0");
      tailIds.add(id);
      const createResponse = response({ success: true, result: {
        id,
        expires_at: new Date(clock.value + tailTtlMs).toISOString(),
        url: "wss://tail.example.invalid/secret-in-memory",
      } });
      if (deferTailRenewal && tailsCreated > 1) return new Promise(resolve => { releaseTailRenewal = () => resolve(createResponse); });
      return createResponse;
    }
    if (path.endsWith("/schedules") && method === "PUT") {
      const next = JSON.parse(init.body);
      if (next.length) assert.equal(initialized, true, "tail handshake precedes schedule installation");
      puts.push(next);
      schedules = next;
      if (next.length && pingDuringInstall) heartbeat?.();
      if (next.length && reconnectOnce && socketsCreated === 1) queueMicrotask(() => socket.onclose({ code: 1006, reason: "network interruption" }));
      if (next.length === 1 && sendReceipt) {
        if (reconnectOnce) return response({ success: true, result: { schedules } });
        clock.value += receiptAfterMs;
        const value = receiptAfterMs === 0 ? emittedReceipt : { ...emittedReceipt, scheduled_time_ms: clock.value };
        const text = emittedRawFrame ?? JSON.stringify(emittedEvent ?? scheduledFrame(value, clock.value));
        const data = frameKind === "arraybuffer" ? new TextEncoder().encode(text).buffer
          : frameKind === "blob" ? new Blob([text]) : text;
        queueMicrotask(() => socket.onmessage({ data }));
        if (duplicateReceipt) queueMicrotask(() => socket.onmessage({ data }));
      }
      return response({ success: true, result: { schedules } });
    }
    if (/\/tails\/[a-f0-9]{32}$/.test(path) && method === "DELETE") {
      const id = path.split("/").at(-1);
      deleteAttempts.push(id);
      if (!failTailDelete || deleteAttempts.length > 1) tailIds.delete(id);
      tailDeleted = true;
      return failTailDelete && deleteAttempts.length === 1
        ? response({ success: false, result: {} }, false)
        : response({ success: true, result: {} });
    }
    throw new Error("unexpected test API request");
  };
  return {
    api,
    socketFactory: (_url, protocol) => {
      assert.equal(protocol, "trace-v1");
      socketsCreated += 1;
      const createdSocket = { protocol: openMode === "wrong_protocol" ? "" : protocol,
        onmessage: undefined, onerror: undefined, onclose: undefined, close() {},
        on(_name, listener) { this.pongListener = listener; },
        ping() { pongs += 1; if (acknowledgePong) this.pongListener?.(); },
        send(value) { assert.deepEqual(JSON.parse(value), { debug: false }); initialized = true; },
      };
      socket = createdSocket;
      sockets.push(createdSocket);
      if (openMode !== "timeout" && !(stallReplacementOpen && socketsCreated > 1)) queueMicrotask(() => {
        if (openMode === "error") createdSocket.onerror();
        else {
          createdSocket.onopen();
          if (reconnectOnce && sendReceipt && socketsCreated === 2) queueMicrotask(() => createdSocket.onmessage({ data: JSON.stringify(scheduledFrame(emittedReceipt)) }));
        }
      });
      return socket;
    },
    get schedules() { return schedules; },
    puts,
    setHeartbeat(callback) { heartbeat = callback; },
    get heartbeat() { return heartbeat; },
    get pongs() { return pongs; },
    clock,
    get tailDeleted() { return tailDeleted; },
    get tailsCreated() { return tailsCreated; },
    releaseTailRenewal() { releaseTailRenewal?.(); },
    sockets,
    deleteAttempts,
    emitReceipt(value = receipt) {
      const text = JSON.stringify(scheduledFrame(value, clock.value));
      socket?.onmessage?.({ data: text });
    },
  };
}

function response(body, ok = true) {
  return { ok, status: ok ? 200 : 500, json: async () => body };
}

test("installs one exact cron, accepts the release-bound receipt, and restores empty schedules", async () => {
  const h = harness({ pingDuringInstall: true });
  const proof = await runRuntimeProbe({
    token: "test-token-never-logged", release, expectedSha: release,
    imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => now, timeoutMs: 25 * 60_000,
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
  });
  assert.equal(proof.cron, PROBE_CRON);
  assert.equal(proof.receipt.worker_release, release);
  assert.equal(proof.schedule_restored_empty, true);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.deepEqual(h.schedules, []);
  assert.equal(h.tailDeleted, true);
  assert.equal(proof.tail_cleanup_receipts.length, 1);
  assert.equal(proof.tail_cleanup_receipts[0].http_status, 200);
  assert.equal(proof.tail_cleanup_receipts[0].success, true);
  assert.equal(proof.control_pings, 1);
  assert.equal(proof.control_pongs, 1);
  assert.equal(h.pongs, 1);
});

test("missing control pong fails closed and cleans the exact schedule and tail", async () => {
  const h = harness({ sendReceipt: false, pingDuringInstall: true, acknowledgePong: false });
  await assert.rejects(runRuntimeProbe({
    token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => now,
    timeoutMs: 25 * 60_000,
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
    setTimeoutFn(callback, delay) { if (delay === 10_000) queueMicrotask(callback); return { callback, delay }; },
    clearTimeoutFn() {},
  }), error => {
    assert.match(error.message, /Worker tail pong deadline exceeded/);
    const diagnostic = failureDiagnostic(error);
    assert.equal(diagnostic.code, "tail_pong_timeout");
    const tail = diagnostic.tail_evidence.counters;
    assert.equal(tail.control_pings, 1);
    assert.equal(tail.control_pongs, 0);
    return true;
  });
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.deepEqual(h.schedules, []);
  assert.equal(h.tailDeleted, true);
  assert.equal(h.pongs, 1);
});

test("a healthy tail first ping at 10001ms is not treated as an overdue pong", async () => {
  const h = harness({ pingDuringInstall: false });
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
    setTimeoutFn(callback, delay) { return { callback, delay }; }, clearTimeoutFn() {},
  });
  await new Promise(resolve => setImmediate(resolve));
  h.clock.value += 10_001;
  h.heartbeat();
  h.emitReceipt();
  const proof = await running;
  assert.equal(proof.receipt.outcome, "pass");
  assert.equal(h.pongs, 1);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
});

test("accepts the persisted receipt after a fake fifteen-minute Cron propagation interval", async () => {
  const h = harness({ receiptAfterMs: 15 * 60_000 });
  const proof = await runRuntimeProbe({ token: "token", release, expectedSha: release,
    imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    timeoutMs: 25 * 60_000 });
  assert.equal(proof.receipt.scheduled_time_ms, now + 15 * 60_000);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.equal(h.tailDeleted, true);
});

test("reconnects the existing tail once without reinstalling the schedule", async () => {
  const h = harness({ reconnectOnce: true });
  const proof = await runRuntimeProbe({ token: "token", release, expectedSha: release,
    imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now,
    timeoutMs: 2_000 });
  assert.equal(proof.tail_reconnects, 1);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.equal(proof.receipt.outcome, "pass");
});

test("renews a short-lived tail with overlap and one schedule install, then deletes every owned tail", async () => {
  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, duplicateReceipt: true });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
  });
  await new Promise(resolve => setImmediate(resolve));
  const renew = timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000);
  assert.ok(renew, "renewal is scheduled one minute before the actual tail expiry");
  renew.callback();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.tailsCreated, 2);
  assert.equal(h.sockets.length, 2, "replacement connects before old socket is closed");
  h.emitReceipt();
  h.emitReceipt();
  const proof = await running;
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.equal(h.tailDeleted, true);
  assert.equal(proof.schedule_restored_empty, true);
  assert.equal(proof.tail_cleanup_receipts.length, 2);
  assert.ok(proof.tail_cleanup_receipts.every(item => item.success && item.http_status === 200));
});

test("short TTL and failed renewal are inconclusive and clean every created tail", async () => {
  const short = harness({ tailTtlMs: 4 * 60_000 - 1 });
  await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
    imageDigest, api: short.api, socketFactory: short.socketFactory, now: () => short.clock.value,
  }), /tail preflight rejected/);
  assert.equal(short.tailDeleted, true);

  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, failTailRenewal: true });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
  });
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000).callback();
  await assert.rejects(running, /Worker tail renewal failed/);
  assert.equal(h.tailsCreated, 1);
  assert.equal(h.tailDeleted, true);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
});

test("waits for an in-flight tail create before final cleanup", async () => {
  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, deferTailRenewal: true });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
  });
  let settled = false;
  running.then(() => { settled = true; }, () => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000).callback();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.tailsCreated, 2, "renewal POST has started and owns a new ID when it resolves");
  h.emitReceipt();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false, "final cleanup waits for the bounded create request");
  assert.equal(h.deleteAttempts.length, 0);
  h.releaseTailRenewal();
  const proof = await running;
  assert.equal(h.deleteAttempts.length, 2);
  assert.equal(proof.tail_cleanup_receipts.length, 2);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
});

test("attempts cleanup for every owned tail and fails if any DELETE is rejected", async () => {
  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, failTailDelete: true });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
  });
  const expectedFailure = assert.rejects(running, error => {
    assert.match(error.message, /Worker tail renewal failed/);
    const cleanup = failureDiagnostic(error).tail_cleanup;
    assert.equal(cleanup.length, 2);
    assert.deepEqual(cleanup.map(item => item.http_status), [500, 200]);
    assert.deepEqual(cleanup.map(item => item.success), [false, true]);
    assert.ok(cleanup.every(item => Number.isSafeInteger(item.deleted_at_ms)));
    return true;
  });
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000).callback();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  h.emitReceipt();
  await expectedFailure;
  assert.equal(h.tailsCreated, 2);
  assert.equal(h.deleteAttempts.length, 2);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
});

test("a replacement tail must pong before the old tail is retired", async () => {
  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, acknowledgePong: false });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) {
      const timer = { callback, delay, cleared: false };
      timers.push(timer);
      if (delay === 10_000) queueMicrotask(callback);
      return timer;
    },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
  });
  const expectedFailure = assert.rejects(running, /Worker tail renewal failed/);
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000).callback();
  await expectedFailure;
  assert.equal(h.tailsCreated, 2);
  assert.equal(h.deleteAttempts.length, 2);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
});

test("expired replacement open deadline settles renewal and cleans all owned resources", async () => {
  const h = harness({ sendReceipt: false, tailTtlMs: 5 * 60_000, stallReplacementOpen: true });
  const timers = [];
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setTimeoutFn(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn(timer) { if (timer) timer.cleared = true; },
  });
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 4 * 60_000).callback();
  await new Promise(resolve => setImmediate(resolve));
  timers.find(timer => !timer.cleared && timer.delay === 20_000).callback();
  await assert.rejects(running, /Worker tail renewal failed/);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.equal(h.schedules.length, 0);
  assert.deepEqual(h.deleteAttempts, ["0".repeat(31) + "2", "0".repeat(31) + "1"]);
});

test("a stale pong from a replaced socket cannot keep the active tail alive", async () => {
  const h = harness({ sendReceipt: false, reconnectOnce: true, acknowledgePong: false });
  const running = runRuntimeProbe({ token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => h.clock.value,
    setIntervalFn(callback) { h.setHeartbeat(callback); return callback; }, clearIntervalFn() {},
    setTimeoutFn(callback, delay) { return { callback, delay }; }, clearTimeoutFn() {},
  });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.sockets.length, 2);
  h.heartbeat();
  h.clock.value += 10_001;
  h.sockets[0].pongListener?.();
  h.heartbeat();
  await assert.rejects(running, /Worker tail pong deadline exceeded/);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.equal(h.tailDeleted, true);
});

test("rejects preexisting schedules before creating a tail or mutating", async () => {
  const h = harness({ schedules: [{ cron: "0 0 * * *" }] });
  await assert.rejects(runRuntimeProbe({
    token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => now,
  }), /preexisting Worker schedules/);
  assert.deepEqual(h.puts, []);
  assert.equal(h.tailDeleted, false);
});

test("failed install readback records bounded shape without weakening guards or cleanup", async () => {
  const cases = [
    { rows: [], matches: 0 },
    { rows: [{ cron: PROBE_CRON }, { cron: "0 0 * * *" }], matches: 1 },
    { rows: [{ cron: PROBE_CRON, next_run: "private-value-never-output" }], matches: 1 },
    { rows: [{ cron: "* * 30 SEP *" }], matches: 0 },
  ];
  for (const { rows, matches } of cases) {
    const h = harness({ installReadback: rows });
    await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
      imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now,
    }), error => {
      const diagnostic = failureDiagnostic(error);
      assert.equal(diagnostic.stage, "schedule_install");
      assert.equal(diagnostic.code, "schedule_readback");
      assert.equal(diagnostic.schedule_readback.count, rows.length);
      assert.equal(diagnostic.schedule_readback.expected_cron_matches, matches);
      assert.deepEqual(diagnostic.schedule_readback.entries.map(entry => entry.keys), rows.map(row => Object.keys(row).sort()));
      assert.deepEqual(diagnostic.schedule_readback.entries.map(entry => entry.cron), rows.map(row => row.cron));
      assert.ok(!JSON.stringify(diagnostic).includes("private-value"));
      return true;
    });
    assert.deepEqual(h.schedules, []);
    assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
    assert.equal(h.tailDeleted, true);
  }
});

test("schedule diagnostics redact payload-like cron and keys, cap output, and reject injected evidence", async () => {
  const rows = Array.from({ length: 20 }, () => ({ cron: "Bearer secret-token", "secret-token-value": "customer-payload" }));
  rows[1].cron = "12345678901234567890 1 1 1 1";
  const h = harness({ installReadback: rows });
  await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
    imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now,
  }), error => {
    const summary = failureDiagnostic(error).schedule_readback;
    assert.equal(summary.count, 20);
    assert.equal(summary.entries.length, 8);
    assert.equal(summary.truncated, true);
    assert.equal(summary.entries[0].cron, "[redacted]");
    assert.equal(summary.entries[1].cron, "[redacted]");
    assert.deepEqual(summary.entries[0].keys, ["cron", "[redacted]"]);
    assert.ok(!JSON.stringify(summary).includes("secret-token"));
    assert.ok(!JSON.stringify(summary).includes("customer-payload"));
    return true;
  });
  assert.equal(failureDiagnostic(Object.assign(new Error("installed schedule readback rejected"), {
    schedule_readback: { token: "secret" },
  })).schedule_readback, undefined);
  assert.deepEqual(h.schedules, []);
  assert.equal(h.tailDeleted, true);
});

test("does not overwrite schedule drift during cleanup and still deletes the tail", async () => {
  const h = harness({ driftAfterReceipt: true });
  await assert.rejects(runRuntimeProbe({
    token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => now,
  }), /schedule drift/);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }]]);
  assert.equal(h.tailDeleted, true);
});

test("fails closed when the bounded probe window cannot fit", async () => {
  const h = harness();
  await assert.rejects(runRuntimeProbe({
    token: "token", release, expectedSha: release, imageDigest,
    api: h.api, socketFactory: h.socketFactory,
    now: () => PROBE_EXPIRY - 10_000,
  }), /preflight rejected/);
  assert.deepEqual(h.puts, []);
});

test("fails closed when fifteen-minute Cron propagation cannot fit before last entry", async () => {
  const h = harness();
  await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
    imageDigest, api: h.api, socketFactory: h.socketFactory,
    now: () => PROBE_WINDOW.last_entry_ms - 15 * 60_000,
    timeoutMs: 25 * 60_000 }), /preflight rejected/);
  assert.deepEqual(h.puts, []);
});

test("captures exactly one deployed version and immutable image digest", () => {
  const versionId = "01234567-89ab-cdef-0123-456789abcdef";
  const result = captureDeployImageDigest([
    `Current Version ID: ${versionId}`,
    `Container image pushed; digest: ${imageDigest}`,
  ].join("\n"));
  assert.deepEqual(result, { versionId, imageDigest });
});

test("rejects missing, duplicated, malformed, or uppercase image digest output", () => {
  const versionId = "01234567-89ab-cdef-0123-456789abcdef";
  const version = `Current Version ID: ${versionId}`;
  assert.throws(() => captureDeployImageDigest(version), /ambiguous/);
  assert.throws(() => captureDeployImageDigest(`${version}\nimage digest: sha256:bad`), /malformed/);
  assert.throws(() => captureDeployImageDigest(`${version}\nimage digest: ${imageDigest}\ncontainer image digest: ${imageDigest}`), /ambiguous/);
  assert.throws(() => captureDeployImageDigest(`${version}\nimage digest: ${imageDigest.toUpperCase()}`), /malformed/);
});

test("captures only the fixed staging Container application and exact immutable image", () => {
  const image = `registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/${CONTAINER_APP_NAME}@${imageDigest}`;
  const result = captureContainerPreimage(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]));
  assert.deepEqual(result, {
    application_id: CONTAINER_APP_ID,
    application_name: CONTAINER_APP_NAME,
    application_version: 2,
    image,
    image_digest: imageDigest,
  });
  assert.equal(verifyContainerPreimage(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), image).image, image);
  assert.equal(verifyContainerImageDigest(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), imageDigest).image_digest, imageDigest);
  assert.equal(verifyContainerState(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), imageDigest, { expectedVersion: 2 }).application_version, 2);
  assert.throws(() => verifyContainerPreimage(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), image.replace(/a/g, "b")), /differs from preimage/);
  assert.throws(() => verifyContainerImageDigest(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), `sha256:${"b".repeat(64)}`), /differs from candidate/);
  assert.throws(() => verifyContainerState(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), imageDigest, { expectedVersion: 3 }), /version changed/);
  assert.throws(() => verifyContainerState(JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 },
  ]), imageDigest, { minimumVersion: 2 }), /did not advance/);
  const old = JSON.stringify([{ id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 3 }]);
  const afterWorkerRollback = JSON.stringify([{ id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 3 }]);
  assert.equal(verifyContainerRollback(old, afterWorkerRollback, image).application_version, 3);
  assert.throws(() => verifyContainerRollback(old, JSON.stringify([
    { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 4 },
  ]), image), /changed after Worker rollback/);
});

test("rejects a missing, duplicated, substituted, or mutable staging image preimage", () => {
  const image = `registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/${CONTAINER_APP_NAME}@${imageDigest}`;
  const app = { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, image, version: 2 };
  assert.throws(() => captureContainerPreimage("{}"), /inventory rejected/);
  assert.throws(() => captureContainerPreimage(JSON.stringify([app, app])), /ambiguous/);
  assert.throws(() => captureContainerPreimage(JSON.stringify([{ ...app, name: "corelink-prod" }])), /malformed/);
  assert.throws(() => captureContainerPreimage(JSON.stringify([{ ...app, image: image.replace("@sha256:", ":") }])), /malformed/);
});

test("runtime rollback is exclusive with early rollback and never retries a failed restore", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/issue-1700-container-staging-deploy.yml", import.meta.url), "utf8");
  const runtimeStep = workflow.match(/- name: Roll back only this run after runtime acceptance failure\n(?<step>[\s\S]*?)(?=\n      - name:|\n  verify_existing:)/)?.groups?.step;
  assert.ok(runtimeStep, "runtime rollback step is present");
  const condition = runtimeStep.match(/^\s+if:\s+(.+)$/m)?.[1];
  assert.ok(condition, "runtime rollback has a condition");
  assert.match(runtimeStep, /ROLLBACK_MARKER: issue-1700-route-free-rollback-/);
  assert.ok(runtimeStep.indexOf('CLOUDFLARE_API_TOKEN="$ROUTE_READ_TOKEN" python3 scripts/verify_issue_1700_route_inventory.py') < runtimeStep.indexOf("pnpm exec wrangler deploy"));
  assert.match(condition, /steps\.early_rollback\.outcome == 'skipped'/);

  const shouldRollbackRuntime = ({ failed, candidateVerified, deployVerified, earlyRollback }) =>
    failed && candidateVerified && deployVerified && earlyRollback === "skipped";
  const cases = [
    ["early rollback succeeded", { failed: true, candidateVerified: true, deployVerified: false, earlyRollback: "success" }, false],
    ["early rollback partially failed", { failed: true, candidateVerified: true, deployVerified: false, earlyRollback: "failure" }, false],
    ["route passed and runtime acceptance failed", { failed: true, candidateVerified: true, deployVerified: true, earlyRollback: "skipped" }, true],
    ["all acceptance passed", { failed: false, candidateVerified: true, deployVerified: true, earlyRollback: "skipped" }, false],
  ];
  for (const [name, input, expected] of cases) {
    assert.equal(shouldRollbackRuntime(input), expected, name);
  }
});


test("captures the actual Wrangler registry push result without an image label", () => {
  const versionId = "d787acbc-666b-4e2f-87b3-0e93a3f6393b";
  assert.deepEqual(captureDeployImageDigest(`d787acbc: digest: ${imageDigest} size: 1580\nCurrent Version ID: ${versionId}`), { versionId, imageDigest });
});

function containerRow(version, digest = imageDigest) {
  return { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, version, exact_application_health_verified: true,
    image: `registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/${CONTAINER_APP_NAME}@${digest}` };
}

test("readback retries only the exact stale preimage and accepts the next exact version", async () => {
  const old = containerRow(2, `sha256:${"b".repeat(64)}`);
  const preimage = captureContainerPreimage(JSON.stringify([old]));
  let clock = 0, reads = 0;
  const result = await waitForContainerState({ preimage, expectedDigest: imageDigest,
    now: () => clock, sleep: async ms => { clock += ms; },
    read: async () => JSON.stringify([++reads < 3 ? old : containerRow(3)]),
  });
  assert.equal(reads, 3);
  assert.equal(result.state.application_version, 3);
});

test("readback rejects wrong app, wrong digest, skipped version, and deadline", async () => {
  const old = containerRow(2, `sha256:${"b".repeat(64)}`);
  const preimage = captureContainerPreimage(JSON.stringify([old]));
  for (const row of [{ ...containerRow(3), id: "other" }, containerRow(3, `sha256:${"c".repeat(64)}`), containerRow(4)]) {
    await assert.rejects(waitForContainerState({ preimage, expectedDigest: imageDigest,
      read: async () => JSON.stringify([row]), sleep: async () => assert.fail("must not retry drift"),
    }));
  }
  let clock = 0;
  await assert.rejects(waitForContainerState({ preimage, expectedDigest: imageDigest,
    timeoutMs: 10, intervalMs: 5, now: () => clock,
    sleep: async ms => { clock += ms; }, read: async () => JSON.stringify([old]),
  }), /deadline/);
});


test("host ignores wrong nonce, release, expired and pre-invocation receipts and cleans up", async () => {
  const missingV4CatalogReceipt = { ...receipt };
  delete missingV4CatalogReceipt.v4_probe_catalog_absent;
  const missingV5Retirement = { ...receipt };
  delete missingV5Retirement.v5_probe_retired;
  for (const emittedReceipt of [
    missingV4CatalogReceipt,
    missingV5Retirement,
    { ...receipt, v4_probe_catalog_absent: false },
    { ...receipt, probe_nonce: "old-window" },
    { ...receipt, worker_release: "f".repeat(40) },
    { ...receipt, old_probe_retired: false },
    { ...receipt, old_probe_tables_absent: false },
    { ...receipt, v5_probe_release: "a".repeat(40) },
    { ...receipt, v5_probe_retired: false },
    { ...receipt, v5_probe_tables_absent: false },
    { ...receipt, v5_prior_execution: "pass" },
    { ...receipt, old_probe_release: "a".repeat(40) },
    { ...receipt, scheduled_time_ms: PROBE_EXPIRY },
    { ...receipt, scheduled_time_ms: now - 60000 },
  ]) {
    const h = harness({ emittedReceipt });
    await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
      imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now, timeoutMs: 5,
    }), /timed out/);
    assert.deepEqual(h.schedules, []);
    assert.equal(h.tailDeleted, true);
  }
});

test("failed probe diagnostics distinguish no frames, empty events, malformed frames and fixed markers", async () => {
  const cases = [
    { name: "no frame", options: { sendReceipt: false }, expect: { frames_received: 0 } },
    { name: "empty event", options: { emittedEvent: { outcome: "ok", event: {}, logs: [] } }, expect: { frames_received: 1, frames_decoded: 1, empty_events: 1, unknown_event_metadata: 1 } },
    { name: "malformed frame", options: { emittedRawFrame: "not-json" }, expect: { frames_received: 1, frames_decoded: 0, malformed_frames: 1 } },
    { name: "failed marker", options: { emittedEvent: { ...scheduledFrame(), logs: [{ message: ["[staging_d1_runtime_probe] failed reason=probe_failed"] }] } }, expect: { failed_markers: 1, rejected_markers: 0 } },
    { name: "rejected marker", options: { emittedEvent: { ...scheduledFrame(), logs: [{ message: ["[staging_d1_runtime_probe] rejected reason=staging_guard"] }] } }, expect: { failed_markers: 0, rejected_markers: 1 } },
    { name: "malformed receipt", options: { emittedEvent: { ...scheduledFrame(), logs: [{ message: ["[staging_d1_runtime_probe] receipt=malformed-private-payload"] }] } }, expect: { receipt_markers: 1, malformed_receipts: 1 } },
    { name: "wrong nonce receipt", options: { emittedEvent: scheduledFrame({ ...receipt, probe_nonce: "wrong-window", private_event_sentinel: "must-not-be-retained" }) }, expect: { receipt_markers: 1, wrong_nonce_receipts: 1, accepted_receipts: 0 } },
    { name: "wrong release receipt", options: { emittedEvent: scheduledFrame({ ...receipt, worker_release: "f".repeat(40) }) }, expect: { wrong_release_receipts: 1, schema_rejected_receipts: 1 } },
    { name: "out-of-window receipt", options: { emittedEvent: scheduledFrame({ ...receipt, scheduled_time_ms: now - 1 }) }, expect: { out_of_window_receipts: 1, schema_rejected_receipts: 1 } },
    { name: "failed receipt flags", options: { emittedEvent: scheduledFrame({ ...receipt, failed_batch_observed: false }) }, expect: { schema_rejected_receipts: 1 } },
  ];
  for (const item of cases) {
    const h = harness(item.options);
    await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
      imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now, timeoutMs: 5,
    }), error => {
      const diagnostic = failureDiagnostic(error);
      assert.equal(diagnostic.code, "receipt_timeout", item.name);
      for (const [key, expected] of Object.entries(item.expect)) {
        assert.equal(diagnostic.tail_evidence.counters[key], expected, `${item.name}: ${key}`);
      }
      assert.equal(diagnostic.tail_evidence.counters.accepted_receipts, 0);
      assert.equal(JSON.stringify(diagnostic).includes("private_event_sentinel"), false);
      assert.equal(JSON.stringify(diagnostic).includes("must-not-be-retained"), false);
      assert.equal(h.tailDeleted, true, `${item.name}: tail cleanup`);
      assert.deepEqual(h.schedules, [], `${item.name}: schedule cleanup`);
      assert.equal(JSON.stringify(diagnostic).includes("wrong-window"), false);
      return true;
    });
  }
});


test("decodes Cloudflare scheduled text, ArrayBuffer and Blob frames", async () => {
  for (const frameKind of ["text", "arraybuffer", "blob"]) {
    const h = harness({ frameKind });
    const proof = await runRuntimeProbe({ token: "token", release, expectedSha: release,
      imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now });
    assert.deepEqual(proof.receipt, receipt);
    assert.equal(h.tailDeleted, true);
  }
  assert.equal(await decodeTailFrame(new Blob(["x".repeat(1024 * 1024 + 1)])), undefined);
  await assert.rejects(decodeTailFrame(new Uint8Array([255]).buffer));
  assert.equal(await decodeTailFrame({ secret: "do-not-print" }), undefined);
});

test("open failure and wrong protocol never install a schedule and delete the tail", async () => {
  for (const openMode of ["timeout", "error", "wrong_protocol"]) {
    const h = harness({ openMode });
    await assert.rejects(runRuntimeProbe({ token: "token", release, expectedSha: release,
      imageDigest, api: h.api, socketFactory: h.socketFactory, now: () => now, timeoutMs: 10,
    }), error => {
      assert.equal(failureDiagnostic(error).stage, "tail_connect");
      assert.match(failureDiagnostic(error).code, /^tail_/);
      return true;
    });
    assert.deepEqual(h.puts, []);
    assert.equal(h.tailDeleted, true);
  }
});

test("diagnostics never echo exception text, body, credentials or tail URLs", async () => {
  assert.deepEqual(failureDiagnostic(Object.assign(new Error("secret wss://secret"),
    { stage: "secret", httpStatus: "secret" })), { stage: "local_validation", code: "unexpected_error" });
  await assert.rejects(runRuntimeProbe({ token: "secret-token", release, expectedSha: release,
    imageDigest, now: () => now,
    api: async () => ({ ok: false, status: 403, json: async () => ({ success: false, errors: ["secret-body"] }) }),
  }), error => {
    assert.deepEqual(failureDiagnostic(error), { stage: "schedule_preflight", code: "api_failure", http_status: 403 });
    assert.ok(!JSON.stringify(error).includes("secret"));
    return true;
  });
});

test("native WebSocket negotiates trace-v1, initializes, and consumes a binary Cloudflare event", async (t) => {
  const server = createServer();
  let peer;
  let markInitialized;
  const initialized = new Promise(resolve => { markInitialized = resolve; });
  server.on("upgrade", (request, socket) => {
    peer = socket;
    assert.equal(request.headers["sec-websocket-protocol"], "trace-v1");
    const accept = createHash("sha1").update(request.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: trace-v1\r\n\r\n`);
    let bytes = Buffer.alloc(0);
    socket.on("data", data => {
      bytes = Buffer.concat([bytes, data]);
      if (bytes.length < 6) return;
      const length = bytes[1] & 127;
      if (bytes.length < 6 + length) return;
      assert.equal(bytes[0], 0x81);
      assert.equal(bytes[1] & 128, 128);
      const payload = Buffer.from(bytes.subarray(6, 6 + length));
      for (let i = 0; i < length; i++) payload[i] ^= bytes[2 + i % 4];
      assert.deepEqual(JSON.parse(payload.toString()), { debug: false });
      socket.removeAllListeners("data");
      markInitialized();
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { peer?.destroy(); server.close(); });
  let schedules = [], tailDeleted = false;
  function sendFrame(payload, opcode) {
    const data = Buffer.from(payload);
    const header = Buffer.alloc(4);
    header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(data.length, 2);
    peer.write(Buffer.concat([header, data]));
  }
  const api = async (url, init = {}) => {
    const method = init.method ?? "GET";
    if (url.endsWith("/tails") && method === "POST") {
      assert.deepEqual(JSON.parse(init.body), { filters: [] });
      return response({ success: true, result: { id: "a".repeat(32), url: "wss://redacted.invalid/tail", expires_at: new Date(now + 3600000).toISOString() } });
    }
    if (method === "DELETE") { tailDeleted = true; return response({ success: true }); }
    if (method === "PUT") {
      schedules = JSON.parse(init.body);
      if (schedules.length) {
        await initialized;
        sendFrame("invalid JSON that must not be logged", 1);
        sendFrame(JSON.stringify(scheduledFrame()), 2);
      }
    }
    return response({ success: true, result: { schedules } });
  };
  const proof = await runRuntimeProbe({ token: "test-token", release, expectedSha: release,
    imageDigest, now: () => now, timeoutMs: 2000, api,
    socketFactory: (_url, protocol) => new WebSocket(`ws://127.0.0.1:${server.address().port}`, protocol),
  });
  assert.deepEqual(proof.receipt, receipt);
  assert.deepEqual(schedules, []);
  assert.equal(tailDeleted, true);
});


test("exact application read uses provider detail envelope and rejects stale-list and unhealthy shapes", async () => {
  const envelope = { success: true, errors: [], messages: [], result: {
    account_id: ACCOUNT_ID, id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, version: 9, instances: 5,
    configuration: { image: `registry.cloudflare.com/${ACCOUNT_ID}/${CONTAINER_APP_NAME}@${imageDigest}` },
    health: { errors: [], instances: { active: 0, assigned: 0, healthy: 5, stopped: 0, failed: 0, scheduling: 0, starting: 0 } },
  } };
  const rows = normalizeContainerDetail(envelope);
  const starting = structuredClone(envelope);
  starting.result.health.instances.healthy = 4;
  starting.result.health.instances.starting = 1;
  const pendingRows = normalizeContainerDetail(starting, { requireHealthy: false });
  assert.equal(pendingRows[0].exact_application_health_verified, false);
  let clock = 0, reads = 0;
  const preimage = captureContainerPreimage(JSON.stringify([containerRow(8, `sha256:${"b".repeat(64)}`)]));
  const converged = await waitForContainerState({ preimage, expectedDigest: imageDigest,
    now: () => clock, sleep: async ms => { clock += ms; },
    read: async () => JSON.stringify(++reads === 1 ? pendingRows : rows),
  });
  assert.equal(reads, 2);
  assert.equal(converged.state.application_version, 9);
  await assert.rejects(waitForContainerState({ preimage, expectedDigest: imageDigest, timeoutMs: 10, intervalMs: 5,
    now: () => clock, sleep: async ms => { clock += ms; }, read: async () => JSON.stringify(pendingRows),
  }), /deadline/);
  assert.equal(rows[0].version, 9);
  assert.equal(rows[0].exact_application_health_verified, true);
  const text = await readContainerDetail({ token: "fixture", api: async (url, options) => {
    assert.equal(url, `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/containers/applications/${CONTAINER_APP_ID}`);
    assert.equal(options.headers.Authorization, "Bearer fixture");
    assert.ok(options.signal);
    return { ok: true, json: async () => envelope };
  } });
  assert.deepEqual(JSON.parse(text), rows);
  for (const mutate of [
    e => { e.success = false; }, e => { delete e.result; }, e => { e.result.account_id = "wrong"; },
    e => { e.result.id = "wrong"; }, e => { e.result.name = "wrong"; },
    e => { delete e.result.configuration; }, e => { e.result.configuration.image = "mutable:latest"; },
    e => { e.result.version = "9"; }, e => { e.result.version = 0; }, e => { e.result.instances = 4; },
    e => { delete e.result.health; }, e => { e.result.health.errors = ["unhealthy"]; },
    e => { e.result.health.instances.healthy = 4; }, e => { e.result.health.instances.failed = 1; },
    e => { delete e.result.health.instances.starting; },
  ]) {
    const bad = structuredClone(envelope); mutate(bad);
    assert.throws(() => normalizeContainerDetail(bad));
  }
  assert.throws(() => normalizeContainerDetail(rows));
  assert.throws(() => verifyContainerState(text, imageDigest, { expectedVersion: 8 }));
  assert.throws(() => verifyContainerState(text, `sha256:${"b".repeat(64)}`, { expectedVersion: 9 }));
  await assert.rejects(readContainerDetail({ token: "fixture", api: async () => ({ ok: false }) }));
  const workflow = await readFile(new URL("../../.github/workflows/issue-1700-container-staging-deploy.yml", import.meta.url), "utf8");
  assert.doesNotMatch(workflow, /wrangler containers list/);
});
