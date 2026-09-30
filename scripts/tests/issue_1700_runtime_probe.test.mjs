import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runRuntimeProbe, failureDiagnostic, decodeTailFrame, waitForContainerState, captureDeployImageDigest, captureContainerPreimage, verifyContainerPreimage, verifyContainerImageDigest, verifyContainerState, verifyContainerRollback, CONTAINER_APP_ID, CONTAINER_APP_NAME, PROBE_CRON, PROBE_EXPIRY, PROBE_WINDOW } from "../issue_1700_runtime_probe.mjs";

const release = "0123456789abcdef0123456789abcdef01234567";
const now = Date.parse("2026-09-30T14:01:00Z");
const imageDigest = `sha256:${"a".repeat(64)}`;
const receipt = {
  contract: "corelink-staging-d1-binding-runtime-v1",
  outcome: "pass",
  probe_nonce: PROBE_WINDOW.nonce,
  worker_release: release,
  scheduled_time_ms: Date.parse("2026-09-30T14:01:00Z"),
  parameterized_select: true,
  failed_batch_observed: true,
  rollback_absence_verified: true,
  probe_table_dropped: true,
  d1_binding_intercepted: true,
  authorization_absent: true,
  cf_api_token_absent: true, old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true,
};

// Cloudflare workers-sdk TailEventMessage: scheduled event and console log envelope.
function scheduledFrame(value = receipt) {
  return { outcome: "ok", scriptName: "corelink-staging", exceptions: [],
    eventTimestamp: now, event: { cron: PROBE_CRON, scheduledTime: now },
    logs: [{ level: "info", timestamp: now,
      message: [`[staging_d1_runtime_probe] receipt=${JSON.stringify(value)}`] }],
  };
}

function harness({ schedules: initial = [], sendReceipt = true, driftAfterReceipt = false, emittedReceipt = receipt, frameKind = "text", openMode = "open" } = {}) {
  let schedules = initial;
  let socket;
  let tailDeleted = false;
  const puts = [];
  let scheduleReads = 0;
  let initialized = false;
  const api = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method ?? "GET";
    if (path.endsWith("/schedules") && method === "GET") {
      scheduleReads += 1;
      if (driftAfterReceipt && scheduleReads === 3) schedules = [{ cron: "0 0 * * *" }];
      return response({ success: true, result: { schedules } });
    }
    if (path.endsWith("/tails") && method === "POST") {
      assert.equal(init.headers["content-type"], "application/json");
      assert.deepEqual(JSON.parse(init.body), { filters: [] });
      return response({ success: true, result: {
        id: "0123456789abcdef0123456789abcdef",
        expires_at: new Date(now + 30 * 60_000).toISOString(),
        url: "wss://tail.example.invalid/secret-in-memory",
      } });
    }
    if (path.endsWith("/schedules") && method === "PUT") {
      const next = JSON.parse(init.body);
      if (next.length) assert.equal(initialized, true, "tail handshake precedes schedule installation");
      puts.push(next);
      schedules = next;
      if (next.length === 1 && sendReceipt) {
        const text = JSON.stringify(scheduledFrame(emittedReceipt));
        const data = frameKind === "arraybuffer" ? new TextEncoder().encode(text).buffer
          : frameKind === "blob" ? new Blob([text]) : text;
        queueMicrotask(() => socket.onmessage({ data }));
      }
      return response({ success: true, result: { schedules } });
    }
    if (path.endsWith("/tails/0123456789abcdef0123456789abcdef") && method === "DELETE") {
      tailDeleted = true;
      return response({ success: true, result: {} });
    }
    throw new Error("unexpected test API request");
  };
  return {
    api,
    socketFactory: (_url, protocol) => {
      assert.equal(protocol, "trace-v1");
      socket = { protocol: openMode === "wrong_protocol" ? "" : protocol,
        onmessage: undefined, onerror: undefined, onclose: undefined, close() {},
        send(value) { assert.deepEqual(JSON.parse(value), { debug: false }); initialized = true; },
      };
      if (openMode !== "timeout") queueMicrotask(() => openMode === "error" ? socket.onerror() : socket.onopen());
      return socket;
    },
    get schedules() { return schedules; },
    puts,
    get tailDeleted() { return tailDeleted; },
  };
}

function response(body, ok = true) {
  return { ok, json: async () => body };
}

test("installs one exact cron, accepts the release-bound receipt, and restores empty schedules", async () => {
  const h = harness();
  const proof = await runRuntimeProbe({
    token: "test-token-never-logged", release, expectedSha: release,
    imageDigest,
    api: h.api, socketFactory: h.socketFactory, now: () => now, timeoutMs: 16 * 60_000,
  });
  assert.equal(proof.cron, PROBE_CRON);
  assert.equal(proof.receipt.worker_release, release);
  assert.equal(proof.schedule_restored_empty, true);
  assert.deepEqual(h.puts, [[{ cron: PROBE_CRON }], []]);
  assert.deepEqual(h.schedules, []);
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
  return { id: CONTAINER_APP_ID, name: CONTAINER_APP_NAME, version,
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
  for (const emittedReceipt of [
    { ...receipt, probe_nonce: "old-window" },
    { ...receipt, worker_release: "f".repeat(40) },
    { ...receipt, old_probe_retired: false },
    { ...receipt, old_probe_tables_absent: false },
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
