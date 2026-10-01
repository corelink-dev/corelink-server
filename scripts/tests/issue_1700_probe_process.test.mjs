import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PROBE_WINDOW, PROBE_CRON } from "../issue_1700_runtime_probe.mjs";

for (const cleanupFails of [false, true]) {
test(`CLI exits ${cleanupFails ? "failure" : "success"} after cleanup settles despite an unacknowledged tail close`, { timeout: 6000 }, async (t) => {
  const release = "a".repeat(40), digest = `sha256:${"b".repeat(64)}`;
  const now = PROBE_WINDOW.starts_ms + 120_000;
  const receipt = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
    worker_release: release, probe_nonce: PROBE_WINDOW.nonce, scheduled_time_ms: now,
    parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
    probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true, old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true, v5_probe_release: "cc32b3d819181bf9175e795868f66212aa5456c1", v5_probe_retired: true, v5_probe_tables_absent: true, v5_prior_execution: "unknown", v4_probe_catalog_absent: true };
  const v8Cleanup = { contract: "corelink-staging-v8-cleanup-v1",
    old_release: "7d18bcfc450db97b1b987923050b92971da530a8", old_nonce: "issue-1700-recovery-20261001-v8",
    worker_release: release, prior_execution: "unknown", prior_admission_present: true,
    container_stopped: true, alarm_absent: true, tables_absent: true, completed_at_ms: now };
  let peer, schedules = [], tailDeleted = false, initialized = false;
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    let result = {};
    if (request.url.endsWith("/tails") && request.method === "POST") {
      result = { id: "c".repeat(32), url: "wss://tail.invalid/private", expires_at: new Date(now + 3600000).toISOString() };
    } else if (request.method === "DELETE") {
      tailDeleted = !cleanupFails;
    } else if (request.url.endsWith("/schedules")) {
      if (request.method === "PUT") {
        schedules = JSON.parse(body);
        if (schedules.length) {
          assert.equal(initialized, true, "the real ws initialization frame must precede the schedule");
          assert.deepEqual(schedules, [{ cron: PROBE_CRON }]);
          const data = Buffer.from(JSON.stringify({ outcome: "ok", scriptName: "corelink-staging",
            event: { cron: PROBE_CRON, scheduledTime: now }, logs: [
              { level: "info", timestamp: now, message: [`[staging_d1_runtime_probe] v8_cleanup=${JSON.stringify(v8Cleanup)}`] },
              { level: "info", timestamp: now, message: [`[staging_d1_runtime_probe] receipt=${JSON.stringify(receipt)}`] },
            ] }));
          const header = Buffer.alloc(4);
          header[0] = 0x82; header[1] = 126; header.writeUInt16BE(data.length, 2);
          peer.write(Buffer.concat([header, data]));
        }
      }
      result = { schedules };
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ success: !(cleanupFails && request.method === "DELETE"), result }));
  });
  server.on("upgrade", (request, socket) => {
    peer = socket;
    const accept = createHash("sha1").update(request.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: trace-v1\r\n\r\n`);
    let pending = Buffer.alloc(0);
    socket.on("data", bytes => {
      if (initialized) return; // Deliberately do not acknowledge the close frame.
      pending = Buffer.concat([pending, bytes]);
      if (pending.length < 2) return;
      const length = pending[1] & 127;
      assert.equal(pending[0], 0x81, "initialization is uncompressed FIN text");
      assert.equal(pending[1] & 128, 0, "Wrangler trace initialization uses MASK=0");
      assert.ok(length < 126);
      if (pending.length < length + 2) return;
      assert.deepEqual(JSON.parse(pending.subarray(2, length + 2).toString()), { debug: false });
      initialized = true;
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const directory = await mkdtemp(join(tmpdir(), "issue1700-process-"));
  t.after(async () => { peer?.destroy(); server.closeAllConnections(); server.close(); await rm(directory, { recursive: true }); });
  const port = server.address().port;
  const preload = join(directory, "local-only.mjs");
  await writeFile(preload, `
    Date.now = () => ${now};
    const nativeFetch = globalThis.fetch;
    globalThis.fetch = (url, options) => nativeFetch("http://127.0.0.1:${port}" + new URL(url).pathname, options);
  `);
  const loader = join(directory, "ws-loader.mjs");
  await writeFile(loader, `
    export async function resolve(specifier, context, nextResolve) {
      if (specifier === "ws") return {
        url: "data:text/javascript," + encodeURIComponent(${JSON.stringify(`import WebSocket from ${JSON.stringify(import.meta.resolve("ws"))}; export default class extends WebSocket { constructor(_url, protocol) { super("ws://127.0.0.1:${port}", protocol); } }`)}),
        shortCircuit: true,
      };
      return nextResolve(specifier, context);
    }
  `);
  const child = spawn(process.execPath, ["--import", preload, "--experimental-loader", loader,
    new URL("../issue_1700_runtime_probe.mjs", import.meta.url).pathname], {
    env: { ...process.env, CLOUDFLARE_API_TOKEN: "local-fixture", SENTRY_RELEASE: release, EXPECTED_SHA: release, IMAGE_DIGEST: digest },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill("SIGKILL"));
  let output = "", errors = "";
  child.stdout.on("data", data => { output += data; });
  child.stderr.on("data", data => { errors += data; });
  const exited = new Promise(resolve => child.once("exit", (code, signal) => resolve({ code, signal })));
  // Include process/loader startup while remaining far below ws's 30s close wait.
  const timer = setTimeout(() => child.kill("SIGKILL"), 4000);
  const status = await exited;
  clearTimeout(timer);
  assert.equal(tailDeleted, !cleanupFails);
  assert.deepEqual(schedules, []);
  if (cleanupFails) {
    assert.equal(output, "");
    assert.match(errors, /"stage":"tail_cleanup","code":"api_failure"/);
  } else {
    const proof = JSON.parse(output);
    assert.equal(proof.receipt.outcome, "pass", errors);
    assert.equal(Object.keys(proof.receipt).length, 20);
    assert.deepEqual(proof.v8_cleanup, v8Cleanup);
  }
  assert.deepEqual(status, { code: cleanupFails ? 1 : 0, signal: null }, "a closing WebSocket must not pin a settled CLI process");
});

}
