import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { runRuntimeProbe, captureDeployImageDigest, captureContainerPreimage, verifyContainerPreimage, verifyContainerImageDigest, verifyContainerState, verifyContainerRollback, CONTAINER_APP_ID, CONTAINER_APP_NAME, PROBE_CRON, PROBE_EXPIRY } from "../issue_1700_runtime_probe.mjs";

const release = "0123456789abcdef0123456789abcdef01234567";
const now = Date.parse("2026-09-28T00:02:00Z");
const imageDigest = `sha256:${"a".repeat(64)}`;
const receipt = {
  contract: "corelink-staging-d1-binding-runtime-v1",
  outcome: "pass",
  worker_release: release,
  scheduled_time_ms: Date.parse("2026-09-28T00:01:00Z"),
  parameterized_select: true,
  failed_batch_observed: true,
  rollback_absence_verified: true,
  probe_table_dropped: true,
  d1_binding_intercepted: true,
  authorization_absent: true,
  cf_api_token_absent: true,
};

function harness({ schedules: initial = [], sendReceipt = true, driftAfterReceipt = false } = {}) {
  let schedules = initial;
  let socket;
  let tailDeleted = false;
  const puts = [];
  let scheduleReads = 0;
  const api = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method ?? "GET";
    if (path.endsWith("/schedules") && method === "GET") {
      scheduleReads += 1;
      if (driftAfterReceipt && scheduleReads === 3) schedules = [{ cron: "0 0 * * *" }];
      return response({ success: true, result: { schedules } });
    }
    if (path.endsWith("/tails") && method === "POST") {
      return response({ success: true, result: {
        id: "0123456789abcdef0123456789abcdef",
        expires_at: new Date(now + 30 * 60_000).toISOString(),
        url: "wss://tail.example.invalid/secret-in-memory",
      } });
    }
    if (path.endsWith("/schedules") && method === "PUT") {
      const next = JSON.parse(init.body);
      puts.push(next);
      schedules = next;
      if (next.length === 1 && sendReceipt) {
        queueMicrotask(() => socket.onmessage({ data: JSON.stringify({
          logs: [{ message: [`[staging_d1_runtime_probe] receipt=${JSON.stringify(receipt)}`] }],
        }) }));
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
    socketFactory: () => {
      socket = { onmessage: undefined, onerror: undefined, onclose: undefined, close() {} };
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
