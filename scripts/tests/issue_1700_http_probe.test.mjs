import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { APPROVED_ORIGIN, HTTP_PATH, HTTP_CONTRACT, ATTEMPT_CONTRACT, EXECUTE_MS, CLEANUP_MS,
  TRANSPORT_ALLOWANCE_MS, MAX_STATUS_READS, runProof, persistAttempt,
  validateAttempt, validateHttpStatus, validateDeploymentProof } from "../issue_1700_http_probe.mjs";
import { PROBE_WINDOW } from "../issue_1700_probe_window.mjs";

const release = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const startedAt = PROBE_WINDOW.starts_ms + 35_123;
const credentials = { release, expectedSha: release, imageDigest: digest,
  authKey: "private-admin-test-key", apiToken: "private-inventory-test-key", attemptPath: "/fixture/attempt.json" };
function fixture() {
  const attempt = { contract: ATTEMPT_CONTRACT, carrier: "authenticated_http", origin: APPROVED_ORIGIN,
    worker_release: release, probe_nonce: PROBE_WINDOW.nonce, started_at_ms: startedAt,
    scheduled_time_ms: Math.floor(startedAt / 120_000) * 120_000,
    deadline_ms: startedAt + EXECUTE_MS + CLEANUP_MS,
    transport_deadline_ms: startedAt + EXECUTE_MS + CLEANUP_MS + TRANSPORT_ALLOWANCE_MS,
    request_attempted: true };
  const native = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass", worker_release: release,
    probe_nonce: PROBE_WINDOW.nonce, scheduled_time_ms: attempt.scheduled_time_ms,
    old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true,
    v5_probe_release: "cc32b3d819181bf9175e795868f66212aa5456c1", v5_probe_retired: true, v5_probe_tables_absent: true,
    v5_prior_execution: "unknown", v4_probe_catalog_absent: true,
    parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true, probe_table_dropped: true,
    d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true };
  const cleanup = version => ({ contract: `corelink-staging-${version}-cleanup-v1`,
    old_release: version === "v8" ? "7d18bcfc450db97b1b987923050b92971da530a8" : "5da497051f0b11dbfc8b87d1dfa8e753304e2719",
    old_nonce: `issue-1700-recovery-20261001-${version}`, worker_release: release, prior_execution: "unknown",
    prior_admission_present: false, container_stopped: true, alarm_absent: true, tables_absent: true,
    completed_at_ms: startedAt + 1000 });
  const status = { contract: HTTP_CONTRACT, carrier: "authenticated_http", worker_release: release,
    probe_nonce: PROBE_WINDOW.nonce, status: "complete", rollback_safe: true,
    native_receipt: native, v8_cleanup: cleanup("v8"), v9_cleanup: cleanup("v9") };
  return { attempt, status };
}
const jsonResponse = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const pending = status => ({ contract: HTTP_CONTRACT, carrier: "authenticated_http", worker_release: release,
  probe_nonce: PROBE_WINDOW.nonce, status, rollback_safe: false, native_receipt: null, v8_cleanup: null, v9_cleanup: null });
function harness(handler) {
  const clock = { value: startedAt }, calls = [], ledgers = [];
  const options = { ...credentials, now: () => clock.value,
    writeAttempt: async (_path, attempt) => { ledgers.push(structuredClone(attempt)); },
    sleep: async ms => { clock.value += ms; },
    request: async (url, init) => {
      assert.equal(ledgers.length, 1, "durable attempt must precede POST");
      calls.push({ url, ...init });
      assert.equal(init.redirect, "error");
      assert.equal(init.credentials, "omit");
      if (url.startsWith(APPROVED_ORIGIN)) {
        assert.equal(url, APPROVED_ORIGIN + HTTP_PATH);
        assert.equal(init.headers["x-corelink-internal-auth"], credentials.authKey);
        assert.equal(init.headers.authorization, undefined);
        assert.equal(init.headers.cookie, undefined);
        if (init.method === "POST") assert.deepEqual(JSON.parse(init.body), {
          worker_release: release, probe_nonce: PROBE_WINDOW.nonce, scheduled_time_ms: fixture().attempt.scheduled_time_ms });
        else { assert.equal(init.method, "GET"); assert.equal(init.body, undefined); }
        clock.value += 1000;
        return handler ? handler(url, init, clock) : jsonResponse(fixture().status);
      }
      assert.equal(init.method, "GET");
      assert.equal(init.headers["x-corelink-internal-auth"], undefined);
      assert.equal(init.headers.authorization, `Bearer ${credentials.apiToken}`);
      const path = new URL(url).pathname;
      assert.match(path, /\/workers\/scripts\/corelink-staging\/(schedules|tails)$/);
      return jsonResponse({ success: true, result: path.endsWith("/schedules") ? { schedules: [] } : [] });
    } };
  return { clock, calls, ledgers, options };
}

test("one POST plus actual empty inventories produces the authenticated HTTP wrapper", async () => {
  const h = harness();
  const proof = await runProof(h.options);
  assert.equal(validateDeploymentProof(proof, h.ledgers[0], { expectedRelease: release,
    expectedImageDigest: digest, observedAt: h.clock.value }), true);
  assert.equal(proof.carrier, "authenticated_http");
  assert.equal(Object.keys(proof.http_proof).length, 9);
  assert.equal(Object.keys(proof.receipt).length, 20);
  assert.equal(Object.keys(proof.http_proof.v8_cleanup).length, 10);
  assert.equal(Object.keys(proof.http_proof.v9_cleanup).length, 10);
  assert.deepEqual(h.calls.map(call => call.method), ["POST", "GET", "GET"]);
  assert.equal(proof.schedules_empty, true);
  assert.equal(proof.tails_empty, true);
  assert.equal(proof.schedule_restored_empty, undefined);
  assert.equal(proof.tail_deleted, undefined);
  for (const secret of [credentials.authKey, credentials.apiToken]) {
    assert.ok(!JSON.stringify(proof).includes(secret));
    assert.ok(!JSON.stringify(h.ledgers).includes(secret));
  }
});

test("lost POST response recovers only through bounded authenticated status without replay", async () => {
  const h = harness((_url, init) => {
    if (init.method === "POST") throw new Error(credentials.authKey);
    return jsonResponse(fixture().status);
  });
  assert.equal((await runProof(h.options)).http_proof.status, "complete");
  assert.deepEqual(h.calls.map(call => call.method), ["POST", "GET", "GET", "GET"]);
});

test("running response uses at most three status reads within the original budget", async () => {
  const h = harness(() => jsonResponse(pending("running"), 202));
  await assert.rejects(runProof(h.options), /^Error: http_status_unknown$/);
  assert.equal(h.calls.filter(call => call.method === "POST").length, 1);
  assert.equal(h.calls.filter(call => call.method === "GET").length, MAX_STATUS_READS);
  assert.ok(h.clock.value <= fixture().attempt.transport_deadline_ms);
});

for (const status of ["unknown", "not_started"]) {
  test(`${status} cannot imply completion or permit another execute`, async () => {
    const h = harness(() => jsonResponse(pending(status)));
    await assert.rejects(runProof(h.options), /http_status_unknown/);
    assert.deepEqual(h.calls.map(call => call.method), ["POST"]);
  });
}

test("client timeout does not claim server cancellation or accept a late POST result", async () => {
  let late;
  const h = harness((_url, init) => init.method === "POST"
    ? new Promise(resolve => { late = resolve; }) : jsonResponse(pending("unknown")));
  let timers = 0;
  h.options.setTimeoutFn = callback => { if (++timers === 1) queueMicrotask(callback); return timers; };
  h.options.clearTimeoutFn = () => {};
  await assert.rejects(runProof(h.options), /http_status_unknown/);
  assert.deepEqual(h.calls.map(call => call.method), ["POST", "GET"]);
  assert.equal(h.calls[0].signal.aborted, true);
  late(jsonResponse(fixture().status));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.calls.length, 2);
  assert.equal(h.ledgers[0].request_attempted, true);
});

test("signal cancellation leaves attempted execution unsafe without another request", async () => {
  const controller = new AbortController();
  const h = harness(() => { controller.abort(); return jsonResponse(fixture().status); });
  h.options.signal = controller.signal;
  await assert.rejects(runProof(h.options), /http_status_unknown/);
  assert.deepEqual(h.calls.map(call => call.method), ["POST"]);
  assert.equal(h.ledgers.length, 1);
});

test("ledger failure prevents execute and exclusive persistence prevents replay", async t => {
  const directory = await mkdtemp(join(tmpdir(), "issue1700-http-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "attempt.json");
  const attempt = fixture().attempt;
  await persistAttempt(path, attempt);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await readFile(path, "utf8")), attempt);
  await assert.rejects(persistAttempt(path, attempt), /EEXIST/);
  const h = harness();
  h.options.writeAttempt = async () => { throw new Error(credentials.authKey); };
  await assert.rejects(runProof(h.options), /^Error: http_attempt_ledger_rejected$/);
  assert.equal(h.calls.length, 0);
});

for (const origin of ["https://arbitrary.workers.dev", APPROVED_ORIGIN + "/", APPROVED_ORIGIN + "?token=secret",
  APPROVED_ORIGIN.replace("https:", "http:"), APPROVED_ORIGIN + ":443", APPROVED_ORIGIN.replace("https://", "https://user@")]) {
  test(`rejects unapproved origin ${origin}`, async () => {
    const h = harness();
    await assert.rejects(runProof({ ...h.options, origin }), /http_preflight_rejected/);
    assert.equal(h.calls.length, 0);
    assert.equal(h.ledgers.length, 0);
  });
}

test("missing auth, reused provider token, source mismatch and absent image fail before POST", async () => {
  for (const changed of [{ authKey: "" }, { authKey: credentials.apiToken },
    { expectedSha: "c".repeat(40) }, { imageDigest: "" }, { apiToken: "" }]) {
    const h = harness();
    await assert.rejects(runProof({ ...h.options, ...changed }), /http_preflight_rejected/);
    assert.equal(h.calls.length, 0);
  }
});

test("strict envelope and native receipt reject missing, extra, wrong-source and unsafe fields", () => {
  const changes = [
    s => { delete s.rollback_safe; }, s => { s.extra = "private"; }, s => { s.carrier = "cron"; },
    s => { s.worker_release = "c".repeat(40); }, s => { s.probe_nonce = "wrong"; },
    s => { s.rollback_safe = false; }, s => { s.status = "running"; },
    s => { s.native_receipt.scheduled_time_ms += 120000; }, s => { s.native_receipt.worker_release = "c".repeat(40); },
    s => { s.native_receipt.probe_nonce = "wrong"; }, s => { s.native_receipt.extra = true; },
    s => { delete s.native_receipt.v5_prior_execution; }, s => { s.native_receipt.old_probe_retired = false; },
    s => { s.native_receipt.cf_api_token_absent = 1; }, s => { s.native_receipt.v5_prior_execution = "pass"; },
  ];
  for (const change of changes) {
    const { attempt, status } = fixture();
    change(status);
    assert.equal(validateHttpStatus(status, attempt, { expectedRelease: release, observedAt: startedAt + 2000, requireComplete: true }), false);
  }
});

for (const version of ["v8", "v9"]) {
  test(`${version} cleanup requires all ten exact facts and inclusive start/exclusive deadline`, () => {
    const changes = [c => { delete c.alarm_absent; }, c => { c.extra = true; }, c => { c.old_release = release; },
      c => { c.old_nonce = PROBE_WINDOW.nonce; }, c => { c.worker_release = "c".repeat(40); },
      c => { c.contract = "wrong"; }, c => { c.prior_execution = "pass"; }, c => { c.prior_admission_present = 1; },
      c => { c.container_stopped = false; }, c => { c.alarm_absent = false; }, c => { c.tables_absent = false; },
      c => { c.completed_at_ms = startedAt - 1; }, c => { c.completed_at_ms = startedAt + 2001; },
      c => { c.completed_at_ms = fixture().attempt.deadline_ms; }, c => { c.completed_at_ms = PROBE_WINDOW.expires_ms; },
      c => { c.completed_at_ms = 1.5; }, c => { c.completed_at_ms = Number.MAX_SAFE_INTEGER + 1; }];
    for (const change of changes) {
      const { attempt, status } = fixture();
      change(status[version + "_cleanup"]);
      assert.equal(validateHttpStatus(status, attempt, { observedAt: startedAt + 2000, requireComplete: true }), false);
    }
    const { attempt, status } = fixture();
    status[version + "_cleanup"].completed_at_ms = startedAt;
    assert.equal(validateHttpStatus(status, attempt, { observedAt: startedAt + 1000, requireComplete: true }), true);
    status[version + "_cleanup"].completed_at_ms = attempt.deadline_ms - 1;
    assert.equal(validateHttpStatus(status, attempt, { observedAt: attempt.deadline_ms - 1, requireComplete: true }), true);
  });
}

test("attempt ledger binds origin, exact current bucket, release, nonce and fixed budgets", () => {
  assert.equal(validateAttempt(fixture().attempt, release), true);
  for (const field of ["origin", "worker_release", "probe_nonce", "scheduled_time_ms", "deadline_ms", "transport_deadline_ms", "request_attempted"]) {
    const { attempt } = fixture();
    attempt[field] = typeof attempt[field] === "number" ? attempt[field] + 1 : "wrong";
    assert.equal(validateAttempt(attempt, release), false, field);
  }
});

test("malformed, redirected and oversized responses cannot provide HTTP proof", async () => {
  for (const response of [
    () => new Response("private-body", { status: 200, headers: { "content-type": "application/json" } }),
    () => new Response("", { status: 302, headers: { location: "https://private.invalid" } }),
    () => new Response("x".repeat(16385), { status: 200, headers: { "content-type": "application/json" } }),
  ]) {
    const h = harness((_url, init) => init.method === "POST" ? response() : jsonResponse(pending("unknown")));
    await assert.rejects(runProof(h.options), /^Error: http_status_unknown$/);
    assert.deepEqual(h.calls.map(call => call.method), ["POST", "GET"]);
  }
});

test("a complete envelope without actual empty schedule/tail inventory is not a deployment proof", async () => {
  for (const target of ["schedules", "tails"]) {
    const h = harness();
    const original = h.options.request;
    h.options.request = async (url, init) => url.endsWith("/" + target)
      ? jsonResponse({ success: true, result: target === "schedules" ? { schedules: [{ cron: "private" }] } : [{ id: "private" }] })
      : original(url, init);
    await assert.rejects(runProof(h.options), /^Error: http_inventory_unproven$/);
    assert.equal(h.calls.filter(call => call.method === "POST").length, 1);
  }
});

test("outer proof cannot substitute another receipt, digest or falsely claim a different carrier", async () => {
  const h = harness();
  const proof = await runProof(h.options);
  for (const change of [p => { p.receipt = { ...p.receipt, outcome: "fail" }; },
    p => { p.container_image_digest = `sha256:${"c".repeat(64)}`; }, p => { p.carrier = "cron"; },
    p => { p.tails_empty = false; }, p => { p.schedules_empty = false; }, p => { p.http_proof.rollback_safe = false; }]) {
    const bad = structuredClone(proof);
    change(bad);
    assert.equal(validateDeploymentProof(bad, h.ledgers[0], { expectedRelease: release, expectedImageDigest: digest,
      observedAt: h.clock.value }), false);
  }
});
