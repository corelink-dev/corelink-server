import test from "node:test";
import assert from "node:assert/strict";
import fsPromises, { appendFile, mkdtemp, open, readFile, readdir, rename, rm, chmod, lstat, symlink, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { once } from "node:events";
import { execFile, spawn } from "node:child_process";
import { PassThrough } from "node:stream";
import {
  BROKER_CONTRACT, BROKER_LEDGER, BROKER_SOCKET, BROKER_PROCESS, MAX_LIFETIME_MS, PROBE_RESERVE_MS, SECRET_NAME,
  bindingInventory, deploymentInventory, subdomainState, createBootstrapBroker,
  serveBroker, brokerCommand, startBroker, privateDirectory, captureBrokerProcess, shutdownBroker,
  FAILURE_KEYS, FAILURE_PHASES, FAILURE_VALIDATIONS, failureLine, ledgerFailureLine, validFailure,
  SECRETS_FILE, RESTORE_CONTRACT, verifyRestoredPreimage,
} from "../issue_1700_http_bootstrap.mjs";
import { APPROVED_ORIGIN, HTTP_CONTRACT, ATTEMPT_CONTRACT } from "../issue_1700_http_probe.mjs";
import { PROBE_WINDOW } from "../issue_1700_probe_window.mjs";

const RELEASE = "a".repeat(40), IMAGE = `sha256:${"b".repeat(64)}`;
const TOKEN = "fixture-api-credential-not-for-output";
const NOW = PROBE_WINDOW.starts_ms + 120_000;
// Complete sanitized 2026-10-01 settings observation: all 35 names/types, no binding values.
const OBSERVED_BINDINGS = [
  ["AC_BUCKET_IAD", "r2_bucket"],
  ["AUDIT_DRAIN_BATCH_LIMIT", "plain_text"],
  ["AUDIT_DRAIN_LEASE_ENABLED", "plain_text"],
  ["CAS_BUCKET", "r2_bucket"],
  ["CHUNK_BUCKET_IAD", "r2_bucket"],
  ["CLERK_JWKS_KV", "kv_namespace"],
  ["CONFIG_DB", "d1"],
  ["CORELINK_SERVER", "durable_object_namespace"],
  ["D1_DATABASE_ID", "plain_text"],
  ["EDGE_ASYNC_METER", "plain_text"],
  ["EDGE_DO_METER", "plain_text"],
  ["EDGE_FIND_MISSING", "plain_text"],
  ["EDGE_PUBLIC_READ", "plain_text"],
  ["ENVIRONMENT", "plain_text"],
  ["EVENT_LOG_DO", "durable_object_namespace"],
  ["MANIFEST_BUCKET_IAD", "r2_bucket"],
  ["METADATA_KV", "kv_namespace"],
  ["NEGATIVE_CACHE_KV", "kv_namespace"],
  ["OCI_PUBLIC_DEDUP_ENABLED", "plain_text"],
  ["OCI_UPSTREAM_ON_MISS", "plain_text"],
  ["R2_AC_BUCKET", "plain_text"],
  ["R2_AC_REGION", "plain_text"],
  ["R2_CAS_BUCKET", "plain_text"],
  ["R2_CAS_REGION", "plain_text"],
  ["R2_CHUNK_BUCKET", "plain_text"],
  ["R2_CHUNK_REGION", "plain_text"],
  ["R2_S3_ENDPOINT", "plain_text"],
  ["REPLICATION_COORDINATOR_DO", "durable_object_namespace"],
  ["REQUEST_METER_COORDINATOR_DO", "durable_object_namespace"],
  ["REQUEST_METER_SHARD_DO", "durable_object_namespace"],
  ["ROLLOUT_DO", "durable_object_namespace"],
  ["SCHEDULED_DRILL_DELIVERY", "service"],
  ["SENTRY_RELEASE", "plain_text"],
  ["SYNTHETIC_DRILL_ENABLED", "plain_text"],
  ["SYNTHETIC_DRILL_PROVIDER_MODE", "plain_text"],
].map(([name, type]) => ({ name, type }));
const bindingFixture = () => OBSERVED_BINDINGS.map(row => row.name === "SENTRY_RELEASE" ? { ...row, text: RELEASE } : { ...row });
const BOOTSTRAP_SOURCE = fileURLToPath(new URL("../issue_1700_http_bootstrap.mjs", import.meta.url));
const processIdentity = (directory, pid = 1234) => ({ pid, uid: process.getuid(), started: "Thu Oct 1 14:00:00 2026",
  command: `${process.execPath} ${BOOTSTRAP_SOURCE} serve ${directory}` });
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const input = () => ({ api_token: TOKEN, operation_id: "36861129068", expected_release: RELEASE,
  preimage_deployment_id: id(1), preimage_version_id: id(11) });
const candidate = () => ({ operation_id: input().operation_id, candidate_deployment_id: id(3),
  candidate_version_id: id(13), worker_release: RELEASE, image_digest: IMAGE });
const wrapped = result => ({ success: true, errors: [], messages: [], result });
const response = result => Response.json(wrapped(result));
const deployment = (n, at) => ({ id: id(n), created_on: new Date(at).toISOString(), source: "api", strategy: "percentage",
  versions: [{ percentage: 100, version_id: id(n + 10) }], annotations: { "workers/message": "fixture" }, author_email: "not-retained@example.invalid" });

function completeProof(at) {
  const attempt = { contract: ATTEMPT_CONTRACT, carrier: "authenticated_http", origin: APPROVED_ORIGIN,
    worker_release: RELEASE, probe_nonce: PROBE_WINDOW.nonce, scheduled_time_ms: Math.floor(at / 120000) * 120000,
    started_at_ms: at, deadline_ms: at + 1200000, transport_deadline_ms: at + 1260000, request_attempted: true };
  const native = { old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true,
    v5_probe_release: "cc32b3d819181bf9175e795868f66212aa5456c1", v5_probe_retired: true, v5_probe_tables_absent: true,
    v5_prior_execution: "unknown", v4_probe_catalog_absent: true, contract: "corelink-staging-d1-binding-runtime-v1",
    probe_nonce: PROBE_WINDOW.nonce, outcome: "pass", worker_release: RELEASE, scheduled_time_ms: attempt.scheduled_time_ms,
    parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true, probe_table_dropped: true,
    d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true };
  const cleanup = (version, release) => ({ contract: `corelink-staging-${version}-cleanup-v1`, old_release: release,
    old_nonce: `issue-1700-recovery-20261001-${version}`, worker_release: RELEASE, prior_execution: "unknown",
    prior_admission_present: true, container_stopped: true, alarm_absent: true, tables_absent: true, completed_at_ms: at });
  const http = { contract: HTTP_CONTRACT, carrier: "authenticated_http", worker_release: RELEASE, probe_nonce: PROBE_WINDOW.nonce,
    status: "complete", rollback_safe: true, native_receipt: native,
    v8_cleanup: cleanup("v8", "7d18bcfc450db97b1b987923050b92971da530a8"),
    v9_cleanup: cleanup("v9", "5da497051f0b11dbfc8b87d1dfa8e753304e2719") };
  return { attempt, proof: { contract: "corelink-staging-runtime-deployment-proof-v1", carrier: "authenticated_http",
    account_id: "6a1fc1c626fc2628823e60b9db01f5cd", worker_name: "corelink-staging", workflow_sha: RELEASE,
    worker_release: RELEASE, container_image_digest: IMAGE, probe_nonce: PROBE_WINDOW.nonce, origin: APPROVED_ORIGIN,
    http_proof: http, receipt: native, schedules_empty: true, tails_empty: true } };
}
// Cloudflare provider model: versions are immutable once uploaded, a deployment serves one
// version at 100%, and an upload inherits the newest upload's secrets (wrangler's additive
// --secrets-file). The default state is V15's (run 37044496198): the newest upload is a
// prior run's rollback version, NOT the deployed preimage, and it still carries a stale key.
const LATEST_ROLLBACK = id(12);
const versionBody = (versionId, message, bindings) => ({ id: versionId,
  metadata: { created_on: new Date(NOW - 5000).toISOString(), source: "wrangler" },
  annotations: { "workers/message": message }, resources: { bindings, script: { etag: `etag-${versionId}` } } });
const secretRows = bindings => bindings.filter(row => row.type === "secret_text" || row.type === "secret_key")
  .map(row => ({ name: row.name, type: row.type }));
function fixture(options = {}) {
  let clock = NOW, domain = { enabled: false, previews_enabled: false }, attempt, secretsFile = null, latest = null;
  const versions = new Map();
  const upload = (versionId, message, bindings) => { versions.set(versionId, versionBody(versionId, message, bindings)); latest = versionId; };
  upload(id(11), "issue-1700-route-free-rollback-preimage", [...bindingFixture(), ...(options.preimageBindings ?? [])]);
  if (!options.latestIsDeployed) {
    upload(LATEST_ROLLBACK, "issue-1700-route-free-rollback-36861129067-prior",
      [...bindingFixture(), { name: SECRET_NAME, type: "secret_text" }, ...(options.latestSecrets ?? [])]);
  }
  const deployments = [deployment(1, NOW - 1000)];
  const calls = [], snapshots = [], runnerArgs = [], secretWrites = [];
  const request = async (url, init) => {
    const path = new URL(url).pathname.split("/corelink-staging")[1];
    calls.push({ path, method: init.method, body: init.body });
    assert.equal(new URL(url).origin, "https://api.cloudflare.com");
    assert.equal(init.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    if (options.request) {
      const override = await options.request(path, init, calls);
      if (override !== undefined) return override;
    }
    if (path === "/deployments") return response({ deployments });
    if (path.startsWith("/versions/")) {
      const body = versions.get(path.slice("/versions/".length));
      return body ? response(structuredClone(body)) : cfError(404, [{ code: 10007, message: "workers.api.error.version_not_found" }]);
    }
    if (path === "/subdomain") {
      if (init.method === "POST") domain = JSON.parse(init.body);
      return response(domain);
    }
    // The script-level surfaces the old bootstrap used: settings follow the newest upload,
    // and secret edits are refused (10215) while the newest upload is not deployed.
    if (path === "/settings") return response({ bindings: structuredClone(versions.get(latest).resources.bindings) });
    if (path.startsWith("/secrets")) {
      return latest === deployments[0].versions[0].version_id ? response({ name: SECRET_NAME, type: "secret_text" })
        : cfError(400, [{ code: 10215, message: "Secret edit failed. Latest version of your Worker isn't currently deployed." }]);
    }
    assert.fail(`Unexpected fixture API path ${path}`);
  };
  const broker = createBootstrapBroker(input(), { directory: "/tmp/i1700-fixture", request, now: () => clock,
    random: () => Buffer.alloc(32, 73), save: async value => { snapshots.push(structuredClone(value)); },
    writeSecrets: async content => { assert.equal(secretsFile, null); secretsFile = content; secretWrites.push(content); },
    removeSecrets: async () => { secretsFile = null; },
    attemptExists: async () => options.attemptExists ?? attempt !== undefined,
    readAttempt: async () => { if (options.missingAttempt || !attempt) throw new Error("ENOENT"); return attempt; },
    proofRunner: async args => { runnerArgs.push(args); if (options.proofRunner) return options.proofRunner(args);
      const result = completeProof(clock); attempt = result.attempt; return result.proof; },
  });
  return { broker, calls, snapshots, runnerArgs, request, versions, deployments, secretWrites,
    secretsFile: () => secretsFile, latest: () => latest, clock: () => clock,
    advance: ms => { clock += ms; },
    // `wrangler deploy --secrets-file`: a new version with the config bindings, the newest
    // upload's secrets inherited, the file's secrets on top, then deployed at 100%.
    deploy: ({ withFile = true } = {}) => {
      clock += 1010;
      const fromFile = withFile && secretsFile !== null
        ? Object.keys(JSON.parse(secretsFile)).map(name => ({ name, type: "secret_text" })) : [];
      const secrets = new Map([...secretRows(versions.get(latest).resources.bindings), ...fromFile].map(row => [row.name, row]));
      upload(id(13), `issue-1700-route-free-${input().operation_id}-${RELEASE}`, [...bindingFixture(), ...secrets.values()]);
      deployments.unshift(deployment(3, clock));
    },
    drift: () => { clock += 1000; upload(id(19), "someone-else", bindingFixture()); deployments.unshift(deployment(9, clock)); },
    // The workflow's rollback: an upload that inherits the newest upload's secrets, then the
    // exact preimage version redeployed at 100%. The newest upload is left undeployed.
    rollback: () => {
      clock += 1000;
      upload(id(14), "issue-1700-route-free-rollback-this-run", [...bindingFixture(), ...secretRows(versions.get(latest).resources.bindings)]);
      deployments.unshift(deployment(4, clock));
      clock += 1000;
      deployments.unshift({ ...deployment(5, clock), versions: [{ percentage: 100, version_id: id(11) }] });
    },
    async enabled() { await broker.dispatch("prepare"); this.deploy(); await broker.dispatch("bind_candidate", candidate()); },
  };
}

test("official API envelope fixtures retain only binding names/types and exact subdomain/deployment identity", () => {
  assert.equal(OBSERVED_BINDINGS.length, 35);
  assert.deepEqual(bindingInventory(wrapped({ bindings: bindingFixture() })), OBSERVED_BINDINGS);
  assert.deepEqual(bindingInventory(wrapped({ bindings: [{ name: "PUBLIC_VALUE", type: "plain_text", text: "do-not-retain" }] })),
    [{ name: "PUBLIC_VALUE", type: "plain_text" }]);
  assert.deepEqual(subdomainState(wrapped({ enabled: false, previews_enabled: false })), { enabled: false, previews_enabled: false });
  assert.deepEqual(deploymentInventory(wrapped({ deployments: [deployment(1, NOW)] })),
    [{ deployment_id: id(1), version_id: id(11), created_at_ms: NOW }]);
  for (const value of [null, {}, wrapped({}), wrapped({ bindings: null }), wrapped({ bindings: [{ name: SECRET_NAME }] }),
    wrapped({ bindings: [{ name: "X", type: "plain_text" }, { name: "X", type: "secret_text" }] })]) assert.throws(() => bindingInventory(value));
  assert.throws(() => subdomainState(wrapped({ enabled: false })));
  assert.throws(() => subdomainState(wrapped({ enabled: false, previews_enabled: false, extra: true })));
  assert.throws(() => deploymentInventory(wrapped({ deployments: [deployment(1, NOW), deployment(2, NOW + 1)] })));
  assert.throws(() => deploymentInventory(wrapped({ deployments: [{ ...deployment(1, NOW), versions: [{ percentage: 50, version_id: id(11) }] }] })));
  for (const type of ["r2-bucket", "2invalid", "", null, "a".repeat(65)]) {
    assert.throws(() => bindingInventory(wrapped({ bindings: [{ name: "X", type }] })));
  }
});

test("V15 state (newest upload != deployed): the bootstrap completes with no script-level secret call", async () => {
  const f = fixture();
  // The provider really is in the state that refused V15's PUT with 10215.
  assert.notEqual(f.latest(), f.deployments[0].versions[0].version_id);
  const refused = await f.request(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/corelink-staging/secrets`,
    { method: "PUT", redirect: "error", credentials: "omit", headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(refused.status, 400); assert.deepEqual((await refused.json()).errors.map(row => row.code), [10215]);
  f.calls.length = 0;
  const prepared = await f.broker.dispatch("prepare");
  assert.equal(prepared.state, "prepared"); assert.equal(prepared.secret_file_written, true);
  assert.deepEqual(f.calls.map(call => [call.method, call.path]), [
    ["GET", "/deployments"], ["GET", "/subdomain"], ["GET", `/versions/${id(11)}`]]);
  // The key file carries exactly the admin key, once, for the candidate upload.
  assert.equal(f.secretWrites.length, 1);
  const file = JSON.parse(f.secretWrites[0]);
  assert.deepEqual(Object.keys(file), [SECRET_NAME]);
  assert.equal(Buffer.from(file[SECRET_NAME], "base64url").length, 32);
  f.deploy();
  assert.deepEqual(f.versions.get(id(13)).resources.bindings.filter(row => row.name === SECRET_NAME),
    [{ name: SECRET_NAME, type: "secret_text" }]);
  const bound = await f.broker.dispatch("bind_candidate", candidate());
  assert.equal(f.secretsFile(), null); assert.equal(bound.secret_file_removed, true);
  assert.equal(bound.candidate_key_confirmed, true);
  const proof = await f.broker.dispatch("probe");
  assert.equal(proof.http_proof.status, "complete");
  assert.equal(f.runnerArgs[0].authKey, file[SECRET_NAME]);
  const result = await f.broker.dispatch("cleanup");
  assert.equal(result.state, "cleaned"); assert.equal(result.rollback_safe, true);
  assert.equal(result.cleanup_basis, "complete_proof");
  // No secrets or settings path, and the only provider writes are the workers.dev toggle.
  assert.equal(f.calls.length, 15); // 3 prepare + 5 bind + 2 probe identity + 5 cleanup
  assert.equal(f.calls.some(call => call.path.startsWith("/secrets") || call.path === "/settings"), false);
  assert.deepEqual(f.calls.filter(call => call.method !== "GET").map(call => [call.method, call.path]),
    [["POST", "/subdomain"], ["POST", "/subdomain"]]);
  const serialized = JSON.stringify([f.snapshots, result, proof]);
  assert.equal(serialized.includes(TOKEN), false);
  assert.equal(serialized.includes(file[SECRET_NAME]), false);
});

test("a rollback-shaped residue cannot break the next run, and the old script-level path stays refused", async () => {
  const first = fixture({ latestIsDeployed: true });
  await first.enabled(); await first.broker.dispatch("probe"); await first.broker.dispatch("cleanup");
  first.rollback();
  // Our own rollback leaves the newest upload undeployed and carrying a stale key.
  assert.notEqual(first.latest(), first.deployments[0].versions[0].version_id);
  assert.equal(first.versions.get(first.latest()).resources.bindings.some(row => row.name === SECRET_NAME), true);
  const settings = await (await first.request(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/corelink-staging/settings`,
    { method: "GET", redirect: "error", credentials: "omit", headers: { authorization: `Bearer ${TOKEN}` } })).json();
  assert.equal(settings.result.bindings.some(row => row.name === SECRET_NAME), true);
  // The next run reads the exact deployed preimage version, which is key-free, and passes.
  const second = fixture();
  assert.equal((await second.broker.dispatch("prepare")).state, "prepared");
  second.deploy(); await second.broker.dispatch("bind_candidate", candidate());
  assert.equal(second.calls.some(call => call.path.startsWith("/secrets")), false);
  const source = await readFile(BOOTSTRAP_SOURCE, "utf8");
  assert.doesNotMatch(source, /\/secrets\b/);
  assert.doesNotMatch(source, /"PUT"|"DELETE"|"PATCH"/);
});

for (const type of ["secret_text", "plain_text", "json", "service", "secret_key", "d1", "r2_bucket"]) {
  test(`a deployed preimage version with a ${type} admin binding refuses before any key leaves the broker`, async () => {
    const f = fixture({ preimageBindings: [{ name: SECRET_NAME, type, text: "preexisting-sensitive-value" }] });
    await assert.rejects(f.broker.dispatch("prepare"), /bootstrap_unknown/);
    assert.equal(f.broker.snapshot().failure.validation_failed, "preimage_key_present");
    assert.equal(f.secretWrites.length, 0); assert.equal(f.broker.snapshot().secret_file_written, false);
    assert.equal(f.calls.some(call => call.method !== "GET"), false);
    assert.equal(JSON.stringify(f.snapshots).includes("preexisting-sensitive-value"), false);
  });
}
for (const failure of ["enabled", "previews", "malformed-preimage-version", "wrong-preimage", "preimage-version-lost"]) {
  test(`bootstrap rejects ${failure} and never writes the key file`, async () => {
    const f = fixture({ request: path => {
      if (path === "/subdomain" && failure === "enabled") return response({ enabled: true, previews_enabled: false });
      if (path === "/subdomain" && failure === "previews") return response({ enabled: false, previews_enabled: true });
      if (path === `/versions/${id(11)}` && failure === "malformed-preimage-version") {
        return response({ id: id(11), resources: { bindings: [null] } });
      }
      if (path === "/deployments" && failure === "wrong-preimage") return response({ deployments: [deployment(9, NOW)] });
      if (path === `/versions/${id(11)}` && failure === "preimage-version-lost") throw new Error(TOKEN);
    } });
    await assert.rejects(f.broker.dispatch("prepare"), /bootstrap_unknown/);
    await assert.rejects(f.broker.dispatch("prepare"));
    assert.equal(f.secretWrites.length, 0);
    assert.equal(f.calls.some(call => call.method !== "GET"), false);
    assert.equal(f.broker.snapshot().rollback_safe, false);
    assert.equal(JSON.stringify(f.snapshots).includes(TOKEN), false);
  });
}

// Redacted failure classification (V13 run 36976287686 could not say why it failed; V15 run
// 37044496198 printed http_status=400 cf_error_codes=10215 cf_message_class=conflict).
const SECRET_TEXT = Buffer.alloc(32, 73).toString("base64url");
const ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd";
const PLANTED = "planted-provider-text";
const ECHOES = [TOKEN, SECRET_TEXT, ACCOUNT, PLANTED, "api.cloudflare.com", "elsewhere.invalid"];
const leakyErrors = codes => codes.map(code => ({ code,
  message: `${PLANTED} ${TOKEN} ${SECRET_TEXT} ${id(1)} https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}` }));
const cfError = (status, errors, messages = []) => Response.json({ success: false, errors, messages, result: null }, { status });
const preimageVersionOnly = respond => path => (path === `/versions/${id(11)}` ? respond() : undefined);
const pending = init => new Promise((_yes, no) => init.signal.addEventListener("abort",
  () => no(new DOMException("aborted", "AbortError")), { once: true }));
const preimageVersion = () => ({ id: id(11), resources: { bindings: bindingFixture() } });
const offOrigin = ({ redirected = false, url = "" }) => {
  const real = response(preimageVersion());
  return { status: 200, redirected, url, headers: real.headers, body: real.body };
};
const readFailure = overrides => ({ phase: "prepare_preimage_version", endpoint_label: "version", http_status: null,
  cf_error_codes: [], cf_message_class: null, validation_failed: null, timed_out: false, aborted: false, ...overrides });
// Every classified failure must still fail closed: UNKNOWN, no key file, never retried, persisted.
async function failedPrepare(f) {
  await assert.rejects(f.broker.dispatch("prepare"), /bootstrap_unknown/);
  await assert.rejects(f.broker.dispatch("prepare"));
  const snapshot = f.broker.snapshot();
  assert.equal(snapshot.state, "unknown"); assert.equal(snapshot.rollback_safe, false);
  assert.equal(snapshot.secret_file_written, false); assert.equal(f.secretWrites.length, 0);
  assert.equal(f.calls.some(call => call.method !== "GET"), false);
  assert.deepEqual(f.snapshots.at(-1).failure, snapshot.failure);
  assert.equal(validFailure(snapshot.failure), true);
  return snapshot.failure;
}

const READ_FAILURES = [
  ["403 authentication error 10000", () => cfError(403, [{ code: 10000, message: "Authentication error" }]),
    { http_status: 403, cf_error_codes: [10000], cf_message_class: "authentication" }],
  ["400 secret-edit 10215", () => cfError(400, [{ code: 10215,
    message: "Secret edit failed. Latest version of your Worker isn't currently deployed." }]),
  { http_status: 400, cf_error_codes: [10215], cf_message_class: "conflict" }],
  ["404 version not found", () => cfError(404, [{ code: 10007, message: "workers.api.error.version_not_found" }]),
    { http_status: 404, cf_error_codes: [10007], cf_message_class: "not_found" }],
  ["429 rate limit", () => cfError(429, [{ code: 971, message: "Please wait and consider throttling your request speed" }]),
    { http_status: 429, cf_error_codes: [971], cf_message_class: "rate_limit" }],
  ["2xx with another version", () => response({ ...preimageVersion(), id: id(12) }),
    { http_status: 200, validation_failed: "version_mismatch" }],
  ["2xx with malformed bindings", () => response({ ...preimageVersion(), resources: { bindings: [{ name: "X" }] } }),
    { http_status: 200, validation_failed: "bindings_invalid" }],
  ["2xx carrying the admin key", () => response({ ...preimageVersion(),
    resources: { bindings: [...bindingFixture(), { name: SECRET_NAME, type: "secret_text" }] } }),
  { http_status: 200, validation_failed: "preimage_key_present" }],
  ["2xx unsuccessful envelope", () => Response.json({ success: false, errors: [], messages: [], result: null }),
    { http_status: 200, validation_failed: "envelope_not_success" }],
  ["2xx with envelope messages", () => Response.json({ success: true, errors: [],
    messages: [{ code: 10200, message: "workers.dev subdomain notice" }], result: preimageVersion() }),
  { http_status: 200, cf_message_class: "workers_dev", validation_failed: "envelope_messages_present" }],
  ["201 instead of 200", () => Response.json(wrapped(preimageVersion()), { status: 201 }),
    { http_status: 201, validation_failed: "status_not_200" }],
  ["non-JSON content type", () => new Response("ok", { headers: { "content-type": "text/plain" } }),
    { http_status: 200, validation_failed: "content_type_not_json" }],
  ["non-JSON body", () => new Response("{not json", { headers: { "content-type": "application/json" } }),
    { http_status: 200, validation_failed: "body_not_json" }],
  ["oversized body", () => new Response(" ".repeat(262_145), { headers: { "content-type": "application/json" } }),
    { http_status: 200, validation_failed: "body_too_large" }],
  ["502 HTML gateway page", () => new Response("<html>bad gateway</html>", { status: 502, headers: { "content-type": "text/html" } }),
    { http_status: 502 }],
  ["redirected response", () => offOrigin({ redirected: true }), { http_status: 200, validation_failed: "redirected_url" }],
  ["response from another URL", () => offOrigin({ url: "https://elsewhere.invalid/accounts/x" }),
    { http_status: 200, validation_failed: "redirected_url" }],
  ["fetch refuses a redirect", () => { throw new TypeError("fetch failed: unexpected redirect"); }, {}],
];
for (const [name, respond, expected] of READ_FAILURES) {
  test(`preimage version read ${name} is classified, redacted and still fails closed`, async () => {
    const f = fixture({ request: preimageVersionOnly(respond) });
    assert.deepEqual(await failedPrepare(f), readFailure(expected));
    assert.equal(f.calls.filter(call => call.path === `/versions/${id(11)}`).length, 1);
  });
}

test("a provider call that outlives its budget records timed_out and still fails closed", async () => {
  let f;
  f = fixture({ request: (path, init) => {
    // Bring the broker deadline 50ms ahead of the version read so the real per-call timer fires quickly.
    if (path === "/subdomain") f.advance(MAX_LIFETIME_MS - 50);
    if (path === `/versions/${id(11)}`) return pending(init);
  } });
  assert.deepEqual(await failedPrepare(f), readFailure({ timed_out: true }));
});

test("closing the broker during a provider call records aborted and still fails closed", async () => {
  const f = fixture({ request: (path, init) => (path === `/versions/${id(11)}` ? pending(init) : undefined) });
  const preparing = f.broker.dispatch("prepare");
  // Bounded wait: a broker that never issues the read fails here instead of hanging the run.
  for (let turns = 0; !f.calls.some(call => call.path === `/versions/${id(11)}`); turns++) {
    assert.ok(turns < 10_000, "the preimage version read was never issued");
    await new Promise(resolve => setImmediate(resolve));
  }
  await f.broker.close();
  await assert.rejects(preparing, /bootstrap_unknown/);
  assert.deepEqual(f.broker.snapshot().failure, readFailure({ aborted: true }));
  assert.equal(f.broker.snapshot().secret_file_written, false);
});

test("reads before the key file are classified by phase and endpoint", async () => {
  const cases = [
    ["/deployments", () => cfError(403, [{ code: 10000, message: "Authentication error" }]),
      { phase: "prepare_deployments_before", endpoint_label: "deployments", http_status: 403, cf_error_codes: [10000], cf_message_class: "authentication" }],
    ["/subdomain", () => response({ enabled: true, previews_enabled: false }),
      { phase: "prepare_subdomain_before", endpoint_label: "subdomain", http_status: 200, validation_failed: "subdomain_not_disabled" }],
    ["/deployments", () => response({ deployments: [deployment(9, NOW)] }),
      { phase: "prepare_deployments_before", endpoint_label: "deployments", http_status: 200, validation_failed: "preimage_mismatch" }],
  ];
  for (const [target, respond, expected] of cases) {
    const f = fixture({ request: path => (path === target ? respond() : undefined) });
    assert.deepEqual(await failedPrepare(f), readFailure(expected), expected.validation_failed ?? target);
  }
});

test("later phases attribute a refusal to the exact call that produced it", async () => {
  const enable = fixture({ request: (path, init) => (path === "/subdomain" && init.method === "POST"
    ? response({ enabled: false, previews_enabled: false }) : undefined) });
  await enable.broker.dispatch("prepare"); enable.deploy();
  await assert.rejects(enable.broker.dispatch("bind_candidate", candidate()), /bootstrap_unknown/);
  assert.deepEqual(enable.broker.snapshot().failure, readFailure({ phase: "bind_enable_subdomain", endpoint_label: "subdomain",
    http_status: 200, validation_failed: "subdomain_not_enabled" }));

  // An upload without the key file (and no key to inherit) never reaches the workers.dev toggle.
  const keyless = fixture({ latestIsDeployed: true });
  await keyless.broker.dispatch("prepare"); keyless.deploy({ withFile: false });
  await assert.rejects(keyless.broker.dispatch("bind_candidate", candidate()), /bootstrap_unknown/);
  assert.deepEqual(keyless.broker.snapshot().failure, readFailure({ phase: "bind_verify_candidate", endpoint_label: "version",
    http_status: 200, validation_failed: "candidate_key_missing" }));
  assert.equal(keyless.calls.some(call => call.method === "POST"), false);
  assert.equal(keyless.secretsFile(), null);

  // The candidate must be this run's: newer than the broker and stacked on the exact preimage.
  for (const rewrite of [
    rows => { rows.splice(1); }, // the preimage deployment is gone from the history
    rows => { rows[1] = deployment(1, NOW - 20_000); rows[0] = deployment(3, NOW - 10_000); }, // uploaded before the broker started
  ]) {
    const unowned = fixture();
    await unowned.broker.dispatch("prepare"); unowned.deploy(); rewrite(unowned.deployments);
    await assert.rejects(unowned.broker.dispatch("bind_candidate", candidate()), /bootstrap_unknown/);
    assert.deepEqual(unowned.broker.snapshot().failure, readFailure({ phase: "bind_verify_candidate", endpoint_label: "deployments",
      http_status: 200, validation_failed: "deployment_chain_mismatch" }));
    assert.equal(unowned.calls.some(call => call.method === "POST"), false);
  }

  // A secret the preimage does not have, inherited from the newest upload, is drift.
  const drifted = fixture({ latestSecrets: [{ name: "UNEXPECTED_SECRET", type: "secret_text" }] });
  await drifted.broker.dispatch("prepare"); drifted.deploy();
  await assert.rejects(drifted.broker.dispatch("bind_candidate", candidate()), /bootstrap_unknown/);
  assert.equal(drifted.broker.snapshot().failure.validation_failed, "candidate_secret_drift");
  assert.equal(drifted.calls.some(call => call.method === "POST"), false);

  const denied = fixture({ request: (path, init, calls) => (path === "/subdomain" && init.method === "POST" &&
    calls.filter(call => call.method === "POST").length === 2 ? cfError(403, [{ code: 10000, message: "Authentication error" }]) : undefined) });
  await denied.enabled(); await denied.broker.dispatch("probe");
  await assert.rejects(denied.broker.dispatch("cleanup"), /bootstrap_unknown/);
  assert.deepEqual(denied.broker.snapshot().failure, readFailure({ phase: "cleanup_restore_subdomain", endpoint_label: "subdomain",
    http_status: 403, cf_error_codes: [10000], cf_message_class: "authentication" }));
  assert.equal(denied.broker.snapshot().subdomain_restored, false);
});

test("no token, key, ID, URL or provider text reaches the receipt on any classified failure", async () => {
  const responses = [
    () => cfError(403, [...leakyErrors([10000, 10001]), { code: "10002" }, { code: -1 }, { code: 1.5 },
      ...leakyErrors([1, 2, 3, 4, 5, 6, 7])], leakyErrors([9])),
    () => response({ ...preimageVersion(), id: id(12), echo: `${TOKEN} ${SECRET_TEXT}` }),
    () => new Response(`${TOKEN} ${SECRET_TEXT} ${PLANTED}`, { status: 500, headers: { "content-type": "text/plain" } }),
    () => offOrigin({ url: `https://elsewhere.invalid/${ACCOUNT}?token=${TOKEN}` }),
    () => { throw new Error(`${TOKEN} ${SECRET_TEXT} ${PLANTED}`); },
  ];
  const failures = [];
  for (const respond of responses) {
    const f = fixture({ request: preimageVersionOnly(respond) });
    const failure = await failedPrepare(f);
    failures.push(failure);
    const receipt = JSON.stringify(f.snapshots), recorded = JSON.stringify(failure), line = failureLine(f.broker.snapshot());
    for (const echo of ECHOES) {
      assert.equal(receipt.includes(echo), false, echo);
      assert.equal(line.includes(echo), false, echo);
    }
    for (const value of [id(1), id(11), RELEASE, "/"]) assert.equal(recorded.includes(value), false, value);
    assert.deepEqual(Object.keys(failure), [...FAILURE_KEYS]);
  }
  // Integers only, at most eight, from errors[].code; the leaked message reduces to a class.
  assert.deepEqual(failures[0].cf_error_codes, [10000, 10001, 1, 2, 3, 4, 5, 6]);
  assert.equal(failures[0].cf_message_class, "other");
  assert.equal(failures[2].http_status, 500);
});

test("every tagged refusal and API phase in the source is allowlisted, and every allowlist entry is used", async () => {
  const source = await readFile(BOOTSTRAP_SOURCE, "utf8");
  const tags = new Set([...source.matchAll(/\b(?:reject|refuse)\("([a-z0-9_]+)"/g)].map(match => match[1]));
  const phases = new Set([...source.matchAll(/\b(?:api|currentCandidate)\("([a-z0-9_]+)"/g)].map(match => match[1]));
  assert.deepEqual([...tags].sort(), [...FAILURE_VALIDATIONS].sort());
  assert.deepEqual([...phases].sort(), [...FAILURE_PHASES].sort());
  // Every provider call names its phase: no call site passes a bare path any more.
  assert.doesNotMatch(source, /\bapi\(\s*[`"]\//);
});

test("the rollback-quiescence reader expects exactly the broker snapshot keys, failure included", async () => {
  const python = await readFile(new URL("../issue_1700_rollback_quiescence.py", import.meta.url), "utf8");
  const declared = /\n {4}keys = \(((?:\s*'[^']*')+)\)/.exec(python);
  assert.ok(declared, "quiescence key list not found");
  const keys = [...declared[1].matchAll(/'([^']*)'/g)].map(match => match[1]).join("").split(/\s+/).filter(Boolean);
  assert.deepEqual(keys.sort(), Object.keys(fixture().broker.snapshot()).sort());
  assert.match(python, /broker\['failure'\] is not None/);
  assert.ok(python.includes(`'${BROKER_CONTRACT}'`));
});

test("the failure line re-validates the record and prints only enums and integers", () => {
  const valid = readFailure({ http_status: 403, cf_error_codes: [10000, 7003], cf_message_class: "authentication" });
  assert.equal(failureLine({ failure: valid }), "issue-1700 bootstrap failure phase=prepare_preimage_version endpoint=version " +
    "http_status=403 cf_error_codes=10000,7003 cf_message_class=authentication validation_failed=none timed_out=false aborted=false");
  assert.equal(failureLine({ failure: null }), "issue-1700 bootstrap failure none_recorded");
  for (const tampered of [{ ...valid, phase: `free text ${TOKEN}` }, { ...valid, endpoint_label: "url" },
    { ...valid, phase: "prepare_put_secret" }, { ...valid, endpoint_label: "secrets" },
    { ...valid, http_status: 99 }, { ...valid, http_status: 600 }, { ...valid, http_status: "403" },
    { ...valid, cf_error_codes: [1, 2, 3, 4, 5, 6, 7, 8, 9] }, { ...valid, cf_error_codes: ["10000"] }, { ...valid, cf_error_codes: [-1] },
    { ...valid, cf_message_class: PLANTED }, { ...valid, validation_failed: PLANTED }, { ...valid, timed_out: 0 },
    { ...valid, extra: TOKEN }, (({ aborted: _aborted, ...rest }) => rest)(valid), undefined, "text"]) {
    assert.equal(failureLine({ failure: tampered }), "issue-1700 bootstrap failure unavailable");
    assert.equal(validFailure(tampered), false);
  }
  assert.equal(failureLine(null), "issue-1700 bootstrap failure unavailable");
});

test("a failed start leaves a receipt whose failure prints as one redacted line from the CLI", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-fail-")); await chmod(directory, 0o700);
  const request = async url => {
    const path = new URL(url).pathname.split("/corelink-staging")[1];
    if (path === "/deployments") return response({ deployments: [deployment(1, NOW - 1000)] });
    if (path === "/subdomain") return response({ enabled: false, previews_enabled: false });
    if (path === `/versions/${id(11)}`) return cfError(403, leakyErrors([10000]));
    assert.fail(`Unexpected fixture API path ${path}`);
  };
  const expected = "issue-1700 bootstrap failure phase=prepare_preimage_version endpoint=version http_status=403 " +
    "cf_error_codes=10000 cf_message_class=other validation_failed=none timed_out=false aborted=false";
  try {
    await assert.rejects(serveBroker(directory, input(), { brokerFactory: (value, options) => createBootstrapBroker(value,
      { ...options, request, now: () => NOW, random: () => Buffer.alloc(32, 73) }) }), /bootstrap_unknown/);
    const ledger = await readFile(join(directory, BROKER_LEDGER), "utf8");
    for (const echo of ECHOES) assert.equal(ledger.includes(echo), false, echo);
    assert.equal(JSON.parse(ledger).state, "unknown");
    assert.equal((await readdir(directory)).includes(SECRETS_FILE), false);
    assert.equal(await ledgerFailureLine(directory), expected);
    const child = spawn(process.execPath, [BOOTSTRAP_SOURCE, "failure", directory], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    const [code] = await once(child, "close");
    assert.equal(code, 0); assert.equal(stdout, `${expected}\n`);
    // A substituted ledger is never followed: the reader reports unavailable, still one line.
    await rm(join(directory, BROKER_LEDGER));
    await writeFile(join(directory, "elsewhere.json"), JSON.stringify({ failure: readFailure({}) }), { mode: 0o600 });
    await symlink(join(directory, "elsewhere.json"), join(directory, BROKER_LEDGER));
    assert.equal(await ledgerFailureLine(directory), "issue-1700 bootstrap failure unavailable");
    await rm(join(directory, BROKER_LEDGER));
    assert.equal(await ledgerFailureLine(directory), "issue-1700 bootstrap failure unavailable");
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("the key file is exclusive, owner-only, never followed and gone after bind", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-key-")); await chmod(directory, 0o700);
  const outside = await mkdtemp(join(tmpdir(), "i1700-key-target-"));
  const f = fixture();
  // A fresh provider for every broker, so each later prepare reaches the key-file step.
  const make = (provider = fixture()) => createBootstrapBroker(input(), { directory, request: provider.request,
    now: provider.clock, random: () => Buffer.alloc(32, 73), save: async () => {} });
  const refusedAtFile = async () => {
    const broker = make();
    await assert.rejects(broker.dispatch("prepare"), /bootstrap_unknown/);
    // Every provider read passed: the refusal is the exclusive, no-follow create.
    assert.equal(broker.snapshot().failure, null); assert.equal(broker.snapshot().secret_file_written, false);
    assert.notEqual(broker.snapshot().preimage, null);
  };
  try {
    const broker = make(f);
    await broker.dispatch("prepare");
    const path = join(directory, SECRETS_FILE), stat = await lstat(path);
    assert.equal(stat.isFile(), true); assert.equal(stat.mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), { [SECRET_NAME]: SECRET_TEXT });
    f.deploy();
    await broker.dispatch("bind_candidate", candidate());
    assert.equal((await readdir(directory)).includes(SECRETS_FILE), false);
    // A planted symlink or leftover file is never written through or reused.
    await symlink(join(outside, "planted.json"), path);
    await refusedAtFile();
    assert.deepEqual(await readdir(outside), []);
    await rm(path); await writeFile(path, "{}", { mode: 0o600 });
    await refusedAtFile();
    assert.equal(await readFile(path, "utf8"), "{}");
  } finally { await rm(directory, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});

test("after the exact preimage rollback, the restore readback proves the active version carries no key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-restore-")); await chmod(directory, 0o700);
  const restoreInput = { api_token: TOKEN, preimage_deployment_id: id(1), preimage_version_id: id(11) };
  try {
    const f = fixture(); await f.enabled(); await f.broker.dispatch("probe"); await f.broker.dispatch("cleanup");
    // Before the rollback the candidate, which carries the key, is still active.
    await assert.rejects(verifyRestoredPreimage(restoreInput, { directory, request: f.request }));
    f.rollback();
    assert.deepEqual(await verifyRestoredPreimage(restoreInput, { directory, request: f.request }),
      { contract: RESTORE_CONTRACT, preimage_version_id: id(11), active_percentage: 100, admin_key_present: false,
        secrets_file_present: false });
    const keyed = fixture({ preimageBindings: [{ name: SECRET_NAME, type: "secret_text" }] }); keyed.rollback();
    await assert.rejects(verifyRestoredPreimage(restoreInput, { directory, request: keyed.request }));
    // The original preimage deployment is not a restore; a new 100% deployment of that version is.
    const untouched = fixture();
    await assert.rejects(verifyRestoredPreimage(restoreInput, { directory, request: untouched.request }));
    await writeFile(join(directory, SECRETS_FILE), "{}", { mode: 0o600 });
    await assert.rejects(verifyRestoredPreimage(restoreInput, { directory, request: f.request }));
    await rm(join(directory, SECRETS_FILE));
    await assert.rejects(verifyRestoredPreimage({ ...restoreInput, extra: true }, { directory, request: f.request }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const offset of [-1, 0, 1]) {
  test(`native admission requires the fixed remaining broker reserve, boundary ${offset}ms`, async () => {
    const f = fixture(); await f.enabled();
    // The simulated candidate upload advanced fixture time 1010ms.
    f.advance(MAX_LIFETIME_MS - PROBE_RESERVE_MS - 1010 - offset);
    const before = f.calls.length;
    if (offset < 0) {
      await assert.rejects(f.broker.dispatch("probe"));
      assert.equal(f.calls.length, before);
      assert.equal(f.broker.snapshot().admission_closed, true);
      assert.equal(f.broker.snapshot().probe_command_seen, false);
      assert.equal((await f.broker.dispatch("cleanup")).cleanup_basis, "never_execute");
      assert.equal(f.runnerArgs.length, 0);
    } else {
      await f.broker.dispatch("probe");
      assert.equal(f.runnerArgs.length, 1);
    }
  });
}

test("candidate drift or wrong IPC tuple denies enabling and blocks cleanup", async () => {
  for (const kind of ["drift", "release", "image", "extra"]) {
    const f = fixture(); await f.broker.dispatch("prepare"); f.deploy();
    if (kind === "drift") f.drift();
    const target = candidate();
    if (kind === "release") target.worker_release = "c".repeat(40);
    if (kind === "image") target.image_digest = "latest";
    if (kind === "extra") target.authKey = "not-allowed";
    await assert.rejects(f.broker.dispatch("bind_candidate", target));
    assert.equal(f.calls.some(call => call.path === "/subdomain" && call.method === "POST"), false);
    await assert.rejects(f.broker.dispatch("cleanup"));
  }
});

for (const state of ["prepared", "enabled"]) {
  test(`positive never_execute ${state} cleanup closes admission before restoring only owned state`, async () => {
    const f = fixture();
    if (state === "enabled") await f.enabled(); else await f.broker.dispatch("prepare");
    const cleaning = f.broker.dispatch("cleanup");
    await assert.rejects(f.broker.dispatch("probe"));
    const result = await cleaning;
    assert.equal(result.cleanup_basis, "never_execute"); assert.equal(result.rollback_safe, true);
    assert.equal(result.probe_command_seen, false); assert.equal(f.runnerArgs.length, 0);
    assert.equal(result.secret_file_removed, true); assert.equal(f.secretsFile(), null);
    assert.equal(f.calls.filter(call => call.method === "POST").length, state === "enabled" ? 2 : 0);
    await assert.rejects(f.broker.dispatch("probe"));
    assert.equal(f.broker.snapshot().state, "cleaned");
  });
}

test("missing attempt after probe or an unexplained existing ledger cannot become never_execute", async () => {
  const attempted = fixture({ missingAttempt: true }); await attempted.enabled();
  await assert.rejects(attempted.broker.dispatch("probe"));
  await assert.rejects(attempted.broker.dispatch("cleanup"));
  assert.equal(attempted.broker.snapshot().probe_command_seen, true);
  assert.equal(attempted.calls.filter(call => call.method === "POST").length, 1);
  const unexplained = fixture({ attemptExists: true }); await unexplained.broker.dispatch("prepare");
  await assert.rejects(unexplained.broker.dispatch("cleanup"));
  assert.equal(unexplained.calls.some(call => call.method === "POST"), false);
});

test("probe winning concurrency, lost response and expiry stay UNKNOWN with no cleanup or retry", async () => {
  let finish;
  const f = fixture({ proofRunner: () => new Promise((_yes, no) => { finish = no; }) }); await f.enabled();
  const probing = f.broker.dispatch("probe");
  const rejected = assert.rejects(probing, /bootstrap_unknown/);
  while (!finish) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(f.broker.dispatch("cleanup"));
  finish(new Error("private-provider-response")); await rejected;
  await assert.rejects(f.broker.dispatch("probe")); await assert.rejects(f.broker.dispatch("cleanup"));
  assert.equal(f.runnerArgs.length, 1);
  assert.equal(f.calls.filter(call => call.method === "POST").length, 1);
  const expired = fixture(); await expired.broker.dispatch("prepare"); expired.advance(MAX_LIFETIME_MS);
  await expired.broker.expire();
  assert.equal(expired.broker.snapshot().state, "unknown");
  assert.equal(expired.broker.snapshot().rollback_safe, false);
  assert.equal(expired.secretsFile(), null);
  await assert.rejects(expired.broker.dispatch("cleanup"));
});

test("cleanup drift after complete proof never restores state it does not own", async () => {
  const f = fixture(); await f.enabled(); await f.broker.dispatch("probe"); f.drift();
  await assert.rejects(f.broker.dispatch("cleanup"));
  assert.equal(f.calls.filter(call => call.method === "POST").length, 1);
});

test("private Unix IPC is bounded, secret-free, and close removes owned socket without provider cleanup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-broker-")); await chmod(directory, 0o700);
  const f = fixture();
  const service = await serveBroker(directory, input(), { brokerFactory: () => f.broker });
  try {
    assert.equal((await lstat(directory)).mode & 0o777, 0o700);
    assert.equal((await lstat(join(directory, BROKER_SOCKET))).mode & 0o777, 0o600);
    const result = await brokerCommand(directory, "status");
    assert.equal(result.contract, BROKER_CONTRACT); assert.equal(result.state, "prepared");
    await assert.rejects(brokerCommand(directory, "get_secret"));
    const closed = await brokerCommand(directory, "close");
    assert.equal(closed.state, "unknown"); assert.equal(closed.rollback_safe, false);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(service.server.listening, false);
    assert.equal((await readdir(directory)).includes(BROKER_SOCKET), false);
    assert.equal(f.calls.some(call => call.method === "DELETE"), false);
    assert.equal((await readFile(join(directory, BROKER_LEDGER), "utf8")).includes(TOKEN), false);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test("finite broker expiry marks UNKNOWN and closes its IPC listener", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-expiry-")); await chmod(directory, 0o700);
  const f = fixture();
  const service = await serveBroker(directory, input(), { brokerFactory: () => f.broker, lifetimeMs: 20 });
  try {
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.equal(f.broker.snapshot().state, "unknown"); assert.equal(service.server.listening, false);
    assert.equal((await readdir(directory)).includes(BROKER_SOCKET), false);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test("IPC preserves known never-execute after reserve denial and completed cleanup after rejected probe", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-reserve-")); await chmod(directory, 0o700);
  const f = fixture();
  const service = await serveBroker(directory, input(), { brokerFactory: () => f.broker });
  try {
    f.deploy(); await brokerCommand(directory, "bind_candidate", candidate());
    f.advance(MAX_LIFETIME_MS - PROBE_RESERVE_MS - 1010 + 1);
    await assert.rejects(brokerCommand(directory, "probe"));
    const denied = await brokerCommand(directory, "status");
    assert.equal(denied.state, "enabled"); assert.equal(denied.admission_closed, true);
    assert.equal(denied.probe_command_seen, false); assert.equal(f.runnerArgs.length, 0);
    const cleaned = await brokerCommand(directory, "cleanup");
    assert.equal(cleaned.cleanup_basis, "never_execute"); assert.equal(cleaned.rollback_safe, true);
    await assert.rejects(brokerCommand(directory, "probe"));
    assert.equal((await brokerCommand(directory, "status")).state, "cleaned");
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test("launcher sends API credentials only through stdin and scrubs child environment/argv", async () => {
  const parent = await mkdtemp(join(tmpdir(), "i1700-launch-")); const directory = join(parent, "private");
  let args, options, stdin = "", killed = false, unref = false;
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough();
  child.pid = 1234;
  child.kill = () => { killed = true; child.emit("exit", 0); child.emit("close", 0); }; child.unref = () => { unref = true; };
  child.stdin.on("data", chunk => { stdin += chunk; });
  child.stdin.on("end", () => child.stdout.write(`${JSON.stringify({ state: "prepared", pid: 1234 })}\n`));
  try {
    await startBroker(directory, input(), { spawnProcess: (_bin, argv, opts) => { args = argv; options = opts; return child; },
      inspect: async () => processIdentity(directory) });
    assert.equal(JSON.parse(stdin).api_token, TOKEN);
    assert.equal(args.includes(TOKEN), false);
    assert.deepEqual(Object.keys(options.env).sort(), ["LANG", "PATH"]);
    assert.equal(JSON.stringify(options).includes(TOKEN), false);
    assert.equal(options.detached, true); assert.equal(unref, true); assert.equal(killed, false);
    assert.deepEqual(await readdir(directory), [BROKER_PROCESS]);
    assert.equal((await readFile(join(directory, BROKER_PROCESS), "utf8")).includes(TOKEN), false);
    await chmod(directory, 0o755); await assert.rejects(privateDirectory(directory));
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("a real child broker closes its Unix socket, exits and is reaped by its owner", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-child-")); await chmod(directory, 0o700);
  const moduleUrl = new URL("../issue_1700_http_bootstrap.mjs", import.meta.url).href;
  const source = `import { serveBroker } from ${JSON.stringify(moduleUrl)};
    let state='prepared';
    const broker={snapshot:()=>({state}),dispatch:async()=>({state}),expire:async()=>{state='unknown'},close:async()=>({state:'unknown'})};
    await serveBroker(process.argv[1],{}, {brokerFactory:()=>broker,onStopped:()=>process.exit(0)});
    process.stdout.write('ready\\n');`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, directory],
    { env: { PATH: process.env.PATH ?? "/usr/bin:/bin" }, stdio: ["ignore", "pipe", "pipe"] });
  const exit = once(child, "exit");
  const deadline = setTimeout(() => child.kill("SIGKILL"), 3000);
  try {
    await once(child.stdout, "data");
    await brokerCommand(directory, "close");
    const [code, signal] = await exit;
    assert.equal(code, 0); assert.equal(signal, null);
    assert.equal((await readdir(directory)).includes(BROKER_SOCKET), false);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  } finally { clearTimeout(deadline); if (child.exitCode === null) child.kill("SIGKILL"); await rm(directory, { recursive: true, force: true }); }
});

test("local shutdown does not treat a close acknowledgement as exit and escalates only verified identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-stop-")); await chmod(directory, 0o700);
  const identity = processIdentity(directory), signals = [], commands = [];
  let alive = true;
  try {
    await captureBrokerProcess(directory, identity.pid, async () => identity);
    const result = await shutdownBroker(directory, { inspect: async () => alive ? identity : null,
      command: async (...args) => { commands.push(args); return { state: "unknown" }; }, pause: async () => {},
      signal: (pid, name) => { signals.push([pid, name]); if (name === "SIGKILL") alive = false; } });
    assert.deepEqual(signals, [[identity.pid, "SIGTERM"], [identity.pid, "SIGKILL"]]);
    assert.equal(commands.length, 1); assert.equal(commands[0][1], "close");
    assert.equal(commands[0][3].timeoutMs, 1000);
    assert.deepEqual(result, { contract: "corelink-staging-http-bootstrap-shutdown-v1", pid: identity.pid,
      process_exited: true, provider_cleanup_claimed: false });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("local shutdown rejects unrelated or reused PID and never signals an unverified process", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-stop-owner-")); await chmod(directory, 0o700);
  const identity = processIdentity(directory);
  let signals = 0, commands = 0;
  try {
    await captureBrokerProcess(directory, identity.pid, async () => identity);
    for (const changed of [{ command: "/unrelated/worker" }, { started: "Thu Oct 1 14:00:01 2026" }, { uid: identity.uid + 1 }]) {
      await assert.rejects(shutdownBroker(directory, { inspect: async () => ({ ...identity, ...changed }),
        command: async () => { commands++; }, signal: () => { signals++; }, pause: async () => {} }));
    }
    assert.equal(signals, 0); assert.equal(commands, 0);
    let reads = 0;
    await assert.rejects(shutdownBroker(directory, { inspect: async () => ++reads < 13 ? identity : { ...identity, started: "reused" },
      command: async () => {}, signal: () => { signals++; }, pause: async () => {} }));
    assert.equal(signals, 0); // identity changed immediately before the first signal
    const exited = await shutdownBroker(directory, { inspect: async () => null,
      command: async () => { commands++; }, signal: () => { signals++; } });
    assert.equal(exited.process_exited, true); assert.equal(signals, 0); assert.equal(commands, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("local shutdown verifies a real broker process exit when its private IPC never became available", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-stop-real-")); await chmod(directory, 0o700);
  // No stdin JSON is sent, so the real CLI cannot create a key or make provider calls.
  const child = spawn(process.execPath, [BOOTSTRAP_SOURCE, "serve", directory],
    { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C" }, stdio: ["pipe", "pipe", "pipe"] });
  const exit = once(child, "exit"), deadline = setTimeout(() => child.kill("SIGKILL"), 10_000);
  try {
    await once(child, "spawn");
    await captureBrokerProcess(directory, child.pid);
    const result = await shutdownBroker(directory);
    await exit;
    assert.equal(result.process_exited, true); assert.equal(result.provider_cleanup_claimed, false);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
    assert.deepEqual(await readdir(directory), [BROKER_PROCESS]);
    assert.equal((await readFile(join(directory, BROKER_PROCESS), "utf8")).includes(TOKEN), false);
  } finally { clearTimeout(deadline); if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); await rm(directory, { recursive: true, force: true }); }
});

test("local shutdown has a finite inspection ceiling and never reports a still-live broker as exited", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-stop-bound-")); await chmod(directory, 0o700);
  const identity = processIdentity(directory), signals = [];
  let inspections = 0, pauses = 0;
  try {
    await captureBrokerProcess(directory, identity.pid, async () => identity);
    await assert.rejects(shutdownBroker(directory, { inspect: async () => { inspections++; return identity; },
      command: async () => { throw new Error("IPC unavailable"); },
      signal: (_pid, name) => signals.push(name), pause: async () => { pauses++; } }), /bootstrap_unknown/);
    assert.equal(inspections, 36); assert.equal(pauses, 30);
    assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const phase of ["close", "signal"]) for (const becomesAbsent of [true, false]) {
  test(`post-${phase} command change is observation-only until actual absence: ${becomesAbsent}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "i1700-stop-transition-")); await chmod(directory, 0o700);
    const identity = processIdentity(directory), signals = [];
    let shutdownStarted = false, transitionReads = 0;
    try {
      await captureBrokerProcess(directory, identity.pid, async () => identity);
      const shutdown = shutdownBroker(directory, {
        inspect: async () => {
          if (!shutdownStarted) return identity;
          if (++transitionReads > 1 && becomesAbsent) return null;
          return { ...identity, command: "termination-metadata-fixture" };
        },
        command: async () => { if (phase === "close") { shutdownStarted = true; return { state: "unknown" }; }
          throw new Error("IPC unavailable"); },
        signal: (_pid, name) => { shutdownStarted = true; signals.push(name); }, pause: async () => {},
      });
      if (becomesAbsent) assert.equal((await shutdown).process_exited, true);
      else await assert.rejects(shutdown, /bootstrap_unknown/);
      assert.deepEqual(signals, phase === "close" ? [] : ["SIGTERM"]);
      assert.equal(transitionReads, becomesAbsent ? 2 : 11);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

// The ownership record names the PID that shutdown may signal. These tests change the
// record between validation and use (CWE-367) and require that shutdown acts only on
// bytes it validated, on the inode it validated.
const ownerRecord = (directory, identity) =>
  `${JSON.stringify({ contract: "corelink-staging-http-bootstrap-process-v1", directory, ...identity })}\n`;
const recordingShutdown = (directory, inspected, signals) => shutdownBroker(directory, {
  inspect: async pid => { inspected.push(pid); return null; },
  command: async () => {}, signal: (pid, name) => { signals.push([pid, name]); }, pause: async () => {},
});
// Builtin ESM bindings follow the CommonJS exports after syncBuiltinESMExports, so the
// module under test calls these wrappers through its own `node:fs/promises` imports.
async function withPatchedFs(patches, run) {
  const saved = Object.fromEntries(Object.keys(patches).map(name => [name, fsPromises[name]]));
  try {
    for (const [name, wrap] of Object.entries(patches)) fsPromises[name] = wrap(saved[name]);
    syncBuiltinESMExports();
    return await run();
  } finally { Object.assign(fsPromises, saved); syncBuiltinESMExports(); }
}

test("local shutdown acts on the validated owner record even when the path is swapped after validation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-owner-swap-")); await chmod(directory, 0o700);
  const outside = await mkdtemp(join(tmpdir(), "i1700-owner-decoy-"));
  const identity = processIdentity(directory), ownerPath = join(directory, BROKER_PROCESS), staged = join(directory, "staged");
  const inspected = [], signals = [];
  let swaps = 0;
  try {
    await captureBrokerProcess(directory, identity.pid, async () => identity);
    // Validated in place, this decoy would be refused: world-readable, outside the private directory.
    await writeFile(join(outside, "decoy.json"), ownerRecord(directory, processIdentity(directory, 4321)), { mode: 0o644 });
    await symlink(join(outside, "decoy.json"), staged);
    const swapAfter = original => async (path, ...rest) => {
      const result = await original(path, ...rest);
      if (path === ownerPath && swaps === 0) { swaps++; await rename(staged, ownerPath); }
      return result;
    };
    const result = await withPatchedFs({ lstat: swapAfter, stat: swapAfter, open: swapAfter },
      () => recordingShutdown(directory, inspected, signals));
    assert.equal(swaps, 1); // the substitution really happened after the first path check
    assert.equal((await lstat(ownerPath)).isSymbolicLink(), true);
    assert.equal(result.pid, identity.pid);
    assert.deepEqual(inspected, [identity.pid]); assert.deepEqual(signals, []);
  } finally { await rm(directory, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});

test("local shutdown bounds the owner bytes it reads, not only the size it validated", async () => {
  const directory = await mkdtemp(join(tmpdir(), "i1700-owner-grow-")); await chmod(directory, 0o700);
  const identity = processIdentity(directory), ownerPath = join(directory, BROKER_PROCESS);
  const inspected = [], signals = [];
  let grown = false;
  // Trailing whitespace keeps the record valid JSON, so only a byte bound can refuse it.
  const grow = async () => { if (grown) return; grown = true; await appendFile(ownerPath, " ".repeat(8192)); };
  const probe = await open(BOOTSTRAP_SOURCE, "r"), handleProto = Object.getPrototypeOf(probe);
  await probe.close();
  const handleStat = handleProto.stat;
  try {
    await captureBrokerProcess(directory, identity.pid, async () => identity);
    const growAfter = original => async (path, ...rest) => {
      const result = await original(path, ...rest);
      if (path === ownerPath) await grow();
      return result;
    };
    handleProto.stat = async function (...args) { const result = await handleStat.apply(this, args); await grow(); return result; };
    await assert.rejects(withPatchedFs({ lstat: growAfter, stat: growAfter },
      () => recordingShutdown(directory, inspected, signals)), /bootstrap_rejected/);
    handleProto.stat = handleStat;
    assert.equal(grown, true); assert.equal((await lstat(ownerPath)).size > 8192, true);
    assert.deepEqual(inspected, []); assert.deepEqual(signals, []);
  } finally { handleProto.stat = handleStat; await rm(directory, { recursive: true, force: true }); }
});

test("local shutdown refuses a symlinked, FIFO, loose-mode or oversized owner record without following or blocking", async () => {
  const outside = await mkdtemp(join(tmpdir(), "i1700-owner-target-")); await chmod(outside, 0o700);
  const plants = {
    // A conforming record behind a symlink: only refusing to follow the link rejects it.
    symlink: async (path, owner) => {
      const target = join(outside, "owner.json");
      await writeFile(target, owner); await chmod(target, 0o600); await symlink(target, path);
    },
    fifo: async path => { await promisify(execFile)("mkfifo", ["-m", "600", path]); },
    loose_mode: async (path, owner) => { await writeFile(path, owner); await chmod(path, 0o644); },
    oversized: async (path, owner) => { await writeFile(path, owner + " ".repeat(4096)); await chmod(path, 0o600); },
  };
  try {
    for (const [name, plant] of Object.entries(plants)) {
      const directory = await mkdtemp(join(tmpdir(), "i1700-owner-shape-")); await chmod(directory, 0o700);
      const ownerPath = join(directory, BROKER_PROCESS), inspected = [], signals = [];
      try {
        await plant(ownerPath, ownerRecord(directory, processIdentity(directory)));
        const shutdown = recordingShutdown(directory, inspected, signals);
        let timer;
        const outcome = await Promise.race([shutdown.then(() => "accepted", error => error.message),
          new Promise(yes => { timer = setTimeout(yes, 5000, "blocked"); })]);
        clearTimeout(timer);
        if (outcome === "blocked") {
          // Release a reader stuck in open() so the failure is reported instead of hanging the run.
          const writer = await open(ownerPath, constants.O_RDWR);
          await shutdown.catch(() => {}); await writer.close();
        }
        assert.equal(outcome, "bootstrap_rejected", name);
        assert.deepEqual(inspected, [], name); assert.deepEqual(signals, [], name);
      } finally { await rm(directory, { recursive: true, force: true }); }
    }
  } finally { await rm(outside, { recursive: true, force: true }); }
});
