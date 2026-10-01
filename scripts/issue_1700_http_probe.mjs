#!/usr/bin/env node
// Single authenticated execution; an interrupted request is never rollback proof.
import { open, readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { PROBE_WINDOW, isApprovedProbeWindow } from "./issue_1700_probe_window.mjs";

export const HTTP_CONTRACT = "corelink-staging-d1-http-proof-v1";
export const ATTEMPT_CONTRACT = "corelink-staging-http-attempt-v1";
export const HTTP_PATH = "/_internal/staging/d1-binding-runtime-probe";
// Authorized account metadata: workers.dev and previews are both disabled.
// Reachability and dedicated secret provisioning require a separate root lease.
export const APPROVED_ORIGIN = "https://corelink-staging.gmhelmold.workers.dev";
export const EXECUTE_MS = 600_000;
export const CLEANUP_MS = 600_000;
export const TRANSPORT_ALLOWANCE_MS = 60_000;
export const MAX_STATUS_READS = 3;
const ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
const WORKER_NAME = "corelink-staging";
const INVENTORY_API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}`;
const CADENCE_MS = 120_000;
const MAX_BODY_BYTES = 16_384;
const OLD_RELEASES = {
  v8: "7d18bcfc450db97b1b987923050b92971da530a8",
  v9: "5da497051f0b11dbfc8b87d1dfa8e753304e2719",
};
const ENVELOPE_KEYS = "contract carrier worker_release probe_nonce status rollback_safe native_receipt v8_cleanup v9_cleanup".split(" ");
const ATTEMPT_KEYS = "contract carrier origin worker_release probe_nonce scheduled_time_ms started_at_ms deadline_ms transport_deadline_ms request_attempted".split(" ");
const NATIVE_KEYS = "old_probe_release old_probe_retired old_probe_tables_absent v5_probe_release v5_probe_retired v5_probe_tables_absent v5_prior_execution v4_probe_catalog_absent contract probe_nonce outcome worker_release scheduled_time_ms parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent".split(" ");
const CLEANUP_KEYS = "contract old_release old_nonce worker_release prior_execution prior_admission_present container_stopped alarm_absent tables_absent completed_at_ms".split(" ");
const DEPLOYMENT_KEYS = "contract carrier account_id worker_name workflow_sha worker_release container_image_digest probe_nonce origin http_proof receipt schedules_empty tails_empty".split(" ");
const NATIVE_FLAGS = "old_probe_retired old_probe_tables_absent v5_probe_retired v5_probe_tables_absent v4_probe_catalog_absent parameterized_select failed_batch_observed rollback_absence_verified probe_table_dropped d1_binding_intercepted authorization_absent cf_api_token_absent".split(" ");

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function validRelease(value) {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value) && !Object.values(OLD_RELEASES).includes(value);
}
function validOrigin(value) {
  return /^https:\/\/corelink-staging\.[a-z0-9-]+\.workers\.dev$/.test(APPROVED_ORIGIN) && value === APPROVED_ORIGIN;
}
export function validateAttempt(value, expectedRelease) {
  return exactKeys(value, ATTEMPT_KEYS) && value.contract === ATTEMPT_CONTRACT &&
    value.carrier === "authenticated_http" && value.request_attempted === true && validOrigin(value.origin) &&
    validRelease(value.worker_release) && value.worker_release === expectedRelease &&
    value.probe_nonce === "issue-1700-recovery-20261002-v12" &&
    value.probe_nonce === PROBE_WINDOW.nonce && isApprovedProbeWindow(PROBE_WINDOW) &&
    ["started_at_ms", "scheduled_time_ms", "deadline_ms", "transport_deadline_ms"].every(key => Number.isSafeInteger(value[key])) &&
    value.started_at_ms >= PROBE_WINDOW.starts_ms && value.started_at_ms < PROBE_WINDOW.last_entry_ms &&
    value.scheduled_time_ms === Math.floor(value.started_at_ms / CADENCE_MS) * CADENCE_MS &&
    value.scheduled_time_ms >= PROBE_WINDOW.starts_ms &&
    value.deadline_ms === value.started_at_ms + EXECUTE_MS + CLEANUP_MS &&
    value.transport_deadline_ms === value.deadline_ms + TRANSPORT_ALLOWANCE_MS &&
    value.transport_deadline_ms < PROBE_WINDOW.expires_ms;
}
function validNative(value, attempt, observedAt) {
  return exactKeys(value, NATIVE_KEYS) && value.contract === "corelink-staging-d1-binding-runtime-v1" &&
    value.outcome === "pass" && value.probe_nonce === attempt.probe_nonce &&
    value.worker_release === attempt.worker_release &&
    Number.isSafeInteger(value.scheduled_time_ms) && value.scheduled_time_ms === attempt.scheduled_time_ms &&
    value.scheduled_time_ms <= observedAt &&
    value.old_probe_release === "0f785fb9b096afe01247f1057d46377b9f604f13" &&
    value.v5_probe_release === "cc32b3d819181bf9175e795868f66212aa5456c1" &&
    value.v5_prior_execution === "unknown" && NATIVE_FLAGS.every(key => value[key] === true);
}
function validCleanup(value, version, attempt, observedAt) {
  return exactKeys(value, CLEANUP_KEYS) && value.contract === `corelink-staging-${version}-cleanup-v1` &&
    value.old_release === OLD_RELEASES[version] && value.old_nonce === `issue-1700-recovery-20261001-${version}` &&
    value.worker_release === attempt.worker_release && value.prior_execution === "unknown" &&
    typeof value.prior_admission_present === "boolean" && value.container_stopped === true &&
    value.alarm_absent === true && value.tables_absent === true && Number.isSafeInteger(value.completed_at_ms) &&
    value.completed_at_ms >= attempt.started_at_ms && value.completed_at_ms <= observedAt &&
    value.completed_at_ms < attempt.deadline_ms && value.completed_at_ms >= Date.parse("2026-10-02T15:00:00Z") &&
    value.completed_at_ms < Date.parse("2026-10-02T18:15:00Z");
}
export function validateHttpStatus(value, attempt, { expectedRelease = attempt?.worker_release, observedAt = Date.now(), requireComplete = false } = {}) {
  if (!validateAttempt(attempt, expectedRelease) || !Number.isSafeInteger(observedAt) ||
      !exactKeys(value, ENVELOPE_KEYS) || value.contract !== HTTP_CONTRACT ||
      value.carrier !== "authenticated_http" || value.worker_release !== expectedRelease ||
      value.probe_nonce !== attempt.probe_nonce ||
      !["not_started", "running", "unknown", "complete"].includes(value.status) ||
      typeof value.rollback_safe !== "boolean") return false;
  if (value.status === "complete") return value.rollback_safe === true &&
    validNative(value.native_receipt, attempt, observedAt) &&
    validCleanup(value.v8_cleanup, "v8", attempt, observedAt) && validCleanup(value.v9_cleanup, "v9", attempt, observedAt);
  return !requireComplete && value.rollback_safe === false && value.native_receipt === null &&
    (value.v8_cleanup === null || validCleanup(value.v8_cleanup, "v8", attempt, observedAt)) &&
    (value.v9_cleanup === null || validCleanup(value.v9_cleanup, "v9", attempt, observedAt));
}
export function validateDeploymentProof(value, attempt, { expectedRelease, expectedImageDigest, observedAt = Date.now() } = {}) {
  return exactKeys(value, DEPLOYMENT_KEYS) && value.contract === "corelink-staging-runtime-deployment-proof-v1" &&
    value.carrier === "authenticated_http" && value.account_id === ACCOUNT_ID && value.worker_name === WORKER_NAME &&
    value.workflow_sha === expectedRelease && value.worker_release === expectedRelease &&
    /^sha256:[0-9a-f]{64}$/.test(value.container_image_digest) && value.container_image_digest === expectedImageDigest &&
    value.origin === APPROVED_ORIGIN && value.probe_nonce === PROBE_WINDOW.nonce &&
    value.schedules_empty === true && value.tails_empty === true &&
    validateHttpStatus(value.http_proof, attempt, { expectedRelease, observedAt, requireComplete: true }) &&
    exactKeys(value.receipt, NATIVE_KEYS) && NATIVE_KEYS.every(key => value.receipt[key] === value.http_proof.native_receipt[key]);
}

export async function persistAttempt(path, attempt) {
  const handle = await open(path, "wx", 0o600);
  try { await handle.writeFile(`${JSON.stringify(attempt)}\n`); await handle.sync(); }
  finally { await handle.close(); }
}
async function boundedJson(response, expectedUrl) {
  if (![200, 202].includes(response.status) || response.redirected ||
      (response.url && response.url !== expectedUrl) ||
      !/^application\/json(?:;|$)/i.test(response.headers.get("content-type") ?? "")) throw new Error("http_response_rejected");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("http_response_rejected");
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) throw new Error("http_response_rejected");
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally { await reader.cancel().catch(() => {}); }
}

// Called only inside the RAM-only bootstrap broker; neither credential is a
// process argument, environment variable, artifact or IPC response.
export async function runProof({ authKey, apiToken, release, expectedSha, imageDigest,
  origin = APPROVED_ORIGIN, request = fetch, now = Date.now,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  writeAttempt = persistAttempt, setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout,
  signal, attemptPath,
} = {}) {
  const startedAt = now();
  const attempt = { contract: ATTEMPT_CONTRACT, carrier: "authenticated_http", origin,
    worker_release: release, probe_nonce: PROBE_WINDOW.nonce,
    scheduled_time_ms: Math.floor(startedAt / CADENCE_MS) * CADENCE_MS,
    started_at_ms: startedAt, deadline_ms: startedAt + EXECUTE_MS + CLEANUP_MS,
    transport_deadline_ms: startedAt + EXECUTE_MS + CLEANUP_MS + TRANSPORT_ALLOWANCE_MS,
    request_attempted: true };
  if (!validateAttempt(attempt, expectedSha) || typeof authKey !== "string" ||
      authKey.length < 1 || /[\r\n]/.test(authKey) || typeof apiToken !== "string" ||
      apiToken.length < 1 || apiToken === authKey || /[\r\n]/.test(apiToken) ||
      !/^sha256:[0-9a-f]{64}$/.test(imageDigest ?? "") || !attemptPath || signal?.aborted) throw new Error("http_preflight_rejected");
  // This exclusive, synced ledger is the write-ahead fence. Failure means no POST.
  try { await writeAttempt(attemptPath, attempt); } catch { throw new Error("http_attempt_ledger_rejected"); }

  async function readResponse(url, options, requestedBudget) {
    const budget = Math.min(requestedBudget, attempt.transport_deadline_ms - now());
    if (budget <= 0 || signal?.aborted) throw new Error("http_status_unknown");
    const controller = new AbortController();
    let timer;
    let aborted;
    const stopped = new Promise((_, reject) => {
      const stop = () => { controller.abort(); reject(new Error("http_status_unknown")); };
      aborted = stop;
      signal?.addEventListener("abort", stop, { once: true });
      timer = setTimeoutFn(stop, budget);
    });
    const operation = (async () => {
      const response = await request(url, { ...options, redirect: "error", credentials: "omit", cache: "no-store", signal: controller.signal });
      const value = await boundedJson(response, url);
      if (now() >= attempt.transport_deadline_ms) throw new Error("http_status_unknown");
      return value;
    })();
    try { return await Promise.race([operation, stopped]); }
    finally { clearTimeoutFn(timer); signal?.removeEventListener("abort", aborted); }
  }
  async function exchange(method) {
    const value = await readResponse(origin + HTTP_PATH, {
      method, headers: { accept: "application/json", "x-corelink-internal-auth": authKey,
        ...(method === "POST" ? { "content-type": "application/json" } : {}) },
      ...(method === "POST" ? { body: JSON.stringify({ worker_release: attempt.worker_release,
        probe_nonce: attempt.probe_nonce, scheduled_time_ms: attempt.scheduled_time_ms }) } : {}),
    }, method === "POST" ? EXECUTE_MS + CLEANUP_MS + 30_000 : 30_000);
    if (!validateHttpStatus(value, attempt, { observedAt: now() })) throw new Error("http_response_rejected");
    return value;
  }
  async function finish(httpProof) {
    for (const path of ["/schedules", "/tails"]) {
      const value = await readResponse(INVENTORY_API + path, { method: "GET",
        headers: { accept: "application/json", authorization: `Bearer ${apiToken}` } }, 30_000);
      const rows = path === "/schedules" ? value?.result?.schedules : value?.result;
      if (value?.success !== true || !Array.isArray(rows) || rows.length !== 0) throw new Error("http_inventory_unproven");
    }
    return { contract: "corelink-staging-runtime-deployment-proof-v1", carrier: "authenticated_http",
      account_id: ACCOUNT_ID, worker_name: WORKER_NAME, workflow_sha: expectedSha,
      worker_release: attempt.worker_release, container_image_digest: imageDigest,
      probe_nonce: attempt.probe_nonce, origin, http_proof: httpProof, receipt: httpProof.native_receipt,
      schedules_empty: true, tails_empty: true };
  }
  // Never retry execute, including a redirect, malformed response, lost response,
  // process cancellation or a client-side timeout: any one can follow admission.
  let status;
  try { status = await exchange("POST"); } catch { /* Three bounded read-only status attempts may recover the lost result. */ }
  if (status?.status === "complete") return finish(status);
  if (status && status.status !== "running") throw new Error("http_status_unknown");
  for (let reads = 0; reads < MAX_STATUS_READS && now() < attempt.transport_deadline_ms && !signal?.aborted; reads += 1) {
    try { status = await exchange("GET"); } catch { status = undefined; }
    if (status?.status === "complete") return finish(status);
    if (status && status.status !== "running") throw new Error("http_status_unknown");
    const remaining = attempt.transport_deadline_ms - now();
    if (reads + 1 < MAX_STATUS_READS && remaining > 0 && !signal?.aborted) await sleep(Math.min(5000, remaining));
  }
  // GET reads persisted status only. It never starts work or renews either
  // deadline, and cannot turn UNKNOWN into permission to replay execute.
  throw new Error("http_status_unknown");
}

async function readLocalJson(path) {
  const value = await readFile(path);
  if (value.byteLength > MAX_BODY_BYTES) throw new Error("http_receipt_rejected");
  return JSON.parse(value.toString("utf8"));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once("SIGTERM", abort); process.once("SIGINT", abort);
  try {
    if (process.argv[2] === "validate") {
      if (process.argv.length !== 5) throw new Error("http_receipt_rejected");
      const proof = await readLocalJson(process.argv[3]);
      const attempt = await readLocalJson(process.argv[4]);
      if (!validateDeploymentProof(proof, attempt, { expectedRelease: process.env.EXPECTED_SHA,
        expectedImageDigest: process.env.IMAGE_DIGEST })) throw new Error("http_receipt_rejected");
    } else throw new Error("http_broker_required");
  } catch (error) {
    const allowed = new Set(["http_preflight_rejected", "http_attempt_ledger_rejected", "http_status_unknown", "http_receipt_rejected", "http_inventory_unproven", "http_broker_required"]);
    process.stderr.write(`issue-1700 HTTP probe failed ${allowed.has(error?.message) ? error.message : "http_status_unknown"}\n`);
    process.exitCode = 1;
  } finally { process.removeListener("SIGTERM", abort); process.removeListener("SIGINT", abort); }
}
