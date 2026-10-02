#!/usr/bin/env node
// Cloudflare API contracts, checked against official documentation:
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/subdomain/methods/create/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, unlink } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import { execFile, spawn } from "node:child_process";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runProof, validateDeploymentProof } from "./issue_1700_http_probe.mjs";

export const BROKER_CONTRACT = "corelink-staging-http-bootstrap-v2";
export const RESTORE_CONTRACT = "corelink-staging-http-bootstrap-restore-v1";
export const MAX_LIFETIME_MS = 45 * 60_000;
// 21m native transport + 8m owned bootstrap cleanup + three 30s preflight reads.
export const BOOTSTRAP_CLEANUP_MS = 8 * 60_000;
export const PROBE_RESERVE_MS = 21 * 60_000 + BOOTSTRAP_CLEANUP_MS + 90_000;
export const SECRET_NAME = "CORELINK_ADMIN_AUTH_KEY";
export const BROKER_SOCKET = "broker.sock";
export const BROKER_LEDGER = "staging-http-bootstrap.json";
export const BROKER_PROCESS = "broker-process.json";
export const ATTEMPT_LEDGER = "staging-http-probe-attempt.json";
// The admin key reaches Cloudflare only inside the candidate upload
// (`wrangler deploy --secrets-file`), never through a script-level secret write.
// Cloudflare refuses script-level secret edits (code 10215) whenever the newest
// uploaded version is not the deployed one, which every exact-preimage rollback
// leaves behind.
export const SECRETS_FILE = "candidate-secrets.json";
const API = "https://api.cloudflare.com/client/v4/accounts/6a1fc1c626fc2628823e60b9db01f5cd/workers/scripts/corelink-staging";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const MAX_API_BYTES = 262_144;
const MAX_IPC_BYTES = 32_768;
const SOURCE = fileURLToPath(import.meta.url);
// A refusal may name the acceptance check that failed, from FAILURE_VALIDATIONS only.
const VALIDATION = Symbol("validation");
const reject = (validation = null) => Object.assign(new Error("bootstrap_rejected"), { [VALIDATION]: validation });
const unknown = () => new Error("bootstrap_unknown");
const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const uuid = value => typeof value === "string" && UUID.test(value);
const wrappedSettings = bindings => ({ success: true, errors: [], messages: [], result: { bindings } });

// Redacted failure record: the receipt names WHERE a provider call failed and HOW,
// using fixed enums and bounded integers only. It never holds a body, URL, ID,
// token, secret or provider-supplied text.
export const FAILURE_PHASES = Object.freeze([
  "prepare_deployments_before", "prepare_subdomain_before", "prepare_preimage_version",
  "bind_verify_candidate", "bind_subdomain_before", "bind_enable_subdomain", "bind_subdomain_after",
  "probe_verify_candidate",
  "cleanup_verify_before_restore", "cleanup_subdomain_before", "cleanup_restore_subdomain", "cleanup_subdomain_after",
]);
export const FAILURE_ENDPOINTS = Object.freeze(["deployments", "subdomain", "version"]);
export const FAILURE_MESSAGE_CLASSES = Object.freeze(["authentication", "permission", "not_found", "rate_limit",
  "conflict", "workers_dev", "other"]);
export const FAILURE_VALIDATIONS = Object.freeze([
  // The HTTP response itself (validation is null for a non-2xx status: the status says it).
  "redirected_url", "status_not_200", "content_type_not_json", "body_missing", "body_too_large", "body_not_json",
  // The Cloudflare v4 envelope.
  "envelope_not_object", "envelope_not_success", "envelope_errors_present", "envelope_messages_present",
  "envelope_result_missing",
  // The result shape and the exact checks made on it.
  "bindings_invalid", "subdomain_invalid", "deployments_invalid", "preimage_mismatch", "subdomain_not_disabled",
  "preimage_key_present", "preimage_secrets_unprovable", "candidate_key_missing", "candidate_secret_drift",
  "deployment_chain_mismatch",
  "version_mismatch", "release_binding_mismatch", "subdomain_not_enabled", "subdomain_state_mismatch",
]);
export const FAILURE_KEYS = Object.freeze(["phase", "endpoint_label", "http_status", "cf_error_codes", "cf_message_class",
  "validation_failed", "timed_out", "aborted"]);
const httpStatus = response => Number.isSafeInteger(response?.status) && response.status >= 100 && response.status <= 599 ? response.status : null;
const MAX_CF_CODES = 8;
const MAX_CF_CODE = 2_147_483_647;
// Well-known Cloudflare API error messages, matched on a bounded prefix and reduced to a class.
const CF_MESSAGE_PATTERNS = [
  ["authentication", /authentication error|unable to authenticate|invalid (?:api |access )?token|unauthori[sz]ed/i],
  ["permission", /permission|not authori[sz]ed|forbidden|access denied/i],
  ["rate_limit", /rate limit|too many requests|throttl/i],
  ["not_found", /not[ _]found|does not exist/i],
  ["workers_dev", /workers\.dev|subdomain/i],
  ["conflict", /conflict|already exists|in progress|concurrent|version|etag/i],
];
function endpointLabel(path) {
  if (path === "/deployments") return "deployments";
  if (path === "/subdomain") return "subdomain";
  return /^\/versions\/[0-9a-f-]{36}$/.test(path) ? "version" : null;
}
function messageClass(rows) {
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!record(row) || typeof row.message !== "string") continue;
    const text = row.message.slice(0, 256);
    return CF_MESSAGE_PATTERNS.find(([, pattern]) => pattern.test(text))?.[0] ?? "other";
  }
  return null;
}
// Reads only integer `errors[].code` and a message class; nothing else of the body is kept.
function describeBody(call, body) {
  if (!record(body)) return;
  call.cf_error_codes = (Array.isArray(body.errors) ? body.errors : [])
    .filter(row => record(row) && Number.isSafeInteger(row.code) && row.code >= 0 && row.code <= MAX_CF_CODE)
    .slice(0, MAX_CF_CODES).map(row => row.code);
  call.cf_message_class = messageClass(body.errors) ?? messageClass(body.messages);
}
export function validFailure(value) {
  return exact(value, FAILURE_KEYS) && FAILURE_PHASES.includes(value.phase) && FAILURE_ENDPOINTS.includes(value.endpoint_label) &&
    (value.http_status === null || (Number.isSafeInteger(value.http_status) && value.http_status >= 100 && value.http_status <= 599)) &&
    Array.isArray(value.cf_error_codes) && value.cf_error_codes.length <= MAX_CF_CODES &&
    value.cf_error_codes.every(code => Number.isSafeInteger(code) && code >= 0 && code <= MAX_CF_CODE) &&
    (value.cf_message_class === null || FAILURE_MESSAGE_CLASSES.includes(value.cf_message_class)) &&
    (value.validation_failed === null || FAILURE_VALIDATIONS.includes(value.validation_failed)) &&
    typeof value.timed_out === "boolean" && typeof value.aborted === "boolean";
}
// One line for the workflow log, re-validated so a tampered ledger cannot print free text.
export function failureLine(snapshot) {
  const value = record(snapshot) ? snapshot.failure : undefined;
  if (value === null) return "issue-1700 bootstrap failure none_recorded";
  if (!validFailure(value)) return "issue-1700 bootstrap failure unavailable";
  return `issue-1700 bootstrap failure phase=${value.phase} endpoint=${value.endpoint_label} ` +
    `http_status=${value.http_status ?? "none"} cf_error_codes=${value.cf_error_codes.join(",") || "none"} ` +
    `cf_message_class=${value.cf_message_class ?? "none"} validation_failed=${value.validation_failed ?? "none"} ` +
    `timed_out=${value.timed_out} aborted=${value.aborted}`;
}

function envelope(value) {
  if (!record(value)) throw reject("envelope_not_object");
  if (value.success !== true) throw reject("envelope_not_success");
  if (!Array.isArray(value.errors) || value.errors.length !== 0) throw reject("envelope_errors_present");
  if (!Array.isArray(value.messages) || value.messages.length !== 0) throw reject("envelope_messages_present");
  if (!Object.hasOwn(value, "result")) throw reject("envelope_result_missing");
  return value.result;
}
export function bindingInventory(value) {
  const result = envelope(value);
  if (!record(result) || !Array.isArray(result.bindings) || result.bindings.length > 128) throw reject("bindings_invalid");
  const names = new Set();
  return result.bindings.map(binding => {
    if (!record(binding) || typeof binding.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(binding.name) ||
        typeof binding.type !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(binding.type) || names.has(binding.name)) throw reject("bindings_invalid");
    names.add(binding.name);
    // No binding values (including plaintext fields) leave this extractor.
    return { name: binding.name, type: binding.type };
  });
}
export function subdomainState(value) {
  const result = envelope(value);
  if (!exact(result, ["enabled", "previews_enabled"]) || typeof result.enabled !== "boolean" ||
      typeof result.previews_enabled !== "boolean") throw reject("subdomain_invalid");
  return { enabled: result.enabled, previews_enabled: result.previews_enabled };
}
export function deploymentInventory(value) {
  const result = envelope(value);
  if (!exact(result, ["deployments"]) || !Array.isArray(result.deployments) ||
      result.deployments.length < 1 || result.deployments.length > 10) throw reject("deployments_invalid");
  const ids = new Set();
  let previous = Infinity;
  return result.deployments.map(row => {
    const at = typeof row?.created_on === "string" ? Date.parse(row.created_on) : NaN;
    if (!record(row) || !uuid(row.id) || ids.has(row.id) || !Number.isSafeInteger(at) || at > previous ||
        row.strategy !== "percentage" || !Array.isArray(row.versions) || row.versions.length !== 1 ||
        !exact(row.versions[0], ["version_id", "percentage"]) || !uuid(row.versions[0].version_id) || row.versions[0].percentage !== 100) throw reject("deployments_invalid");
    ids.add(row.id); previous = at;
    return { deployment_id: row.id, version_id: row.versions[0].version_id, created_at_ms: at };
  });
}
function startupInput(value) {
  if (!exact(value, ["api_token", "operation_id", "expected_release", "preimage_deployment_id", "preimage_version_id"]) ||
      typeof value.api_token !== "string" || value.api_token.length < 1 || value.api_token.length > 8192 || /[\r\n]/.test(value.api_token) ||
      typeof value.operation_id !== "string" || !/^[1-9][0-9]{0,19}$/.test(value.operation_id) || !SHA.test(value.expected_release ?? "") ||
      !uuid(value.preimage_deployment_id) || !uuid(value.preimage_version_id)) throw reject();
  return value;
}
function candidateInput(value, input) {
  if (!exact(value, ["operation_id", "candidate_deployment_id", "candidate_version_id", "worker_release", "image_digest"]) ||
      value.operation_id !== input.operation_id || value.worker_release !== input.expected_release ||
      !uuid(value.candidate_deployment_id) || !uuid(value.candidate_version_id) ||
      value.candidate_deployment_id === input.preimage_deployment_id || value.candidate_version_id === input.preimage_version_id ||
      !/^sha256:[0-9a-f]{64}$/.test(value.image_digest ?? "")) throw reject();
  return { ...value };
}
async function boundedJson(response) {
  const reader = response.body?.getReader();
  if (!reader) throw reject("body_missing");
  let length = 0;
  const chunks = [];
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.byteLength;
      if (length > MAX_API_BYTES) throw reject("body_too_large");
      chunks.push(item.value);
    }
    try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))); }
    catch { throw reject("body_not_json"); }
  } finally { await reader.cancel().catch(() => {}); }
}
// Accepts only a 200, non-redirected, bounded JSON body. A refused non-200 JSON body is read
// under the same bound solely for its integer error codes and message class.
async function boundedBody(response, call) {
  if (response.redirected) throw reject("redirected_url");
  const json = /^application\/json(?:;|$)/i.test(response.headers.get("content-type") ?? "");
  if (response.status !== 200) {
    if (json) describeBody(call, await boundedJson(response).catch(() => undefined));
    // A non-2xx status names itself; only a 2xx other than 200 is a failed acceptance check.
    if (call.http_status >= 200 && call.http_status <= 299) throw reject("status_not_200");
    throw reject();
  }
  if (!json) throw reject("content_type_not_json");
  const body = await boundedJson(response);
  describeBody(call, body);
  return body;
}
export async function privateDirectory(directory, create = false) {
  if (typeof directory !== "string" || !isAbsolute(directory) || resolve(directory) !== directory ||
      Buffer.byteLength(join(directory, BROKER_SOCKET)) > 103) throw reject();
  if (create) await mkdir(directory, { mode: 0o700 });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || stat.uid !== process.getuid()) throw reject();
}
async function writeLedger(directory, value, initial = false) {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (initial ? constants.O_EXCL : constants.O_TRUNC);
  const handle = await open(join(directory, BROKER_LEDGER), flags, 0o600);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); }
  finally { await handle.close(); }
}
// One exclusive, no-follow, owner-only file in the private broker directory; the deploy
// step hands it to `wrangler deploy --secrets-file` and the broker removes it at bind.
async function writeSecretsFile(directory, content) {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  const handle = await open(join(directory, SECRETS_FILE), flags, 0o600);
  try { await handle.writeFile(content); await handle.sync(); }
  finally { await handle.close(); }
}
async function removeSecretsFile(directory) {
  await unlink(join(directory, SECRETS_FILE)).catch(error => { if (error.code !== "ENOENT") throw error; });
}
// Name AND type of every hidden-value binding: a secret_key turned secret_text is drift.
const secretSignature = inventory => inventory.filter(row => row.type === "secret_text" || row.type === "secret_key")
  .map(row => `${row.name}:${row.type}`).sort();
// After the workflow restores the exact preimage version, prove from the provider that it
// is active at 100% and carries no admin key, and that the key file is gone. Read-only.
export async function verifyRestoredPreimage(inputValue, { directory, request = fetch, timeoutMs = 30_000 } = {}) {
  if (!exact(inputValue, ["api_token", "preimage_deployment_id", "preimage_version_id"]) ||
      typeof inputValue.api_token !== "string" || inputValue.api_token.length < 1 || inputValue.api_token.length > 8192 ||
      /[\r\n]/.test(inputValue.api_token) || !uuid(inputValue.preimage_deployment_id) || !uuid(inputValue.preimage_version_id)) throw reject();
  await privateDirectory(directory);
  await lstat(join(directory, SECRETS_FILE)).then(() => { throw reject(); }, error => { if (error.code !== "ENOENT") throw error; });
  const read = async path => {
    const url = API + path;
    const response = await request(url, { method: "GET", redirect: "error", credentials: "omit", cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs), headers: { authorization: `Bearer ${inputValue.api_token}`, accept: "application/json" } });
    if (response.url && response.url !== url) throw reject();
    return boundedBody(response, { http_status: httpStatus(response), cf_error_codes: [], cf_message_class: null });
  };
  const rows = deploymentInventory(await read("/deployments"));
  if (rows[0].version_id !== inputValue.preimage_version_id || rows[0].deployment_id === inputValue.preimage_deployment_id) throw reject();
  const version = envelope(await read(`/versions/${inputValue.preimage_version_id}`));
  if (!record(version) || version.id !== inputValue.preimage_version_id) throw reject();
  if (bindingInventory(wrappedSettings(version.resources?.bindings)).some(row => row.name === SECRET_NAME)) throw reject();
  return { contract: RESTORE_CONTRACT, preimage_version_id: inputValue.preimage_version_id, active_percentage: 100,
    admin_key_present: false, secrets_file_present: false };
}
// Prints exactly one redacted line and never throws: the ledger is read through one
// no-follow, non-blocking descriptor, bounded, and only its re-validated `failure` is shown.
export async function ledgerFailureLine(directory) {
  try {
    await privateDirectory(directory);
    const handle = await open(join(directory, BROKER_LEDGER), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > MAX_IPC_BYTES) throw reject();
      const buffer = Buffer.alloc(MAX_IPC_BYTES + 1);
      let length = 0;
      for (let read; (read = (await handle.read(buffer, length, buffer.length - length, length)).bytesRead) > 0;) {
        length += read;
        if (length > MAX_IPC_BYTES) throw reject();
      }
      return failureLine(JSON.parse(buffer.toString("utf8", 0, length)));
    } finally { await handle.close(); }
  } catch { return "issue-1700 bootstrap failure unavailable"; }
}

// This closure alone owns both credentials. It exposes only fixed protocol data.
export function createBootstrapBroker(inputValue, { directory, request = fetch, proofRunner = runProof,
  now = Date.now, random = randomBytes, save = value => writeLedger(directory, value),
  readAttempt = () => readFile(join(directory, ATTEMPT_LEDGER), "utf8").then(JSON.parse),
  attemptExists = () => lstat(join(directory, ATTEMPT_LEDGER)).then(() => true, error => {
    if (error.code === "ENOENT") return false;
    throw error;
  }),
  writeSecrets = content => writeSecretsFile(directory, content),
  removeSecrets = () => removeSecretsFile(directory),
  lifetimeMs = MAX_LIFETIME_MS,
} = {}) {
  const input = { ...startupInput(inputValue) };
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1 || lifetimeMs > MAX_LIFETIME_MS) throw reject();
  const key = random(32);
  if (!Buffer.isBuffer(key) || key.length !== 32) throw reject();
  const started = now();
  const deadline = started + lifetimeMs;
  const controller = new AbortController();
  let state = "starting", busy = false, candidate = null, proof = null, attempt = null;
  let secretFileWritten = false, secretFileRemoved = false, candidateKeyConfirmed = false;
  let enabledAttempted = false, enabled = false, restoreAttempted = false, restored = false;
  let preimage = null, bindings = null;
  let probeSeen = false, cleanupBasis = null, admissionClosed = false;
  let failure = null, lastCall = null;
  // rollback_safe covers broker-owned state only (key file, subdomain). The key leaves the
  // deployed path when the workflow restores the exact, key-free preimage version.
  const snapshot = () => ({ contract: BROKER_CONTRACT, operation_id: input.operation_id,
    worker_release: input.expected_release, started_at_ms: started, expires_at_ms: deadline, state,
    secret_name: SECRET_NAME, secret_carrier: "candidate_version", secret_file_written: secretFileWritten,
    secret_file_removed: secretFileRemoved, candidate_key_confirmed: candidateKeyConfirmed,
    subdomain_enable_attempted: enabledAttempted, subdomain_enabled: enabled,
    subdomain_restore_attempted: restoreAttempted, subdomain_restored: restored,
    rollback_safe: state === "cleaned", cleanup_basis: cleanupBasis, probe_command_seen: probeSeen, admission_closed: admissionClosed,
    preimage, candidate, preimage_bindings: bindings, failure, pid: process.pid });
  async function dropSecretsFile() {
    await removeSecrets();
    if (secretFileWritten) secretFileRemoved = true;
  }
  const alive = () => { if (now() >= deadline || controller.signal.aborted || state === "unknown" || state === "closed") throw unknown(); };
  async function persist() { await save(snapshot()); }
  // First failure wins; only enums and bounded integers are copied out of a call.
  function note(call, error, timedOut = false, aborted = false) {
    if (failure !== null || call === null || call.endpoint_label === null) return;
    const validation = error?.[VALIDATION] ?? null;
    failure = { phase: call.phase, endpoint_label: call.endpoint_label, http_status: call.http_status,
      cf_error_codes: [...call.cf_error_codes], cf_message_class: call.cf_message_class,
      validation_failed: FAILURE_VALIDATIONS.includes(validation) ? validation : null, timed_out: timedOut, aborted };
  }
  // A check on an already-accepted response failed: attribute it to that call.
  function refuse(validation, call = lastCall) {
    const error = reject(validation);
    note(call, error);
    return error;
  }
  function nestedBindings(bindings, call = lastCall) {
    try { return bindingInventory(wrappedSettings(bindings)); }
    catch { throw refuse("bindings_invalid", call); }
  }
  async function api(phase, path, extract = value => value, method = "GET", body) {
    if (!FAILURE_PHASES.includes(phase)) throw reject();
    const call = lastCall = { phase, endpoint_label: endpointLabel(path), http_status: null, cf_error_codes: [], cf_message_class: null };
    try { alive(); }
    catch (error) { note(call, error, now() >= deadline, controller.signal.aborted); throw error; }
    // Read-only GETs plus the workers.dev toggle. There is no secrets path to call.
    if (!["/deployments", "/subdomain"].includes(path) && !/^\/versions\/[0-9a-f-]{36}$/.test(path)) throw reject();
    if (method !== "GET" && !(method === "POST" && path === "/subdomain")) throw reject();
    const budget = Math.min(30_000, deadline - now());
    let timer, timedOut = false;
    const abort = new AbortController();
    const onAbort = () => abort.abort();
    controller.signal.addEventListener("abort", onAbort, { once: true });
    const timeout = new Promise((_, fail) => { timer = setTimeout(() => { timedOut = true; abort.abort(); fail(unknown()); }, budget); });
    const operation = (async () => {
      const url = API + path;
      const response = await request(url, { method, redirect: "error", credentials: "omit", cache: "no-store", signal: abort.signal,
        headers: { authorization: `Bearer ${input.api_token}`, accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      call.http_status = httpStatus(response);
      if (response.url && response.url !== url) throw reject("redirected_url");
      const result = extract(await boundedBody(response, call));
      alive();
      return result;
    })();
    try { return await Promise.race([operation, timeout]); }
    catch (error) { note(call, error, timedOut || now() >= deadline, !timedOut && controller.signal.aborted); throw error; }
    finally { clearTimeout(timer); controller.signal.removeEventListener("abort", onAbort); }
  }
  async function currentCandidate(phase) {
    const rows = await api(phase, "/deployments", deploymentInventory);
    const current = rows[0];
    if (!candidate || current.deployment_id !== candidate.candidate_deployment_id || current.version_id !== candidate.candidate_version_id ||
        !rows.some(row => row.deployment_id === preimage.deployment_id && row.version_id === preimage.version_id) ||
        current.created_at_ms < Math.floor(started / 1000) * 1000 || current.created_at_ms > now()) throw refuse("deployment_chain_mismatch");
    const version = await api(phase, `/versions/${candidate.candidate_version_id}`, envelope);
    if (!record(version) || version.id !== candidate.candidate_version_id ||
        version.annotations?.["workers/message"] !== `issue-1700-route-free-${input.operation_id}-${input.expected_release}`) throw refuse("version_mismatch");
    const rawBindings = version.resources?.bindings;
    if (!Array.isArray(rawBindings)) throw refuse("bindings_invalid");
    const inventory = nestedBindings(rawBindings);
    const release = rawBindings.filter(row => row.name === "SENTRY_RELEASE");
    if (release.length !== 1 || release[0].type !== "plain_text" || release[0].text !== input.expected_release) throw refuse("release_binding_mismatch");
    // The admin key rides this exact version as secret_text and is its ONLY hidden-value
    // binding (the preimage has none, see prepare): any other secret came from inheritance.
    const carried = inventory.filter(row => row.name === SECRET_NAME);
    if (carried.length !== 1 || carried[0].type !== "secret_text") throw refuse("candidate_key_missing");
    if (JSON.stringify(secretSignature(inventory)) !== JSON.stringify([`${SECRET_NAME}:secret_text`])) throw refuse("candidate_secret_drift");
    return version;
  }
  async function prepare() {
    if (state !== "starting") throw reject();
    const rows = await api("prepare_deployments_before", "/deployments", deploymentInventory);
    if (rows[0].deployment_id !== input.preimage_deployment_id || rows[0].version_id !== input.preimage_version_id) throw refuse("preimage_mismatch");
    preimage = { ...rows[0], subdomain: await api("prepare_subdomain_before", "/subdomain", subdomainState) };
    if (preimage.subdomain.enabled !== false || preimage.subdomain.previews_enabled !== false) throw refuse("subdomain_not_disabled");
    // Inspect ALL binding types of the exact deployed preimage VERSION. After a rollback the
    // newest upload (and script settings) differ from it and may still name a stale key;
    // restoring this immutable version is what removes the key, so it must be key-free now.
    const version = await api("prepare_preimage_version", `/versions/${input.preimage_version_id}`, envelope);
    if (!record(version) || version.id !== input.preimage_version_id) throw refuse("version_mismatch");
    bindings = nestedBindings(version.resources?.bindings);
    if (bindings.some(row => row.name === SECRET_NAME)) throw refuse("preimage_key_present");
    // An upload inherits secret VALUES from the newest upload, which after every exact-preimage
    // rollback is not the preimage. Inherited values cannot be shown to be the preimage's, so a
    // preimage carrying any other secret is refused rather than silently re-sourced.
    if (secretSignature(bindings).length !== 0) throw refuse("preimage_secrets_unprovable");
    // No provider write: the key reaches Cloudflare only inside the candidate upload.
    await writeSecrets(`${JSON.stringify({ [SECRET_NAME]: key.toString("base64url") })}\n`);
    secretFileWritten = true;
    state = "prepared"; await persist(); return snapshot();
  }
  async function bindCandidate(value) {
    if (state !== "prepared") throw reject();
    candidate = candidateInput(value, input);
    // The upload has consumed the key file; it never outlives the bind, verified or not.
    await dropSecretsFile(); await persist();
    await currentCandidate("bind_verify_candidate");
    candidateKeyConfirmed = true;
    const before = await api("bind_subdomain_before", "/subdomain", subdomainState);
    if (before.enabled || before.previews_enabled) throw refuse("subdomain_not_disabled");
    enabledAttempted = true; await persist();
    const result = await api("bind_enable_subdomain", "/subdomain", subdomainState, "POST", { enabled: true, previews_enabled: false });
    if (!result.enabled || result.previews_enabled) throw refuse("subdomain_not_enabled");
    const readback = await api("bind_subdomain_after", "/subdomain", subdomainState);
    if (!readback.enabled || readback.previews_enabled) throw refuse("subdomain_not_enabled");
    enabled = true; state = "enabled"; await persist(); return snapshot();
  }
  async function probe() {
    if (state !== "enabled") throw reject();
    await currentCandidate("probe_verify_candidate");
    state = "running"; await persist();
    proof = await proofRunner({ authKey: key.toString("base64url"), apiToken: input.api_token,
      release: input.expected_release, expectedSha: input.expected_release, imageDigest: candidate.image_digest,
      attemptPath: join(directory, ATTEMPT_LEDGER), signal: controller.signal });
    alive();
    attempt = await readAttempt();
    if (!validateDeploymentProof(proof, attempt, { expectedRelease: input.expected_release,
      expectedImageDigest: candidate.image_digest, observedAt: now() })) throw reject();
    state = "complete"; await persist(); return proof;
  }
  async function cleanup() {
    const neverExecute = !probeSeen && ["prepared", "enabled", "bind_failed"].includes(state);
    if (!secretFileWritten || restoreAttempted || (!neverExecute &&
        (state !== "complete" || !validateDeploymentProof(proof, attempt, { expectedRelease: input.expected_release,
          expectedImageDigest: candidate?.image_digest, observedAt: now() })))) throw reject();
    // Irreversible close latch before the first await. Missing disk state alone
    // never authorizes this arm: the broker must positively own never-executed RAM state.
    state = "closing";
    admissionClosed = true;
    cleanupBasis = neverExecute ? "never_execute" : "complete_proof";
    await persist();
    if (neverExecute && await attemptExists()) throw reject();
    await dropSecretsFile();
    // A bound candidate must still be the exact active version before the restore. After a
    // failed bind this re-proves ownership (including the carried key) before any write.
    if (candidate) { await currentCandidate("cleanup_verify_before_restore"); candidateKeyConfirmed = true; }
    const current = await api("cleanup_subdomain_before", "/subdomain", subdomainState);
    // Undo only a toggle this broker attempted. An origin it never tried to enable, or a
    // confirmed enable someone else has since reverted, is not ours to touch.
    if (current.previews_enabled || (current.enabled && !enabledAttempted) || (enabled && !current.enabled)) {
      throw refuse("subdomain_state_mismatch");
    }
    if (current.enabled) {
      restoreAttempted = true; await persist();
      const restore = await api("cleanup_restore_subdomain", "/subdomain", subdomainState, "POST", preimage.subdomain);
      if (restore.enabled || restore.previews_enabled) throw refuse("subdomain_not_disabled");
    }
    const readback = await api("cleanup_subdomain_after", "/subdomain", subdomainState);
    if (readback.enabled || readback.previews_enabled) throw refuse("subdomain_not_disabled");
    restored = true; enabled = false; state = "cleaned"; key.fill(0); await persist(); return snapshot();
  }
  async function dispatch(command, value) {
    if (command === "status") { if (now() >= deadline) await expire(); return snapshot(); }
    if (busy) throw reject();
    if (!["prepare", "bind_candidate", "probe", "cleanup"].includes(command)) throw reject();
    if (command === "probe" && (state !== "enabled" || admissionClosed)) throw reject();
    if (command === "probe" && deadline - now() < PROBE_RESERVE_MS) {
      admissionClosed = true; await persist(); throw reject();
    }
    alive(); busy = true;
    if (command === "probe") probeSeen = true;
    try { return await ({ prepare, bind_candidate: bindCandidate, probe, cleanup })[command](value); }
    catch {
      // A failed bind of a parsed candidate never executed the probe. Keep that positive fact,
      // fenced (no probe is ever admitted again), so cleanup can still prove ownership, undo any
      // attempted workers.dev enable and let the workflow restore the exact preimage.
      // close() and expire() always end in UNKNOWN (expire before aborting, close after), so a
      // bind they interrupt is never left fenced.
      const fenced = command === "bind_candidate" && state === "prepared" && candidate !== null && !probeSeen &&
        now() < deadline;
      state = fenced ? "bind_failed" : "unknown";
      if (fenced) admissionClosed = true;
      await persist().catch(() => {}); throw unknown();
    }
    finally { busy = false; }
  }
  async function expire() {
    state = "unknown"; controller.abort(); key.fill(0); await dropSecretsFile().catch(() => {}); await persist();
  }
  async function close() {
    controller.abort(); key.fill(0); await dropSecretsFile().catch(() => {});
    if (state !== "cleaned") state = "unknown";
    await persist(); return snapshot();
  }
  return { dispatch, snapshot, expire, close };
}

export async function serveBroker(directory, input, { brokerFactory = createBootstrapBroker, lifetimeMs = MAX_LIFETIME_MS,
  onStopped = () => {},
} = {}) {
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1 || lifetimeMs > MAX_LIFETIME_MS) throw reject();
  await privateDirectory(directory);
  const broker = brokerFactory(input, { directory, lifetimeMs });
  await writeLedger(directory, broker.snapshot(), true);
  const sockets = new Set();
  let closed = false;
  const server = createServer(socket => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {});
    let data = Buffer.alloc(0), handled = false;
    const invalidate = async () => { await broker.expire().catch(() => {}); socket.destroy(); };
    socket.setTimeout(25 * 60_000, invalidate);
    socket.on("end", () => { if (!handled) void invalidate(); });
    socket.on("data", async chunk => {
      if (handled) return invalidate();
      data = Buffer.concat([data, chunk]);
      if (data.length > MAX_IPC_BYTES) return invalidate();
      if (!data.includes(10)) return;
      handled = true;
      let dispatched = false;
      try {
        const message = JSON.parse(data.toString("utf8"));
        if (!exact(message, ["command", "payload"]) || !["bind_candidate", "probe", "status", "cleanup", "close"].includes(message.command) ||
            (message.command !== "bind_candidate" && message.payload !== null)) throw reject();
        // Dispatch owns its state transitions: a safe admission/busy rejection
        // must not erase positively known never-execute or completed cleanup.
        dispatched = message.command !== "close";
        const result = message.command === "close" ? await broker.close() : await broker.dispatch(message.command, message.payload);
        socket.end(`${JSON.stringify({ ok: true, result })}\n`);
        if (message.command === "close") await shutdown();
      } catch { if (!dispatched) await broker.expire().catch(() => {}); socket.end('{"ok":false,"error":"bootstrap_unknown"}\n'); }
    });
  });
  const socketPath = join(directory, BROKER_SOCKET);
  let expiry;
  async function shutdown() {
    if (closed) return;
    closed = true; clearTimeout(expiry);
    const forciblyClose = setTimeout(() => { for (const socket of sockets) socket.destroy(); }, 1000);
    for (const socket of sockets) socket.end();
    if (server.listening) await new Promise(resolveClosed => server.close(resolveClosed));
    clearTimeout(forciblyClose);
    await unlink(socketPath).catch(error => { if (error.code !== "ENOENT") throw error; });
    onStopped();
  }
  expiry = setTimeout(async () => { try { await broker.expire(); } finally { await shutdown(); } }, lifetimeMs);
  try {
    await broker.dispatch("prepare");
    if (closed) throw unknown();
    await new Promise((yes, no) => { server.once("error", no); server.listen(socketPath, yes); });
    await chmod(socketPath, 0o600);
  } catch { await broker.close().catch(() => {}); await shutdown(); throw unknown(); }
  return { broker, server, close: async () => { await broker.close(); await shutdown(); } };
}

export async function brokerCommand(directory, command, payload = null, { timeoutMs = 25 * 60_000 } = {}) {
  await privateDirectory(directory);
  const path = join(directory, BROKER_SOCKET);
  const stat = await lstat(path);
  if (!stat.isSocket() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid()) throw reject();
  return new Promise((yes, no) => {
    const socket = createConnection(path);
    let data = Buffer.alloc(0);
    const finish = (error, value) => { clearTimeout(timer); socket.destroy(); error ? no(unknown()) : yes(value); };
    const timer = setTimeout(() => finish(unknown()), timeoutMs);
    socket.on("connect", () => socket.write(`${JSON.stringify({ command, payload })}\n`));
    socket.on("error", () => finish(unknown()));
    socket.on("data", chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.length > MAX_IPC_BYTES) return finish(unknown());
      if (data.includes(10)) {
        try { const reply = JSON.parse(data.toString("utf8")); if (reply.ok !== true) throw unknown(); finish(null, reply.result); }
        catch { finish(unknown()); }
      }
    });
    socket.on("end", () => { if (!data.includes(10)) finish(unknown()); });
  });
}
// Local process metadata only. Neither argv nor the ownership record contains credentials.
// lstart plus exact uid/executable/source/private-directory binds a PID to this launch.
export async function inspectBrokerProcess(pid) {
  if (!Number.isSafeInteger(pid) || pid < 2) throw reject();
  return new Promise((yes, no) => {
    execFile("/bin/ps", ["-ww", "-p", String(pid), "-o", "pid=,uid=,stat=,lstart=,command="],
      { timeout: 500, maxBuffer: 16_384, env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } }, (error, stdout) => {
        if (error && error.code === 1 && stdout.trim() === "") return yes(null);
        if (error) return no(unknown());
        const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+([^\r\n]+)\s*$/.exec(stdout);
        if (!match || Number(match[1]) !== pid) return no(unknown());
        // An OS-confirmed zombie has exited and has no process memory left;
        // its changed display command must not be mistaken for a live reused PID.
        if (match[3].startsWith("Z")) return yes(null);
        yes({ pid, uid: Number(match[2]), started: match[4].replace(/\s+/g, " "), command: match[5].trim() });
      });
  });
}
function exactProcess(value, directory) {
  return exact(value, ["pid", "uid", "started", "command"]) && Number.isSafeInteger(value.pid) && value.pid > 1 &&
    value.uid === process.getuid() && typeof value.started === "string" && value.started.length > 0 && value.started.length < 64 &&
    value.command === `${process.execPath} ${SOURCE} serve ${directory}`;
}
export async function captureBrokerProcess(directory, pid, inspect = inspectBrokerProcess) {
  await privateDirectory(directory);
  const identity = await inspect(pid);
  if (!exactProcess(identity, directory) || identity.pid !== pid) throw reject();
  const owner = { contract: "corelink-staging-http-bootstrap-process-v1", directory, ...identity };
  const handle = await open(join(directory, BROKER_PROCESS), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(`${JSON.stringify(owner)}\n`); await handle.sync(); }
  finally { await handle.close(); }
  return owner;
}
const MAX_OWNER_BYTES = 4096;
// The ownership record names the PID that shutdown may signal, so the bytes that are
// parsed must be the bytes that were validated. One descriptor does both: O_NOFOLLOW
// refuses a symlink, O_NONBLOCK keeps a FIFO from stalling open(), and fstat/read act
// on that inode, so a rename after validation cannot substitute another record.
async function readBrokerProcess(path) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if (error.code === "ENOENT") throw error; throw reject(); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > MAX_OWNER_BYTES) throw reject();
    const buffer = Buffer.alloc(MAX_OWNER_BYTES + 1);
    let length = 0;
    for (let read; (read = (await handle.read(buffer, length, buffer.length - length, length)).bytesRead) > 0;) {
      length += read;
      if (length > MAX_OWNER_BYTES) throw reject();
    }
    return JSON.parse(buffer.toString("utf8", 0, length));
  } finally { await handle.close(); }
}
export async function shutdownBroker(directory, { inspect = inspectBrokerProcess, signal = (pid, name) => process.kill(pid, name),
  command = brokerCommand, pause = ms => new Promise(yes => setTimeout(yes, ms)),
} = {}) {
  await privateDirectory(directory);
  const owner = await readBrokerProcess(join(directory, BROKER_PROCESS));
  if (!exact(owner, ["contract", "directory", "pid", "uid", "started", "command"]) ||
      owner.contract !== "corelink-staging-http-bootstrap-process-v1" || owner.directory !== directory) throw reject();
  const { contract: _contract, directory: _directory, ...identity } = owner;
  if (!exactProcess(identity, directory) || identity.pid === process.pid) throw reject();
  let observationOnly = false;
  const gone = async (observeTransition = false) => {
    const current = await inspect(identity.pid);
    if (current === null) return true;
    if (!exactProcess(current, directory) || current.pid !== identity.pid || current.started !== identity.started) {
      if (!observeTransition) throw reject();
      // During shutdown, OS command metadata can change before actual absence.
      // A mismatch is never exit proof and permanently forbids further signals.
      observationOnly = true;
    }
    return false;
  };
  const waitGone = async () => {
    for (let index = 0; index < 10; index++) { if (await gone(true)) return true; await pause(100); }
    return gone(true);
  };
  let exited = await gone();
  if (!exited) {
    await command(directory, "close", null, { timeoutMs: 1000 }).catch(() => {});
    exited = await waitGone();
  }
  for (const name of ["SIGTERM", "SIGKILL"]) {
    if (exited || observationOnly) break;
    // Revalidate immediately before each signal; a missing/reused/unrelated PID is never killed.
    if (await gone()) { exited = true; break; }
    try { signal(identity.pid, name); } catch (error) { if (error.code !== "ESRCH") throw unknown(); }
    exited = await waitGone();
  }
  if (!exited) throw unknown();
  const socketPath = join(directory, BROKER_SOCKET);
  try {
    const socket = await lstat(socketPath);
    if (!socket.isSocket() || socket.uid !== process.getuid() || (socket.mode & 0o777) !== 0o600) throw reject();
    await unlink(socketPath);
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  return { contract: "corelink-staging-http-bootstrap-shutdown-v1", pid: identity.pid,
    process_exited: true, provider_cleanup_claimed: false };
}
async function stdinJson() {
  let data = Buffer.alloc(0);
  for await (const chunk of process.stdin) { data = Buffer.concat([data, chunk]); if (data.length > 16_384) throw reject(); }
  return JSON.parse(data.toString("utf8"));
}
export async function startBroker(directory, input, { spawnProcess = spawn, inspect = inspectBrokerProcess } = {}) {
  startupInput(input);
  await privateDirectory(directory, true);
  // Do not inherit NODE_OPTIONS, CI credentials, or unrelated workflow secrets.
  const child = spawnProcess(process.execPath, [SOURCE, "serve", directory], {
    detached: true, env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C.UTF-8" }, stdio: ["pipe", "pipe", "ignore"],
  });
  let data = Buffer.alloc(0);
  const exited = new Promise(resolveExited => child.once("close", resolveExited));
  const ready = new Promise((yes, no) => {
    child.once("error", () => no(unknown())); child.once("exit", () => no(unknown()));
    child.stdout.on("data", chunk => {
      data = Buffer.concat([data, chunk]);
      if (data.length > MAX_IPC_BYTES) return no(unknown());
      if (data.includes(10)) {
        try { const value = JSON.parse(data.toString("utf8")); if (value.state !== "prepared") throw unknown(); yes(value); }
        catch { no(unknown()); }
      }
    });
  });
  ready.catch(() => {});
  const timer = setTimeout(() => child.kill("SIGTERM"), 5 * 60_000);
  child.stdin.on("error", () => {});
  try {
    await captureBrokerProcess(directory, child.pid, inspect);
    child.stdin.end(JSON.stringify(input));
    const result = await ready; child.stdout.destroy(); child.unref(); return result;
  }
  catch {
    child.kill("SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 1000);
    try { await exited; } finally { clearTimeout(force); }
    throw unknown();
  }
  finally { clearTimeout(timer); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, directory] = process.argv.slice(2);
  try {
    if (process.argv.length !== 4) throw reject();
    if (command === "serve") {
      const service = await serveBroker(directory, startupInput(await stdinJson()), { onStopped: () => process.exit(0) });
      let stopping = false;
      const stop = async () => { if (stopping) return; stopping = true; await service.close().catch(() => {}); process.exit(0); };
      process.once("SIGTERM", stop); process.once("SIGINT", stop);
      process.stdout.end(`${JSON.stringify(service.broker.snapshot())}\n`);
    } else if (command === "start") {
      process.stdout.write(`${JSON.stringify(await startBroker(directory, startupInput(await stdinJson())))}\n`);
    } else if (command === "shutdown") {
      process.stdout.write(`${JSON.stringify(await shutdownBroker(directory))}\n`);
    } else if (command === "verify_restored") {
      process.stdout.write(`${JSON.stringify(await verifyRestoredPreimage(await stdinJson(), { directory }))}\n`);
    } else if (command === "failure") {
      process.stdout.write(`${await ledgerFailureLine(directory)}\n`);
    } else if (["bind_candidate", "probe", "status", "cleanup", "close"].includes(command)) {
      const result = await brokerCommand(directory, command, command === "bind_candidate" ? await stdinJson() : null);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } else throw reject();
  } catch { process.stderr.write("issue-1700 bootstrap failed bootstrap_unknown\n"); process.exitCode = 1; }
}
