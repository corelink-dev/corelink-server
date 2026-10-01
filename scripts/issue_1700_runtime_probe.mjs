#!/usr/bin/env node
// Protected, temporary Cron-to-DO-to-Container D1 proof for issue #1700.
// Never prints Cloudflare credentials, the tail URL, or unmatched Worker logs.

import { appendFile, readFile, writeFile } from "node:fs/promises";
import { readFileSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";
import WebSocket from "ws";
import { isApprovedProbeWindow } from "./issue_1700_probe_window.mjs";

export const ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
export const WORKER_NAME = "corelink-staging";
export const CONTAINER_APP_ID = "a033fb81-6388-47d9-9049-0b6942778055";
export const CONTAINER_APP_NAME = "corelink-staging-corelinkserver";
export const PROBE_WINDOW = JSON.parse(readFileSync(new URL("../crates/corelink-container/src/routes/staging_d1_probe_window.json", import.meta.url), "utf8"));
export function approvedProbeWindow(value = PROBE_WINDOW) {
  return isApprovedProbeWindow(value);
}
export const PROBE_CRON = PROBE_WINDOW.cron;
export const PROBE_EXPIRY = PROBE_WINDOW.expires_ms;
export const RECEIPT_PREFIX = "[staging_d1_runtime_probe] receipt=";
const MIN_TAIL_TTL_MS = 4 * 60_000;
const TAIL_RENEW_LEAD_MS = 60_000;
const MAX_OWNED_TAILS = 8;
const TAIL_CREATE_TIMEOUT_MS = 20_000;
const TAIL_RENEW_OPEN_TIMEOUT_MS = 20_000;

const apiBase = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}`;
const allowedReceiptKeys = new Set([
  "old_probe_release", "old_probe_retired", "old_probe_tables_absent", "v5_probe_release", "v5_probe_retired", "v5_probe_tables_absent", "v5_prior_execution", "v4_probe_catalog_absent",
  "contract", "probe_nonce", "outcome", "worker_release", "scheduled_time_ms", "parameterized_select",
  "failed_batch_observed", "rollback_absence_verified", "probe_table_dropped",
  "d1_binding_intercepted", "authorization_absent", "cf_api_token_absent",
]);

export function captureDeployImageDigest(text) {
  if (typeof text !== "string") throw new Error("deploy log rejected");
  const versionLines = text.split(/\r?\n/).filter((line) => line.includes("Current Version ID:"));
  const imageLines = text.split(/\r?\n/).filter((line) => /\bdigest:/i.test(line));
  const digestPattern = /\bdigest:\s*(sha256:[0-9a-f]{64})(?:\s|$)/;
  if (versionLines.length !== 1 || imageLines.length !== 1) throw new Error("deploy version/image result is ambiguous");
  const version = versionLines[0].match(/Current Version ID:\s*([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})(?:\s|$)/);
  const digest = imageLines[0].match(digestPattern);
  if (!version || !digest || (imageLines[0].match(/sha256:[0-9a-f]{64}/g) ?? []).length !== 1) {
    throw new Error("deploy version/image result is malformed");
  }
  return { versionId: version[1], imageDigest: digest[1] };
}

// Cloudflare's account-wide list can retain a previous rollout indefinitely.
// Only the exact application detail endpoint is authoritative for this proof.
export function normalizeContainerDetail(envelope, { requireHealthy = true } = {}) {
  const app = envelope?.result;
  const health = app?.health?.instances;
  if (envelope?.success !== true || !Array.isArray(envelope.errors) || envelope.errors.length !== 0 ||
      app?.account_id !== ACCOUNT_ID || app?.id !== CONTAINER_APP_ID || app?.name !== CONTAINER_APP_NAME ||
      app?.instances !== 5 || !Array.isArray(app?.health?.errors) || app.health.errors.length !== 0 ||
      !["healthy", "active", "assigned", "stopped", "failed", "scheduling", "starting"].every(k => Number.isSafeInteger(health?.[k]) && health[k] >= 0 && health[k] <= 5) || health.failed !== 0) {
    throw new Error("exact Container application health rejected");
  }
  const healthy = health.healthy === 5 && ["active", "assigned", "stopped", "failed", "scheduling", "starting"].every(k => health[k] === 0);
  if (requireHealthy && !healthy) throw new Error("exact Container application not ready");
  const rows = [{ id: app.id, name: app.name, version: app.version, image: app.configuration?.image,
    exact_application_health_verified: healthy }];
  captureContainerPreimage(JSON.stringify(rows));
  return rows;
}

export async function readContainerDetail({ token = process.env.CLOUDFLARE_API_TOKEN,
  api = fetch, timeoutMs = 30_000, requireHealthy = true } = {}) {
  if (!token || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new Error("exact Container read contract rejected");
  }
  const response = await api(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/containers/applications/${CONTAINER_APP_ID}`, {
    headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error("exact Container read failed");
  return JSON.stringify(normalizeContainerDetail(await response.json(), { requireHealthy }));
}

export function captureContainerPreimage(text) {
  let rows;
  try { rows = JSON.parse(text); } catch { throw new Error("Container application inventory rejected"); }
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 100) {
    throw new Error("Container application inventory rejected");
  }
  const matches = rows.filter((row) => row?.id === CONTAINER_APP_ID || row?.name === CONTAINER_APP_NAME);
  if (matches.length !== 1) throw new Error("staging Container preimage is missing or ambiguous");
  const [app] = matches;
  const imagePattern = new RegExp(`^registry\\.cloudflare\\.com/${ACCOUNT_ID}/${CONTAINER_APP_NAME.replaceAll("-", "\\-")}@sha256:[0-9a-f]{64}$`);
  if (app.id !== CONTAINER_APP_ID || app.name !== CONTAINER_APP_NAME ||
      typeof app.image !== "string" || !imagePattern.test(app.image) ||
      !Number.isSafeInteger(app.version) || app.version < 1) {
    throw new Error("staging Container preimage is malformed");
  }
  return {
    application_id: app.id,
    application_name: app.name,
    application_version: app.version,
    image: app.image,
    image_digest: app.image.slice(app.image.lastIndexOf("@") + 1),
  };
}

export function verifyContainerPreimage(text, expectedImage) {
  const actual = captureContainerPreimage(text);
  if (actual.image !== expectedImage) throw new Error("staging Container image rollback readback differs from preimage");
  return actual;
}

export function verifyContainerImageDigest(text, expectedDigest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error("expected Container digest rejected");
  const actual = captureContainerPreimage(text);
  if (actual.image_digest !== expectedDigest) throw new Error("staging Container image digest readback differs from candidate");
  return actual;
}

export function verifyContainerState(text, expectedDigest, { expectedVersion, minimumVersion } = {}) {
  const state = verifyContainerImageDigest(text, expectedDigest);
  if (expectedVersion !== undefined && state.application_version !== expectedVersion) {
    throw new Error("staging Container application version changed");
  }
  if (minimumVersion !== undefined && state.application_version <= minimumVersion) {
    throw new Error("staging Container application version did not advance");
  }
  return state;
}

// Retry only an unchanged, captured preimage while the provider converges.
// A different app, unexpected version or digest is drift, never a retry signal.
export async function waitForContainerState({
  read, preimage, expectedDigest, now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = 600_000, intervalMs = 5_000,
}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000 ||
      !Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > timeoutMs ||
      !/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "") ||
      preimage?.application_id !== CONTAINER_APP_ID ||
      !Number.isSafeInteger(preimage.application_version)) {
    throw new Error("Container readback retry contract rejected");
  }
  const deadline = now() + timeoutMs;
  while (now() < deadline) {
    const text = await read(Math.max(1, deadline - now()));
    const state = captureContainerPreimage(text);
    if (now() >= deadline) throw new Error("Container readback deadline exceeded");
    const candidate = state.image_digest === expectedDigest && state.application_version === preimage.application_version + 1;
    if (candidate && JSON.parse(text)[0]?.exact_application_health_verified === true) return { text, state };
    if (!candidate && (state.application_version !== preimage.application_version || state.image !== preimage.image)) {
      throw new Error("Container readback drift rejected");
    }
    await sleep(Math.min(intervalMs, deadline - now()));
  }
  throw new Error("Container readback deadline exceeded");
}

export function verifyContainerRollback(beforeText, afterText, expectedImage) {
  const before = verifyContainerPreimage(beforeText, expectedImage);
  const after = verifyContainerPreimage(afterText, expectedImage);
  if (after.application_version !== before.application_version) {
    throw new Error("Container application changed after Worker rollback");
  }
  return after;
}

function exactReceipt(receipt, release, startedAt, deadline) {
  return receipt !== null && typeof receipt === "object" && !Array.isArray(receipt) &&
    Object.keys(receipt).length === allowedReceiptKeys.size &&
    Object.keys(receipt).every((key) => allowedReceiptKeys.has(key)) &&
    receipt.contract === "corelink-staging-d1-binding-runtime-v1" &&
    receipt.probe_nonce === PROBE_WINDOW.nonce &&
    receipt.old_probe_release === "0f785fb9b096afe01247f1057d46377b9f604f13" &&
    receipt.old_probe_retired === true && receipt.old_probe_tables_absent === true &&
    receipt.v5_probe_release === "cc32b3d819181bf9175e795868f66212aa5456c1" &&
    receipt.v5_probe_retired === true && receipt.v5_probe_tables_absent === true &&
    receipt.v5_prior_execution === "unknown" &&
    receipt.v4_probe_catalog_absent === true &&
    receipt.outcome === "pass" && receipt.worker_release === release &&
    Number.isSafeInteger(receipt.scheduled_time_ms) &&
    receipt.scheduled_time_ms >= startedAt &&
    receipt.scheduled_time_ms < deadline &&
    ["parameterized_select", "failed_batch_observed", "rollback_absence_verified",
      "probe_table_dropped", "d1_binding_intercepted", "authorization_absent",
      "cf_api_token_absent"].every((key) => receipt[key] === true);
}

function extractReceipt(event, release, startedAt, deadline) {
  const logs = Array.isArray(event?.logs) ? event.logs : [];
  for (const entry of logs) {
    const messages = Array.isArray(entry?.message) ? entry.message : [entry?.message];
    for (const message of messages) {
      if (typeof message !== "string" || !message.startsWith(RECEIPT_PREFIX)) continue;
      try {
        const receipt = JSON.parse(message.slice(RECEIPT_PREFIX.length));
        if (exactReceipt(receipt, release, startedAt, deadline)) return receipt;
      } catch {
        // Malformed/unrelated logs are discarded without being printed.
      }
    }
  }
  return undefined;
}

function requireScheduleEnvelope(value) {
  if (value?.success !== true || !Array.isArray(value?.result?.schedules)) {
    throw new Error("schedule API response rejected");
  }
  return value.result.schedules;
}

function exactSchedules(schedules, crons) {
  return schedules.length === crons.length && schedules.every((item, index) =>
    item !== null && typeof item === "object" && item.cron === crons[index] &&
    Object.keys(item).every((key) => ["cron", "created_on", "modified_on"].includes(key)));
}

// Retain only bounded structural evidence, never arbitrary provider values.
// WeakMap provenance prevents callers from injecting diagnostic payloads.
const scheduleReadbacks = new WeakMap();
const tailCleanupEvidence = new WeakMap();
function scheduleReadbackSummary(schedules) {
  const cronField = /^(?:[0-9*/?,LW#-]+|(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC|SUN|MON|TUE|WED|THU|FRI|SAT)(?:[-/,](?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC|SUN|MON|TUE|WED|THU|FRI|SAT))*)$/;
  return {
    count: schedules.length,
    expected_cron_matches: schedules.filter(item => item?.cron === PROBE_CRON).length,
    truncated: schedules.length > 8,
    entries: schedules.slice(0, 8).map(item => {
      const object = item !== null && typeof item === "object" && !Array.isArray(item);
      const keys = object ? Object.keys(item).sort() : [];
      const cron = object && typeof item.cron === "string" ? item.cron : "";
      const fields = cron.split(" ");
      return {
        object,
        key_count: keys.length,
        keys: keys.slice(0, 16).map(key => /^[a-z][a-z_]{0,39}$/.test(key) ? key : "[redacted]"),
        keys_truncated: keys.length > 16,
        cron: cron.length <= 80 && !/\d{3}/.test(cron) && fields.length === 5 && fields.every(field => cronField.test(field)) ? cron : "[redacted]",
      };
    }),
  };
}

const probeStages = new Set(["probe_preflight", "schedule_preflight", "tail_create", "tail_connect", "schedule_install", "receipt_wait", "schedule_cleanup", "tail_cleanup"]);
const probeErrors = new Map([
  ["runtime probe preflight rejected", "probe_preflight"],
  ["preexisting Worker schedules block probe", "preexisting_schedule"],
  ["Cloudflare API response rejected", "api_envelope"],
  ["Cloudflare API operation failed", "api_failure"],
  ["Cloudflare API request failed", "api_transport"],
  ["tail preflight rejected", "tail_envelope"],
  ["Worker tail connection timed out", "tail_open_timeout"],
  ["Worker tail initialization failed", "tail_initialization"],
  ["Worker tail protocol rejected", "tail_protocol"],
  ["Worker tail stream failed", "tail_stream"],
  ["Worker tail stream closed before receipt", "tail_closed"],
  ["Worker tail renewal failed", "tail_renewal"],
  ["Worker tail renewal window missed", "tail_renewal_window"],
  ["Worker tail renewal limit exceeded", "tail_renewal_limit"],
  ["Worker tail renewal pong deadline exceeded", "tail_renewal_pong_timeout"],
  ["Worker tail expired before replacement", "tail_expired"],
  ["runtime probe receipt timed out", "receipt_timeout"],
  ["schedule API response rejected", "schedule_envelope"],
  ["installed schedule readback rejected", "schedule_readback"],
  ["schedule cleanup readback rejected", "schedule_cleanup"],
  ["schedule drift requires operator cleanup", "schedule_drift"],
]);

// Never include provider bodies, exception messages, tokens or tail URLs.
export function failureDiagnostic(error) {
  return {
    stage: probeStages.has(error?.stage) ? error.stage : "local_validation",
    code: probeErrors.get(error?.message) ?? "unexpected_error",
    ...(Number.isInteger(error?.httpStatus) && error.httpStatus >= 100 && error.httpStatus <= 599
      ? { http_status: error.httpStatus } : {}),
    ...(scheduleReadbacks.has(error) ? { schedule_readback: scheduleReadbacks.get(error) } : {}),
    ...(tailCleanupEvidence.has(error) ? { tail_cleanup: tailCleanupEvidence.get(error) } : {}),
  };
}

export async function decodeTailFrame(data) {
  if (data instanceof Blob) {
    if (data.size > 1024 * 1024) return undefined;
    data = await data.arrayBuffer();
  }
  if (typeof data === "string") return data.length <= 1024 * 1024 ? data : undefined;
  if (data instanceof ArrayBuffer && data.byteLength <= 1024 * 1024) return new TextDecoder("utf-8", { fatal: true }).decode(data);
  return undefined;
}

export async function runRuntimeProbe({
  token,
  release,
  expectedSha,
  imageDigest,
  api = fetch,
  socketFactory = (url, protocol) => new WebSocket(url, protocol),
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
  signal,
  timeoutMs = 25 * 60_000,
}) {
  if (!approvedProbeWindow()) throw Object.assign(new Error("runtime probe window rejected"), { stage: "probe_preflight" });
  if (typeof token !== "string" || token.length < 1 || !/^[0-9a-f]{40}$/.test(release ?? "") ||
      release !== expectedSha || !/^sha256:[0-9a-f]{64}$/.test(imageDigest ?? "") ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 25 * 60_000 ||
      now() < PROBE_WINDOW.starts_ms ||
      now() + 16 * 60_000 >= PROBE_WINDOW.last_entry_ms ||
      now() + timeoutMs >= PROBE_EXPIRY) {
    throw Object.assign(new Error("runtime probe preflight rejected"), { stage: "probe_preflight" });
  }

  let stage = "schedule_preflight";
  const tagged = (error) => Object.assign(error instanceof Error ? error : new Error("runtime probe failed"), { stage });
  async function request(path, init = {}, cleanup = false, requestTimeoutMs = 30_000) {
    let response;
    try { response = await api(`${apiBase}${path}`, {
      ...init,
      signal: cleanup || signal === undefined ? AbortSignal.timeout(requestTimeoutMs)
        : AbortSignal.any([signal, AbortSignal.timeout(requestTimeoutMs)]),
      headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
    }); } catch { throw tagged(new Error("Cloudflare API request failed")); }
    let body;
    try { body = await response.json(); } catch { throw tagged(new Error("Cloudflare API response rejected")); }
    if (!response.ok || body?.success !== true) throw Object.assign(tagged(new Error("Cloudflare API operation failed")), { httpStatus: response.status });
    return Object.assign(body, { http_status: response.status });
  }

  const startedAt = now();
  const deadline = Math.min(startedAt + timeoutMs, PROBE_EXPIRY);
  try {
    const before = requireScheduleEnvelope(await request("/schedules"));
    if (before.length !== 0) throw new Error("preexisting Worker schedules block probe");
  } catch (error) { throw tagged(error); }

  const tails = [];
  let activeTail;
  let socket;
  let scheduleAttempted = false;
  let receipt;
  let primaryError;
  let receiptTimer;
  let openTimer;
  let heartbeatTimer;
  let heartbeatFn;
  let pongTimer;
  let renewalTimer;
  let tailExpiryTimer;
  let renewalTask = Promise.resolve();
  let resolveCandidatePong;
  let rejectCandidatePong;
  let resolveCandidateOpen;
  let rejectCandidateOpen;
  let renewalConnecting = false;
  let bindTailSocket;
  let initializeTailSocket;
  let lastPongAt;
  let pendingPongAt;
  let tailFrameCount = 0;
  let tailReconnects = 0;
  let receiptAccepted = false;
  let terminalFailure = false;
  let stopRequested = false;
  let pingCount = 0;
  let closeEvidence;
  const tailCleanupReceipts = [];
  let resolveOpen = () => {};
  let rejectOpen = () => {};
  let rejectReceipt = () => {};
  let failTail = (_reason) => {};
  async function createTail() {
    if (tails.length >= MAX_OWNED_TAILS) throw new Error("Worker tail renewal limit exceeded");
    const record = (await request("/tails", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ filters: [] }),
    }, false, TAIL_CREATE_TIMEOUT_MS)).result;
    if (typeof record?.id !== "string" || !/^[a-f0-9]{32}$/.test(record.id)) throw new Error("tail preflight rejected");
    const expiry = Date.parse(record?.expires_at);
    const owned = { id: record.id, url: record.url, expiresAt: expiry };
    tails.push(owned);
    if (typeof record?.url !== "string" || !/^wss:\/\//.test(record.url) ||
        !Number.isFinite(expiry) || expiry < now() + MIN_TAIL_TTL_MS) throw new Error("tail preflight rejected");
    return owned;
  }
  async function deleteOwnedTail(tail) {
    if (tail.cleanupAttempted) return;
    tail.cleanupAttempted = true;
    try {
      const deleted = await request(`/tails/${tail.id}`, { method: "DELETE" }, true);
      tailCleanupReceipts.push({ id: tail.id, http_status: deleted.http_status,
        success: deleted.success === true, deleted_at_ms: now() });
    } catch (error) {
      tailCleanupReceipts.push({ id: tail.id,
        http_status: Number.isInteger(error?.httpStatus) ? error.httpStatus : null,
        success: false, deleted_at_ms: now() });
      throw error;
    }
  }
  function armTailExpiry(tail) {
    clearTimeoutFn(tailExpiryTimer);
    tailExpiryTimer = setTimeoutFn(() => {
      if (activeTail?.id === tail.id && now() >= tail.expiresAt) failTail("Worker tail expired before replacement");
    }, Math.max(1, tail.expiresAt - now()));
  }
  const onAbort = () => {
    stopRequested = true;
    rejectOpen(new Error("runtime probe cancelled"));
    rejectReceipt(new Error("runtime probe cancelled"));
    rejectCandidateOpen?.(new Error("runtime probe cancelled"));
    rejectCandidatePong?.(new Error("runtime probe cancelled"));
    clearTimeoutFn(renewalTimer);
    try { socket?.close(); } catch { /* schedule and tail cleanup still run below */ }
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  try {
    stage = "tail_create";
    const tail = await createTail();
    activeTail = tail;
    armTailExpiry(tail);
    if (signal?.aborted) throw new Error("runtime probe cancelled");

    stage = "tail_connect";
    socket = socketFactory(tail.url, "trace-v1");
    socket.binaryType = "arraybuffer";
    const opened = new Promise((resolve, reject) => {
      resolveOpen = resolve;
      rejectOpen = reject;
      openTimer = setTimeoutFn(() => reject(new Error("Worker tail connection timed out")), Math.min(30_000, Math.max(1, deadline - now())));
      socket.onopen = () => {
        clearTimeoutFn(openTimer);
        if (socket.protocol !== "trace-v1") return reject(new Error("Worker tail protocol rejected"));
        try { socket.send(JSON.stringify({ debug: false })); }
        catch { return reject(new Error("Worker tail initialization failed")); }
        resolve();
      };
    });
    const receiptPromise = new Promise((resolve, reject) => {
      rejectReceipt = reject;
      receiptTimer = setTimeoutFn(() => reject(new Error("runtime probe receipt timed out")), Math.max(0, deadline - now()));
      const onMessage = async (message) => {
        tailFrameCount = Math.min(1_000_000, tailFrameCount + 1);
        try {
          const event = JSON.parse(await decodeTailFrame(message.data));
          const found = extractReceipt(event, release, startedAt, deadline);
          if (found !== undefined && now() < deadline && found.scheduled_time_ms <= now()) {
            receiptAccepted = true;
            clearTimeoutFn(renewalTimer);
            clearTimeoutFn(tailExpiryTimer);
            resolveCandidateOpen?.();
            resolveCandidatePong?.();
            clearTimeoutFn(receiptTimer);
            resolve(found);
          }
        } catch {
          // Ignore malformed tail frames without logging their contents.
        }
      };
      const closeEvidenceFor = (event) => {
        const code = Number.isInteger(event?.code) ? event.code : null;
        const reason = event?.reason instanceof Buffer ? event.reason : Buffer.from(String(event?.reason ?? ""));
        closeEvidence = { code, was_clean: typeof event?.wasClean === "boolean" ? event.wasClean : null,
          reason_sha256: createHash("sha256").update(reason).digest("hex") };
      };
      const fail = (reason) => {
        terminalFailure = true;
        clearTimeoutFn(receiptTimer);
        rejectOpen(new Error(reason));
        rejectCandidateOpen?.(new Error(reason));
        rejectCandidatePong?.(new Error(reason));
        reject(new Error(reason));
      };
      failTail = fail;
      const onPong = (target) => {
        // A late pong from a replaced socket must not satisfy the active tail's
        // heartbeat deadline.
        if (target !== socket) return;
        lastPongAt = now();
        pendingPongAt = undefined;
        clearTimeoutFn(pongTimer);
        pongTimer = undefined;
        resolveCandidatePong?.();
      };
      const initialize = (target) => {
        clearTimeoutFn(openTimer);
        pendingPongAt = undefined;
        if (target.protocol !== "trace-v1") return fail("Worker tail protocol rejected");
        try { target.send(JSON.stringify({ debug: false })); }
        catch { return fail("Worker tail initialization failed"); }
        lastPongAt = now();
        resolveOpen();
      };
      initializeTailSocket = initialize;
      const recover = () => {
        if (receiptAccepted || tailReconnects >= 1 || now() >= deadline) return false;
        tailReconnects += 1;
        clearTimeoutFn(pongTimer);
        pongTimer = undefined;
        pendingPongAt = undefined;
        try {
          const replacement = socketFactory(activeTail.url, "trace-v1");
          socket = replacement;
          replacement.binaryType = "arraybuffer";
          bind(replacement);
          openTimer = setTimeoutFn(() => fail("Worker tail reconnect timed out"),
            Math.min(30_000, Math.max(1, deadline - now())));
          replacement.onopen = () => initialize(replacement);
          return true;
        } catch { return false; }
      };
      const bind = (target) => {
        target.onmessage = onMessage;
        target.onerror = () => {
          if (target !== socket) return;
          if (renewalConnecting) {
            rejectCandidateOpen?.(new Error("Worker tail renewal stream failed"));
            rejectCandidatePong?.(new Error("Worker tail renewal stream failed"));
          } else if (!recover()) fail("Worker tail stream failed");
        };
        target.onclose = (event) => {
          if (target !== socket) return;
          closeEvidenceFor(event);
          if (renewalConnecting) {
            rejectCandidateOpen?.(new Error("Worker tail renewal stream closed"));
            rejectCandidatePong?.(new Error("Worker tail renewal stream closed"));
            return;
          }
          if (!recover() && !receiptAccepted) fail("Worker tail stream closed before receipt");
        };
        target.on?.("pong", () => onPong(target));
      };
      bindTailSocket = bind;
      bind(socket);
    });
    // A failed schedule install can return before the receipt promise is
    // awaited. Mark its later timeout handled while preserving the awaited
    // rejection on the normal path.
    receiptPromise.catch(() => undefined);

    await opened;
    lastPongAt = now();
    const scheduleRenewal = (currentTail) => {
      clearTimeoutFn(renewalTimer);
      if (currentTail.expiresAt >= deadline) return;
      const delay = currentTail.expiresAt - TAIL_RENEW_LEAD_MS - now();
      if (delay < 1) {
        failTail("Worker tail renewal window missed");
        return;
      }
      renewalTimer = setTimeoutFn(() => {
        renewalTask = (async () => {
          if (now() >= deadline) throw new Error("runtime probe receipt timed out");
          const next = await createTail();
          if (receiptAccepted || terminalFailure || stopRequested) return;
          clearIntervalFn(heartbeatTimer);
          const oldSocket = socket;
          stage = "tail_connect";
          const replacement = socketFactory(next.url, "trace-v1");
          replacement.binaryType = "arraybuffer";
          renewalConnecting = true;
          socket = replacement;
          bindTailSocket(replacement);
          await new Promise((resolve, reject) => {
            resolveCandidateOpen = resolve;
            rejectCandidateOpen = reject;
            openTimer = setTimeoutFn(() => reject(new Error("Worker tail renewal timed out")),
              Math.min(TAIL_RENEW_OPEN_TIMEOUT_MS, Math.max(1, deadline - now())));
            replacement.onopen = () => {
              clearTimeoutFn(openTimer);
              if (replacement.protocol !== "trace-v1") return reject(new Error("Worker tail protocol rejected"));
              initializeTailSocket(replacement);
              resolveCandidateOpen = undefined;
              rejectCandidateOpen = undefined;
              resolve();
            };
          });
          resolveCandidateOpen = undefined;
          rejectCandidateOpen = undefined;
          if (receiptAccepted || terminalFailure || stopRequested) return;
          await new Promise((resolve, reject) => {
            resolveCandidatePong = resolve;
            rejectCandidatePong = reject;
            pongTimer = setTimeoutFn(() => reject(new Error("Worker tail renewal pong deadline exceeded")),
              Math.min(10_000, Math.max(1, deadline - now())));
            pendingPongAt = now();
            try { replacement.ping(); }
            catch { reject(new Error("Worker tail control ping failed")); }
          });
          resolveCandidatePong = undefined;
          rejectCandidatePong = undefined;
          if (receiptAccepted || terminalFailure || stopRequested) return;
          activeTail = next;
          armTailExpiry(next);
          renewalConnecting = false;
          try { oldSocket?.close(); } catch { /* owned tail is still deleted through the API */ }
          stage = "tail_cleanup";
          await deleteOwnedTail(currentTail);
          heartbeatTimer = setIntervalFn(heartbeatFn, 10_000);
          stage = "receipt_wait";
          scheduleRenewal(next);
        })().catch((error) => {
          renewalConnecting = false;
          failTail(error?.message === "Worker tail renewal limit exceeded"
            ? "Worker tail renewal limit exceeded" : "Worker tail renewal failed");
        });
      }, delay);
    };
    scheduleRenewal(activeTail);
    heartbeatFn = () => {
      if (pendingPongAt !== undefined && now() - pendingPongAt >= 10_000) {
        failTail("Worker tail pong deadline exceeded");
        return;
      }
      if (pongTimer !== undefined) return;
      try {
        pingCount = Math.min(1_000_000, pingCount + 1);
        pendingPongAt = now();
        pongTimer = setTimeoutFn(() => {
          failTail("Worker tail pong deadline exceeded");
        }, 10_000);
        socket.ping();
      } catch {
        socket.onerror?.(new Error("Worker tail control ping failed"));
      }
    };
    heartbeatTimer = setIntervalFn(heartbeatFn, 10_000);
    stage = "schedule_install";
    scheduleAttempted = true;
    await request("/schedules", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([{ cron: PROBE_CRON }]),
    });
    const installed = requireScheduleEnvelope(await request("/schedules"));
    if (!exactSchedules(installed, [PROBE_CRON])) {
      const error = new Error("installed schedule readback rejected");
      scheduleReadbacks.set(error, scheduleReadbackSummary(installed));
      throw error;
    }
    stage = "receipt_wait";
    receipt = await receiptPromise;
    socket.close();
  } catch (error) {
    primaryError = tagged(error);
  } finally {
    stopRequested = true;
    clearTimeoutFn(receiptTimer);
    renewalConnecting = false;
    // Wake any renewal handshake before joining its tracked task. The task
    // must settle before we snapshot tail IDs for cleanup.
    rejectCandidateOpen?.(new Error("runtime probe cleanup started"));
    rejectCandidatePong?.(new Error("runtime probe cleanup started"));
    clearTimeoutFn(renewalTimer);
    clearTimeoutFn(tailExpiryTimer);
    clearIntervalFn(heartbeatTimer);
    // Serialize final cleanup behind a tail-create/connect handoff already in flight.
    await renewalTask;
    clearTimeoutFn(openTimer);
    clearTimeoutFn(pongTimer);
    resolveCandidateOpen = undefined;
    rejectCandidateOpen = undefined;
    resolveCandidatePong = undefined;
    rejectCandidatePong = undefined;
    try { socket?.close(); } catch { /* best-effort close; tail is deleted below */ }
    if (scheduleAttempted) {
      stage = "schedule_cleanup";
      try {
        const current = requireScheduleEnvelope(await request("/schedules", {}, true));
        if (exactSchedules(current, [PROBE_CRON])) {
          await request("/schedules", { method: "PUT", headers: { "content-type": "application/json" }, body: "[]" }, true);
          const cleared = requireScheduleEnvelope(await request("/schedules", {}, true));
          if (cleared.length !== 0) throw new Error("schedule cleanup readback rejected");
        } else if (current.length !== 0) {
          throw new Error("schedule drift requires operator cleanup");
        }
      } catch (error) {
        primaryError ??= tagged(error);
      }
    }
    if (tails.length !== 0) {
      stage = "tail_cleanup";
      for (const tail of [...tails].reverse()) {
        try { await deleteOwnedTail(tail); }
        catch (error) { primaryError ??= tagged(error); }
      }
    }
  }
  signal?.removeEventListener("abort", onAbort);

  if (primaryError !== undefined) {
    if (tailCleanupReceipts.length !== 0) tailCleanupEvidence.set(primaryError, tailCleanupReceipts.slice(0, MAX_OWNED_TAILS));
    throw primaryError;
  }
  if (!exactReceipt(receipt, release, startedAt, deadline)) throw new Error("runtime probe receipt rejected");
  return {
    contract: "corelink-staging-runtime-deployment-proof-v1",
    account_id: ACCOUNT_ID,
    worker_name: WORKER_NAME,
    workflow_sha: expectedSha,
    worker_release: release,
    container_image_digest: imageDigest,
    cron: PROBE_CRON,
    probe_nonce: PROBE_WINDOW.nonce,
    window_expires_ms: PROBE_EXPIRY,
    receipt,
    schedule_restored_empty: true,
    tail_deleted: true,
    tail_cleanup_receipts: tailCleanupReceipts,
    tail_close: closeEvidence ?? { code: null, was_clean: null, reason_sha256: null },
    tail_frames: tailFrameCount,
    tail_reconnects: tailReconnects,
    control_pings: pingCount,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const abortController = new AbortController();
  const abortOnSignal = () => abortController.abort();
  process.on("SIGTERM", abortOnSignal);
  process.on("SIGINT", abortOnSignal);
  try {
    if (process.argv[2] === "capture-deploy") {
      const log = await readFile(process.argv[3], "utf8");
      const captured = captureDeployImageDigest(log);
      await appendFile(process.env.GITHUB_OUTPUT, `deployed_version_id=${captured.versionId}\nimage_digest=${captured.imageDigest}\n`);
      process.exit(0);
    }
    if (process.argv[2] === "read-container-state") {
      writeSync(1, `${await readContainerDetail()}\n`);
      process.exit(0);
    }
    if (process.argv[2] === "capture-container-preimage") {
      const text = await readFile(process.argv[3], "utf8");
      const preimage = captureContainerPreimage(text);
      await writeFile(process.argv[4], `${JSON.stringify(preimage)}\n`, { mode: 0o600 });
      await appendFile(process.env.GITHUB_OUTPUT,
        `preimage_container_id=${preimage.application_id}\n` +
        `preimage_container_version=${preimage.application_version}\n` +
        `preimage_container_image=${preimage.image}\n` +
        `preimage_container_image_digest=${preimage.image_digest}\n`);
      process.exit(0);
    }
    if (process.argv[2] === "wait-container-state") {
      const preimage = JSON.parse(await readFile(process.argv[3], "utf8"));
      const result = await waitForContainerState({
        preimage, expectedDigest: process.env.EXPECTED_CONTAINER_IMAGE_DIGEST,
        read: async (timeout) => readContainerDetail({ timeoutMs: Math.min(timeout, 30_000), requireHealthy: false }),
      });
      await writeFile(process.argv[4], result.text, { mode: 0o600 });
      process.exit(0);
    }
    if (process.argv[2] === "capture-container-state") {
      const text = await readFile(process.argv[3], "utf8");
      const state = captureContainerPreimage(text);
      const prefix = process.argv[4];
      if (!/^(candidate|verified)_$/.test(prefix)) throw new Error("Container state label rejected");
      const minimumVersion = process.env.MIN_CONTAINER_APP_VERSION === undefined
        ? undefined : Number(process.env.MIN_CONTAINER_APP_VERSION);
      if (minimumVersion !== undefined &&
          (!Number.isSafeInteger(minimumVersion) || state.application_version <= minimumVersion)) {
        throw new Error("Container application version did not advance from preimage");
      }
      await writeFile(process.argv[5], `${JSON.stringify(state)}\n`, { mode: 0o600 });
      await appendFile(process.env.GITHUB_OUTPUT,
        `${prefix}container_id=${state.application_id}\n` +
        `${prefix}container_version=${state.application_version}\n` +
        `${prefix}container_image_digest=${state.image_digest}\n`);
      process.exit(0);
    }
    if (process.argv[2] === "verify-container-preimage") {
      const text = await readFile(process.argv[3], "utf8");
      verifyContainerPreimage(text, process.env.PREIMAGE_CONTAINER_IMAGE);
      process.stdout.write("staging Container image matches captured preimage\n");
      process.exit(0);
    }
    if (process.argv[2] === "verify-container-digest") {
      const text = await readFile(process.argv[3], "utf8");
      const expectedVersion = process.env.EXPECTED_CONTAINER_APP_VERSION === undefined
        ? undefined : Number(process.env.EXPECTED_CONTAINER_APP_VERSION);
      const minimumVersion = process.env.MIN_CONTAINER_APP_VERSION === undefined
        ? undefined : Number(process.env.MIN_CONTAINER_APP_VERSION);
      if ((expectedVersion !== undefined && !Number.isSafeInteger(expectedVersion)) ||
          (minimumVersion !== undefined && !Number.isSafeInteger(minimumVersion))) {
        throw new Error("Container application version expectation rejected");
      }
      const state = verifyContainerState(text, process.env.EXPECTED_CONTAINER_IMAGE_DIGEST, {
        expectedVersion, minimumVersion,
      });
      process.stdout.write("staging Container image digest matches candidate\n");
      process.exit(0);
    }
    if (process.argv[2] === "verify-container-rollback") {
      const before = await readFile(process.argv[3], "utf8");
      const after = await readFile(process.argv[4], "utf8");
      verifyContainerRollback(before, after, process.env.PREIMAGE_CONTAINER_IMAGE);
      process.stdout.write("staging Container image and application version remain at restored preimage\n");
      process.exit(0);
    }
    const result = await runRuntimeProbe({
      token: process.env.CLOUDFLARE_API_TOKEN,
      release: process.env.SENTRY_RELEASE,
      expectedSha: process.env.EXPECTED_SHA,
      imageDigest: process.env.IMAGE_DIGEST,
      signal: abortController.signal,
    });
    // Native WebSocket.close() may leave a CLOSING handle indefinitely.
    // runRuntimeProbe has awaited cleanup; flush proof before terminating CLI.
    writeSync(1, `${JSON.stringify(result)}\n`);
    process.exit(0);
  } catch (error) {
    writeSync(2, `issue-1700 runtime probe failed ${JSON.stringify(failureDiagnostic(error))}\n`);
    process.exit(1);
  }
}
