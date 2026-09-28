#!/usr/bin/env node
// Protected, temporary Cron-to-DO-to-Container D1 proof for issue #1700.
// Never prints Cloudflare credentials, the tail URL, or unmatched Worker logs.

import { appendFile, readFile, writeFile } from "node:fs/promises";

export const ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
export const WORKER_NAME = "corelink-staging";
export const CONTAINER_APP_ID = "a033fb81-6388-47d9-9049-0b6942778055";
export const CONTAINER_APP_NAME = "corelink-staging-corelinkserver";
export const PROBE_CRON = "* * 28 9 *";
export const PROBE_EXPIRY = Date.parse("2026-09-28T06:00:00Z");
export const RECEIPT_PREFIX = "[staging_d1_runtime_probe] receipt=";

const apiBase = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}`;
const allowedReceiptKeys = new Set([
  "contract", "outcome", "worker_release", "scheduled_time_ms", "parameterized_select",
  "failed_batch_observed", "rollback_absence_verified", "probe_table_dropped",
  "d1_binding_intercepted", "authorization_absent", "cf_api_token_absent",
]);

export function captureDeployImageDigest(text) {
  if (typeof text !== "string") throw new Error("deploy log rejected");
  const versionLines = text.split(/\r?\n/).filter((line) => line.includes("Current Version ID:"));
  const imageLines = text.split(/\r?\n/).filter((line) => /image/i.test(line) && /\bdigest:/i.test(line));
  const digestPattern = /\bdigest:\s*(sha256:[0-9a-f]{64})(?:\s|$)/;
  if (versionLines.length !== 1 || imageLines.length !== 1) throw new Error("deploy version/image result is ambiguous");
  const version = versionLines[0].match(/Current Version ID:\s*([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})(?:\s|$)/);
  const digest = imageLines[0].match(digestPattern);
  if (!version || !digest || (imageLines[0].match(/sha256:[0-9a-f]{64}/g) ?? []).length !== 1) {
    throw new Error("deploy version/image result is malformed");
  }
  return { versionId: version[1], imageDigest: digest[1] };
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

export function verifyContainerRollback(beforeText, afterText, expectedImage) {
  const before = verifyContainerPreimage(beforeText, expectedImage);
  const after = verifyContainerPreimage(afterText, expectedImage);
  if (after.application_version !== before.application_version) {
    throw new Error("Container application changed after Worker rollback");
  }
  return after;
}

function exactReceipt(receipt, release) {
  return receipt !== null && typeof receipt === "object" && !Array.isArray(receipt) &&
    Object.keys(receipt).length === allowedReceiptKeys.size &&
    Object.keys(receipt).every((key) => allowedReceiptKeys.has(key)) &&
    receipt.contract === "corelink-staging-d1-binding-runtime-v1" &&
    receipt.outcome === "pass" && receipt.worker_release === release &&
    Number.isSafeInteger(receipt.scheduled_time_ms) &&
    receipt.scheduled_time_ms >= Date.parse("2026-09-28T00:00:00Z") &&
    receipt.scheduled_time_ms < PROBE_EXPIRY &&
    ["parameterized_select", "failed_batch_observed", "rollback_absence_verified",
      "probe_table_dropped", "d1_binding_intercepted", "authorization_absent",
      "cf_api_token_absent"].every((key) => receipt[key] === true);
}

function extractReceipt(event, release) {
  const logs = Array.isArray(event?.logs) ? event.logs : [];
  for (const entry of logs) {
    const messages = Array.isArray(entry?.message) ? entry.message : [entry?.message];
    for (const message of messages) {
      if (typeof message !== "string" || !message.startsWith(RECEIPT_PREFIX)) continue;
      try {
        const receipt = JSON.parse(message.slice(RECEIPT_PREFIX.length));
        if (exactReceipt(receipt, release)) return receipt;
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

export async function runRuntimeProbe({
  token,
  release,
  expectedSha,
  imageDigest,
  api = fetch,
  socketFactory = (url) => new WebSocket(url),
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = 16 * 60_000,
}) {
  if (typeof token !== "string" || token.length < 1 || !/^[0-9a-f]{40}$/.test(release ?? "") ||
      release !== expectedSha || !/^sha256:[0-9a-f]{64}$/.test(imageDigest ?? "") ||
      now() < Date.parse("2026-09-28T00:00:00Z") ||
      now() + timeoutMs >= PROBE_EXPIRY) {
    throw new Error("runtime probe preflight rejected");
  }

  async function request(path, init = {}) {
    const response = await api(`${apiBase}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
    });
    let body;
    try { body = await response.json(); } catch { throw new Error("Cloudflare API response rejected"); }
    if (!response.ok || body?.success !== true) throw new Error("Cloudflare API operation failed");
    return body;
  }

  const before = requireScheduleEnvelope(await request("/schedules"));
  if (before.length !== 0) throw new Error("preexisting Worker schedules block probe");

  let tailId;
  let socket;
  let scheduleAttempted = false;
  let receipt;
  let primaryError;
  try {
    const tail = (await request("/tails", { method: "POST" })).result;
    if (typeof tail?.id !== "string" || !/^[a-f0-9]{32}$/.test(tail.id) ||
        typeof tail?.url !== "string" || !/^wss:\/\//.test(tail.url) ||
        !Number.isFinite(Date.parse(tail.expires_at)) || Date.parse(tail.expires_at) <= now()) {
      throw new Error("tail preflight rejected");
    }
    tailId = tail.id;

    socket = socketFactory(tail.url);
    const deadline = Math.min(now() + timeoutMs, PROBE_EXPIRY);
    const receiptPromise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("runtime probe receipt timed out")), Math.max(0, deadline - now()));
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(String(message.data));
          const found = extractReceipt(event, release);
          if (found !== undefined) {
            clearTimeout(timer);
            resolve(found);
          }
        } catch {
          // Ignore malformed tail frames without logging their contents.
        }
      };
      socket.onerror = () => {
        clearTimeout(timer);
        reject(new Error("Worker tail stream failed"));
      };
      socket.onclose = () => {
        clearTimeout(timer);
        reject(new Error("Worker tail stream closed before receipt"));
      };
    });
    // A failed schedule install can return before the receipt promise is
    // awaited. Mark its later timeout handled while preserving the awaited
    // rejection on the normal path.
    receiptPromise.catch(() => undefined);

    scheduleAttempted = true;
    await request("/schedules", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([{ cron: PROBE_CRON }]),
    });
    const installed = requireScheduleEnvelope(await request("/schedules"));
    if (!exactSchedules(installed, [PROBE_CRON])) throw new Error("installed schedule readback rejected");
    receipt = await receiptPromise;
    socket.close();
  } catch (error) {
    primaryError = error;
  } finally {
    try { socket?.close(); } catch { /* best-effort close; tail is deleted below */ }
    if (scheduleAttempted) {
      try {
        const current = requireScheduleEnvelope(await request("/schedules"));
        if (exactSchedules(current, [PROBE_CRON])) {
          await request("/schedules", { method: "PUT", headers: { "content-type": "application/json" }, body: "[]" });
          const cleared = requireScheduleEnvelope(await request("/schedules"));
          if (cleared.length !== 0) throw new Error("schedule cleanup readback rejected");
        } else if (current.length !== 0) {
          throw new Error("schedule drift requires operator cleanup");
        }
      } catch (error) {
        primaryError ??= error;
      }
    }
    if (tailId !== undefined) {
      try { await request(`/tails/${tailId}`, { method: "DELETE" }); }
      catch (error) { primaryError ??= error; }
    }
  }

  if (primaryError !== undefined) throw new Error(primaryError instanceof Error ? primaryError.message : "runtime probe failed");
  if (!exactReceipt(receipt, release)) throw new Error("runtime probe receipt rejected");
  return {
    contract: "corelink-staging-runtime-deployment-proof-v1",
    account_id: ACCOUNT_ID,
    worker_name: WORKER_NAME,
    workflow_sha: expectedSha,
    worker_release: release,
    container_image_digest: imageDigest,
    cron: PROBE_CRON,
    receipt,
    schedule_restored_empty: true,
    tail_deleted: true,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    if (process.argv[2] === "capture-deploy") {
      const log = await readFile(process.argv[3], "utf8");
      const captured = captureDeployImageDigest(log);
      await appendFile(process.env.GITHUB_OUTPUT, `deployed_version_id=${captured.versionId}\nimage_digest=${captured.imageDigest}\n`);
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
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write("issue-1700 runtime probe failed; inspect the protected job step status\n");
    process.exitCode = 1;
  }
}
