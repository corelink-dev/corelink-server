import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, copyFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { PROBE_WINDOW, deploymentWindowAllows, isApprovedProbeWindow } from "../issue_1700_probe_window.mjs";

const MIN_CLEANUP_MS = 75 * 60_000;
const workflowPath = new URL("../../.github/workflows/issue-1700-container-staging-deploy.yml", import.meta.url);
const runtimePath = new URL("../issue_1700_runtime_probe.mjs", import.meta.url);

test("v14 window and full-cleanup admission boundaries are exact", () => {
  assert.deepEqual(PROBE_WINDOW, {
    cron: "*/2 * * * *",
    starts_ms: Date.parse("2026-10-02T10:00:00Z"),
    last_entry_ms: Date.parse("2026-10-02T12:00:00Z"),
    expires_ms: Date.parse("2026-10-02T13:15:00Z"),
    nonce: "issue-1700-recovery-20261002-v14",
  });
  assert.equal(isApprovedProbeWindow({ ...PROBE_WINDOW }), true);
  for (const nonce of ["issue-1700-recovery-20261001-v7", "issue-1700-recovery-20261001-v10",
    "issue-1700-recovery-20261001-v11", "issue-1700-recovery-20261002-v12",
    "issue-1700-recovery-20261002-v13"]) {
    assert.equal(isApprovedProbeWindow({ ...PROBE_WINDOW, nonce }), false);
  }
  // The expired, never-dispatched v11 tuple, the superseded, never-dispatched
  // v12 tuple and the dispatched, failed-closed v13 tuple are never reused.
  const expiredV11 = { cron: "*/2 * * * *", starts_ms: Date.parse("2026-10-01T20:00:00Z"),
    last_entry_ms: Date.parse("2026-10-01T22:00:00Z"), expires_ms: Date.parse("2026-10-01T23:15:00Z"),
    nonce: "issue-1700-recovery-20261001-v11" };
  const supersededV12 = { cron: "*/2 * * * *", starts_ms: Date.parse("2026-10-02T15:00:00Z"),
    last_entry_ms: Date.parse("2026-10-02T17:00:00Z"), expires_ms: Date.parse("2026-10-02T18:15:00Z"),
    nonce: "issue-1700-recovery-20261002-v12" };
  const failedV13 = { cron: "*/2 * * * *", starts_ms: Date.parse("2026-10-02T07:00:00Z"),
    last_entry_ms: Date.parse("2026-10-02T09:00:00Z"), expires_ms: Date.parse("2026-10-02T10:15:00Z"),
    nonce: "issue-1700-recovery-20261002-v13" };
  for (const retired of [expiredV11, supersededV12, failedV13]) {
    assert.equal(isApprovedProbeWindow(retired), false);
    assert.equal(isApprovedProbeWindow({ ...retired, nonce: PROBE_WINDOW.nonce }), false);
    assert.equal(isApprovedProbeWindow({ ...PROBE_WINDOW, nonce: retired.nonce }), false);
    assert.equal(deploymentWindowAllows(retired.starts_ms), false);
  }
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms - 1), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms), true);
  const dispatchEnd = Date.parse("2026-10-02T10:20:00Z");
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms + 1), true);
  assert.equal(deploymentWindowAllows(dispatchEnd - 1), true);
  assert.equal(deploymentWindowAllows(dispatchEnd), false);
  assert.equal(deploymentWindowAllows(dispatchEnd + 1), false);
  assert.equal(deploymentWindowAllows(dispatchEnd, 0), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms, PROBE_WINDOW.last_entry_ms - PROBE_WINDOW.starts_ms), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.last_entry_ms - MIN_CLEANUP_MS - 1), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.last_entry_ms - MIN_CLEANUP_MS), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.last_entry_ms), false);
});

test("protected pre-install deploy guard imports only the dependency-free window module", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const guardStart = workflow.indexOf("Require a full deployment and cleanup budget inside the compiled window");
  const guardEnd = workflow.indexOf("- name: Prove hosted Docker and Cloudflare Worker access", guardStart);
  assert.notEqual(guardStart, -1);
  assert.ok(guardEnd > guardStart);
  const guard = workflow.slice(guardStart, guardEnd);
  assert.match(guard, /import \{ deploymentWindowAllows \} from "\.\/scripts\/issue_1700_probe_window\.mjs"/);
  assert.doesNotMatch(guard, /issue_1700_runtime_probe\.mjs|from ["']ws["']/);
  assert.ok(workflow.indexOf("pnpm install --frozen-lockfile --ignore-scripts") > guardEnd);
  const runtime = await readFile(runtimePath, "utf8");
  assert.match(runtime, /import \{ isApprovedProbeWindow \} from "\.\/issue_1700_probe_window\.mjs"/);
  assert.match(runtime, /return isApprovedProbeWindow\(value\)/);
});

test("pre-install window module executes from an empty node_modules directory", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "i1700-window-empty-deps-"));
  try {
    await mkdir(join(temporary, "node_modules"));
    const modulePath = new URL("../issue_1700_probe_window.mjs", import.meta.url);
    const localModule = join(temporary, "issue_1700_probe_window.mjs");
    await copyFile(modulePath, localModule);
    const child = spawnSync(process.execPath, ["--input-type=module", "-e",
      `import { PROBE_WINDOW, deploymentWindowAllows } from ${JSON.stringify(pathToFileURL(localModule).href)};\n` +
      `if (PROBE_WINDOW.nonce !== "issue-1700-recovery-20261002-v14") process.exit(2);\n` +
      `if (!deploymentWindowAllows(PROBE_WINDOW.starts_ms)) process.exit(3);\n` +
      `if (deploymentWindowAllows(PROBE_WINDOW.last_entry_ms - 75 * 60_000)) process.exit(4);\n`
    ], { cwd: temporary, encoding: "utf8", timeout: 5000 });
    assert.equal(child.status, 0, `${child.stderr}\n${child.stdout}`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});


test("all compiled admission and cleanup consumers agree on the v14 tuple", async () => {
  const source = async path => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
  const iso = ms => new Date(ms).toISOString().replace(/\.000Z$/, "Z");
  assert.deepEqual(JSON.parse(await source("crates/corelink-container/src/routes/staging_d1_probe_window.json")), PROBE_WINDOW);
  assert.deepEqual(JSON.parse(await source("worker/src/staging_d1_probe_cleanup_window.json")), {
    starts_ms: PROBE_WINDOW.starts_ms, expires_ms: PROBE_WINDOW.expires_ms,
  });
  const shell = await source("scripts/issue_1700_native_supervisor.sh");
  for (const [name, value] of [["window_start", PROBE_WINDOW.starts_ms], ["last_entry", PROBE_WINDOW.last_entry_ms], ["expiry", PROBE_WINDOW.expires_ms]]) {
    assert.ok(shell.includes(`${name}=${value}\n`), name);
  }
  for (const path of ["scripts/issue_1700_rollback_quiescence.py", "scripts/verify_i2575_readiness.py"]) {
    const text = await source(path);
    for (const value of [PROBE_WINDOW.nonce, PROBE_WINDOW.starts_ms, PROBE_WINDOW.last_entry_ms, PROBE_WINDOW.expires_ms]) assert.ok(text.includes(String(value)), `${path}: ${value}`);
    assert.doesNotMatch(text, /issue-1700-recovery-20261001-v1[01]|issue-1700-recovery-20261002-v1[23]|1790856000000|1790877600000|1790882100000|1790884800000|1790892000000|1790896500000|1790953200000|1790960400000|1790964900000|1790924400000|1790931600000|1790936100000/);
  }
  for (const path of ["scripts/issue_1700_http_probe.mjs", "scripts/issue_1700_runtime_probe.mjs"]) {
    const text = await source(path);
    assert.ok(text.includes(`Date.parse("${iso(PROBE_WINDOW.starts_ms)}")`), `${path}: start`);
    assert.ok(text.includes(`Date.parse("${iso(PROBE_WINDOW.expires_ms)}")`), `${path}: expiry`);
    assert.doesNotMatch(text, /issue-1700-recovery-20261001-v1[01]|issue-1700-recovery-20261002-v1[23]|2026-10-01T19:15:00Z|2026-10-01T20:00:00Z|2026-10-01T23:15:00Z|2026-10-02T15:00:00Z|2026-10-02T18:15:00Z|2026-10-02T07:00:00Z|2026-10-02T10:15:00Z/);
  }
  // The legacy scheduled admission stays HTTP-only for the compiled nonce.
  const durableObject = await source("worker/src/durable_object.ts");
  const httpOnly = durableObject.match(/if \((\["issue-1700-recovery-[^\]]*\])\.includes\(STAGING_D1_PROBE_WINDOW\.nonce\)\)/)?.[1];
  assert.ok(httpOnly, "durable_object.ts HTTP-only nonce list");
  assert.ok(JSON.parse(httpOnly).includes(PROBE_WINDOW.nonce), "durable_object.ts HTTP-only nonce list omits the compiled nonce");
  const native = await source("crates/corelink-container/src/routes/staging_d1_binding_probe.rs");
  const fixtureTime = Number(native.match(/const TIME: u64 = (\d+);/)?.[1]);
  assert.equal(fixtureTime, PROBE_WINDOW.starts_ms + 120_000);
  assert.equal(fixtureTime % 120_000, 0);
  assert.ok(fixtureTime <= PROBE_WINDOW.last_entry_ms);
  assert.ok(native.includes(`"corelink_staging_d1_probe_0123456789abcdef_${fixtureTime}"`));
  for (const key of ["starts_ms", "last_entry_ms", "expires_ms", "nonce"]) {
    assert.ok(native.includes(`assert_eq!(window.${key}, ${JSON.stringify(PROBE_WINDOW[key])});`));
  }
});
