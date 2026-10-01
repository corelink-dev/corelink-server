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

test("v8 window and full-cleanup admission boundaries are exact", () => {
  assert.deepEqual(PROBE_WINDOW, {
    cron: "*/2 * * * *",
    starts_ms: Date.parse("2026-10-01T03:30:00Z"),
    last_entry_ms: Date.parse("2026-10-01T09:30:00Z"),
    expires_ms: Date.parse("2026-10-01T10:45:00Z"),
    nonce: "issue-1700-recovery-20261001-v8",
  });
  assert.equal(isApprovedProbeWindow({ ...PROBE_WINDOW }), true);
  assert.equal(isApprovedProbeWindow({ ...PROBE_WINDOW, nonce: "issue-1700-recovery-20261001-v7" }), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms - 1), false);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.starts_ms), true);
  assert.equal(deploymentWindowAllows(PROBE_WINDOW.last_entry_ms - MIN_CLEANUP_MS - 1), true);
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
      `if (PROBE_WINDOW.nonce !== "issue-1700-recovery-20261001-v8") process.exit(2);\n` +
      `if (!deploymentWindowAllows(PROBE_WINDOW.starts_ms)) process.exit(3);\n` +
      `if (deploymentWindowAllows(PROBE_WINDOW.last_entry_ms - 75 * 60_000)) process.exit(4);\n`
    ], { cwd: temporary, encoding: "utf8", timeout: 5000 });
    assert.equal(child.status, 0, `${child.stderr}\n${child.stdout}`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
