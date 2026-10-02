import { describe, expect, it } from "vitest";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { TARGET } from "../scripts/deploy-route.mjs";
import {
  DRY_RUN_DATABASE_ID,
  buildDryRunConfig,
  buildWranglerArgs,
  buildWranglerEnvironment,
  runWranglerDryRun,
} from "../scripts/run-wrangler-dry-run.mjs";

describe("credentialless B-216 Wrangler dry-run", () => {
  it("replaces only the tracked placeholder with the fixed offline D1 UUID", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const projectDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
    const materialized = buildDryRunConfig(config, migration, projectDir);
    const expected = config
      .replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${DRY_RUN_DATABASE_ID}"`)
      .replace('main = "src/index.ts"', `main = "${resolve(projectDir, "src/index.ts")}"`)
      .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(projectDir, "migrations")}"`);
    expect(materialized).toBe(expected);
    expect(materialized).toContain(`account_id = "${TARGET.accountId}"`);
    expect(materialized).toContain(`name = "${TARGET.workerName}"`);
    expect(materialized).toContain(`binding = "${TARGET.databaseBinding}"`);
    expect(materialized).not.toContain(TARGET.placeholderId);
  });

  it("passes a fixed entrypoint and dry-run/outdir flags without target inputs", () => {
    expect(buildWranglerArgs({ entrypoint: "/repo/src/index.ts", config: "/repo/wrangler.toml", outdir: "/tmp/bundle" })).toEqual([
      "exec", "wrangler", "versions", "upload", "/repo/src/index.ts",
      "--config", "/repo/wrangler.toml", "--dry-run", "--outdir", "/tmp/bundle",
    ]);
  });

  it("gives Wrangler only the isolated build environment and no provider credentials", () => {
    const environment = buildWranglerEnvironment({ path: "/usr/bin", home: "/tmp/empty-home" });
    expect(environment).toEqual({
      PATH: "/usr/bin",
      HOME: "/tmp/empty-home",
      CI: "true",
      WRANGLER_SEND_METRICS: "false",
    });
    expect(Object.keys(environment)).not.toContain("CLOUDFLARE_API_TOKEN");
    expect(Object.keys(environment)).not.toContain("B216_CF_RECEIVER_WRITE_TOKEN");
  });

  it("records only the process status and never forwards Wrangler stdout or stderr", async () => {
    let invocation;
    const baseDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
    const receipt = await runWranglerDryRun({
      path: "/usr/bin",
      home: "/tmp/empty-home",
      runnerTemp: "/tmp",
      sourceSha: "a".repeat(40),
      baseDir,
      spawn: (command, args, options) => {
        const configPath = args[args.indexOf("--config") + 1];
        invocation = {
          command,
          args,
          options,
          config: readFileSync(configPath, "utf8"),
        };
        return { status: 19, stdout: "private bundle output", stderr: "private provider-like detail" };
      },
    });
    expect(invocation.command).toBe("pnpm");
    expect(invocation.args).toContain("--dry-run");
    expect(invocation.config).toContain(`database_id = "${DRY_RUN_DATABASE_ID}"`);
    expect(invocation.options.env).not.toHaveProperty("CLOUDFLARE_API_TOKEN");
    expect(invocation.options.env).not.toHaveProperty("B216_CF_RECEIVER_WRITE_TOKEN");
    expect(receipt).toMatchObject({ schema_version: 1, outcome: "bundle_failed", exit_code: 19 });
    expect(JSON.stringify(receipt)).not.toContain("private");
  });

  it("requires a generated outdir file before recording a successful bundle", async () => {
    const baseDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
    const receipt = await runWranglerDryRun({
      path: "/usr/bin",
      home: "/tmp/empty-home",
      runnerTemp: "/tmp",
      sourceSha: "b".repeat(40),
      baseDir,
      spawn: (_command, args) => {
        const outdir = args[args.indexOf("--outdir") + 1];
        mkdirSync(outdir, { recursive: true });
        writeFileSync(`${outdir}/bundle.js`, "not retained");
        return { status: 0, stdout: "private bundle output", stderr: "" };
      },
    });
    expect(receipt).toMatchObject({ schema_version: 1, outcome: "bundle_compiled", exit_code: 0 });
  });

  it("keeps the hosted invocation inside a fail-closed network namespace", async () => {
    const workflow = await readFile(new URL("../../../.github/workflows/issue-2730-dsr-alert-receiver.yml", import.meta.url), "utf8");
    const step = workflow.split("- name: Run credentialless Wrangler bundle dry-run")[1]?.split("\n      - ")[0] ?? "";
    expect(step).toContain("sudo unshare --net -- setpriv");
    expect(step).toContain("--clear-groups --");
    expect(step).toContain("env -i");
    expect(step).toContain("run-wrangler-dry-run.mjs");
    expect(step).not.toContain("secrets.");
    expect(step).not.toContain("B216_CF_RECEIVER_WRITE_TOKEN");
    expect(step).not.toContain("B216_DSR_ALERT_RECEIVER_TOKEN");
  });
});
