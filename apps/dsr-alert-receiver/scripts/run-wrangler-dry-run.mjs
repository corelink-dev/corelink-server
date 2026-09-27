import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { TARGET, validateTrackedInputs } from "./deploy-route.mjs";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function containsGeneratedFile(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry.isFile()) return true;
    if (entry.isDirectory() && await containsGeneratedFile(join(directory, entry.name))) return true;
  }
  return false;
}

export function buildDryRunConfig(config, migration, projectDir) {
  validateTrackedInputs(config, migration);
  const placeholder = `database_id = "${TARGET.placeholderId}"`;
  if (config.split(placeholder).length !== 2) throw new Error("target_config_not_unique");
  const configured = config.replace(placeholder, `database_id = "${TARGET.databaseId}"`);
  return configured
    .replace('main = "src/index.ts"', `main = "${resolve(projectDir, "src/index.ts")}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(projectDir, "migrations")}"`);
}

export function buildWranglerArgs({ entrypoint, config, outdir }) {
  return [
    "exec", "wrangler", "versions", "upload", entrypoint,
    "--config", config,
    "--dry-run",
    "--outdir", outdir,
  ];
}

export function buildWranglerEnvironment({ path, home }) {
  return {
    PATH: path,
    HOME: home,
    CI: "true",
    WRANGLER_SEND_METRICS: "false",
  };
}

export async function runWranglerDryRun({
  spawn = spawnSync,
  path = process.env.PATH,
  home = process.env.HOME,
  runnerTemp = process.env.RUNNER_TEMP,
  sourceSha = process.env.GITHUB_SHA,
  baseDir = appDir,
} = {}) {
  if (!path || !home || !runnerTemp || !/^[0-9a-f]{40}$/.test(sourceSha ?? "")) {
    return { outcome: "runner_input_invalid", exit_code: null, source_sha: null };
  }

  const receipt = {
    schema_version: 1,
    outcome: "not_started",
    exit_code: null,
  };
  let runDir;

  try {
    runDir = await mkdtemp(join(runnerTemp, "b216-wrangler-dry-run-"));
    const configPath = join(runDir, "wrangler.toml");
    const outdir = join(runDir, "out");
    const config = await readFile(join(baseDir, "wrangler.toml"), "utf8");
    const migration = await readFile(join(baseDir, "migrations", TARGET.migration), "utf8");
    const dryRunConfig = buildDryRunConfig(config, migration, baseDir);
    await writeFile(configPath, dryRunConfig, { flag: "wx", mode: 0o600 });

    const result = spawn("pnpm", buildWranglerArgs({
      entrypoint: resolve(baseDir, "src/index.ts"),
      config: configPath,
      outdir,
    }), {
      cwd: baseDir,
      env: buildWranglerEnvironment({ path, home }),
      encoding: "utf8",
      stdio: "pipe",
      maxBuffer: 8 * 1024 * 1024,
    });

    if (result.error || !Number.isInteger(result.status)) {
      receipt.outcome = "wrangler_process_failed";
    } else if (result.status === 0) {
      receipt.exit_code = 0;
      receipt.outcome = await containsGeneratedFile(outdir) ? "bundle_compiled" : "bundle_output_missing";
    } else {
      receipt.outcome = "bundle_failed";
      receipt.exit_code = result.status;
    }
  } catch {
    receipt.outcome = "preparation_failed";
  } finally {
    if (runDir) await rm(runDir, { recursive: true, force: true }).catch(() => {});
  }

  return receipt;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const receipt = await runWranglerDryRun();
  process.stdout.write(`b216_wrangler_dry_run=${JSON.stringify(receipt)}\n`);
  if (receipt.outcome !== "bundle_compiled") process.exitCode = 1;
}
