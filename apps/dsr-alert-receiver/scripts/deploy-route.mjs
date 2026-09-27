import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

export const TARGET = Object.freeze({
  repository: "HuGR-dev/corelink-server",
  accountId: "51284495e71acdb5a7677e7383ab026b",
  workerName: "corelink-dsr-b216-alert-receiver-20260927",
  databaseName: "corelink-dsr-b216-alert-receipts-20260927",
  databaseBinding: "ALERT_RECEIPTS_DB",
  migration: "0001_alert_receipts.sql",
  apiTokenSecret: "B216_CF_RECEIVER_WRITE_TOKEN",
  receiverSecret: "B216_DSR_ALERT_RECEIVER_TOKEN",
  workerSecret: "DSR_ALERT_RECEIVER_TOKEN",
  placeholderId: "00000000-0000-0000-0000-000000000000",
  configSha256: "212e2779067b91d65ccb037f49cc5464325da9cb73d7ec93d929ad684380264b",
  migrationSha256: "7b9819d1f155645d84b1037e8376063e46ff117dd4d57553b66e22c2d2822bb2",
});

export class RouteError extends Error {
  constructor(code) {
    super(code);
    this.name = "RouteError";
    this.code = code;
  }
}

const fail = (code) => { throw new RouteError(code); };
const isUuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

export function validateDispatch(context) {
  if (context.repository !== TARGET.repository) fail("repository_mismatch");
  if (context.ref !== "refs/heads/main") fail("main_ref_required");
  if (typeof context.sha !== "string" || !/^[0-9a-f]{40}$/i.test(context.sha)) fail("exact_sha_required");
  if (context.checkoutSha !== context.sha) fail("checkout_sha_mismatch");
  if (!context.apiToken) fail("provider_token_missing");
  if (!context.receiverToken || context.receiverToken.length < 32 || context.receiverToken.length > 512) fail("receiver_secret_missing");
  return context.sha.toLowerCase();
}

export function validateTrackedInputs(config, migration) {
  if (createHash("sha256").update(config).digest("hex") !== TARGET.configSha256) fail("wrangler_config_drift");
  if (createHash("sha256").update(migration).digest("hex") !== TARGET.migrationSha256) fail("migration_drift");
  if (!config.includes(`account_id = "${TARGET.accountId}"`) || !config.includes(`name = "${TARGET.workerName}"`)) fail("worker_target_drift");
  if (!config.includes(`binding = "${TARGET.databaseBinding}"`) || !config.includes(`database_name = "${TARGET.databaseName}"`)) fail("database_target_drift");
  if (!config.includes(`database_id = "${TARGET.placeholderId}"`)) fail("placeholder_uuid_contract_drift");
  if (!config.includes(`migrations_dir = "migrations"`)) fail("migration_directory_drift");
  return true;
}

export function selectNamedResource(resources, expectedName, kind) {
  if (!Array.isArray(resources)) fail(`${kind}_inventory_ambiguous`);
  const matches = resources.filter((resource) => (resource?.name ?? resource?.id) === expectedName);
  if (matches.length > 1) fail(`${kind}_duplicate_name`);
  return matches[0] ?? null;
}

export function validateDatabaseIdentity(database) {
  if (!database || database.name !== TARGET.databaseName || !isUuid(database.uuid ?? database.id)) fail("database_identity_ambiguous");
  const id = database.uuid ?? database.id;
  if (id === TARGET.placeholderId) fail("placeholder_uuid_rejected");
  return id;
}

const normalizeSql = (sql) => sql.toLowerCase()
  .replace(/--[^\n]*/g, " ")
  .replace(/create\s+table\s+if\s+not\s+exists/g, "create table")
  .replace(/["`\[\]]/g, "")
  .replace(/\s+/g, " ")
  .replace(/\s*([(),=])\s*/g, "$1")
  .replace(/;$/, "")
  .trim();

export function validateReceiptSchema(rows, migration) {
  if (!Array.isArray(rows)) fail("database_schema_ambiguous");
  const userTables = rows.filter((row) => typeof row?.name === "string" && !row.name.startsWith("sqlite_"));
  const migrationTable = userTables.find((row) => row.name === "d1_migrations");
  const receiptTable = userTables.find((row) => row.name === "dsr_alert_receipts");
  if (userTables.some((row) => !["d1_migrations", "dsr_alert_receipts"].includes(row.name))) fail("database_schema_unknown");
  if (!receiptTable) {
    if (migrationTable) fail("database_migration_state_unknown");
    return "empty";
  }
  const expected = normalizeSql(migration).replace(/create table if not exists/g, "create table");
  const actual = normalizeSql(receiptTable.sql ?? "");
  const expectedBody = expected.slice(expected.indexOf("create table"));
  if (!actual || actual !== expectedBody || !migrationTable) fail("database_schema_drift");
  return "applied";
}

export function validateMigrationLedger(names) {
  if (!Array.isArray(names) || names.some((row) => typeof row?.name !== "string")) fail("database_migration_ledger_ambiguous");
  if (names.length !== 1 || names[0].name !== TARGET.migration) fail("database_migration_ledger_drift");
  return true;
}

export function selectPriorRevision(deployments) {
  if (!Array.isArray(deployments)) fail("worker_preimage_ambiguous");
  if (deployments.length === 0) return null;
  const current = deployments[0];
  const versions = current?.versions;
  if (!Array.isArray(versions) || versions.length !== 1 || versions[0]?.percentage !== 100 || !isUuid(versions[0]?.version_id)) fail("worker_preimage_ambiguous");
  return versions[0].version_id;
}

export function validateRollbackReadback(deployments, exactVersionId) {
  if (selectPriorRevision(deployments) !== exactVersionId) fail("rollback_readback_mismatch");
  return true;
}

export function validateIntakeDisabled(subdomain) {
  if (subdomain?.enabled !== false || subdomain?.previews_enabled !== false) fail("rollback_readback_mismatch");
  return true;
}

export function validateCandidateVersion(version, expectedDatabaseId, expectedTag) {
  if (!isUuid(version?.id) || version?.metadata?.annotations?.["workers/tag"] !== expectedTag) fail("worker_revision_tag_mismatch");
  const bindings = version?.resources?.bindings;
  if (bindings?.some((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === expectedDatabaseId) !== true) fail("worker_database_binding_mismatch");
  if (bindings?.some((binding) => binding?.type === "secret_text" && binding.name === TARGET.workerSecret) !== true) fail("worker_secret_readback_missing");
  return true;
}

export function validatePostflight({ versionId, deployment, bindings, secrets }, expectedDatabaseId, expectedTag) {
  if (!isUuid(versionId) || !Array.isArray(deployment?.versions) || deployment.versions.length !== 1 || deployment.versions[0]?.version_id !== versionId || deployment.versions[0]?.percentage !== 100) fail("worker_revision_readback_mismatch");
  if (bindings?.some((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === expectedDatabaseId) !== true) fail("worker_database_binding_mismatch");
  if (secrets?.some((secret) => secret?.name === TARGET.workerSecret) !== true) fail("worker_secret_readback_missing");
  if (!/^b216-[0-9a-f]{40}$/i.test(expectedTag)) fail("worker_revision_tag_invalid");
  return true;
}

const apiBase = "https://api.cloudflare.com/client/v4";

export function makeCloudflareApi(token, fetchImpl = fetch) {
  return async function request(path, { method = "GET", body } = {}) {
    let response;
    try {
      response = await fetchImpl(`${apiBase}${path}`, {
        method,
        redirect: "error",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      fail("provider_transport_ambiguous");
    }
    let payload;
    try { payload = await response.json(); } catch { fail("provider_response_ambiguous"); }
    if (!response.ok || payload?.success !== true) fail("provider_response_rejected");
    if (Array.isArray(payload.result) && payload.result_info) {
      Object.defineProperty(payload.result, "result_info", { value: payload.result_info });
    }
    return payload.result;
  };
}

function runWrangler(args, { cwd, home, apiToken, receiverToken, input } = {}) {
  const result = spawnSync("pnpm", ["exec", "wrangler", ...args], {
    cwd,
    input,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      HOME: home,
      CI: "true",
      WRANGLER_SEND_METRICS: "false",
      CLOUDFLARE_API_TOKEN: apiToken,
      CLOUDFLARE_ACCOUNT_ID: TARGET.accountId,
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) fail("provider_command_failed");
  return result.stdout;
}

function writeReceipt(path, receipt) {
  return writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
}

export async function runRoute({ context, config, migration, fetchImpl = fetch, command = runWrangler, receiptPath, worktree = process.cwd() }) {
  const sha = validateDispatch(context);
  validateTrackedInputs(config, migration);
  const api = makeCloudflareApi(context.apiToken, fetchImpl);
  const receipt = {
    schema_version: 1,
    issue: 2741,
    repository: TARGET.repository,
    reviewed_main_sha: sha,
    account_id: TARGET.accountId,
    worker_name: TARGET.workerName,
    database_name: TARGET.databaseName,
    binding: TARGET.databaseBinding,
    migration: TARGET.migration,
    migration_sha256: TARGET.migrationSha256,
    disjointness_note: "B-216 uses its dedicated exact-name resource; #2563 has no current D1 target and its future owner must provision a distinct disposable database.",
    captured_at: new Date().toISOString(),
    status: "started",
  };
  let stage = "account_readback";
  let databaseCreated = false;
  let workerMutationStarted = false;
  let priorWorkerVersion = null;
  let tempConfig = null;
  let wranglerHome = null;
  try {
    const account = await api(`/accounts/${TARGET.accountId}`);
    if (account?.id !== TARGET.accountId) fail("account_identity_mismatch");
    const [databasePage, workerPage] = await Promise.all([
      api(`/accounts/${TARGET.accountId}/d1/database?per_page=100`),
      api(`/accounts/${TARGET.accountId}/workers/scripts?per_page=100`),
    ]);
    if (databasePage?.result_info?.total_pages > 1 || workerPage?.result_info?.total_pages > 1) fail("provider_inventory_truncated");
    const priorDatabase = selectNamedResource(databasePage, TARGET.databaseName, "database");
    const priorWorker = selectNamedResource(workerPage, TARGET.workerName, "worker");
    if (priorWorker) {
      const deployments = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`);
      priorWorkerVersion = selectPriorRevision(deployments);
      if (!priorWorkerVersion) fail("worker_preimage_ambiguous");
    }
    receipt.worker_preimage = priorWorkerVersion ?? "absent";
    if (priorDatabase) {
      receipt.database_id = validateDatabaseIdentity(priorDatabase);
      stage = "database_schema_preimage";
      const tables = await queryDatabase(api, receipt.database_id, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
      receipt.database_schema_preimage = validateReceiptSchema(tables, migration);
      if (receipt.database_schema_preimage === "applied") {
        validateMigrationLedger(await queryDatabase(api, receipt.database_id, "SELECT name FROM d1_migrations ORDER BY name"));
      }
    } else {
      stage = "database_create";
      receipt.database_preimage = "absent";
      receipt.database_create_attempted = true;
      const created = await api(`/accounts/${TARGET.accountId}/d1/database`, { method: "POST", body: { name: TARGET.databaseName } });
      if (created?.name !== TARGET.databaseName || created?.account_id && created.account_id !== TARGET.accountId) fail("database_create_readback_mismatch");
      receipt.database_id = validateDatabaseIdentity(created);
      databaseCreated = true;
      const reread = await api(`/accounts/${TARGET.accountId}/d1/database?per_page=100`);
      if (reread?.result_info?.total_pages > 1) fail("provider_inventory_truncated");
      const confirmed = selectNamedResource(reread, TARGET.databaseName, "database");
      if (!confirmed || validateDatabaseIdentity(confirmed) !== receipt.database_id) fail("database_create_readback_mismatch");
    }

    const runDir = process.env.RUNNER_TEMP || tmpdir();
    const configDir = join(runDir, `b216-${randomUUID()}`);
    await mkdir(configDir, { recursive: true, mode: 0o700 });
    wranglerHome = join(configDir, "home");
    await mkdir(wranglerHome, { mode: 0o700 });
    tempConfig = join(configDir, "wrangler.toml");
    const configured = config.replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${receipt.database_id}"`);
    const appDir = resolve(worktree, "apps/dsr-alert-receiver");
    const runnableConfig = configured
      .replace('main = "src/index.ts"', `main = "${resolve(appDir, "src/index.ts")}"`)
      .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(appDir, "migrations")}"`);
    await writeFile(tempConfig, runnableConfig, { mode: 0o600, flag: "wx" });

    stage = "migration_apply";
    const beforeMigration = await queryDatabase(api, receipt.database_id, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
    const migrationState = validateReceiptSchema(beforeMigration, migration);
    if (migrationState !== "applied") {
      command(["d1", "migrations", "apply", TARGET.databaseName, "--remote", "--config", tempConfig], { cwd: appDir, home: wranglerHome, apiToken: context.apiToken });
    }
    stage = "migration_readback";
    const afterMigration = await queryDatabase(api, receipt.database_id, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
    if (validateReceiptSchema(afterMigration, migration) !== "applied") fail("migration_readback_mismatch");
    validateMigrationLedger(await queryDatabase(api, receipt.database_id, "SELECT name FROM d1_migrations ORDER BY name"));
    receipt.database_schema_postflight = "exact_migration_applied";
    receipt.database_migration_ledger = [TARGET.migration];

    stage = "worker_preimage_recheck";
    const currentWorkers = await api(`/accounts/${TARGET.accountId}/workers/scripts?per_page=100`);
    if (currentWorkers?.result_info?.total_pages > 1) fail("provider_inventory_truncated");
    const currentWorker = selectNamedResource(currentWorkers, TARGET.workerName, "worker");
    let currentWorkerVersion = null;
    if (currentWorker) {
      const currentDeployments = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`);
      currentWorkerVersion = selectPriorRevision(currentDeployments);
    }
    if (currentWorkerVersion !== priorWorkerVersion) fail("worker_preimage_changed");

    const versionTag = `b216-${sha}`;
    workerMutationStarted = true;
    stage = "worker_version_upload";
    command(["versions", "upload", resolve(appDir, "src/index.ts"), "--config", tempConfig, "--tag", `b216-source-${sha}`, "--message", `B-216 reviewed main ${sha}`], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.apiToken,
    });
    stage = "worker_secret_provision";
    workerMutationStarted = true;
    command(["versions", "secret", "put", TARGET.workerSecret, "--config", tempConfig, "--tag", versionTag, "--message", `B-216 reviewed main ${sha}`], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.apiToken,
      input: context.receiverToken,
    });
    const versionList = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions?per_page=100`);
    if (versionList?.result_info?.total_pages > 1) fail("worker_version_inventory_truncated");
    const tagged = (Array.isArray(versionList) ? versionList : []).filter((version) => version?.metadata?.annotations?.["workers/tag"] === versionTag);
    if (tagged.length !== 1 || !isUuid(tagged[0]?.id)) fail("worker_uploaded_revision_ambiguous");
    const candidateVersion = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`);
    validateCandidateVersion(candidateVersion, receipt.database_id, versionTag);

    stage = "worker_deploy";
    command(["versions", "deploy", `${tagged[0].id}@100%`, "--yes", "--config", tempConfig], { cwd: appDir, home: wranglerHome, apiToken: context.apiToken });
    stage = "worker_readback";
    const [deployments, version, secrets] = await Promise.all([
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/secrets`),
    ]);
    const activeVersion = selectPriorRevision(deployments);
    if (activeVersion !== tagged[0].id) fail("worker_revision_readback_mismatch");
    const bindings = version?.resources?.bindings ?? [];
    validatePostflight({ versionId: activeVersion, deployment: deployments[0], bindings, secrets, expectedTag: versionTag }, receipt.database_id, versionTag);
    receipt.worker_preimage = priorWorkerVersion ?? "absent";
    receipt.worker_revision = activeVersion;
    receipt.worker_binding_uuid = receipt.database_id;
    receipt.worker_secret_name_present = true;
    receipt.status = "deployed";
    receipt.completed_at = new Date().toISOString();
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  } catch (error) {
    receipt.status = "failed";
    receipt.failed_stage = stage;
    receipt.failure_code = error instanceof RouteError ? error.code : "route_failed_closed";
    if (databaseCreated) receipt.database_created = true;
    if (workerMutationStarted && tempConfig) {
      receipt.rollback_target = priorWorkerVersion ?? "absent";
      try {
        const appDir = resolve(worktree, "apps/dsr-alert-receiver");
        if (priorWorkerVersion) {
          command(["rollback", priorWorkerVersion, "--config", tempConfig, "--message", "B-216 exact preimage rollback"], { cwd: appDir, home: wranglerHome, apiToken: context.apiToken });
          const deployments = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`);
          validateRollbackReadback(deployments, priorWorkerVersion);
          receipt.rollback_status = "restored_exact_revision";
        } else {
          await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/subdomain`, {
            method: "POST",
            body: { enabled: false, previews_enabled: false },
          });
          const subdomain = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/subdomain`);
          validateIntakeDisabled(subdomain);
          receipt.rollback_status = "intake_disabled_preimage_absent";
        }
      } catch {
        receipt.rollback_status = "ambiguous_do_not_retry";
      }
    }
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    throw error instanceof RouteError ? error : new RouteError("route_failed_closed");
  }
}

async function queryDatabase(api, id, sql) {
  const results = await api(`/accounts/${TARGET.accountId}/d1/database/${id}/query`, { method: "POST", body: { sql } });
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.success !== true || !Array.isArray(results[0]?.results)) fail("database_query_ambiguous");
  return results[0].results;
}

export async function main() {
  const worktree = resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const appDir = resolve(worktree, "apps/dsr-alert-receiver");
  const config = await readFile(resolve(appDir, "wrangler.toml"), "utf8");
  const migration = await readFile(resolve(appDir, "migrations", TARGET.migration), "utf8");
  const context = {
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
    checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim(),
    apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN,
    receiverToken: process.env.B216_DSR_ALERT_RECEIVER_TOKEN,
  };
  const receiptPath = join(process.env.RUNNER_TEMP || tmpdir(), "b216-receiver-route-receipt.json");
  try {
    await runRoute({ context, config, migration, receiptPath, worktree });
  } catch (error) {
    const code = error instanceof RouteError ? error.code : "route_failed_closed";
    try {
      await readFile(receiptPath, "utf8");
    } catch {
      await writeReceipt(receiptPath, {
        schema_version: 1,
        issue: 2741,
        repository: TARGET.repository,
        reviewed_main_sha: context.sha,
        account_id: TARGET.accountId,
        worker_name: TARGET.workerName,
        database_name: TARGET.databaseName,
        binding: TARGET.databaseBinding,
        migration: TARGET.migration,
        migration_sha256: TARGET.migrationSha256,
        disjointness_note: "B-216 uses its dedicated exact-name resource; #2563 has no current D1 target and its future owner must provision a distinct disposable database.",
        captured_at: new Date().toISOString(),
        status: "failed",
        failure_code: code,
      });
    }
    process.stderr.write(`B-216 route stopped: ${code}\n`);
    process.exitCode = 1;
  }
}
