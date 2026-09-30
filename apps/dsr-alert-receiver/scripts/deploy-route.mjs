import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { ReadbackError, readWorkerInventory } from "./readback-route.mjs";

export const TARGET = Object.freeze({
  repository: "HuGR-dev/corelink-server",
  accountId: "51284495e71acdb5a7677e7383ab026b",
  workerName: "corelink-dsr-b216-alert-receiver-20260927",
  databaseName: "corelink-dsr-b216-alert-receipts-20260927",
  databaseId: "dce5e90a-2c3d-43d2-8037-a6d15d74e1cb",
  databaseBinding: "ALERT_RECEIPTS_DB",
  migration: "0001_alert_receipts.sql",
  apiTokenSecret: "B216_CF_RECEIVER_WRITE_TOKEN",
  bootstrapTokenSecret: "B216_CF_RECEIVER_BOOTSTRAP_TOKEN",
  receiverSecret: "B216_DSR_ALERT_RECEIVER_TOKEN",
  workerSecret: "DSR_ALERT_RECEIVER_TOKEN",
  placeholderId: "00000000-0000-0000-0000-000000000000",
  configSha256: "212e2779067b91d65ccb037f49cc5464325da9cb73d7ec93d929ad684380264b",
  migrationSha256: "7b9819d1f155645d84b1037e8376063e46ff117dd4d57553b66e22c2d2822bb2",
});

export class RouteError extends Error {
  constructor(code, providerFailure = null) {
    super(code);
    this.name = "RouteError";
    this.code = code;
    this.providerFailure = providerFailure && sanitizeProviderFailure(providerFailure);
  }
}

const fail = (code) => { throw new RouteError(code); };
const isUuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const D1_PAGE_SIZE = 100;
const BOOTSTRAP_ALLOWED_WORKERS = new Set(["corelink-i2568-sla-credit-test-20260928"]);

const PROVIDER_FAILURE_CLASSES = new Set([
  "provider_error_code",
  "ambiguous_provider_error_code",
  "process_exit",
  "spawn_failure",
]);

function boundedExitCode(value) {
  return Number.isInteger(value) && value >= 0 && value <= 255 ? value : null;
}

function sanitizeProviderFailure(value) {
  const failureClass = PROVIDER_FAILURE_CLASSES.has(value?.provider_failure_class)
    ? value.provider_failure_class
    : "spawn_failure";
  const providerCode = failureClass === "provider_error_code"
    && Number.isInteger(value?.provider_error_code)
    && value.provider_error_code >= 0
    && value.provider_error_code <= 999999
    ? value.provider_error_code
    : null;
  return Object.freeze({
    provider_failure_class: failureClass,
    provider_error_code: providerCode,
    process_exit_code: boundedExitCode(value?.process_exit_code),
  });
}

export function classifyWranglerFailure(result) {
  const processExitCode = boundedExitCode(result?.status);
  if (result?.error) {
    return sanitizeProviderFailure({ provider_failure_class: "spawn_failure", process_exit_code: processExitCode });
  }
  const output = [result?.stdout, result?.stderr].filter((part) => typeof part === "string").join("\n");
  const markerPattern = /\[code:\s*([^\]\r\n]*)\]/gi;
  const markers = [...output.matchAll(markerPattern)];
  const markerPrefixes = [...output.matchAll(/\[code:/gi)];
  if (markers.length === 1 && markerPrefixes.length === 1 && /^\d{1,6}$/.test(markers[0][1])) {
    return sanitizeProviderFailure({
      provider_failure_class: "provider_error_code",
      provider_error_code: Number(markers[0][1]),
      process_exit_code: processExitCode,
    });
  }
  if (markerPrefixes.length > 0) {
    return sanitizeProviderFailure({
      provider_failure_class: "ambiguous_provider_error_code",
      process_exit_code: processExitCode,
    });
  }
  return sanitizeProviderFailure({ provider_failure_class: "process_exit", process_exit_code: processExitCode });
}

export function validateDispatch(context) {
  if (context.repository !== TARGET.repository) fail("repository_mismatch");
  if (context.ref !== "refs/heads/main") fail("main_ref_required");
  if (typeof context.sha !== "string" || !/^[0-9a-f]{40}$/i.test(context.sha)) fail("exact_sha_required");
  if (context.checkoutSha !== context.sha) fail("checkout_sha_mismatch");
  if (!context.apiToken) fail("provider_token_missing");
  if (!context.receiverToken || context.receiverToken.length < 32 || context.receiverToken.length > 512) fail("receiver_secret_missing");
  return context.sha.toLowerCase();
}

export function validateBootstrapDispatch(context) {
  if (context.repository !== TARGET.repository) fail("repository_mismatch");
  if (context.ref !== "refs/heads/main") fail("main_ref_required");
  if (typeof context.sha !== "string" || !/^[0-9a-f]{40}$/i.test(context.sha)) fail("exact_sha_required");
  if (context.checkoutSha !== context.sha) fail("checkout_sha_mismatch");
  if (!/^\d{1,20}$/.test(context.runId ?? "") || !/^\d{1,6}$/.test(context.runAttempt ?? "")) fail("workflow_run_identity_required");
  if (context.apiToken !== undefined || context.receiverToken !== undefined) fail("bootstrap_context_credential_mismatch");
  if (!context.bootstrapToken) fail("bootstrap_token_missing");
  return context.sha.toLowerCase();
}

export function validateBootstrapPreexistingWorkerNames(names) {
  if (!Array.isArray(names) || names.length > BOOTSTRAP_ALLOWED_WORKERS.size
    || names.some((name) => typeof name !== "string" || !BOOTSTRAP_ALLOWED_WORKERS.has(name))
    || new Set(names).size !== names.length
    || JSON.stringify(names) !== JSON.stringify([...names].sort())) fail("worker_inventory_unexpected_name");
  return names;
}

export function validateBootstrapFinalizeDispatch(context) {
  if (context.bootstrapToken !== undefined) fail("bootstrap_token_forbidden_in_finalize");
  const sha = validateDispatch(context);
  if (!context.bootstrapReceipt || typeof context.bootstrapReceipt !== "object") fail("bootstrap_handoff_missing");
  const handoff = context.bootstrapReceipt;
  validateBootstrapPreexistingWorkerNames(handoff.preexisting_worker_names);
  if (!Number.isInteger(handoff.worker_inventory_count_preimage)
    || handoff.worker_inventory_count_preimage !== handoff.preexisting_worker_names.length
    || !Number.isInteger(handoff.worker_inventory_count_postflight)
    || handoff.worker_inventory_count_postflight !== handoff.worker_inventory_count_preimage + 1) fail("bootstrap_handoff_mismatch");
  if (handoff.schema_version !== 1 || handoff.status !== "private_version_uploaded"
    || handoff.repository !== TARGET.repository || handoff.reviewed_main_sha !== sha
    || handoff.account_id !== TARGET.accountId || handoff.worker_name !== TARGET.workerName
    || handoff.database_name !== TARGET.databaseName || handoff.database_id !== TARGET.databaseId
    || handoff.binding !== TARGET.databaseBinding || handoff.migration !== TARGET.migration
    || handoff.migration_sha256 !== TARGET.migrationSha256
    || !/^\d{1,20}$/.test(context.runId ?? "") || !/^\d{1,6}$/.test(context.runAttempt ?? "")
    || handoff.run_id !== context.runId || handoff.run_attempt !== context.runAttempt
    || handoff.workers_dev !== false || handoff.secret_provisioned !== false
    || handoff.custom_routes_status !== "unknown" && handoff.custom_routes_status !== "absent"
    || !isUuid(handoff.worker_revision)
    || handoff.worker_revision_tag !== `b216-source-${sha}`
    || handoff.deployments_postflight !== "absent"
    || !["absent", "disabled"].includes(handoff.subdomain_postflight)) fail("bootstrap_handoff_mismatch");
  return sha;
}

export function preparePrivateBootstrapConfig(config, migration, databaseId, appDir) {
  validateTrackedInputs(config, migration);
  if (databaseId !== TARGET.databaseId) fail("database_identity_mismatch");
  const workersDevSettings = [...config.matchAll(/^workers_dev\s*=\s*(true|false)\s*$/gm)];
  if (workersDevSettings.length !== 1 || workersDevSettings[0][1] !== "true") fail("bootstrap_config_drift");
  if (/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(config)) fail("bootstrap_route_config_forbidden");
  const privateConfig = config
    .replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${databaseId}"`)
    .replace(/^workers_dev\s*=\s*true\s*$/m, "workers_dev = false")
    .replace('main = "src/index.ts"', `main = "${resolve(appDir, "src/index.ts")}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(appDir, "migrations")}"`);
  if (!privateConfig.includes('workers_dev = false') || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(privateConfig)) fail("bootstrap_config_drift");
  return privateConfig;
}

export function prepareWorkersDevBootstrapConfig(config, migration, databaseId, appDir) {
  validateTrackedInputs(config, migration);
  if (databaseId !== TARGET.databaseId) fail("database_identity_mismatch");
  const workersDevSettings = [...config.matchAll(/^workers_dev\s*=\s*(true|false)\s*$/gm)];
  if (workersDevSettings.length !== 1 || workersDevSettings[0][1] !== "true") fail("bootstrap_config_drift");
  if (/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(config)) fail("bootstrap_route_config_forbidden");
  const publicConfig = config
    .replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${databaseId}"`)
    .replace('main = "src/index.ts"', `main = "${resolve(appDir, "src/index.ts")}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(appDir, "migrations")}"`);
  if (!publicConfig.includes('workers_dev = true') || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(publicConfig)) fail("bootstrap_config_drift");
  return publicConfig;
}

export function validateBootstrapWorkerScriptInventory(rows, { allowTarget = false } = {}) {
  if (!Array.isArray(rows)) fail("worker_inventory_ambiguous");
  const info = rows.result_info;
  if (info !== undefined) {
    if (!info || typeof info !== "object" || Array.isArray(info)) fail("worker_inventory_ambiguous");
    if (info.count !== undefined && (!Number.isInteger(info.count) || info.count !== rows.length)) fail("worker_inventory_ambiguous");
    if (info.total_count !== undefined && (!Number.isInteger(info.total_count) || info.total_count !== rows.length)) fail("worker_inventory_truncated");
    if (info.page !== undefined && info.page !== 1) fail("worker_inventory_truncated");
    if (info.total_pages !== undefined && info.total_pages !== 1) fail("worker_inventory_truncated");
    if (info.per_page !== undefined && (!Number.isInteger(info.per_page) || info.per_page < rows.length)) fail("worker_inventory_ambiguous");
  }
  const completeRows = rows;
  const names = [];
  const seen = new Set();
  for (const row of completeRows) {
    if (!row || typeof row.id !== "string" || row.id.length === 0) fail("worker_inventory_ambiguous");
    if (seen.has(row.id)) fail("worker_duplicate_name");
    seen.add(row.id);
    if (row.id === TARGET.workerName) {
      if (!allowTarget) fail("worker_bootstrap_target_not_absent");
    } else if (!BOOTSTRAP_ALLOWED_WORKERS.has(row.id)) {
      fail("worker_inventory_unexpected_name");
    } else {
      names.push(row.id);
    }
  }
  return { count: completeRows.length, preexisting_worker_names: names.sort(), target_exists: seen.has(TARGET.workerName) };
}

export function validateBootstrapWorkerPreimage(inventory, scriptRows) {
  const scriptInventory = validateBootstrapWorkerScriptInventory(scriptRows);
  if (!inventory || inventory.status !== "complete") fail("worker_inventory_ambiguous");
  if (inventory.worker?.exists === true) fail("worker_bootstrap_target_not_absent");
  if (inventory.worker?.exists !== false || !Number.isInteger(inventory.worker?.inventory_count) || inventory.worker.inventory_count < 0) fail("worker_inventory_ambiguous");
  if (inventory.worker.inventory_count !== scriptInventory.count
    || inventory.worker.exists !== scriptInventory.target_exists
    || inventory.versions?.status !== "absent"
    || inventory.deployments?.status !== "absent"
    || inventory.subdomain?.status !== "absent"
    || inventory.inventory_consistency !== "worker_absent") fail("worker_bootstrap_target_not_absent");
  if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
  if (!new Set(["known", "unknown"]).has(inventory.routes?.status)) fail("worker_routes_ambiguous");
  return {
    worker: "absent",
    routes: inventory.routes.status === "known" ? "absent" : "unknown",
    worker_inventory_count: scriptInventory.count,
    preexisting_worker_names: scriptInventory.preexisting_worker_names,
  };
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
  if (!database || database.name !== TARGET.databaseName) fail("database_identity_ambiguous");
  if (database.account_id !== undefined && database.account_id !== TARGET.accountId) fail("database_account_mismatch");
  const id = database.uuid ?? database.id;
  if (id === TARGET.placeholderId) fail("placeholder_uuid_rejected");
  if (!isUuid(id)) fail("database_identity_ambiguous");
  if (id !== TARGET.databaseId) fail("database_identity_mismatch");
  return id;
}

const normalizeSql = (sql) => sql.toLowerCase()
  .replace(/--[^\n]*/g, " ")
  .replace(/create\s+table\s+if\s+not\s+exists/g, "create table")
  .replace(/["`\[\]]/g, "")
  .replace(/\s+/g, " ")
  .replace(/\s*([(),=])\s*/g, "$1")
  .trim()
  .replace(/;$/, "");

export function validateReceiptSchema(rows, migration) {
  if (!Array.isArray(rows)) fail("database_schema_ambiguous");
  // Cloudflare D1 exposes this reserved internal table in sqlite_master; do not
  // generalize the exclusion to other provider-looking names.
  const userTables = rows.filter((row) => typeof row?.name === "string" && !row.name.startsWith("sqlite_") && row.name !== "_cf_KV");
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

export function normalizeDeploymentList(response) {
  if (!response || typeof response !== "object" || Array.isArray(response) || !Array.isArray(response.deployments)) fail("worker_preimage_ambiguous");
  return response.deployments;
}

export function normalizeVersionList(response) {
  if (!response || typeof response !== "object" || Array.isArray(response) || !Array.isArray(response.items)) fail("worker_version_inventory_ambiguous");
  return response.items;
}

export function validateRollbackReadback(deployments, exactVersionId) {
  if (selectPriorRevision(normalizeDeploymentList(deployments)) !== exactVersionId) fail("rollback_readback_mismatch");
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

export function validateInventoryPage(rows, kind, { requireTotalCount = false } = {}) {
  if (!Array.isArray(rows)) fail(`${kind}_inventory_ambiguous`);
  const info = rows.result_info;
  if (!info) {
    if (requireTotalCount) fail(`${kind}_inventory_ambiguous`);
    return rows;
  }
  if (info.page !== undefined && info.page !== 1) fail(`${kind}_inventory_truncated`);
  if (info.count !== undefined && info.count !== rows.length) fail(`${kind}_inventory_ambiguous`);
  if (info.total_count !== undefined && (!Number.isInteger(info.total_count) || info.total_count > rows.length)) fail(`${kind}_inventory_truncated`);
  if (requireTotalCount && (!Number.isInteger(info.total_count) || info.total_count !== rows.length || info.count !== rows.length)) fail(`${kind}_inventory_ambiguous`);
  if (info.total_pages !== undefined && info.total_pages !== 1) fail(`${kind}_inventory_truncated`);
  return rows;
}

export function validateD1InventoryPage(rows, { page, perPage }) {
  if (!Array.isArray(rows) || rows.length > perPage) fail("database_inventory_ambiguous");
  const info = rows.result_info;
  if (info === undefined) return { rows, count: undefined };
  if (!info || typeof info !== "object" || Array.isArray(info)) fail("database_inventory_ambiguous");
  if (info.page !== undefined && (!Number.isInteger(info.page) || info.page !== page)) fail("database_inventory_truncated");
  if (info.per_page !== undefined && (!Number.isInteger(info.per_page) || info.per_page !== perPage)) fail("database_inventory_ambiguous");
  if (info.count !== undefined && (!Number.isInteger(info.count) || info.count < rows.length)) fail("database_inventory_ambiguous");
  if (info.total_count !== undefined && (!Number.isInteger(info.total_count) || info.total_count < 0)) fail("database_inventory_ambiguous");
  if (info.count !== undefined && info.total_count !== undefined && info.total_count < info.count) fail("database_inventory_ambiguous");
  return { rows, count: info.count };
}

export async function listNamedD1Databases(api) {
  const resources = [];
  let maxReportedCount = 0;
  for (let page = 1; page <= 100; page += 1) {
    const query = new URLSearchParams({ name: TARGET.databaseName, page: String(page), per_page: String(D1_PAGE_SIZE) });
    const pageRows = await api(`/accounts/${TARGET.accountId}/d1/database?${query}`);
    const validated = validateD1InventoryPage(pageRows, { page, perPage: D1_PAGE_SIZE });
    if (validated.count !== undefined) maxReportedCount = Math.max(maxReportedCount, validated.count);
    resources.push(...validated.rows);
    if (validated.rows.length < D1_PAGE_SIZE) {
      if (maxReportedCount > resources.length) fail("database_inventory_truncated");
      return resources;
    }
  }
  fail("database_inventory_truncated");
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
  if (result.error || result.status !== 0) {
    throw new RouteError("provider_command_failed", classifyWranglerFailure(result));
  }
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
    disjointness_note: "B-216 adopts its dedicated exact-name and UUID target; #2563 uses a separate distinct D1 resource.",
    captured_at: new Date().toISOString(),
    status: "started",
  };
  let stage = "account_readback";
  let workerMutationStarted = false;
  let priorWorkerVersion = null;
  let tempConfig = null;
  let wranglerHome = null;
  try {
    const account = await api(`/accounts/${TARGET.accountId}`);
    if (account?.id !== TARGET.accountId) fail("account_identity_mismatch");
    const [databaseRows, workerPage] = await Promise.all([
      listNamedD1Databases(api),
      api(`/accounts/${TARGET.accountId}/workers/scripts`),
    ]);
    validateInventoryPage(workerPage, "worker");
    const priorDatabase = selectNamedResource(databaseRows, TARGET.databaseName, "database");
    const priorWorker = selectNamedResource(workerPage, TARGET.workerName, "worker");
    if (priorWorker) {
      const deployments = normalizeDeploymentList(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`));
      priorWorkerVersion = selectPriorRevision(deployments);
      if (!priorWorkerVersion) fail("worker_preimage_ambiguous");
    }
    receipt.worker_preimage = priorWorkerVersion ?? "absent";
    if (priorDatabase) {
      receipt.database_id = validateDatabaseIdentity(priorDatabase);
      receipt.database_preimage = "existing_exact_target";
      stage = "database_schema_preimage";
      const tables = await queryDatabase(api, receipt.database_id, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
      receipt.database_schema_preimage = validateReceiptSchema(tables, migration);
      if (receipt.database_schema_preimage === "applied") {
        validateMigrationLedger(await queryDatabase(api, receipt.database_id, "SELECT name FROM d1_migrations ORDER BY name"));
      }
    } else {
      receipt.database_preimage = "absent";
      fail("database_target_missing");
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
    const currentWorkers = await api(`/accounts/${TARGET.accountId}/workers/scripts`);
    validateInventoryPage(currentWorkers, "worker");
    const currentWorker = selectNamedResource(currentWorkers, TARGET.workerName, "worker");
    let currentWorkerVersion = null;
    if (currentWorker) {
      const currentDeployments = normalizeDeploymentList(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`));
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
    const versionList = normalizeVersionList(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions?per_page=100&deployable=true`));
    const tagged = versionList.filter((version) => version?.metadata?.annotations?.["workers/tag"] === versionTag);
    if (tagged.length !== 1 || !isUuid(tagged[0]?.id)) fail("worker_uploaded_revision_ambiguous");
    const candidateVersion = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`);
    validateCandidateVersion(candidateVersion, receipt.database_id, versionTag);

    stage = "worker_deploy";
    command(["versions", "deploy", `${tagged[0].id}@100%`, "--yes", "--config", tempConfig], { cwd: appDir, home: wranglerHome, apiToken: context.apiToken });
    stage = "worker_readback";
    const [deploymentResponse, version, secrets] = await Promise.all([
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/secrets`),
    ]);
    const deployments = normalizeDeploymentList(deploymentResponse);
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
    if (stage === "worker_version_upload" && error instanceof RouteError && error.providerFailure) {
      Object.assign(receipt, error.providerFailure);
    }
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

async function readBootstrapDatabase(api, migration) {
  const databases = await listNamedD1Databases(api);
  const target = selectNamedResource(databases, TARGET.databaseName, "database");
  const databaseId = validateDatabaseIdentity(target);
  const schema = await queryBootstrapDatabase(api, databaseId, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
  if (validateReceiptSchema(schema, migration) !== "applied") fail("database_schema_not_applied");
  validateMigrationLedger(await queryBootstrapDatabase(api, databaseId, "SELECT name FROM d1_migrations ORDER BY name"));
  return databaseId;
}

async function assertPrivateWorkerState(inventory) {
  if (inventory.worker?.exists !== true || inventory.worker.inventory_count < 1) fail("worker_bootstrap_handoff_mismatch");
  if (inventory.versions?.status !== "known" || !Array.isArray(inventory.versions.items)) fail("worker_versions_ambiguous");
  if (inventory.deployments?.status !== "absent"
    && !(inventory.deployments?.status === "known" && inventory.deployments.count === 0)) fail("worker_bootstrap_handoff_mismatch");
  if (!["absent", "known"].includes(inventory.subdomain?.status)) fail("worker_subdomain_ambiguous");
  if (inventory.subdomain.status === "known") validateIntakeDisabled(inventory.subdomain);
  if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
  if (!new Set(["known", "unknown"]).has(inventory.routes?.status)) fail("worker_routes_ambiguous");
  return true;
}

export function validateBootstrapFinalizeInventory(inventory, handoff) {
  if (!inventory || inventory.status !== "complete" || !handoff) fail("worker_bootstrap_handoff_mismatch");
  const subdomainPrivate = inventory.subdomain?.status === "absent"
    || inventory.subdomain?.status === "known" && inventory.subdomain.enabled === false && inventory.subdomain.previews_enabled === false;
  const routesPrivate = inventory.routes?.status === "unknown"
    || inventory.routes?.status === "known" && inventory.routes.count === 0;
  if (inventory.worker?.exists !== true || inventory.worker.inventory_count < 1
    || inventory.versions?.status !== "known" || inventory.versions.count !== 1
    || !Array.isArray(inventory.versions.items) || inventory.versions.items.length !== 1
    || inventory.versions.items[0]?.id !== handoff.worker_revision
    || inventory.versions.items[0]?.tag !== handoff.worker_revision_tag
    || inventory.deployments?.status !== "absent" && !(inventory.deployments?.status === "known" && inventory.deployments.count === 0)
    || !subdomainPrivate || !routesPrivate) fail("worker_bootstrap_handoff_mismatch");
  return true;
}

export function validateBootstrapDeployedInventory(inventory, versionId) {
  if (inventory?.worker?.exists !== true || inventory.deployments?.status !== "known"
    || !inventory.deployments.active || !Array.isArray(inventory.deployments.active.versions)) fail("worker_revision_readback_mismatch");
  const deploymentList = normalizeDeploymentList({ deployments: [inventory.deployments.active] });
  if (selectPriorRevision(deploymentList) !== versionId) fail("worker_revision_readback_mismatch");
  if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
  if (inventory.subdomain?.status !== "known" || inventory.subdomain.enabled !== true || inventory.subdomain.previews_enabled !== false) fail("worker_subdomain_readback_mismatch");
  return true;
}

export function validateWorkersDevEnabled(subdomain) {
  if (!subdomain || subdomain.enabled !== true || subdomain.previews_enabled !== false) fail("worker_subdomain_readback_mismatch");
  return true;
}

async function readWorkerWithToken(context, api, apiToken, fetchImpl, { allowTarget = false } = {}) {
  let inventory;
  try {
    inventory = await readWorkerInventory({
      context: {
        repository: context.repository,
        ref: context.ref,
        sha: context.sha,
        checkoutSha: context.checkoutSha,
        readbackOnly: "true",
        apiToken,
      },
      fetchImpl,
    });
  } catch (error) {
    fail(error instanceof ReadbackError ? error.code : "worker_inventory_ambiguous");
  }
  const scriptRows = await api(`/accounts/${TARGET.accountId}/workers/scripts`);
  const scriptSummary = validateBootstrapWorkerScriptInventory(scriptRows, { allowTarget });
  if (inventory.worker?.exists !== scriptSummary.target_exists
    || inventory.worker?.inventory_count !== scriptSummary.count) fail("worker_inventory_changed");
  const preimageSummary = allowTarget ? null : validateBootstrapWorkerPreimage(inventory, scriptRows);
  return { inventory, scriptSummary, preimageSummary };
}

export async function runBootstrapUpload({ context, config, migration, fetchImpl = fetch, command = runWrangler, receiptPath, worktree = process.cwd() }) {
  const sha = validateBootstrapDispatch(context);
  validateTrackedInputs(config, migration);
  const api = makeCloudflareApi(context.bootstrapToken, fetchImpl);
  const receipt = {
    schema_version: 1,
    issue: 1678,
    mode: "bootstrap_upload",
    run_id: context.runId,
    run_attempt: context.runAttempt,
    repository: TARGET.repository,
    reviewed_main_sha: sha,
    account_id: TARGET.accountId,
    worker_name: TARGET.workerName,
    database_name: TARGET.databaseName,
    database_id: TARGET.databaseId,
    binding: TARGET.databaseBinding,
    migration: TARGET.migration,
    migration_sha256: TARGET.migrationSha256,
    workers_dev: false,
    notifier: "not_configured",
    custom_routes_status: "unknown",
    captured_at: new Date().toISOString(),
    status: "started",
  };
  let workerMutationStarted = false;
  let tempDir = null;
  let tempConfig = null;
  let wranglerHome = null;
  let stage = "account_readback";
  try {
    const account = await api(`/accounts/${TARGET.accountId}`);
    if (account?.id !== TARGET.accountId) fail("account_identity_mismatch");

    stage = "worker_preimage";
    const firstWorkerRead = await readWorkerWithToken(context, api, context.bootstrapToken, fetchImpl);
    const firstWorkerSummary = firstWorkerRead.preimageSummary;
    Object.assign(receipt, {
      worker_preimage: "absent",
      custom_routes_status: firstWorkerSummary.routes,
      worker_inventory_count_preimage: firstWorkerSummary.worker_inventory_count,
      preexisting_worker_names: firstWorkerSummary.preexisting_worker_names,
      versions_preimage: firstWorkerRead.inventory.versions.status,
      deployments_preimage: firstWorkerRead.inventory.deployments.status,
      subdomain_preimage: firstWorkerRead.inventory.subdomain.status,
    });

    stage = "database_schema_preimage";
    const databaseId = await readBootstrapDatabase(api, migration);
    if (databaseId !== TARGET.databaseId) fail("database_identity_mismatch");
    receipt.database_preimage = "existing_exact_target";
    receipt.database_schema_preimage = "applied";
    receipt.database_migration_ledger = [TARGET.migration];

    const runDir = process.env.RUNNER_TEMP || tmpdir();
    tempDir = join(runDir, `b216-bootstrap-${randomUUID()}`);
    await mkdir(tempDir, { recursive: true, mode: 0o700 });
    wranglerHome = join(tempDir, "home");
    await mkdir(wranglerHome, { mode: 0o700 });
    tempConfig = join(tempDir, "wrangler.toml");
    const appDir = resolve(worktree, "apps/dsr-alert-receiver");
    const privateConfig = preparePrivateBootstrapConfig(config, migration, databaseId, appDir);
    await writeFile(tempConfig, privateConfig, { mode: 0o600, flag: "wx" });

    stage = "bootstrap_preimage_recheck";
    const verifiedDatabaseId = await readBootstrapDatabase(api, migration);
    if (verifiedDatabaseId !== TARGET.databaseId) fail("database_identity_mismatch");
    receipt.database_schema_postflight = "exact_migration_applied";
    const finalWorkerRead = await readWorkerWithToken(context, api, context.bootstrapToken, fetchImpl);
    const finalWorkerSummary = finalWorkerRead.preimageSummary;
    if (finalWorkerSummary.worker_inventory_count !== firstWorkerSummary.worker_inventory_count
      || JSON.stringify(finalWorkerSummary.preexisting_worker_names) !== JSON.stringify(firstWorkerSummary.preexisting_worker_names)) fail("worker_inventory_changed");
    Object.assign(receipt, {
      custom_routes_status: finalWorkerSummary.routes,
      worker_inventory_count_preimage: finalWorkerSummary.worker_inventory_count,
      preexisting_worker_names: finalWorkerSummary.preexisting_worker_names,
      versions_preimage: finalWorkerRead.inventory.versions.status,
      deployments_preimage: finalWorkerRead.inventory.deployments.status,
      subdomain_preimage: finalWorkerRead.inventory.subdomain.status,
    });

    workerMutationStarted = true;
    stage = "worker_version_upload";
    command(["versions", "upload", resolve(appDir, "src/index.ts"), "--config", tempConfig, "--tag", `b216-source-${sha}`, "--message", `B-216 private bootstrap reviewed main ${sha}`], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.bootstrapToken,
    });

    stage = "bootstrap_upload_readback";
    const postUploadState = await readWorkerWithToken(context, api, context.bootstrapToken, fetchImpl, { allowTarget: true });
    const postUploadInventory = postUploadState.inventory;
    await assertPrivateWorkerState(postUploadInventory);
    if (!postUploadState.scriptSummary.target_exists
      || postUploadState.scriptSummary.count !== firstWorkerSummary.worker_inventory_count + 1
      || JSON.stringify(postUploadState.scriptSummary.preexisting_worker_names) !== JSON.stringify(firstWorkerSummary.preexisting_worker_names)) fail("worker_inventory_changed");
    const sourceTag = `b216-source-${sha}`;
    const sourceVersions = postUploadInventory.versions.items.filter((version) => version.tag === sourceTag);
    if (sourceVersions.length !== 1 || postUploadInventory.versions.count !== 1) fail("worker_uploaded_revision_ambiguous");
    const sourceVersion = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${sourceVersions[0].id}`);
    if (sourceVersion?.id !== sourceVersions[0].id
      || sourceVersion?.metadata?.annotations?.["workers/tag"] !== sourceTag
      || sourceVersion?.resources?.bindings?.some((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === TARGET.databaseId) !== true
      || sourceVersion?.resources?.bindings?.some((binding) => binding?.type === "secret_text" && binding.name === TARGET.workerSecret) === true) fail("worker_bootstrap_version_mismatch");
    receipt.worker_revision = sourceVersions[0].id;
    receipt.worker_revision_tag = sourceTag;
    receipt.secret_provisioned = false;
    receipt.worker_inventory_count_postflight = postUploadState.scriptSummary.count;
    receipt.preexisting_worker_names = postUploadState.scriptSummary.preexisting_worker_names;
    receipt.deployments_postflight = "absent";
    receipt.custom_routes_status = postUploadInventory.routes.status === "known" ? "absent" : "unknown";
    receipt.custom_routes_count = postUploadInventory.routes.status === "known" ? 0 : null;
    receipt.subdomain_postflight = postUploadInventory.subdomain.status === "absent"
      ? "absent"
      : postUploadInventory.subdomain.enabled === false && postUploadInventory.subdomain.previews_enabled === false
        ? "disabled"
        : "unknown";
    if (postUploadInventory.deployments.status !== "absent"
      && !(postUploadInventory.deployments.status === "known" && postUploadInventory.deployments.count === 0)
      || receipt.subdomain_postflight === "unknown") fail("worker_bootstrap_postflight_mismatch");
    receipt.public_ingress_status = receipt.custom_routes_status === "absent"
      ? "workers_dev_disabled_routes_absent_subdomain_disabled"
      : "workers_dev_disabled_subdomain_disabled_routes_unknown";
    receipt.status = "private_version_uploaded";
    receipt.completed_at = new Date().toISOString();
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  } catch (error) {
    receipt.status = "failed";
    receipt.failed_stage = stage;
    receipt.failure_code = error instanceof RouteError ? error.code : "route_failed_closed";
    if (stage === "worker_version_upload" && error instanceof RouteError && error.providerFailure) {
      Object.assign(receipt, error.providerFailure);
    }
    if (workerMutationStarted) receipt.rollback_status = "ambiguous_do_not_retry";
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    throw error instanceof RouteError ? error : new RouteError("route_failed_closed");
  } finally {
    if (tempDir) await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function runBootstrapFinalize({ context, config, migration, fetchImpl = fetch, command = runWrangler, receiptPath, bootstrapReceipt, worktree = process.cwd() }) {
  const sha = validateBootstrapFinalizeDispatch({ ...context, bootstrapReceipt });
  validateTrackedInputs(config, migration);
  const api = makeCloudflareApi(context.apiToken, fetchImpl);
  const receipt = {
    schema_version: 1,
    issue: 1678,
    mode: "bootstrap_finalize",
    run_id: context.runId,
    run_attempt: context.runAttempt,
    reviewed_main_sha: sha,
    account_id: TARGET.accountId,
    worker_name: TARGET.workerName,
    database_name: TARGET.databaseName,
    database_id: TARGET.databaseId,
    binding: TARGET.databaseBinding,
    worker_revision: bootstrapReceipt.worker_revision,
    worker_revision_tag: bootstrapReceipt.worker_revision_tag,
    workers_dev: true,
    preexisting_worker_names: bootstrapReceipt.preexisting_worker_names,
    worker_inventory_count_preimage: bootstrapReceipt.worker_inventory_count_preimage,
    secret_provisioned: false,
    custom_routes_status: bootstrapReceipt.custom_routes_status,
    captured_at: new Date().toISOString(),
    status: "started",
  };
  let stage = "database_schema_preimage";
  let mutationStarted = false;
  let tempDir = null;
  let tempConfig = null;
  let wranglerHome = null;
  try {
    const account = await api(`/accounts/${TARGET.accountId}`);
    if (account?.id !== TARGET.accountId) fail("account_identity_mismatch");
    if (await readBootstrapDatabase(api, migration) !== TARGET.databaseId) fail("database_identity_mismatch");
    receipt.database_schema_preimage = "exact_migration_applied";
    receipt.database_migration_ledger = [TARGET.migration];
    const initialWorkerState = await readWorkerWithToken(context, api, context.apiToken, fetchImpl, { allowTarget: true });
    const initialInventory = initialWorkerState.inventory;
    validateBootstrapFinalizeInventory(initialInventory, bootstrapReceipt);
    if (!initialWorkerState.scriptSummary.target_exists
      || initialWorkerState.scriptSummary.count !== bootstrapReceipt.worker_inventory_count_preimage + 1
      || JSON.stringify(initialWorkerState.scriptSummary.preexisting_worker_names) !== JSON.stringify(bootstrapReceipt.preexisting_worker_names)) fail("worker_inventory_changed");
    const initialTags = initialInventory.versions.items.filter((version) => version.id === bootstrapReceipt.worker_revision && version.tag === bootstrapReceipt.worker_revision_tag);
    if (initialTags.length !== 1 || initialInventory.versions.count !== 1) fail("worker_bootstrap_handoff_mismatch");
    const initialVersion = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${bootstrapReceipt.worker_revision}`);
    if (initialVersion?.metadata?.annotations?.["workers/tag"] !== bootstrapReceipt.worker_revision_tag
      || initialVersion?.resources?.bindings?.some((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === TARGET.databaseId) !== true
      || initialVersion?.resources?.bindings?.some((binding) => binding?.type === "secret_text" && binding.name === TARGET.workerSecret) === true) fail("worker_bootstrap_handoff_mismatch");

    const runDir = process.env.RUNNER_TEMP || tmpdir();
    tempDir = join(runDir, `b216-bootstrap-finalize-${randomUUID()}`);
    await mkdir(tempDir, { recursive: true, mode: 0o700 });
    wranglerHome = join(tempDir, "home");
    await mkdir(wranglerHome, { mode: 0o700 });
    tempConfig = join(tempDir, "wrangler.toml");
    const appDir = resolve(worktree, "apps/dsr-alert-receiver");
    await writeFile(tempConfig, prepareWorkersDevBootstrapConfig(config, migration, TARGET.databaseId, appDir), { mode: 0o600, flag: "wx" });

    stage = "bootstrap_prewrite_recheck";
    if (await readBootstrapDatabase(api, migration) !== TARGET.databaseId) fail("database_identity_mismatch");
    const latestWorkerState = await readWorkerWithToken(context, api, context.apiToken, fetchImpl, { allowTarget: true });
    const latestInventory = latestWorkerState.inventory;
    validateBootstrapFinalizeInventory(latestInventory, bootstrapReceipt);
    if (latestWorkerState.scriptSummary.count !== initialWorkerState.scriptSummary.count
      || JSON.stringify(latestWorkerState.scriptSummary.preexisting_worker_names) !== JSON.stringify(initialWorkerState.scriptSummary.preexisting_worker_names)) fail("worker_inventory_changed");

    const versionTag = `b216-${sha}`;
    mutationStarted = true;
    stage = "worker_secret_provision";
    command(["versions", "secret", "put", TARGET.workerSecret, "--config", tempConfig, "--tag", versionTag, "--message", `B-216 private bootstrap reviewed main ${sha}`], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.apiToken,
      input: context.receiverToken,
    });

    stage = "worker_secret_readback";
    const versionList = normalizeVersionList(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions?per_page=100&deployable=true`));
    const tagged = versionList.filter((version) => version?.metadata?.annotations?.["workers/tag"] === versionTag);
    const source = versionList.filter((version) => version?.metadata?.annotations?.["workers/tag"] === bootstrapReceipt.worker_revision_tag);
    if (versionList.length !== 2 || tagged.length !== 1 || source.length !== 1 || source[0]?.id !== bootstrapReceipt.worker_revision || !isUuid(tagged[0]?.id)) fail("worker_uploaded_revision_ambiguous");
    const candidateVersion = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`);
    validateCandidateVersion(candidateVersion, TARGET.databaseId, versionTag);

    stage = "worker_workers_dev_deploy";
    command(["versions", "deploy", `${tagged[0].id}@100%`, "--yes", "--config", tempConfig], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.apiToken,
    });

    stage = "worker_workers_dev_readback";
    const [deploymentResponse, deployedVersion, secrets] = await Promise.all([
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${tagged[0].id}`),
      api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/secrets`),
    ]);
    const deployments = normalizeDeploymentList(deploymentResponse);
    if (selectPriorRevision(deployments) !== tagged[0].id) fail("worker_revision_readback_mismatch");
    validatePostflight({
      versionId: tagged[0].id,
      deployment: deployments[0],
      bindings: deployedVersion?.resources?.bindings ?? [],
      secrets,
      expectedTag: versionTag,
    }, TARGET.databaseId, versionTag);
    const postWorkerState = await readWorkerWithToken(context, api, context.apiToken, fetchImpl, { allowTarget: true });
    const postInventory = postWorkerState.inventory;
    validateBootstrapDeployedInventory(postInventory, tagged[0].id);
    if (postWorkerState.scriptSummary.count !== initialWorkerState.scriptSummary.count
      || JSON.stringify(postWorkerState.scriptSummary.preexisting_worker_names) !== JSON.stringify(initialWorkerState.scriptSummary.preexisting_worker_names)) fail("worker_inventory_changed");
    receipt.worker_revision = tagged[0].id;
    receipt.worker_revision_tag = versionTag;
    receipt.secret_provisioned = true;
    receipt.deployment_revision = tagged[0].id;
    receipt.worker_inventory_count_postflight = postWorkerState.scriptSummary.count;
    receipt.custom_routes_status = postInventory.routes.status === "known" ? "absent" : "unknown";
    receipt.subdomain_postflight = postInventory.subdomain.status === "absent"
      ? "absent"
      : postInventory.subdomain.enabled === true && postInventory.subdomain.previews_enabled === false ? "enabled" : "unknown";
    validateWorkersDevEnabled(postInventory.subdomain);
    receipt.public_ingress_status = receipt.custom_routes_status === "absent"
      ? "workers_dev_enabled_custom_routes_absent_previews_disabled"
      : "workers_dev_enabled_no_custom_routes_configured_previews_disabled";
    receipt.status = "workers_dev_receiver_deployed_and_verified";
    receipt.completed_at = new Date().toISOString();
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  } catch (error) {
    receipt.status = "failed";
    receipt.failed_stage = stage;
    receipt.failure_code = error instanceof RouteError ? error.code : "route_failed_closed";
    if (stage === "worker_secret_provision" && error instanceof RouteError && error.providerFailure) Object.assign(receipt, error.providerFailure);
    if (mutationStarted) {
      try {
        const path = `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/subdomain`;
        await api(path, { method: "POST", body: { enabled: false, previews_enabled: false } });
        const disabled = await api(path);
        if (disabled?.enabled !== false || disabled?.previews_enabled !== false) fail("workers_dev_rollback_readback_mismatch");
        receipt.rollback_status = "workers_dev_disabled_verified";
      } catch {
        receipt.rollback_status = "ambiguous_manual_disable_required";
      }
    }
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    throw error instanceof RouteError ? error : new RouteError("route_failed_closed");
  } finally {
    if (tempDir) await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function queryDatabase(api, id, sql, params = []) {
  const results = await api(`/accounts/${TARGET.accountId}/d1/database/${id}/query`, { method: "POST", body: { sql, ...(params.length === 0 ? {} : { params }) } });
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.success !== true || !Array.isArray(results[0]?.results)) fail("database_query_ambiguous");
  return results[0].results;
}

export async function queryBootstrapDatabase(api, id, sql, params = []) {
  if (!/^SELECT\b/i.test(sql) || /\b(?:CREATE|DROP|ALTER|INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)) fail("bootstrap_database_query_not_read_only");
  if (!Array.isArray(params) || params.some((parameter) => typeof parameter !== "string" && typeof parameter !== "number" && typeof parameter !== "boolean" && parameter !== null)) fail("bootstrap_database_query_not_read_only");
  return queryDatabase(api, id, sql, params);
}

export async function main() {
  const worktree = resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const appDir = resolve(worktree, "apps/dsr-alert-receiver");
  const config = await readFile(resolve(appDir, "wrangler.toml"), "utf8");
  const migration = await readFile(resolve(appDir, "migrations", TARGET.migration), "utf8");
  const bootstrapStage = process.env.B216_BOOTSTRAP_STAGE;
  if (bootstrapStage !== undefined && !["upload", "finalize"].includes(bootstrapStage)) {
    process.stderr.write("B-216 route stopped: bootstrap_stage_invalid\n");
    process.exitCode = 1;
    return;
  }
  const context = {
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
    checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim(),
    ...(bootstrapStage === "upload"
      ? { bootstrapToken: process.env.B216_CF_RECEIVER_BOOTSTRAP_TOKEN }
      : { apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN, receiverToken: process.env.B216_DSR_ALERT_RECEIVER_TOKEN }),
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
  };
  const runDir = process.env.RUNNER_TEMP || tmpdir();
  const receiptPath = join(runDir, bootstrapStage === "upload" ? "b216-receiver-bootstrap-stage-a.json" : "b216-receiver-route-receipt.json");
  try {
    if (bootstrapStage === "upload") {
      await runBootstrapUpload({ context, config, migration, receiptPath, worktree });
    } else if (bootstrapStage === "finalize") {
      const handoffPath = process.env.B216_BOOTSTRAP_HANDOFF_PATH;
      if (!handoffPath) fail("bootstrap_handoff_missing");
      let bootstrapReceipt;
      try { bootstrapReceipt = JSON.parse(await readFile(handoffPath, "utf8")); } catch { fail("bootstrap_handoff_ambiguous"); }
      await runBootstrapFinalize({ context, config, migration, receiptPath, bootstrapReceipt, worktree });
    } else {
      await runRoute({ context, config, migration, receiptPath, worktree });
    }
  } catch (error) {
    const code = error instanceof RouteError ? error.code : "route_failed_closed";
    try {
      await readFile(receiptPath, "utf8");
    } catch {
      await writeReceipt(receiptPath, {
        schema_version: 1,
        issue: bootstrapStage ? 1678 : 2741,
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
