import { mkdtemp, readFile, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  RouteError,
  TARGET,
  classifyWranglerFailure,
  completeLinesInWindow,
  labelWranglerEndpoint,
  makeCloudflareApi,
  listNamedD1Databases,
  normalizeDeploymentList,
  normalizeVersionList,
  runRoute,
  selectNamedResource,
  selectPriorRevision,
  validateDatabaseIdentity,
  validateCandidateVersion,
  validateIntakeDisabled,
  validateInventoryPage,
  validateDispatch,
  assertConfigTargetNames,
  assertProviderRequest,
  assertWranglerCommand,
  requireReceiverResourceName,
  preparePrivateReceiverConfig,
  validateD1InventoryPage,
  validateMigrationLedger,
  validatePostflight,
  validateReceiptSchema,
  validateRollbackReadback,
  validateTrackedInputs,
  validateInitialPrivateDeployment,
  validateInitialPrivateVersion,
  prepareInitialPrivateReceiverConfig,
  prepareFinalReceiverConfig,
  summarizeCustomRoutes,
  queryReadOnlyDatabase,
} from "../scripts/deploy-route.mjs";
import { PROTECTED_RESOURCE_NAMES, RECEIVER_TARGET, assertReceiverResourceName } from "../scripts/receiver-target.mjs";

// The UUID the provider reports for the receiver D1; routes adopt it by exact name.
const DATABASE_ID = "c0ffee00-0b16-4000-8000-0000000006a1";
const goodContext = {
  repository: TARGET.repository,
  ref: "refs/heads/main",
  sha: "a".repeat(40),
  checkoutSha: "a".repeat(40),
  apiToken: "provider-token-never-logged",
  receiverToken: "r".repeat(40),
};
// What a failure carries when stderr holds no Wrangler error block (and stdout no
// bundle report), and what an unclassified (spawn or untrusted) failure carries.
const NO_STRUCTURED_ERROR = Object.freeze({
  provider_failure_class: "process_exit",
  provider_error_code: null,
  provider_error_codes: [],
  provider_error_category: "unknown_cli_failure",
  provider_failure_endpoint: "none_reported",
  provider_http_status: null,
  provider_progress: "before_bundle_report",
  provider_output_structure: "no_structured_error",
});
const NO_CLASSIFIED_DETAIL = Object.freeze({
  provider_error_codes: [],
  provider_failure_endpoint: null,
  provider_http_status: null,
  provider_progress: null,
  provider_output_structure: null,
});
// A Wrangler API-request error block naming the fixed Worker script, with the given
// note lines; how 4.141.0 renders a coded or uncoded API rejection.
const scriptApiFailure = (...notes) => [
  `✘ [ERROR] A request to the Cloudflare API (/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}) failed.`,
  "",
  ...notes.map((note) => `  ${note}`),
  "",
].join("\n");
const SCRIPT_API_FAILURE = Object.freeze({
  provider_failure_endpoint: "worker_script",
  provider_http_status: null,
  provider_progress: "before_bundle_report",
  provider_output_structure: "first_error_block",
});
const WRANGLER_4141_FAILURES = JSON.parse(readFileSync(new URL("./fixtures/wrangler-4.141.0-failures.json", import.meta.url), "utf8")).cases;
// Captures whose diagnosis must equal another capture's: the extra output is noise
// (a follow-up after the root failure, or an echoed response body).
const SAME_DIAGNOSIS_AS = Object.freeze({
  coded_auth_then_offline_whoami: "coded_auth_on_script_upload",
  hostile_body_on_script_upload: "malformed_response_on_script_upload",
});
const errorCode = (fn, code) => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(RouteError);
    expect(error.code).toBe(code);
    return;
  }
  throw new Error(`expected route rejection: ${code}`);
};

function routeHarness({ migration, sha, existing = false, wrongInitialDatabase = false, failInitialDeploy = false, malformedRoutes = false, failFinalDeploymentReadback = false, failFinalSubdomainReadback = false } = {}) {
  const initialId = "323e4567-e89b-42d3-a456-426614174000";
  const sourceId = "423e4567-e89b-42d3-a456-426614174000";
  const finalId = "523e4567-e89b-42d3-a456-426614174000";
  const originalId = "623e4567-e89b-42d3-a456-426614174000";
  const sourceTag = `b216-source-${sha}`;
  const finalTag = `b216-${sha}`;
  const targetDb = wrongInitialDatabase ? "723e4567-e89b-42d3-a456-426614174000" : DATABASE_ID;
  const state = {
    script: existing,
    workersDev: false,
    previewsEnabled: false,
    versions: existing ? [{ id: originalId, metadata: { annotations: { "workers/tag": "b216-existing" } } }] : [],
    details: new Map(),
    deployments: existing ? [{ id: "823e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: originalId, percentage: 100 }] }] : [],
    commands: [],
    requests: [],
    secretPut: false,
    routeFixture: malformedRoutes === true
      ? [{ id: "bad" }]
      : malformedRoutes === "present"
        ? [{ id: "route-1", pattern: "alerts.example/*", script: TARGET.workerName }]
        : null,
    failFinalDeploymentReadback,
    failFinalSubdomainReadback,
  };
  if (existing) state.details.set(originalId, { id: originalId, metadata: { annotations: { "workers/tag": "b216-existing" } }, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID }] } });
  const receiptSql = migration.trim().replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE");
  const tables = [
    { name: "_cf_KV", sql: "CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB)" },
    { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (name TEXT PRIMARY KEY)" },
    { name: "dsr_alert_receipts", sql: receiptSql },
  ];
  const scriptRows = () => state.script
    ? [{ id: TARGET.workerName, ...(state.routeFixture ? { routes: state.routeFixture } : {}) }]
    : [];
  const json = (result, status = 200) => Response.json({ success: status < 400, result }, { status });
  const fetchImpl = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(/^\/client\/v4(?=\/)/, "");
    const method = options.method ?? "GET";
    state.requests.push({ path, method });
    if (path === `/accounts/${TARGET.accountId}`) return json({ id: TARGET.accountId });
    if (path === `/accounts/${TARGET.accountId}/d1/database`) return json([{ name: TARGET.databaseName, uuid: DATABASE_ID, account_id: TARGET.accountId }]);
    if (path.endsWith(`/d1/database/${DATABASE_ID}/query`)) {
      const sql = JSON.parse(options.body).sql;
      return json([{ success: true, results: sql.includes("sqlite_master") ? tables : [{ name: TARGET.migration }] }]);
    }
    if (path === `/accounts/${TARGET.accountId}/workers/scripts`) return json(scriptRows());
    const workerPath = `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`;
    if (path === `${workerPath}/versions` || path.startsWith(`${workerPath}/versions/`)) {
      if (!state.script) return json({}, 404);
      if (path === `${workerPath}/versions` || parsed.searchParams.has("page") || parsed.searchParams.has("per_page")) return json({ items: state.versions });
      const id = path.slice(`${workerPath}/versions/`.length);
      const detail = state.details.get(id);
      return detail ? json(detail) : json({}, 404);
    }
    if ((path === `${workerPath}/deployments` || path === `${workerPath}/deployments?page=1&per_page=100`)
      && state.failFinalDeploymentReadback && state.finalDeployed) {
      state.failFinalDeploymentReadback = false;
      return json({}, 500);
    }
    if (path === `${workerPath}/deployments` || path === `${workerPath}/deployments?page=1&per_page=100`) return state.script ? json({ deployments: state.deployments }) : json({}, 404);
    if (path === `${workerPath}/secrets`) return json(state.secretPut ? [{ name: TARGET.workerSecret }] : []);
    if (path === `${workerPath}/subdomain` && method === "POST") {
      const body = typeof options.body === "string" ? JSON.parse(options.body) : options.body;
      state.workersDev = body.enabled;
      state.previewsEnabled = body.previews_enabled;
      return json({ enabled: state.workersDev, previews_enabled: state.previewsEnabled });
    }
    if (path === `${workerPath}/subdomain` && state.failFinalSubdomainReadback && state.workersDev) {
      state.failFinalSubdomainReadback = false;
      return json({}, 500);
    }
    if (path === `${workerPath}/subdomain`) return state.script ? json({ enabled: state.workersDev, previews_enabled: state.previewsEnabled }) : json({}, 404);
    throw new Error(`unexpected provider request ${method} ${path}`);
  };
  const command = (args, options = {}) => {
    state.commands.push({ args, options });
    if (args[0] === "deploy") {
      if (failInitialDeploy) throw new RouteError("provider_command_failed", failInitialDeploy === true ? { provider_failure_class: "process_exit", process_exit_code: 1, provider_error_category: "permission_denied" } : failInitialDeploy);
      const config = readFileSync(args[args.indexOf("--config") + 1], "utf8");
      if (!config.includes("workers_dev = false\npreview_urls = false") || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/m.test(config)) throw new Error("initial deployment config was not private");
      state.script = true;
      state.versions = [{ id: initialId, metadata: { annotations: {} } }];
      state.details.set(initialId, { id: initialId, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: targetDb }] } });
      state.deployments = [{ id: "923e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: initialId, percentage: 100 }] }];
      state.workersDev = false;
      state.previewsEnabled = false;
      return "";
    }
    if (args[0] === "versions" && args[1] === "upload") {
      state.versions.push({ id: sourceId, metadata: { annotations: { "workers/tag": sourceTag } } });
      state.details.set(sourceId, { id: sourceId, metadata: { annotations: { "workers/tag": sourceTag } }, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID }] } });
      return "";
    }
    if (args[0] === "versions" && args[1] === "secret" && args[2] === "put") {
      expect(options.input).toBe(goodContext.receiverToken);
      state.secretPut = true;
      state.versions.push({ id: finalId, metadata: { annotations: { "workers/tag": finalTag } } });
      state.details.set(finalId, { id: finalId, metadata: { annotations: { "workers/tag": finalTag } }, resources: { bindings: [
        { type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID },
        { type: "secret_text", name: TARGET.workerSecret },
      ] } });
      return "";
    }
    if (args[0] === "versions" && args[1] === "deploy") {
      state.finalDeployed = true;
      state.deployments = [{ id: "a23e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: finalId, percentage: 100 }] }];
      return "";
    }
    if (args[0] === "rollback") {
      state.deployments = [{ id: "b23e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: originalId, percentage: 100 }] }];
      return "";
    }
    throw new Error(`unexpected mocked command ${args.join(" ")}`);
  };
  return { state, fetchImpl, command, initialId, sourceId, finalId };
}

describe("B-216 protected receiver route admission", () => {
  it.each([false, true])("runs the complete receiver route protocol with worker preimage existing=%s", async (existing) => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, existing });
    const receipt = await runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" });
    expect(receipt.status).toBe("deployed");
    expect(receipt.issue).toBe(1678);
    expect(receipt.database_id).toBe(DATABASE_ID);
    expect(receipt.final_workers_dev).toBe(existing ? "preexisting_state_unchanged" : "enabled_verified");
    expect(receipt.final_preview_urls).toBe(existing ? "preexisting_state_unchanged" : "disabled_verified");
    expect(receipt.custom_routes_status).toBe("unknown");
    if (existing) {
      expect(receipt.worker_preimage).toBe("623e4567-e89b-42d3-a456-426614174000");
      expect(harness.state.commands.some(({ args }) => args[0] === "deploy")).toBe(false);
    } else {
      expect(receipt.worker_preimage).toBe("absent");
      expect(receipt.initial_private_revision).toBe(harness.initialId);
      expect(receipt.initial_private_workers_dev).toBe("disabled_verified");
      expect(receipt.initial_private_preview_urls).toBe("disabled_verified");
      expect(harness.state.commands[0].args[0]).toBe("deploy");
      expect(harness.state.commands[0].args).not.toContain("--yes");
    }
    expect(harness.state.workersDev).toBe(!existing);
    expect(harness.state.previewsEnabled).toBe(false);
    expect(harness.state.commands.some(({ args }) => args.includes("rollback"))).toBe(false);
    expect(harness.state.requests.some(({ path, method }) => path.endsWith("/subdomain") && method === "POST")).toBe(!existing);
  });

  it("does not change existing private ingress when final Worker readback fails", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, existing: true, failFinalDeploymentReadback: true });
    await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "provider_response_rejected" });
    expect(harness.state.commands.map(({ args }) => args[1])).toEqual(["upload", "secret", "deploy", "623e4567-e89b-42d3-a456-426614174000"]);
    expect(harness.state.requests.some(({ path, method }) => path.endsWith("/subdomain") && method === "POST")).toBe(false);
    expect(harness.state.workersDev).toBe(false);
    expect(harness.state.deployments[0].versions).toEqual([{ version_id: "623e4567-e89b-42d3-a456-426614174000", percentage: 100 }]);
  });

  it("disables first-create ingress after its enable readback fails", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, failFinalSubdomainReadback: true });
    await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "provider_response_rejected" });
    expect(harness.state.requests.filter(({ path, method }) => path.endsWith("/subdomain") && method === "POST")).toHaveLength(2);
    expect(harness.state.workersDev).toBe(false);
    expect(harness.state.previewsEnabled).toBe(false);
  });

  it("stops on wrong first-deploy D1 binding before receiver secret or final deployment", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, wrongInitialDatabase: true });
    await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "worker_database_binding_mismatch" });
    expect(harness.state.commands.map(({ args }) => args[0])).toEqual(["deploy"]);
    expect(harness.state.secretPut).toBe(false);
    expect(harness.state.workersDev).toBe(false);
  });

  it("rejects malformed or present preexisting routes before invoking Wrangler", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    for (const malformedRoutes of [true, "present"]) {
      const harness = routeHarness({ migration, sha: goodContext.sha, existing: true, malformedRoutes });
      await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" })).rejects.toBeInstanceOf(RouteError);
      expect(harness.state.commands).toHaveLength(0);
    }
  });

  it("keeps route facts unknown and safely compensates a failed first-create attempt", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, failInitialDeploy: true });
    const receiptDir = await mkdtemp(join(tmpdir(), "b216-route-test-"));
    const receiptPath = join(receiptDir, "receipt.json");
    try {
      await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, receiptPath, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "provider_command_failed" });
      const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
      expect(receipt.issue).toBe(1678);
      expect(receipt.provider_error_category).toBe("permission_denied");
      expect(receipt.rollback_status).toBe("absent_preimage_verified");
      expect(receipt.rollback_custom_routes_status).toBeUndefined();
      expect(harness.state.commands.map(({ args }) => args[0])).toEqual(["deploy"]);
      expect(harness.state.secretPut).toBe(false);
    } finally {
      await rm(receiptDir, { recursive: true, force: true });
    }
  });

  it("builds an exact private first-deploy config and rejects route or preview exposure", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const privateConfig = prepareInitialPrivateReceiverConfig(config, migration, DATABASE_ID, "/repo/apps/dsr-alert-receiver");
    expect(privateConfig).toContain(`database_id = "${DATABASE_ID}"`);
    expect(privateConfig).toContain("workers_dev = false\npreview_urls = false");
    expect(privateConfig).not.toMatch(/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/m);
    const finalConfig = prepareFinalReceiverConfig(config, migration, DATABASE_ID, "/repo/apps/dsr-alert-receiver");
    expect(finalConfig).toContain("workers_dev = true\npreview_urls = false");
    expect(finalConfig).not.toMatch(/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/m);
    errorCode(() => prepareInitialPrivateReceiverConfig(`${config}\nroute = \"example.test/*\"\n`, migration, DATABASE_ID, "/repo/apps/dsr-alert-receiver"), "wrangler_config_drift");
    // The adopted UUID is checked for shape; the placeholder and non-UUIDs never pass.
    errorCode(() => prepareFinalReceiverConfig(config, migration, TARGET.placeholderId, "/repo/apps/dsr-alert-receiver"), "database_identity_mismatch");
    errorCode(() => prepareFinalReceiverConfig(config, migration, "not-a-uuid", "/repo/apps/dsr-alert-receiver"), "database_identity_mismatch");
    errorCode(() => prepareInitialPrivateReceiverConfig(config, migration, undefined, "/repo/apps/dsr-alert-receiver"), "database_identity_mismatch");
  });

  it("validates the actual first private deployment shape and rejects wrong DB, secret, revision, routes, or preview state", () => {
    const revision = "123e4567-e89b-42d3-a456-426614174000";
    const inventory = {
      status: "complete",
      worker: { exists: true, inventory_count: 4 },
      routes: { status: "unknown" },
      versions: { status: "known", count: 1, items: [{ id: revision, tag: null }] },
      deployments: { status: "known", count: 1, active: { id: "223e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: revision, percentage: 100 }] } },
      subdomain: { status: "known", enabled: false, previews_enabled: false },
    };
    expect(validateInitialPrivateDeployment(inventory, 4)).toBe(revision);
    expect(validateInitialPrivateVersion({ id: revision, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID }] } }, DATABASE_ID)).toBe(true);
    errorCode(() => validateInitialPrivateDeployment({ ...inventory, worker: { ...inventory.worker, inventory_count: 3 } }, 4), "worker_initial_deployment_ambiguous");
    errorCode(() => validateInitialPrivateDeployment({ ...inventory, subdomain: { status: "known", enabled: false, previews_enabled: true } }, 4), "worker_initial_deployment_ambiguous");
    errorCode(() => validateInitialPrivateDeployment({ ...inventory, routes: { status: "known", count: 1 } }, 4), "worker_custom_route_present");
    errorCode(() => validateInitialPrivateDeployment({ ...inventory, deployments: { ...inventory.deployments, active: { ...inventory.deployments.active, versions: [{ version_id: "323e4567-e89b-42d3-a456-426614174000", percentage: 100 }] } } }, 4), "worker_initial_deployment_ambiguous");
    errorCode(() => validateInitialPrivateVersion({ id: revision, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: "323e4567-e89b-42d3-a456-426614174000" }] } }, DATABASE_ID), "worker_database_binding_mismatch");
    errorCode(() => validateInitialPrivateVersion({ id: revision, resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID }, { type: "secret_text", name: TARGET.workerSecret }] } }, DATABASE_ID), "worker_initial_secret_present");
    expect(summarizeCustomRoutes(undefined)).toBe("unknown");
    expect(summarizeCustomRoutes({ id: TARGET.workerName, routes: [] })).toBe("absent");
    errorCode(() => summarizeCustomRoutes({ id: TARGET.workerName, routes: [{ id: "bad" }] }), "worker_routes_ambiguous");
    errorCode(() => summarizeCustomRoutes({ id: TARGET.workerName, routes: [{ id: "r1", pattern: "*.example/*", script: TARGET.workerName }] }), "worker_custom_route_present");
  });

  it("classifies Wrangler failures into bounded numeric-only receipt fields", () => {
    const sensitive = `${goodContext.apiToken} ${goodContext.receiverToken}`;
    const providerFailure = classifyWranglerFailure({
      status: 1,
      stdout: `diagnostic ${sensitive}`,
      stderr: scriptApiFailure(`upload failed [code: 10021] ${sensitive}`),
    });
    expect(providerFailure).toEqual({
      ...SCRIPT_API_FAILURE,
      provider_failure_class: "provider_error_code",
      provider_error_code: 10021,
      provider_error_codes: [10021],
      process_exit_code: 1,
      provider_error_category: "api_request_rejected",
    });
    expect(JSON.stringify(providerFailure)).not.toContain(sensitive);

    expect(classifyWranglerFailure({ status: 17, stdout: `opaque ${sensitive}`, stderr: "" })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 17,
    });
    for (const [note, codes] of [
      ["[code: nope]", []],
      ["[code: 10021] [code: 10022]", [10021, 10022]],
      ["[code: 1234567]", []],
      ["[code: 10021", []],
      ["[code: 10021] [code:", [10021]],
    ]) {
      expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: scriptApiFailure(note) })).toEqual({
        ...SCRIPT_API_FAILURE,
        provider_failure_class: "ambiguous_provider_error_code",
        provider_error_code: null,
        provider_error_codes: codes,
        process_exit_code: 1,
        provider_error_category: "api_request_rejected",
      });
    }
    // Outside a Wrangler error block no code, category or endpoint is read at all.
    for (const output of ["upload failed [code: 10021]", "[code: 10021] [code: 10022]", "Permission denied", "Authentication error [code: 10000]"]) {
      expect(classifyWranglerFailure({ status: 1, stdout: output, stderr: output })).toEqual({ ...NO_STRUCTURED_ERROR, process_exit_code: 1 });
    }
    const spawnFailure = classifyWranglerFailure({
      error: new Error(`spawn failure ${sensitive}`),
      status: null,
      stdout: sensitive,
      stderr: sensitive,
    });
    expect(spawnFailure).toEqual({
      ...NO_CLASSIFIED_DETAIL,
      provider_failure_class: "spawn_failure",
      provider_error_code: null,
      process_exit_code: null,
      provider_error_category: null,
    });
    expect(JSON.stringify(spawnFailure)).not.toContain(sensitive);

    const untrustedFailure = new RouteError("provider_command_failed", {
      provider_failure_class: "process_exit",
      provider_error_code: 10021,
      process_exit_code: 1,
      extra_sensitive: sensitive,
    });
    expect(untrustedFailure.message).toBe("provider_command_failed");
    expect(untrustedFailure.providerFailure).toEqual({
      ...NO_CLASSIFIED_DETAIL,
      provider_failure_class: "process_exit",
      provider_error_code: null,
      process_exit_code: 1,
      provider_error_category: null,
    });
    expect(JSON.stringify(untrustedFailure.providerFailure)).not.toContain(sensitive);
    expect(JSON.stringify(untrustedFailure)).not.toContain(sensitive);

    const permission = classifyWranglerFailure({ status: 1, stdout: "", stderr: scriptApiFailure(`Permission denied ${sensitive}`) });
    expect(permission.provider_error_category).toBe("permission_denied");
    expect(JSON.stringify(permission)).not.toContain(sensitive);
  });

  // PR #2877 re-review finding 2: only Wrangler's exact first-deploy message counts.
  it("names first_deploy_required only for Wrangler's exact message", () => {
    const exact = "You cannot upload a new version of a Worker that does not yet exist. Please run the `deploy` command first.";
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] ${exact}\n` })).toMatchObject({
      provider_error_category: "first_deploy_required",
      provider_output_structure: "first_error_block",
    });
    for (const stderr of [
      "✘ [ERROR] Build failed the first time worker.ts was compiled\n",
      "✘ [ERROR] Using wrangler versions upload the first time you upload a Worker will fail\n",
      `✘ [ERROR] ${exact} Or not.\n`,
      `✘ [ERROR] ${exact.toLowerCase()}\n`,
      `✘ [ERROR] Build failed\n\n  ${exact}\n`,
      // An unrecognised banner is not read for provider categories or codes either.
      "✘ [ERROR] Build failed: unauthorized import, permission denied [code: 10000]\n\n  Authentication error [code: 10000]\n",
    ]) {
      expect(classifyWranglerFailure({ status: 1, stdout: "", stderr })).toEqual({
        ...NO_STRUCTURED_ERROR,
        process_exit_code: 1,
        provider_output_structure: "first_error_block",
      });
    }
    expect(classifyWranglerFailure({ status: 1, stdout: `Using wrangler versions upload the first time you upload a Worker will fail`, stderr: "" }).provider_error_category).toBe("unknown_cli_failure");
  });

  // PR #2877 re-review finding 1: a first error block beyond the analysed head is
  // not replaced by whatever unstructured text the analysis can still see.
  it("claims nothing when the first error block lies beyond the analysed window", () => {
    const warning = "▲ [WARNING] Processing wrangler.toml configuration:\n\n    - Deprecation: a warning that repeats.\n\n";
    const warnings = warning.repeat(Math.ceil((324 * 1024) / warning.length));
    expect(warnings.length).toBeGreaterThanOrEqual(324 * 1024);
    const malformedEchoingAuth = [
      "✘ [ERROR] Received a malformed response from the API",
      "",
      "  Authentication error [code: 10000]",
      `  PUT /accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName} -> 403 Forbidden`,
      "",
    ].join("\n");
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${warnings}${malformedEchoingAuth}` })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
    // The same block inside the window is a malformed response, and the echoed
    // code is still not read.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${warning}${malformedEchoingAuth}` })).toMatchObject({
      provider_failure_class: "process_exit",
      provider_error_codes: [],
      provider_error_category: "malformed_api_response",
      provider_failure_endpoint: "worker_script",
      provider_http_status: 403,
      provider_output_structure: "first_error_block",
    });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${warnings}${scriptApiFailure("Authentication error [code: 10000]")}` })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: warning })).toEqual({ ...NO_STRUCTURED_ERROR, process_exit_code: 1 });
  });

  // Runs 36812580006 and 36934258883 both recorded process_exit +
  // unknown_cli_failure for the first private deploy. Before this change the first
  // five cases below all produced exactly that receipt, so it could not say which
  // one happened. Each must now classify to a distinct, bounded tuple.
  it.each([
    ["waf_block_on_script_upload", { provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "waf_block", provider_failure_endpoint: "worker_script", provider_http_status: 403, provider_progress: "bundle_reported" }],
    ["malformed_response_on_script_upload", { provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "malformed_api_response", provider_failure_endpoint: "worker_script", provider_http_status: 403, provider_progress: "bundle_reported" }],
    ["uncoded_rejection_on_service_read", { provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "api_request_rejected", provider_failure_endpoint: "worker_service", provider_http_status: null, provider_progress: "before_bundle_report" }],
    ["transport_failure_on_script_upload", { provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "network_failure", provider_failure_endpoint: "none_reported", provider_http_status: null, provider_progress: "bundle_reported" }],
    ["versions_upload_on_absent_worker", { provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "first_deploy_required", provider_failure_endpoint: "none_reported", provider_http_status: null, provider_progress: "before_bundle_report" }],
    ["coded_auth_on_script_upload", { provider_failure_class: "provider_error_code", provider_error_code: 10000, provider_error_codes: [10000], provider_error_category: "authentication_failed", provider_failure_endpoint: "worker_script", provider_http_status: null, provider_progress: "bundle_reported" }],
    ["coded_auth_on_subdomain_after_upload", { provider_failure_class: "provider_error_code", provider_error_code: 10000, provider_error_codes: [10000], provider_error_category: "authentication_failed", provider_failure_endpoint: "worker_subdomain", provider_http_status: null, provider_progress: "upload_reported" }],
  ])("classifies real Wrangler 4.141.0 output for %s without copying it", (name, expected) => {
    const captured = WRANGLER_4141_FAILURES[name];
    expect(captured.status).toBe(1);
    const failure = classifyWranglerFailure(captured);
    expect(failure).toEqual({ ...expected, process_exit_code: 1, provider_output_structure: "first_error_block" });
    const serialized = JSON.stringify(failure);
    for (const leaked of [TARGET.accountId, TARGET.workerName, "8f0000000000abcd", "Forbidden", "/accounts/", "wrangler.log"]) {
      expect(serialized).not.toContain(leaked);
    }
  });

  it("gives every distinct captured Wrangler failure its own receipt tuple", () => {
    const distinct = Object.entries(WRANGLER_4141_FAILURES)
      .filter(([name]) => !SAME_DIAGNOSIS_AS[name])
      .map(([, captured]) => JSON.stringify(classifyWranglerFailure(captured)));
    expect(distinct).toHaveLength(7);
    expect(new Set(distinct).size).toBe(distinct.length);
  });

  // PR #2877 review findings 1 and 2, on real Wrangler 4.141.0 output: a whoami
  // follow-up that loses its connection after a 10000, and a 403 body imitating an
  // error banner, a request note, an upload line and a code marker. Neither may
  // change, or sharpen, the diagnosis of the request that failed first.
  it.each(Object.entries(SAME_DIAGNOSIS_AS))("classifies %s exactly like %s", (name, reference) => {
    expect(classifyWranglerFailure(WRANGLER_4141_FAILURES[name])).toEqual(classifyWranglerFailure(WRANGLER_4141_FAILURES[reference]));
  });

  it("takes the category, codes and endpoint from the first error block only", () => {
    const colour = (text) => `\u001b[31m✘ \u001b[41;31m[\u001b[41;97mERROR\u001b[41;31m]\u001b[0m \u001b[1m${text}\u001b[0m`;
    const scriptFailed = colour(`A request to the Cloudflare API (/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}) failed.`);
    const followUp = classifyWranglerFailure({
      status: 1,
      stdout: "Total Upload: 4.67 KiB / gzip: 1.74 KiB\n",
      stderr: [
        scriptFailed,
        "",
        "  Authentication error [code: 10000]",
        "",
        colour("A request to the Cloudflare API (/user/tokens/verify) failed."),
        "",
        "  Invalid API Token [code: 1000]",
        "",
        colour("fetch failed"),
      ].join("\n"),
    });
    expect(followUp).toMatchObject({
      provider_failure_class: "provider_error_code",
      provider_error_code: 10000,
      provider_error_codes: [10000],
      provider_error_category: "authentication_failed",
      provider_failure_endpoint: "worker_script",
      provider_progress: "bundle_reported",
    });
    const networkFirst = classifyWranglerFailure({
      status: 1,
      stdout: "",
      stderr: `${colour("fetch failed")}\n\n${scriptFailed}\n\n  Authentication error [code: 10000]`,
    });
    expect(networkFirst).toMatchObject({ provider_failure_class: "process_exit", provider_error_codes: [], provider_error_category: "network_failure", provider_failure_endpoint: "none_reported" });
    const malformed = classifyWranglerFailure({
      status: 1,
      stdout: "",
      stderr: `${colour("Received a malformed response from the API")}\n\n  <html>401 Unauthorized</html>\n  GET /accounts/${TARGET.accountId}/workers/services/${TARGET.workerName} -> 401 Unauthorized`,
    });
    expect(malformed).toMatchObject({ provider_error_category: "malformed_api_response", provider_failure_endpoint: "worker_service", provider_http_status: 401 });
    const wafThenFollowUp = classifyWranglerFailure({
      status: 1,
      stdout: "",
      stderr: `${WRANGLER_4141_FAILURES.waf_block_on_script_upload.stderr}\n${colour("A request to the Cloudflare API (/memberships) failed.")}\n\n  Forbidden [code: 9109]`,
    });
    expect(wafThenFollowUp).toMatchObject({ provider_failure_class: "process_exit", provider_error_codes: [], provider_error_category: "waf_block", provider_failure_endpoint: "worker_script", provider_http_status: 403 });
    const sdkError = classifyWranglerFailure({ status: 1, stdout: "", stderr: colour("A request to the Cloudflare API failed.") });
    expect(sdkError).toMatchObject({ provider_error_category: "api_request_rejected", provider_failure_endpoint: "none_reported" });
  });

  it("never reads an echoed response body as Wrangler metadata", () => {
    const banner = "✘ [ERROR] Received a malformed response from the API";
    const realNote = `  PUT /accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName} -> 403 Forbidden`;
    // A body line at column 0 is printed at the same two-space indent as Wrangler's
    // own request note; two request-shaped notes cannot be told apart.
    const forgedNote = classifyWranglerFailure({ status: 1, stdout: "", stderr: `${banner}\n\n  GET /user -> 200 OK\n${realNote}` });
    expect(forgedNote).toMatchObject({ provider_error_category: "malformed_api_response", provider_failure_endpoint: "ambiguous_report", provider_http_status: null });
    const forgedCode = classifyWranglerFailure({ status: 1, stdout: "", stderr: `${banner}\n\n  {"errors":[{"code":10000}]} [code: 10000]\n${realNote}` });
    expect(forgedCode).toMatchObject({ provider_failure_class: "process_exit", provider_error_code: null, provider_error_codes: [], provider_error_category: "malformed_api_response", provider_failure_endpoint: "worker_script" });
    const forgedBanner = classifyWranglerFailure({ status: 1, stdout: "", stderr: `${banner}\n\n  ✘ [ERROR] fetch failed\n${realNote}` });
    expect(forgedBanner).toMatchObject({ provider_error_category: "malformed_api_response", provider_failure_endpoint: "worker_script", provider_http_status: 403 });
    for (const stdout of [
      "Uploaded fake-worker (0.1 sec)\n",
      `  Uploaded ${TARGET.workerName} (0.10 sec)\n`,
      `Uploaded ${TARGET.workerName} (0.10 sec) and more\n`,
      "Total Upload: lots\n",
    ]) {
      expect(classifyWranglerFailure({ status: 1, stdout, stderr: `${banner}\n\n${realNote}` }).provider_progress).toBe("before_bundle_report");
    }
    expect(classifyWranglerFailure({ status: 1, stdout: `Uploaded ${TARGET.workerName} (0.15 sec)\n`, stderr: "" }).provider_progress).toBe("upload_reported");
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${banner}\n\n  Uploaded ${TARGET.workerName} (0.15 sec)\n${realNote}` }).provider_progress).toBe("before_bundle_report");
  });

  // PR #2877 review finding 3: the old patterns took ~54/214/854 ms at 14/28/56 KB
  // of repeated "worker " text. 4 MiB of each adversarial shape must classify well
  // inside the bound. The provider-message and code patterns only run inside an
  // API-request block, and only a block complete inside the window is read, so most
  // shapes are a complete block of long notes followed by 4 MiB of filler.
  const completeScriptApiFailure = (notes) => `${scriptApiFailure(...notes)}🪵  Logs were written\n${"z".repeat(4 * 1024 * 1024)}`;
  const distinctCodeNote = (line) => Array.from({ length: 80 }, (_, index) => `[code: ${line * 80 + index}]`).join(" ");
  it.each([
    ["repeated worker text", () => ({ stdout: "worker ".repeat(600_000), stderr: completeScriptApiFailure(Array(190).fill("worker ".repeat(143))) }), "first_error_block"],
    ["repeated not found text", () => ({ stdout: "", stderr: completeScriptApiFailure(Array(190).fill("not found ".repeat(100))) }), "first_error_block"],
    ["unterminated code marker", () => ({ stdout: "", stderr: completeScriptApiFailure(Array(50).fill(`[code:${" ".repeat(4000)}`)) }), "first_error_block"],
    ["many unterminated markers", () => ({ stdout: "[code: 1".repeat(530_000), stderr: completeScriptApiFailure(Array(190).fill("[code: 1".repeat(125))) }), "first_error_block"],
    ["provider message lookalikes", () => ({ stdout: "", stderr: completeScriptApiFailure(Array(190).fill("unauthorize permission rate limi ".repeat(30))) }), "first_error_block"],
    ["many distinct codes", () => ({ stdout: "", stderr: completeScriptApiFailure(Array.from({ length: 190 }, (_, line) => distinctCodeNote(line))) }), "first_error_block"],
    ["many banners", () => ({ stdout: "", stderr: "✘ [ERROR] fetch failed\n".repeat(183_000) }), "first_error_block"],
    ["progress lookalikes", () => ({ stdout: `${"Total Upload: 1 KiB / gzip: ".repeat(150_000)}\n${"Uploaded x (".repeat(350_000)}`, stderr: "" }), "no_structured_error"],
    ["huge first error block", () => ({ stdout: "", stderr: `✘ [ERROR] Received a malformed response from the API\n\n  ${"GET /user -> 200 OK worker ".repeat(160_000)}` }), "truncated"],
    ["many request notes", () => ({ stdout: "", stderr: `✘ [ERROR] Received a malformed response from the API\n\n${"  GET /x -> 200 OK\n".repeat(222_000)}` }), "truncated"],
  ])("classifies 4 MiB of %s in bounded time", (_name, build, structure) => {
    const { stdout, stderr } = build();
    expect(stdout.length + stderr.length).toBeGreaterThanOrEqual(4 * 1024 * 1024);
    const started = performance.now();
    const failure = classifyWranglerFailure({ status: 1, stdout, stderr });
    expect(performance.now() - started).toBeLessThan(1500);
    expect(failure.provider_output_structure).toBe(structure);
    expect(failure.provider_error_codes.length).toBeLessThanOrEqual(8);
  });

  // PR #2877 round-3 finding: a block cut by the window must not be read as complete.
  // Both cases put the cut where the visible part alone would mislead.
  it("cuts output to whole lines: the last line before a cut window is dropped", () => {
    expect(completeLinesInWindow("ab\ncd", 5)).toEqual({ lines: ["ab", "cd"], truncated: false });
    expect(completeLinesInWindow("ab\ncd", 4)).toEqual({ lines: ["ab", ""], truncated: true });
    expect(completeLinesInWindow("ab\ncd", 3)).toEqual({ lines: ["ab", ""], truncated: true });
    expect(completeLinesInWindow("ab\ncd", 2)).toEqual({ lines: [""], truncated: true });
    expect(completeLinesInWindow("\u001b[1mab\u001b[0m\ncd", 13)).toEqual({ lines: ["ab", "cd"], truncated: false });
    expect(completeLinesInWindow("\u001b[1mab\u001b[0m\ncd", 12)).toEqual({ lines: ["ab", ""], truncated: true });
    expect(completeLinesInWindow("\u001b[1mab\u001b[0m\ncd", 4)).toEqual({ lines: [""], truncated: true });
  });

  // PR #2877 round-4 finding, reproduced exactly: the stdout window ending right
  // after an upload line made a longer, unrecognised line look like progress.
  it("does not read progress from a stdout line the window cuts", () => {
    const window = 256 * 1024;
    const line = `Uploaded ${TARGET.workerName} (0.15 sec)`;
    const stdout = `${"w".repeat(window - line.length - 1)}\n${line} and more\n`;
    expect(classifyWranglerFailure({ status: 1, stdout, stderr: "" }).provider_progress).toBe("before_bundle_report");
    expect(classifyWranglerFailure({ status: 1, stdout: `${"w".repeat(window - line.length - 2)}\n${line}\nmore`, stderr: "" }).provider_progress).toBe("upload_reported");
    expect(classifyWranglerFailure({ status: 1, stdout: `${"w".repeat(window - line.length - 1)}\n${line}`, stderr: "" }).provider_progress).toBe("upload_reported");
  });

  // PR #2877 round-4 class fix: no field may be read from a partial line. Each
  // recognised line of each capture, in stdout and in stderr, is cut by the window
  // at every offset from its start to two past its end; the cut classification may
  // keep or lose detail but never claim more than the uncut one.
  const RECOGNISED_LINE = /^(?:✘ \[ERROR\] |▲ \[WARNING\] |🪵 | {2}\S|Total Upload: |Uploaded )/;
  const PROGRESS_RANK = { before_bundle_report: 0, bundle_reported: 1, upload_reported: 2 };
  // The window is moved with classifyWranglerFailure's windowChars option so each cut
  // costs the size of the capture, not 256 KiB; the 256 KiB default is exercised by
  // the reproduction above and the window tests below.
  const sharpenedFields = (cut, full) => [
    cut.process_exit_code === full.process_exit_code || "process_exit_code",
    [full.provider_failure_class, "process_exit"].includes(cut.provider_failure_class) || "provider_failure_class",
    [full.provider_error_code, null].includes(cut.provider_error_code) || "provider_error_code",
    [JSON.stringify(full.provider_error_codes), "[]"].includes(JSON.stringify(cut.provider_error_codes)) || "provider_error_codes",
    [full.provider_error_category, "unknown_cli_failure"].includes(cut.provider_error_category) || "provider_error_category",
    [full.provider_failure_endpoint, "none_reported"].includes(cut.provider_failure_endpoint) || "provider_failure_endpoint",
    [full.provider_http_status, null].includes(cut.provider_http_status) || "provider_http_status",
    PROGRESS_RANK[cut.provider_progress] <= PROGRESS_RANK[full.provider_progress] || "provider_progress",
    [full.provider_output_structure, "truncated"].includes(cut.provider_output_structure) || "provider_output_structure",
  ].filter((field) => field !== true);
  it.each(Object.keys(WRANGLER_4141_FAILURES))("never sharpens %s when the window cuts a recognised line", (name) => {
    const captured = WRANGLER_4141_FAILURES[name];
    const full = classifyWranglerFailure(captured);
    const windowChars = Math.max(captured.stdout.length, captured.stderr.length) + 4;
    const violations = [];
    let cuts = 0;
    let truncatedCuts = 0;
    for (const stream of ["stdout", "stderr"]) {
      const text = captured[stream];
      let lineStart = 0;
      for (const line of text.split("\n")) {
        const lineEnd = lineStart + line.length;
        if (RECOGNISED_LINE.test(line.replace(/\u001b\[[0-9;]*m/g, ""))) {
          for (let offset = lineStart; offset <= lineEnd + 2; offset += 1) {
            // The padding line puts the window boundary `offset` characters into the
            // stream; the tail keeps that stream longer than the window, while the
            // other stream stays inside it.
            const cutText = `${"w".repeat(windowChars - offset - 1)}\n${text}\nzzzzzzzz`;
            const cut = classifyWranglerFailure({ ...captured, [stream]: cutText }, { windowChars });
            const sharpened = sharpenedFields(cut, full);
            if (sharpened.length > 0) violations.push(`${stream}@${offset}: ${sharpened.join(",")}`);
            if (cut.provider_output_structure === "truncated") truncatedCuts += 1;
            cuts += 1;
          }
        }
        lineStart = lineEnd + 1;
      }
    }
    expect(violations).toEqual([]);
    expect(cuts).toBeGreaterThan(100);
    expect(truncatedCuts).toBeGreaterThan(0);
  });

  it("reports a first error block cut by the analysed window as truncated", () => {
    const window = 256 * 1024;
    const padTo = (visible) => `${"w".repeat(window - visible.length - 1)}\n${visible}`;
    const echoedThenReal = [
      "✘ [ERROR] Received a malformed response from the API",
      "",
      "  <p>",
      "  GET /user -> 200 OK",
      "",
    ].join("\n");
    const realNote = `  PUT /accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName} -> 403 Forbidden\n`;
    const cutBetweenNotes = `${padTo(echoedThenReal)}${realNote}`;
    expect(padTo(echoedThenReal)).toHaveLength(window);
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: cutBetweenNotes })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
    // Uncut, the same block has two request-shaped notes and neither is believed.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${echoedThenReal}${realNote}` })).toMatchObject({
      provider_error_category: "malformed_api_response",
      provider_failure_endpoint: "ambiguous_report",
      provider_http_status: null,
      provider_output_structure: "first_error_block",
    });

    const unrecognised = "✘ [ERROR] fetch failed";
    const cutInBanner = `${padTo(unrecognised)} because the proxy refused the connection\n`;
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: cutInBanner })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${unrecognised} because the proxy refused the connection\n` })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "first_error_block",
    });
  });

  it("reads only the head of stderr for the first error block", () => {
    const filler = "x".repeat(4 * 1024 * 1024);
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] fetch failed\n▲ [WARNING] x\n${filler}` })).toMatchObject({
      provider_error_category: "network_failure",
      provider_output_structure: "first_error_block",
    });
    // The 4 MiB line after the block is cut by the window, so it cannot end the block.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] fetch failed\n${filler}` })).toMatchObject({
      provider_error_category: "unknown_cli_failure",
      provider_output_structure: "truncated",
    });
    // Ending exactly at the window: complete only because stderr ends there too.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(256 * 1024 - 24)}\n✘ [ERROR] fetch failed\n` }).provider_error_category).toBe("network_failure");
    // Ending before stderr does: complete only because a whole terminating line is
    // inside; a terminating line the window cuts is partial and is not read either.
    const blockThenWarning = "\n✘ [ERROR] fetch failed\n▲ [WARNING] x\n";
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(256 * 1024 - blockThenWarning.length)}${blockThenWarning}more` }).provider_error_category).toBe("network_failure");
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(256 * 1024 - 25)}\n✘ [ERROR] fetch failed\n▲ [WARNING] more` })).toMatchObject({ provider_error_category: "unknown_cli_failure", provider_output_structure: "truncated" });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(256 * 1024 - 24)}\n✘ [ERROR] fetch failed\n  ` })).toMatchObject({ provider_error_category: "unknown_cli_failure", provider_output_structure: "truncated" });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(256 * 1024 - 23)}\n✘ [ERROR] fetch failed\n` })).toMatchObject({ provider_error_category: "unknown_cli_failure", provider_output_structure: "truncated" });
    // A block past the line cap, or with a line past the line cap, is cut too.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] Received a malformed response from the API\n\n${"  GET /x -> 200 OK\n".repeat(200)}` })).toMatchObject({ provider_output_structure: "truncated", provider_failure_endpoint: "none_reported" });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] Received a malformed response from the API\n\n${"  GET /x -> 200 OK\n".repeat(150)}` })).toMatchObject({ provider_output_structure: "first_error_block", provider_failure_endpoint: "ambiguous_report" });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${scriptApiFailure(`Authentication error [code: 10000]${" ".repeat(4096)}`)}` })).toMatchObject({ provider_output_structure: "truncated", provider_error_codes: [] });
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `✘ [ERROR] fetch failed${" ".repeat(4096)}\n` })).toMatchObject({ provider_output_structure: "truncated", provider_error_category: "unknown_cli_failure" });
    // A banner beyond the analysed head cannot be placed as the first error, so
    // nothing more specific than unknown is claimed.
    expect(classifyWranglerFailure({ status: 1, stdout: "", stderr: `${" ".repeat(300 * 1024)}\n✘ [ERROR] fetch failed\n` })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
    expect(classifyWranglerFailure({ status: 1, stdout: `${filler}[code: 12345]`, stderr: filler })).toEqual({
      ...NO_STRUCTURED_ERROR,
      process_exit_code: 1,
      provider_output_structure: "truncated",
    });
  });

  it("labels only known Cloudflare endpoints and never returns the path", () => {
    const account = `/accounts/${TARGET.accountId}`;
    const worker = `${account}/workers/scripts/${TARGET.workerName}`;
    for (const [path, label] of [
      [`${account}/workers/services/${TARGET.workerName}`, "worker_service"],
      [worker, "worker_script"],
      [`${worker}?excludeScript=true&bindings_inherit=strict`, "worker_script"],
      [`${worker}/secrets`, "worker_secrets"],
      [`${worker}/deployments`, "worker_deployments"],
      [`${worker}/settings`, "worker_settings"],
      [`${worker}/subdomain`, "worker_subdomain"],
      [`${worker}/versions/0f0e0d0c-0b0a-4908-8706-050403020100`, "worker_versions"],
      [`${account}/workers/workers/${TARGET.workerName}`, "worker_resource"],
      [`${account}/workers/subdomain`, "account_workers_subdomain"],
      [`${account}/d1/database/${DATABASE_ID}/query`, "d1_database"],
      ["/user/tokens/verify", "user_or_membership"],
      ["/memberships", "user_or_membership"],
      ["/accounts", "user_or_membership"],
      [account, "other_endpoint"],
      [`${worker}/schedules`, "other_endpoint"],
      [`${worker}/secrets/extra/depth`, "other_endpoint"],
      ["/accounts/not-an-account/workers/scripts/x", "other_endpoint"],
      ["/zones/abc/workers/routes", "other_endpoint"],
    ]) {
      expect(labelWranglerEndpoint(path)).toBe(label);
    }
  });

  it("drops forged or out-of-range diagnostic fields instead of trusting them", () => {
    const forged = new RouteError("provider_command_failed", {
      provider_failure_class: "process_exit",
      provider_error_codes: [10000, "10001", 2.5],
      provider_failure_endpoint: `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`,
      provider_http_status: 99,
      provider_progress: "Uploaded corelink",
    });
    expect(forged.providerFailure).toMatchObject({
      provider_error_codes: [],
      provider_failure_endpoint: null,
      provider_http_status: null,
      provider_progress: null,
    });
    const tooMany = new RouteError("provider_command_failed", {
      provider_failure_class: "ambiguous_provider_error_code",
      provider_error_codes: [1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      provider_http_status: 600,
    });
    expect(tooMany.providerFailure.provider_error_codes).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(tooMany.providerFailure.provider_http_status).toBeNull();
    expect(Object.isFrozen(tooMany.providerFailure.provider_error_codes)).toBe(true);
  });

  it("writes the classified WAF diagnosis into the failed first-deploy receipt", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha, failInitialDeploy: classifyWranglerFailure(WRANGLER_4141_FAILURES.waf_block_on_script_upload) });
    const receiptDir = await mkdtemp(join(tmpdir(), "b216-route-test-"));
    const receiptPath = join(receiptDir, "receipt.json");
    try {
      await expect(runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, receiptPath, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "provider_command_failed" });
      const raw = await readFile(receiptPath, "utf8");
      const receipt = JSON.parse(raw);
      expect(receipt).toMatchObject({
        failed_stage: "worker_initial_private_deploy",
        provider_failure_class: "process_exit",
        provider_error_category: "waf_block",
        provider_failure_endpoint: "worker_script",
        provider_http_status: 403,
        provider_progress: "bundle_reported",
        provider_error_codes: [],
        provider_output_structure: "first_error_block",
        rollback_status: "absent_preimage_verified",
      });
      expect(raw).not.toContain("8f0000000000abcd");
      expect(raw).not.toContain(goodContext.apiToken);
    } finally {
      await rm(receiptDir, { recursive: true, force: true });
    }
  });

  it("accepts only canonical repository, main ref, exact checkout SHA, and named protected secrets", () => {
    expect(validateDispatch(goodContext)).toBe(goodContext.sha);
    errorCode(() => validateDispatch({ ...goodContext, repository: "fork/corelink-server" }), "repository_mismatch");
    errorCode(() => validateDispatch({ ...goodContext, ref: "refs/heads/feature" }), "main_ref_required");
    errorCode(() => validateDispatch({ ...goodContext, sha: "a".repeat(39) }), "exact_sha_required");
    errorCode(() => validateDispatch({ ...goodContext, checkoutSha: "b".repeat(40) }), "checkout_sha_mismatch");
    errorCode(() => validateDispatch({ ...goodContext, apiToken: "" }), "provider_token_missing");
    errorCode(() => validateDispatch({ ...goodContext, receiverToken: "" }), "receiver_secret_missing");
    errorCode(() => validateDispatch({ ...goodContext, receiverToken: "short" }), "receiver_secret_missing");
  });

  it("allows only SELECT statements in read-only D1 checks and never issues DDL", async () => {
    const calls = [];
    const api = async (path, options) => {
      calls.push({ path, options });
      return [{ success: true, results: [] }];
    };
    await expect(queryReadOnlyDatabase(api, DATABASE_ID, "SELECT name FROM d1_migrations ORDER BY name")).resolves.toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0].path).toContain(`/d1/database/${DATABASE_ID}/query`);
    expect(calls[0].options.method).toBe("POST");
    expect(calls[0].options.body.sql).toMatch(/^SELECT\b/);
    for (const sql of [
      "CREATE TABLE extra (id TEXT)",
      "DROP TABLE dsr_alert_receipts",
      "ALTER TABLE dsr_alert_receipts ADD COLUMN extra TEXT",
      "INSERT INTO d1_migrations (name) VALUES ('other.sql')",
      "SELECT name FROM d1_migrations; DELETE FROM d1_migrations",
    ]) await expect(queryReadOnlyDatabase(api, DATABASE_ID, sql)).rejects.toMatchObject({ code: "database_query_not_read_only" });
    expect(calls).toHaveLength(1);
  });

  it("pins config and sole migration bytes and rejects placeholder or target drift", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    expect(validateTrackedInputs(config, migration)).toBe(true);
    errorCode(() => validateTrackedInputs(config.replace(TARGET.accountId, "f".repeat(32)), migration), "wrangler_config_drift");
    errorCode(() => validateTrackedInputs(config, `${migration}\nCREATE TABLE extra (id TEXT);`), "migration_drift");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: TARGET.placeholderId }), "placeholder_uuid_rejected");
    errorCode(() => validateDatabaseIdentity({ name: "another-database", uuid: "123e4567-e89b-42d3-a456-426614174000" }), "database_identity_ambiguous");
    // Adopted by exact name: any well-formed UUID the provider reports is the target's;
    // a malformed one, or uuid and id that disagree, is refused.
    expect(validateDatabaseIdentity({ name: TARGET.databaseName, uuid: "123e4567-e89b-42d3-a456-426614174000" })).toBe("123e4567-e89b-42d3-a456-426614174000");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: "not-a-uuid" }), "database_identity_ambiguous");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: DATABASE_ID, account_id: "f".repeat(32) }), "database_account_mismatch");
  });

  it("fails closed on duplicate provider names instead of choosing or creating again", () => {
    errorCode(() => selectNamedResource([
      { name: TARGET.databaseName },
      { name: TARGET.databaseName },
    ], TARGET.databaseName, "database"), "database_duplicate_name");
  });

  it("rejects truncated or inconsistent provider inventories instead of assuming a unique target", () => {
    const completeWorkerList = [{ id: TARGET.workerName }];
    expect(validateInventoryPage(completeWorkerList, "worker")).toHaveLength(1);
    expect(selectNamedResource(completeWorkerList, TARGET.workerName, "worker")).toEqual(completeWorkerList[0]);
    errorCode(() => selectNamedResource([
      { id: TARGET.workerName },
      { id: TARGET.workerName },
    ], TARGET.workerName, "worker"), "worker_duplicate_name");
  });

  it("adopts the exact B-216 D1 when the account has two databases", async () => {
    const requests = [];
    const rows = Object.assign([{
      name: TARGET.databaseName,
      uuid: DATABASE_ID,
    }], { result_info: { count: 1, page: 1, per_page: 100, total_count: 2 } });
    const result = await listNamedD1Databases(async (path) => {
      requests.push(path);
      return rows;
    });
    expect(result).toHaveLength(1);
    expect(validateDatabaseIdentity(selectNamedResource(result, TARGET.databaseName, "database"))).toBe(DATABASE_ID);
    expect(requests).toEqual([`/accounts/${TARGET.accountId}/d1/database?name=${TARGET.databaseName}&page=1&per_page=100`]);
  });

  it("accepts a documented D1 array with omitted optional result_info metadata", async () => {
    const rows = [{ name: TARGET.databaseName, uuid: DATABASE_ID }];
    const result = await listNamedD1Databases(async () => rows);
    expect(result).toEqual(rows);
  });

  it("paginates a full result page without metadata before deciding target uniqueness", async () => {
    const requests = [];
    const fullPage = Array.from({ length: 100 }, (_, index) => ({ name: `unrelated-${index}` }));
    const target = { name: TARGET.databaseName, uuid: DATABASE_ID };
    const result = await listNamedD1Databases(async (path) => {
      requests.push(path);
      return requests.length === 1 ? fullPage : [target];
    });
    expect(requests).toHaveLength(2);
    expect(selectNamedResource(result, TARGET.databaseName, "database")).toEqual(target);
  });

  it("rejects duplicate exact D1 names across pages and contradictory pagination metadata", async () => {
    const duplicate = { name: TARGET.databaseName, uuid: DATABASE_ID };
    const duplicates = await listNamedD1Databases(async (path) => {
      const requestedPage = Number(new URLSearchParams(path.split("?")[1]).get("page"));
      return requestedPage === 1
        ? Object.assign([duplicate, ...Array.from({ length: 99 }, (_, index) => ({ name: `similar-${index}` }))], { result_info: { count: 100, page: 1, per_page: 100, total_count: 200 } })
        : Object.assign([duplicate], { result_info: { count: 100, page: 2, per_page: 100, total_count: 200 } });
    });
    errorCode(() => selectNamedResource(duplicates, TARGET.databaseName, "database"), "database_duplicate_name");
    errorCode(() => validateD1InventoryPage(Object.assign([{ name: TARGET.databaseName }], {
      result_info: { count: 1, page: 2, per_page: 100, total_count: 2 },
    }), { page: 1, perPage: 100 }), "database_inventory_truncated");
    errorCode(() => validateD1InventoryPage(Object.assign([{ name: TARGET.databaseName }], {
      result_info: { count: 2, page: 1, per_page: 100, total_count: 1 },
    }), { page: 1, perPage: 100 }), "database_inventory_ambiguous");
    const pages = [];
    let truncated;
    try {
      await listNamedD1Databases(async (path) => {
        const requestedPage = Number(new URLSearchParams(path.split("?")[1]).get("page"));
        pages.push(requestedPage);
        return requestedPage === 1
          ? Object.assign(Array.from({ length: 100 }, (_, index) => ({ name: `page-one-${index}` })), { result_info: { count: 150, page: 1, per_page: 100, total_count: 200 } })
          : Object.assign([{ name: "one-result-on-short-page" }], { result_info: { count: 150, page: 2, per_page: 100, total_count: 200 } });
      });
    } catch (error) {
      truncated = error;
    }
    expect(pages).toEqual([1, 2]);
    expect(truncated).toBeInstanceOf(RouteError);
    expect(truncated.code).toBe("database_inventory_truncated");
  });

  it("retries a partial-create run by adopting the exact existing D1, never POSTing another database", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    let creates = 0;
    let migrations = 0;
    const fetchImpl = async (url, options) => {
      if (url.endsWith(`/accounts/${TARGET.accountId}`)) return Response.json({ success: true, result: { id: TARGET.accountId } });
      if (url.includes("/d1/database?name=")) {
        return Response.json({
          success: true,
          result: [{ name: TARGET.databaseName, uuid: DATABASE_ID }],
          result_info: { count: 1, page: 1, per_page: 100, total_count: 2 },
        });
      }
      if (url.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (url.includes(`/d1/database/${DATABASE_ID}/query`)) {
        return Response.json({ success: true, result: [{ success: true, results: [] }] });
      }
      if (url.endsWith("/d1/database") && options.method === "POST") {
        creates += 1;
        throw new Error("retry must not create another D1");
      }
      throw new Error("unexpected provider request");
    };
    const command = (args) => {
      if (args[0] === "d1" && args[1] === "migrations") {
        migrations += 1;
        throw new RouteError("injected_after_exact_adoption");
      }
      throw new Error("Worker command must not precede the exact D1 schema");
    };
    let rejection;
    try {
      await runRoute({ context: goodContext, config, migration, fetchImpl, command });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(RouteError);
    expect(rejection.code).toBe("injected_after_exact_adoption");
    expect(creates).toBe(0);
    expect(migrations).toBe(1);
  });

  it("fails closed when the frozen D1 is absent instead of provisioning an unverified UUID", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    let creates = 0;
    const fetchImpl = async (url, options) => {
      if (url.endsWith(`/accounts/${TARGET.accountId}`)) return Response.json({ success: true, result: { id: TARGET.accountId } });
      if (url.includes("/d1/database?name=")) {
        return Response.json({ success: true, result: [{ name: "unrelated-d1-fixture", uuid: "123e4567-e89b-42d3-a456-426614174000" }], result_info: { count: 1, page: 1, per_page: 100, total_count: 2 } });
      }
      if (url.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (url.endsWith("/d1/database") && options.method === "POST") creates += 1;
      throw new Error("no provider mutation is allowed for an absent frozen D1");
    };
    let rejection;
    try {
      await runRoute({ context: goodContext, config, migration, fetchImpl, command: () => { throw new Error("Worker command must not run"); } });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(RouteError);
    expect(rejection.code).toBe("database_target_missing");
    expect(creates).toBe(0);
  });

  it("accepts only the exact empty or migrated schema and rejects unknown/partial state", async () => {
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    expect(validateReceiptSchema([], migration)).toBe("empty");
    const reservedD1Table = { name: "_cf_KV", sql: "CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB)" };
    expect(validateReceiptSchema([reservedD1Table], migration)).toBe("empty");
    expect(validateReceiptSchema([
      reservedD1Table,
      { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (id INTEGER)" },
      { name: "dsr_alert_receipts", sql: migration.trim().replace(/;$/, "") },
    ], migration)).toBe("applied");
    errorCode(() => validateReceiptSchema([
      reservedD1Table,
      { name: "unexpected_internal_table", sql: "CREATE TABLE unexpected_internal_table (id TEXT)" },
    ], migration), "database_schema_unknown");
    errorCode(() => validateReceiptSchema([
      reservedD1Table,
      { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (id INTEGER)" },
      { name: "dsr_alert_receipts", sql: migration.replace("schema_version INTEGER", "schema_version TEXT").trim().replace(/;$/, "") },
    ], migration), "database_schema_drift");
    errorCode(() => validateReceiptSchema([{ name: "unknown_table", sql: "CREATE TABLE unknown_table (id TEXT)" }], migration), "database_schema_unknown");
    errorCode(() => validateReceiptSchema([{ name: "d1_migrations", sql: "CREATE TABLE d1_migrations (id INTEGER)" }], migration), "database_migration_state_unknown");
    errorCode(() => validateReceiptSchema([
      { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (id INTEGER)" },
      { name: "dsr_alert_receipts", sql: "CREATE TABLE dsr_alert_receipts (event_id TEXT)" },
    ], migration), "database_schema_drift");
    expect(validateMigrationLedger([{ name: TARGET.migration }])).toBe(true);
    errorCode(() => validateMigrationLedger([{ name: TARGET.migration }, { name: "0002_extra.sql" }]), "database_migration_ledger_drift");
    errorCode(() => validateMigrationLedger([{ name: "0002_extra.sql" }]), "database_migration_ledger_drift");
  });

  it("requires a single exact preimage and exact 100-percent postflight binding and secret names", () => {
    const version = "123e4567-e89b-42d3-a456-426614174000";
    expect(selectPriorRevision([{ versions: [{ version_id: version, percentage: 100 }] }])).toBe(version);
    errorCode(() => selectPriorRevision([{ versions: [{ version_id: version, percentage: 50 }, { version_id: version, percentage: 50 }] }]), "worker_preimage_ambiguous");
    errorCode(() => selectPriorRevision([{ versions: [{ version_id: version, percentage: 90 }] }]), "worker_preimage_ambiguous");
    const deploymentResponse = { deployments: [{ versions: [{ version_id: version, percentage: 100 }] }] };
    expect(normalizeDeploymentList(deploymentResponse)).toEqual(deploymentResponse.deployments);
    expect(normalizeVersionList({ items: [{ id: version }] })).toEqual([{ id: version }]);
    expect(validateRollbackReadback(deploymentResponse, version)).toBe(true);
    errorCode(() => normalizeDeploymentList([{ versions: [{ version_id: version, percentage: 100 }] }]), "worker_preimage_ambiguous");
    errorCode(() => normalizeVersionList([{ id: version }]), "worker_version_inventory_ambiguous");
    errorCode(() => validateRollbackReadback({ deployments: [{ versions: [{ version_id: "123e4567-e89b-42d3-a456-426614174001", percentage: 100 }] }] }, version), "rollback_readback_mismatch");
    expect(validateIntakeDisabled({ enabled: false, previews_enabled: false })).toBe(true);
    errorCode(() => validateIntakeDisabled({ enabled: true, previews_enabled: false }), "rollback_readback_mismatch");
    const deployment = { versions: [{ version_id: version, percentage: 100 }] };
    const tag = `b216-${"a".repeat(40)}`;
    const bindings = [{ type: "d1", name: TARGET.databaseBinding, id: "123e4567-e89b-42d3-a456-426614174000" }];
    const candidate = {
      id: version,
      metadata: { annotations: { "workers/tag": tag } },
      resources: { bindings: [
        { type: "d1", name: TARGET.databaseBinding, database_id: bindings[0].id },
        { type: "secret_text", name: TARGET.workerSecret },
      ] },
    };
    expect(validateCandidateVersion(candidate, bindings[0].id, tag)).toBe(true);
    errorCode(() => validateCandidateVersion({ ...candidate, resources: { bindings: [] } }, bindings[0].id, tag), "worker_database_binding_mismatch");
    expect(validatePostflight({ versionId: version, deployment, bindings, secrets: [{ name: TARGET.workerSecret }] }, bindings[0].id, tag)).toBe(true);
    errorCode(() => validatePostflight({ versionId: version, deployment, bindings: [], secrets: [{ name: TARGET.workerSecret }] }, bindings[0].id, tag), "worker_database_binding_mismatch");
    errorCode(() => validatePostflight({ versionId: version, deployment, bindings, secrets: [] }, bindings[0].id, tag), "worker_secret_readback_missing");
    errorCode(() => validatePostflight({ versionId: version, deployment: { versions: [{ version_id: version, percentage: 50 }] }, bindings, secrets: [{ name: TARGET.workerSecret }] }, bindings[0].id, tag), "worker_revision_readback_mismatch");
    errorCode(() => validatePostflight({ versionId: version, deployment, bindings, secrets: [{ name: TARGET.workerSecret }] }, bindings[0].id, "latest"), "worker_revision_tag_invalid");
  });

  it("never reports a provider error body or secret in its public failure type", () => {
    const error = new RouteError("provider_response_rejected");
    expect(error.message).toBe("provider_response_rejected");
    expect(error.message).not.toContain(goodContext.apiToken);
    expect(error.message).not.toContain(goodContext.receiverToken);
  });

  it("fails closed on a missing exact D1 target without attempting a database create", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    let creates = 0;
    const fetchImpl = async (url, options) => {
      if (url.endsWith(`/accounts/${TARGET.accountId}`)) return Response.json({ success: true, result: { id: TARGET.accountId } });
      if (url.includes("/d1/database?name=") || url.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (url.endsWith("/d1/database") && options.method === "POST") {
        creates += 1;
        throw new Error("missing frozen target must never be created by a retry");
      }
      throw new Error("unexpected provider request");
    };
    let rejection;
    try {
      await runRoute({ context: goodContext, config, migration, fetchImpl, command: () => { throw new Error("no Worker command without the exact D1"); } });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(RouteError);
    expect(rejection.code).toBe("database_target_missing");
    expect(creates).toBe(0);
  });

  it("stops before any provider request when protected receiver secret or approval ref is absent", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    let calls = 0;
    const fetchImpl = async () => { calls += 1; throw new Error("provider must not be contacted"); };
    for (const context of [
      { ...goodContext, receiverToken: "" },
      { ...goodContext, ref: "refs/heads/other" },
    ]) {
      let rejection;
      try {
        await runRoute({ context, config, migration, fetchImpl });
      } catch (error) {
        rejection = error;
      }
      expect(rejection).toBeInstanceOf(RouteError);
    }
    expect(calls).toBe(0);
  });

  it("rejects provider transport and response ambiguity without exposing the response body", async () => {
    const responseText = "sensitive provider response";
    let calls = 0;
    const api = makeCloudflareApi(goodContext.apiToken, async () => {
      calls += 1;
      return Response.json({ success: false, errors: [{ message: responseText }] }, { status: 403 });
    });
    let rejection;
    try {
      await api(`/accounts/${TARGET.accountId}`);
    } catch (error) {
      rejection = error;
    }
    expect(rejection.code).toBe("provider_response_rejected");
    expect(rejection.message).not.toContain(responseText);
    expect(calls).toBe(1);
  });

  it("admits only manual protected main dispatch with no target, command, or ref inputs", async () => {
    const workflow = await readFile(new URL("../../../.github/workflows/b216-receiver-deploy-nonprod.yml", import.meta.url), "utf8");
    const route = await readFile(new URL("../scripts/deploy-route.mjs", import.meta.url), "utf8");
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).toContain("readback_only:");
    expect(workflow).not.toContain("bootstrap");
    expect(workflow).toContain("default: false");
    expect(workflow).toContain("type: boolean");
    expect(workflow).not.toContain("inputs.target");
    expect(workflow).not.toContain("inputs.command");
    expect(workflow).not.toContain("inputs.ref");
    expect(workflow).toContain("runs-on: ubuntu-24.04");
    // Owner decision 2026-10-01: shared main account, protected staging environment.
    expect(workflow).toContain("environment:\n      name: staging");
    expect(workflow.match(/^\s+environment:/gm)).toHaveLength(1);
    expect(workflow).toContain("one independent approval from either");
    expect(workflow).toContain("not a two-approval quorum");
    expect(workflow).toContain("github.repository == 'HuGR-dev/corelink-server'");
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain(`EXPECTED_ACCOUNT: ${TARGET.accountId}`);
    expect(workflow).toContain(`EXPECTED_WORKER: ${TARGET.workerName}`);
    expect(workflow).toContain(`EXPECTED_DATABASE: ${TARGET.databaseName}`);
    expect(workflow).toContain('if [[ "$STAGING_CF_ACCOUNT_ID" != "$EXPECTED_ACCOUNT" ]]; then');
    expect(workflow).toContain("staging_account_mismatch");
    const secretReferences = [...workflow.matchAll(/\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}/g)].map((match) => match[1]);
    expect(new Set(secretReferences)).toEqual(new Set(["STAGING_CF_ACCOUNT_ID", "STAGING_CF_WORKER_API_TOKEN", "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN"]));
    expect(workflow).toContain("B216_CF_RECEIVER_WRITE_TOKEN: ${{ secrets.STAGING_CF_WORKER_API_TOKEN }}");
    expect(workflow).toContain("B216_DSR_ALERT_RECEIVER_TOKEN: ${{ secrets.STAGING_DSR_DLQ_ALERT_AUTH_TOKEN }}");
    expect(workflow).not.toMatch(/^  (push|pull_request|schedule):/m);
    const inputReferences = [...workflow.matchAll(/\$\{\{\s*!?inputs\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g)].map((match) => match[1]);
    expect(inputReferences.length).toBeGreaterThan(0);
    expect(new Set(inputReferences)).toEqual(new Set(["readback_only", "deploy_once", "exercise_once", "disable_workers_dev"]));
    expect(workflow).toContain("exactly_one_dispatch_mode_required");
    expect(workflow).toContain("run-synthetic-exercise.mjs");
    expect(workflow).toContain("run-disable-workers-dev.mjs");
    expect(route).not.toContain("runBootstrap");
    expect(route).toContain("bootstrap_retired_on_shared_account");
    expect(workflow).not.toContain("secrets." + "CF_API_TOKEN");
    expect(workflow).not.toContain("secrets." + "CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toContain("env.CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toMatch(/runs-on:\s*\[?self-hosted/i);
    expect(route).not.toMatch(/method:\s*["']DELETE["']/i);
  });
});

// Owner decision 2026-10-01: the receiver shares the main Cloudflare account with
// production and staging. These are the refusals that keep it on its own pair.
describe("B-216 receiver on the shared main account", () => {
  const PRODUCTION_AND_STAGING_NAMES = [
    "corelink-prod", "corelink-prod-iad", "corelink-prod-d1", "corelink-api", "corelink-api-prod",
    "corelink-signup-worker", "corelink-staging", "corelink-staging-d1", "corelink-server",
    "corelink-config-prod", "corelink-config-dev", "corelink-cas-prod", "corelink-analytics-prod",
    "corelink-dsr-erasure", "corelink-dsr-erasure-dlq", "corelink-chunk-iad", "corelink-manifest-lhr",
    "corelink-ac-syd", "corelink-spawn-worker", "corelink-synthetic-pager", "corelink",
    "CORELINK-PROD", "corelink-prod.bak",
  ];
  const NEAR_MISSES = [
    "corelink-dsr-b216-alert-receiver-20260927", "corelink-dsr-b216-alert-receipts-20260927",
    "corelink-dsr-b216-alert-receiver-6a-copy", "corelink-dsr-b216-alert-receiver-6b",
    "corelink-dsr-b216-alert-receiver-6A", " corelink-dsr-b216-alert-receiver-6a", "corelink-dsr-b216-alert-receiver",
    "", "corelink-dsr-b216-alert-receipts-6a\n",
  ];

  it("pins one dedicated Worker and D1 on the main account, outside every protected name", () => {
    expect(TARGET.accountId).toBe("6a1fc1c626fc2628823e60b9db01f5cd");
    expect(TARGET.workerName).toBe("corelink-dsr-b216-alert-receiver-6a");
    expect(TARGET.databaseName).toBe("corelink-dsr-b216-alert-receipts-6a");
    expect(RECEIVER_TARGET).toMatchObject({ accountId: TARGET.accountId, workerName: TARGET.workerName, databaseName: TARGET.databaseName });
    for (const name of [TARGET.workerName, TARGET.databaseName]) {
      expect(PROTECTED_RESOURCE_NAMES.some((pattern) => pattern.test(name))).toBe(false);
    }
    expect(assertReceiverResourceName(TARGET.workerName, "worker")).toBe(TARGET.workerName);
    expect(assertReceiverResourceName(TARGET.databaseName, "database")).toBe(TARGET.databaseName);
  });

  it("refuses every production or staging name for either resource kind", () => {
    for (const name of PRODUCTION_AND_STAGING_NAMES) {
      expect(PROTECTED_RESOURCE_NAMES.some((pattern) => pattern.test(name)), name).toBe(true);
      for (const kind of ["worker", "database"]) {
        expect(() => assertReceiverResourceName(name, kind), `${kind} ${name}`).toThrow(expect.objectContaining({ code: "protected_resource_name_refused" }));
        errorCode(() => requireReceiverResourceName(name, kind), "protected_resource_name_refused");
      }
    }
  });

  it("refuses any name other than the exact pinned pair, including swapped kinds", () => {
    for (const name of NEAR_MISSES) {
      for (const kind of ["worker", "database"]) {
        errorCode(() => requireReceiverResourceName(name, kind), "receiver_resource_name_refused");
      }
    }
    for (const name of [null, undefined, 42]) errorCode(() => requireReceiverResourceName(name, "worker"), "protected_resource_name_refused");
    errorCode(() => requireReceiverResourceName(TARGET.workerName, "database"), "receiver_resource_name_refused");
    errorCode(() => requireReceiverResourceName(TARGET.databaseName, "worker"), "receiver_resource_name_refused");
    errorCode(() => requireReceiverResourceName(TARGET.workerName, "queue"), "receiver_resource_kind_unknown");
    errorCode(() => selectNamedResource([{ name: "corelink-config-prod" }], "corelink-config-prod", "database"), "protected_resource_name_refused");
    errorCode(() => validateDatabaseIdentity({ name: "corelink-config-prod", uuid: DATABASE_ID }), "database_identity_ambiguous");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: DATABASE_ID, id: "123e4567-e89b-42d3-a456-426614174000" }), "database_identity_ambiguous");
    expect(validateDatabaseIdentity({ name: TARGET.databaseName, uuid: DATABASE_ID, account_id: TARGET.accountId })).toBe(DATABASE_ID);
  });

  it("refuses a tracked config that names any other Worker or D1", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    expect(validateTrackedInputs(config, migration)).toBe(true);
    expect(assertConfigTargetNames(config)).toBe(true);
    for (const [from, to, code] of [
      [`name = "${TARGET.workerName}"`, 'name = "corelink-signup-worker"', "protected_resource_name_refused"],
      [`database_name = "${TARGET.databaseName}"`, 'database_name = "corelink-config-prod"', "protected_resource_name_refused"],
      [`name = "${TARGET.workerName}"`, 'name = "corelink-dsr-b216-alert-receiver-6b"', "receiver_resource_name_refused"],
      [`database_name = "${TARGET.databaseName}"`, `database_name = "${TARGET.databaseName}"\ndatabase_name = "corelink-prod-d1"`, "worker_target_drift"],
      [`name = "${TARGET.workerName}"`, `name = "${TARGET.workerName}"\n  name = "corelink-api"`, "worker_target_drift"],
    ]) {
      // The hash pin stops these first; the name check holds without it.
      errorCode(() => validateTrackedInputs(config.replace(from, to), migration), "wrangler_config_drift");
      errorCode(() => assertConfigTargetNames(config.replace(from, to)), code);
    }
  });

  it("sends only the allowlisted requests for the exact Worker and the adopted D1", () => {
    const account = `/accounts/${TARGET.accountId}`;
    const worker = `${account}/workers/scripts/${TARGET.workerName}`;
    const d1List = `${account}/d1/database?name=${TARGET.databaseName}&page=1&per_page=100`;
    for (const [path, method] of [
      [account, "GET"], [`${account}/workers/scripts`, "GET"], [`${account}/workers/subdomain`, "GET"],
      [`${worker}/deployments`, "GET"], [`${worker}/secrets`, "GET"], [`${worker}/subdomain`, "GET"], [`${worker}/subdomain`, "POST"],
      [`${worker}/versions?per_page=100&deployable=true`, "GET"], [`${worker}/versions/123e4567-e89b-42d3-a456-426614174000`, "GET"],
      [d1List, "GET"], [`${account}/d1/database/${DATABASE_ID}/query`, "POST"],
    ]) {
      expect(assertProviderRequest(path, method, DATABASE_ID), `${method} ${path}`).toBe(true);
    }
    for (const [path, method, adopted] of [
      [`${account}/d1/database/${DATABASE_ID}/query`, "POST", null],
      [`${account}/d1/database/123e4567-e89b-42d3-a456-426614174000/query`, "POST", DATABASE_ID],
      [`${account}/workers/scripts/corelink-signup-worker/subdomain`, "POST", DATABASE_ID],
      [`${account}/workers/scripts/corelink-staging/deployments`, "GET", DATABASE_ID],
      [`${account}/workers/scripts/${TARGET.workerName}`, "PUT", DATABASE_ID],
      [`${account}/workers/scripts/${TARGET.workerName}`, "GET", DATABASE_ID],
      [`${worker}/subdomain`, "DELETE", DATABASE_ID],
      [`${worker}/secrets`, "POST", DATABASE_ID],
      [`${worker}/../corelink-prod/subdomain`, "POST", DATABASE_ID],
      [`${account}/d1/database?name=corelink-config-prod&page=1&per_page=100`, "GET", DATABASE_ID],
      [`${account}/d1/database`, "POST", DATABASE_ID],
      ["/accounts/51284495e71acdb5a7677e7383ab026b/workers/scripts", "GET", DATABASE_ID],
      [`${account}/workers/scripts/${TARGET.workerName}-copy/subdomain`, "POST", DATABASE_ID],
      [`${account}/queues`, "GET", DATABASE_ID],
    ]) {
      errorCode(() => assertProviderRequest(path, method, adopted), "provider_path_refused");
    }
  });

  it("refuses a D1 query before adoption and a second adoption of another UUID, before any fetch", async () => {
    const calls = [];
    const api = makeCloudflareApi("token", async (url) => { calls.push(url); return Response.json({ success: true, result: [{ success: true, results: [] }] }); });
    await expect(api(`/accounts/${TARGET.accountId}/d1/database/${DATABASE_ID}/query`, { method: "POST", body: { sql: "SELECT 1" } })).rejects.toMatchObject({ code: "provider_path_refused" });
    await expect(api(`/accounts/${TARGET.accountId}/workers/scripts/corelink-prod/subdomain`, { method: "POST", body: { enabled: false } })).rejects.toMatchObject({ code: "provider_path_refused" });
    expect(calls).toHaveLength(0);
    expect(api.adoptDatabase(DATABASE_ID)).toBe(DATABASE_ID);
    expect(api.adoptDatabase(DATABASE_ID)).toBe(DATABASE_ID);
    errorCode(() => api.adoptDatabase("123e4567-e89b-42d3-a456-426614174000"), "database_adoption_changed");
    errorCode(() => api.adoptDatabase(TARGET.placeholderId), "database_identity_mismatch");
    await api(`/accounts/${TARGET.accountId}/d1/database/${DATABASE_ID}/query`, { method: "POST", body: { sql: "SELECT 1" } });
    expect(calls).toHaveLength(1);
  });

  it("runs only the exact Wrangler command shapes against the run's pinned config", () => {
    const sha = "a".repeat(40);
    const entry = "/runner/work/corelink-server/apps/dsr-alert-receiver/src/index.ts";
    const config = "/runner/_temp/b216-123e4567-e89b-42d3-a456-426614174000/wrangler.toml";
    const privateConfig = "/runner/_temp/b216-123e4567-e89b-42d3-a456-426614174000/wrangler-initial-private.toml";
    const version = "223e4567-e89b-42d3-a456-426614174000";
    for (const args of [
      ["d1", "migrations", "apply", TARGET.databaseName, "--remote", "--config", config],
      ["deploy", entry, "--config", privateConfig, "--message", `B-216 private initial revision ${sha}`],
      ["versions", "upload", entry, "--config", config, "--tag", `b216-source-${sha}`, "--message", `B-216 reviewed main ${sha}`],
      ["versions", "secret", "put", TARGET.workerSecret, "--config", config, "--tag", `b216-${sha}`, "--message", `B-216 reviewed main ${sha}`],
      ["versions", "deploy", `${version}@100%`, "--yes", "--config", config],
      ["rollback", version, "--config", config, "--message", "B-216 exact preimage rollback"],
    ]) {
      expect(assertWranglerCommand(args), args.join(" ")).toBe(true);
    }
    errorCode(() => assertWranglerCommand(["d1", "migrations", "apply", "corelink-config-prod", "--remote", "--config", config]), "protected_resource_name_refused");
    for (const args of [
      ["d1", "execute", TARGET.databaseName, "--remote", "--command", "DROP TABLE x", "--config", config],
      ["deploy", entry, "--config", privateConfig, "--message", "m", "--name", "corelink-prod"],
      ["deploy", entry, "--config", "/repo/wrangler.toml", "--message", "m"],
      ["deploy", entry, "--config", privateConfig, "--env=production", "m"],
      ["versions", "upload", entry, "--config", config, "--tag", "t", "--message", "--name=corelink-api"],
      ["versions", "secret", "put", "OTHER_SECRET", "--config", config, "--tag", "t", "--message", "m"],
      ["versions", "deploy", `${version}@50%`, "--yes", "--config", config],
      ["delete", "--config", config],
      ["secret", "put", TARGET.workerSecret, "--config", config],
      ["rollback", "latest", "--config", config, "--message", "m"],
      "deploy",
    ]) {
      errorCode(() => assertWranglerCommand(args), "wrangler_command_refused");
    }
  });

  // The guards below cannot be tripped by the route's own well-formed calls, so their
  // wiring is pinned structurally: each one sits on the only path to the provider.
  it("wires every guard onto the only path to Cloudflare and Wrangler", async () => {
    const route = await readFile(new URL("../scripts/deploy-route.mjs", import.meta.url), "utf8");
    const target = await readFile(new URL("../scripts/receiver-target.mjs", import.meta.url), "utf8");
    const exercise = await readFile(new URL("../scripts/synthetic-exercise.mjs", import.meta.url), "utf8");
    const runRouteSource = route.slice(route.indexOf("export async function runRoute("), route.indexOf("async function queryDatabase("));
    expect(runRouteSource.length).toBeGreaterThan(1000);
    expect(runRouteSource).toMatch(/const command = \(args, options\) => \{\n\s+assertWranglerCommand\(args\);\n\s+return runCommand\(args, options\);\n\s+\};/);
    expect(runRouteSource).not.toMatch(/\brunCommand\(\[/);
    expect(route).toMatch(/async function request\(path, \{ method = "GET", body \} = \{\}\) \{\n\s+assertProviderRequest\(path, method, adoptedDatabase\);/);
    const tracked = route.slice(route.indexOf("export function validateTrackedInputs("), route.indexOf("export function selectNamedResource("));
    expect(tracked).toContain("assertConfigTargetNames(config);");
    expect(route).toContain("receipt.database_id = api.adoptDatabase(validateDatabaseIdentity(priorDatabase));");
    expect(exercise).toContain("const databaseId = api.adoptDatabase(validateDatabaseIdentity(database));");
    expect(target).toMatch(/^assertReceiverResourceName\(RECEIVER_TARGET\.workerName, "worker"\);$/m);
    expect(target).toMatch(/^assertReceiverResourceName\(RECEIVER_TARGET\.databaseName, "database"\);$/m);
  });

  it("refuses nothing the real route sends: every request and command of a full run passes the guards", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const harness = routeHarness({ migration, sha: goodContext.sha });
    await runRoute({ context: goodContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" });
    expect(harness.state.commands.length).toBeGreaterThan(0);
    for (const { args } of harness.state.commands) expect(assertWranglerCommand(args)).toBe(true);
    expect(harness.state.requests.length).toBeGreaterThan(0);
    expect(harness.state.requests.every(({ path }) => path.startsWith(`/accounts/${TARGET.accountId}`))).toBe(true);
    expect(harness.state.requests.some(({ path }) => /corelink-(?:prod|api|signup-worker|staging)/.test(path))).toBe(false);
  });
});
