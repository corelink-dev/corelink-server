import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  RouteError,
  TARGET,
  classifyWranglerFailure,
  makeCloudflareApi,
  listNamedD1Databases,
  normalizeDeploymentList,
  normalizeVersionList,
  runRoute,
  runBootstrapUpload,
  runBootstrapFinalize,
  selectNamedResource,
  selectPriorRevision,
  validateDatabaseIdentity,
  validateCandidateVersion,
  validateIntakeDisabled,
  validateInventoryPage,
  validateDispatch,
  validateBootstrapDispatch,
  validateBootstrapFinalizeDispatch,
  validateBootstrapFinalizeInventory,
  validateBootstrapDeployedInventory,
  validateBootstrapWorkerPreimage,
  validateBootstrapWorkerScriptInventory,
  validateBootstrapWorkerScriptInventory,
  preparePrivateBootstrapConfig,
  validateD1InventoryPage,
  validateMigrationLedger,
  validatePostflight,
  validateReceiptSchema,
  validateRollbackReadback,
  validateTrackedInputs,
  queryBootstrapDatabase,
} from "../scripts/deploy-route.mjs";

const goodContext = {
  repository: TARGET.repository,
  ref: "refs/heads/main",
  sha: "a".repeat(40),
  checkoutSha: "a".repeat(40),
  apiToken: "provider-token-never-logged",
  receiverToken: "r".repeat(40),
};
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

function bootstrapHarness({ migration, sha, failDeploy = false, preexistingWorkerNames = [] }) {
  const sourceId = "123e4567-e89b-42d3-a456-426614174000";
  const finalId = "223e4567-e89b-42d3-a456-426614174000";
  const sourceTag = `b216-source-${sha}`;
  const finalTag = `b216-${sha}`;
  const state = { script: false, versions: [], versionDetails: new Map(), deployments: [], commands: [], requests: [] };
  const receiptSql = migration.replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE");
  const workerRows = () => [
    ...preexistingWorkerNames.map((id) => ({ id, routes: [] })),
    ...(state.script ? [{ id: TARGET.workerName, routes: [] }] : []),
  ];
  const d1Tables = [
    { name: "_cf_KV", sql: "CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB)" },
    { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (name TEXT PRIMARY KEY)" },
    { name: "dsr_alert_receipts", sql: receiptSql },
  ];
  const fetchImpl = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(/^\/client\/v4(?=\/)/, "");
    state.requests.push({ path, method: options.method ?? "GET", authorization: options.headers?.authorization });
    const json = (result, status = 200) => Response.json({ success: true, result }, { status });
    if (path === `/accounts/${TARGET.accountId}`) return json({ id: TARGET.accountId });
    if (path === `/accounts/${TARGET.accountId}/d1/database`) return json([{ name: TARGET.databaseName, uuid: TARGET.databaseId, account_id: TARGET.accountId }]);
    if (path.endsWith(`/d1/database/${TARGET.databaseId}/query`)) {
      const sql = JSON.parse(options.body).sql;
      const rows = sql.includes("sqlite_master") ? d1Tables : [{ name: TARGET.migration }];
      return json([{ success: true, results: rows }]);
    }
    if (path === `/accounts/${TARGET.accountId}/workers/scripts`) {
      return json(workerRows());
    }
    const workerPath = `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`;
    if (path === `${workerPath}/versions` || path === `${workerPath}/versions/${sourceId}` || path === `${workerPath}/versions/${finalId}`) {
      if (!state.script) return new Response("{}", { status: 404 });
      if (path.endsWith("/versions")) return json({ items: state.versions });
      const id = path.endsWith(sourceId) ? sourceId : finalId;
      const detail = state.versionDetails.get(id);
      return detail ? json(detail) : new Response("{}", { status: 404 });
    }
    if (path === `${workerPath}/deployments`) return state.script ? json({ deployments: state.deployments }) : new Response("{}", { status: 404 });
    if (path === `${workerPath}/secrets`) return json(state.script && state.versionDetails.has(finalId) ? [{ name: TARGET.workerSecret }] : []);
    if (path === `${workerPath}/subdomain`) return new Response("{}", { status: 404 });
    if (path === `${workerPath}/versions`) return json({ items: state.versions });
    if (path === `${workerPath}/deployments`) return json({ deployments: state.deployments });
    throw new Error(`unexpected mocked route ${path}`);
  };
  const command = (args, options = {}) => {
    state.commands.push({ args, options });
    if (args[0] === "versions" && args[1] === "upload") {
      state.script = true;
      state.versions = [{ id: sourceId, metadata: { annotations: { "workers/tag": sourceTag } } }];
      state.versionDetails.set(sourceId, {
        id: sourceId,
        metadata: { annotations: { "workers/tag": sourceTag } },
        resources: { bindings: [{ type: "d1", name: TARGET.databaseBinding, database_id: TARGET.databaseId }] },
      });
      return "";
    }
    if (args[0] === "versions" && args[1] === "secret" && args[2] === "put") {
      state.versions = [
        ...state.versions,
        { id: finalId, metadata: { annotations: { "workers/tag": finalTag } } },
      ];
      state.versionDetails.set(finalId, {
        id: finalId,
        metadata: { annotations: { "workers/tag": finalTag } },
        resources: { bindings: [
          { type: "d1", name: TARGET.databaseBinding, database_id: TARGET.databaseId },
          { type: "secret_text", name: TARGET.workerSecret },
        ] },
      });
      return "";
    }
    if (args[0] === "versions" && args[1] === "deploy") {
      if (failDeploy) throw new RouteError("provider_command_failed", { provider_failure_class: "process_exit", process_exit_code: 1 });
      state.deployments = [{ id: "323e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: finalId, percentage: 100 }] }];
      return "";
    }
    throw new Error("unexpected mocked command");
  };
  return { state, fetchImpl, command, sourceId, sourceTag, finalId, finalTag };
}

describe("B-216 protected receiver route admission", () => {
  it("classifies Wrangler failures into bounded numeric-only receipt fields", () => {
    const sensitive = `${goodContext.apiToken} ${goodContext.receiverToken}`;
    const providerFailure = classifyWranglerFailure({
      status: 1,
      stdout: `upload failed [code: 10021] ${sensitive}`,
      stderr: `diagnostic ${sensitive}`,
    });
    expect(providerFailure).toEqual({
      provider_failure_class: "provider_error_code",
      provider_error_code: 10021,
      process_exit_code: 1,
    });
    expect(JSON.stringify(providerFailure)).not.toContain(sensitive);

    expect(classifyWranglerFailure({ status: 17, stdout: `opaque ${sensitive}`, stderr: "" })).toEqual({
      provider_failure_class: "process_exit",
      provider_error_code: null,
      process_exit_code: 17,
    });
    for (const output of [
      "[code: nope]",
      "[code: 10021] [code: 10022]",
      "[code: 1234567]",
      "[code: 10021",
      "[code: 10021] [code:",
    ]) {
      expect(classifyWranglerFailure({ status: 1, stdout: output, stderr: "" })).toEqual({
        provider_failure_class: "ambiguous_provider_error_code",
        provider_error_code: null,
        process_exit_code: 1,
      });
    }
    const spawnFailure = classifyWranglerFailure({
      error: new Error(`spawn failure ${sensitive}`),
      status: null,
      stdout: sensitive,
      stderr: sensitive,
    });
    expect(spawnFailure).toEqual({
      provider_failure_class: "spawn_failure",
      provider_error_code: null,
      process_exit_code: null,
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
      provider_failure_class: "process_exit",
      provider_error_code: null,
      process_exit_code: 1,
    });
    expect(JSON.stringify(untrustedFailure.providerFailure)).not.toContain(sensitive);
    expect(JSON.stringify(untrustedFailure)).not.toContain(sensitive);
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

  it("keeps bootstrap credentials stage-separated and binds Stage B to this run's exact Stage A receipt", () => {
    const bootstrapContext = {
      repository: TARGET.repository,
      ref: "refs/heads/main",
      sha: "c".repeat(40),
      checkoutSha: "c".repeat(40),
      bootstrapToken: "bootstrap-token",
      runId: "12345",
      runAttempt: "1",
    };
    expect(validateBootstrapDispatch(bootstrapContext)).toBe(bootstrapContext.sha);
    errorCode(() => validateBootstrapDispatch({ ...bootstrapContext, bootstrapToken: "" }), "bootstrap_token_missing");
    errorCode(() => validateBootstrapDispatch({ ...bootstrapContext, receiverToken: "must-not-cross-stage" }), "bootstrap_context_credential_mismatch");
    const handoff = {
      schema_version: 1,
      status: "private_version_uploaded",
      repository: TARGET.repository,
      reviewed_main_sha: bootstrapContext.sha,
      account_id: TARGET.accountId,
      worker_name: TARGET.workerName,
      database_name: TARGET.databaseName,
      database_id: TARGET.databaseId,
      binding: TARGET.databaseBinding,
      migration: TARGET.migration,
      migration_sha256: TARGET.migrationSha256,
      preexisting_worker_names: [],
      worker_inventory_count_preimage: 0,
      worker_inventory_count_postflight: 1,
      run_id: "12345",
      run_attempt: "1",
      workers_dev: false,
      secret_provisioned: false,
      custom_routes_status: "unknown",
      worker_revision: "123e4567-e89b-42d3-a456-426614174000",
      worker_revision_tag: `b216-source-${bootstrapContext.sha}`,
      deployments_postflight: "absent",
      subdomain_postflight: "absent",
    };
    const finalizeContext = { ...goodContext, ...bootstrapContext, bootstrapToken: undefined, apiToken: "editor-token", receiverToken: "r".repeat(40), runId: "12345", runAttempt: "1" };
    delete finalizeContext.bootstrapToken;
    expect(validateBootstrapFinalizeDispatch({ ...finalizeContext, bootstrapReceipt: handoff })).toBe(bootstrapContext.sha);
    errorCode(() => validateBootstrapFinalizeDispatch({ ...finalizeContext, bootstrapToken: "must-not-cross-stage", bootstrapReceipt: handoff }), "bootstrap_token_forbidden_in_finalize");
    errorCode(() => validateBootstrapFinalizeDispatch({ ...finalizeContext, bootstrapReceipt: { ...handoff, run_id: "other" } }), "bootstrap_handoff_mismatch");
    errorCode(() => validateBootstrapFinalizeDispatch({ ...finalizeContext, bootstrapReceipt: { ...handoff, database_id: "123e4567-e89b-42d3-a456-426614174000" } }), "bootstrap_handoff_mismatch");
    errorCode(() => validateBootstrapFinalizeDispatch({ ...finalizeContext, bootstrapReceipt: { ...handoff, worker_revision_tag: `b216-source-${"d".repeat(40)}` } }), "bootstrap_handoff_mismatch");
  });

  it("pins private bootstrap config and admits only the exact Stage A upload-only preimage", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const privateConfig = preparePrivateBootstrapConfig(config, migration, TARGET.databaseId, "/runner/work/corelink-server/apps/dsr-alert-receiver");
    expect(privateConfig).toContain(`database_id = "${TARGET.databaseId}"`);
    expect(privateConfig).toContain("workers_dev = false");
    expect(privateConfig).not.toMatch(/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im);

    const absent = {
      status: "complete",
      worker: { exists: false, inventory_count: 0 },
      versions: { status: "absent" },
      deployments: { status: "absent" },
      subdomain: { status: "absent" },
      routes: { status: "unknown" },
      inventory_consistency: "worker_absent",
    };
    expect(validateBootstrapWorkerPreimage(absent, [])).toEqual({
      worker: "absent",
      routes: "unknown",
      worker_inventory_count: 0,
      preexisting_worker_names: [],
    });
    const allowedName = "corelink-i2568-sla-credit-test-20260928";
    expect(validateBootstrapWorkerScriptInventory([])).toEqual({ count: 0, preexisting_worker_names: [], target_exists: false });
    expect(validateBootstrapWorkerScriptInventory([{ id: allowedName }])).toEqual({ count: 1, preexisting_worker_names: [allowedName], target_exists: false });
    expect(validateBootstrapWorkerPreimage({ ...absent, worker: { exists: false, inventory_count: 1 } }, [{ id: allowedName }])).toEqual({
      worker: "absent",
      routes: "unknown",
      worker_inventory_count: 1,
      preexisting_worker_names: [allowedName],
    });
    for (const partial of [
      { ...absent, versions: { status: "known", count: 1, items: [{ id: "123e4567-e89b-42d3-a456-426614174000" }] }, inventory_consistency: "partial_version_only" },
      { ...absent, worker: { exists: true, inventory_count: 1 } },
      { ...absent, routes: { status: "known", count: 1 } },
      { ...absent, subdomain: { status: "known", enabled: true, previews_enabled: false } },
    ]) errorCode(() => validateBootstrapWorkerPreimage(partial, []), partial.routes?.count ? "worker_custom_route_present" : "worker_bootstrap_target_not_absent");
    errorCode(() => validateBootstrapWorkerScriptInventory([{ id: TARGET.workerName }]), "worker_bootstrap_target_not_absent");
    errorCode(() => validateBootstrapWorkerScriptInventory([{ id: "unowned-worker-name" }]), "worker_inventory_unexpected_name");
    errorCode(() => validateBootstrapWorkerScriptInventory(Object.assign([{ id: allowedName }], {
      result_info: { page: 1, per_page: 1, count: 1, total_count: 2 },
    })), "worker_inventory_truncated");
    errorCode(() => validateBootstrapWorkerScriptInventory([{ id: allowedName }, { id: allowedName }]), "worker_duplicate_name");
    errorCode(() => validateBootstrapWorkerScriptInventory(Object.assign([{ id: allowedName }], {
      result_info: { page: 1, per_page: 1, count: 1, total_count: 0 },
    })), "worker_inventory_truncated");
  });

  it.each([[], ["corelink-i2568-sla-credit-test-20260928"]])("simulates Stage A→B with private credentials and preexisting Workers %j", async (preexistingWorkerNames) => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const sha = "e".repeat(40);
    const bootstrapToken = "bootstrap-admin-token";
    const editorToken = "editor-token";
    const bearer = "receiver-bearer-never-logged-0000000000000000";
    const uploadContext = {
      repository: TARGET.repository,
      ref: "refs/heads/main",
      sha,
      checkoutSha: sha,
      bootstrapToken,
      runId: "987654321",
      runAttempt: "1",
    };
    const finalizeContext = {
      repository: TARGET.repository,
      ref: "refs/heads/main",
      sha,
      checkoutSha: sha,
      apiToken: editorToken,
      receiverToken: bearer,
      runId: "987654321",
      runAttempt: "1",
    };
    const harness = bootstrapHarness({ migration, sha, preexistingWorkerNames });
    const handoff = await runBootstrapUpload({ context: uploadContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" });
    expect(handoff.status).toBe("private_version_uploaded");
    expect(handoff.secret_provisioned).toBe(false);
    expect(handoff.deployments_postflight).toBe("absent");
    expect(handoff.worker_revision).toBe(harness.sourceId);
    expect(handoff.worker_inventory_count_preimage).toBe(preexistingWorkerNames.length);
    expect(handoff.worker_inventory_count_postflight).toBe(preexistingWorkerNames.length + 1);
    expect(handoff.preexisting_worker_names).toEqual(preexistingWorkerNames);
    expect(harness.state.commands.map(({ args }) => args.slice(0, 2))).toEqual([["versions", "upload"]]);
    expect(harness.state.commands[0].options.apiToken).toBe(bootstrapToken);
    expect(harness.state.commands[0].options.input).toBeUndefined();

    const deployed = await runBootstrapFinalize({ context: finalizeContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, bootstrapReceipt: handoff, worktree: "/runner/work/corelink-server" });
    expect(deployed.status).toBe("private_worker_deployed_and_verified");
    expect(deployed.run_id).toBe("987654321");
    expect(deployed.run_attempt).toBe("1");
    expect(deployed.database_migration_ledger).toEqual([TARGET.migration]);
    expect(deployed.deployment_revision).toBe(harness.finalId);
    expect(deployed.worker_inventory_count_preimage).toBe(preexistingWorkerNames.length);
    expect(deployed.worker_inventory_count_postflight).toBe(preexistingWorkerNames.length + 1);
    expect(deployed.preexisting_worker_names).toEqual(preexistingWorkerNames);
    expect(harness.state.commands.map(({ args }) => args[1])).toEqual(["upload", "secret", "deploy"]);
    expect(harness.state.commands[1].options.apiToken).toBe(editorToken);
    expect(harness.state.commands[1].options.input).toBe(bearer);
    expect(harness.state.commands[2].options.apiToken).toBe(editorToken);
    for (const request of harness.state.requests) {
      if (request.path.endsWith("/query")) expect(request.method).toBe("POST");
      else expect(request.method).toBe("GET");
    }
    expect(new Set(harness.state.requests.map(({ authorization }) => authorization))).toEqual(new Set([`Bearer ${bootstrapToken}`, `Bearer ${editorToken}`]));
    expect(harness.state.requests.some(({ path }) => path.includes("corelink-i2568-sla-credit-test-20260928"))).toBe(false);
    expect(JSON.stringify({ handoff, deployed })).not.toContain(bearer);
  });

  it("stops after one ambiguous Stage B deploy failure without retrying or deleting resources", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    const sha = "f".repeat(40);
    const uploadContext = {
      repository: TARGET.repository,
      ref: "refs/heads/main",
      sha,
      checkoutSha: sha,
      bootstrapToken: "bootstrap-admin-token",
      runId: "987654322",
      runAttempt: "1",
    };
    const finalizeContext = {
      repository: TARGET.repository,
      ref: "refs/heads/main",
      sha,
      checkoutSha: sha,
      apiToken: "editor-token",
      receiverToken: "receiver-bearer-never-logged-0000000000000000",
      runId: "987654322",
      runAttempt: "1",
    };
    const harness = bootstrapHarness({ migration, sha, failDeploy: true });
    const handoff = await runBootstrapUpload({ context: uploadContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, worktree: "/runner/work/corelink-server" });
    await expect(runBootstrapFinalize({ context: finalizeContext, config, migration, fetchImpl: harness.fetchImpl, command: harness.command, bootstrapReceipt: handoff, worktree: "/runner/work/corelink-server" })).rejects.toMatchObject({ code: "provider_command_failed" });
    expect(harness.state.commands.map(({ args }) => args[1])).toEqual(["upload", "secret", "deploy"]);
    expect(harness.state.commands.filter(({ args }) => args[1] === "secret")).toHaveLength(1);
    expect(harness.state.commands.filter(({ args }) => args[1] === "deploy")).toHaveLength(1);
    expect(harness.state.requests.some(({ method }) => method === "DELETE")).toBe(false);
  });

  it("accepts only the Stage A private version, with no secret, deployment, or public ingress", () => {
    const handoff = {
      worker_revision: "123e4567-e89b-42d3-a456-426614174000",
      worker_revision_tag: `b216-source-${"a".repeat(40)}`,
    };
    const inventory = {
      status: "complete",
      worker: { exists: true, inventory_count: 1 },
      versions: { status: "known", count: 1, items: [{ id: handoff.worker_revision, tag: handoff.worker_revision_tag }] },
      deployments: { status: "known", count: 0, active: null },
      subdomain: { status: "absent" },
      routes: { status: "unknown" },
    };
    expect(validateBootstrapFinalizeInventory(inventory, handoff)).toBe(true);
    for (const invalid of [
      { ...inventory, versions: { ...inventory.versions, count: 2, items: [...inventory.versions.items, { id: "223e4567-e89b-42d3-a456-426614174000", tag: "extra" }] } },
      { ...inventory, versions: { ...inventory.versions, items: [{ id: "223e4567-e89b-42d3-a456-426614174000", tag: handoff.worker_revision_tag }] } },
      { ...inventory, deployments: { status: "known", count: 1, active: { id: "323e4567-e89b-42d3-a456-426614174000" } } },
      { ...inventory, subdomain: { status: "known", enabled: true, previews_enabled: false } },
      { ...inventory, routes: { status: "known", count: 1 } },
    ]) errorCode(() => validateBootstrapFinalizeInventory(invalid, handoff), "worker_bootstrap_handoff_mismatch");
  });

  it("allows only SELECT statements in bootstrap D1 checks and never issues DDL", async () => {
    const calls = [];
    const api = async (path, options) => {
      calls.push({ path, options });
      return [{ success: true, results: [] }];
    };
    await expect(queryBootstrapDatabase(api, TARGET.databaseId, "SELECT name FROM d1_migrations ORDER BY name")).resolves.toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0].path).toContain(`/d1/database/${TARGET.databaseId}/query`);
    expect(calls[0].options.method).toBe("POST");
    expect(calls[0].options.body.sql).toMatch(/^SELECT\b/);
    for (const sql of [
      "CREATE TABLE extra (id TEXT)",
      "DROP TABLE dsr_alert_receipts",
      "ALTER TABLE dsr_alert_receipts ADD COLUMN extra TEXT",
      "INSERT INTO d1_migrations (name) VALUES ('other.sql')",
      "SELECT name FROM d1_migrations; DELETE FROM d1_migrations",
    ]) await expect(queryBootstrapDatabase(api, TARGET.databaseId, sql)).rejects.toMatchObject({ code: "bootstrap_database_query_not_read_only" });
    expect(calls).toHaveLength(1);
  });

  it("validates the documented readback deployment active shape before recording Stage B", () => {
    const versionId = "123e4567-e89b-42d3-a456-426614174000";
    const inventory = {
      worker: { exists: true },
      deployments: {
        status: "known",
        count: 1,
        active: { id: "223e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: versionId, percentage: 100 }] },
      },
      routes: { status: "unknown" },
      subdomain: { status: "known", enabled: false, previews_enabled: false },
    };
    expect(validateBootstrapDeployedInventory(inventory, versionId)).toBe(true);
    errorCode(() => validateBootstrapDeployedInventory({ ...inventory, deployments: { ...inventory.deployments, active: null } }, versionId), "worker_revision_readback_mismatch");
    errorCode(() => validateBootstrapDeployedInventory({ ...inventory, deployments: { ...inventory.deployments, active: { deployments: inventory.deployments.active } } }, versionId), "worker_revision_readback_mismatch");
  });

  it("pins config and sole migration bytes and rejects placeholder or target drift", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    expect(validateTrackedInputs(config, migration)).toBe(true);
    errorCode(() => validateTrackedInputs(config.replace(TARGET.accountId, "f".repeat(32)), migration), "wrangler_config_drift");
    errorCode(() => validateTrackedInputs(config, `${migration}\nCREATE TABLE extra (id TEXT);`), "migration_drift");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: TARGET.placeholderId }), "placeholder_uuid_rejected");
    errorCode(() => validateDatabaseIdentity({ name: "another-database", uuid: "123e4567-e89b-42d3-a456-426614174000" }), "database_identity_ambiguous");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: "123e4567-e89b-42d3-a456-426614174000" }), "database_identity_mismatch");
    errorCode(() => validateDatabaseIdentity({ name: TARGET.databaseName, uuid: TARGET.databaseId, account_id: "f".repeat(32) }), "database_account_mismatch");
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
      uuid: TARGET.databaseId,
    }], { result_info: { count: 1, page: 1, per_page: 100, total_count: 2 } });
    const result = await listNamedD1Databases(async (path) => {
      requests.push(path);
      return rows;
    });
    expect(result).toHaveLength(1);
    expect(validateDatabaseIdentity(selectNamedResource(result, TARGET.databaseName, "database"))).toBe(TARGET.databaseId);
    expect(requests).toEqual([`/accounts/${TARGET.accountId}/d1/database?name=${TARGET.databaseName}&page=1&per_page=100`]);
  });

  it("accepts a documented D1 array with omitted optional result_info metadata", async () => {
    const rows = [{ name: TARGET.databaseName, uuid: TARGET.databaseId }];
    const result = await listNamedD1Databases(async () => rows);
    expect(result).toEqual(rows);
  });

  it("paginates a full result page without metadata before deciding target uniqueness", async () => {
    const requests = [];
    const fullPage = Array.from({ length: 100 }, (_, index) => ({ name: `unrelated-${index}` }));
    const target = { name: TARGET.databaseName, uuid: TARGET.databaseId };
    const result = await listNamedD1Databases(async (path) => {
      requests.push(path);
      return requests.length === 1 ? fullPage : [target];
    });
    expect(requests).toHaveLength(2);
    expect(selectNamedResource(result, TARGET.databaseName, "database")).toEqual(target);
  });

  it("rejects duplicate exact D1 names across pages and contradictory pagination metadata", async () => {
    const duplicate = { name: TARGET.databaseName, uuid: TARGET.databaseId };
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
          result: [{ name: TARGET.databaseName, uuid: TARGET.databaseId }],
          result_info: { count: 1, page: 1, per_page: 100, total_count: 2 },
        });
      }
      if (url.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (url.includes(`/d1/database/${TARGET.databaseId}/query`)) {
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
    expect(workflow).toContain("bootstrap_once:");
    expect(workflow).toContain("default: false");
    expect(workflow).toContain("type: boolean");
    expect(workflow).not.toContain("inputs.target");
    expect(workflow).not.toContain("inputs.command");
    expect(workflow).not.toContain("inputs.ref");
    expect(workflow).toContain("runs-on: ubuntu-24.04");
    expect(workflow).toContain("environment:\n      name: b216-receiver-nonprod");
    expect(workflow).toContain("one independent approval from either named reviewer");
    expect(workflow).toContain("not a two-approval quorum");
    expect(workflow).toContain("github.repository == 'HuGR-dev/corelink-server'");
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain("secrets.B216_CF_RECEIVER_WRITE_TOKEN");
    expect(workflow).toContain("secrets.B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(workflow).not.toMatch(/^  (push|pull_request|schedule):/m);
    const inputReferences = [...workflow.matchAll(/\$\{\{\s*!?inputs\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g)].map((match) => match[1]);
    expect(inputReferences.length).toBeGreaterThan(0);
    expect(new Set(inputReferences)).toEqual(new Set(["readback_only", "bootstrap_once"]));
    const uploadJob = workflow.split("  bootstrap_upload:")[1]?.split("  bootstrap_finalize:")[0] ?? "";
    const finalizeJob = workflow.split("  bootstrap_finalize:")[1] ?? "";
    expect(uploadJob).toContain("name: b216-receiver-bootstrap");
    expect(uploadJob).toContain("B216_BOOTSTRAP_STAGE: upload");
    expect(uploadJob).toContain("secrets.B216_CF_RECEIVER_BOOTSTRAP_TOKEN");
    expect(uploadJob).not.toContain("B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(uploadJob).not.toContain("B216_CF_RECEIVER_WRITE_TOKEN");
    expect(uploadJob).not.toContain("versions deploy");
    expect(finalizeJob).toContain("name: b216-receiver-nonprod");
    expect(finalizeJob).toContain("B216_BOOTSTRAP_STAGE: finalize");
    expect(finalizeJob).toContain("secrets.B216_CF_RECEIVER_WRITE_TOKEN");
    expect(finalizeJob).toContain("secrets.B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(finalizeJob).not.toContain("B216_CF_RECEIVER_BOOTSTRAP_TOKEN");
    expect(finalizeJob).toContain("needs: [validate_dispatch_mode, bootstrap_upload]");
    const stageA = route.slice(route.indexOf("export async function runBootstrapUpload"), route.indexOf("export async function runBootstrapFinalize"));
    const stageB = route.slice(route.indexOf("export async function runBootstrapFinalize"), route.indexOf("async function queryDatabase"));
    expect(stageA).not.toContain('"versions", "secret", "put"');
    expect(stageA).not.toContain('"versions", "deploy"');
    expect(stageB.indexOf('"versions", "secret", "put"')).toBeGreaterThanOrEqual(0);
    expect(stageB.indexOf('"versions", "secret", "put"')).toBeLessThan(stageB.indexOf('"versions", "deploy"'));
    expect(stageA + stageB).not.toContain("d1 migrations apply");
    expect(workflow).not.toContain("secrets." + "CF_API_TOKEN");
    expect(workflow).not.toContain("secrets." + "CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toContain("env.CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toMatch(/runs-on:\s*\[?self-hosted/i);
    expect(route).not.toMatch(/method:\s*["']DELETE["']/i);
  });
});
