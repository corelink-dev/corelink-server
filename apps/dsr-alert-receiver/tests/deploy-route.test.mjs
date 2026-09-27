import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  RouteError,
  TARGET,
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
  validateD1InventoryPage,
  validateMigrationLedger,
  validatePostflight,
  validateReceiptSchema,
  validateRollbackReadback,
  validateTrackedInputs,
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

describe("B-216 protected receiver route admission", () => {
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
      { name: "dsr_alert_receipts", sql: migration },
    ], migration)).toBe("applied");
    errorCode(() => validateReceiptSchema([
      reservedD1Table,
      { name: "unexpected_internal_table", sql: "CREATE TABLE unexpected_internal_table (id TEXT)" },
    ], migration), "database_schema_unknown");
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
    expect(workflow).toContain("workflow_dispatch: {}");
    expect(workflow).toContain("runs-on: ubuntu-24.04");
    expect(workflow).toContain("environment:\n      name: b216-receiver-nonprod");
    expect(workflow).toContain("one independent approval from either named reviewer");
    expect(workflow).toContain("not a two-approval quorum");
    expect(workflow).toContain("github.repository == 'HuGR-dev/corelink-server'");
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain("secrets.B216_CF_RECEIVER_WRITE_TOKEN");
    expect(workflow).toContain("secrets.B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(workflow).not.toMatch(/^\s*(inputs|push|pull_request|schedule):/m);
    expect(workflow).not.toContain("${{ inputs.");
    expect(workflow).not.toContain("secrets." + "CF_API_TOKEN");
    expect(workflow).not.toContain("secrets." + "CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toContain("env.CLOUDFLARE_API_TOKEN");
    expect(workflow).not.toMatch(/runs-on:\s*\[?self-hosted/i);
    expect(route).not.toMatch(/method:\s*["']DELETE["']/i);
  });
});
