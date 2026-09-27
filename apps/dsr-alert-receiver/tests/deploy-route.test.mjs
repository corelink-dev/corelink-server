import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  RouteError,
  TARGET,
  makeCloudflareApi,
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
  });

  it("fails closed on duplicate provider names instead of choosing or creating again", () => {
    errorCode(() => selectNamedResource([
      { name: TARGET.databaseName },
      { name: TARGET.databaseName },
    ], TARGET.databaseName, "database"), "database_duplicate_name");
  });

  it("rejects truncated or inconsistent provider inventories instead of assuming a unique target", () => {
    expect(validateInventoryPage(Object.assign([{ name: "only-db" }], { result_info: { count: 1, page: 1, per_page: 100, total_count: 1 } }), "database", { requireTotalCount: true })).toHaveLength(1);
    const completeWorkerList = [{ id: TARGET.workerName }];
    expect(validateInventoryPage(completeWorkerList, "worker")).toHaveLength(1);
    expect(selectNamedResource(completeWorkerList, TARGET.workerName, "worker")).toEqual(completeWorkerList[0]);
    errorCode(() => selectNamedResource([
      { id: TARGET.workerName },
      { id: TARGET.workerName },
    ], TARGET.workerName, "worker"), "worker_duplicate_name");
    errorCode(() => validateInventoryPage(Object.assign([{ name: "first-page-db" }], { result_info: { count: 1, page: 1, per_page: 100, total_count: 101 } }), "database", { requireTotalCount: true }), "database_inventory_truncated");
    errorCode(() => validateInventoryPage(Object.assign([{ name: "only-db" }], { result_info: { count: 2, page: 1, per_page: 100, total_count: 1 } }), "database", { requireTotalCount: true }), "database_inventory_ambiguous");
    errorCode(() => validateInventoryPage([], "database", { requireTotalCount: true }), "database_inventory_ambiguous");
  });

  it("accepts only the exact empty or migrated schema and rejects unknown/partial state", async () => {
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    expect(validateReceiptSchema([], migration)).toBe("empty");
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

  it("does not retry an ambiguous D1 create or invoke a second create", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
    let creates = 0;
    const fetchImpl = async (url, options) => {
      if (url.endsWith(`/accounts/${TARGET.accountId}`)) return Response.json({ success: true, result: { id: TARGET.accountId } });
      if (url.includes("/d1/database?") || url.endsWith("/workers/scripts")) return Response.json({ success: true, result: [], result_info: { count: 0, page: 1, per_page: 100, total_count: 0 } });
      if (url.endsWith("/d1/database")) {
        creates += 1;
        expect(options.method).toBe("POST");
        return Response.json({ success: false, errors: [{ message: "provider body must stay private" }] }, { status: 503 });
      }
      throw new Error("unexpected provider request");
    };
    const command = () => { throw new Error("no Worker command before D1 create is confirmed"); };
    let rejection;
    try {
      await runRoute({ context: goodContext, config, migration, fetchImpl, command });
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(RouteError);
    expect(rejection.code).toBe("provider_response_rejected");
    expect(rejection.message).not.toContain("provider body must stay private");
    expect(creates).toBe(1);
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
