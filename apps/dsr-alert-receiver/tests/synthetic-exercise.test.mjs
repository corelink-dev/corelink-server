import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { TARGET } from "../scripts/deploy-route.mjs";
import { disableWorkersDev, runSyntheticReceiverExercise, safeWorkersDevUrl } from "../scripts/synthetic-exercise.mjs";

// The UUID the provider reports for the receiver D1; routes adopt it by exact name.
const DATABASE_ID = "c0ffee00-0b16-4000-8000-0000000006a1";
const workerPath = `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`;
const subdomainPath = `${workerPath}/subdomain`;
const versionId = "123e4567-e89b-42d3-a456-426614174000";
const sha = "a".repeat(40);
const context = {
  repository: TARGET.repository, ref: "refs/heads/main", sha, checkoutSha: sha,
  apiToken: "provider-token", receiverToken: "r".repeat(40), runId: "987654", runAttempt: "1",
};
const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
const migration = await readFile(new URL("../migrations/0001_alert_receipts.sql", import.meta.url), "utf8");
const activeDeployment = { id: "223e4567-e89b-42d3-a456-426614174000", versions: [{ version_id: versionId, percentage: 100 }] };
const activeVersion = {
  id: versionId,
  metadata: { annotations: { "workers/tag": `b216-${sha}` } },
  resources: { bindings: [
    { type: "d1", name: TARGET.databaseBinding, database_id: DATABASE_ID },
    { type: "secret_text", name: TARGET.workerSecret },
  ] },
};
const inventory = {
  status: "complete", worker: { exists: true }, routes: { status: "known", count: 0 },
  subdomain: { status: "known", enabled: true, previews_enabled: false },
  deployments: { status: "known", active: activeDeployment },
  versions: { status: "known", count: 1, items: [{ id: versionId, tag: `b216-${sha}` }] },
};

const ZONE_ID = "f".repeat(32);

function exerciseHarness({ receiverStatus = 202, readbackRows, version = activeVersion, ingress = {} } = {}) {
  const { domains = [], zoneRoutes = [], serviceRoutes = [], zonesStatus = 200, serviceRoutesStatus = 200 } = ingress;
  const state = { workersDev: true, preview: false, receiverCalls: [], providerCalls: [], receiptRow: null };
  const tables = [
    { name: "d1_migrations", sql: "CREATE TABLE d1_migrations (name TEXT PRIMARY KEY)" },
    { name: "dsr_alert_receipts", sql: migration.replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE") },
  ];
  const fetchProvider = async (url, options = {}) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(/^\/client\/v4(?=\/)/, "");
    state.providerCalls.push({ path, method: options.method ?? "GET", body: options.body ? JSON.parse(options.body) : undefined });
    const json = (result) => Response.json({ success: true, result });
    const rejected = (status) => Response.json({ success: false, result: null }, { status });
    if (path === `/accounts/${TARGET.accountId}`) return json({ id: TARGET.accountId });
    // The zero-ingress proof: account custom domains, zone list, zone routes, service routes.
    if (path === `/accounts/${TARGET.accountId}/workers/domains`) return json(domains);
    if (path === "/zones") return zonesStatus === 200 ? Response.json({ success: true, result: [{ id: ZONE_ID }], result_info: { page: 1, per_page: 50, count: 1, total_count: 1, total_pages: 1 } }) : rejected(zonesStatus);
    if (path === `/zones/${ZONE_ID}/workers/routes`) return json(zoneRoutes);
    if (path === `/accounts/${TARGET.accountId}/workers/services/${TARGET.workerName}/environments/production/routes`) return serviceRoutesStatus === 200 ? json(serviceRoutes) : rejected(serviceRoutesStatus);
    if (path === `/accounts/${TARGET.accountId}/d1/database`) return json([{ name: TARGET.databaseName, uuid: DATABASE_ID, account_id: TARGET.accountId }]);
    if (path.endsWith(`/d1/database/${DATABASE_ID}/query`)) {
      const { sql, params = [] } = JSON.parse(options.body);
      if (sql.includes("sqlite_master")) return json([{ success: true, results: tables }]);
      if (sql.includes("d1_migrations")) return json([{ success: true, results: [{ name: TARGET.migration }] }]);
      const rows = readbackRows ?? (state.receiptRow?.event_id === params[0] ? [state.receiptRow] : []);
      return json([{ success: true, results: rows }]);
    }
    if (path === `${workerPath}/deployments`) return json({ deployments: [activeDeployment] });
    if (path === `${workerPath}/versions/${versionId}`) return json(version);
    if (path === `${workerPath}/secrets`) return json([{ name: TARGET.workerSecret }]);
    if (path === subdomainPath && (options.method ?? "GET") === "POST") {
      const body = JSON.parse(options.body);
      state.workersDev = body.enabled;
      state.preview = body.previews_enabled;
      return json({ success: true });
    }
    if (path === subdomainPath) return json({ enabled: state.workersDev, previews_enabled: state.preview });
    if (path === `/accounts/${TARGET.accountId}/workers/subdomain`) return json({ subdomain: "corelink-team" });
    throw new Error(`unexpected provider request ${path}`);
  };
  const fetchReceiver = async (url, options) => {
    state.receiverCalls.push({ url, options, envelope: JSON.parse(options.body) });
    if (receiverStatus !== 202) return Response.json({ accepted: false }, { status: receiverStatus });
    const envelope = JSON.parse(options.body);
    state.receiptRow = {
      event_id: envelope.event_id, schema_version: 1, event: envelope.event,
      severity: envelope.severity, component: envelope.component, exhausted: 1,
      requeue_count: 1, received_at_ms: 1780000000000,
    };
    return Response.json({ accepted: true, duplicate: false }, { status: 202 });
  };
  return { state, fetchProvider, fetchReceiver };
}

describe("B-216 receiver-only synthetic operator", () => {
  it("forms only the fixed Worker HTTPS URL from a safe account subdomain", () => {
    expect(safeWorkersDevUrl("corelink-team")).toBe(`https://${TARGET.workerName}.corelink-team.workers.dev/`);
    for (const subdomain of ["", "Corelink", "example.com", "../x", "x/y", "-bad", "bad-"]) {
      expect(() => safeWorkersDevUrl(subdomain)).toThrow("workers_dev_subdomain_ambiguous");
    }
  });

  it("sends one synthetic alert, verifies its exact D1 row, then disables public and preview ingress", async () => {
    const harness = exerciseHarness();
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver, now: () => "2026-09-30T00:00:00.000Z" });
    expect(receipt.status).toBe("complete");
    expect(receipt.alert_acceptance).toBe("http_202_accepted");
    expect(receipt.durable_receipt).toBe("exact_row_read_back");
    expect(receipt.workers_dev_cleanup).toBe("disabled");
    expect(receipt.cleanup_failures).toEqual([]);
    expect(harness.state.receiverCalls).toHaveLength(1);
    const call = harness.state.receiverCalls[0];
    expect(call.url).toBe(`https://${TARGET.workerName}.corelink-team.workers.dev/`);
    expect(call.options.method).toBe("POST");
    expect(call.options.redirect).toBe("error");
    expect(call.options.headers.authorization).toBe(`Bearer ${context.receiverToken}`);
    expect(call.envelope).toEqual({ schema_version: 1, event: "dsr.erasure.dead_letter", severity: "critical", component: "dsr-erasure-dlq", event_id: receipt.event_id, exhausted: true, requeue_count: 1 });
    expect(Object.keys(call.envelope).sort()).toEqual(["component", "event", "event_id", "exhausted", "requeue_count", "schema_version", "severity"]);
    const durableQuery = harness.state.providerCalls.find(({ path, body }) => path.endsWith(`/d1/database/${DATABASE_ID}/query`) && body?.sql.includes("WHERE event_id"));
    expect(durableQuery.body.params).toEqual([receipt.event_id]);
    expect(harness.state.workersDev).toBe(false);
    expect(harness.state.preview).toBe(false);
  });

  it("does not retry an unaccepted receiver POST, still disables ingress, and fails closed", async () => {
    const harness = exerciseHarness({ receiverStatus: 503 });
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt.status).toBe("failed_closed");
    expect(receipt.alert_acceptance).toBe("not_accepted");
    expect(receipt.workers_dev_cleanup).toBe("disabled");
    expect(harness.state.receiverCalls).toHaveLength(1);
    expect(harness.state.workersDev).toBe(false);
  });

  it("disables only the fixed workers.dev endpoint and verifies the postimage", async () => {
    const calls = [];
    const api = async (requestedPath, options = {}) => {
      calls.push({ path: requestedPath, ...options });
      return calls.length === 1
        ? { enabled: true, previews_enabled: true }
        : calls.length === 2
          ? { success: true }
          : { enabled: false, previews_enabled: false };
    };
    const result = await disableWorkersDev({ api, now: () => "2026-09-30T00:00:00.000Z" });
    expect(result).toEqual({ status: "disabled", captured_at: "2026-09-30T00:00:00.000Z", workers_dev_before: true, previews_before: true, workers_dev_after: false, previews_after: false });
    expect(calls.map(({ path: requestedPath, method }) => [requestedPath, method ?? "GET"])).toEqual([[subdomainPath, "GET"], [subdomainPath, "POST"], [subdomainPath, "GET"]]);
    expect(calls[1].body).toEqual({ enabled: false, previews_enabled: false });
  });

  it("does not write when workers.dev and previews are already disabled", async () => {
    const calls = [];
    const result = await disableWorkersDev({
      api: async (requestedPath, options = {}) => { calls.push({ requestedPath, ...options }); return { enabled: false, previews_enabled: false }; },
    });
    expect(result.status).toBe("already_disabled");
    expect(calls).toEqual([{ requestedPath: subdomainPath }]);
  });

  // PR #2880 round-2 review, reproduced: extra production bindings on the active
  // revision passed the presence-only checks and the authenticated POST was sent.
  it.each([
    ["a production D1", { type: "d1", name: "PROD_DB", database_id: "123e4567-e89b-42d3-a456-426614174000" }],
    ["a corelink-api service", { type: "service", name: "API", service: "corelink-api" }],
    ["a production secret", { type: "secret_text", name: "PRODUCTION_SECRET" }],
  ])("sends nothing when the active revision also binds %s", async (_name, extra) => {
    const harness = exerciseHarness({ version: { ...activeVersion, resources: { bindings: [...activeVersion.resources.bindings, extra] } } });
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt.status).toBe("failed_closed");
    expect(receipt.failure_code).toBe("worker_revision_bindings_not_exact");
    expect(harness.state.receiverCalls).toHaveLength(0);
    expect(receipt.alert_acceptance).toBe("not_attempted");
    expect(receipt.workers_dev_cleanup).toBe("disabled");
  });

  it("sends nothing when the reproduced production bindings are all present together", async () => {
    const harness = exerciseHarness({ version: { ...activeVersion, resources: { bindings: [
      ...activeVersion.resources.bindings,
      { type: "d1", name: "PROD_DB", database_id: "123e4567-e89b-42d3-a456-426614174000" },
      { type: "service", name: "API", service: "corelink-api" },
      { type: "secret_text", name: "PRODUCTION_SECRET" },
    ] } } });
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt).toMatchObject({ status: "failed_closed", failure_code: "worker_revision_bindings_not_exact", alert_acceptance: "not_attempted" });
    expect(harness.state.receiverCalls).toHaveLength(0);
  });

  // "b216-release" fails the existing postflight tag check; an upper-case hex tag
  // passes that case-insensitive check and is refused only by the route-owned one.
  it.each([
    ["b216-release", "worker_revision_tag_invalid"],
    [`b216-${"E".repeat(40)}`, "worker_revision_not_route_owned"],
  ])("sends nothing to an active revision tagged %s", async (tag, code) => {
    const harness = exerciseHarness({ version: { ...activeVersion, metadata: { annotations: { "workers/tag": tag } } } });
    const foreignInventory = { ...inventory, versions: { ...inventory.versions, items: [{ id: versionId, tag }] } };
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => foreignInventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt.failure_code).toBe(code);
    expect(harness.state.receiverCalls).toHaveLength(0);
  });

  it("proves zero ingress before sending, even when the inventory reports routes as unknown", async () => {
    const harness = exerciseHarness();
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => ({ ...inventory, routes: { status: "unknown" } }), fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt.status).toBe("complete");
    expect(receipt.ingress_preflight).toEqual({ zones_checked: 1, zone_routes: 0, custom_domains: 0, service_routes: 0 });
    const ingressReads = harness.state.providerCalls.filter(({ path }) => path === "/zones" || path === `/zones/${ZONE_ID}/workers/routes` || path.endsWith("/workers/domains") || path.endsWith("/environments/production/routes"));
    expect(ingressReads).toHaveLength(4);
  });

  it.each([
    [{ domains: [{ id: "d1", hostname: "alerts.example.com", service: TARGET.workerName }] }, "worker_custom_domain_present"],
    [{ zoneRoutes: [{ id: "r1", pattern: "api.example.com/*", script: TARGET.workerName }] }, "worker_zone_route_present"],
    [{ serviceRoutes: [{ id: "r2", pattern: "api.example.com/alerts" }] }, "worker_zone_route_present"],
  ])("halts every write and sends nothing when external ingress reaches the receiver (%j)", async (ingress, code) => {
    const harness = exerciseHarness({ ingress });
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt).toMatchObject({ status: "failed_closed", failure_code: code, workers_dev_cleanup: "halted_external_ingress_detected", escalation: "lead_review_required" });
    expect(receipt).not.toHaveProperty("cleanup_failures");
    expect(harness.state.receiverCalls).toHaveLength(0);
    expect(harness.state.providerCalls.filter(({ method, path }) => method !== "GET" && !path.endsWith("/query"))).toHaveLength(0);
    expect(harness.state.workersDev).toBe(true);
  });

  it.each([
    [{ zonesStatus: 403 }, "ingress_zones_permission_denied", { endpoint: "zones_list", http_status: 403, cf_error_codes: [], message_class: "permission" }],
    [{ serviceRoutesStatus: 500 }, "ingress_service_routes_unreadable", { endpoint: "service_routes", http_status: 500, cf_error_codes: [], message_class: "server_error" }],
  ])("sends nothing when the ingress proof cannot be read (%j), names the read, and still disables workers.dev", async (ingress, code, readFailure) => {
    const harness = exerciseHarness({ ingress });
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider: harness.fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt).toMatchObject({ status: "failed_closed", failure_code: code, workers_dev_cleanup: "disabled", read_failure: readFailure, cleanup_failures: [] });
    expect(harness.state.receiverCalls).toHaveLength(0);
  });

  it("records a refused workers.dev disable as a cleanup failure, keeping the primary failure as is", async () => {
    const harness = exerciseHarness({ receiverStatus: 503 });
    const fetchProvider = async (url, options = {}) => {
      if ((options.method ?? "GET") === "POST" && new URL(url).pathname.endsWith("/subdomain")) {
        return Response.json({ success: false, errors: [{ code: 10013, message: `private failure for ${TARGET.accountId}` }] }, { status: 500 });
      }
      return harness.fetchProvider(url, options);
    };
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt).toMatchObject({ status: "failed_closed", failure_code: "receiver_acceptance_missing", workers_dev_cleanup: "ambiguous_do_not_retry" });
    expect(receipt.read_failure).toBeUndefined();
    expect(receipt.write_failure).toBeUndefined();
    expect(receipt.cleanup_failures).toEqual([{
      failure_code: "provider_response_rejected",
      write_failure: { endpoint: "worker_subdomain", http_status: 500, cf_error_codes: [10013], message_class: "server_error" },
    }]);
    expect(JSON.stringify(receipt)).not.toContain("private failure");
  });

  it("records an unreadable cleanup state as a cleanup failure, beside the primary read failure", async () => {
    const harness = exerciseHarness({ ingress: { zonesStatus: 403 } });
    const fetchProvider = async (url, options = {}) => {
      if (new URL(url).pathname.endsWith(subdomainPath)) return Response.json({ success: false, errors: [{ code: 10000, message: "private" }] }, { status: 403 });
      return harness.fetchProvider(url, options);
    };
    const receipt = await runSyntheticReceiverExercise({ context, config, migration, readInventory: async () => inventory, fetchProvider, fetchReceiver: harness.fetchReceiver });
    expect(receipt).toMatchObject({
      status: "failed_closed",
      failure_code: "ingress_zones_permission_denied",
      read_failure: { endpoint: "zones_list", http_status: 403, cf_error_codes: [], message_class: "permission" },
      workers_dev_cleanup: "ambiguous_manual_disable_required",
    });
    expect(receipt.cleanup_failures).toEqual([{
      failure_code: "provider_response_rejected",
      read_failure: { endpoint: "worker_subdomain", http_status: 403, cf_error_codes: [10000], message_class: "authentication" },
    }]);
  });
});
