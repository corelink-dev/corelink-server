import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  TARGET,
  RouteError,
  isExternalIngressError,
  listNamedD1Databases,
  makeCloudflareApi,
  normalizeDeploymentList,
  proveNoExternalIngress,
  providerFailureFields,
  queryReadOnlyDatabase,
  recordCleanupFailure,
  selectNamedResource,
  selectPriorRevision,
  validateCandidateVersion,
  validateDatabaseIdentity,
  validateDispatch,
  validateInventoryPage,
  validateMigrationLedger,
  validatePostflight,
  validateReceiptSchema,
  validateRouteOwnedRevision,
} from "./deploy-route.mjs";
import { readWorkerInventory } from "./readback-route.mjs";

const fail = (code) => { throw new RouteError(code); };
const WORKER_PATH = `/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`;

export function safeWorkersDevUrl(accountSubdomain) {
  if (typeof accountSubdomain !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(accountSubdomain)) fail("workers_dev_subdomain_ambiguous");
  return `https://${TARGET.workerName}.${accountSubdomain}.workers.dev/`;
}

function validateActiveWorker(inventory, version, secrets, databaseId) {
  if (inventory.worker?.exists !== true || inventory.subdomain?.status !== "known"
    || inventory.subdomain.enabled !== true || inventory.subdomain.previews_enabled !== false) fail("worker_workers_dev_not_ready");
  if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
  const activeVersion = selectPriorRevision(normalizeDeploymentList({ deployments: [inventory.deployments?.active] }));
  if (!activeVersion || activeVersion !== inventory.deployments?.active?.versions?.[0]?.version_id) fail("worker_revision_readback_mismatch");
  const tag = inventory.versions?.items?.find((item) => item.id === activeVersion)?.tag;
  if (typeof tag !== "string") fail("worker_revision_readback_mismatch");
  validateCandidateVersion(version, databaseId, tag);
  validatePostflight({ versionId: activeVersion, deployment: inventory.deployments.active, bindings: version?.resources?.bindings ?? [], secrets, expectedTag: tag }, databaseId, tag);
  // The same exact check as rollback: route-created, and the receiver D1 and secret
  // are its only bindings. Extra production bindings refuse before any send.
  validateRouteOwnedRevision(version, databaseId);
  return activeVersion;
}

function validateDsrReceiptRow(rows, eventId) {
  if (!Array.isArray(rows) || rows.length !== 1) fail("synthetic_receipt_readback_ambiguous");
  const row = rows[0];
  if (row?.event_id !== eventId || row?.schema_version !== 1
    || row?.event !== "dsr.erasure.dead_letter" || row?.severity !== "critical"
    || row?.component !== "dsr-erasure-dlq" || row?.exhausted !== 1
    || row?.requeue_count !== 1 || !Number.isInteger(row?.received_at_ms)) fail("synthetic_receipt_readback_mismatch");
  return true;
}

export async function disableWorkersDev({ api, now = () => new Date().toISOString() }) {
  const subdomainPath = `${WORKER_PATH}/subdomain`;
  const before = await api(subdomainPath);
  if (!before || typeof before.enabled !== "boolean" || typeof before.previews_enabled !== "boolean") fail("workers_dev_disable_preimage_mismatch");
  if (before.enabled === false && before.previews_enabled === false) return { status: "already_disabled", captured_at: now(), workers_dev_before: false, previews_before: false, workers_dev_after: false, previews_after: false };
  await api(subdomainPath, { method: "POST", body: { enabled: false, previews_enabled: false } });
  const after = await api(subdomainPath);
  if (!after || after.enabled !== false || after.previews_enabled !== false) fail("workers_dev_disable_readback_mismatch");
  return { status: "disabled", captured_at: now(), workers_dev_before: before.enabled, previews_before: before.previews_enabled, workers_dev_after: false, previews_after: false };
}

export async function runSyntheticReceiverExercise({ context, config, migration, fetchProvider = fetch, fetchReceiver = fetch, readInventory = readWorkerInventory, receiptPath, now = () => new Date().toISOString() }) {
  const sha = validateDispatch(context);
  if (!/^\d{1,20}$/.test(context.runId ?? "") || !/^\d{1,6}$/.test(context.runAttempt ?? "")) fail("synthetic_run_identity_invalid");
  const api = makeCloudflareApi(context.apiToken, fetchProvider);
  const eventDigest = createHash("sha256").update(`${TARGET.repository}:${sha}:${context.runId}:${context.runAttempt}:b216-receiver-only-synthetic`).digest("hex");
  const eventId = `dsr-erasure-dlq:${eventDigest}`;
  const receipt = {
    schema_version: 1,
    issue: 1678,
    mode: "receiver_only_synthetic",
    repository: TARGET.repository,
    reviewed_main_sha: sha,
    run_id: context.runId,
    run_attempt: context.runAttempt,
    account_id: TARGET.accountId,
    worker_name: TARGET.workerName,
    database_name: TARGET.databaseName,
    database_id: null,
    binding: TARGET.databaseBinding,
    event_id: eventId,
    customer_data_included: false,
    source_queue_injected: false,
    alert_acceptance: "not_attempted",
    durable_receipt: "not_verified",
    workers_dev_cleanup: "not_needed",
    captured_at: now(),
    status: "started",
  };
  let workersDevWasEnabled = false;
  let exerciseError = null;
  let externalIngress = false;
  try {
    const account = await api(`/accounts/${TARGET.accountId}`);
    if (account?.id !== TARGET.accountId) fail("account_identity_mismatch");
    const database = selectNamedResource(await listNamedD1Databases(api), TARGET.databaseName, "database");
    const databaseId = api.adoptDatabase(validateDatabaseIdentity(database));
    receipt.database_id = databaseId;
    const tables = await queryReadOnlyDatabase(api, databaseId, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
    if (validateReceiptSchema(tables, migration) !== "applied") fail("database_schema_not_applied");
    validateMigrationLedger(await queryReadOnlyDatabase(api, databaseId, "SELECT name FROM d1_migrations ORDER BY name"));

    const inventory = await readInventory({
      context: { repository: context.repository, ref: context.ref, sha: context.sha, checkoutSha: context.checkoutSha, readbackOnly: "true", apiToken: context.apiToken },
      fetchImpl: fetchProvider,
      now,
    });
    if (inventory.status !== "complete" || inventory.worker?.exists !== true) fail("worker_target_missing");
    workersDevWasEnabled = inventory.subdomain?.status === "known" && inventory.subdomain.enabled === true;
    if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
    if (inventory.subdomain?.status !== "known" || inventory.subdomain.enabled !== true || inventory.subdomain.previews_enabled !== false) fail("worker_workers_dev_not_ready");

    const versionId = selectPriorRevision(normalizeDeploymentList(await api(`${WORKER_PATH}/deployments`)));
    if (!versionId) fail("worker_revision_readback_mismatch");
    const [version, secrets, accountSubdomain] = await Promise.all([
      api(`${WORKER_PATH}/versions/${versionId}`),
      api(`${WORKER_PATH}/secrets`),
      api(`/accounts/${TARGET.accountId}/workers/subdomain`),
    ]);
    validateActiveWorker(inventory, version, secrets, databaseId);
    // The same zero-ingress proof as deploy: no custom domain, no zone route and an
    // empty Worker route list. Unreadable or unknown refuses before any send.
    receipt.ingress_preflight = await proveNoExternalIngress(api, { workerExists: true });
    const endpoint = safeWorkersDevUrl(accountSubdomain?.subdomain);
    receipt.worker_revision = versionId;
    receipt.workers_dev_url = endpoint;
    receipt.database_schema = "exact_migration_applied";
    receipt.database_migration_ledger = [TARGET.migration];
    receipt.workers_dev_preflight = "enabled_previews_disabled";

    const envelope = {
      schema_version: 1,
      event: "dsr.erasure.dead_letter",
      severity: "critical",
      component: "dsr-erasure-dlq",
      event_id: eventId,
      exhausted: true,
      requeue_count: 1,
    };
    let response;
    try {
      response = await fetchReceiver(endpoint, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
        headers: { authorization: `Bearer ${context.receiverToken}`, "content-type": "application/json" },
        body: JSON.stringify(envelope),
      });
    } catch {
      receipt.alert_acceptance = "transport_ambiguous_no_retry";
      fail("receiver_transport_ambiguous");
    }
    let responseBody;
    try { responseBody = await response.json(); } catch { fail("receiver_response_ambiguous"); }
    if (response.status !== 202 || responseBody?.accepted !== true || responseBody?.duplicate !== false) {
      receipt.alert_acceptance = "not_accepted";
      fail("receiver_acceptance_missing");
    }
    receipt.alert_acceptance = "http_202_accepted";
    const rows = await queryReadOnlyDatabase(api, databaseId,
      "SELECT event_id, schema_version, event, severity, component, exhausted, requeue_count, received_at_ms FROM dsr_alert_receipts WHERE event_id = ?",
      [eventId]);
    validateDsrReceiptRow(rows, eventId);
    receipt.durable_receipt = "exact_row_read_back";
    receipt.received_at_ms = rows[0].received_at_ms;
  } catch (error) {
    exerciseError = error instanceof RouteError ? error.code : "synthetic_exercise_failed_closed";
    receipt.failure_code = exerciseError;
    Object.assign(receipt, providerFailureFields(error));
    externalIngress = isExternalIngressError(error);
  } finally {
    if (externalIngress) {
      // External ingress reaches the receiver: no further write, not even the
      // workers.dev disable. The lead decides.
      receipt.workers_dev_cleanup = "halted_external_ingress_detected";
      receipt.escalation = "lead_review_required";
    } else {
      receipt.cleanup_failures = [];
      try {
        const cleanupState = await api(`${WORKER_PATH}/subdomain`);
        workersDevWasEnabled ||= cleanupState?.enabled === true || cleanupState?.previews_enabled === true;
        if (typeof cleanupState?.enabled !== "boolean" || typeof cleanupState?.previews_enabled !== "boolean") fail("workers_dev_cleanup_state_ambiguous");
      } catch (cleanupError) {
        recordCleanupFailure(receipt, cleanupError);
        receipt.workers_dev_cleanup = "ambiguous_manual_disable_required";
      }
      if (workersDevWasEnabled && receipt.workers_dev_cleanup !== "ambiguous_manual_disable_required") {
        try {
          const cleanup = await disableWorkersDev({ api, now });
          receipt.workers_dev_cleanup = cleanup.status === "already_disabled" ? "already_disabled_verified" : cleanup.status;
          receipt.cleanup_completed_at = cleanup.captured_at;
        } catch (cleanupError) {
          recordCleanupFailure(receipt, cleanupError);
          receipt.workers_dev_cleanup = "ambiguous_do_not_retry";
        }
      } else if (receipt.workers_dev_cleanup !== "ambiguous_manual_disable_required") {
        receipt.workers_dev_cleanup = "already_disabled_verified";
      }
    }
  }
  receipt.status = exerciseError === null && receipt.alert_acceptance === "http_202_accepted"
    && receipt.durable_receipt === "exact_row_read_back" && receipt.workers_dev_cleanup === "disabled"
    ? "complete"
    : "failed_closed";
  if (receiptPath) {
    await mkdir(dirname(receiptPath), { recursive: true });
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  }
  return receipt;
}
