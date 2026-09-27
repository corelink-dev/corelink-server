import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const READBACK_TARGET = Object.freeze({
  repository: "HuGR-dev/corelink-server",
  accountId: "51284495e71acdb5a7677e7383ab026b",
  workerName: "corelink-dsr-b216-alert-receiver-20260927",
});

const API = "https://api.cloudflare.com/client/v4";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TAG = /^b216-(?:source-)?[0-9a-f]{40}$/i;
const PAGE_SIZE = 100;
const MAX_PAGES = 100;

export class ReadbackError extends Error {
  constructor(code) { super(code); this.name = "ReadbackError"; this.code = code; }
}

const fail = (code) => { throw new ReadbackError(code); };

export function validateReadbackContext(context) {
  if (context.repository !== READBACK_TARGET.repository) fail("repository_mismatch");
  if (context.ref !== "refs/heads/main") fail("main_ref_required");
  if (!/^[0-9a-f]{40}$/i.test(context.sha ?? "")) fail("exact_sha_required");
  if (context.checkoutSha !== context.sha) fail("checkout_sha_mismatch");
  if (context.readbackOnly !== "true") fail("readback_mode_required");
  if (!context.apiToken) fail("provider_token_missing");
  return context.sha.toLowerCase();
}

function safeId(value) { return typeof value === "string" && UUID.test(value) ? value : null; }

function checkedPage(result, info, page, kind) {
  if (!Array.isArray(result) || result.length > PAGE_SIZE) fail(`${kind}_inventory_ambiguous`);
  if (info !== undefined) {
    if (!info || typeof info !== "object" || Array.isArray(info)) fail(`${kind}_inventory_ambiguous`);
    if (info.page !== undefined && info.page !== page) fail(`${kind}_inventory_truncated`);
    if (info.per_page !== undefined && info.per_page !== PAGE_SIZE) fail(`${kind}_inventory_ambiguous`);
    if (info.count !== undefined && (!Number.isInteger(info.count) || info.count < result.length)) fail(`${kind}_inventory_ambiguous`);
    if (info.total_pages !== undefined && (!Number.isInteger(info.total_pages) || info.total_pages < page)) fail(`${kind}_inventory_ambiguous`);
    if (result.length < PAGE_SIZE && info.total_pages !== undefined && info.total_pages > page) fail(`${kind}_inventory_truncated`);
  }
  return result;
}

export function assertReadbackPath(path) {
  const root = `/accounts/${READBACK_TARGET.accountId}/workers/scripts`;
  if (path === root) return true;
  const child = new RegExp(`^${root}/${READBACK_TARGET.workerName}/(versions|deployments|subdomain)(?:\\?page=[1-9][0-9]*&per_page=${PAGE_SIZE})?$`);
  if (child.test(path)) return true;
  fail("provider_path_rejected");
}

function makeReadOnlyApi(token, fetchImpl) {
  return async (path, { absent404 = false } = {}) => {
    assertReadbackPath(path);
    let response;
    try {
      response = await fetchImpl(`${API}${path}`, {
        method: "GET",
        redirect: "error",
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
    } catch { fail("provider_transport_ambiguous"); }
    if (response.status === 404 && absent404) return { absent: true };
    if (!response.ok) fail(response.status === 404 ? "provider_target_not_found" : "provider_response_rejected");
    let payload;
    try { payload = await response.json(); } catch { fail("provider_response_ambiguous"); }
    if (payload?.success !== true) fail("provider_response_rejected");
    return { result: payload.result, resultInfo: payload.result_info };
  };
}

async function collectPages(api, endpoint, kind, responseKey, firstResponse = undefined) {
  const collected = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const suffix = `?page=${page}&per_page=${PAGE_SIZE}`;
    const response = page === 1 && firstResponse !== undefined ? firstResponse : await api(`${endpoint}${suffix}`);
    const rows = responseKey ? response.result?.[responseKey] : response.result;
    const checked = checkedPage(rows, response.resultInfo, page, kind);
    collected.push(...checked);
    if (checked.length < PAGE_SIZE) return collected;
  }
  fail(`${kind}_inventory_truncated`);
}

export async function readWorkerInventory({ context, fetchImpl = fetch, now = () => new Date().toISOString() }) {
  const sha = validateReadbackContext(context);
  const api = makeReadOnlyApi(context.apiToken, fetchImpl);
  const receipt = {
    schema_version: 1,
    repository: READBACK_TARGET.repository,
    ref: "refs/heads/main",
    sha,
    account_id: READBACK_TARGET.accountId,
    worker_name: READBACK_TARGET.workerName,
    captured_at: now(),
    status: "complete",
  };

  // Cloudflare's documented Worker Scripts list is a complete result array and
  // does not expose the paginated result_info contract used by other endpoints.
  const scriptInventory = await api(`/accounts/${READBACK_TARGET.accountId}/workers/scripts`);
  if (!Array.isArray(scriptInventory.result)) fail("worker_inventory_ambiguous");
  const scripts = scriptInventory.result;
  if (scriptInventory.resultInfo !== undefined && (!scriptInventory.resultInfo || typeof scriptInventory.resultInfo !== "object" || Array.isArray(scriptInventory.resultInfo))) fail("worker_inventory_ambiguous");
  const matches = scripts.filter((row) => row?.id === READBACK_TARGET.workerName);
  if (matches.length > 1) fail("worker_duplicate_name");
  const script = matches[0];
  receipt.worker = { exists: Boolean(script), inventory_count: scripts.length };
  receipt.routes = !script || !Object.hasOwn(script, "routes")
    ? { status: "unknown" }
    : Array.isArray(script.routes) && script.routes.every((route) => route && typeof route === "object" && typeof route.id === "string" && typeof route.pattern === "string" && route.script === READBACK_TARGET.workerName)
      ? { status: "known", count: script.routes.length }
      : fail("worker_routes_ambiguous");

  const workerPath = `/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}`;
  const versionResponse = await api(`${workerPath}/versions?page=1&per_page=${PAGE_SIZE}`, { absent404: true });
  const versions = versionResponse.absent
    ? null
    : await collectPages(api, `${workerPath}/versions`, "worker_versions", "items", versionResponse);
  if (script && versions === null) fail("worker_versions_ambiguous");
  receipt.versions = {
    status: versions === null ? "absent" : "known",
    ...(versions === null ? {} : {
    count: versions.length,
    items: versions.map((version) => {
      const id = safeId(version?.id);
      if (!id) fail("worker_versions_ambiguous");
      const rawTag = version?.metadata?.annotations?.["workers/tag"];
      return { id, tag: typeof rawTag === "string" && TAG.test(rawTag) ? rawTag : null };
    }),
    }),
  };

  const deploymentResponse = await api(`${workerPath}/deployments?page=1&per_page=${PAGE_SIZE}`, { absent404: true });
  const deployments = deploymentResponse.absent
    ? null
    : await collectPages(api, `${workerPath}/deployments`, "worker_deployments", "deployments", deploymentResponse);
  receipt.deployments = {
    status: deployments === null ? "absent" : "known",
    ...(deployments === null ? {} : {
    count: deployments.length,
    active: deployments.length === 0 ? null : (() => {
      const current = deployments[0];
      const id = safeId(current?.id);
      if (!id || !Array.isArray(current.versions) || current.versions.length === 0) fail("worker_deployments_ambiguous");
      const currentVersions = current.versions.map((version) => {
        const versionId = safeId(version?.version_id);
        if (!versionId || !Number.isInteger(version?.percentage) || version.percentage < 0 || version.percentage > 100) fail("worker_deployments_ambiguous");
        return { version_id: versionId, percentage: version.percentage };
      });
      return { id, versions: currentVersions };
    })(),
    }),
  };

  const subdomain = await api(`${workerPath}/subdomain`, { absent404: true });
  if (subdomain.absent) receipt.subdomain = { status: "absent" };
  else {
    if (!subdomain.result || typeof subdomain.result.enabled !== "boolean" || typeof subdomain.result.previews_enabled !== "boolean") fail("worker_subdomain_ambiguous");
    receipt.subdomain = { status: "known", enabled: subdomain.result.enabled, previews_enabled: subdomain.result.previews_enabled };
  }
  if (!script) {
    const hasVersions = versions !== null && versions.length > 0;
    const hasActiveDeployment = deployments?.some((deployment) => Array.isArray(deployment?.versions) && deployment.versions.some((version) => version?.percentage > 0)) ?? false;
    const enabledSubdomain = receipt.subdomain.status === "known" && (receipt.subdomain.enabled || receipt.subdomain.previews_enabled);
    receipt.inventory_consistency = hasActiveDeployment || enabledSubdomain
      ? "inconsistent_provider_inventory"
      : hasVersions ? "partial_version_only" : "worker_absent";
  }
  return receipt;
}

export async function writeReadbackReceipt(context, options = {}) {
  const outputPath = join(context.runnerTemp || tmpdir(), "b216-receiver-readback-receipt.json");
  let receipt;
  try {
    receipt = await readWorkerInventory({ context, ...options });
  } catch (error) {
    receipt = {
      schema_version: 1,
      repository: READBACK_TARGET.repository,
      ref: "refs/heads/main",
      sha: /^[0-9a-f]{40}$/i.test(context.sha ?? "") ? context.sha.toLowerCase() : null,
      account_id: READBACK_TARGET.accountId,
      worker_name: READBACK_TARGET.workerName,
      status: "failed_closed",
      failure_code: error instanceof ReadbackError ? error.code : "readback_internal_error",
    };
  }
  await mkdir(context.runnerTemp || tmpdir(), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  return receipt;
}
