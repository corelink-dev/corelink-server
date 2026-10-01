import { createHash } from "node:crypto";

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
const TOKEN_DIAGNOSTIC_TIMEOUT_MS = 45_000;
const TOKEN_ID = /^[0-9a-f]{32}$/i;

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

// Cloudflare verifies user-owned tokens under /user/tokens and account-owned
// tokens under /accounts/{account_id}/tokens. An account-owned token gets 401
// from /user/tokens/verify, so the account pair is allowed for the fixed target
// account only; every other account ID is rejected.
const ACCOUNT_TOKENS_PATH = `/accounts/${READBACK_TARGET.accountId}/tokens`;

export function assertTokenDiagnosticPath(path) {
  if (path === "/user/tokens/verify") return true;
  if (/^\/user\/tokens\/[0-9a-f]{32}$/i.test(path)) return true;
  if (path === `${ACCOUNT_TOKENS_PATH}/verify`) return true;
  if (path.startsWith(`${ACCOUNT_TOKENS_PATH}/`) && TOKEN_ID.test(path.slice(ACCOUNT_TOKENS_PATH.length + 1))) return true;
  fail("token_diagnostic_path_rejected");
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
      ? {
        status: "known",
        count: script.routes.length,
        pattern_sha256: script.routes
          .map((route) => createHash("sha256").update(route.pattern, "utf8").digest("hex"))
          .sort(),
      }
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

const TOKEN_KINDS = Object.freeze(["user", "account", "unknown"]);

function allowlistedHttpStatus(httpStatus) {
  return Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599 ? httpStatus : null;
}

// One verify exchange: the numeric status and an error class, never the body.
function verifyExchangeDiagnostic({ httpStatus = null, errorClass = "not_attempted" } = {}) {
  return Object.freeze({ http_status: allowlistedHttpStatus(httpStatus), error_class: errorClass });
}

function tokenVerificationDiagnostic({
  httpStatus = null,
  errorClass = "not_attempted",
  activeStatus = "unknown",
  tokenIdShape = "not_checked",
  tokenKind = "unknown",
  userVerify = verifyExchangeDiagnostic(),
  accountVerify = verifyExchangeDiagnostic(),
} = {}) {
  return Object.freeze({
    http_status: allowlistedHttpStatus(httpStatus),
    error_class: errorClass,
    active_status: activeStatus,
    token_id_shape: tokenIdShape,
    token_kind: TOKEN_KINDS.includes(tokenKind) ? tokenKind : "unknown",
    user_verify: userVerify,
    account_verify: accountVerify,
  });
}

function unknownTokenPolicyDiagnostic(status = "unknown_response", tokenActive = null, verification = tokenVerificationDiagnostic()) {
  return Object.freeze({
    status,
    token_active: tokenActive,
    account_5128_scope: null,
    workers_admin_on_5128: null,
    verification,
  });
}

// User- and account-owned token details share one policy shape: account-level
// resources are keyed `com.cloudflare.api.account.<account_id>`, so the same
// summary applies to both token kinds.
function summarizeTokenPolicies(policies) {
  if (!Array.isArray(policies)) return unknownTokenPolicyDiagnostic("policy_unknown", true);
  let accountScoped = false;
  let scopeUnclassified = false;
  let adminOnTargetAccount = false;
  let adminDeniedOnTargetAccount = false;
  for (const policy of policies) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)
      || !["allow", "deny"].includes(policy.effect)
      || !Array.isArray(policy.permission_groups)
      || !policy.resources || typeof policy.resources !== "object" || Array.isArray(policy.resources)) {
      return unknownTokenPolicyDiagnostic("policy_unknown", true);
    }
    const targetResource = `com.cloudflare.api.account.${READBACK_TARGET.accountId}`;
    for (const [resourceName, resourceValue] of Object.entries(policy.resources)) {
      const accountResource = /^com\.cloudflare\.api\.account\.([0-9a-f]{32})$/i.test(resourceName);
      if (!accountResource || resourceValue !== "*") {
        scopeUnclassified = true;
        continue;
      }
    }
    const targetIncluded = Object.entries(policy.resources)
      .some(([resourceName, resourceValue]) => resourceName.toLowerCase() === targetResource && resourceValue === "*");
    if (policy.effect === "allow" && targetIncluded) accountScoped = true;
    for (const group of policy.permission_groups) {
      if (!group || typeof group !== "object" || Array.isArray(group) || typeof group.name !== "string") {
        return unknownTokenPolicyDiagnostic("policy_unknown", true);
      }
      if (targetIncluded && group.name === "Workers Admin") {
        if (policy.effect === "allow") adminOnTargetAccount = true;
        if (policy.effect === "deny") adminDeniedOnTargetAccount = true;
      }
    }
  }
  if (scopeUnclassified) return unknownTokenPolicyDiagnostic("policy_scope_unknown", true);
  if (adminOnTargetAccount && adminDeniedOnTargetAccount) {
    return unknownTokenPolicyDiagnostic("policy_conflict", true);
  }
  return Object.freeze({
    status: "details_read",
    token_active: true,
    account_5128_scope: accountScoped,
    workers_admin_on_5128: accountScoped ? adminOnTargetAccount : false,
  });
}

export async function readTokenPolicyDiagnostic({ apiToken, fetchImpl = fetch, now = () => Date.now() } = {}) {
  if (typeof apiToken !== "string" || apiToken.length === 0) return unknownTokenPolicyDiagnostic("token_missing");
  const deadline = now() + TOKEN_DIAGNOSTIC_TIMEOUT_MS;
  const request = async (path) => {
    assertTokenDiagnosticPath(path);
    const remaining = deadline - now();
    if (remaining <= 0) return { kind: "timeout", exchange: verifyExchangeDiagnostic({ errorClass: "timeout" }) };
    let response;
    try {
      response = await fetchImpl(`${API}${path}`, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(remaining),
        headers: { authorization: `Bearer ${apiToken}`, accept: "application/json" },
      });
    } catch (error) {
      const timedOut = error instanceof Error && error.name === "TimeoutError";
      return { kind: timedOut ? "timeout" : "transport_unknown", exchange: verifyExchangeDiagnostic({ errorClass: timedOut ? "timeout" : "transport_error" }) };
    }
    if (response.status !== 200) {
      return {
        kind: response.status === 403 ? "unknown_access" : "http_unknown",
        exchange: verifyExchangeDiagnostic({ httpStatus: response.status, errorClass: "http_response" }),
      };
    }
    let payload;
    try { payload = await response.json(); } catch {
      return { kind: "response_unknown", exchange: verifyExchangeDiagnostic({ httpStatus: response.status, errorClass: "malformed_json" }) };
    }
    return payload?.success === true && payload.result && typeof payload.result === "object" && !Array.isArray(payload.result)
      ? { kind: "ok", result: payload.result, exchange: verifyExchangeDiagnostic({ httpStatus: response.status, errorClass: "none" }) }
      : { kind: "response_unknown", exchange: verifyExchangeDiagnostic({ httpStatus: response.status, errorClass: "malformed_payload" }) };
  };

  // A user-owned token verifies at /user/tokens/verify. An account-owned token
  // is rejected there with 401, so only a 401 or 403 earns one retry at the
  // fixed account's verify endpoint. Whichever endpoint succeeds decides the
  // token kind and therefore which details path is read.
  const userVerification = await request("/user/tokens/verify");
  const accountVerification = userVerification.kind !== "ok" && [401, 403].includes(userVerification.exchange.http_status)
    ? await request(`${ACCOUNT_TOKENS_PATH}/verify`)
    : null;
  const verification = accountVerification ?? userVerification;
  const tokenKind = verification.kind !== "ok" ? "unknown" : verification === accountVerification ? "account" : "user";
  const exchanges = {
    tokenKind,
    userVerify: userVerification.exchange,
    accountVerify: accountVerification?.exchange ?? verifyExchangeDiagnostic(),
  };
  if (verification.kind !== "ok") {
    const denied = [userVerification, accountVerification].some((attempt) => attempt?.kind === "unknown_access");
    return unknownTokenPolicyDiagnostic(denied ? "unknown_access" : "verify_unknown", null, tokenVerificationDiagnostic({
      httpStatus: verification.exchange.http_status,
      errorClass: verification.exchange.error_class,
      ...exchanges,
    }));
  }
  const tokenStatus = verification.result.status;
  const activeStatus = tokenStatus === "active" ? "active" : ["disabled", "expired"].includes(tokenStatus) ? "inactive" : "other";
  const tokenIdShape = typeof verification.result.id !== "string" ? "missing" : TOKEN_ID.test(verification.result.id) ? "valid_32_hex" : "malformed";
  const verificationDiagnostic = tokenVerificationDiagnostic({
    httpStatus: verification.exchange.http_status,
    errorClass: ["active", "disabled", "expired"].includes(tokenStatus) && (activeStatus !== "active" || tokenIdShape === "valid_32_hex")
      ? "none"
      : "malformed_verification_fields",
    activeStatus,
    tokenIdShape,
    ...exchanges,
  });
  if (["disabled", "expired"].includes(tokenStatus)) return unknownTokenPolicyDiagnostic("inactive", false, verificationDiagnostic);
  if (tokenStatus !== "active" || tokenIdShape !== "valid_32_hex") {
    return unknownTokenPolicyDiagnostic("verify_unknown", null, verificationDiagnostic);
  }
  const tokensPath = tokenKind === "account" ? ACCOUNT_TOKENS_PATH : "/user/tokens";
  const details = await request(`${tokensPath}/${encodeURIComponent(verification.result.id)}`);
  if (details.kind === "unknown_access") return unknownTokenPolicyDiagnostic("unknown_access", true, verificationDiagnostic);
  if (details.kind !== "ok") return unknownTokenPolicyDiagnostic("details_unknown", true, verificationDiagnostic);
  return Object.freeze({ ...summarizeTokenPolicies(details.result.policies), verification: verificationDiagnostic });
}

export async function writeReadbackReceipt(context, options = {}) {
  const outputPath = join(context.runnerTemp || tmpdir(), "b216-receiver-readback-receipt.json");
  let receipt;
  try {
    receipt = await readWorkerInventory({ context, ...options });
    if (options.includeTokenPolicyDiagnostic === true) {
      try {
        receipt.token_policy_diagnostic = await readTokenPolicyDiagnostic({
          apiToken: context.apiToken,
          fetchImpl: options.fetchImpl,
          now: options.nowMs,
        });
      } catch {
        receipt.token_policy_diagnostic = unknownTokenPolicyDiagnostic();
      }
    }
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
