import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { readWorkerInventory } from "./readback-route.mjs";
import { RECEIVER_TARGET, ReceiverTargetError, assertReceiverResourceName } from "./receiver-target.mjs";
import { classifyReadFailure, sanitizeReadFailure } from "./read-failure.mjs";

// The D1 database is adopted by its exact pinned name (D1 names are unique per
// account) rather than by a UUID frozen in source: the lead creates it once on the
// shared account, and every route re-resolves and re-checks it before use.
export const TARGET = Object.freeze({
  ...RECEIVER_TARGET,
  databaseBinding: "ALERT_RECEIPTS_DB",
  migration: "0001_alert_receipts.sql",
  apiTokenSecret: "STAGING_CF_WORKER_API_TOKEN",
  receiverSecret: "STAGING_DSR_DLQ_ALERT_AUTH_TOKEN",
  workerSecret: "DSR_ALERT_RECEIVER_TOKEN",
  placeholderId: "00000000-0000-0000-0000-000000000000",
  configSha256: "8b9aae44f049b14966c4a35b938c561785a40d0c924c0f5d7c6ffeb2ef2ea496",
  migrationSha256: "7b9819d1f155645d84b1037e8376063e46ff117dd4d57553b66e22c2d2822bb2",
});

// Cloudflare API permissions each workflow mode needs on account 6a1fc1c6…
// (one token: account resources = this account; zone resources = all zones of
// this account). A refused call is named in the receipt's `read_failure` /
// `write_failure` endpoint label, so a missing grant shows up by name.
//
// | mode / calls                                         | permission (resource)               |
// |------------------------------------------------------|-------------------------------------|
// | readback_only                                        |                                     |
// |   GET workers/scripts, …/versions, …/deployments,    | Workers Scripts: Read (account)     |
// |       …/subdomain                                    |                                     |
// |   GET user|accounts tokens/verify                    | none (a token verifies itself)      |
// |   GET token details (diagnostic only, optional)      | API Tokens: Read (user token) or    |
// |                                                      | Account API Tokens: Read (account)  |
// | deploy_once                                          |                                     |
// |   GET accounts/{id}                                  | Account Settings: Read (account)    |
// |   GET d1/database?name=…, POST d1/…/query,           | D1: Edit (account; covers read)     |
// |       wrangler d1 migrations apply                   |                                     |
// |   GET scripts list, deployments, versions, secrets,  | Workers Scripts: Read (account)     |
// |       subdomain, workers/domains, services/…/routes  |                                     |
// |   wrangler deploy / versions upload / secret put /   | Workers Scripts: Edit (account)     |
// |       versions deploy / rollback; POST subdomain;    |                                     |
// |       DELETE the receiver script (cleanup only)      |                                     |
// |   GET zones?account.id=…                             | Zone: Read (all zones of account)   |
// |   GET zones/{id}/workers/routes, services/…/routes   | Workers Routes: Read (all zones)    |
// | exercise_once                                        |                                     |
// |   GET accounts/{id}                                  | Account Settings: Read (account)    |
// |   GET d1 list, POST d1/…/query (SELECT only)         | D1: Edit (account; query endpoint)  |
// |   GET scripts, deployments, versions, secrets,       | Workers Scripts: Read (account)     |
// |       subdomain, workers/subdomain, workers/domains  |                                     |
// |   GET zones, zones/{id}/workers/routes,              | Zone: Read + Workers Routes: Read   |
// |       services/…/routes                              | (all zones of account)              |
// |   POST …/subdomain (workers.dev disable)             | Workers Scripts: Edit (account)     |
// | disable_workers_dev                                  |                                     |
// |   GET/POST …/subdomain                               | Workers Scripts: Edit (account)     |
//
// One key for every mode: Account Settings: Read, Workers Scripts: Edit, D1: Edit
// (account 6a only); Zone: Read, Workers Routes: Read (all zones of account 6a);
// optionally Account API Tokens: Read so readback can prove the key's own scope.

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

const PROVIDER_FAILURE_CLASSES = new Set([
  "provider_error_code",
  "ambiguous_provider_error_code",
  "process_exit",
  "spawn_failure",
]);
const WRANGLER_ERROR_CATEGORIES = new Set([
  "first_deploy_required",
  "waf_block",
  "malformed_api_response",
  "network_failure",
  "authentication_failed",
  "permission_denied",
  "resource_not_found",
  "rate_limited",
  "invalid_configuration",
  "api_request_rejected",
  "unknown_cli_failure",
]);
// Which Cloudflare API endpoint Wrangler named in its first failure. Only these
// labels are recorded; the path itself (account ID, Worker name) never is.
const WRANGLER_FAILURE_ENDPOINTS = new Set([
  "worker_service",
  "worker_script",
  "worker_secrets",
  "worker_deployments",
  "worker_settings",
  "worker_subdomain",
  "worker_versions",
  "worker_resource",
  "account_workers_subdomain",
  "d1_database",
  "user_or_membership",
  "other_endpoint",
  "ambiguous_report",
  "none_reported",
]);
// How far Wrangler got before it failed: it prints "Total Upload:" once the bundle
// is built and the pre-upload API checks passed, and "Uploaded <name>" once the
// script upload request succeeded.
const WRANGLER_FAILURE_PROGRESS = new Set(["before_bundle_report", "bundle_reported", "upload_reported"]);
// Whether the diagnosis rests on a Wrangler error block. Without one in the analysed
// window ("truncated" when stderr ran past it), nothing beyond unknown is claimed.
const WRANGLER_OUTPUT_STRUCTURES = new Set(["first_error_block", "no_structured_error", "truncated"]);
const MAX_PROVIDER_ERROR_CODES = 8;
// Bounds on how much Wrangler output is analysed. The first error block sits near
// the start of stderr (only warnings can precede it) and the progress lines near
// the start of stdout, so only the head of each is read.
const MAX_ANALYSED_CHARS = 256 * 1024;
const MAX_ROOT_BLOCK_LINES = 200;
const MAX_LINE_CHARS = 4096;
const AUTHENTICATION_ERROR_CODES = new Set([9106, 10000]);
const ANSI_SGR = /\u001b\[[0-9;]{0,32}[A-Za-z]/g;
const CODE_MARKER = /\[code:[ \t]{0,8}([^\]\r\n]{0,16})\]/gi;
const CODE_PREFIX = /\[code:/gi;
const ERROR_BANNER_PREFIX = "✘ [ERROR] ";
const REQUEST_NOTE = /^ {2}(?:GET|PUT|POST|PATCH|DELETE|HEAD) (\/\S{1,2048}) -> ([1-5]\d\d)(?: |$)/;
const API_REQUEST_BANNER = /^A request to the Cloudflare API (?:\((\/\S{1,2048})\) )?failed\.$/;
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const UPLOAD_REPORTED_LINE = new RegExp(`^Uploaded ${escapeRegExp(TARGET.workerName)} \\(\\d{1,6}(?:\\.\\d{1,3})? sec\\)$`);
const BUNDLE_REPORTED_LINE = /^Total Upload: \d{1,9}(?:\.\d{1,3})? [KM]iB \/ gzip: \d{1,9}(?:\.\d{1,3})? [KM]iB$/;

function boundedExitCode(value) {
  return Number.isInteger(value) && value >= 0 && value <= 255 ? value : null;
}

function boundedErrorCodes(value) {
  if (!Array.isArray(value)) return [];
  const codes = new Set();
  for (const code of value) {
    if (!Number.isInteger(code) || code < 0 || code > 999999) return [];
    codes.add(code);
    if (codes.size === MAX_PROVIDER_ERROR_CODES) break;
  }
  return [...codes];
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
    provider_error_codes: Object.freeze(boundedErrorCodes(value?.provider_error_codes)),
    process_exit_code: boundedExitCode(value?.process_exit_code),
    provider_error_category: WRANGLER_ERROR_CATEGORIES.has(value?.provider_error_category)
      ? value.provider_error_category
      : null,
    provider_failure_endpoint: WRANGLER_FAILURE_ENDPOINTS.has(value?.provider_failure_endpoint)
      ? value.provider_failure_endpoint
      : null,
    provider_http_status: Number.isInteger(value?.provider_http_status)
      && value.provider_http_status >= 100
      && value.provider_http_status <= 599
      ? value.provider_http_status
      : null,
    provider_progress: WRANGLER_FAILURE_PROGRESS.has(value?.provider_progress)
      ? value.provider_progress
      : null,
    provider_output_structure: WRANGLER_OUTPUT_STRUCTURES.has(value?.provider_output_structure)
      ? value.provider_output_structure
      : null,
  });
}

export function labelWranglerEndpoint(resource) {
  const path = String(resource).split("?", 1)[0];
  if (/^\/(?:user|memberships)(?:\/|$)/.test(path) || path === "/accounts") return "user_or_membership";
  const scoped = /^\/accounts\/[0-9a-f]{32}(\/.*)?$/i.exec(path);
  if (!scoped) return "other_endpoint";
  const rest = scoped[1] ?? "";
  if (/^\/workers\/services\/[^/]+$/.test(rest)) return "worker_service";
  if (/^\/workers\/scripts\/[^/]+$/.test(rest)) return "worker_script";
  const child = /^\/workers\/scripts\/[^/]+\/(secrets|deployments|settings|subdomain|versions)(?:\/[^/]+)?$/.exec(rest);
  if (child) return `worker_${child[1]}`;
  if (/^\/workers\/workers\/[^/]+$/.test(rest)) return "worker_resource";
  if (rest === "/workers/subdomain") return "account_workers_subdomain";
  if (/^\/d1\/database(?:\/|$)/.test(rest)) return "d1_database";
  return "other_endpoint";
}

// Wrangler prints each error as a "✘ [ERROR] <message>" banner at column 0, then
// note lines indented by two spaces. It indents every line of a note, including a
// response body it echoes, so a column-0 banner can only come from Wrangler. The
// first banner in stderr is the root failure; later blocks are Wrangler's own
// follow-up (for example whoami after a 10000) and must not change the diagnosis.
//
// The block counts only when it is complete inside the analysed window: its end,
// the next column-0 line or the end of stderr, must be visible, and no line may
// exceed the line or block caps. A cut block can be missing exactly what would
// contradict the visible part: the real request note after an echoed body, or the
// rest of a banner message. So a cut block is reported as truncated, and nothing is
// read from it.
const TRUNCATED_BLOCK = Object.freeze({ truncated: true });

// The single place where Wrangler output is cut to the analysed window, used for
// stdout and stderr alike. When the output runs past the window, the last line
// inside it is partial by definition (unless the window ends right after a newline)
// and is dropped, so no field is ever derived from a partial line. `truncated` says
// whether the lines stop before the true end of the output.
export function completeLinesInWindow(text, windowChars = MAX_ANALYSED_CHARS) {
  if (text.length <= windowChars) return { lines: text.replace(ANSI_SGR, "").split("\n"), truncated: false };
  const head = text.slice(0, windowChars);
  return { lines: head.slice(0, head.lastIndexOf("\n") + 1).replace(ANSI_SGR, "").split("\n"), truncated: true };
}

function rootErrorBlock({ lines, truncated }) {
  const start = lines.findIndex((line) => line.startsWith(ERROR_BANNER_PREFIX));
  if (start < 0) return truncated ? TRUNCATED_BLOCK : null;
  const message = lines[start].slice(ERROR_BANNER_PREFIX.length);
  if (message.length > MAX_LINE_CHARS) return TRUNCATED_BLOCK;
  const notes = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    if (index - start > MAX_ROOT_BLOCK_LINES) return TRUNCATED_BLOCK;
    const line = lines[index];
    if (line.trim() === "") continue;
    if (!line.startsWith("  ")) return { message, notes };
    if (line.length > MAX_LINE_CHARS) return TRUNCATED_BLOCK;
    notes.push(line);
  }
  // No complete line after the block ends it, so the block runs to the end of the
  // analysed lines: the end of stderr only when nothing was cut.
  return truncated ? TRUNCATED_BLOCK : { message, notes };
}

// The banner messages Wrangler 4.141.0 prints for the failures this route can name,
// matched exactly: captured in tests/fixtures/wrangler-4.141.0-failures.json, except
// the API timeout line, which is copied from the 4.141.0 error handler. Any other
// banner is an unrecognised failure and stays unknown_cli_failure.
const WAF_BLOCK_MESSAGE = "The Cloudflare API responded with a WAF block page instead of the expected JSON response";
const MALFORMED_RESPONSE_MESSAGE = "Received a malformed response from the API";
const NETWORK_FAILURE_MESSAGES = new Set(["fetch failed", "The request to Cloudflare's API timed out."]);
const FIRST_DEPLOY_MESSAGE = "You cannot upload a new version of a Worker that does not yet exist. Please run the `deploy` command first.";

// Category from the error messages the Cloudflare API returned, as Wrangler renders
// them under an API-request banner. Linear patterns only; order keeps the original
// precedence.
function categoryFromProviderMessages(lines) {
  const tests = [
    ["authentication_failed", (line) => /invalid api token|authentication (?:failed|error)|unauthorized/i.test(line)],
    ["permission_denied", (line) => /permission denied|missing permission|not authorized|not permitted/i.test(line)],
    ["resource_not_found", (line) => /\bnot found\b/i.test(line) && /\b(?:worker|script|resource)\b/i.test(line)],
    ["rate_limited", (line) => /rate limit|too many requests|\b429\b/i.test(line)],
    ["invalid_configuration", (line) => /invalid (?:wrangler )?config|configuration (?:is )?invalid|unknown configuration/i.test(line)],
  ];
  for (const [category, matches] of tests) {
    if (lines.some(matches)) return category;
  }
  return null;
}

function codeSummary(lines) {
  const codes = new Set();
  let wellFormed = 0;
  let prefixes = 0;
  for (const line of lines) {
    prefixes += (line.match(CODE_PREFIX) ?? []).length;
    for (const marker of line.matchAll(CODE_MARKER)) {
      if (!/^\d{1,6}$/.test(marker[1])) continue;
      wellFormed += 1;
      if (codes.size < MAX_PROVIDER_ERROR_CODES) codes.add(Number(marker[1]));
    }
  }
  return { codes: [...codes], wellFormed, prefixes };
}

// A WAF or malformed-response error names its request in a "<METHOD> <path> ->
// <status>" note, but the malformed case also echoes up to 100 characters of the
// response body as an earlier note. One request-shaped note is Wrangler's; more
// than one cannot be told apart, so none of them is believed.
function reportedRequest(notes) {
  const requests = [];
  for (const note of notes) {
    const match = REQUEST_NOTE.exec(note);
    if (match) requests.push(match);
  }
  if (requests.length === 0) return { endpoint: "none_reported", status: null };
  if (requests.length > 1) return { endpoint: "ambiguous_report", status: null };
  return { endpoint: labelWranglerEndpoint(requests[0][1]), status: Number(requests[0][2]) };
}

const UNKNOWN_DIAGNOSIS = Object.freeze({ category: "unknown_cli_failure", endpoint: "none_reported", status: null, codeLines: [] });

// Only an API-request block carries the API's own error codes and messages; every
// other recognised banner is classified by its exact message alone, and its notes
// (which may echo a response body) are never read for codes or categories.
function classifyRootBlock({ message, notes }) {
  if (message === WAF_BLOCK_MESSAGE) return { category: "waf_block", ...reportedRequest(notes), codeLines: [] };
  if (message === MALFORMED_RESPONSE_MESSAGE) return { category: "malformed_api_response", ...reportedRequest(notes), codeLines: [] };
  if (NETWORK_FAILURE_MESSAGES.has(message)) return { ...UNKNOWN_DIAGNOSIS, category: "network_failure" };
  if (message === FIRST_DEPLOY_MESSAGE) return { ...UNKNOWN_DIAGNOSIS, category: "first_deploy_required" };
  const apiRequest = API_REQUEST_BANNER.exec(message);
  if (!apiRequest) return UNKNOWN_DIAGNOSIS;
  const { codes } = codeSummary(notes);
  return {
    category: codes.some((code) => AUTHENTICATION_ERROR_CODES.has(code))
      ? "authentication_failed"
      : categoryFromProviderMessages(notes) ?? "api_request_rejected",
    endpoint: apiRequest[1] ? labelWranglerEndpoint(apiRequest[1]) : "none_reported",
    status: null,
    codeLines: notes,
  };
}

// `windowChars` exists so tests can move the analysed window across small captures;
// every caller in this route uses the default.
export function classifyWranglerFailure(result, { windowChars = MAX_ANALYSED_CHARS } = {}) {
  const processExitCode = boundedExitCode(result?.status);
  if (result?.error) {
    return sanitizeProviderFailure({ provider_failure_class: "spawn_failure", process_exit_code: processExitCode });
  }
  const stdout = typeof result?.stdout === "string" ? result.stdout : "";
  const stderr = typeof result?.stderr === "string" ? result.stderr : "";
  // Without a complete Wrangler error block in the analysed head of stderr there is
  // nothing to place as the first failure: no category, code, endpoint or status is
  // read from the remaining text, which may be a later follow-up or an echoed body.
  const root = rootErrorBlock(completeLinesInWindow(stderr, windowChars));
  const diagnosis = root && !root.truncated ? classifyRootBlock(root) : UNKNOWN_DIAGNOSIS;
  // Progress lines are Wrangler's own complete stdout lines, matched whole and
  // naming the fixed Worker; an echoed body is on stderr and indented, so it cannot
  // produce them.
  const stdoutLines = completeLinesInWindow(stdout, windowChars).lines;
  const { codes, wellFormed, prefixes } = codeSummary(diagnosis.codeLines);
  const details = {
    process_exit_code: processExitCode,
    provider_error_category: diagnosis.category,
    provider_error_codes: codes,
    provider_failure_endpoint: diagnosis.endpoint,
    provider_http_status: diagnosis.status,
    provider_progress: stdoutLines.some((line) => UPLOAD_REPORTED_LINE.test(line))
      ? "upload_reported"
      : stdoutLines.some((line) => BUNDLE_REPORTED_LINE.test(line)) ? "bundle_reported" : "before_bundle_report",
    provider_output_structure: root?.truncated ? "truncated" : root ? "first_error_block" : "no_structured_error",
  };
  if (wellFormed === 1 && prefixes === 1) {
    return sanitizeProviderFailure({ ...details, provider_failure_class: "provider_error_code", provider_error_code: codes[0] });
  }
  if (prefixes > 0) return sanitizeProviderFailure({ ...details, provider_failure_class: "ambiguous_provider_error_code" });
  return sanitizeProviderFailure({ ...details, provider_failure_class: "process_exit" });
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

// The adopted D1 UUID: a real UUID, never the source placeholder.
function adoptedDatabaseId(databaseId) {
  if (!isUuid(databaseId) || databaseId === TARGET.placeholderId) fail("database_identity_mismatch");
  return databaseId;
}

export function preparePrivateReceiverConfig(config, migration, databaseId, appDir) {
  validateTrackedInputs(config, migration);
  adoptedDatabaseId(databaseId);
  const workersDevSettings = [...config.matchAll(/^workers_dev\s*=\s*(true|false)\s*$/gm)];
  if (workersDevSettings.length !== 1 || workersDevSettings[0][1] !== "true") fail("private_config_drift");
  if (/^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(config)) fail("private_route_config_forbidden");
  const privateConfig = config
    .replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${databaseId}"`)
    .replace(/^workers_dev\s*=\s*true\s*$/m, "workers_dev = false")
    .replace('main = "src/index.ts"', `main = "${resolve(appDir, "src/index.ts")}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(appDir, "migrations")}"`);
  if (!privateConfig.includes('workers_dev = false') || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(privateConfig)) fail("private_config_drift");
  return privateConfig;
}

export function prepareInitialPrivateReceiverConfig(config, migration, databaseId, appDir) {
  const privateConfig = preparePrivateReceiverConfig(config, migration, databaseId, appDir);
  if (/^\s*preview_urls\s*=/im.test(privateConfig)) fail("private_config_drift");
  const guardedConfig = privateConfig.replace(/^workers_dev\s*=\s*false\s*$/m, "workers_dev = false\npreview_urls = false");
  if (!guardedConfig.includes("workers_dev = false\npreview_urls = false")
    || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(guardedConfig)) fail("private_config_drift");
  return guardedConfig;
}

export function prepareFinalReceiverConfig(config, migration, databaseId, appDir) {
  validateTrackedInputs(config, migration);
  adoptedDatabaseId(databaseId);
  if (/^\s*preview_urls\s*=/im.test(config)
    || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(config)) fail("private_config_drift");
  const finalConfig = config
    .replace(`database_id = "${TARGET.placeholderId}"`, `database_id = "${databaseId}"`)
    .replace('main = "src/index.ts"', `main = "${resolve(appDir, "src/index.ts")}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${resolve(appDir, "migrations")}"`)
    .replace(/^workers_dev\s*=\s*true\s*$/m, "workers_dev = true\npreview_urls = false");
  if (!finalConfig.includes("workers_dev = true\npreview_urls = false")
    || /^\s*(?:\[\[?routes\]\]?|routes\s*=|route\s*=)/im.test(finalConfig)) fail("private_config_drift");
  return finalConfig;
}

// Name refusal as a route failure: a protected production/staging name or anything
// other than the exact pinned receiver pair stops the route before a request.
export function requireReceiverResourceName(name, kind) {
  try {
    return assertReceiverResourceName(name, kind);
  } catch (error) {
    fail(error instanceof ReceiverTargetError ? error.code : "receiver_resource_name_refused");
  }
}

// Independent of the config hash pin: the tracked config must name exactly one
// Worker and one D1, and both must be the pinned receiver pair.
export function assertConfigTargetNames(config) {
  const names = [...config.matchAll(/^\s*name\s*=\s*"([^"\n]*)"\s*$/gm)].map((match) => match[1]);
  const databases = [...config.matchAll(/^\s*database_name\s*=\s*"([^"\n]*)"\s*$/gm)].map((match) => match[1]);
  if (names.length !== 1 || databases.length !== 1) fail("worker_target_drift");
  requireReceiverResourceName(names[0], "worker");
  requireReceiverResourceName(databases[0], "database");
  return true;
}

export function validateTrackedInputs(config, migration) {
  if (createHash("sha256").update(config).digest("hex") !== TARGET.configSha256) fail("wrangler_config_drift");
  if (createHash("sha256").update(migration).digest("hex") !== TARGET.migrationSha256) fail("migration_drift");
  assertConfigTargetNames(config);
  if (!config.includes(`account_id = "${TARGET.accountId}"`) || !config.includes(`name = "${TARGET.workerName}"`)) fail("worker_target_drift");
  if (!config.includes(`binding = "${TARGET.databaseBinding}"`) || !config.includes(`database_name = "${TARGET.databaseName}"`)) fail("database_target_drift");
  if (!config.includes(`database_id = "${TARGET.placeholderId}"`)) fail("placeholder_uuid_contract_drift");
  if (!config.includes(`migrations_dir = "migrations"`)) fail("migration_directory_drift");
  return true;
}

export function selectNamedResource(resources, expectedName, kind) {
  requireReceiverResourceName(expectedName, kind);
  if (!Array.isArray(resources)) fail(`${kind}_inventory_ambiguous`);
  const matches = resources.filter((resource) => (resource?.name ?? resource?.id) === expectedName);
  if (matches.length > 1) fail(`${kind}_duplicate_name`);
  return matches[0] ?? null;
}

// Adopts the receiver D1 by its exact pinned name on the pinned account. Its UUID
// comes from the provider, so it is checked for shape and consistency only.
export function validateDatabaseIdentity(database) {
  if (!database || database.name !== TARGET.databaseName) fail("database_identity_ambiguous");
  requireReceiverResourceName(database.name, "database");
  if (database.account_id !== undefined && database.account_id !== TARGET.accountId) fail("database_account_mismatch");
  if (database.uuid !== undefined && database.id !== undefined && database.uuid !== database.id) fail("database_identity_ambiguous");
  const id = database.uuid ?? database.id;
  if (id === TARGET.placeholderId) fail("placeholder_uuid_rejected");
  if (!isUuid(id)) fail("database_identity_ambiguous");
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

export function summarizeCustomRoutes(script) {
  if (!script || !Object.hasOwn(script, "routes")) return "unknown";
  if (!Array.isArray(script.routes)
    || script.routes.some((route) => !route || typeof route.id !== "string" || typeof route.pattern !== "string" || route.script !== TARGET.workerName)) fail("worker_routes_ambiguous");
  if (script.routes.length > 0) fail("worker_custom_route_present");
  return "absent";
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

export function validateInitialPrivateDeployment(inventory, expectedWorkerCount) {
  if (!inventory || inventory.status !== "complete"
    || inventory.worker?.exists !== true
    || !Number.isInteger(expectedWorkerCount)
    || inventory.worker.inventory_count !== expectedWorkerCount
    || inventory.versions?.status !== "known"
    || inventory.versions.count !== 1
    || !Array.isArray(inventory.versions.items)
    || inventory.versions.items.length !== 1
    || inventory.deployments?.status !== "known"
    || inventory.deployments.count !== 1
    || !inventory.deployments.active
    || inventory.subdomain?.status !== "known"
    || inventory.subdomain.enabled !== false
    || inventory.subdomain.previews_enabled !== false) fail("worker_initial_deployment_ambiguous");
  if (inventory.routes?.status === "known" && inventory.routes.count !== 0) fail("worker_custom_route_present");
  if (!new Set(["known", "unknown"]).has(inventory.routes?.status)) fail("worker_routes_ambiguous");
  const deploymentVersions = inventory.deployments.active.versions;
  if (!Array.isArray(deploymentVersions) || deploymentVersions.length !== 1
    || deploymentVersions[0]?.percentage !== 100
    || deploymentVersions[0]?.version_id !== inventory.versions.items[0]?.id
    || !isUuid(deploymentVersions[0]?.version_id)) fail("worker_initial_deployment_ambiguous");
  return deploymentVersions[0].version_id;
}

export function validateInitialPrivateVersion(version, expectedDatabaseId) {
  const bindings = version?.resources?.bindings;
  if (!isUuid(version?.id)
    || bindings?.some((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === expectedDatabaseId) !== true) fail("worker_database_binding_mismatch");
  if (bindings.some((binding) => binding?.type === "secret_text" && binding.name === TARGET.workerSecret)) fail("worker_initial_secret_present");
  return true;
}

const apiBase = "https://api.cloudflare.com/client/v4";

// A failed provider request carries its allowlisted classification: a GET as
// `readFailure`, anything else as `writeFailure` (see read-failure.mjs).
function providerRequestFailure(code, method, failure) {
  const error = new RouteError(code);
  if (method === "GET") error.readFailure = failure;
  else error.writeFailure = failure;
  return error;
}

// Recorded in a failure receipt when the error carries one; never the body.
export function providerFailureFields(error) {
  return {
    ...(error?.readFailure ? { read_failure: sanitizeReadFailure(error.readFailure) } : {}),
    ...(error?.writeFailure ? { write_failure: sanitizeReadFailure(error.writeFailure) } : {}),
  };
}
const PROVIDER_ACCOUNT_PATH = `/accounts/${TARGET.accountId}`;
const PROVIDER_WORKER_PATH = `${PROVIDER_ACCOUNT_PATH}/workers/scripts/${TARGET.workerName}`;
const UUID_PATTERN = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const WORKER_VERSION_PATH = new RegExp(`^/versions/${UUID_PATTERN}$`, "i");
const D1_LIST_PATH = new RegExp(`^${escapeRegExp(PROVIDER_ACCOUNT_PATH)}/d1/database\\?name=${escapeRegExp(TARGET.databaseName)}&page=[1-9][0-9]{0,2}&per_page=${D1_PAGE_SIZE}$`);
const ZONE_PAGE_SIZE = 50;
const MAX_ZONE_PAGES = 20;
const ZONE_LIST_PATH = new RegExp(`^/zones\\?account\\.id=${TARGET.accountId}&page=[1-9][0-9]?&per_page=${ZONE_PAGE_SIZE}$`);
const ZONE_ROUTES_PATH = /^\/zones\/([0-9a-f]{32})\/workers\/routes$/;
const ZONE_ID = /^[0-9a-f]{32}$/;
const PROVIDER_SERVICE_ROUTES_PATH = `${PROVIDER_ACCOUNT_PATH}/workers/services/${TARGET.workerName}/environments/production/routes`;

// Every Cloudflare API request this route makes, on an account it shares with
// production:
// - reads of the account, its script list and its workers.dev subdomain;
// - reads of the receiver Worker's deployments, versions, secrets and subdomain,
//   and the one write that toggles that subdomain;
// - the exact-name D1 lookup, and queries against the D1 UUID adopted in this run;
// - the ingress proof: the account's Workers custom domains, its zone list, and
//   the Worker routes of the zones that list returned;
// - one DELETE of the receiver Worker, only after this run created it from an
//   absent preimage.
// Anything else, a D1 query before adoption, a zone not adopted from the list, or
// a DELETE that was not armed, is refused before a request is sent.
export function assertProviderRequest(path, method, state = {}) {
  const { database = null, zones = null, deletion = false } = state;
  if (typeof path !== "string" || !["GET", "POST", "DELETE"].includes(method)) fail("provider_path_refused");
  if (method === "DELETE") {
    if (deletion === true && path === PROVIDER_WORKER_PATH) return true;
    fail("provider_path_refused");
  }
  if (method === "GET" && [PROVIDER_ACCOUNT_PATH, `${PROVIDER_ACCOUNT_PATH}/workers/scripts`, `${PROVIDER_ACCOUNT_PATH}/workers/subdomain`, `${PROVIDER_ACCOUNT_PATH}/workers/domains`, PROVIDER_SERVICE_ROUTES_PATH].includes(path)) return true;
  if (path.startsWith(`${PROVIDER_WORKER_PATH}/`)) {
    const rest = path.slice(PROVIDER_WORKER_PATH.length);
    if (method === "GET" && (["/deployments", "/secrets", "/subdomain", "/versions?per_page=100&deployable=true"].includes(rest) || WORKER_VERSION_PATH.test(rest))) return true;
    if (method === "POST" && rest === "/subdomain") return true;
  }
  if (method === "GET" && D1_LIST_PATH.test(path)) return true;
  if (method === "POST" && database !== null && path === `${PROVIDER_ACCOUNT_PATH}/d1/database/${database}/query`) return true;
  if (method === "GET" && ZONE_LIST_PATH.test(path)) return true;
  const zoneRoutes = ZONE_ROUTES_PATH.exec(path);
  if (method === "GET" && zoneRoutes && zones instanceof Set && zones.has(zoneRoutes[1])) return true;
  fail("provider_path_refused");
}

export function makeCloudflareApi(token, fetchImpl = fetch) {
  const state = { database: null, zones: null, deletion: false };
  async function request(path, { method = "GET", body } = {}) {
    assertProviderRequest(path, method, state);
    let response;
    try {
      response = await fetchImpl(`${apiBase}${path}`, {
        method,
        redirect: "error",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw providerRequestFailure("provider_transport_ambiguous", method, classifyReadFailure({ path, transport: true }));
    }
    let payload;
    try { payload = await response.json(); } catch {
      throw providerRequestFailure("provider_response_ambiguous", method, classifyReadFailure({ path, status: response.status, malformed: true }));
    }
    if (!response.ok || payload?.success !== true) {
      const rejected = providerRequestFailure("provider_response_rejected", method, classifyReadFailure({ path, status: response.status, payload }));
      rejected.httpStatus = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : null;
      throw rejected;
    }
    if (Array.isArray(payload.result) && payload.result_info) {
      Object.defineProperty(payload.result, "result_info", { value: payload.result_info });
    }
    return payload.result;
  }
  // Binds this client to the one D1 UUID resolved from the exact pinned name.
  request.adoptDatabase = (databaseId) => {
    adoptedDatabaseId(databaseId);
    if (state.database !== null && state.database !== databaseId) fail("database_adoption_changed");
    state.database = databaseId;
    return databaseId;
  };
  // Binds zone-route reads to the zones the account's own zone list returned.
  request.adoptZones = (zoneIds) => {
    if (!Array.isArray(zoneIds) || zoneIds.some((id) => typeof id !== "string" || !ZONE_ID.test(id)) || new Set(zoneIds).size !== zoneIds.length) fail("ingress_zones_ambiguous");
    state.zones = new Set(zoneIds);
    return zoneIds.length;
  };
  // Allows the one DELETE of the receiver Worker; armed only by a run that created it.
  request.armWorkerDeletion = () => {
    state.deletion = true;
  };
  return request;
}

// The refusals that mean something other than workers.dev reaches the receiver.
// Once either is seen, no route performs another write: no rollback, no delete,
// no workers.dev change. It reports `halted_external_ingress_detected` instead.
export const EXTERNAL_INGRESS_CODES = Object.freeze(["worker_custom_domain_present", "worker_zone_route_present", "worker_custom_route_present"]);
export function isExternalIngressError(error) {
  return error instanceof RouteError && EXTERNAL_INGRESS_CODES.includes(error.code);
}

// Reads one ingress list and classifies an unreadable answer: a 401/403 is a missing
// read permission, anything else is unreadable. Either refuses the run.
async function readIngress(api, path, kind) {
  try {
    return await api(path);
  } catch (error) {
    const permission = error instanceof RouteError && error.code === "provider_response_rejected" && [401, 403].includes(error.httpStatus);
    const refused = new RouteError(permission ? `ingress_${kind}_permission_denied` : `ingress_${kind}_unreadable`);
    // Keep which read failed, and how, for the receipt.
    if (error?.readFailure) refused.readFailure = error.readFailure;
    throw refused;
  }
}

function completeListPage(rows, kind) {
  if (!Array.isArray(rows)) fail(`ingress_${kind}_unreadable`);
  const info = rows.result_info;
  if (info !== undefined) {
    if (!info || typeof info !== "object" || Array.isArray(info)) fail(`ingress_${kind}_unreadable`);
    if (info.total_pages !== undefined && info.total_pages !== 1 && info.total_pages !== 0) fail(`ingress_${kind}_truncated`);
    if (info.total_count !== undefined && info.total_count !== rows.length) fail(`ingress_${kind}_truncated`);
  }
  return rows;
}

// Before any write, and again after deploy and after cleanup: positively read that
// no Workers custom domain and no zone route sends traffic to the receiver Worker.
// workers.dev is the only ingress the route ever enables, so anything else attached
// to the pinned name refuses the run. Unknown, unreadable or truncated lists refuse
// too. The zone scan sees the zones this token can list. Once the Worker exists, its
// own service route list is read as well, and that list covers every zone.
export async function proveNoExternalIngress(api, { workerExists }) {
  if (typeof workerExists !== "boolean") fail("ingress_worker_state_unknown");
  let serviceRoutes = null;
  if (workerExists) {
    const routes = completeListPage(await readIngress(api, PROVIDER_SERVICE_ROUTES_PATH, "service_routes"), "service_routes");
    if (routes.some((route) => !route || typeof route !== "object")) fail("ingress_service_routes_unreadable");
    if (routes.length !== 0) fail("worker_zone_route_present");
    serviceRoutes = 0;
  }
  const domains = completeListPage(await readIngress(api, `${PROVIDER_ACCOUNT_PATH}/workers/domains`, "custom_domains"), "custom_domains");
  if (domains.some((domain) => !domain || typeof domain !== "object" || typeof domain.service !== "string")) fail("ingress_custom_domains_unreadable");
  const zoneIds = [];
  let totalPages = null;
  for (let page = 1; page <= MAX_ZONE_PAGES; page += 1) {
    const rows = await readIngress(api, `/zones?account.id=${TARGET.accountId}&page=${page}&per_page=${ZONE_PAGE_SIZE}`, "zones");
    const info = rows?.result_info;
    if (!Array.isArray(rows) || !info || !Number.isInteger(info.total_pages) || !Number.isInteger(info.total_count) || info.page !== page || rows.length > ZONE_PAGE_SIZE) fail("ingress_zones_unreadable");
    if (totalPages === null) totalPages = info.total_pages;
    if (info.total_pages !== totalPages) fail("ingress_zones_unreadable");
    for (const zone of rows) {
      if (!zone || typeof zone.id !== "string" || !ZONE_ID.test(zone.id) || (zone.account?.id !== undefined && zone.account.id !== TARGET.accountId)) fail("ingress_zones_unreadable");
      zoneIds.push(zone.id);
    }
    if (page >= totalPages) {
      if (zoneIds.length !== info.total_count) fail("ingress_zones_truncated");
      break;
    }
    if (page === MAX_ZONE_PAGES) fail("ingress_zones_truncated");
  }
  if (totalPages === null) fail("ingress_zones_unreadable");
  api.adoptZones(zoneIds);
  let zoneRoutes = 0;
  for (const zoneId of zoneIds) {
    const routes = completeListPage(await readIngress(api, `/zones/${zoneId}/workers/routes`, "zone_routes"), "zone_routes");
    if (routes.some((route) => !route || typeof route !== "object" || typeof route.pattern !== "string" || (route.script !== undefined && route.script !== null && typeof route.script !== "string"))) fail("ingress_zone_routes_unreadable");
    zoneRoutes += routes.filter((route) => route.script === TARGET.workerName).length;
  }
  const customDomains = domains.filter((domain) => domain.service === TARGET.workerName).length;
  if (customDomains !== 0) fail("worker_custom_domain_present");
  if (zoneRoutes !== 0) fail("worker_zone_route_present");
  return Object.freeze({ zones_checked: zoneIds.length, zone_routes: 0, custom_domains: 0, service_routes: serviceRoutes === null ? "worker_absent" : 0 });
}

// A revision this route itself produced: its secret-put step tags it
// `b216-<40-hex reviewed main SHA>`, and it binds exactly the receiver D1 (the UUID
// adopted in this run) and the receiver secret, with nothing else. Only such a
// revision may serve as a rollback target; a pre-existing receiver Worker whose
// active revision is anything else refuses the run before any write; and the
// synthetic exercise sends nothing to an active revision that fails it.
export function validateRouteOwnedRevision(version, databaseId) {
  const tag = version?.metadata?.annotations?.["workers/tag"];
  if (!isUuid(version?.id) || typeof tag !== "string" || !/^b216-[0-9a-f]{40}$/.test(tag)) fail("worker_revision_not_route_owned");
  const bindings = version?.resources?.bindings;
  if (!Array.isArray(bindings) || bindings.length !== 2) fail("worker_revision_bindings_not_exact");
  const database = bindings.filter((binding) => binding?.type === "d1" && binding.name === TARGET.databaseBinding && (binding.database_id ?? binding.id) === databaseId);
  const secret = bindings.filter((binding) => binding?.type === "secret_text" && binding.name === TARGET.workerSecret);
  if (database.length !== 1 || secret.length !== 1) fail("worker_revision_bindings_not_exact");
  return version.id;
}

const VERSION_ID = new RegExp(`^${UUID_PATTERN}$`, "i");
const VERSION_AT_100 = new RegExp(`^${UUID_PATTERN}@100%$`, "i");
// Each Wrangler invocation this route makes, by exact shape: argument count, fixed
// positions, which position carries the config and which kind of generated config
// it must be, where the entry point goes, and which positions carry free values
// (tag, message) that may not look like an option.
const WRANGLER_COMMANDS = Object.freeze({
  deploy: { length: 6, config: 3, kind: "initial_private", entry: 1, values: [5], fixed: { 2: "--config", 4: "--message" } },
  "versions upload": { length: 9, config: 4, kind: "final", entry: 2, values: [6, 8], fixed: { 3: "--config", 5: "--tag", 7: "--message" } },
  "versions secret put": { length: 10, config: 5, kind: "final", values: [7, 9], fixed: { 3: TARGET.workerSecret, 4: "--config", 6: "--tag", 8: "--message" } },
  "versions deploy": { length: 6, config: 5, kind: "final", values: [], fixed: { 3: "--yes", 4: "--config" }, check: (args) => VERSION_AT_100.test(args[2]) },
  "d1 migrations apply": { length: 7, config: 6, kind: "final", values: [], fixed: { 4: "--remote", 5: "--config" }, check: (args) => requireReceiverResourceName(args[3], "database") === TARGET.databaseName },
  rollback: { length: 6, config: 3, kind: "final", values: [5], fixed: { 2: "--config", 4: "--message" }, check: (args) => VERSION_ID.test(args[1]) },
});

// The Wrangler invocations this route makes. Each names its target only through a
// config file this run generated: the exact path it wrote, of the kind the command
// needs, with the content hash it had when written. The entry point is the run's
// exact source path, and no argument can add an option such as --name or --env.
export function assertWranglerCommand(args, { configs, entrypoint } = {}) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) fail("wrangler_command_refused");
  const key = args[0] === "versions" ? (args[1] === "secret" && args[2] === "put" ? "versions secret put" : `versions ${args[1]}`) : args[0] === "d1" ? `d1 ${args[1]} ${args[2]}` : args[0];
  const shape = Object.hasOwn(WRANGLER_COMMANDS, key) ? WRANGLER_COMMANDS[key] : null;
  if (!shape || args.length !== shape.length) fail("wrangler_command_refused");
  if (args.some((arg) => /^--(?:name|env|script-name|dispatch-namespace|routes?|account-id)(?:=|$)/.test(arg))) fail("wrangler_command_refused");
  for (const [index, value] of Object.entries(shape.fixed)) {
    if (args[Number(index)] !== value) fail("wrangler_command_refused");
  }
  if (shape.entry !== undefined && (typeof entrypoint !== "string" || args[shape.entry] !== entrypoint)) fail("wrangler_command_refused");
  for (const index of shape.values) {
    if (args[index].length === 0 || args[index].startsWith("-")) fail("wrangler_command_refused");
  }
  if (shape.check && !shape.check(args)) fail("wrangler_command_refused");
  const configPath = args[shape.config];
  const recorded = configs instanceof Map ? configs.get(configPath) : undefined;
  if (!recorded || recorded.kind !== shape.kind) fail("wrangler_command_refused");
  let content;
  try { content = readFileSync(configPath, "utf8"); } catch { fail("wrangler_command_refused"); }
  if (createHash("sha256").update(content).digest("hex") !== recorded.sha256) fail("wrangler_command_refused");
  return true;
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

export async function runRoute({ context, config, migration, fetchImpl = fetch, command: runCommand = runWrangler, receiptPath, worktree = process.cwd() }) {
  const sha = validateDispatch(context);
  validateTrackedInputs(config, migration);
  const api = makeCloudflareApi(context.apiToken, fetchImpl);
  const appDir = resolve(worktree, "apps/dsr-alert-receiver");
  const entrypoint = resolve(appDir, "src/index.ts");
  // Every config Wrangler may read is one this run wrote; its kind and content
  // hash are recorded at write time and checked again before each command.
  const generatedConfigs = new Map();
  const writeRunConfig = async (path, content, kind) => {
    await writeFile(path, content, { mode: 0o600, flag: "wx" });
    generatedConfigs.set(path, { kind, sha256: createHash("sha256").update(content).digest("hex") });
  };
  const command = (args, options) => {
    assertWranglerCommand(args, { configs: generatedConfigs, entrypoint });
    return runCommand(args, options);
  };
  const readInventory = () => readWorkerInventory({
    context: {
      repository: context.repository,
      ref: context.ref,
      sha: context.sha,
      checkoutSha: context.checkoutSha,
      readbackOnly: "true",
      apiToken: context.apiToken,
    },
    fetchImpl,
  });
  const receipt = {
    schema_version: 1,
    issue: 1678,
    repository: TARGET.repository,
    reviewed_main_sha: sha,
    account_id: TARGET.accountId,
    worker_name: TARGET.workerName,
    database_name: TARGET.databaseName,
    binding: TARGET.databaseBinding,
    migration: TARGET.migration,
    migration_sha256: TARGET.migrationSha256,
    disjointness_note: "B-216 adopts only its dedicated exact-name Worker and D1 on the shared account; production and staging names are refused.",
    captured_at: new Date().toISOString(),
    status: "started",
  };
  let stage = "account_readback";
  let workerMutationStarted = false;
  let workerCreatedThisRun = false;
  let priorWorkerVersion = null;
  let privateInitialVersion = null;
  let tempConfig = null;
  let initialPrivateConfig = null;
  let wranglerHome = null;
  let tempConfigDir = null;
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
    let customRoutesStatus = summarizeCustomRoutes(priorWorker);
    receipt.custom_routes_status = customRoutesStatus;
    if (priorDatabase) {
      receipt.database_id = api.adoptDatabase(validateDatabaseIdentity(priorDatabase));
      receipt.database_adoption = "exact_name_unique_on_pinned_account";
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
    if (priorWorker) {
      // A receiver Worker that already exists must be one this route produced, with
      // exactly the receiver bindings; otherwise nothing is written, and its revision
      // is never a rollback target.
      stage = "worker_preimage_ownership";
      const deployments = normalizeDeploymentList(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`));
      priorWorkerVersion = selectPriorRevision(deployments);
      if (!priorWorkerVersion) fail("worker_preimage_ambiguous");
      validateRouteOwnedRevision(await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${priorWorkerVersion}`), receipt.database_id);
      receipt.worker_preimage_owner = "this_route_exact_bindings";
    }
    receipt.worker_preimage = priorWorkerVersion ?? "absent";
    stage = "ingress_preimage";
    receipt.ingress_preimage = await proveNoExternalIngress(api, { workerExists: Boolean(priorWorker) });

    const runDir = process.env.RUNNER_TEMP || tmpdir();
    tempConfigDir = join(runDir, `b216-${randomUUID()}`);
    await mkdir(tempConfigDir, { recursive: true, mode: 0o700 });
    wranglerHome = join(tempConfigDir, "home");
    await mkdir(wranglerHome, { mode: 0o700 });
    tempConfig = join(tempConfigDir, "wrangler.toml");
    await writeRunConfig(tempConfig, prepareFinalReceiverConfig(config, migration, receipt.database_id, appDir), "final");

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

    if (!priorWorker) {
      stage = "worker_initial_private_config";
      initialPrivateConfig = join(tempConfigDir, "wrangler-initial-private.toml");
      await writeRunConfig(initialPrivateConfig, prepareInitialPrivateReceiverConfig(config, migration, receipt.database_id, appDir), "initial_private");
      stage = "worker_initial_private_deploy";
      workerMutationStarted = true;
      workerCreatedThisRun = true;
      command(["deploy", entrypoint, "--config", initialPrivateConfig, "--message", `B-216 private initial revision ${sha}`], {
        cwd: appDir,
        home: wranglerHome,
        apiToken: context.apiToken,
      });

      stage = "worker_initial_private_readback";
      const privateInventory = await readInventory();
      privateInitialVersion = validateInitialPrivateDeployment(privateInventory, workerPage.length + 1);
      const privateRevision = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/versions/${privateInitialVersion}`);
      validateInitialPrivateVersion(privateRevision, receipt.database_id);
      receipt.initial_private_revision = privateInitialVersion;
      receipt.initial_private_workers_dev = "disabled_verified";
      receipt.initial_private_preview_urls = "disabled_verified";
      receipt.initial_private_custom_routes = privateInventory.routes.status === "known" ? "absent" : "unknown";
      customRoutesStatus = receipt.initial_private_custom_routes;
      // The Worker now exists, so its own service route list (every zone) is
      // readable: prove nothing routes to it before it gets code or a secret.
      stage = "ingress_after_create";
      receipt.ingress_after_create = await proveNoExternalIngress(api, { workerExists: true });
    }

    const versionTag = `b216-${sha}`;
    workerMutationStarted = true;
    stage = "worker_version_upload";
    command(["versions", "upload", entrypoint, "--config", tempConfig, "--tag", `b216-source-${sha}`, "--message", `B-216 reviewed main ${sha}`], {
      cwd: appDir,
      home: wranglerHome,
      apiToken: context.apiToken,
    });
    stage = "worker_secret_provision";
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
    // Before activation: the same exact check as rollback and the exercise. Route
    // tag, and the receiver D1 and secret are the only bindings.
    validateRouteOwnedRevision(candidateVersion, receipt.database_id);

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
    // And again on what is actually active.
    validateRouteOwnedRevision(version, receipt.database_id);
    if (!priorWorker) {
      stage = "worker_public_ingress_enable";
      await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/subdomain`, {
        method: "POST",
        body: { enabled: true, previews_enabled: false },
      });
      const subdomain = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/subdomain`);
      validateWorkersDevEnabled(subdomain);
    }
    stage = "ingress_postflight";
    receipt.ingress_postflight = await proveNoExternalIngress(api, { workerExists: true });
    receipt.worker_preimage = priorWorkerVersion ?? "absent";
    if (privateInitialVersion) receipt.initial_private_revision = privateInitialVersion;
    receipt.worker_revision = activeVersion;
    receipt.worker_binding_uuid = receipt.database_id;
    receipt.worker_secret_name_present = true;
    receipt.final_workers_dev = priorWorker ? "preexisting_state_unchanged" : "enabled_verified";
    receipt.final_preview_urls = priorWorker ? "preexisting_state_unchanged" : "disabled_verified";
    receipt.custom_routes_status = customRoutesStatus;
    receipt.status = "deployed";
    receipt.completed_at = new Date().toISOString();
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    return receipt;
  } catch (error) {
    receipt.status = "failed";
    receipt.failed_stage = stage;
    receipt.failure_code = error instanceof RouteError ? error.code : "route_failed_closed";
    if (error instanceof RouteError && error.providerFailure) Object.assign(receipt, error.providerFailure);
    Object.assign(receipt, providerFailureFields(error));
    if (isExternalIngressError(error)) {
      // External ingress reaches the receiver: whatever serves it now may be
      // production traffic, so no rollback and no delete. The lead decides.
      receipt.rollback_status = "halted_external_ingress_detected";
      receipt.escalation = "lead_review_required";
    } else if (workerMutationStarted && tempConfig) {
      receipt.rollback_target = priorWorkerVersion ?? "delete_worker_created_this_run";
      try {
        if (priorWorkerVersion) {
          // The prior revision was proven route-owned with exact bindings above. A
          // rollback is a write, so zero ingress is proven immediately before it.
          receipt.cleanup_ingress_preimage = await proveNoExternalIngress(api, { workerExists: true });
          command(["rollback", priorWorkerVersion, "--config", tempConfig, "--message", "B-216 exact preimage rollback"], { cwd: appDir, home: wranglerHome, apiToken: context.apiToken });
          const deployments = await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}/deployments`);
          validateRollbackReadback(deployments, priorWorkerVersion);
          receipt.rollback_status = "restored_route_owned_revision";
          receipt.rollback_ingress = await proveNoExternalIngress(api, { workerExists: true });
        } else if (workerCreatedThisRun) {
          // The preimage was absent, so cleanup removes the Worker this run created,
          // but only once zero ingress is proven immediately before the delete.
          let inventory;
          try { inventory = await readInventory(); } catch { inventory = null; }
          if (inventory?.worker?.exists === false && inventory.inventory_consistency === "worker_absent") {
            receipt.rollback_status = "absent_preimage_verified";
          } else {
            const currentScripts = await api(`/accounts/${TARGET.accountId}/workers/scripts`);
            validateInventoryPage(currentScripts, "worker");
            if (!selectNamedResource(currentScripts, TARGET.workerName, "worker")) fail("worker_rollback_target_ambiguous");
            receipt.cleanup_ingress_preimage = await proveNoExternalIngress(api, { workerExists: true });
            api.armWorkerDeletion();
            await api(`/accounts/${TARGET.accountId}/workers/scripts/${TARGET.workerName}`, { method: "DELETE" });
            const after = await readInventory();
            if (after?.worker?.exists !== false || after.inventory_consistency !== "worker_absent") fail("worker_delete_readback_mismatch");
            receipt.rollback_status = "created_worker_deleted";
          }
          receipt.rollback_ingress = await proveNoExternalIngress(api, { workerExists: false });
        }
      } catch (cleanupError) {
        if (isExternalIngressError(cleanupError)) {
          receipt.rollback_status = "halted_external_ingress_detected";
          receipt.escalation = "lead_review_required";
        } else {
          receipt.rollback_status = "ambiguous_do_not_retry";
        }
      }
    }
    if (receiptPath) await writeReceipt(receiptPath, receipt);
    throw error instanceof RouteError ? error : new RouteError("route_failed_closed");
  } finally {
    if (tempConfigDir) await rm(tempConfigDir, { recursive: true, force: true }).catch(() => {});
  }
}

export function validateWorkersDevEnabled(subdomain) {
  if (!subdomain || subdomain.enabled !== true || subdomain.previews_enabled !== false) fail("worker_subdomain_readback_mismatch");
  return true;
}

async function queryDatabase(api, id, sql, params = []) {
  const results = await api(`/accounts/${TARGET.accountId}/d1/database/${id}/query`, { method: "POST", body: { sql, ...(params.length === 0 ? {} : { params }) } });
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.success !== true || !Array.isArray(results[0]?.results)) fail("database_query_ambiguous");
  return results[0].results;
}

export async function queryReadOnlyDatabase(api, id, sql, params = []) {
  if (!/^SELECT\b/i.test(sql) || /\b(?:CREATE|DROP|ALTER|INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)) fail("database_query_not_read_only");
  if (!Array.isArray(params) || params.some((parameter) => typeof parameter !== "string" && typeof parameter !== "number" && typeof parameter !== "boolean" && parameter !== null)) fail("database_query_not_read_only");
  return queryDatabase(api, id, sql, params);
}

export async function main() {
  const worktree = resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const appDir = resolve(worktree, "apps/dsr-alert-receiver");
  const config = await readFile(resolve(appDir, "wrangler.toml"), "utf8");
  const migration = await readFile(resolve(appDir, "migrations", TARGET.migration), "utf8");
  // The two-stage bootstrap (#2765) needed an account whose whole Worker inventory
  // it could pin; on the shared account it cannot exist, and it is retired.
  if (process.env.B216_BOOTSTRAP_STAGE !== undefined) {
    process.stderr.write("B-216 route stopped: bootstrap_retired_on_shared_account\n");
    process.exitCode = 1;
    return;
  }
  const context = {
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
    checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim(),
    apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN,
    receiverToken: process.env.B216_DSR_ALERT_RECEIVER_TOKEN,
  };
  const runDir = process.env.RUNNER_TEMP || tmpdir();
  const receiptPath = join(runDir, "b216-receiver-route-receipt.json");
  try {
    await runRoute({ context, config, migration, receiptPath, worktree });
  } catch (error) {
    const code = error instanceof RouteError ? error.code : "route_failed_closed";
    try {
      await readFile(receiptPath, "utf8");
    } catch {
      await writeReceipt(receiptPath, {
        schema_version: 1,
        issue: 1678,
        repository: TARGET.repository,
        reviewed_main_sha: context.sha,
        account_id: TARGET.accountId,
        worker_name: TARGET.workerName,
        database_name: TARGET.databaseName,
        binding: TARGET.databaseBinding,
        migration: TARGET.migration,
        migration_sha256: TARGET.migrationSha256,
        disjointness_note: "B-216 adopts only its dedicated exact-name Worker and D1 on the shared account; production and staging names are refused.",
        captured_at: new Date().toISOString(),
        status: "failed",
        failure_code: code,
      });
    }
    process.stderr.write(`B-216 route stopped: ${code}\n`);
    process.exitCode = 1;
  }
}
