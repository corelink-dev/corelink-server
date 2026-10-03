// Which Cloudflare request failed, and how, without the response text.
//
// readback_only run 36977214852 on the main account recorded only
// `provider_response_rejected`, so it did not say which GET was refused. Every
// receiver API helper now attaches a `read_failure` (or `write_failure` for a
// non-GET) built here. The record holds an endpoint label from a closed set, the
// HTTP status, up to eight numeric Cloudflare error codes, and a message class
// from a closed set. It never holds a body, message text, path, account, zone or
// Worker ID, or token. Same redaction rules as #2877.

export const READ_FAILURE_ENDPOINTS = Object.freeze([
  "account",
  "scripts_list",
  "worker_script",
  "worker_versions",
  "worker_version",
  "worker_deployments",
  "worker_secrets",
  "worker_subdomain",
  "account_workers_subdomain",
  "custom_domains",
  "zones_list",
  "zone_routes",
  "service_routes",
  "d1_list",
  "d1_query",
  "token_verify_user",
  "token_verify_account",
  "token_details_user",
  "token_details_account",
  "other",
]);

export const READ_FAILURE_MESSAGE_CLASSES = Object.freeze([
  "authentication",
  "permission",
  "not_found",
  "rate_limited",
  "server_error",
  "malformed_response",
  "unexpected_shape",
  "transport",
  "rejected_without_detail",
  "other",
]);

const MAX_CF_ERROR_CODES = 8;
const ACCOUNT = "[0-9a-f]{32}";
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const NAME = "[a-z0-9][a-z0-9-]{0,62}";
const LABELS = [
  [new RegExp(`^/accounts/${ACCOUNT}$`, "i"), "account"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts$`, "i"), "scripts_list"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}$`, "i"), "worker_script"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}/versions$`, "i"), "worker_versions"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}/versions/${UUID}$`, "i"), "worker_version"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}/deployments$`, "i"), "worker_deployments"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}/secrets$`, "i"), "worker_secrets"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/scripts/${NAME}/subdomain$`, "i"), "worker_subdomain"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/subdomain$`, "i"), "account_workers_subdomain"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/domains$`, "i"), "custom_domains"],
  [/^\/zones$/, "zones_list"],
  [new RegExp(`^/zones/${ACCOUNT}/workers/routes$`, "i"), "zone_routes"],
  [new RegExp(`^/accounts/${ACCOUNT}/workers/services/${NAME}/environments/production/routes$`, "i"), "service_routes"],
  [new RegExp(`^/accounts/${ACCOUNT}/d1/database$`, "i"), "d1_list"],
  [new RegExp(`^/accounts/${ACCOUNT}/d1/database/${UUID}/query$`, "i"), "d1_query"],
  [/^\/user\/tokens\/verify$/, "token_verify_user"],
  [new RegExp(`^/accounts/${ACCOUNT}/tokens/verify$`, "i"), "token_verify_account"],
  [new RegExp(`^/user/tokens/${ACCOUNT}$`, "i"), "token_details_user"],
  [new RegExp(`^/accounts/${ACCOUNT}/tokens/${ACCOUNT}$`, "i"), "token_details_account"],
];

export function labelReadEndpoint(path) {
  const bare = String(path).split("?", 1)[0];
  for (const [pattern, label] of LABELS) {
    if (pattern.test(bare)) return label;
  }
  return "other";
}

// Cloudflare's own authentication-failure codes. 10000 is also what it returns
// for a token that lacks the permission, so the two cannot be told apart by code.
const AUTHENTICATION_CODES = new Set([1000, 9106, 9109, 10000, 10001]);

function errorCodes(payload) {
  const codes = [];
  for (const error of Array.isArray(payload?.errors) ? payload.errors : []) {
    const code = error?.code;
    if (Number.isInteger(code) && code >= 0 && code <= 999999 && !codes.includes(code)) codes.push(code);
    if (codes.length === MAX_CF_ERROR_CODES) break;
  }
  return codes;
}

function messageClass({ status, payload, transport, malformed, unexpectedShape }) {
  if (transport) return "transport";
  if (malformed) return "malformed_response";
  if (unexpectedShape) return "unexpected_shape";
  const codes = errorCodes(payload);
  const messages = (Array.isArray(payload?.errors) ? payload.errors : [])
    .slice(0, MAX_CF_ERROR_CODES)
    .map((error) => (typeof error?.message === "string" ? error.message.slice(0, 512) : ""));
  if (codes.some((code) => AUTHENTICATION_CODES.has(code)) || messages.some((message) => /authenticat|invalid api token|unauthori[sz]ed/i.test(message))) return "authentication";
  if (messages.some((message) => /permission|not authorized|not allowed|forbidden|access denied/i.test(message))) return "permission";
  if (status === 404 || messages.some((message) => /not found|does not exist/i.test(message))) return "not_found";
  if (status === 429 || messages.some((message) => /rate limit|too many requests/i.test(message))) return "rate_limited";
  if (Number.isInteger(status) && status >= 500) return "server_error";
  if (status === 401) return "authentication";
  if (status === 403) return "permission";
  if (codes.length === 0 && messages.every((message) => message === "")) return "rejected_without_detail";
  return "other";
}

// payload is the parsed JSON body, or undefined when there was none to parse.
// unexpectedShape: the request succeeded, but a field of its result failed the
// receiver's own shape check (the failure code names the field).
export function classifyReadFailure({ path, status = null, payload, transport = false, malformed = false, unexpectedShape = false }) {
  return Object.freeze({
    endpoint: labelReadEndpoint(path),
    http_status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
    cf_error_codes: Object.freeze(transport || malformed || unexpectedShape ? [] : errorCodes(payload)),
    message_class: messageClass({ status, payload, transport, malformed, unexpectedShape }),
  });
}

// Copies only allowlisted fields from an untrusted record into a receipt.
export function sanitizeReadFailure(value) {
  if (!value || typeof value !== "object") return null;
  const codes = Array.isArray(value.cf_error_codes)
    ? value.cf_error_codes.filter((code) => Number.isInteger(code) && code >= 0 && code <= 999999).slice(0, MAX_CF_ERROR_CODES)
    : [];
  return Object.freeze({
    endpoint: READ_FAILURE_ENDPOINTS.includes(value.endpoint) ? value.endpoint : "other",
    http_status: Number.isInteger(value.http_status) && value.http_status >= 100 && value.http_status <= 599 ? value.http_status : null,
    cf_error_codes: Object.freeze([...new Set(codes)]),
    message_class: READ_FAILURE_MESSAGE_CLASSES.includes(value.message_class) ? value.message_class : "other",
  });
}
