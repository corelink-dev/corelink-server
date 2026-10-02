// The one place the B-216 receiver's Cloudflare target is named.
//
// Owner decision 2026-10-01: the nonprod receiver moves off account 5128 to the
// main account, which also hosts production and staging. So the receiver may only
// ever name its own dedicated Worker and D1 database. Every route that talks to
// Cloudflare checks names through assertReceiverResourceName, and this module
// refuses to load if the pinned names themselves drift out of the dedicated
// namespace or onto a production or staging resource.

export class ReceiverTargetError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReceiverTargetError";
    this.code = code;
  }
}

export const RECEIVER_TARGET = Object.freeze({
  repository: "HuGR-dev/corelink-server",
  accountId: "6a1fc1c626fc2628823e60b9db01f5cd",
  workerName: "corelink-dsr-b216-alert-receiver-6a",
  databaseName: "corelink-dsr-b216-alert-receipts-6a",
});

// The only shape a receiver resource name may have on the shared account.
const RECEIVER_NAMESPACE = /^corelink-dsr-b216-alert-(?:receiver|receipts)-6a$/;

// Production and staging names on the shared account (Workers, D1, queues, R2 and
// services declared in this repository), refused even if a pinned constant were
// edited to one of them. The exact-name allowlist above is the primary guard; this
// list is the second, independent one.
export const PROTECTED_RESOURCE_NAMES = Object.freeze([
  /^corelink-prod(?:$|[-_.])/i,
  /^corelink-api(?:$|[-_.])/i,
  /^corelink-signup-worker(?:$|[-_.])/i,
  /^corelink-staging(?:$|[-_.])/i,
  /^corelink-server(?:$|[-_.])/i,
  /^corelink-config-/i,
  /^corelink-cas-/i,
  /^corelink-analytics(?:$|[-_.])/i,
  /^corelink-dsr-erasure(?:$|[-_.])/i,
  /^corelink-(?:chunk|manifest|ac)-/i,
  /^corelink-(?:spawn-worker|synthetic-pager|audit-witness|admin-ui|docs|get-corelink)(?:$|[-_.])/i,
  /^corelink$/i,
]);

const EXPECTED_NAME = Object.freeze({
  worker: RECEIVER_TARGET.workerName,
  database: RECEIVER_TARGET.databaseName,
});

export function assertReceiverResourceName(name, kind) {
  if (!Object.hasOwn(EXPECTED_NAME, kind)) throw new ReceiverTargetError("receiver_resource_kind_unknown");
  if (typeof name !== "string" || PROTECTED_RESOURCE_NAMES.some((pattern) => pattern.test(name))) {
    throw new ReceiverTargetError("protected_resource_name_refused");
  }
  if (!RECEIVER_NAMESPACE.test(name) || name !== EXPECTED_NAME[kind]) throw new ReceiverTargetError("receiver_resource_name_refused");
  return name;
}

// Fail at import, before any route can build a request, if the pinned pair drifted.
assertReceiverResourceName(RECEIVER_TARGET.workerName, "worker");
assertReceiverResourceName(RECEIVER_TARGET.databaseName, "database");
if (!/^[0-9a-f]{32}$/.test(RECEIVER_TARGET.accountId)) throw new ReceiverTargetError("receiver_account_invalid");
