import type { Container, D1Database, Fetcher } from "@cloudflare/workers-types";
import type { Env } from "./index_env.js";
import { checkHttpExecutionDeadline, type StagingD1HttpDeadline } from "./staging_d1_http_lifetime.js";

const D1_PROXY_HOST = "corelink-d1-proxy.invalid";
const STAGING_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
const STAGING_DATABASE_ID = "d72a6b39-6a48-4338-bfda-1111dda98604";
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_SQL_BYTES = 256 * 1024;
const MAX_PARAMS = 128;
const MAX_BATCH_STATEMENTS = 100;

type D1Param = null | number | string | ArrayBuffer | ArrayBufferView;
type StatementInput = { sql: string; params: D1Param[] };

type ProxyEnv = Pick<Env,
  "CONFIG_DB" | "CLOUDFLARE_ACCOUNT_ID" | "D1_DATABASE_ID" |
  "R2_S3_ENDPOINT" | "ENVIRONMENT"
>;

/** Install before container.start; a rejected install aborts the boot path. */
export async function installD1BindingProxy(
  container: Pick<Container, "interceptOutboundHttp"> | undefined,
  binding: Fetcher,
): Promise<void> {
  if (container === undefined) throw new Error("staging D1 Container is unavailable");
  await container.interceptOutboundHttp(D1_PROXY_HOST, binding);
}

export async function handleStagingD1BindingRequest(
  request: Request,
  env: ProxyEnv,
  deadline?: StagingD1HttpDeadline,
): Promise<Response> {
  const checkDeadline = () => { if (deadline !== undefined) checkHttpExecutionDeadline(deadline); };
  try { checkDeadline(); } catch { return jsonError(502, "D1 binding operation failed"); }
  const url = new URL(request.url);
  // `URL.port` normalizes an explicit default HTTP port (`:80`) to empty.
  // The intercepted Container request retains its HTTP authority in Host, so
  // require the exact bare hostname there as well as in the parsed URL.
  const authority = request.headers.get("host");
  const expectedPath = `/client/v4/accounts/${STAGING_ACCOUNT_ID}/d1/database/${STAGING_DATABASE_ID}/query`;
  if (
    request.method !== "POST" ||
    url.protocol !== "http:" ||
    url.hostname !== D1_PROXY_HOST ||
    url.port !== "" ||
    authority !== D1_PROXY_HOST ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname !== expectedPath
  ) {
    return jsonError(404, "D1 binding proxy target rejected");
  }
  if (
    env.ENVIRONMENT !== "staging" ||
    env.CLOUDFLARE_ACCOUNT_ID !== STAGING_ACCOUNT_ID ||
    env.D1_DATABASE_ID !== STAGING_DATABASE_ID ||
    !stagingR2EndpointMatchesAccount(env.R2_S3_ENDPOINT)
  ) {
    return jsonError(503, "staging D1 binding is not configured for this target");
  }
  if (
    request.headers.has("authorization") ||
    request.headers.has("cookie") ||
    !/^application\/json(?:\s*;|\s*$)/i.test(request.headers.get("content-type") ?? "") ||
    (request.headers.get("content-encoding") ?? "identity").toLowerCase() !== "identity"
  ) {
    return jsonError(400, "D1 binding proxy request headers rejected");
  }

  let input: unknown;
  let bytes: ArrayBuffer;
  try { checkDeadline(); } catch { return jsonError(502, "D1 binding operation failed"); }
  try {
    bytes = await request.arrayBuffer();
  } catch {
    return jsonError(400, "D1 binding proxy body is malformed");
  }
  try { checkDeadline(); } catch { return jsonError(502, "D1 binding operation failed"); }
  try {
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BODY_BYTES) {
      return jsonError(413, "D1 binding proxy body size rejected");
    }
    input = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return jsonError(400, "D1 binding proxy body is malformed");
  }
  try {
    checkDeadline();
    const envelope = await executeD1Input(env.CONFIG_DB, input, checkDeadline);
    checkDeadline();
    return Response.json(envelope, { headers: { "cache-control": "no-store" } });
  } catch {
    return jsonError(502, "D1 binding operation failed");
  }
}

async function executeD1Input(
  db: D1Database,
  input: unknown,
  checkDeadline: () => void,
): Promise<{ result: Array<{ results: unknown[]; success: boolean }>; success: boolean; errors: [] }> {
  const record = exactRecord(input);
  if (record === null) throw new Error("invalid request envelope");
  if (Object.keys(record).length === 2 && "sql" in record && "params" in record) {
    const statement = parseStatement(record);
    checkDeadline();
    const result = await prepare(db, statement).all();
    checkDeadline();
    return {
      result: [{ results: result.results, success: result.success }],
      success: result.success,
      errors: [],
    };
  }
  if (Object.keys(record).length === 1 && "batch" in record && Array.isArray(record["batch"])) {
    if (record["batch"].length === 0 || record["batch"].length > MAX_BATCH_STATEMENTS) {
      throw new Error("batch size rejected");
    }
    const statements = record["batch"].map((item) => prepare(db, parseStatement(exactRecord(item))));
    // D1Database.batch is transactional: any failed statement rolls back all.
    checkDeadline();
    const results = await db.batch(statements);
    checkDeadline();
    return {
      result: results.map((item) => ({ results: item.results, success: item.success })),
      success: results.every((item) => item.success),
      errors: [],
    };
  }
  throw new Error("unknown request envelope");
}

function parseStatement(value: Record<string, unknown> | null): StatementInput {
  if (
    value === null ||
    Object.keys(value).length !== 2 ||
    typeof value["sql"] !== "string" ||
    value["sql"].length === 0 ||
    new TextEncoder().encode(value["sql"]).byteLength > MAX_SQL_BYTES ||
    value["sql"].includes("\0") ||
    !Array.isArray(value["params"]) ||
    value["params"].length > MAX_PARAMS
  ) {
    throw new Error("statement rejected");
  }
  const params = value["params"].map(parseParam);
  return { sql: value["sql"], params };
}

function parseParam(value: unknown): D1Param {
  if (value === null || typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  // JSON booleans are normalized to SQLite's integer representation.
  if (typeof value === "boolean") return value ? 1 : 0;
  throw new Error("D1 parameter type rejected");
}

function prepare(db: D1Database, statement: StatementInput) {
  return db.prepare(statement.sql).bind(...statement.params);
}

function exactRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function stagingR2EndpointMatchesAccount(endpoint: string | undefined): boolean {
  if (typeof endpoint !== "string") return false;
  try {
    const url = new URL(endpoint);
    return url.protocol === "https:" &&
      url.hostname === `${STAGING_ACCOUNT_ID}.r2.cloudflarestorage.com` &&
      url.port === "" && url.username === "" && url.password === "" &&
      url.pathname === "/" && url.search === "" && url.hash === "";
  } catch {
    return false;
  }
}

function jsonError(status: number, message: string): Response {
  return Response.json(
    { result: [], success: false, errors: [{ message }] },
    { status, headers: { "cache-control": "no-store" } },
  );
}
