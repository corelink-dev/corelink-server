/** Protected authorization for the narrow staging-native-gRPC diagnostic. */

import type { Env } from "./index_common.js";
import { constantTimeSecretEqual } from "./lib/internal_auth.js";

export const STAGING_GRPC_DIAGNOSTIC_HOST = "staging.corelink.humangr.com";
const STAGING_CLOUDFLARE_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
export const STAGING_GRPC_DIAGNOSTIC_PATHS = [
  "/corelink.staging.v1.TransportProbe/Unary",
  "/corelink.staging.v1.TransportProbe/Stream",
] as const;

const MAX_PROBE_LIFETIME_MS = 15 * 60 * 1_000;
const MIN_PROBE_TOKEN_BYTES = 32;
const bindingBrand = Symbol("corelink-staging-grpc-probe-binding");

export type StagingGrpcDiagnosticPath = (typeof STAGING_GRPC_DIAGNOSTIC_PATHS)[number];

/** Only this module can construct a value carrying the private brand. */
export type VerifiedStagingGrpcBinding = Readonly<{
  path: StagingGrpcDiagnosticPath;
  [bindingBrand]: true;
}>;

function canonicalInteger(value: string | undefined): number | null {
  if (value === undefined || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && String(parsed) === value ? parsed : null;
}

function hasNativeGrpcMediaType(headers: Headers): boolean {
  const mediaType = headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/grpc" || mediaType === "application/grpc+proto";
}

function hasOnlyTrailersTe(headers: Headers): boolean {
  const value = headers.get("te");
  if (value === null) return false;
  const values = value.split(",").map((part) => part.trim().toLowerCase());
  return values.length === 1 && values[0] === "trailers";
}

function diagnosticPath(request: Request): StagingGrpcDiagnosticPath | null {
  const url = new URL(request.url);
  if (
    request.method !== "POST" ||
    url.protocol !== "https:" ||
    url.hostname !== STAGING_GRPC_DIAGNOSTIC_HOST ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !hasNativeGrpcMediaType(request.headers) ||
    !hasOnlyTrailersTe(request.headers)
  ) return null;
  return STAGING_GRPC_DIAGNOSTIC_PATHS.includes(url.pathname as StagingGrpcDiagnosticPath)
    ? url.pathname as StagingGrpcDiagnosticPath
    : null;
}

/** True for either reserved probe path, regardless of request shape. */
export function isStagingGrpcDiagnosticPath(request: Request): boolean {
  return STAGING_GRPC_DIAGNOSTIC_PATHS.includes(
    new URL(request.url).pathname as StagingGrpcDiagnosticPath,
  );
}

/** True only for the two syntactically valid diagnostic requests. */
export function isStagingGrpcDiagnosticRequest(request: Request): boolean {
  return diagnosticPath(request) !== null;
}

/**
 * Authenticate the protected operator credential and staging bindings. This
 * routine neither logs nor transforms Authorization or request bytes.
 */
export function verifyStagingGrpcDiagnosticBinding(
  request: Request,
  env: Env,
  nowMs = Date.now(),
): VerifiedStagingGrpcBinding | null {
  const path = diagnosticPath(request);
  const expectedToken = env.CORELINK_STAGING_GRPC_PROBE_TOKEN;
  const expiresAtMs = canonicalInteger(env.CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS);
  const deploymentSha = env.CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA;
  const authorization = request.headers.get("authorization");
  const token = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : "";

  if (
    path === null ||
    env.CORELINK_ENVIRONMENT !== "staging" ||
    env.ENVIRONMENT !== "staging" ||
    env.CLOUDFLARE_ACCOUNT_ID !== STAGING_CLOUDFLARE_ACCOUNT_ID ||
    env.CORELINK_STAGING_GRPC_PROBE_WORKER_NAME !== "corelink-staging" ||
    expectedToken === undefined ||
    new TextEncoder().encode(expectedToken).byteLength < MIN_PROBE_TOKEN_BYTES ||
    expiresAtMs === null ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0 ||
    nowMs >= expiresAtMs ||
    expiresAtMs > nowMs + MAX_PROBE_LIFETIME_MS ||
    deploymentSha === undefined ||
    !/^[0-9a-f]{40}$/.test(deploymentSha) ||
    !constantTimeSecretEqual(expectedToken, token)
  ) return null;

  const binding: VerifiedStagingGrpcBinding = { path, [bindingBrand]: true };
  return Object.freeze(binding);
}
