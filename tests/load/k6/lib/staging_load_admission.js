// Request-scoped staging admission for k6 workload traffic.
// This module never writes credentials, nonces, or tags to stdout or artifacts.

import crypto from 'k6/crypto';

const DOMAIN = 'corelink/staging-load-admission-auth/v2\0';
const LIFETIME_MS = 60_000;
const HEADER = 'x-corelink-staging-load-admission';
const KEY = __ENV.K6_STAGING_LOAD_ADMISSION_KEY || '';
const RUN_ID = __ENV.K6_RUN_ID || '';
const SCENARIO = __ENV.K6_STAGING_LOAD_SCENARIO || '';
const DEPLOYMENT_SHA = __ENV.K6_TARGET_DEPLOYMENT_SHA || '';

export const ADMISSION_GOLDEN_VECTOR_V2 = {
  key: '01234567890123456789012345678901',
  payload: 'v2.123.cas.staging.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.100.200.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  tag: '4e2eac1b4406894df9d64b59ef5ad2446ab0ab707425280f37fb207ca8eb0ab0',
};

function lowerHex(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function assertConfig(key, runId, scenario, deploymentSha) {
  if (key.length < 32) throw new Error('K6_STAGING_LOAD_ADMISSION_KEY required');
  if (!/^\d{1,20}$/.test(runId)) throw new Error('K6_RUN_ID must be canonical');
  if (!/^(signup|webhook|dsr|cas|byok|endurance-2h)$/.test(scenario)) throw new Error('K6_STAGING_LOAD_SCENARIO is not allowlisted');
  if (!/^[a-f0-9]{40}$/.test(deploymentSha)) throw new Error('K6_TARGET_DEPLOYMENT_SHA must be lowercase 40-hex');
}

export function requireAdmissionConfig() {
  assertConfig(KEY, RUN_ID, SCENARIO, DEPLOYMENT_SHA);
}

export function mintAdmissionCredential({ nowMs, nonce } = {}) {
  assertConfig(KEY, RUN_ID, SCENARIO, DEPLOYMENT_SHA);
  const issued = nowMs === undefined ? Date.now() : nowMs;
  const expires = issued + LIFETIME_MS;
  const freshNonce = nonce || lowerHex(crypto.randomBytes(32));
  const payload = `v2.${RUN_ID}.${SCENARIO}.staging.${DEPLOYMENT_SHA}.${issued}.${expires}.${freshNonce}`;
  const tag = crypto.hmac('sha256', KEY, DOMAIN + payload, 'hex');
  return `${payload}.${tag}`;
}

// Call at every HTTP operation. Do not cache this return value.
export function admissionHeaders(extra) {
  return Object.assign({ [HEADER]: mintAdmissionCredential() }, extra || {});
}
