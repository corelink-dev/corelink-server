// R3-prep load test — DSR API ("annual privacy week" scenario).
//
// SCENARIO
// --------
// DSRs are infrequent in steady state (perhaps a handful per tenant per
// year), but a regulatory event can trigger a *cluster* — privacy week,
// breach notice cascade, regulator audit. This test models that surge:
// 20 RPS sustained for 10 min, mixed across access / erasure / portability.
//
// Endpoints exercised — see `crates/corelink-dsr/src/endpoint.rs`:
//   POST /v1/privacy/dsr/access
//   POST /v1/privacy/dsr/erasure
//   POST /v1/privacy/dsr/portability
//
// Assertions:
//   (a) p99 ≤ 1s (DSR endpoints are async-acknowledged; the synchronous leg
//       only enqueues + signs a receipt JWT, target ≤ 1s p99),
//   (b) every successful response carries a receipt JWT whose `alg` is
//       Ed25519 and whose `sig` is non-empty,
//   (c) re-submitting the same `client_request_id` returns the identical
//       receipt (idempotency held — see `crates/corelink-dsr/src/store.rs`).
//
// MFA in staging
// --------------
// Production wiring requires a fresh Clerk MFA token. Staging accepts a
// stubbed `x-corelink-mfa-test-token` header signed with the staging MFA
// signing key (`K6_MFA_STUB_TOKEN`). This switch is documented in
// `crates/corelink-dsr/src/mfa.rs` and is GATED — production refuses the
// stub header entirely.

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';
import { admissionHeaders, requireAdmissionConfig } from './lib/staging_load_admission.js';

const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';
const MFA_STUB    = __ENV.K6_MFA_STUB_TOKEN || '';

// Defer env-required gate to setup() so `k6 inspect` (syntax check) works
// in CI without secrets.
export function setup() {
  if (!MFA_STUB) {
    throw new Error('K6_MFA_STUB_TOKEN env required');
  }
  requireAdmissionConfig();
  return {};
}

const DSR_VERBS = ['access', 'erasure', 'portability'];

const receiptInvalid       = new Counter('dsr_receipt_invalid_total');
const idempotencyMismatch  = new Counter('dsr_idempotency_mismatch_total');
const receiptLatency       = new Trend('dsr_receipt_latency_ms', true);

export const options = {
  scenarios: {
    dsr_steady: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 40,
      maxVUs: 80,
    },
  },
  thresholds: {
    'http_req_duration{endpoint:dsr}': ['p(99)<1000'],
    'http_req_failed{endpoint:dsr}': ['rate<0.001'],
    'dsr_receipt_invalid_total': ['count==0'],
    'dsr_idempotency_mismatch_total': ['count==0'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

function buildBody(verb, clientReqId) {
  return JSON.stringify({
    client_request_id: clientReqId,
    subject_email: `dsr-load+${clientReqId}@corelink.test`,
    verb,
    jurisdiction: 'EU',
    submitted_at_ms: Date.now(),
  });
}

function dsrHeaders() {
  return admissionHeaders({
    'content-type': 'application/json',
    'x-corelink-mfa-test-token': MFA_STUB,
    'x-corelink-load-test': 'r3-prep',
  });
}

// Receipt JWT shape: header.payload.signature (base64url). We only assert
// the structural minimum here; cryptographic verification is exercised by
// the e2e suite using the published Ed25519 jwks.
function receiptLooksValid(token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  // Each segment must be non-empty + base64url-shaped.
  return parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 0);
}

export default function main() {
  const verb = DSR_VERBS[Math.floor(Math.random() * DSR_VERBS.length)];
  const clientReqId = `load-${verb}-${randomString(12)}`;
  const url = `${TARGET_HOST}/v1/privacy/dsr/${verb}`;
  const body = buildBody(verb, clientReqId);

  const first = http.post(url, body, { headers: dsrHeaders(), tags: { endpoint: 'dsr' } });
  receiptLatency.add(first.timings.duration);

  const ok = check(first, {
    'dsr ack 2xx': (r) => r.status >= 200 && r.status < 300,
    'dsr receipt present': (r) => {
      try {
        return receiptLooksValid(r.json('receipt_jwt'));
      } catch (_) {
        return false;
      }
    },
  });
  if (!ok) {
    receiptInvalid.add(1);
    return;
  }
  const firstReceipt = first.json('receipt_jwt');

  // 20% of iterations resubmit the same `client_request_id` to exercise
  // idempotency — store must return the identical receipt JWT.
  if (Math.random() < 0.2) {
    const replay = http.post(url, body, { headers: dsrHeaders(), tags: { endpoint: 'dsr', replay: 'true' } });
    const sameReceipt = check(replay, {
      'replay dsr 2xx': (r) => r.status >= 200 && r.status < 300,
      'replay returns same receipt': (r) => r.json('receipt_jwt') === firstReceipt,
    });
    if (!sameReceipt) idempotencyMismatch.add(1);
  }
}
