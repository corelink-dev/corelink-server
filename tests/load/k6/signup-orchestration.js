// R3-prep load test — signup orchestration burst.
//
// SCENARIO
// --------
// Exercises `POST /v1/signup` under burst load (0 → 50 RPS ramp over 1 min,
// 50 RPS sustained for 5 min). Each VU presents a *unique* idempotency key
// per iteration so the orchestrator must allocate one fresh tenant row per
// request.
//
// Property under test
// -------------------
//   "every signup with a unique Idempotency-Key creates exactly one tenant
//    row and returns a stable tenant_id on retry."
//
// We cannot read the D1 row from here, so atomicity is approximated via:
//   (a) HTTP 200 / 201 status,
//   (b) response body must include a `tenant_id` string,
//   (c) a 10% subset of iterations REPLAYS the same Idempotency-Key and
//       must observe the EXACT same tenant_id (orchestrator idempotency).
//
// SLO thresholds — match `specs/03_architecture/slo_catalog.md §4.1`
// (control-plane availability) and the signup orchestrator latency budget
// recorded in `crates/corelink-signup/src/orchestrator.rs` docs.
//
// USAGE
// -----
//   K6_TARGET_HOST=https://staging.corelink.humangr.com \
//   k6 run tests/load/k6/signup-orchestration.js
//
// DO NOT run against production. The script aborts if it detects a
// production-shaped hostname (`*.corelink.com` without `staging.`).

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';
import { admissionHeaders, requireAdmissionConfig } from './lib/staging_load_admission.js';

// ─────────────────────────────────────────────────────────────────────────
// Target host + auth resolution.
// ─────────────────────────────────────────────────────────────────────────
const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';

// Extract hostname without using the WHATWG URL global (k6/goja lacks it).
function extractHostname(u) {
  const m = /^https?:\/\/([^/:?#]+)/i.exec(u);
  return m ? m[1] : '';
}
const TARGET_HOSTNAME = extractHostname(TARGET_HOST);
if (/\.corelink\.com$/.test(TARGET_HOSTNAME) && TARGET_HOSTNAME.indexOf('staging.') === -1) {
  throw new Error('refusing to run signup load test against production hostname');
}

// ─────────────────────────────────────────────────────────────────────────
// Metrics.
// ─────────────────────────────────────────────────────────────────────────
const signupSuccess = new Counter('signup_success_total');
const signupIdempotencyMismatch = new Counter('signup_idempotency_mismatch_total');
const signupBodyLatency = new Trend('signup_body_latency_ms', true);

// ─────────────────────────────────────────────────────────────────────────
// Stage config.
// ─────────────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    signup_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 100,
      stages: [
        { target: 50, duration: '1m' },  // ramp 0 → 50 RPS
        { target: 50, duration: '5m' },  // sustain 50 RPS
        { target: 0,  duration: '30s' }, // graceful drain
      ],
    },
  },
  thresholds: {
    // p99 latency budget per spec (control plane: 500 ms p99 incl orchestrator
    // fan-out to Clerk + D1 INSERT). Below floor will fail the run.
    'http_req_duration{endpoint:signup}': ['p(99)<500'],
    // Error budget: ≤ 0.1% non-2xx across the run.
    'http_req_failed{endpoint:signup}': ['rate<0.001'],
    'signup_idempotency_mismatch_total': ['count==0'],
  },
  // Drop verbose iteration metrics; keep summary only.
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  requireAdmissionConfig();
  return {};
}

// ─────────────────────────────────────────────────────────────────────────
// VU helpers.
// ─────────────────────────────────────────────────────────────────────────
function buildSignupPayload(suffix) {
  // Synthetic — orchestrator validates shape, not identity provenance,
  // because staging Clerk is configured with the test PAT issuer.
  return JSON.stringify({
    email: `loadtest+${suffix}@corelink.test`,
    org_name: `LoadTest Org ${suffix}`,
    region: 'us-east-1',
    accept_dpa: true,
  });
}

function signupHeaders(idemKey) {
  return admissionHeaders({
    'content-type': 'application/json',
    'idempotency-key': idemKey,
    'x-corelink-load-test': 'r3-prep',
  });
}

// ─────────────────────────────────────────────────────────────────────────
// VU body.
// ─────────────────────────────────────────────────────────────────────────
export default function main() {
  const suffix = randomString(12);
  const idemKey = `load-${suffix}`;
  const url = `${TARGET_HOST}/v1/signup`;
  const body = buildSignupPayload(suffix);
  const first = http.post(url, body, { headers: signupHeaders(idemKey), tags: { endpoint: 'signup' } });
  signupBodyLatency.add(first.timings.duration);

  const firstOk = check(first, {
    'first signup status 2xx': (r) => r.status >= 200 && r.status < 300,
    'first signup has tenant_id': (r) => {
      try {
        return typeof r.json('tenant_id') === 'string';
      } catch (_) {
        return false;
      }
    },
  });
  if (!firstOk) return;
  signupSuccess.add(1);
  const firstTenant = first.json('tenant_id');

  // 10% of iterations replay the SAME idempotency key — orchestrator MUST
  // return the same tenant_id and MUST NOT allocate a second row.
  if (Math.random() < 0.1) {
    sleep(0.05);
    const replay = http.post(url, body, {
      headers: signupHeaders(idemKey),
      tags: { endpoint: 'signup', replay: 'true' },
    });
    const replayOk = check(replay, {
      'replay signup status 2xx': (r) => r.status >= 200 && r.status < 300,
      'replay returns same tenant_id': (r) => r.json('tenant_id') === firstTenant,
    });
    if (!replayOk) {
      signupIdempotencyMismatch.add(1);
    }
  }
}
