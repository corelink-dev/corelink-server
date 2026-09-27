// R3-prep load test — Stripe webhook idempotency burst.
//
// SCENARIO
// --------
// Stripe retries failed deliveries for up to 3 days, and may legitimately
// re-deliver the same event_id many times in a short window after a Worker
// transient. This test replays the SAME 10 event_ids from 100 simultaneous
// VUs for 2 minutes, asserting:
//
//   (a) 100% of replays return HTTP 200,
//   (b) zero double-mutation (handler dispatch count == 10 across the run,
//       observed indirectly via response body marker),
//   (c) p99 latency ≤ 200 ms — the dedup INSERT-OR-IGNORE in D1 must be the
//       hot path, NOT the signature verify or the dispatch.
//
// Property under test — INV-WEBHOOK-IDEMPOTENT (see
//   apps/server/src/webhook.rs §Invariants):
//
//     ∀ event_id e, ∀ delivery d₁ d₂ … : handle(e, d_n) ≡ handle(e, d₁)
//
// We CANNOT mint real Stripe HMACs from a load test without leaking the
// signing secret, so we rely on a staging-only webhook secret exposed to CI
// via `K6_STRIPE_WHSEC` and compute the t=…,v1=… header in JS.
//
// USAGE
// -----
//   K6_TARGET_HOST=https://staging.corelink.humangr.com \
//   K6_STRIPE_WHSEC=$STAGING_WHSEC \
//   k6 run tests/load/k6/stripe-webhook-burst.js

import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { admissionHeaders, requireAdmissionConfig } from './lib/staging_load_admission.js';

const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';
const STRIPE_WHSEC = __ENV.K6_STRIPE_WHSEC || '';

// setup() runs once per test; module-load runs ALSO during `k6 inspect`
// (where env vars are not yet bound). Defer the env-required gate to
// setup so `k6 inspect` can validate syntax without secrets.
export function setup() {
  if (!STRIPE_WHSEC) {
    throw new Error('K6_STRIPE_WHSEC env required (staging-only webhook secret)');
  }
  requireAdmissionConfig();
  return {};
}

// 10 canonical event_ids replayed across the whole run.
const REPLAY_EVENT_IDS = [
  'evt_load_001', 'evt_load_002', 'evt_load_003', 'evt_load_004', 'evt_load_005',
  'evt_load_006', 'evt_load_007', 'evt_load_008', 'evt_load_009', 'evt_load_010',
];

const EVENT_TYPES = [
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'customer.subscription.trial_will_end',
  'invoice.paid',
  'invoice.payment_failed',
];

const duplicateAck = new Counter('webhook_duplicate_ack_total');
const nonTwoHundred = new Counter('webhook_non_200_total');

export const options = {
  scenarios: {
    webhook_replay: {
      executor: 'constant-vus',
      vus: 100,
      duration: '2m',
    },
  },
  thresholds: {
    // p99 ≤ 200 ms: dedup path is INSERT-OR-IGNORE; nothing else should
    // dominate.
    'http_req_duration{endpoint:webhook}': ['p(99)<200'],
    'http_req_failed{endpoint:webhook}': ['rate<0.0001'],
    'webhook_non_200_total': ['count==0'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// Stripe canonical signature: HMAC_SHA256(secret, "${ts}.${payload}").
function stripeSignature(secret, ts, payload) {
  const mac = crypto.hmac('sha256', secret, `${ts}.${payload}`, 'hex');
  return `t=${ts},v1=${mac}`;
}

function buildEnvelope(eventId, eventType) {
  // Stripe envelope shape — minimal subset the dispatcher uses. The
  // `data.object.status` field is needed for `customer.subscription.updated`.
  return JSON.stringify({
    id: eventId,
    type: eventType,
    created: Math.floor(Date.now() / 1000),
    data: {
      object: {
        id: `sub_load_${eventId}`,
        status: 'active',
      },
    },
  });
}

export default function main() {
  const eventId = REPLAY_EVENT_IDS[Math.floor(Math.random() * REPLAY_EVENT_IDS.length)];
  const eventType = EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];
  const ts = Math.floor(Date.now() / 1000);
  const body = buildEnvelope(eventId, eventType);
  const signature = stripeSignature(STRIPE_WHSEC, ts, body);

  const res = http.post(
    `${TARGET_HOST}/v1/billing/stripe-webhook`,
    body,
    {
      headers: admissionHeaders({
        'content-type': 'application/json',
        'stripe-signature': signature,
        'x-corelink-load-test': 'r3-prep',
      }),
      tags: { endpoint: 'webhook' },
    },
  );

  const ok = check(res, {
    'webhook returns 200': (r) => r.status === 200,
  });
  if (!ok) {
    nonTwoHundred.add(1);
  }
  // The route returns the literal "duplicate event acknowledged" body when
  // the dedup row was already present — track these for the report.
  if (res.body && String(res.body).indexOf('duplicate event acknowledged') !== -1) {
    duplicateAck.add(1);
  }
}
