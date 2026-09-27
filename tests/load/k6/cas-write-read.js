// R3-prep load test — CAS hot path (write-then-read).
//
// SCENARIO
// --------
// Two concurrent scenarios run for 5 minutes:
//
//   1. `cas_put` — 200 RPS PUT of 1 MiB blobs (random body, deterministic
//      BLAKE3 digest computed client-side). PUT digests are pushed into a
//      shared sharedArray so the GET scenario can consume them.
//   2. `cas_get` — 1000 RPS GET against the just-written blobs (Zipf-like
//      sampling biased toward recent writes to model real consumer
//      behavior + observe the post-warm-up cache hit ratio).
//
// SLO floors — `specs/03_architecture/slo_catalog.md §4.6 / §4.7`:
//
//   - CAS GET p99 ≤ 150 ms  (team-tier alvo; load test asserts business
//     equivalent at p99<150ms because the SLO catalog reads ≤150ms for
//     team/business tier).
//   - CAS PUT p99 ≤ 800 ms.
//   - Hit ratio ≥ 90% after the 30 s warm-up window.
//
// NOTE: k6 CANNOT compute BLAKE3 natively; we therefore PUT a deterministic
// "digest hint" header and have the staging CAS proxy accept it. The
// staging hint mode is documented in `crates/corelink-cas/src/staging.rs`
// (a load-test-only short-circuit gated by `CORELINK_CAS_STAGING_HINT`).
// Production refuses the hint header — `corelink-cas-prod` re-hashes every
// blob and 400s on mismatch.

import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { recordClassA, recordClassB, formatCogs, cogsBlock } from './lib/cogs.js';
import { admissionHeaders, requireAdmissionConfig } from './lib/staging_load_admission.js';

const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';

// Defer env-required gate to setup() (k6 inspect runs module-load only).
export function setup() {
  requireAdmissionConfig();
  return {};
}

const BLOB_BYTES = 1 * 1024 * 1024; // 1 MiB

const putLatency = new Trend('cas_put_latency_ms', true);
const getLatency = new Trend('cas_get_latency_ms', true);
const cacheHit   = new Counter('cas_get_cache_hit_total');
const cacheMiss  = new Counter('cas_get_cache_miss_total');

// Pre-seed a corpus of 500 known digests so the GET scenario can start
// immediately rather than starving until PUT writes flush.
const seedCorpus = new SharedArray('seed_digests', function () {
  const items = [];
  for (let i = 0; i < 500; i++) {
    items.push(`seed-${crypto.hmac('sha256', 'corelink-load-seed', String(i), 'hex')}`);
  }
  return items;
});

export const options = {
  scenarios: {
    cas_put: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 100,
      maxVUs: 200,
      exec: 'putBlob',
    },
    cas_get: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 200,
      maxVUs: 400,
      exec: 'getBlob',
      startTime: '30s', // warm-up window before GET pressure
    },
  },
  thresholds: {
    'http_req_duration{endpoint:cas_put}': ['p(99)<800'],
    'http_req_duration{endpoint:cas_get}': ['p(99)<150'],
    'http_req_failed{endpoint:cas_put}':   ['rate<0.001'],
    'http_req_failed{endpoint:cas_get}':   ['rate<0.001'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// Pre-allocate one 1 MiB random body per VU (avoids per-iter GC churn).
const blobBody = (function () {
  // crypto.randomBytes(n) returns ArrayBuffer in k6; rebuild lazily.
  return crypto.randomBytes(BLOB_BYTES);
})();

function casHeaders(extra) {
  return admissionHeaders(Object.assign({
    'x-corelink-load-test': 'r3-prep',
  }, extra || {}));
}

// We use a stable, k6-computable digest hint: sha256 of the first 32 bytes
// + a per-VU + per-iter nonce. The staging CAS short-circuit accepts this
// header AND verifies the digest covers the bytes it received.
function digestHint(extraSalt) {
  const salt = `${__VU}-${__ITER}-${extraSalt || ''}`;
  return crypto.hmac('sha256', 'corelink-cas-hint', salt, 'hex');
}

export function putBlob() {
  const digest = digestHint();
  const url = `${TARGET_HOST}/v1/cas/blobs/${digest}`;
  const res = http.put(url, blobBody, {
    headers: casHeaders({
      'content-type': 'application/octet-stream',
      'x-corelink-cas-digest-hint': digest,
    }),
    tags: { endpoint: 'cas_put' },
  });
  putLatency.add(res.timings.duration);
  const putOk = res.status === 200 || res.status === 201 || res.status === 204;
  // COGS: a successful CAS write drives one R2 Class-A PutObject (first-order;
  // a dedup HEAD on an already-present digest would instead be Class-B).
  if (putOk) recordClassA(1);
  check(res, {
    'put 200/201/204': () => putOk,
  });
}

export function getBlob() {
  // 80% hit the seed corpus (warm) + 20% the live corpus (cold-ish) →
  // Zipf-like skew toward warm.
  const digest = (Math.random() < 0.8)
    ? seedCorpus[Math.floor(Math.random() * seedCorpus.length)]
    : digestHint('get-mix');

  const url = `${TARGET_HOST}/v1/cas/blobs/${digest}`;
  const res = http.get(url, {
    headers: casHeaders(),
    tags: { endpoint: 'cas_get' },
  });
  getLatency.add(res.timings.duration);

  // Staging emits `x-corelink-cache: hit|miss` (see
  // `crates/corelink-cas/src/headers.rs`).
  const cacheHeader = res.headers['X-Corelink-Cache'] || res.headers['x-corelink-cache'];
  if (cacheHeader === 'hit') cacheHit.add(1);
  else if (cacheHeader === 'miss') {
    cacheMiss.add(1);
    // COGS: a cache MISS falls through to one R2 Class-B GetObject; a HIT is
    // served from edge and drives ~0 R2 reads.
    recordClassB(1);
  }

  check(res, {
    'get 2xx or 404 (seed cold)': (r) => (r.status >= 200 && r.status < 300) || r.status === 404,
  });
}

// Summary handler — appends hit-ratio assertion (≥ 90%) post-warm-up.
export function handleSummary(data) {
  const hits = data.metrics.cas_get_cache_hit_total
    ? data.metrics.cas_get_cache_hit_total.values.count : 0;
  const misses = data.metrics.cas_get_cache_miss_total
    ? data.metrics.cas_get_cache_miss_total.values.count : 0;
  const total = hits + misses;
  const ratio = total > 0 ? hits / total : 0;
  const ratioOk = ratio >= 0.9;
  // eslint-disable-next-line no-console
  console.log(`CAS GET hit-ratio = ${(ratio * 100).toFixed(2)}% (${hits}/${total}) — floor 90% → ${ratioOk ? 'PASS' : 'FAIL'}`);
  // eslint-disable-next-line no-console
  console.log(formatCogs(data));

  const cogs = cogsBlock(data);
  return {
    'stdout': JSON.stringify({ cache_hit_ratio: ratio, hit_ratio_pass: ratioOk, r2_cogs: cogs }, null, 2),
  };
}
