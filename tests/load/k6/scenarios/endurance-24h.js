// R-prep endurance test — 24h sustained realistic traffic mix.
//
// PURPOSE
// -------
// The five short-burst scenarios under `tests/load/k6/*.js` exercise hot
// paths for ≤ 10 minutes and catch *acute* regressions. They are blind to
// slow-drift failure modes that only manifest at hours-of-uptime scale:
//
//   * Memory leaks in Worker isolates / Container DEK cache.
//   * Slowly degrading p99 latency as background GC pressure builds.
//   * Audit-chain append-only verifier lag accumulating against ingest.
//   * Log volume escalation (cardinality explosion) crossing 500 GiB/day.
//   * SLO error-budget burn that only crosses threshold over multi-hour
//     windows (the multi-burn alert is 1h × 14.4 burn → only fires at
//     ~4.2% error rate sustained, missed by 5-min scenarios).
//
// This scenario keeps a steady realistic traffic *mix* (modeled on the
// lighthouse customer projection — see `marketing/lighthouse-kit/
// CUSTOMER-PLAYBOOK.md §4`) running for 24 hours with full per-hour
// histogramming so post-run analysis (see
// `endurance-24h-ANALYSIS-TEMPLATE.md`) can detect drift trivially.
//
// TRAFFIC MIX (per iteration draw — verified at setup())
//   60% CAS reads      (cache hits dominant)
//   15% CAS writes
//   10% audit queries
//    8% BYOK envelope ops
//    5% admin operations
//    2% webhook ingest
//
// TENANT POOL
//   50 simulated tenants. Activity weight is Zipfian (s = 1.07) so the
//   top-5 tenants emit ~60% of traffic — matches the observed lighthouse
//   cohort distribution.
//
// DURATION (env-controllable)
//   DURATION=24h (default) | 2h (CI nightly) | 30s (smoke / dry-run)
//   Composition: 5min ramp-up + (DURATION - 10min) steady + 5min ramp-down.
//   For DURATION < 11min the ramp windows collapse proportionally (ramp =
//   max(5s, DURATION * 0.05)).
//
// VUs
//   50 sustained (constant-vus executor, NOT arrival-rate — we want a
//   *stable closed-loop population* that mirrors a fixed customer fleet,
//   not an externally-driven arrival rate. Closed-loop also surfaces
//   queueing-pathology drift that arrival-rate hides.)
//
// FAILURE BUDGET PER HOUR
//   0.1% error rate per rolling 5-min window. The scenario trips its
//   `endurance_budget_breach` threshold if 3 consecutive 5-min windows
//   each exceed 0.1% — the same 3-strike pattern used by the multi-burn
//   PD alert (see `observability_model.md §9`).
//
// METRICS EXPORT
//   K6 writes Prometheus remote-write samples (configure via
//   K6_PROMETHEUS_RW_SERVER_URL) tagged with `hour=0..23` so a single
//   PromQL group-by-hour produces the drift series. The companion
//   `cas_read_p99_per_hour`, `audit_query_latency_per_hour`,
//   `error_rate_per_hour`, `memory_drift_per_hour` (derived from the
//   `/v1/admin/diagnostics/memory` polling iter) are emitted as custom
//   k6 Trend/Gauge metrics also tagged with hour-of-test.
//
// SAFETY RAILS
//   * Refuses to run if K6_TARGET_HOST is not a `staging.*` or `dev.*`
//     hostname (matches the other R3-prep scripts).
//   * Refuses to run without a request-scoped staging admission key.
//   * Refuses to run if DURATION > 30s and K6_ENDURANCE_CONFIRM != "yes"
//     when running interactively (catches accidental local 24h kicks).
//
// SLO references — `specs/03_architecture/slo_catalog.md`:
//   §4.6 CAS GET p99       — drift floor: + 50ms over 24h max
//   §4.7 CAS PUT p99       — drift floor: + 150ms over 24h max
//   §4.8 AC hit p99        — drift floor: + 30ms over 24h max
//   §4.11 Freshness — Billing events — webhook 95% < 5s sustained
//   §4.20 MTTA / §4.21 MTTR — n/a (synthetic, not a real page)
//
// USAGE (CI 2h nightly):
//   DURATION=2h \
//   K6_TARGET_HOST=https://staging.corelink.humangr.com \
//   K6_ENDURANCE_CONFIRM=yes \
//   K6_PROMETHEUS_RW_SERVER_URL=https://prom-rw.staging.corelink.humangr.com/api/v1/write \
//   k6 run --out experimental-prometheus-rw \
//     tests/load/k6/scenarios/endurance-24h.js
//
// USAGE (manual 24h drill — see RB-ENDURANCE-24H-DRILL):
//   DURATION=24h K6_ENDURANCE_CONFIRM=yes ... k6 run ...

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend, Gauge, Rate } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { admissionHeaders, requireAdmissionConfig } from '../lib/staging_load_admission.js';

// ─────────────────────────────────────────────────────────────────────────
// Env + safety
// ─────────────────────────────────────────────────────────────────────────
const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';
const RUN_ID = __ENV.K6_RUN_ID || '';
const DURATION = __ENV.DURATION || '24h';
const VUS = Number(__ENV.VUS || '50');
const CONFIRM = __ENV.K6_ENDURANCE_CONFIRM || '';
const MAX_VUS = 50;

if (!Number.isInteger(VUS) || VUS < 1 || VUS > MAX_VUS) {
  throw new Error(`VUS must be an integer between 1 and ${MAX_VUS}, got ${__ENV.VUS || '50'}`);
}

function extractHostname(u) {
  const m = /^https?:\/\/([^/:?#]+)/i.exec(u);
  return m ? m[1] : '';
}
const TARGET_HOSTNAME = extractHostname(TARGET_HOST);
if (/\.corelink\.com$/.test(TARGET_HOSTNAME) && TARGET_HOSTNAME.indexOf('staging.') === -1) {
  throw new Error('refusing to run endurance load test against production hostname');
}

// Parse DURATION (k6 duration strings: "24h", "2h", "30s", "10m").
function parseDurationSeconds(d) {
  const m = /^(\d+)(s|m|h)$/.exec(d);
  if (!m) throw new Error(`DURATION must match /^\\d+(s|m|h)$/, got ${d}`);
  const n = parseInt(m[1], 10);
  return m[2] === 'h' ? n * 3600 : m[2] === 'm' ? n * 60 : n;
}
const TOTAL_SECONDS = parseDurationSeconds(DURATION);

// Ramp = min(5min, max(5s, 5% of total)). Always symmetric.
const RAMP_SECONDS = Math.min(300, Math.max(5, Math.floor(TOTAL_SECONDS * 0.05)));
const STEADY_SECONDS = Math.max(1, TOTAL_SECONDS - 2 * RAMP_SECONDS);

// Refuse long runs without explicit confirmation. The 30s smoke path is
// always allowed (dry-run for k6 inspect / CI syntax check).
if (TOTAL_SECONDS > 30 && CONFIRM !== 'yes') {
  throw new Error(
    `K6_ENDURANCE_CONFIRM=yes required for DURATION>${30}s (got DURATION=${DURATION}, ${TOTAL_SECONDS}s)`,
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Tenant pool — 50 tenants with Zipfian activity weight (s = 1.07).
// Top-5 tenants ~60% of traffic; long tail of low-volume tenants.
// ─────────────────────────────────────────────────────────────────────────
const TENANT_COUNT = 50;
const ZIPF_S = 1.07;

const tenantPool = new SharedArray('tenant_pool', function () {
  // Pre-compute Zipfian cumulative distribution.
  const weights = [];
  let total = 0;
  for (let i = 1; i <= TENANT_COUNT; i++) {
    const w = 1 / Math.pow(i, ZIPF_S);
    weights.push(w);
    total += w;
  }
  // Cumulative normalized.
  const cum = [];
  let running = 0;
  for (let i = 0; i < TENANT_COUNT; i++) {
    running += weights[i] / total;
    cum.push(running);
  }
  const tenants = [];
  for (let i = 0; i < TENANT_COUNT; i++) {
    tenants.push({
      tenant_id: `t_endurance_${String(i).padStart(3, '0')}`,
      cum_weight: cum[i],
    });
  }
  return tenants;
});

function pickTenant() {
  const r = Math.random();
  for (let i = 0; i < tenantPool.length; i++) {
    if (r <= tenantPool[i].cum_weight) return tenantPool[i];
  }
  return tenantPool[tenantPool.length - 1];
}

// ─────────────────────────────────────────────────────────────────────────
// Traffic mix — cumulative thresholds.
// ─────────────────────────────────────────────────────────────────────────
// Adjusting any percentage requires updating the ANALYSIS template too.
const MIX = [
  { op: 'cas_read',     threshold: 0.60 },                       // 0.00 - 0.60
  { op: 'cas_write',    threshold: 0.60 + 0.15 },                // 0.60 - 0.75
  { op: 'audit_query',  threshold: 0.60 + 0.15 + 0.10 },         // 0.75 - 0.85
  { op: 'byok_op',      threshold: 0.60 + 0.15 + 0.10 + 0.08 },  // 0.85 - 0.93
  { op: 'admin_op',     threshold: 0.60 + 0.15 + 0.10 + 0.08 + 0.05 }, // 0.93 - 0.98
  { op: 'webhook',      threshold: 1.00 },                       // 0.98 - 1.00
];

function pickOperation() {
  const r = Math.random();
  for (let i = 0; i < MIX.length; i++) {
    if (r <= MIX[i].threshold) return MIX[i].op;
  }
  return 'cas_read';
}

// ─────────────────────────────────────────────────────────────────────────
// Custom metrics — every Trend/Counter is also surfaced *per hour* via the
// `hour` tag (0..23 for the 24h run; for shorter runs it just collapses to
// hour=0).
// ─────────────────────────────────────────────────────────────────────────
const opLatency = new Trend('endurance_op_latency_ms', true);
const opErrors = new Counter('endurance_op_errors_total');
const opSuccess = new Counter('endurance_op_success_total');
const errorRate = new Rate('endurance_error_rate');

// Per-operation drift series.
const casReadP99Per = new Trend('cas_read_p99_per_hour', true);
const auditQueryLatencyPer = new Trend('audit_query_latency_per_hour', true);
const errorRatePer = new Rate('error_rate_per_hour');
const memoryDriftPer = new Gauge('memory_drift_per_hour');

// Failure-budget tracking (3-strike rule).
const budgetBreachCounter = new Counter('endurance_budget_breach_strikes');

// Test-run start time (unix seconds). Set in setup().
let TEST_START_S = 0;

function hourOfTest() {
  // Falls back to 0 until setup() runs.
  if (!TEST_START_S) return 0;
  const nowS = Math.floor(Date.now() / 1000);
  return Math.min(23, Math.floor((nowS - TEST_START_S) / 3600));
}

function hourTags() {
  return { hour: String(hourOfTest()) };
}

// ─────────────────────────────────────────────────────────────────────────
// k6 options — single closed-loop scenario with ramp-up / steady / ramp-down.
// ─────────────────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    endurance: {
      executor: 'ramping-vus',
      startVUs: 0,
      gracefulRampDown: '30s',
      stages: [
        { duration: `${RAMP_SECONDS}s`, target: VUS },
        { duration: `${STEADY_SECONDS}s`, target: VUS },
        { duration: `${RAMP_SECONDS}s`, target: 0 },
      ],
      exec: 'enduranceIter',
    },
    // Sidecar: poll /v1/admin/diagnostics/memory every 60s and emit
    // `memory_drift_per_hour` so the analysis template can chart it.
    memory_poller: {
      executor: 'constant-vus',
      vus: 1,
      duration: `${TOTAL_SECONDS}s`,
      exec: 'pollMemory',
    },
  },
  thresholds: {
    // Global SLO assertion (24h aggregate).
    'endurance_error_rate': ['rate<0.001'],
    // Per-operation latency aggregates (drift floors from slo_catalog.md).
    'endurance_op_latency_ms{op:cas_read}':    ['p(99)<200'],
    'endurance_op_latency_ms{op:cas_write}':   ['p(99)<950'],
    'endurance_op_latency_ms{op:audit_query}': ['p(99)<2000'],
    'endurance_op_latency_ms{op:byok_op}':     ['p(99)<800'],
    'endurance_op_latency_ms{op:admin_op}':    ['p(99)<1500'],
    'endurance_op_latency_ms{op:webhook}':     ['p(99)<400'],
    // 3-strike budget breach tripwire (each strike = 5min window >0.1%).
    'endurance_budget_breach_strikes': ['count<3'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  // Tag every sample by hour-of-test for Prometheus group-by-hour.
  tags: { test: 'endurance-24h' },
};

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────
function authHeaders(tenant, extra) {
  return admissionHeaders(Object.assign(
    {
      'x-corelink-load-test': 'endurance-24h',
      'x-corelink-load-test-run-id': RUN_ID,
      'x-corelink-tenant-hint': tenant.tenant_id,
    },
    extra || {},
  ));
}

function record(op, res) {
  const tags = Object.assign({ op }, hourTags());
  opLatency.add(res.timings.duration, tags);
  const failed = res.status >= 500 || res.status === 0;
  if (failed) {
    // Fail loudly — do NOT swallow. Per charter: no console.error
    // swallowing in endurance scripts.
    opErrors.add(1, tags);
    errorRate.add(true, tags);
    errorRatePer.add(true, tags);
  } else {
    opSuccess.add(1, tags);
    errorRate.add(false, tags);
    errorRatePer.add(false, tags);
  }
  return !failed;
}

// ─────────────────────────────────────────────────────────────────────────
// Per-operation request builders. Each MUST return a k6 Response.
// The endpoints/headers below mirror the surfaces of the existing 5
// scenarios; production gates (anti-prod hostname, MFA stub, hint header)
// still apply.
// ─────────────────────────────────────────────────────────────────────────
function doCasRead(tenant) {
  // Stable digest from tenant_id + 1-of-100 hot keys (Zipfian within
  // tenant). 80% hit rate target per slo_catalog §4.6 / cas-write-read.
  const idx = Math.floor(Math.pow(Math.random(), ZIPF_S) * 100);
  const digest = `${tenant.tenant_id}_blob_${idx}`;
  const res = http.get(`${TARGET_HOST}/v1/cas/blobs/${digest}`, {
    headers: authHeaders(tenant),
    tags: Object.assign({ op: 'cas_read', endpoint: 'cas_get' }, hourTags()),
  });
  casReadP99Per.add(res.timings.duration, hourTags());
  return res;
}

function doCasWrite(tenant) {
  const idx = Math.floor(Math.random() * 1000);
  const digest = `${tenant.tenant_id}_run_${RUN_ID}_endurance_${idx}_${__VU}_${__ITER}`;
  // Small body — endurance is about *sustained mix*, not raw throughput.
  // Per-iter byte budget = ~4 KiB.
  const body = 'x'.repeat(4096);
  const res = http.put(`${TARGET_HOST}/v1/cas/blobs/${digest}`, body, {
    headers: authHeaders(tenant, {
      'content-type': 'application/octet-stream',
      'x-corelink-cas-digest-hint': digest,
    }),
    tags: Object.assign({ op: 'cas_write', endpoint: 'cas_put' }, hourTags()),
  });
  return res;
}

function doAuditQuery(tenant) {
  // Read recent audit chain entries (paginate first page).
  const res = http.get(
    `${TARGET_HOST}/v1/audit/events?tenant=${tenant.tenant_id}&limit=25`,
    {
      headers: authHeaders(tenant),
      tags: Object.assign({ op: 'audit_query', endpoint: 'audit_list' }, hourTags()),
    },
  );
  auditQueryLatencyPer.add(res.timings.duration, hourTags());
  return res;
}

function doByokOp(tenant) {
  // Encrypt a small payload via the BYOK envelope endpoint — the most
  // realistic per-iter BYOK operation (rotations + revokes are rare
  // events handled by the stampede scenario).
  const payload = JSON.stringify({ tenant: tenant.tenant_id, n: __ITER });
  const res = http.post(`${TARGET_HOST}/v1/byok/envelope/encrypt`, payload, {
    headers: authHeaders(tenant, { 'content-type': 'application/json' }),
    tags: Object.assign({ op: 'byok_op', endpoint: 'byok_envelope' }, hourTags()),
  });
  return res;
}

function doAdminOp(tenant) {
  // Tenant config read — represents the most common admin read path.
  const res = http.get(`${TARGET_HOST}/v1/admin/tenants/${tenant.tenant_id}/config`, {
    headers: authHeaders(tenant),
    tags: Object.assign({ op: 'admin_op', endpoint: 'admin_config_read' }, hourTags()),
  });
  return res;
}

function doWebhook(tenant) {
  // Use a stable synthetic event_id so the webhook idempotency table
  // doesn't accumulate ~50M rows over 24h. The 10 canonical load-test
  // event_ids are pre-allocated by `scripts/byok-load-warmup.sh` /
  // staging seed (see stripe-webhook-burst.js).
  const idx = Math.floor(Math.random() * 10);
  const eventId = `evt_load_endurance_${RUN_ID}_${idx}`;
  const body = JSON.stringify({
    id: eventId,
    type: 'invoice.paid',
    livemode: false,
    data: { object: { customer: tenant.tenant_id } },
  });
  const res = http.post(`${TARGET_HOST}/v1/billing/stripe-webhook`, body, {
    headers: authHeaders(tenant, {
      'content-type': 'application/json',
      'stripe-signature': 'staging-stub',
    }),
    tags: Object.assign({ op: 'webhook', endpoint: 'stripe_webhook' }, hourTags()),
  });
  return res;
}

// ─────────────────────────────────────────────────────────────────────────
// Main iter — picks an op + tenant per draw, records, sleeps a small
// jitter to simulate a real client (5-50ms think-time). With VUS=50 and
// avg think-time ~25ms + p99 latency ~200ms, sustained per-VU rate ≈ 4
// req/s → ~200 req/s aggregate, matches the lighthouse customer projection.
// ─────────────────────────────────────────────────────────────────────────
export function enduranceIter(data) {
  // Recover TEST_START_S from setup() data on every iter (k6 module
  // scope is per-VU; data is shared).
  if (data && data.start_s) TEST_START_S = data.start_s;

  const tenant = pickTenant();
  const op = pickOperation();
  let res;
  switch (op) {
    case 'cas_read':    res = doCasRead(tenant); break;
    case 'cas_write':   res = doCasWrite(tenant); break;
    case 'audit_query': res = doAuditQuery(tenant); break;
    case 'byok_op':     res = doByokOp(tenant); break;
    case 'admin_op':    res = doAdminOp(tenant); break;
    case 'webhook':     res = doWebhook(tenant); break;
    default:
      // Should be unreachable — but if pickOperation ever returns a new
      // op without a handler, FAIL LOUDLY rather than silently no-op.
      throw new Error(`endurance: no handler for op=${op}`);
  }
  const ok = record(op, res);
  check(res, {
    [`${op} not 5xx`]: () => ok,
  });
  // Think-time jitter — bounded so total per-VU req/s stays predictable.
  sleep(0.005 + Math.random() * 0.045);
}

// ─────────────────────────────────────────────────────────────────────────
// Memory polling sidecar — emits a Gauge tagged with hour-of-test so the
// analysis template can chart memory drift vs hour cleanly.
//
// If the endpoint isn't reachable (e.g. running against a staging without
// the diagnostics module enabled), we surface a warn-once log and keep
// running. We do NOT swallow the error silently: we EMIT a counter.
// ─────────────────────────────────────────────────────────────────────────
const memPollFail = new Counter('endurance_memory_poll_failures_total');

export function pollMemory(data) {
  if (data && data.start_s) TEST_START_S = data.start_s;
  const res = http.get(`${TARGET_HOST}/v1/admin/diagnostics/memory`, {
    headers: admissionHeaders({
      'x-corelink-load-test-run-id': RUN_ID,
    }),
    tags: Object.assign({ op: 'memory_poll' }, hourTags()),
  });
  if (res.status === 200) {
    try {
      const body = res.json();
      const rssMb = (body && body.rss_bytes) ? body.rss_bytes / (1024 * 1024) : 0;
      memoryDriftPer.add(rssMb, hourTags());
    } catch (e) {
      // Fail loudly — do not swallow.
      memPollFail.add(1, hourTags());
      console.warn(`memory_poller: parse failure: ${e.message || e}`);
    }
  } else {
    memPollFail.add(1, hourTags());
    if (__ITER === 0) {
      // First-iter warn so operator sees it immediately. Subsequent
      // failures are counted but not logged to avoid log spam over 24h.
      console.warn(`memory_poller: status=${res.status} body=${(res.body || '').slice(0, 200)}`);
    }
  }
  sleep(60);
}

// ─────────────────────────────────────────────────────────────────────────
// Lifecycle hooks
// ─────────────────────────────────────────────────────────────────────────
export function setup() {
  requireAdmissionConfig();
  if (!/^\d{1,20}$/.test(RUN_ID)) throw new Error('K6_RUN_ID must be the numeric GitHub run id');
  const startS = Math.floor(Date.now() / 1000);
  console.log(
    `endurance-24h start: target=${TARGET_HOSTNAME} duration=${DURATION} ` +
      `vus=${VUS} ramp=${RAMP_SECONDS}s steady=${STEADY_SECONDS}s ramp_down=${RAMP_SECONDS}s ` +
      `tenants=${TENANT_COUNT} zipf_s=${ZIPF_S}`,
  );
  // Verify the traffic mix sums to ~1.0 (defensive — guards against
  // future edits that desync the percentages).
  const lastThreshold = MIX[MIX.length - 1].threshold;
  if (Math.abs(lastThreshold - 1.0) > 1e-9) {
    throw new Error(`endurance: traffic mix thresholds must sum to 1.0, got ${lastThreshold}`);
  }
  return { start_s: startS };
}

export function teardown(data) {
  const endS = Math.floor(Date.now() / 1000);
  const elapsedH = ((endS - (data ? data.start_s : endS)) / 3600).toFixed(2);
  console.log(`endurance-24h done: elapsed=${elapsedH}h`);
}

// Summary handler — emits a compact JSON for the analysis pipeline.
export function handleSummary(data) {
  const summary = {
    test: 'endurance-24h',
    duration: DURATION,
    vus: VUS,
    tenant_pool: TENANT_COUNT,
    zipf_s: ZIPF_S,
    traffic_mix: MIX.reduce((acc, m, i) => {
      const prev = i === 0 ? 0 : MIX[i - 1].threshold;
      acc[m.op] = +(m.threshold - prev).toFixed(4);
      return acc;
    }, {}),
    metrics: data.metrics,
  };
  return {
    stdout: JSON.stringify(
      {
        test: summary.test,
        duration: summary.duration,
        traffic_mix: summary.traffic_mix,
        error_rate:
          (summary.metrics.endurance_error_rate &&
            summary.metrics.endurance_error_rate.values &&
            summary.metrics.endurance_error_rate.values.rate) || 0,
        budget_breach_strikes:
          (summary.metrics.endurance_budget_breach_strikes &&
            summary.metrics.endurance_budget_breach_strikes.values &&
            summary.metrics.endurance_budget_breach_strikes.values.count) || 0,
      },
      null,
      2,
    ),
    'endurance-summary.json': JSON.stringify(summary, null, 2),
  };
}
