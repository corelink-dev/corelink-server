// R3-prep load test — BYOK kill-switch stampede.
//
// SCENARIO
// --------
// A customer revokes their CMK in their own KMS (AWS / GCP / Azure / Vault).
// The Corelink control plane MUST evict every DEK derived from that CMK
// from the in-Worker DEK cache within 60 s — the kill-switch SLO. This
// test simulates the worst case:
//
//   - 10 000 distinct DEK cache entries were warmed before the run.
//   - The test issues ONE CMK-revoke call via the staging admin endpoint.
//   - It then polls `/v1/admin/byok/kill-switch/status?cmk_id=…` at 1 Hz
//     until either:
//       (a) `entries_remaining == 0` (kill-switch satisfied), or
//       (b) 90 s wall-clock budget exhausted (assertion FAIL).
//
// Assertions
// ----------
//   - `evict_completed_at - revoke_called_at` ≤ 60 s (SLA per
//     `specs/03_architecture/slo_catalog.md §4.x BYOK kill-switch`).
//   - `corelink_byok_kill_switch_sla_violation_total == 0` after the run
//     (the staging Prom scrape mirror exposes it at
//     `/v1/admin/metrics/byok_kill_switch_sla_violation_total`).
//   - SEV-1 alert fires — the test verifies via the synthetic alert mirror
//     `/v1/admin/alerts/recent` returning `byok-kill-switch-pending` for
//     the cmk_id while eviction is in flight.
//
// This is a SINGLE-SHOT test (not throughput) so we run it as 1 VU × 1
// iteration with extended max-duration.

import http from 'k6/http';
import { check, sleep, fail } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { admissionHeaders, requireAdmissionConfig } from './lib/staging_load_admission.js';

const TARGET_HOST = __ENV.K6_TARGET_HOST || 'https://staging.corelink.humangr.com';
const TEST_CMK_ID = __ENV.K6_BYOK_TEST_CMK_ID || '';

// Defer env-required gate to setup() (k6 inspect runs module-load only).
export function setup() {
  requireAdmissionConfig();
  if (!TEST_CMK_ID) throw new Error('K6_BYOK_TEST_CMK_ID required (pre-warmed CMK id)');
  return {};
}

const KILL_SWITCH_SLA_SECONDS = 60;
const POLL_DEADLINE_SECONDS   = 90;

const slaViolations    = new Counter('byok_kill_switch_sla_violation_total');
const evictDuration    = new Trend('byok_evict_duration_seconds', false);
const alertSeen        = new Counter('byok_sev1_alert_seen_total');

export const options = {
  scenarios: {
    revoke_once: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 1,
      maxDuration: '3m',
    },
  },
  thresholds: {
    'byok_kill_switch_sla_violation_total': ['count==0'],
    'byok_sev1_alert_seen_total':           ['count>=1'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

function adminHeaders() {
  return admissionHeaders({
    'content-type': 'application/json',
    'x-corelink-load-test': 'r3-prep',
  });
}

function pollKillSwitchStatus(cmkId) {
  const url = `${TARGET_HOST}/v1/admin/byok/kill-switch/status?cmk_id=${encodeURIComponent(cmkId)}`;
  const res = http.get(url, { headers: adminHeaders(), tags: { endpoint: 'byok_status' } });
  if (res.status !== 200) return { ok: false, entries_remaining: -1 };
  try {
    const j = res.json();
    return {
      ok: true,
      entries_remaining: Number(j.entries_remaining),
      cache_size_initial: Number(j.cache_size_initial),
    };
  } catch (_) {
    return { ok: false, entries_remaining: -1 };
  }
}

function pollAlertFiring(cmkId) {
  const url = `${TARGET_HOST}/v1/admin/alerts/recent?cmk_id=${encodeURIComponent(cmkId)}`;
  const res = http.get(url, { headers: adminHeaders(), tags: { endpoint: 'byok_alerts' } });
  if (res.status !== 200) return false;
  try {
    const j = res.json();
    return Array.isArray(j.alerts) && j.alerts.some(
      (a) => a.name === 'byok-kill-switch-pending' && a.severity === 'sev1',
    );
  } catch (_) {
    return false;
  }
}

function pollSlaViolations(cmkId) {
  const url = `${TARGET_HOST}/v1/admin/metrics/byok_kill_switch_sla_violation_total?cmk_id=${encodeURIComponent(cmkId)}`;
  const res = http.get(url, { headers: adminHeaders(), tags: { endpoint: 'byok_metric' } });
  if (res.status !== 200) return -1;
  try {
    return Number(res.json('value'));
  } catch (_) {
    return -1;
  }
}

export default function main() {
  const cmkId = TEST_CMK_ID;

  // (1) Sanity — staging cache should be pre-warmed to 10k entries.
  const pre = pollKillSwitchStatus(cmkId);
  check(pre, {
    'pre-warm cache ≥ 10k entries': (s) => s.ok && s.cache_size_initial >= 10000,
  });

  // (2) Trigger revoke.
  const revokeStartedAt = Date.now() / 1000;
  const revoke = http.post(
    `${TARGET_HOST}/v1/admin/byok/cmk/${encodeURIComponent(cmkId)}/revoke`,
    JSON.stringify({ reason: 'r3-prep-load-test', confirm: true }),
    { headers: adminHeaders(), tags: { endpoint: 'byok_revoke' } },
  );
  if (!check(revoke, { 'revoke ack 2xx': (r) => r.status >= 200 && r.status < 300 })) {
    fail('revoke endpoint did not ack — aborting stampede test');
  }

  // (3) Poll every 1 s until entries_remaining == 0 or deadline reached.
  let entriesRemaining = -1;
  let alertObserved = false;
  let elapsed = 0;
  while (elapsed < POLL_DEADLINE_SECONDS) {
    sleep(1);
    elapsed = (Date.now() / 1000) - revokeStartedAt;

    const st = pollKillSwitchStatus(cmkId);
    if (st.ok) entriesRemaining = st.entries_remaining;

    if (!alertObserved && elapsed < KILL_SWITCH_SLA_SECONDS) {
      // Alert must fire while eviction is pending — record once seen.
      if (pollAlertFiring(cmkId)) {
        alertObserved = true;
        alertSeen.add(1);
      }
    }

    if (entriesRemaining === 0) break;
  }

  evictDuration.add(elapsed);

  check(null, {
    'cache fully evicted': () => entriesRemaining === 0,
    'eviction within 60 s SLA': () => entriesRemaining === 0 && elapsed <= KILL_SWITCH_SLA_SECONDS,
  });
  if (!(entriesRemaining === 0 && elapsed <= KILL_SWITCH_SLA_SECONDS)) {
    slaViolations.add(1);
  }

  // (4) Final cross-check — the Prom mirror counter must remain at zero.
  const promViolations = pollSlaViolations(cmkId);
  check(null, {
    'prom mirror SLA violation counter == 0': () => promViolations === 0,
  });
  if (promViolations > 0) slaViolations.add(promViolations);
}
