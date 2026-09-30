/** Private scheduled entrypoint that invokes the frozen canonical B-089 code. */
import {
  recordCanonicalSlaObservation,
  monthlyCutoffAtMs,
  runSlaCreditSweep,
  providerFromEnv,
  type SlaCreditCronEnv,
  type SlaMonthlyObservation,
} from "../../canonical-source/apps/signup-worker/src/webhooks/sla_credit_cron";

interface TestEnv extends SlaCreditCronEnv {
  I2568_TEST_TENANT_ID?: string;
  I2568_TEST_STRIPE_CUSTOMER_ID?: string;
  I2568_TEST_SERVICE_PERIOD?: string;
  I2568_TEST_MONTHLY_FEE_MINOR?: string;
  I2568_TEST_AVAILABILITY_PERCENT?: string;
  I2568_TEST_OBSERVATION_JSON?: string;
}

type WorkerEnv = TestEnv & { BILLING_DB: NonNullable<SlaCreditCronEnv["BILLING_DB"]> };

function assertExactTestInput(env: WorkerEnv): SlaMonthlyObservation {
  const tenant = env.I2568_TEST_TENANT_ID?.trim();
  const customer = env.I2568_TEST_STRIPE_CUSTOMER_ID?.trim();
  const period = env.I2568_TEST_SERVICE_PERIOD?.trim();
  if (!tenant || !/^i2568_[A-Za-z0-9-]{1,80}$/.test(tenant)) throw new Error("invalid_test_tenant");
  if (!customer || !/^cus_[A-Za-z0-9]+$/.test(customer)) throw new Error("invalid_test_customer");
  if (period !== "2026-08") throw new Error("invalid_test_period");
  const fee = Number(env.I2568_TEST_MONTHLY_FEE_MINOR);
  const availability = Number(env.I2568_TEST_AVAILABILITY_PERCENT);
  if (!Number.isSafeInteger(fee) || fee < 100 || fee > 100_000_000) throw new Error("invalid_test_fee");
  if (!Number.isFinite(availability) || availability !== 99.49) throw new Error("invalid_test_availability");
  const supplied = env.I2568_TEST_OBSERVATION_JSON;
  if (!supplied) throw new Error("missing_test_observation");
  const observation = JSON.parse(supplied) as SlaMonthlyObservation;
  const now = Date.now();
  if (
    observation.tenant_id !== tenant || observation.service_period !== period ||
    observation.tier !== "enterprise" || observation.monthly_fee_minor !== fee ||
    observation.currency !== "USD" || observation.availability_percent !== availability ||
    observation.force_majeure !== false || !Number.isSafeInteger(observation.observed_at_ms) ||
    observation.observed_at_ms < Date.UTC(2026, 8, 1) || observation.observed_at_ms > now ||
    observation.latency_excess_percent != null || observation.dsr_breach_days != null ||
    observation.billing_drift_percent != null
  ) throw new Error("test_observation_mismatch");
  if (now < monthlyCutoffAtMs(period)) throw new Error("test_period_cutoff_not_elapsed");
  return observation;
}

async function recordOwnedObservation(env: WorkerEnv): Promise<void> {
  const observation = assertExactTestInput(env);
  const now = Date.now();
  const current = await env.BILLING_DB.prepare(
    "SELECT stripe_customer_id FROM tenant_billing WHERE tenant_id = ? LIMIT 2",
  ).bind(observation.tenant_id).all<{ stripe_customer_id?: string | null }>();
  const rows = current.results ?? [];
  if (rows.length > 1) throw new Error("ambiguous_test_tenant_mapping");
  if (rows.length === 0) {
    const inserted = await env.BILLING_DB.prepare(
      "INSERT INTO tenant_billing (tenant_id, stripe_customer_id, status, created_at_ms, updated_at_ms) VALUES (?, ?, 'inactive', ?, ?)",
    ).bind(observation.tenant_id, env.I2568_TEST_STRIPE_CUSTOMER_ID, now, now).run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) throw new Error("test_tenant_mapping_insert_failed");
  } else if (rows[0]?.stripe_customer_id !== env.I2568_TEST_STRIPE_CUSTOMER_ID) {
    throw new Error("test_tenant_mapping_customer_mismatch");
  }
  await recordCanonicalSlaObservation(env.BILLING_DB, observation);
}

export default {
  fetch(): Response {
    return new Response("not found", { status: 404 });
  },

  async scheduled(_controller: ScheduledController, rawEnv: WorkerEnv): Promise<void> {
    if (!rawEnv.BILLING_DB) throw new Error("missing_isolated_billing_db");
    await recordOwnedObservation(rawEnv);
    const result = await runSlaCreditSweep(rawEnv, Date.now(), providerFromEnv(rawEnv));
    if (!result.ok || result.failed !== 0 || result.blocked !== 0) {
      throw new Error("canonical_sla_credit_sweep_failed");
    }
    console.log(JSON.stringify({
      issue: 2568,
      sweep: {
        ok: result.ok, skipped: result.skipped, measured: result.measured,
        produced: result.produced, created: result.created, applied: result.applied,
        failed: result.failed, blocked: result.blocked, reconciled: result.reconciled,
      },
    }));
  },
};
