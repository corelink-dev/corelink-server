/** Scheduled synthetic drill delivery domain. */
import type { ScheduledController } from "@cloudflare/workers-types";
import type { Env } from "./index_common.js";
import { scheduledDrillForCron, scheduledWeekNumber, syntheticRegionForWeek, syntheticEmitAtMs, SYNTHETIC_PAGE_CONTRACT } from "./index_common.js";
import { readStagingD1BindingRuntimeProbeReceipt, runStagingD1BindingRuntimeProbe, STAGING_D1_PROBE_WINDOW } from "./staging_runtime_d1_probe.js";
import { B072_ONE_SHOT_CRON, runB072OneShot } from "./b072_one_shot.js";

export const STAGING_D1_RUNTIME_PROBE_CRON = STAGING_D1_PROBE_WINDOW.cron;
export const STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS = STAGING_D1_PROBE_WINDOW.expires_ms;
export const STAGING_D1_RUNTIME_PROBE_LAST_ENTRY_MS = STAGING_D1_PROBE_WINDOW.last_entry_ms;

export async function runScheduled(controller: ScheduledController, env: Env): Promise<void> {
    if (controller.cron === B072_ONE_SHOT_CRON) {
      await runB072OneShot(controller, env);
      return;
    }

    if (controller.cron === STAGING_D1_RUNTIME_PROBE_CRON) {
      const release = env.SENTRY_RELEASE ?? "";
      const targetIsStaging = env.ENVIRONMENT === "staging" &&
        /^[0-9a-f]{40}$/.test(release) &&
        env.CLOUDFLARE_ACCOUNT_ID === "6a1fc1c626fc2628823e60b9db01f5cd" &&
        env.D1_DATABASE_ID === "d72a6b39-6a48-4338-bfda-1111dda98604" &&
        env.R2_S3_ENDPOINT === "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com";
      if (!targetIsStaging) {
        console.error("[staging_d1_runtime_probe] rejected reason=staging_guard");
        controller.noRetry();
        throw new Error("staging D1 runtime probe guard rejected");
      }
      // The host's entry lease is fixed. After it closes, a queued or delayed
      // Cron may only read the existing immutable receipt; it cannot retire
      // the old probe, touch D1, or start a Container.
      if (controller.scheduledTime > STAGING_D1_RUNTIME_PROBE_LAST_ENTRY_MS ||
          Date.now() > STAGING_D1_RUNTIME_PROBE_LAST_ENTRY_MS) {
        const receipt = await readStagingD1BindingRuntimeProbeReceipt(env, controller.scheduledTime);
        if (receipt !== undefined) {
          console.info(`[staging_d1_runtime_probe] receipt=${JSON.stringify(receipt)}`);
          return;
        }
        controller.noRetry();
        return;
      }
      if (
        controller.scheduledTime < STAGING_D1_PROBE_WINDOW.starts_ms ||
        controller.scheduledTime >= STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS ||
        Date.now() < STAGING_D1_PROBE_WINDOW.starts_ms ||
        Date.now() >= STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS
      ) {
        console.error("[staging_d1_runtime_probe] rejected reason=staging_guard");
        controller.noRetry();
        throw new Error("staging D1 runtime probe guard rejected");
      }
      try {
        const receipt = await runStagingD1BindingRuntimeProbe(env, controller.scheduledTime);
        console.info(`[staging_d1_runtime_probe] receipt=${JSON.stringify(receipt)}`);
        return;
      } catch {
        console.error("[staging_d1_runtime_probe] failed reason=probe_failed");
        throw new Error("staging D1 runtime probe failed");
      }
    }

    const drill = scheduledDrillForCron(controller.cron);
    if (drill === undefined) {
      // A cron is deployment configuration, not user input. Do not echo it in
      // telemetry anyway: keeping the event fixed makes this path incapable of
      // carrying a future secret-bearing configuration value into logs.
      console.error("[scheduled_drill] rejected reason=unknown_cron");
      controller.noRetry();
      throw new Error("unknown scheduled drill");
    }

    const delivery = env.SCHEDULED_DRILL_DELIVERY;
    if (delivery === undefined) {
      console.error(`[scheduled_drill] failed drill=${drill} reason=delivery_binding_unavailable`);
      throw new Error("scheduled drill delivery binding unavailable");
    }

    // `cron` plus Cloudflare's scheduled time is deterministic for this tick,
    // so the downstream receiver can make a retry idempotent. The body carries
    // only scheduler metadata — never a routing key, token, or customer data.
    // One canonical identifier is carried in the service-binding header, the
    // receiver D1 row, and PagerDuty's dedup_key. The scheduled timestamp is
    // stable for a Cloudflare retry and unique for each weekly tick.
    const deliveryId = `SP-${controller.scheduledTime}`;
    const week = scheduledWeekNumber(controller.scheduledTime);
    const providerMode = env.SYNTHETIC_DRILL_PROVIDER_MODE === "provider_deferred"
      ? "provider_deferred"
      : "pagerduty";
    const body = {
      drill,
      cron: controller.cron,
      scheduled_at_ms: controller.scheduledTime,
      synthetic_page: {
        ...SYNTHETIC_PAGE_CONTRACT,
        region: syntheticRegionForWeek(week),
        rotation_week: ((week % 4) + 4) % 4,
        emit_at_ms: syntheticEmitAtMs(controller.scheduledTime, week),
        delivery_mode: ((week % 4) + 4) % 4 === 3 ? "deferred" : "immediate",
        provider_mode: providerMode,
        worker_revision: env.SENTRY_RELEASE ?? "",
        serving_sha: env.SENTRY_RELEASE ?? "",
        dedup_key: deliveryId,
        correlation_id: `PAT-CORRELATION-ID-001:${deliveryId}`,
      },
    };
    let response: Response;
    try {
      response = await delivery.fetch(`https://scheduled-drill.internal/v1/drills/${drill}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-corelink-scheduled-drill-id": deliveryId,
        },
        body: JSON.stringify(body),
      });
    } catch {
      // Do not include an exception message: service-binding errors can contain
      // endpoint/configuration details that do not belong in worker logs.
      console.error(`[scheduled_drill] failed drill=${drill} reason=delivery_exception`);
      throw new Error("scheduled drill delivery failed");
    }

    if (!response.ok) {
      // A non-2xx is a failed delivery. Throwing leaves Cloudflare's normal
      // scheduled retry behaviour intact; the idempotency key above makes that
      // safe for a receiver that accepted work before its response was lost.
      console.error(`[scheduled_drill] failed drill=${drill} reason=delivery_status`);
      throw new Error("scheduled drill delivery failed");
    }

    if (providerMode === "provider_deferred") {
      let receipt: unknown;
      try { receipt = await response.json(); } catch { receipt = null; }
      const expectedWorkerRevision = env.SENTRY_RELEASE;
      const expectedServingSha = env.SENTRY_RELEASE;
      const terminalReceipt = typeof receipt === "object" && receipt !== null
        ? receipt as Record<string, unknown>
        : null;
      if (terminalReceipt === null ||
          terminalReceipt["terminal"] !== true ||
          terminalReceipt["outcome"] !== "provider_deferred" ||
          terminalReceipt["receiver_result"] !== "persisted_provider_deferred" ||
          terminalReceipt["drill_id"] !== deliveryId ||
          terminalReceipt["correlation_id"] !== `PAT-CORRELATION-ID-001:${deliveryId}` ||
          terminalReceipt["scheduled_at_ms"] !== controller.scheduledTime ||
          terminalReceipt["worker_revision"] !== expectedWorkerRevision ||
          terminalReceipt["serving_sha"] !== expectedServingSha ||
          typeof terminalReceipt["receiver_worker_revision"] !== "string" ||
          terminalReceipt["receiver_worker_revision"].length < 1 ||
          terminalReceipt["receiver_worker_revision"].length > 200) {
        console.error(`[scheduled_drill] failed drill=${drill} reason=terminal_receipt_invalid`);
        throw new Error("scheduled drill terminal receipt invalid");
      }
    }

    if (providerMode === "provider_deferred") {
      console.info(`[scheduled_drill] completed drill=${drill} result=provider_deferred_terminal`);
    } else {
      console.info(`[scheduled_drill] delivered drill=${drill} result=accepted`);
    }
}
