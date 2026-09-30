/** Fail-closed, staging-only, durable one-shot B-072 trigger. */
import type { Env } from "./index_common.js";
import { SYNTHETIC_PAGE_CONTRACT, scheduledWeekNumber, syntheticEmitAtMs, syntheticRegionForWeek } from "./index_common.js";

export const B072_ONE_SHOT_CRON = "* * * * *";
export const B072_STAGING_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd";
export const B072_STAGING_D1_ID = "d72a6b39-6a48-4338-bfda-1111dda98604";
export const B072_MAX_WINDOW_MS = 2 * 60 * 60 * 1_000;
export const B072_MIN_PROPAGATION_MS = 20 * 60 * 1_000;

interface Authorization {
  issue_id: number;
  serving_sha: string;
  approval_nonce: string;
  receiver_worker_revision: string;
  approved_reviewer: string;
  approved_run_id: number;
  authorized_at_ms: number;
  starts_at_ms: number;
  ends_at_ms: number;
}

interface ScheduledControllerLike {
  readonly cron: string;
  readonly scheduledTime: number;
  noRetry(): void;
}

function reject(controller: ScheduledControllerLike, reason: string): never {
  console.error(`[b072_one_shot] rejected reason=${reason}`);
  controller.noRetry();
  throw new Error("B-072 one-shot rejected");
}

function isAuthorization(value: Authorization | null, env: Env, now: number, scheduledTime: number): value is Authorization {
  if (value === null) return false;
  const sha = env.SENTRY_RELEASE ?? "";
  return value.issue_id === 1652 &&
    /^[0-9a-f]{40}$/.test(value.serving_sha) && value.serving_sha === sha &&
    /^[A-Za-z0-9_-]{32,128}$/.test(value.approval_nonce) &&
    typeof value.receiver_worker_revision === "string" && value.receiver_worker_revision.length > 0 && value.receiver_worker_revision.length <= 200 &&
    typeof value.approved_reviewer === "string" && /^[A-Za-z0-9-]{1,39}$/.test(value.approved_reviewer) &&
    Number.isSafeInteger(value.approved_run_id) && value.approved_run_id > 0 &&
    Number.isSafeInteger(value.authorized_at_ms) && Number.isSafeInteger(value.starts_at_ms) && Number.isSafeInteger(value.ends_at_ms) &&
    Number.isSafeInteger(scheduledTime) && scheduledTime % 60_000 === 0 &&
    value.starts_at_ms >= value.authorized_at_ms + B072_MIN_PROPAGATION_MS &&
    value.ends_at_ms > value.starts_at_ms && value.ends_at_ms - value.starts_at_ms <= B072_MAX_WINDOW_MS &&
    now >= value.starts_at_ms && now < value.ends_at_ms &&
    scheduledTime >= value.starts_at_ms && scheduledTime < value.ends_at_ms;
}

export async function runB072OneShot(
  controller: ScheduledControllerLike,
  env: Env,
  now: () => number = Date.now,
): Promise<void> {
  if (controller.cron !== B072_ONE_SHOT_CRON) reject(controller, "unknown_cron");
  const sha = env.SENTRY_RELEASE ?? "";
  if (env.ENVIRONMENT !== "staging" ||
      env.CLOUDFLARE_ACCOUNT_ID !== B072_STAGING_ACCOUNT_ID ||
      env.D1_DATABASE_ID !== B072_STAGING_D1_ID ||
      env.SYNTHETIC_DRILL_PROVIDER_MODE !== "provider_deferred" ||
      !/^[0-9a-f]{40}$/.test(sha) ||
      env.CONFIG_DB === undefined || env.SCHEDULED_DRILL_DELIVERY === undefined) {
    reject(controller, "staging_guard");
  }

  let authorization: Authorization | null;
  try {
    authorization = await env.CONFIG_DB.prepare(
      `SELECT issue_id, serving_sha, approval_nonce, receiver_worker_revision,
              approved_reviewer, approved_run_id, authorized_at_ms, starts_at_ms, ends_at_ms
         FROM b072_one_shot_authorization WHERE singleton_id = 1`,
    ).first<Authorization>();
  } catch {
    reject(controller, "authorization_read_failed");
  }
  const nowMs = now();
  if (!isAuthorization(authorization, env, nowMs, controller.scheduledTime)) reject(controller, "authorization_invalid");

  const drillId = `SP-${controller.scheduledTime}`;
  const correlationId = `PAT-CORRELATION-ID-001:${drillId}`;
  try {
    const claim = await env.CONFIG_DB.prepare(
      `INSERT OR IGNORE INTO b072_one_shot_claim
         (singleton_id, issue_id, drill_id, scheduled_at_ms, serving_sha, approval_nonce, claimed_at_ms)
       SELECT 1, 1652, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM b072_one_shot_authorization a
           JOIN b072_one_shot_activation x ON x.singleton_id = a.singleton_id
          WHERE a.singleton_id = 1 AND a.issue_id = 1652
            AND a.serving_sha = ? AND a.approval_nonce = ?
            AND x.approval_nonce = a.approval_nonce
            AND x.receiver_worker_revision = a.receiver_worker_revision
        )
          AND NOT EXISTS (SELECT 1 FROM b072_one_shot_revocation WHERE singleton_id = 1)`,
    ).bind(drillId, controller.scheduledTime, sha, authorization.approval_nonce, nowMs,
      sha, authorization.approval_nonce).run();
    if (claim.meta.changes !== 1) reject(controller, "claim_already_consumed");
  } catch (error) {
    if (error instanceof Error && error.message === "B-072 one-shot rejected") throw error;
    reject(controller, "claim_failed");
  }

  const week = scheduledWeekNumber(controller.scheduledTime);
  const rotationWeek = ((week % 4) + 4) % 4;
  if (!isAuthorization(authorization, env, now(), controller.scheduledTime)) {
    reject(controller, "authorization_window_elapsed_before_send");
  }
  let response: Response;
  try {
    response = await env.SCHEDULED_DRILL_DELIVERY.fetch("https://scheduled-drill.internal/v1/drills/synthetic_page", {
      method: "POST",
      headers: { "content-type": "application/json", "x-corelink-scheduled-drill-id": drillId },
      body: JSON.stringify({
        drill: "synthetic_page",
        cron: B072_ONE_SHOT_CRON,
        scheduled_at_ms: controller.scheduledTime,
        synthetic_page: {
          ...SYNTHETIC_PAGE_CONTRACT,
          region: syntheticRegionForWeek(week),
          rotation_week: rotationWeek,
          emit_at_ms: syntheticEmitAtMs(controller.scheduledTime, week),
          delivery_mode: rotationWeek === 3 ? "deferred" : "immediate",
          provider_mode: "provider_deferred",
          worker_revision: sha,
          serving_sha: sha,
          dedup_key: drillId,
          correlation_id: correlationId,
        },
      }),
    });
  } catch {
    reject(controller, "delivery_ambiguous");
  }

  let receipt: unknown;
  try { receipt = await response.json(); } catch { receipt = null; }
  const row = typeof receipt === "object" && receipt !== null ? receipt as Record<string, unknown> : null;
  if (!response.ok || row === null || row['terminal'] !== true || row['outcome'] !== "provider_deferred" ||
      row['receiver_result'] !== "persisted_provider_deferred" || row['drill_id'] !== drillId ||
      row['correlation_id'] !== correlationId || row['scheduled_at_ms'] !== controller.scheduledTime ||
      row['worker_revision'] !== sha || row['serving_sha'] !== sha ||
      row['receiver_worker_revision'] !== authorization.receiver_worker_revision) {
    reject(controller, "terminal_receipt_invalid");
  }
  console.info(`[b072_one_shot] completed drill=${drillId} result=provider_deferred_terminal`);
}
