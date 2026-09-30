import {
  buildPagerDutyEvent,
  B072_ONE_SHOT_CRON,
  PAGERDUTY_EVENTS_URL,
  PAGERDUTY_WEBHOOK_PATH,
  parsePagerDutyWebhook,
  parseSyntheticPageEnvelope,
  SYNTHETIC_PAGE_PATH,
  validateReceiverEnvironment,
  validateWebhookEnvironment,
  verifyPagerDutySignature,
  type ReceiverEnv,
  type SyntheticPageEnvelope,
  type SyntheticTerminalOutcome,
} from "./contract.js";

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

type DrillRow = {
  drill_id: string;
  region: "americas" | "emea" | "apac" | "boundary_handoff";
  emit_ts_ms: number;
  scheduled_at_ms: number;
  correlation_id: string;
  delivery_mode: "immediate" | "deferred";
  delivered_at_ms: number | null;
};

type ProviderDeferredReceipt = {
  drill_id: string;
  scheduled_at_ms: number;
  correlation_id: string;
  provider_mode: "provider_deferred";
  outcome: SyntheticTerminalOutcome;
  scheduler_worker_revision: string;
  serving_sha: string;
  receiver_worker_revision: string;
  receiver_result: "persisted_provider_deferred";
};

function pageForRow(row: DrillRow): SyntheticPageEnvelope {
  return {
    drill: "synthetic_page",
    cron: "0 14 * * 1",
    scheduled_at_ms: row.scheduled_at_ms,
    synthetic_page: {
      service: "synthetic-drill",
      event_action: "trigger",
      severity: "info",
      synthetic_severity: "sev2_synthetic",
      region: row.region,
      rotation_week: row.region === "boundary_handoff" ? 3 : 0,
      emit_at_ms: row.emit_ts_ms,
      delivery_mode: "deferred",
      provider_mode: "pagerduty",
      worker_revision: "",
      serving_sha: "",
      dedup_key: row.drill_id,
      correlation_id: row.correlation_id,
    },
  };
}

async function pagerDutyFetch(
  env: ReceiverEnv,
  page: SyntheticPageEnvelope["synthetic_page"],
  fetchImpl: typeof fetch,
): Promise<void> {
  const response = await fetchImpl(PAGERDUTY_EVENTS_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(buildPagerDutyEvent(page, env.PAGERDUTY_SYNTHETIC_ROUTING_KEY!)),
  }).catch(() => null);
  if (response === null || !response.ok) throw new Error("PagerDuty delivery failed");
}

async function persistDelivery(env: ReceiverEnv, envelope: SyntheticPageEnvelope): Promise<void> {
  const page = envelope.synthetic_page;
  const deliveryMode = page.delivery_mode;
  await env.CONFIG_DB!.batch([
    env.CONFIG_DB!.prepare(
      `INSERT OR IGNORE INTO synthetic_page_drills_b072
         (drill_id, region, severity, emit_ts_ms, outcome, correlation_id, schema_version,
          delivery_mode, scheduled_at_ms, delivered_at_ms)
       VALUES (?, ?, ?, ?, 'unacked', ?, 1, ?, ?, ?)`,
    ).bind(
      page.dedup_key,
      page.region,
      page.synthetic_severity,
      page.emit_at_ms,
      page.correlation_id,
      deliveryMode,
      envelope.scheduled_at_ms,
      null,
    ),
    env.CONFIG_DB!.prepare(
      `INSERT OR IGNORE INTO synthetic_page_audit_events
         (event_id, drill_id, event_type, occurred_at_ms, correlation_id, source_event_id)
       VALUES (?, ?, 'triggered', ?, ?, ?)`,
    ).bind(
      `trigger:${page.dedup_key}`,
      page.dedup_key,
      envelope.scheduled_at_ms,
      page.correlation_id,
      page.dedup_key,
    ),
  ]);
}

async function recordB072Ingress(
  env: ReceiverEnv,
  envelope: SyntheticPageEnvelope,
  receiverRevision: string,
): Promise<void> {
  const page = envelope.synthetic_page;
  const result = await env.CONFIG_DB!.prepare(
    `INSERT INTO b072_one_shot_ingress
       (singleton_id, drill_id, scheduled_at_ms, serving_sha, receiver_worker_revision, ingress_count, last_ingress_at_ms)
     VALUES (1, ?, ?, ?, ?, 1, ?)
     ON CONFLICT(singleton_id) DO UPDATE SET
       ingress_count = b072_one_shot_ingress.ingress_count + 1,
       last_ingress_at_ms = excluded.last_ingress_at_ms
     WHERE b072_one_shot_ingress.drill_id = excluded.drill_id
       AND b072_one_shot_ingress.scheduled_at_ms = excluded.scheduled_at_ms
       AND b072_one_shot_ingress.serving_sha = excluded.serving_sha
       AND b072_one_shot_ingress.receiver_worker_revision = excluded.receiver_worker_revision`,
  ).bind(page.dedup_key, envelope.scheduled_at_ms, page.serving_sha, receiverRevision, Date.now()).run();
  if (result.meta.changes !== 1) throw new Error("B-072 ingress correlation mismatch");
}

async function markDelivered(env: ReceiverEnv, drillId: string, correlationId: string, deliveredAtMs: number): Promise<void> {
  // PagerDuty's canonical dedup key makes a retry safe if this transaction is
  // lost after external acceptance. The durable receipt and row transition are
  // committed together; no row claims delivery before PagerDuty accepts it.
  await env.CONFIG_DB!.batch([
    env.CONFIG_DB!.prepare(
      `INSERT OR IGNORE INTO synthetic_page_audit_events
         (event_id, drill_id, event_type, occurred_at_ms, correlation_id, source_event_id)
       VALUES (?, ?, 'delivered', ?, ?, ?)`,
    ).bind(
      `delivered:${drillId}`,
      drillId,
      deliveredAtMs,
      correlationId,
      `delivered:${drillId}`,
    ),
    env.CONFIG_DB!.prepare(
      `UPDATE synthetic_page_drills_b072
          SET delivered_at_ms = ?
        WHERE drill_id = ? AND delivered_at_ms IS NULL`,
    ).bind(deliveredAtMs, drillId),
  ]);
}

async function handleSyntheticPage(request: Request, env: ReceiverEnv): Promise<Response> {
  const environmentError = validateReceiverEnvironment(env);
  if (environmentError !== null) return json({ error: "receiver_not_ready" }, 503);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
    return json({ error: "content_type_required" }, 415);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  const configuredProviderMode = env.SYNTHETIC_DRILL_PROVIDER_MODE ?? "pagerduty";
  const envelope = parseSyntheticPageEnvelope(body, {
    environment: env.ENVIRONMENT,
    providerMode: configuredProviderMode,
  });
  const deliveryId = request.headers.get("x-corelink-scheduled-drill-id");
  if (envelope === null || deliveryId !== envelope.synthetic_page.dedup_key) {
    return json({ error: "invalid_synthetic_page_contract" }, 400);
  }
  if ((envelope.synthetic_page.provider_mode ?? "pagerduty") !== configuredProviderMode) {
    return json({ error: "provider_mode_mismatch" }, 400);
  }
  const receiverRevision = env.CF_VERSION_METADATA?.id;
  if (configuredProviderMode === "provider_deferred" &&
      (receiverRevision === undefined || receiverRevision.length < 1 || receiverRevision.length > 200)) {
    return json({ error: "provider_deferred_provenance_unavailable" }, 503);
  }

  if (envelope.cron === B072_ONE_SHOT_CRON) {
    try {
      if (receiverRevision === undefined) return json({ error: "one_shot_receiver_revision_unavailable" }, 503);
      await recordB072Ingress(env, envelope, receiverRevision);
    } catch {
      return json({ error: "one_shot_ingress_unavailable" }, 503);
    }
  }

  try {
    // Durable row + audit event are committed before any external page.
    await persistDelivery(env, envelope);
  } catch {
    return json({ error: "receiver_storage_unavailable" }, 503);
  }

  if (envelope.synthetic_page.provider_mode === "provider_deferred") {
    const page = envelope.synthetic_page;
    const schedulerRevision = page.worker_revision;
    const servingSha = page.serving_sha;
    if (schedulerRevision === undefined || servingSha === undefined || receiverRevision === undefined) {
      return json({ error: "provider_deferred_provenance_unavailable" }, 503);
    }
    const receipt: ProviderDeferredReceipt = {
      drill_id: deliveryId,
      scheduled_at_ms: envelope.scheduled_at_ms,
      correlation_id: page.correlation_id,
      provider_mode: "provider_deferred",
      outcome: "provider_deferred",
      scheduler_worker_revision: schedulerRevision,
      serving_sha: servingSha,
      receiver_worker_revision: receiverRevision,
      receiver_result: "persisted_provider_deferred",
    };
    const recordedAt = Date.now();
    try {
      await env.CONFIG_DB!.batch([
        env.CONFIG_DB!.prepare(
          `INSERT OR IGNORE INTO synthetic_page_provider_receipts
             (drill_id, scheduled_at_ms, correlation_id, provider_mode, outcome,
              scheduler_worker_revision, serving_sha, receiver_worker_revision,
              receiver_result, recorded_at_ms)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE EXISTS (SELECT 1 FROM synthetic_page_drills_b072 WHERE drill_id = ? AND correlation_id = ?)`
        ).bind(deliveryId, envelope.scheduled_at_ms, page.correlation_id, receipt.provider_mode,
          receipt.outcome, schedulerRevision, servingSha, receiverRevision, receipt.receiver_result,
          recordedAt, deliveryId, page.correlation_id),
        env.CONFIG_DB!.prepare(
          `INSERT OR IGNORE INTO synthetic_page_provider_audit_events
             (event_id, drill_id, event_type, occurred_at_ms, correlation_id, source_event_id)
           SELECT ?, ?, ?, ?, ?, ?
            WHERE EXISTS (SELECT 1 FROM synthetic_page_provider_receipts
                           WHERE drill_id = ? AND correlation_id = ? AND outcome = 'provider_deferred')`
        ).bind(`provider-deferred:${deliveryId}`, deliveryId, receipt.outcome, recordedAt,
          page.correlation_id, `provider-deferred:${deliveryId}`, deliveryId, page.correlation_id),
      ]);
    } catch {
      return json({ error: "provider_deferred_receipt_unavailable" }, 503);
    }
    const persisted = await env.CONFIG_DB!.prepare(
      `SELECT drill_id, scheduled_at_ms, correlation_id, provider_mode, outcome,
              scheduler_worker_revision, serving_sha, receiver_worker_revision, receiver_result
         FROM synthetic_page_provider_receipts WHERE drill_id = ?`
    ).bind(deliveryId).first<ProviderDeferredReceipt>();
    const audit = await env.CONFIG_DB!.prepare(
      `SELECT 1 AS present FROM synthetic_page_provider_audit_events
        WHERE drill_id = ? AND correlation_id = ? AND event_type = 'provider_deferred'`
    ).bind(deliveryId, page.correlation_id).first<{ present: number }>();
    if (persisted === null || audit === null) return json({ error: "provider_deferred_receipt_unavailable" }, 503);
    const sameReceipt = Object.keys(receipt).every((key) =>
      persisted[key as keyof ProviderDeferredReceipt] === receipt[key as keyof ProviderDeferredReceipt]);
    if (!sameReceipt) return json({ error: "provider_deferred_replay_mismatch" }, 409);
    return json({ terminal: true, outcome: "provider_deferred", receiver_result: receipt.receiver_result,
      drill_id: deliveryId, correlation_id: page.correlation_id, scheduled_at_ms: envelope.scheduled_at_ms,
      worker_revision: schedulerRevision, serving_sha: servingSha, receiver_worker_revision: receiverRevision }, 200);
  }

  if (envelope.synthetic_page.delivery_mode === "deferred") {
    // The Sunday scheduled handler will pick this durable row up. Returning
    // 202 is safe because the row, not this response, is the queue.
    return json({ accepted: true, deferred: true, dedup_key: deliveryId }, 202);
  }

  try {
    await pagerDutyFetch(env, envelope.synthetic_page, fetch);
  } catch {
    // Scheduler retry uses the same canonical SP-* dedup key and correlation.
    return json({ error: "pagerduty_delivery_failed" }, 502);
  }
  try {
    await markDelivered(env, deliveryId, envelope.synthetic_page.correlation_id, Date.now());
  } catch {
    // PagerDuty may already have accepted the canonical dedup key. A retry is
    // required to repair the local receipt and cannot create a second incident.
    return json({ error: "delivery_receipt_unavailable" }, 503);
  }
  return json({ accepted: true, dedup_key: deliveryId }, 202);
}

async function runDeferredDeliveries(
  controller: ScheduledController,
  env: ReceiverEnv,
  fetchImpl: typeof fetch,
  nowImpl: () => number = Date.now,
): Promise<void> {
  if (env.SYNTHETIC_DRILL_PROVIDER_MODE === "provider_deferred") return;
  const environmentError = validateReceiverEnvironment(env);
  if (environmentError !== null) throw new Error("receiver not ready");
  const result = await env.CONFIG_DB!.prepare(
    `SELECT drill_id, region, emit_ts_ms, scheduled_at_ms, correlation_id, delivery_mode, delivered_at_ms
       FROM synthetic_page_drills_b072
      WHERE delivery_mode = 'deferred' AND delivered_at_ms IS NULL
        AND outcome = 'unacked' AND emit_ts_ms <= ?
        AND NOT EXISTS (SELECT 1 FROM synthetic_page_provider_receipts p WHERE p.drill_id = synthetic_page_drills_b072.drill_id)
      ORDER BY emit_ts_ms ASC
      LIMIT 20`,
  ).bind(controller.scheduledTime).all<DrillRow>();
  for (const row of result.results) {
    await pagerDutyFetch(env, pageForRow(row).synthetic_page, fetchImpl);
    // Capture the receipt after the external acceptance. scheduledTime is the
    // queue eligibility clock and may be stale on retry/backlog sweeps.
    await markDelivered(env, row.drill_id, row.correlation_id, nowImpl());
  }
}

async function handlePagerDutyWebhook(request: Request, env: ReceiverEnv): Promise<Response> {
  const environmentError = validateWebhookEnvironment(env);
  if (environmentError !== null) return json({ error: "webhook_not_ready" }, 503);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const body = await request.text();
  if (!(await verifyPagerDutySignature(body, request.headers.get("x-pagerduty-signature"), env.PAGERDUTY_WEBHOOK_SECRET!))) {
    return json({ error: "invalid_webhook_signature" }, 401);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  const event = parsePagerDutyWebhook(parsed);
  if (event === null) return json({ error: "invalid_webhook_event" }, 400);
  const row = await env.CONFIG_DB!.prepare(
    `SELECT drill_id, emit_ts_ms, outcome, correlation_id, delivered_at_ms
       FROM synthetic_page_drills_b072 WHERE drill_id = ?`,
  ).bind(event.drill_id).first<{
    drill_id: string;
    emit_ts_ms: number;
    outcome: string;
    correlation_id: string;
    delivered_at_ms: number | null;
  }>();
  if (row === null) return json({ accepted: true, ignored: true }, 202);
  if (row.delivered_at_ms === null) return json({ error: "delivery_not_recorded" }, 503);
  if (row.outcome !== "unacked") return json({ accepted: true, ignored: true, outcome: row.outcome }, 202);
  const outcome = event.kind === "acknowledged" ? "acked" : "escalated";
  const mtta = Math.max(0, event.occurred_at_ms - row.emit_ts_ms);
  await env.CONFIG_DB!.batch([
    env.CONFIG_DB!.prepare(
      `INSERT OR IGNORE INTO synthetic_page_audit_events
         (event_id, drill_id, event_type, occurred_at_ms, correlation_id, source_event_id, engineer_slug)
       SELECT ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM synthetic_page_drills_b072
           WHERE drill_id = ? AND outcome = 'unacked' AND delivered_at_ms IS NOT NULL
        )`,
    ).bind(
      event.event_id,
      event.drill_id,
      outcome,
      event.occurred_at_ms,
      row.correlation_id,
      event.event_id,
      event.engineer_slug,
      event.drill_id,
    ),
    env.CONFIG_DB!.prepare(
      `UPDATE synthetic_page_drills_b072
          SET outcome = ?, engineer_slug = ?, ack_ts_ms = ?, mtta_ms = ?, ack_vector = ?
        WHERE drill_id = ? AND outcome = 'unacked' AND delivered_at_ms IS NOT NULL`,
    ).bind(outcome, event.engineer_slug, event.occurred_at_ms, mtta, event.ack_vector, event.drill_id),
  ]);
  const persisted = await env.CONFIG_DB!.prepare(
    `SELECT outcome FROM synthetic_page_drills_b072 WHERE drill_id = ?`,
  ).bind(event.drill_id).first<{ outcome: string }>();
  if (persisted === null) return json({ error: "receiver_storage_unavailable" }, 503);
  return json({ accepted: true, outcome: persisted.outcome, drill_id: event.drill_id }, 202);
}

const handler: ExportedHandler<ReceiverEnv> = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz" && request.method === "GET") return json({ ok: true });
    if (url.pathname === SYNTHETIC_PAGE_PATH) return handleSyntheticPage(request, env);
    if (url.pathname === PAGERDUTY_WEBHOOK_PATH) return handlePagerDutyWebhook(request, env);
    return json({ error: "not_found" }, 404);
  },
  async scheduled(controller, env) {
    if (controller.cron !== "59 23 * * 1") {
      console.error("[synthetic_pager] rejected reason=unknown_cron");
      controller.noRetry();
      throw new Error("unknown deferred delivery cron");
    }
    await runDeferredDeliveries(controller, env, fetch);
  },
};

export { handlePagerDutyWebhook, handleSyntheticPage, markDelivered, runDeferredDeliveries };
export default handler;
