import { constantTimeBearerMatches, parseDsrAlertEnvelope, receiptMatches, type AlertReceiptRow, type DsrAlertEnvelope, type DsrAlertReceiverEnv } from "./contract.js";
const json = (body: object, status: number) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
async function persistReceipt(db: D1Database, envelope: DsrAlertEnvelope, now: number): Promise<"accepted" | "duplicate" | "mismatch"> {
  const write = await db.prepare(`INSERT OR IGNORE INTO dsr_alert_receipts (event_id, schema_version, event, severity, component, exhausted, requeue_count, received_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(envelope.event_id, envelope.schema_version, envelope.event, envelope.severity, envelope.component, 1, envelope.requeue_count, now).run();
  if (!write.success || (write.meta?.changes !== 0 && write.meta?.changes !== 1)) throw new Error("receipt_write_ambiguous");
  const row = await db.prepare(`SELECT event_id, schema_version, event, severity, component, exhausted, requeue_count FROM dsr_alert_receipts WHERE event_id = ?`).bind(envelope.event_id).first<AlertReceiptRow>();
  if (row === null) throw new Error("receipt_read_ambiguous");
  if (!receiptMatches(row, envelope)) return "mismatch";
  return write.meta?.changes === 1 ? "accepted" : "duplicate";
}
export async function handleDsrAlert(request: Request, env: DsrAlertReceiverEnv, clock: () => number = Date.now): Promise<Response> {
  if (new URL(request.url).protocol !== "https:") return json({ error: "https_required" }, 400);
  if (new URL(request.url).pathname !== "/") return json({ error: "not_found" }, 404);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") return json({ error: "content_type_required" }, 415);
  if (!constantTimeBearerMatches(request.headers.get("authorization"), env.DSR_ALERT_RECEIVER_TOKEN)) return json({ error: "unauthorized" }, 401);
  let body: unknown; try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
  const envelope = parseDsrAlertEnvelope(body); if (envelope === null) return json({ error: "invalid_alert_contract" }, 400);
  if (env.ALERT_RECEIPTS_DB === undefined) return json({ error: "receipt_storage_unavailable" }, 503);
  try { const result = await persistReceipt(env.ALERT_RECEIPTS_DB, envelope, clock()); if (result === "mismatch") return json({ error: "replay_mismatch" }, 409); return json({ accepted: true, duplicate: result === "duplicate" }, 202); } catch { return json({ error: "receipt_storage_unavailable" }, 503); }
}
export default { fetch(request: Request, env: DsrAlertReceiverEnv): Promise<Response> { return handleDsrAlert(request, env); } } satisfies ExportedHandler<DsrAlertReceiverEnv>;
