export const ALERT_EVENT = "dsr.erasure.dead_letter" as const;
export const ALERT_SEVERITY = "critical" as const;
export const ALERT_COMPONENT = "dsr-erasure-dlq" as const;
export interface DsrAlertEnvelope { readonly schema_version: 1; readonly event: typeof ALERT_EVENT; readonly severity: typeof ALERT_SEVERITY; readonly component: typeof ALERT_COMPONENT; readonly event_id: string; readonly exhausted: true; readonly requeue_count: 0 | 1; }
export interface AlertReceiptRow { readonly schema_version: number; readonly event: string; readonly severity: string; readonly component: string; readonly event_id: string; readonly exhausted: number; readonly requeue_count: number; }
export interface DsrAlertReceiverEnv { readonly DSR_ALERT_RECEIVER_TOKEN?: string; readonly ALERT_RECEIPTS_DB?: D1Database; }
const KEYS = ["schema_version", "event", "severity", "component", "event_id", "exhausted", "requeue_count"] as const;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
export function parseDsrAlertEnvelope(value: unknown): DsrAlertEnvelope | null {
  if (!isRecord(value)) return null;
  const actual = Object.keys(value).sort(), expected = [...KEYS].sort();
  if (actual.length !== expected.length || !actual.every((key, index) => key === expected[index])) return null;
  if (value.schema_version !== 1 || value.event !== ALERT_EVENT || value.severity !== ALERT_SEVERITY || value.component !== ALERT_COMPONENT || value.exhausted !== true || typeof value.event_id !== "string" || !/^dsr-erasure-dlq:[0-9a-f]{64}$/.test(value.event_id) || (value.requeue_count !== 0 && value.requeue_count !== 1)) return null;
  return value as unknown as DsrAlertEnvelope;
}
export function constantTimeBearerMatches(header: string | null, expected: string | undefined): boolean {
  if (!expected || expected.length < 32 || expected.length > 512 || !header?.startsWith("Bearer ")) return false;
  const actual = new TextEncoder().encode(header.slice(7)), target = new TextEncoder().encode(expected);
  let difference = actual.length ^ target.length;
  for (let index = 0; index < Math.max(actual.length, target.length); index += 1) difference |= (actual[index] ?? 0) ^ (target[index] ?? 0);
  return difference === 0;
}
export function receiptMatches(row: AlertReceiptRow | null, value: DsrAlertEnvelope): boolean { return row !== null && row.schema_version === value.schema_version && row.event === value.event && row.severity === value.severity && row.component === value.component && row.event_id === value.event_id && row.exhausted === 1 && row.requeue_count === value.requeue_count; }
