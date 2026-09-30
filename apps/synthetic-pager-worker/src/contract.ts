export const SYNTHETIC_PAGE_PATH = "/v1/drills/synthetic_page" as const;
export const PAGERDUTY_WEBHOOK_PATH = "/v1/webhooks/pagerduty" as const;
export const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue" as const;
export const SYNTHETIC_SERVICE = "synthetic-drill" as const;
export const SYNTHETIC_SEVERITY = "sev2_synthetic" as const;
export const SYNTHETIC_EVENT_SEVERITY = "info" as const;
export const SYNTHETIC_CORRELATION_PREFIX = "PAT-CORRELATION-ID-001:" as const;
export const B072_ONE_SHOT_CRON = "* * * * *" as const;

export type SyntheticRegion = "americas" | "emea" | "apac" | "boundary_handoff";
export type SyntheticDeliveryMode = "immediate" | "deferred";
/** Explicit provider disposition; deferred mode never attempts alert delivery. */
export type SyntheticProviderMode = "pagerduty" | "provider_deferred";
/** Terminal D1 outcomes for provider-deferred receipts. */
export type SyntheticTerminalOutcome = "provider_deferred";

export interface SyntheticPagePayload {
  readonly service: typeof SYNTHETIC_SERVICE;
  readonly event_action: "trigger";
  readonly severity: typeof SYNTHETIC_EVENT_SEVERITY;
  readonly synthetic_severity: typeof SYNTHETIC_SEVERITY;
  readonly region: SyntheticRegion;
  readonly rotation_week: 0 | 1 | 2 | 3;
  readonly emit_at_ms: number;
  readonly delivery_mode: SyntheticDeliveryMode;
  readonly provider_mode: SyntheticProviderMode;
  readonly worker_revision?: string;
  readonly serving_sha?: string;
  readonly dedup_key: string;
  readonly correlation_id: string;
}

export interface SyntheticPageEnvelope {
  readonly drill: "synthetic_page";
  readonly cron: "0 14 * * 1" | typeof B072_ONE_SHOT_CRON;
  readonly scheduled_at_ms: number;
  readonly synthetic_page: SyntheticPagePayload;
}

export interface ReceiverEnv {
  readonly ENVIRONMENT?: string;
  readonly SYNTHETIC_DRILL_ENABLED?: string;
  readonly SYNTHETIC_DRILL_PROVIDER_MODE?: "pagerduty" | "provider_deferred";
  readonly PAGERDUTY_EVENTS_URL?: string;
  readonly PAGERDUTY_SERVICE?: string;
  readonly PAGERDUTY_SYNTHETIC_ROUTING_KEY?: string;
  readonly PAGERDUTY_WEBHOOK_SECRET?: string;
  readonly CONFIG_DB?: D1Database;
  /** Cloudflare deployment version identifier, supplied by version metadata. */
  readonly CF_VERSION_METADATA?: { readonly id?: string };
  /** Exact source commit SHA baked into the deployment. */
  readonly SENTRY_RELEASE?: string;
}

export interface PagerDutyEvent {
  readonly routing_key: string;
  readonly event_action: "trigger";
  readonly dedup_key: string;
  readonly payload: {
    readonly summary: string;
    readonly source: "corelink-synthetic-pager";
    readonly severity: typeof SYNTHETIC_EVENT_SEVERITY;
    readonly custom_details: {
      readonly synthetic_severity: typeof SYNTHETIC_SEVERITY;
      readonly region: SyntheticRegion;
      readonly rotation_week: 0 | 1 | 2 | 3;
      readonly emit_at_ms: number;
      readonly delivery_mode: SyntheticDeliveryMode;
      readonly correlation_id: string;
    };
  };
}

export type PagerDutyWebhookKind = "acknowledged" | "escalated";

export interface PagerDutyWebhook {
  readonly event_id: string;
  readonly kind: PagerDutyWebhookKind;
  readonly drill_id: string;
  readonly occurred_at_ms: number;
  readonly engineer_slug: string;
  readonly ack_vector: "mobile_push" | "sms" | "email" | "escalation";
}

const ENVELOPE_KEYS = ["drill", "cron", "scheduled_at_ms", "synthetic_page"] as const;
const PAYLOAD_KEYS = [
  "service",
  "event_action",
  "severity",
  "synthetic_severity",
  "region",
  "rotation_week",
  "emit_at_ms",
  "delivery_mode",
  "provider_mode",
  "worker_revision",
  "serving_sha",
  "dedup_key",
  "correlation_id",
] as const;
const WEEKLY_REQUIRED_KEYS = PAYLOAD_KEYS.filter((key) =>
  key !== "provider_mode" && key !== "worker_revision" && key !== "serving_sha");

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function parseSyntheticPageEnvelope(
  value: unknown,
  context: { readonly environment?: string; readonly providerMode?: string } = {},
): SyntheticPageEnvelope | null {
  if (!isRecord(value) || !hasExactlyKeys(value, ENVELOPE_KEYS)) return null;
  const oneShot = value.cron === B072_ONE_SHOT_CRON;
  if (value.drill !== "synthetic_page" || (!oneShot && value.cron !== "0 14 * * 1") || !isInteger(value.scheduled_at_ms)) {
    return null;
  }
  if (oneShot && (context.environment !== "staging" || context.providerMode !== "provider_deferred")) return null;
  const page = value.synthetic_page;
  if (!isRecord(page)) return null;
  const allowedWeeklyKeys = new Set<string>([...WEEKLY_REQUIRED_KEYS, "provider_mode", "worker_revision", "serving_sha"]);
  if (oneShot ? !hasExactlyKeys(page, PAYLOAD_KEYS) :
      (!Object.keys(page).every((key) => allowedWeeklyKeys.has(key)) ||
       WEEKLY_REQUIRED_KEYS.some((key) => !(key in page)))) return null;
  if (
    page.service !== SYNTHETIC_SERVICE ||
    page.event_action !== "trigger" ||
    page.severity !== SYNTHETIC_EVENT_SEVERITY ||
    page.synthetic_severity !== SYNTHETIC_SEVERITY ||
    !["americas", "emea", "apac", "boundary_handoff"].includes(page.region as string) ||
    ![0, 1, 2, 3].includes(page.rotation_week as number) ||
    !isInteger(page.emit_at_ms) ||
    !["immediate", "deferred"].includes(page.delivery_mode as string) ||
    !["pagerduty", "provider_deferred"].includes((page.provider_mode ?? "pagerduty") as string) ||
    typeof page.dedup_key !== "string" ||
    page.dedup_key.length < 1 ||
    page.dedup_key.length > 200 ||
    typeof page.correlation_id !== "string" ||
    page.correlation_id !== `${SYNTHETIC_CORRELATION_PREFIX}${page.dedup_key}` ||
    !/^SP-[0-9]{13}$/.test(page.dedup_key)
  ) {
    return null;
  }
  if (oneShot && (page.provider_mode !== "provider_deferred" ||
      context.providerMode !== "provider_deferred" || value.scheduled_at_ms % 60_000 !== 0 ||
      !/^[0-9a-f]{40}$/.test(String(page.worker_revision)) || page.serving_sha !== page.worker_revision)) return null;
  const providerMode = page.provider_mode ?? "pagerduty";
  if (providerMode === "provider_deferred" &&
      (typeof page.worker_revision !== "string" || page.worker_revision.length < 1 || page.worker_revision.length > 200 ||
       typeof page.serving_sha !== "string" || !/^[0-9a-f]{40}$/i.test(page.serving_sha))) return null;
  const scheduled = new Date(value.scheduled_at_ms);
  if (!oneShot && (
      scheduled.getUTCDay() !== 1 || scheduled.getUTCHours() !== 14 || scheduled.getUTCMinutes() !== 0 ||
      scheduled.getUTCSeconds() !== 0 || scheduled.getUTCMilliseconds() !== 0
  )) {
    return null;
  }
  const scheduledWeek = Math.floor((value.scheduled_at_ms - Date.UTC(1970, 0, 5)) / (7 * 24 * 60 * 60 * 1_000));
  const expectedRotation = ((scheduledWeek % 4) + 4) % 4;
  const scheduledDrillId = `SP-${value.scheduled_at_ms}`;
  const expectedRegion = (["americas", "emea", "apac", "boundary_handoff"] as const)[expectedRotation];
  const expectedEmitAt = page.delivery_mode === "immediate"
    ? value.scheduled_at_ms
    : Date.UTC(
        scheduled.getUTCFullYear(),
        scheduled.getUTCMonth(),
        scheduled.getUTCDate() + (oneShot ? 7 - scheduled.getUTCDay() : 6),
        23,
        59,
        0,
        0,
      );
  if (
    page.dedup_key !== scheduledDrillId ||
    page.rotation_week !== expectedRotation ||
    page.region !== expectedRegion
  ) return null;
  if (
    (page.delivery_mode === "deferred" && page.region !== "boundary_handoff") ||
    (page.delivery_mode === "immediate" && page.region === "boundary_handoff") ||
    page.emit_at_ms !== expectedEmitAt
  ) {
    return null;
  }
  return {
    drill: "synthetic_page",
    cron: oneShot ? B072_ONE_SHOT_CRON : "0 14 * * 1",
    scheduled_at_ms: value.scheduled_at_ms,
    synthetic_page: {
      service: SYNTHETIC_SERVICE,
      event_action: "trigger",
      severity: SYNTHETIC_EVENT_SEVERITY,
      synthetic_severity: SYNTHETIC_SEVERITY,
      region: page.region as SyntheticRegion,
      rotation_week: page.rotation_week as 0 | 1 | 2 | 3,
      emit_at_ms: page.emit_at_ms,
      delivery_mode: page.delivery_mode as SyntheticDeliveryMode,
      provider_mode: providerMode as SyntheticProviderMode,
      worker_revision: typeof page.worker_revision === "string" ? page.worker_revision : undefined,
      serving_sha: typeof page.serving_sha === "string" ? page.serving_sha : undefined,
      dedup_key: page.dedup_key,
      correlation_id: page.correlation_id,
    },
  };
}

/**
 * Reject production before checking a secret, D1, or the PagerDuty endpoint.
 * `prod-*` regional names are rejected as well as the exact `prod` name.
 */
export function validateReceiverEnvironment(env: ReceiverEnv): string | null {
  const environment = env.ENVIRONMENT?.trim().toLowerCase();
  if (environment === "prod" || environment?.startsWith("prod-")) {
    return "synthetic drill receiver is not activatable in production";
  }
  if (environment !== "dev" && environment !== "staging") return "unsupported receiver environment";
  if (env.SYNTHETIC_DRILL_ENABLED !== "true") return "synthetic drill receiver is disabled";
  if (env.CONFIG_DB === undefined) return "synthetic drill database binding is unavailable";
  if (env.SYNTHETIC_DRILL_PROVIDER_MODE === "provider_deferred") return null;
  if (env.PAGERDUTY_EVENTS_URL !== PAGERDUTY_EVENTS_URL) return "PagerDuty endpoint is not canonical";
  if (env.PAGERDUTY_SERVICE !== SYNTHETIC_SERVICE) return "PagerDuty service is not synthetic-drill";
  if (!env.PAGERDUTY_SYNTHETIC_ROUTING_KEY?.trim()) {
    return "synthetic routing key is unavailable";
  }
  return null;
}

export function buildPagerDutyEvent(page: SyntheticPagePayload, routingKey: string): PagerDutyEvent {
  return {
    routing_key: routingKey,
    event_action: "trigger",
    dedup_key: page.dedup_key,
    payload: {
      summary: `CoreLink synthetic page (${page.region})`,
      source: "corelink-synthetic-pager",
      severity: SYNTHETIC_EVENT_SEVERITY,
      custom_details: {
        synthetic_severity: SYNTHETIC_SEVERITY,
        region: page.region,
        rotation_week: page.rotation_week,
        emit_at_ms: page.emit_at_ms,
        delivery_mode: page.delivery_mode,
        correlation_id: page.correlation_id,
      },
    },
  };
}

export function validateWebhookEnvironment(env: ReceiverEnv): string | null {
  const environment = env.ENVIRONMENT?.trim().toLowerCase();
  if (environment === "prod" || environment?.startsWith("prod-")) {
    return "synthetic drill webhook is not activatable in production";
  }
  if (environment !== "dev" && environment !== "staging") return "unsupported receiver environment";
  if (env.SYNTHETIC_DRILL_ENABLED !== "true") return "synthetic drill receiver is disabled";
  if (!env.PAGERDUTY_WEBHOOK_SECRET?.trim()) return "PagerDuty webhook secret is unavailable";
  if (env.CONFIG_DB === undefined) return "synthetic drill database binding is unavailable";
  return null;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return null;
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export async function verifyPagerDutySignature(body: string, header: string | null, secret: string): Promise<boolean> {
  const signature = header?.split(",").find((part) => part.startsWith("v1="))?.slice(3);
  const expected = signature === undefined ? null : hexToBytes(signature);
  if (expected === null) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const actual = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) difference |= actual[index]! ^ expected[index]!;
  return difference === 0;
}

function dateMs(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const time = Date.parse(value);
  return Number.isSafeInteger(time) && time >= 0 ? time : null;
}

export function parsePagerDutyWebhook(value: unknown): PagerDutyWebhook | null {
  if (!isRecord(value) || typeof value.id !== "string" || !isRecord(value.data)) return null;
  const kind = value.event_type === "incident.acknowledged" ? "acknowledged" : value.event_type === "incident.escalated" ? "escalated" : null;
  if (kind === null || !isRecord(value.data.incident)) return null;
  const incident = value.data.incident;
  if (
    isRecord(incident.service) &&
    typeof incident.service.summary === "string" &&
    incident.service.summary !== SYNTHETIC_SERVICE
  ) {
    return null;
  }
  const drillId = typeof incident.incident_key === "string" ? incident.incident_key : null;
  const occurredAt = dateMs(value.occurred_at);
  if (drillId === null || !/^SP-[0-9]{13}$/.test(drillId) || occurredAt === null) return null;
  const assignments = Array.isArray(incident.assignments) ? incident.assignments : [];
  const firstAssignment = assignments[0];
  const assignee = isRecord(firstAssignment) && isRecord(firstAssignment.assignee) ? firstAssignment.assignee : null;
  const engineerSlug = assignee !== null && typeof assignee.summary === "string" ? assignee.summary : `pagerduty-${value.id}`;
  return {
    event_id: value.id,
    kind,
    drill_id: drillId,
    occurred_at_ms: occurredAt,
    engineer_slug: engineerSlug.slice(0, 200),
    ack_vector: kind === "escalated" ? "escalation" : "mobile_push",
  };
}
