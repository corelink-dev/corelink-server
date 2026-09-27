/** Durable Object telemetry, proxy, and D1 probe domain helpers. */

import type { Fetcher } from "@cloudflare/workers-types";

/** Probe-domain bounds; kept with the probe implementation so the lifecycle
 * manager does not own instrumentation policy. */
const CONTAINER_PORT = 50051;
const D1_PROBE_SAMPLES = 3;
const D1_PROBE_TIMEOUT_MS = 5_000;
const DO_COLO_TIMEOUT_MS = 2_000;

export interface LifecycleEvent {
  readonly event_type: string;
  readonly routing_key: string;
  readonly payload: {
    readonly summary: string;
    readonly severity: "info" | "warning" | "error" | "critical";
    readonly source: string;
    readonly custom_details: {
      readonly tenant_id_hash: string;
      readonly do_id_hash: string;
      readonly cold_start_count: number;
      readonly environment: string;
      readonly timestamp_ms: number;
    };
  };
}

/**
 * One D1 read path (primary or nearest-replica) as measured by the
 * `/_do/health` placement instrument.
 *
 * The three failure modes are DELIBERATELY distinguishable — collapsing them is
 * how a broken instrument reports a fast number it never measured:
 *   - `available: false`            → the path could not be attempted at all.
 *   - `available: true, ok: false`  → attempted and THREW (`error` is non-null).
 *   - `available: true, ok: true`   → measured; `samples_ms` are real.
 */
export interface D1PathProbeResult {
  /** Could this path be attempted at all (binding bound / Sessions API present)? */
  readonly available: boolean;
  /** Did every attempted sample succeed? False whenever `error` is non-null. */
  readonly ok: boolean;
  /** Wall-clock ms per sample, in order. Empty when the path was unavailable. */
  readonly samples_ms: readonly number[];
  /** Fastest sample — the number to read. `null` when nothing was measured. */
  readonly min_ms: number | null;
  /** Non-null iff a read threw or was unavailable. NEVER silently a number. */
  readonly error: string | null;
  /** D1 `meta.served_by_region` (e.g. "ENAM") of the last successful sample. */
  readonly served_by_region: string | null;
  /** D1 `meta.served_by_primary` — false proves a real replica served the read. */
  readonly served_by_primary: boolean | null;
  /** D1 `meta.served_by_colo` (e.g. "MIA") of the last successful sample. */
  readonly served_by_colo: string | null;
}

/** The `d1_probe` object added to the `/_do/health` body. Purely additive. */
export interface D1ProbeReport {
  readonly probe_version: number;
  readonly samples: number;
  readonly binding_bound: boolean;
  readonly sessions_api_available: boolean;
  /** Uncounted first read that absorbs connection setup (the "cold" number). */
  readonly warmup_ms: number | null;
  readonly warmup_error: string | null;
  readonly primary: D1PathProbeResult;
  readonly replica: D1PathProbeResult;
  /** Serving colo of THIS DO — only with `?colo=1`, best-effort. */
  readonly do_colo: string | null;
  readonly do_colo_error: string | null;
}

/** Minimal structural shape of a D1 read handle (a DB or a session). */
export interface D1ProbeHandle {
  prepare(query: string): { all(): Promise<unknown> };
}

/** A `CONFIG_DB` binding: a read handle that MAY expose the Sessions API. */
export interface D1ProbeBinding extends D1ProbeHandle {
  withSession?: (constraint: string) => D1ProbeHandle;
}

// ──────────────────────────────────────────────────────────────────────────────
export async function hashForLog(value: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(value));
  const arr = new Uint8Array(buf);
  return Array.from(arr.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ──────────────────────────────────────────────────────────────────────────────
// Constant-time comparison
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Per-isolate random HMAC key for {@link timingSafeEqual}.
 *
 * F22 (2026-06-13 audit): the previous implementation used an all-zero key,
 * which offers no confidentiality if an attacker can observe the HMAC output.
 * The key MUST be a real secret. It is generated once per isolate from a CSPRNG
 * and never leaves this module; HMAC-ing both inputs under a key the attacker
 * does not know makes the post-HMAC byte comparison non-forgeable.
 */
let hmacKeyPromise: Promise<CryptoKey> | undefined;
function getHmacKey(): Promise<CryptoKey> {
  if (hmacKeyPromise === undefined) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    hmacKeyPromise = crypto.subtle.importKey(
      "raw",
      raw,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  }
  return hmacKeyPromise;
}

/**
 * Constant-time bytes equality.
 *
 * HMAC-SHA256s both inputs under a per-isolate random key, then XOR-compares
 * the two 32-byte tags. Because HMAC-SHA256 always yields a fixed 32-byte
 * output regardless of input length, NO length branch is taken — equal and
 * unequal-length inputs run the exact same two HMACs and the same fixed-width
 * compare, so there is no length-equality timing oracle (F22). The random key
 * (not a zero key) means the post-HMAC tags cannot be forged or replayed.
 * Equivalent to Rust's `subtle::ConstantTimeEq`.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  const key = await getHmacKey();
  // Both HMACs run unconditionally regardless of length — HMAC-SHA256 emits a
  // fixed 32-byte tag, so the comparison below is always over equal widths and
  // there is no length-dependent fast path.
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign("HMAC", key, aBytes),
    crypto.subtle.sign("HMAC", key, bBytes),
  ]);
  const viewA = new Uint8Array(sigA);
  const viewB = new Uint8Array(sigB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= (viewA[i] ?? 0) ^ (viewB[i] ?? 0);
  }
  return diff === 0;
}

// Keep the export so tests can call it directly

// ──────────────────────────────────────────────────────────────────────────────
// PagerDuty telemetry (fire-and-forget)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Emit a lifecycle event to PagerDuty Change Events API.
 * ALWAYS called BEFORE the state mutation it describes.
 *
 * INV-NO-PII-IN-LOGS: tenant_id is pre-hashed before emission.
 */
export async function emitLifecycleEvent(
  routingKey: string,
  eventType: string,
  summary: string,
  severity: "info" | "warning" | "error" | "critical",
  tenantIdHash: string,
  doIdHash: string,
  coldStartCount: number,
  environment: string,
): Promise<void> {
  if (routingKey.length === 0) return;

  const event: LifecycleEvent = {
    event_type: eventType,
    routing_key: routingKey,
    payload: {
      summary,
      severity,
      source: "corelink-do",
      custom_details: {
        tenant_id_hash: tenantIdHash,
        do_id_hash: doIdHash,
        cold_start_count: coldStartCount,
        environment,
        timestamp_ms: Date.now(),
      },
    },
  };

  try {
    const resp = await fetch("https://events.pagerduty.com/v2/change/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
    });
    if (!resp.ok) {
      console.error(`[do] PagerDuty emit failed status=${resp.status}`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message.slice(0, 80) : "unknown";
    console.error(`[do] PagerDuty emit threw: ${msg}`);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Container proxy helpers
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Forward an HTTP request to the running container via the Fetcher obtained
 * from `container.getTcpPort(CONTAINER_PORT)`.
 *
 * The Rust gRPC server (corelink-server) speaks HTTP/2 natively (tonic +
 * tonic-web). The Fetcher routes HTTP to the container port. We preserve the
 * full path + query string so the gRPC-gateway transcoding inside the Rust
 * binary handles protocol routing.
 *
 * INV-NO-BODY-IN-LOGS: we never read or log the body.
 */
export async function proxyToContainer(request: Request, fetcher: Fetcher): Promise<Response> {
  const url = new URL(request.url);
  const containerUrl = `http://localhost:${CONTAINER_PORT}${url.pathname}${url.search}`;

  const proxied = new Request(containerUrl, {
    method: request.method,
    headers: request.headers,
    body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
    // @ts-expect-error duplex is required for streaming request bodies
    duplex: request.method !== "GET" && request.method !== "HEAD" ? "half" : undefined,
  });

  return fetcher.fetch(proxied);
}

// ──────────────────────────────────────────────────────────────────────────────
// D1 placement instrument helpers (used ONLY by /_do/health)
// ──────────────────────────────────────────────────────────────────────────────

/** Short, bounded error text. Never carries a body or a secret. */
export function errText(err: unknown): string {
  return err instanceof Error ? err.message.slice(0, 160) : "unknown error";
}

/**
 * Reject after `ms` if `p` has not settled. The loser's rejection is absorbed
 * (`void p.catch`) so a late failure cannot surface as an unhandled rejection.
 */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  void p.catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  }) as Promise<T>;
}

/** Extract D1's own `meta.served_by_*` provenance from a result, defensively. */
function readServedBy(result: unknown): {
  region: string | null;
  primary: boolean | null;
  colo: string | null;
} {
  const empty = { region: null, primary: null, colo: null };
  if (typeof result !== "object" || result === null) return empty;
  const meta = (result as { meta?: unknown }).meta;
  if (typeof meta !== "object" || meta === null) return empty;
  const m = meta as Record<string, unknown>;
  return {
    region: typeof m["served_by_region"] === "string" ? m["served_by_region"] : null,
    primary: typeof m["served_by_primary"] === "boolean" ? m["served_by_primary"] : null,
    colo: typeof m["served_by_colo"] === "string" ? m["served_by_colo"] : null,
  };
}

/**
 * One timed `SELECT 1` against a D1 read handle.
 *
 * `SELECT 1` touches no table, so what is measured is the ROUND TRIP to whatever
 * D1 instance serves the handle — which is exactly the placement question.
 */
export async function timedD1Read(
  handle: D1ProbeHandle,
): Promise<{ ms: number | null; error: string | null; result: unknown }> {
  const started = Date.now();
  try {
    const result = await withTimeout(
      handle.prepare("SELECT 1").all(),
      D1_PROBE_TIMEOUT_MS,
      "d1 probe read",
    );
    return { ms: Date.now() - started, error: null, result };
  } catch (err: unknown) {
    // A throw is reported as an EXPLICIT error — never as a fast number and
    // never as a missing field. That distinction is the whole instrument.
    return { ms: null, error: errText(err), result: null };
  }
}

/** A path that could not be attempted at all (distinct from attempted-and-failed). */
export function unavailablePath(reason: string): D1PathProbeResult {
  return {
    available: false,
    ok: false,
    samples_ms: [],
    min_ms: null,
    error: reason,
    served_by_region: null,
    served_by_primary: null,
    served_by_colo: null,
  };
}

/** Take {@link D1_PROBE_SAMPLES} timed reads on one handle; stop at the first throw. */
export async function probeD1Path(handle: D1ProbeHandle): Promise<D1PathProbeResult> {
  const samples: number[] = [];
  let error: string | null = null;
  let servedBy: { region: string | null; primary: boolean | null; colo: string | null } = {
    region: null,
    primary: null,
    colo: null,
  };

  for (let i = 0; i < D1_PROBE_SAMPLES; i++) {
    const sample = await timedD1Read(handle);
    if (sample.error !== null || sample.ms === null) {
      error = sample.error ?? "no timing produced";
      break;
    }
    samples.push(sample.ms);
    const provenance = readServedBy(sample.result);
    if (provenance.region !== null || provenance.primary !== null || provenance.colo !== null) {
      servedBy = provenance;
    }
  }

  return {
    available: true,
    ok: error === null && samples.length === D1_PROBE_SAMPLES,
    samples_ms: samples,
    min_ms: samples.length > 0 ? Math.min(...samples) : null,
    error,
    served_by_region: servedBy.region,
    served_by_primary: servedBy.primary,
    served_by_colo: servedBy.colo,
  };
}

/**
 * Best-effort serving colo of THIS DO (`/_do/health?colo=1` only).
 *
 * An outbound `fetch` from a DO egresses through the colo the DO runs in, so
 * `cdn-cgi/trace` reports that colo. ADVISORY: it is a inference from an
 * external call, not a platform-attested placement API — read it as a hint that
 * EXPLAINS the timings, never as the timing itself. Off by default so the plain
 * health probe makes no external request.
 */
export async function resolveDoColo(): Promise<{ colo: string | null; error: string | null }> {
  try {
    const resp = await withTimeout(
      fetch("https://workers.cloudflare.com/cdn-cgi/trace", {
        method: "GET",
        headers: { "Cache-Control": "no-cache" },
      }),
      DO_COLO_TIMEOUT_MS,
      "colo trace",
    );
    if (!resp.ok) return { colo: null, error: `trace status ${resp.status}` };
    const text = await resp.text();
    const line = text.split("\n").find((l) => l.startsWith("colo="));
    return line === undefined
      ? { colo: null, error: "no colo line in trace" }
      : { colo: line.slice("colo=".length).trim(), error: null };
  } catch (err: unknown) {
    return { colo: null, error: errText(err) };
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Durable Object class
// ──────────────────────────────────────────────────────────────────────────────
