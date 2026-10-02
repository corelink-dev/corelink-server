import { cleanOldProbeTables, cleanV5ProbeTables, OLD_PROBE_NAME, OLD_PROBE_RELEASE, OLD_PROBE_RETIRED_KEY, V5_PROBE_NAME, V5_PROBE_RELEASE, V5_PROBE_RETIRED_KEY, type OldProbeRetirement } from "./staging_d1_probe_retirement.js";
import { recordStagingD1ProbePhase, STAGING_D1_PROBE_WINDOW } from "./staging_runtime_d1_probe.js";
import { cleanV8ProbeTables, isV8CleanupReceipt, withinV8CleanupDeadline, V8_PROBE_NAME, V8_PROBE_RELEASE, V8_PROBE_NONCE, V8_PROBE_RETIRED_KEY, V8_CLEANUP_RECEIPT_KEY, type V8CleanupReceipt } from "./staging_d1_probe_v8_cleanup.js";
import { cleanV9ProbeTables, isV9CleanupReceipt, withinV9CleanupDeadline, V9_PROBE_NAME, V9_PROBE_RELEASE, V9_PROBE_NONCE, V9_PROBE_RETIRED_KEY, V9_CLEANUP_RECEIPT_KEY, type V9CleanupReceipt } from "./staging_d1_probe_v9_cleanup.js";
import { STAGING_D1_HTTP_CONTRACT, STAGING_D1_HTTP_EXECUTE_MS, STAGING_D1_HTTP_CLEANUP_MS, isStagingD1HttpStatus, type StagingD1HttpStatus } from "./staging_d1_http_contract.js";
import { StagingD1HttpLifecycle } from "./staging_d1_http_lifecycle.js";
import { STAGING_D1_HTTP_LIFETIME_KEY, createHttpLifetime, httpDeadlineContext, isStagingD1HttpLifetime, isStagingD1HttpDeadline, type StagingD1HttpLifetime, type StagingD1HttpDeadline } from "./staging_d1_http_lifetime.js";
import { runStagingD1HttpSequence } from "./staging_runtime_d1_probe.js";
import cleanupWindow from "./staging_d1_probe_cleanup_window.json";
/**
 * CoreLinkServer Durable Object — container lifecycle manager + gRPC proxy.
 *
 * Responsibilities:
 *   1. Container lifecycle: start on cold wake, stop on idle timeout.
 *   2. Health probe: HTTP GET /_health on container port 50051.
 *   3. Request multiplexing: HTTP request → gRPC call on the container.
 *   4. Lifecycle telemetry: emit audit events BEFORE each state mutation.
 *   5. Per-tenant pinning: DO ID = idFromName(tenantId) — never cross-tenant.
 *
 * Cloudflare Containers beta API (wrangler 4.x / workers-types 4.20260526.1):
 *   - `state.container` — the Container instance bound to this DO.
 *   - `container.start(options?)` — starts the container (returns void).
 *   - `container.running` — true if container is live.
 *   - `container.getTcpPort(port)` → `Fetcher` — HTTP fetcher for container port.
 *   - `container.monitor()` → `Promise<void>` — resolves when container exits.
 *   - `container.destroy()` — terminate the container.
 *   - `container.setInactivityTimeout(ms)` — auto-destroy on idle.
 *
 * Charter constraints:
 *   - Audit emit BEFORE state mutation.
 *   - INV-NO-BODY-IN-LOGS: body bytes NEVER logged.
 *   - INV-NO-PII-IN-LOGS: tenant IDs hashed before tracing.
 *   - Constant-time PAT compare via crypto.subtle.timingSafeEqual.
 *   - Container is started fresh per cold-start; idle timeout triggers stop.
 */
import { DurableObject as CloudflareDurableObject } from "cloudflare:workers";
import {
  emitLifecycleEvent,
  hashForLog,
  probeD1Path,
  proxyToContainer,
  resolveDoColo,
  timedD1Read,
  timingSafeEqual,
  errText,
  unavailablePath,
} from "./durable_object_probes.js";
import { startContainer as runStartContainer } from "./durable_object_start.js";
import { installD1BindingProxy } from "./staging_d1_binding_proxy.js";
import {
  STAGING_D1_RUNTIME_PROBE_PATH,
  STAGING_D1_RUNTIME_PROBE_DO_PREFIX,
  type StagingD1RuntimeProbeAdmission,
  type StagingD1RuntimeProbeAdmissionResult,
  type StagingD1RuntimeProbeReceipt,
} from "./staging_runtime_d1_probe.js";
import type {
  D1ProbeBinding,
  D1PathProbeResult,
  D1ProbeReport,
} from "./durable_object_probes.js";
export { timingSafeEqual };
import type {
  DurableObject,
  DurableObjectStorage,
  Container,
  Fetcher,
  KVNamespace,
} from "@cloudflare/workers-types";
import type { Env } from "./index.js";
type CoreLinkDurableObjectState = ConstructorParameters<typeof CloudflareDurableObject<Env>>[0];
import {
  enforcePatIssueRateLimit,
  PAT_ISSUE_AUTHORIZED_HEADER,
} from "./pat_issue_rate_limit.js";
import { isPilotSignupPath } from "./route_match.js";
import {
  isStagingGrpcDiagnosticPath,
  verifyStagingGrpcDiagnosticBinding,
} from "./grpc_staging_authorization.js";
import { isNonRedirectNativeGrpcResponse } from "./grpc_staging_transport.js";
import { handleRunnerPrepare } from "./lib/runner_credential_routes.js";
import {
  drainCredentialCleanupObligations,
  handleDevenvCleanupRequest,
} from "./lib/devenv_cleanup_route.js";

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────
/** Lifecycle state persisted in DO storage. */
interface LifecycleState {
  readonly containerStatus: ContainerStatus;
  readonly lastHealthCheckMs: number;
  readonly coldStartCount: number;
  readonly tenantId: string | null;
  /**
   * Wall-clock (ms) when `containerStatus` last flipped to `"starting"`. Drives
   * stale-`"starting"` recovery in `ensureContainerRunning`. Optional for
   * back-compat with lifecycle states persisted before this field existed
   * (an absent value reads as 0 → treated as immediately stale → self-heals).
   */
  readonly startingAt_ms?: number;
  /**
   * Wall-clock (ms) of the last REAL proxied request (or container start).
   * Drives the DURABLE idle reaper in `alarm()`. Touched in-memory on the
   * request hot path (zero storage cost) and persisted by the health-check
   * alarm's existing lifecycle write, so it is never more than one
   * `HEALTH_CHECK_INTERVAL_MS` stale after an isolate eviction — negligible
   * against `IDLE_TIMEOUT_MS`. Optional for back-compat: an absent value
   * (pre-fix persisted state) starts the idle clock at the next alarm, so a
   * previously-immortal container dies one idle window after this deploys.
   */
  readonly lastActivityMs?: number;
}

type ContainerStatus = "stopped" | "starting" | "running" | "degraded";

/** Telemetry event shape (emitted to PagerDuty change events API + audit). */
// Constants
// ──────────────────────────────────────────────────────────────────────────────

const CONTAINER_PORT = 50051;

function grpcDiagnosticUnavailable(): Response {
  return new Response(JSON.stringify({ error: "GRPC_TRANSPORT_UNAVAILABLE" }), {
    status: 503,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}
/** Timed samples taken per D1 read path on `/_do/health`. */
const D1_PROBE_SAMPLES = 3;
/** Per-sample ceiling (ms). A hung D1 must not hang the health probe. */
const D1_PROBE_TIMEOUT_MS = 5_000;
/** Ceiling (ms) for the best-effort `?colo=1` trace fetch. */
const DO_COLO_TIMEOUT_MS = 2_000;
/** Bumped whenever the `d1_probe` shape changes, so a reader can tell. */
const D1_PROBE_VERSION = 1;
/**
 * Idle timeout before container is destroyed (ms). 30 minutes.
 *
 * Raised from 5→30min (2026-07-01): the ~2.5s cold-start is only paid on the
 * FIRST request after the container is reaped, and warm steady-state is already
 * fast (post-#368, sub-second). A 30-min idle window keeps a tenant's container
 * warm across normal work-session gaps (a coffee break / a meeting) so they
 * rarely re-pay the cold-start, while the container STILL dies after a bounded
 * idle tail — so the COGS is proportional to real activity (recently-active
 * tenants only), NOT a global always-on warm pool. The cheap, infra-free
 * version of WP-3 (`docs/perf/2026-06-19-cas-hot-path-latency.md`).
 *
 * ENFORCED IN `alarm()` (durable), NOT a `setTimeout`: the original in-memory
 * idle timer evaporated on every isolate eviction while the health-check
 * alarm chain survived, so any once-started container became immortal and
 * was billed 24/7 (2026-07 invoice: ~13 GiB resident memory around the
 * clock / $84 per month of Container Memory against $0.00 of billable
 * traffic). The reaper compares `lastActivityMs` (persisted lifecycle state)
 * against this window on every alarm tick and destroys the container +
 * ends the alarm chain when it expires.
 */
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
/** Health check interval when container is running (ms). */
const HEALTH_CHECK_INTERVAL_MS = 30_000;
/** Max consecutive health-check failures before marking degraded. */
const MAX_HEALTH_FAILURES = 3;
/** Container startup health-poll timeout (ms). */
// Bumped to 90s on 2026-05-28: the container's routes-build path now eagerly
// constructs both the R2 CAS S3 client and the R2 AC S3 client (block_in_place
// + block_on against the real R2 endpoint), each ~10-15s for DNS + SigV4 +
// initial connection. 30s wasn't enough on cold start; observed real failures
// at 26s. Per-handler lazy init would cut this back, but the bump is the
// surgical worker-only fix.
const STARTUP_TIMEOUT_MS = 90_000;

/**
 * A `"starting"` status older than this is treated as a DEAD start (the
 * initiating isolate was evicted, or the start was interrupted mid-flight) and
 * self-healed by restarting. WITHOUT this, a stuck persisted `"starting"` (loaded
 * from storage on every isolate) traps every request in `waitForContainerReady`
 * forever — the 2026-06-23 `_system` wedge (F-020). Must be > `STARTUP_TIMEOUT_MS`
 * so a legitimately in-flight cold start is never pre-empted.
 */
const STALE_STARTING_MS = STARTUP_TIMEOUT_MS + 30_000;
const STAGING_D1_PROBE_CRON = STAGING_D1_PROBE_WINDOW.cron;
const STAGING_D1_PROBE_EXPIRES_AT_MS = STAGING_D1_PROBE_WINDOW.expires_ms;
export const STAGING_D1_HTTP_OPERATION_KEY = "staging-d1-http-operation-v1";
export const STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY = "staging-d1-http-completion-deadline-v1";
const STAGING_D1_PROBE_RECEIPT_KEY = "staging-d1-binding-probe-receipt-v1";
const STAGING_D1_PROBE_STATE_KEY = "staging-d1-binding-probe-state-v1";
const STAGING_D1_PROBE_ADMISSION_KEY = "staging-d1-binding-probe-admission-v1";
const STAGING_D1_PROBE_STARTS_AT_MS = STAGING_D1_PROBE_WINDOW.starts_ms;
const STAGING_D1_PROBE_LAST_ENTRY_MS = STAGING_D1_PROBE_WINDOW.last_entry_ms;

function validStagingD1ProbeTime(scheduledTime: number, now: number): boolean {
  return Number.isSafeInteger(scheduledTime) &&
    scheduledTime % 60_000 === 0 &&
    scheduledTime >= STAGING_D1_PROBE_STARTS_AT_MS &&
    scheduledTime <= STAGING_D1_PROBE_LAST_ENTRY_MS &&
    scheduledTime < STAGING_D1_PROBE_EXPIRES_AT_MS &&
    now >= STAGING_D1_PROBE_STARTS_AT_MS &&
    now < STAGING_D1_PROBE_EXPIRES_AT_MS;
}

function validStagingD1ProbeReceiptRead(scheduledTime: number, now: number): boolean {
  return Number.isSafeInteger(scheduledTime) && scheduledTime % 60_000 === 0 &&
    scheduledTime >= STAGING_D1_PROBE_STARTS_AT_MS && scheduledTime < STAGING_D1_PROBE_EXPIRES_AT_MS &&
    now >= STAGING_D1_PROBE_STARTS_AT_MS && now < STAGING_D1_PROBE_EXPIRES_AT_MS;
}

function isStagingD1RuntimeProbeReceipt(
  value: unknown,
  release: string,
  scheduledTime: number,
): value is StagingD1RuntimeProbeReceipt {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const receipt = value as Record<string, unknown>;
  return receipt["probe_nonce"] === STAGING_D1_PROBE_WINDOW.nonce &&
    validStagingD1ProbeTime(scheduledTime, scheduledTime) &&
    receipt["contract"] === "corelink-staging-d1-binding-runtime-v1" &&
    receipt["outcome"] === "pass" &&
    receipt["worker_release"] === release &&
    receipt["scheduled_time_ms"] === scheduledTime &&
    receipt["parameterized_select"] === true &&
    receipt["failed_batch_observed"] === true &&
    receipt["rollback_absence_verified"] === true &&
    receipt["probe_table_dropped"] === true &&
    receipt["d1_binding_intercepted"] === true &&
    receipt["authorization_absent"] === true &&
    receipt["cf_api_token_absent"] === true;
}

// ──────────────────────────────────────────────────────────────────────────────
// Hashing helpers (INV-NO-PII-IN-LOGS)
// ──────────────────────────────────────────────────────────────────────────────

export class CoreLinkServer extends CloudflareDurableObject<Env> implements DurableObject {
  private readonly state: CoreLinkDurableObjectState;
  private readonly storage: DurableObjectStorage;
  private readonly now: () => number;
  private lifecycleState: LifecycleState = {
    containerStatus: "stopped",
    lastHealthCheckMs: 0,
    coldStartCount: 0,
    tenantId: null,
  };
  private httpClaim: StagingD1HttpStatus | undefined;
  private httpExecuting = false;
  private httpLifetime: StagingD1HttpLifetime | undefined;
  private httpLife: StagingD1HttpLifecycle | undefined;
  private httpDestroyPending = false;
  private probeRetired = false;
  private probeActiveCalls = 0;
  private retirementActive = false;
  private healthFailures = 0;
  private doIdHash = "";

  constructor(state: CoreLinkDurableObjectState, env: Env, now: () => number = Date.now) {
    super(state, env);
    this.state = state;
    this.storage = state.storage;
    this.now = now;

    // Restore persisted lifecycle state on DO wakeup
    void this.state.blockConcurrencyWhile(async () => {
      this.probeRetired = (await this.storage.get(OLD_PROBE_RETIRED_KEY)) !== undefined ||
        (await this.storage.get(V5_PROBE_RETIRED_KEY)) !== undefined ||
        (await this.storage.get(V8_PROBE_RETIRED_KEY)) !== undefined ||
        (await this.storage.get(V9_PROBE_RETIRED_KEY)) !== undefined;
      const httpClaim = await this.storage.get<StagingD1HttpStatus>(STAGING_D1_HTTP_OPERATION_KEY);
      if (httpClaim !== undefined) {
        this.httpClaim = httpClaim.status === "complete" ? httpClaim : this.httpStatus("unknown");
        if (httpClaim.status !== "complete") await this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim);
      }
      const lifetime = await this.storage.get<unknown>(STAGING_D1_HTTP_LIFETIME_KEY);
      if (isStagingD1HttpLifetime(lifetime, this.env.SENTRY_RELEASE ?? "")) this.httpLifetime = lifetime;
      const stored = await this.storage.get<LifecycleState>("lifecycle");
      if (stored !== undefined) {
        this.lifecycleState = stored;
      }
      this.doIdHash = await hashForLog(state.id.toString());
    });
  }

  /**
   * One-shot RPC reachable only through the Worker's scheduled handler. The
   * corresponding HTTP path is explicitly rejected in `fetch` below.
   */
  private isOldProbeObject(): boolean {
    return typeof this.env.CORELINK_SERVER?.idFromName === "function" &&
      (this.state.id.equals(this.env.CORELINK_SERVER.idFromName(OLD_PROBE_NAME)) ||
       this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V5_PROBE_NAME)) ||
       this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V8_PROBE_NAME)) ||
       this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V9_PROBE_NAME)));
  }

  private async withProbeActivity<T>(operation: () => Promise<T>): Promise<T> {
    if (this.probeRetired) throw new Error("old probe is retired");
    this.probeActiveCalls++;
    try { return await operation(); } finally { this.probeActiveCalls--; }
  }

  private httpStatus(status: StagingD1HttpStatus["status"]): StagingD1HttpStatus {
    return { contract: STAGING_D1_HTTP_CONTRACT, carrier: "authenticated_http",
      worker_release: this.env.SENTRY_RELEASE ?? "", probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
      status, rollback_safe: false, native_receipt: null, v8_cleanup: null, v9_cleanup: null };
  }

  private assertHttpProbeTarget(): void {
    const release = this.env.SENTRY_RELEASE ?? "";
    if (this.isOldProbeObject() || this.probeRetired || this.env.ENVIRONMENT !== "staging" ||
        !/^[0-9a-f]{40}$/.test(release) ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        this.env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com" ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`))) {
      throw new Error("HTTP proof target rejected");
    }
  }

  /** Status reads never start, stop, clean, admit or replay an operation. */
  async readStagingD1HttpProof(): Promise<StagingD1HttpStatus> {
    this.assertHttpProbeTarget();
    const stored = this.httpClaim ?? await this.storage.get<StagingD1HttpStatus>(STAGING_D1_HTTP_OPERATION_KEY);
    if (stored === undefined) return this.httpStatus("not_started");
    if (stored.status !== "complete") return this.httpStatus(stored.status === "running" && this.httpExecuting ? "running" : "unknown");
    const deadline = await this.storage.get<unknown>(STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY);
    const alarm = await this.storage.getAlarm();
    if (!isStagingD1HttpStatus(stored, this.env.SENTRY_RELEASE!, this.now()) ||
        !this.httpCompletionDeadlineValid(deadline, stored) || this.httpExecuting ||
        this.probeActiveCalls !== 0 || this.state.container?.running !== false || alarm !== null) return this.httpStatus("unknown");
    return stored;
  }

  private httpCompletionDeadlineValid(value: unknown, proof: StagingD1HttpStatus): boolean {
    if (typeof value !== "object" || value === null || Array.isArray(value) || Reflect.ownKeys(value).length !== 2) return false;
    const v = value as Record<string, unknown>;
    const start = v["operation_started_ms"], end = v["completion_deadline_ms"];
    const native = proof.native_receipt as { scheduled_time_ms?: unknown } | null;
    return typeof start === "number" && typeof end === "number" && Number.isSafeInteger(start) && Number.isSafeInteger(end) &&
      start >= STAGING_D1_PROBE_WINDOW.starts_ms && start <= STAGING_D1_PROBE_LAST_ENTRY_MS &&
      typeof native?.scheduled_time_ms === "number" && native.scheduled_time_ms <= start &&
      end > start && end <= start + STAGING_D1_HTTP_EXECUTE_MS + STAGING_D1_HTTP_CLEANUP_MS &&
      end <= STAGING_D1_PROBE_EXPIRES_AT_MS && this.now() >= start && this.now() < end;
  }

  /** Single durable HTTP owner. A claim survives timeout, failure and eviction. */
  async executeStagingD1HttpProof(scheduledTime: number): Promise<StagingD1HttpStatus> {
    this.assertHttpProbeTarget();
    if (!validStagingD1ProbeTime(scheduledTime, this.now()) || scheduledTime % 120_000 !== 0 ||
        scheduledTime > this.now() || this.now() > STAGING_D1_PROBE_LAST_ENTRY_MS ||
        this.httpExecuting || this.httpClaim !== undefined || this.probeActiveCalls !== 0) {
      throw new Error("HTTP proof execution rejected");
    }
    const life = new StagingD1HttpLifecycle(this.now, STAGING_D1_PROBE_EXPIRES_AT_MS);
    const lifetime = createHttpLifetime(this.env.SENTRY_RELEASE!, life.startedAt);
    this.httpLife = life;
    this.httpExecuting = true;
    this.httpClaim = this.httpStatus("running");
    try {
      const claimed = await life.run(() => this.storage.transaction(async txn => {
        if (await txn.get(STAGING_D1_HTTP_LIFETIME_KEY) !== undefined ||
            await txn.get(STAGING_D1_HTTP_OPERATION_KEY) !== undefined ||
            await txn.get(STAGING_D1_PROBE_ADMISSION_KEY) !== undefined ||
            await txn.get(STAGING_D1_PROBE_STATE_KEY) !== undefined ||
            await txn.get(STAGING_D1_PROBE_RECEIPT_KEY) !== undefined) return false;
        life.check();
        await txn.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpStatus("running"));
        life.check();
        await txn.put(STAGING_D1_HTTP_LIFETIME_KEY, lifetime);
        life.check();
        return true;
      }));
      if (!claimed) {
        this.httpClaim = await this.storage.get<StagingD1HttpStatus>(STAGING_D1_HTTP_OPERATION_KEY) ?? this.httpStatus("unknown");
        throw new Error("HTTP proof already claimed");
      }
      this.httpLifetime = lifetime;
      // No cleanup, admission or Container start before durable arming readback.
      await life.run(() => this.storage.setAlarm(lifetime.kill_at_ms));
      if (await life.run(() => this.storage.getAlarm()) !== lifetime.kill_at_ms) throw new Error("HTTP lifetime alarm unavailable");
      const armed = await life.run(() => this.storage.get<unknown>(STAGING_D1_HTTP_LIFETIME_KEY));
      if (!isStagingD1HttpLifetime(armed, this.env.SENTRY_RELEASE!) || armed.state !== "armed" ||
          armed.operation_started_ms !== life.startedAt) throw new Error("HTTP lifetime unavailable");
    } catch {
      this.httpExecuting = false;
      // Even a timed-out claim write can finish later. The next persisted
      // write fences it UNKNOWN; there is never a provider call in this arm.
      if (this.httpClaim !== undefined) {
        this.httpClaim = this.httpStatus("unknown");
        await life.record(() => this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim!));
      }
      throw new Error("HTTP proof claim rejected");
    }

    let nativeEntered = false;
    try {
      const proof = await runStagingD1HttpSequence(this.env, scheduledTime, life, {
        admit: () => this.admitStagingD1RuntimeProbeOwned(scheduledTime, life),
        run: admission => { nativeEntered = true; return this.runStagingD1RuntimeProbeActive(admission, life); },
      });
      // Cleanup itself may time out. Its durable preimage is already UNKNOWN.
      this.httpClaim = this.httpStatus("unknown");
      await life.record(() => this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim!));
      await life.quiesce();
      await this.stopHttpProbeContainer(life);
      const complete: StagingD1HttpStatus = { ...this.httpStatus("complete"), rollback_safe: true,
        native_receipt: proof.native, v8_cleanup: proof.v8, v9_cleanup: proof.v9 };
      if (!life.settled || !isStagingD1HttpStatus(complete, this.env.SENTRY_RELEASE!, this.now())) {
        throw new Error("HTTP proof receipts rejected");
      }
      // Keep the original native keys and their meanings. Only successful
      // stopped/alarm-null proof can complete either receipt.
      const { v4_probe_catalog_absent: _v4, old_probe_release: _oldRelease, old_probe_retired: _oldRetired,
        old_probe_tables_absent: _oldTables, v5_probe_release: _v5Release, v5_probe_retired: _v5Retired,
        v5_probe_tables_absent: _v5Tables, v5_prior_execution: _v5Prior, ...native } = proof.native;
      await life.cleanup(() => this.storage.put(STAGING_D1_PROBE_RECEIPT_KEY, native));
      await life.cleanup(() => this.storage.put(STAGING_D1_PROBE_STATE_KEY, "complete"));
      await life.cleanup(() => this.storage.transaction(async txn => {
        life.checkCleanup();
        await txn.put(STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY,
          { operation_started_ms: life.startedAt, completion_deadline_ms: life.completionDeadline });
        life.checkCleanup();
        await txn.put(STAGING_D1_HTTP_OPERATION_KEY, complete);
        // A late storage completion rolls back instead of resurrecting COMPLETE.
        life.checkCleanup();
      }));
      if (!life.settled) throw new Error("HTTP proof operation pending");
      this.httpClaim = complete;
      return complete;
    } catch {
      this.httpClaim = this.httpStatus("unknown");
      // Record UNKNOWN before waiting for uncancellable calls. Late settlement
      // can permit cleanup, never admission, native replay, or COMPLETE.
      try { await life.record(() => this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim!)); }
      catch { throw new Error("HTTP proof status unavailable"); }
      try {
        await life.quiesce();
        // A failed remote cleanup RPC may hide an unresolved provider call.
        // It never authorizes a later cleanup or fresh admission.
        if (nativeEntered) await this.stopHttpProbeContainer(life);
      } catch { /* UNKNOWN remains durable; elapsed time is not quiescence. */ }
      return this.httpClaim;
    } finally { this.httpExecuting = false; }
  }

  private async stopHttpProbeContainer(life: StagingD1HttpLifecycle): Promise<void> {
    const container = this.state.container;
    if (container === undefined) throw new Error("HTTP proof Container unavailable");
    if (container.running) await life.cleanup(() => this.destroyHttpContainer());
    if (container.running !== false) throw new Error("HTTP proof Container stop unproven");
    await life.cleanup(() => this.storage.deleteAlarm());
    if (await life.cleanup(() => this.storage.getAlarm()) !== null) throw new Error("HTTP proof alarm unproven");
    await life.cleanup(() => this.transitionStatus("stopped", "staging-d1-http-proof"));
  }

  private async destroyHttpContainer(): Promise<void> {
    if (this.httpDestroyPending || this.state.container === undefined) throw new Error("HTTP Container stop pending");
    this.httpDestroyPending = true;
    try { await this.state.container.destroy(); } finally { this.httpDestroyPending = false; }
  }

  /** Absolute cost-stop only. It cannot admit, submit SQL, clean old objects or prove rollback safe. */
  private async expireHttpProbeContainer(): Promise<void> {
    this.assertHttpProbeTarget();
    const stored = await this.storage.get<unknown>(STAGING_D1_HTTP_LIFETIME_KEY);
    if (!isStagingD1HttpLifetime(stored, this.env.SENTRY_RELEASE!)) {
      this.httpLife?.halt();
      this.httpClaim = this.httpStatus("unknown");
      await this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim);
      return;
    }
    this.httpLifetime = stored;
    if (this.now() < stored.kill_at_ms) {
      await this.storage.setAlarm(stored.kill_at_ms);
      return;
    }
    this.httpLife?.halt();
    const container = this.state.container;
    // A completed proof already stopped the Container and deleted its alarm.
    if (this.httpClaim?.status === "complete" && !this.httpExecuting && container?.running === false) return;
    this.httpClaim = this.httpStatus("unknown");
    await this.storage.put(STAGING_D1_HTTP_OPERATION_KEY, this.httpClaim);
    if (stored.state !== "armed") return; // At-least-once alarm delivery cannot repeat the stop request.
    const attempted: StagingD1HttpLifetime = { ...stored, state: "stop_attempted", stop_attempted_at_ms: this.now() };
    const owned = await this.storage.transaction(async txn => {
      const current = await txn.get<unknown>(STAGING_D1_HTTP_LIFETIME_KEY);
      if (!isStagingD1HttpLifetime(current, this.env.SENTRY_RELEASE!) || current.state !== "armed" ||
          current.operation_started_ms !== stored.operation_started_ms) return false;
      await txn.put(STAGING_D1_HTTP_LIFETIME_KEY, attempted);
      return true;
    });
    if (!owned) return;
    this.httpLifetime = attempted;
    // Persist-before-signal deliberately leaves an interrupted attempt unproven.
    // The independent PID1 deadline still applies if this isolate disappears.
    if (container?.running && !this.httpDestroyPending) {
      try { container.signal(9); } catch { /* A failed stop request is not stop proof. */ }
    }
    const stopped = container?.running === false;
    this.httpLifetime = { ...attempted, state: stopped ? "stopped" : "unproven", stopped_at_ms: stopped ? this.now() : null };
    await this.storage.put(STAGING_D1_HTTP_LIFETIME_KEY, this.httpLifetime);
  }

  /** Reuse native startup wiring with a deadline check at every async seam. */
  private async startHttpProbeContainer(life: StagingD1HttpLifecycle): Promise<{ ok: true } | { ok: false; reason: string }> {
    const container = this.state.container;
    if (container === undefined) throw new Error("HTTP proof Container unavailable");
    const lifetime = this.httpLifetime;
    if (!isStagingD1HttpLifetime(lifetime, this.env.SENTRY_RELEASE!) || lifetime.state !== "armed" ||
        lifetime.operation_started_ms !== life.startedAt || container.running) throw new Error("HTTP lifetime start rejected");
    const deadline = httpDeadlineContext(lifetime);
    const guarded = new Proxy(container, { get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (key === "start") return (...args: Parameters<Container["start"]>) => {
        life.check();
        if (target.running) throw new Error("HTTP lifetime prior Container rejected");
        try { target.start(...args); } catch { throw new Error("HTTP proof Container start failed"); }
        life.check();
      };
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const health = async (): Promise<boolean> => {
      const deadline = Math.min(this.now() + STARTUP_TIMEOUT_MS, STAGING_D1_PROBE_EXPIRES_AT_MS);
      while (this.now() < deadline) {
        life.check();
        const response = await life.run(() => container.getTcpPort(CONTAINER_PORT).fetch(
          new Request(`http://localhost:${CONTAINER_PORT}/_health`, { method: "GET" })).catch(() => null));
        const ok = response?.status === 200;
        if (response?.body) await life.run(() => response.body!.cancel());
        if (ok) return true;
        await life.run(() => new Promise<void>(resolve => setTimeout(resolve, 500)));
      }
      return false;
    };
    return life.run(() => runStartContainer({
      container: guarded, env: this.env, doIdHash: this.doIdHash,
      getLifecycleState: () => { life.check(); return this.lifecycleState; },
      setLifecycleState: state => { life.check(); this.lifecycleState = state; },
      transitionStatus: (status, id) => life.run(() => this.transitionStatus(status, id)),
      updateLifecycleState: state => life.run(() => this.updateLifecycleState(state)),
      waitForContainerReady: async () => await health() ? { ok: true as const } : { ok: false as const, reason: "http_proof_health" },
      armInactivityTimeout: c => life.run(() => c.setInactivityTimeout(IDLE_TIMEOUT_MS)),
      waitForContainerHealth: health,
      destroyContainer: async () => {
        await life.run(() => this.destroyHttpContainer());
        await life.run(() => this.transitionStatus("stopped", "staging-d1-http-proof"));
      },
      installStagingD1BindingProxy: () => life.run(() => this.installStagingD1BindingProxy(deadline)),
      setAlarm: () => life.run(() => this.storage.setAlarm(lifetime.kill_at_ms)),
      suppressLifecycleTelemetry: true,
      httpDeadline: deadline,
    }, "staging-d1-http-proof"));
  }

  async admitStagingD1RuntimeProbe(scheduledTime: number): Promise<StagingD1RuntimeProbeAdmissionResult> {
    if (["issue-1700-recovery-20261001-v10", "issue-1700-recovery-20261001-v11", "issue-1700-recovery-20261002-v12", "issue-1700-recovery-20261002-v13", "issue-1700-recovery-20261002-v14"].includes(STAGING_D1_PROBE_WINDOW.nonce)) {
      throw new Error("HTTP admission required");
    }
    return this.admitStagingD1RuntimeProbeOwned(scheduledTime);
  }

  private async admitStagingD1RuntimeProbeOwned(scheduledTime: number, life?: StagingD1HttpLifecycle): Promise<StagingD1RuntimeProbeAdmissionResult> {
    const release = this.env.SENTRY_RELEASE ?? "";
    if (this.isOldProbeObject() || this.env.ENVIRONMENT !== "staging" ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        this.env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com" ||
        !/^[0-9a-f]{40}$/.test(release) || !validStagingD1ProbeTime(scheduledTime, this.now()) ||
        this.now() > STAGING_D1_PROBE_LAST_ENTRY_MS ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`))) {
      throw new Error("staging D1 runtime probe admission guard rejected");
    }
    const admission: StagingD1RuntimeProbeAdmission = {
      contract: "corelink-staging-d1-probe-admission-v1",
      probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
      worker_release: release,
      scheduled_time_ms: scheduledTime,
    };
    return this.storage.transaction(async (txn) => {
      const claim = await txn.get(STAGING_D1_HTTP_OPERATION_KEY);
      if ((claim !== undefined && life === undefined) || (life !== undefined && claim === undefined)) throw new Error("HTTP admission ownership rejected");
      life?.check();
      const receipt = await txn.get<StagingD1RuntimeProbeReceipt>(STAGING_D1_PROBE_RECEIPT_KEY);
      if (receipt !== undefined) {
        if (!isStagingD1RuntimeProbeReceipt(receipt, release, receipt.scheduled_time_ms) ||
            receipt.scheduled_time_ms > scheduledTime) throw new Error("staging runtime stored receipt rejected");
        return { status: "complete", receipt } as const;
      }
      if (await txn.get<StagingD1RuntimeProbeAdmission>(STAGING_D1_PROBE_ADMISSION_KEY) !== undefined) {
        return { status: "already_admitted" } as const;
      }
      if (await txn.get<string>(STAGING_D1_PROBE_STATE_KEY) !== undefined) {
        throw new Error("staging D1 runtime probe is already claimed");
      }
      life?.check();
      await txn.put(STAGING_D1_PROBE_ADMISSION_KEY, admission);
      life?.check();
      return { status: "admitted", admission } as const;
    });
  }

  async retireStagingD1RuntimeProbe(scheduledTime: number, deadlineMs?: number): Promise<OldProbeRetirement> {
    const isV5 = this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V5_PROBE_NAME));
    const expectedName = isV5 ? V5_PROBE_NAME : OLD_PROBE_NAME;
    const expectedRelease = isV5 ? V5_PROBE_RELEASE : OLD_PROBE_RELEASE;
    const retiredKey = isV5 ? V5_PROBE_RETIRED_KEY : OLD_PROBE_RETIRED_KEY;
    if (this.env.ENVIRONMENT !== "staging" ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        !/^[0-9a-f]{40}$/.test(this.env.SENTRY_RELEASE ?? "") || this.env.SENTRY_RELEASE === expectedRelease ||
        !validStagingD1ProbeTime(scheduledTime, this.now()) ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(expectedName))) {
      throw new Error("old probe retirement guard rejected");
    }
    if (deadlineMs !== undefined && (!Number.isSafeInteger(deadlineMs) || deadlineMs <= this.now() ||
        deadlineMs > this.now() + 600_000 || deadlineMs > STAGING_D1_PROBE_EXPIRES_AT_MS)) throw new Error("old probe deadline rejected");
    const life = deadlineMs === undefined ? undefined : new StagingD1HttpLifecycle(this.now, STAGING_D1_PROBE_EXPIRES_AT_MS, deadlineMs);
    const bounded = <T>(operation: () => Promise<T>): Promise<T> => life ? life.run(operation) : operation();
    // No await before these fences. Already-running fetch/alarm/probe work must
    // finish before retirement; arriving work observes probeRetired immediately.
    if (this.probeActiveCalls !== 0 || this.retirementActive) throw new Error("old probe retirement busy");
    this.retirementActive = true;
    this.probeRetired = true;
    try {
      // Preserve the original claim and receipt, including unknown/failed state.
      await bounded(() => this.storage.put(retiredKey, { old_release: expectedRelease }));
      const container = this.state.container;
      if (container === undefined) throw new Error("old probe Container binding unavailable");
      if (container.running) await bounded(() => container.destroy());
      if (container.running !== false) throw new Error("old probe Container stop unproven");
      await bounded(() => this.storage.deleteAlarm());
      if (await bounded(() => this.storage.getAlarm()) !== null) throw new Error("old probe alarm cleanup unproven");
      await bounded(() => this.transitionStatus("stopped", "staging-d1-probe-retirement"));
      if (isV5) await cleanV5ProbeTables(this.env.CONFIG_DB, this.now, bounded);
      else await cleanOldProbeTables(this.env.CONFIG_DB, this.now, bounded);
      return isV5
        ? { v5_probe_release: V5_PROBE_RELEASE, v5_probe_retired: true, v5_probe_tables_absent: true }
        : { old_probe_release: OLD_PROBE_RELEASE, old_probe_retired: true, old_probe_tables_absent: true };
    } finally { this.retirementActive = false; }
  }

  /** Exact failed v8 object only. Retirement never reopens its old admission. */
  async cleanupV8StagingD1RuntimeProbe(scheduledTime: number, expectedRelease: string): Promise<V8CleanupReceipt> {
    const release = this.env.SENTRY_RELEASE ?? "";
    if (this.env.ENVIRONMENT !== "staging" ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        this.env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com" ||
        !/^[0-9a-f]{40}$/.test(release) || release === V8_PROBE_RELEASE || expectedRelease !== release ||
        !Number.isSafeInteger(scheduledTime) || scheduledTime % 120_000 !== 0 ||
        scheduledTime < cleanupWindow.starts_ms || scheduledTime >= cleanupWindow.expires_ms ||
        this.now() < scheduledTime || this.now() >= cleanupWindow.expires_ms ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V8_PROBE_NAME))) {
      throw new Error("v8 cleanup guard rejected");
    }
    // Fence synchronously. A retirement marker is only an entry fence, never
    // proof that an earlier execution, Container, alarm or table is gone.
    if (this.probeActiveCalls !== 0 || this.retirementActive) throw new Error("v8 cleanup busy");
    this.retirementActive = true;
    this.probeRetired = true;
    const deadline = Math.min(this.now() + 60_000, cleanupWindow.expires_ms);
    const bounded = <T>(operation: () => Promise<T>) => withinV8CleanupDeadline(operation, this.now, deadline);
    try {
      const previousFence = await bounded(() => this.storage.get<{ old_release: string; destroy_attempted: boolean }>(V8_PROBE_RETIRED_KEY));
      if (previousFence !== undefined && (previousFence.old_release !== V8_PROBE_RELEASE ||
          typeof previousFence.destroy_attempted !== "boolean")) throw new Error("v8 cleanup fence rejected");
      if (previousFence === undefined) await bounded(() => this.storage.put(V8_PROBE_RETIRED_KEY,
        { old_release: V8_PROBE_RELEASE, destroy_attempted: false }));
      const container = this.state.container;
      if (container === undefined) throw new Error("v8 cleanup Container unavailable");
      if (container.running) {
        if (previousFence?.destroy_attempted) throw new Error("v8 cleanup prior stop unproven");
        await bounded(() => this.storage.put(V8_PROBE_RETIRED_KEY,
          { old_release: V8_PROBE_RELEASE, destroy_attempted: true }));
        await bounded(() => container.destroy());
      }
      if (container.running !== false) throw new Error("v8 cleanup Container stop unproven");
      await bounded(() => this.storage.deleteAlarm());
      if (await bounded(() => this.storage.getAlarm()) !== null) throw new Error("v8 cleanup alarm unproven");
      const admission = await bounded(() => this.storage.get(STAGING_D1_PROBE_ADMISSION_KEY));
      await cleanV8ProbeTables(this.env.CONFIG_DB, admission, this.now, deadline);
      const receipt: V8CleanupReceipt = {
        contract: "corelink-staging-v8-cleanup-v1", old_release: V8_PROBE_RELEASE,
        old_nonce: V8_PROBE_NONCE, worker_release: release, prior_execution: "unknown",
        prior_admission_present: admission !== undefined, container_stopped: true,
        alarm_absent: true, tables_absent: true, completed_at_ms: this.now(),
      };
      if (!isV8CleanupReceipt(receipt, release, this.now())) throw new Error("v8 cleanup receipt rejected");
      // Every invocation revalidates live state and inventory, including when
      // a previous completion exists. Original admission/state/receipt stay intact.
      await bounded(() => this.storage.put(V8_CLEANUP_RECEIPT_KEY, receipt));
      return receipt;
    } finally { this.retirementActive = false; }
  }

  /** Exact failed v9 object only. Retirement never reopens its old admission. */
  async cleanupV9StagingD1RuntimeProbe(scheduledTime: number, expectedRelease: string): Promise<V9CleanupReceipt> {
    const release = this.env.SENTRY_RELEASE ?? "";
    if (this.env.ENVIRONMENT !== "staging" ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        this.env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com" ||
        !/^[0-9a-f]{40}$/.test(release) || release === V9_PROBE_RELEASE || expectedRelease !== release ||
        !Number.isSafeInteger(scheduledTime) || scheduledTime % 120_000 !== 0 ||
        scheduledTime < cleanupWindow.starts_ms || scheduledTime >= cleanupWindow.expires_ms ||
        this.now() < scheduledTime || this.now() >= cleanupWindow.expires_ms ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(V9_PROBE_NAME))) {
      throw new Error("v9 cleanup guard rejected");
    }
    // Fence synchronously. A retirement marker is only an entry fence, never
    // proof that an earlier execution, Container, alarm or table is gone.
    if (this.probeActiveCalls !== 0 || this.retirementActive) throw new Error("v9 cleanup busy");
    this.retirementActive = true;
    this.probeRetired = true;
    const deadline = Math.min(this.now() + 60_000, cleanupWindow.expires_ms);
    const bounded = <T>(operation: () => Promise<T>) => withinV9CleanupDeadline(operation, this.now, deadline);
    try {
      const previousFence = await bounded(() => this.storage.get<{ old_release: string; destroy_attempted: boolean }>(V9_PROBE_RETIRED_KEY));
      if (previousFence !== undefined && (previousFence.old_release !== V9_PROBE_RELEASE ||
          typeof previousFence.destroy_attempted !== "boolean")) throw new Error("v9 cleanup fence rejected");
      if (previousFence === undefined) await bounded(() => this.storage.put(V9_PROBE_RETIRED_KEY,
        { old_release: V9_PROBE_RELEASE, destroy_attempted: false }));
      const container = this.state.container;
      if (container === undefined) throw new Error("v9 cleanup Container unavailable");
      if (container.running) {
        if (previousFence?.destroy_attempted) throw new Error("v9 cleanup prior stop unproven");
        await bounded(() => this.storage.put(V9_PROBE_RETIRED_KEY,
          { old_release: V9_PROBE_RELEASE, destroy_attempted: true }));
        await bounded(() => container.destroy());
      }
      if (container.running !== false) throw new Error("v9 cleanup Container stop unproven");
      await bounded(() => this.storage.deleteAlarm());
      if (await bounded(() => this.storage.getAlarm()) !== null) throw new Error("v9 cleanup alarm unproven");
      const admission = await bounded(() => this.storage.get(STAGING_D1_PROBE_ADMISSION_KEY));
      await cleanV9ProbeTables(this.env.CONFIG_DB, admission, this.now, deadline);
      const receipt: V9CleanupReceipt = {
        contract: "corelink-staging-v9-cleanup-v1", old_release: V9_PROBE_RELEASE,
        old_nonce: V9_PROBE_NONCE, worker_release: release, prior_execution: "unknown",
        prior_admission_present: admission !== undefined, container_stopped: true,
        alarm_absent: true, tables_absent: true, completed_at_ms: this.now(),
      };
      if (!isV9CleanupReceipt(receipt, release, this.now())) throw new Error("v9 cleanup receipt rejected");
      // Every invocation revalidates live state and inventory, including when
      // a previous completion exists. Original admission/state/receipt stay intact.
      await bounded(() => this.storage.put(V9_CLEANUP_RECEIPT_KEY, receipt));
      return receipt;
    } finally { this.retirementActive = false; }
  }

  async runStagingD1RuntimeProbe(admission: StagingD1RuntimeProbeAdmission): Promise<StagingD1RuntimeProbeReceipt> {
    if (this.isOldProbeObject()) throw new Error("old probe cannot be replayed");
    if (this.httpClaim !== undefined || await this.storage.get(STAGING_D1_HTTP_OPERATION_KEY) !== undefined || this.httpClaim !== undefined) throw new Error("HTTP probe cannot be replayed");
    try {
      return await this.withProbeActivity(() => this.runStagingD1RuntimeProbeActive(admission));
    } catch (error) {
      recordStagingD1ProbePhase(this.env, "native_error");
      throw error;
    }
  }

  async readStagingD1RuntimeProbeReceipt(scheduledTime: number): Promise<StagingD1RuntimeProbeReceipt | undefined> {
    const release = this.env.SENTRY_RELEASE ?? "";
    if (this.isOldProbeObject() || this.env.ENVIRONMENT !== "staging" ||
        this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
        this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
        !/^[0-9a-f]{40}$/.test(release) ||
        !this.state.id.equals(this.env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`)) ||
        !validStagingD1ProbeReceiptRead(scheduledTime, this.now())) {
      throw new Error("staging runtime receipt read guard rejected");
    }
    const receipt = await this.storage.get<StagingD1RuntimeProbeReceipt>(STAGING_D1_PROBE_RECEIPT_KEY);
    if (receipt === undefined) return undefined;
    if (!isStagingD1RuntimeProbeReceipt(receipt, release, receipt.scheduled_time_ms) ||
        receipt.scheduled_time_ms > scheduledTime) throw new Error("staging runtime stored receipt rejected");
    return receipt;
  }

  private async runStagingD1RuntimeProbeActive(admission: StagingD1RuntimeProbeAdmission, life?: StagingD1HttpLifecycle): Promise<StagingD1RuntimeProbeReceipt> {
    const bounded = <T>(operation: () => Promise<T>): Promise<T> => life ? life.run(operation) : operation();
    life?.check();
    const release = this.env.SENTRY_RELEASE ?? "";
    const scheduledTime = admission?.scheduled_time_ms;
    if (
      admission?.contract !== "corelink-staging-d1-probe-admission-v1" ||
      admission.probe_nonce !== STAGING_D1_PROBE_WINDOW.nonce ||
      admission.worker_release !== release ||
      !Number.isSafeInteger(scheduledTime) ||
      this.env.ENVIRONMENT !== "staging" ||
      !/^[0-9a-f]{40}$/.test(release) ||
      this.env.CLOUDFLARE_ACCOUNT_ID !== "6a1fc1c626fc2628823e60b9db01f5cd" ||
      this.env.D1_DATABASE_ID !== "d72a6b39-6a48-4338-bfda-1111dda98604" ||
      this.env.R2_S3_ENDPOINT !== "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com" ||
      !validStagingD1ProbeTime(scheduledTime, this.now())
    ) {
      throw new Error("staging D1 runtime probe guard rejected");
    }

    const previous = await bounded(() => this.storage.get<StagingD1RuntimeProbeReceipt>(STAGING_D1_PROBE_RECEIPT_KEY));
    if (previous !== undefined) {
      if (!isStagingD1RuntimeProbeReceipt(previous, release, previous.scheduled_time_ms) ||
          previous.scheduled_time_ms > scheduledTime) {
        throw new Error("staging D1 runtime probe stored receipt rejected");
      }
      return previous;
    }
    if (!Number.isSafeInteger(this.now()) || this.now() >= STAGING_D1_PROBE_EXPIRES_AT_MS) {
      throw new Error("staging D1 runtime probe completion window expired");
    }
    recordStagingD1ProbePhase(this.env, "native_start");
    const claimed = await bounded(() => this.storage.transaction(async (txn) => {
      const storedAdmission = await txn.get<StagingD1RuntimeProbeAdmission>(STAGING_D1_PROBE_ADMISSION_KEY);
      if (storedAdmission?.contract !== admission.contract || storedAdmission.probe_nonce !== admission.probe_nonce ||
          storedAdmission.worker_release !== admission.worker_release ||
          storedAdmission.scheduled_time_ms !== admission.scheduled_time_ms) {
        throw new Error("staging D1 runtime probe admission receipt rejected");
      }
      if (await txn.get<string>(STAGING_D1_PROBE_STATE_KEY) !== undefined) return false;
      life?.check();
      await txn.put(STAGING_D1_PROBE_STATE_KEY, "running");
      life?.check();
      return true;
    }));
    if (!claimed) throw new Error("staging D1 runtime probe is already claimed");

    const requestId = "staging-d1-binding-runtime-probe";
    const started = life ? await this.startHttpProbeContainer(life) : await this.ensureContainerRunning(requestId, true);
    if (!started.ok) {
      if (life === undefined) await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "failed");
      throw new Error("staging D1 runtime probe container unavailable");
    }
    const container = this.state.container;
    if (container === undefined || !container.running) {
      if (life === undefined) await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "failed");
      throw new Error("staging D1 runtime probe container not running");
    }

    let body: unknown;
    try {
      const response = await bounded(() => container.getTcpPort(CONTAINER_PORT).fetch(new Request(
        `http://localhost:${CONTAINER_PORT}${STAGING_D1_RUNTIME_PROBE_PATH}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            cron: STAGING_D1_PROBE_CRON,
            probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
            scheduled_time_ms: scheduledTime,
            worker_release: release,
          }),
        },
      )));
      if (!response.ok) throw new Error("staging D1 runtime probe endpoint failed");
      body = await bounded(() => response.json());
    } catch {
      if (life === undefined) await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "failed");
      throw new Error("staging D1 runtime probe request failed");
    } finally {
      if (life === undefined) {
        // The original RPC retains its own cleanup. HTTP cleanup is owned by
        // the coordinator, after all submitted operations have settled.
        try {
          if (container.running) await container.destroy();
          if (container.running) throw new Error("Container remained active");
          await this.storage.deleteAlarm();
          await this.transitionStatus("stopped", requestId);
        } catch {
          await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "unknown");
          throw new Error("staging D1 runtime probe cleanup is unknown");
        }
      }
    }

    if (!isStagingD1RuntimeProbeReceipt(body, release, scheduledTime)) {
      if (life === undefined) await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "failed");
      throw new Error("staging D1 runtime probe receipt rejected");
    }
    if (life !== undefined) { life.check(); return body; }
    await this.storage.put(STAGING_D1_PROBE_RECEIPT_KEY, body);
    await this.storage.put(STAGING_D1_PROBE_STATE_KEY, "complete");
    recordStagingD1ProbePhase(this.env, "native_complete");
    return body;
  }
  private enforcePatIssueRateLimit(requestId: string, tenantId: string | null) {
    return enforcePatIssueRateLimit(
      this.state,
      this.storage,
      this.lifecycleState.tenantId,
      requestId,
      tenantId,
    );
  }
  /**
   * Durable admission gate for the two container routes whose native Rust
   * token-bucket state is process-local in dev/test builds.
   *
   * The DO storage transaction is the authority: a container recycle cannot
   * mint a fresh burst. The state is a bounded fixed window (one counter per
   * route/key), deliberately cheap and conservative at this edge boundary;
   * the native route may still apply its finer-grained policy after admission.
   */
  private async enforceDurableRouteRateLimit(
    request: Request,
    url: URL,
  ): Promise<Response | null> {
    const isSignup = request.method === "POST" && isPilotSignupPath(url.pathname);
    const isAuditAnalytics =
      url.pathname.startsWith("/v1/audit/analytics/") &&
      (request.method === "GET" || request.method === "HEAD");
    if (!isSignup && !isAuditAnalytics) return null;

    const limit = isSignup ? 5 : 10;
    const windowMs = isSignup ? 60 * 60 * 1000 : 60 * 1000;
    const rawKey = isSignup
      ? request.headers.get("x-corelink-client-ip") ?? "_no_ip"
      : request.headers.get("x-corelink-tenant-id") ?? "_anonymous";
    // Never persist a raw IP/tenant identifier in DO storage.
    const keyHash = await hashForLog(rawKey);
    const storageKey = `durable-route-rate:v1:${isSignup ? "signup" : "audit"}:${keyHash}`;
    try {
      const result = await this.state.blockConcurrencyWhile(async () => {
        const now = this.now();
        const current = (await this.storage.get<{ windowStartedMs: number; count: number }>(
          storageKey,
        )) ?? { windowStartedMs: now, count: 0 };
        const windowStartedMs =
          now - current.windowStartedMs >= windowMs ? now : current.windowStartedMs;
        const count = windowStartedMs === current.windowStartedMs ? current.count : 0;
        if (count >= limit) {
          return {
            allowed: false,
            retryAfter: Math.max(1, Math.ceil((windowStartedMs + windowMs - now) / 1000)),
          };
        }
        await this.storage.put(storageKey, { windowStartedMs, count: count + 1 });
        return { allowed: true, retryAfter: 0 };
      });
      if (result.allowed) return null;
      return new Response("rate_limited", {
        status: 429,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "retry-after": String(result.retryAfter),
        },
      });
    } catch (err: unknown) {
      // A rate-limit storage failure must not silently become a bypass.
      console.error(`[${this.doIdHash}] durable route rate-limit unavailable: ${errText(err)}`);
      return new Response("rate_limit_unavailable", { status: 503 });
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // fetch — DO entry point
  // ──────────────────────────────────────────────────────────────────────────

  override async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === STAGING_D1_RUNTIME_PROBE_PATH) {
      return new Response("not_found", { status: 404, headers: { "cache-control": "no-store" } });
    }
    if (this.probeRetired || this.isOldProbeObject()) return new Response("gone", { status: 410 });
    if (this.httpClaim !== undefined) {
      return new Response("gone", { status: 410 });
    }
    return this.withProbeActivity(() => this.fetchActive(request));
  }

  private async fetchActive(request: Request): Promise<Response> {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    const url = new URL(request.url);

    // The runtime probe is callable only through the one-shot scheduled RPC
    // above; never let a normal/public DO fetch reach its native endpoint.
    if (url.pathname === STAGING_D1_RUNTIME_PROBE_PATH) {
      return new Response("not_found", { status: 404, headers: { "cache-control": "no-store" } });
    }

    // The staging transport probe must never enter tenant resolution, durable
    // rate limiting, cache routing, or normal response transforms. Its service
    // authenticates the original Authorization again inside the container.
    if (isStagingGrpcDiagnosticPath(request)) {
      return this.forwardStagingGrpcDiagnostic(request);
    }

    // Internal DO management paths
    if (url.pathname === "/_do/health") {
      // `?colo=1` additionally resolves this DO's serving colo (one best-effort
      // external fetch). Opt-in so the ordinary probe stays network-free.
      return this.handleHealthProbe(requestId, url.searchParams.get("colo") === "1");
    }
    if (url.pathname === "/_do/stop") {
      return this.handleStop(requestId);
    }
    if (url.pathname === "/_do/runner-cleanup/prepare") {
      return handleRunnerPrepare(request, this.env, this.state, this.storage, requestId);
    }
    if (url.pathname === "/_do/devenv-cleanup/prepare") {
      return handleDevenvCleanupRequest(request, this.env, this.state, this.storage, requestId, "prepare");
    }
    if (url.pathname === "/_do/devenv-cleanup/adopt") {
      return handleDevenvCleanupRequest(request, this.env, this.state, this.storage, requestId, "adopt");
    }
    if (url.pathname === "/_do/devenv-cleanup/revoke") {
      return handleDevenvCleanupRequest(request, this.env, this.state, this.storage, requestId, "revoke");
    }

    const durableRouteGate = await this.enforceDurableRouteRateLimit(request, url);
    if (durableRouteGate) return durableRouteGate;

    // Both public PAT aliases are authorized by this tenant DO before the
    // container starts. The DO's serialized durable decision is the sole
    // issuance authority across restarts and container instances.
    let requestForProxy = request;
    if (
      request.method === "POST" &&
      (url.pathname === "/v1/pats" || url.pathname === "/v1/customer/keys")
    ) {
      const gate = await this.enforcePatIssueRateLimit(
        requestId,
        request.headers.get("x-corelink-tenant-id"),
      );
      if (!gate.allowed) return gate.response;
      const headers = new Headers(request.headers);
      // A caller-supplied copy can never authorize itself; only this DO's
      // successful decision may stamp the one-request lease.
      headers.delete(PAT_ISSUE_AUTHORIZED_HEADER);
      headers.set(PAT_ISSUE_AUTHORIZED_HEADER, "1");
      requestForProxy = new Request(request, { headers });
    }

    // ── Tenant resolution (WP-T1) ─────────────────────────────────────────────
    // The Worker sets x-corelink-tenant-id to the PAT-resolved tenant before
    // forwarding. Bind it into the lifecycle state the first time we see it
    // (or on every request — idempotent since DO ID is already tenant-derived).
    // This resolves the null tenantId that was hardcoded before WP-T1.
    const incomingTenantId = request.headers.get("x-corelink-tenant-id");
    if (
      incomingTenantId !== null &&
      incomingTenantId.length > 0 &&
      incomingTenantId !== this.lifecycleState.tenantId
    ) {
      await this.updateLifecycleState({
        ...this.lifecycleState,
        tenantId: incomingTenantId,
      });
    }

    // Ensure container is running before forwarding
    const started = await this.ensureContainerRunning(requestId);
    if (!started.ok) {
      return new Response(
        JSON.stringify({
          error: "CONTAINER_UNAVAILABLE",
          message: started.reason,
          request_id: requestId,
        }),
        {
          status: 503,
          headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
        },
      );
    }

    const container = this.state.container;
    if (container === undefined || !container.running) {
      return new Response(
        JSON.stringify({
          error: "INTERNAL_ERROR",
          message: "container not running after start",
          request_id: requestId,
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
        },
      );
    }

    // Touch the durable idle clock on every REAL proxied request. In-memory
    // only (zero hot-path storage cost): the health-check alarm's periodic
    // lifecycle write persists it within one HEALTH_CHECK_INTERVAL_MS.
    this.lifecycleState = { ...this.lifecycleState, lastActivityMs: Date.now() };

    // SELF-HEAL the alarm chain. The alarm owns the reaper, so a lost chain =
    // an immortal container. `ensureContainerRunning` returns early (ok) for an
    // already-running container without arming anything, so a chain dropped by
    // CF (retries exhausted on a throwing tick) would never come back on its
    // own. `getAlarm()` is a cheap cached read; re-arm only when it is null.
    if ((await this.storage.getAlarm()) === null) {
      await this.storage.setAlarm(Date.now() + HEALTH_CHECK_INTERVAL_MS);
    }

    // Get the TCP-port Fetcher for gRPC port 50051
    const fetcher = container.getTcpPort(CONTAINER_PORT);

    try {
      const resp = await proxyToContainer(requestForProxy, fetcher);
      return resp;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message.slice(0, 80) : "unknown";
      console.error(`[${requestId}] container proxy error: ${msg}`);

      // Mark container degraded — next request will attempt restart
      await this.transitionStatus("degraded", requestId);

      return new Response(
        JSON.stringify({
          error: "UPSTREAM_ERROR",
          message: "container error",
          request_id: requestId,
        }),
        {
          status: 502,
          headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
        },
      );
    }
  }

  private async forwardStagingGrpcDiagnostic(request: Request): Promise<Response> {
    if (verifyStagingGrpcDiagnosticBinding(request, this.env, this.now()) === null) {
      return grpcDiagnosticUnavailable();
    }

    const started = await this.ensureContainerRunning("staging-grpc-probe");
    if (!started.ok) return grpcDiagnosticUnavailable();

    const container = this.state.container;
    if (container === undefined || !container.running) return grpcDiagnosticUnavailable();

    try {
      const response = await proxyToContainer(request, container.getTcpPort(CONTAINER_PORT), {
        signal: request.signal,
        redirect: "manual",
      });
      return isNonRedirectNativeGrpcResponse(response) ? response : grpcDiagnosticUnavailable();
    } catch {
      return grpcDiagnosticUnavailable();
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Container lifecycle
  // ──────────────────────────────────────────────────────────────────────────

  /** Ensure the container is running, starting it if necessary. */
  private async ensureContainerRunning(
    requestId: string,
    suppressLifecycleTelemetry = false,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    if (this.probeRetired) return { ok: false, reason: "old_probe_retired" };
    const container = this.state.container;

    if (
      this.lifecycleState.containerStatus === "running" &&
      container !== undefined &&
      container.running
    ) {
      return { ok: true };
    }

    // STALE-RUNNING DETECTION:
    // If our persisted lifecycle says "running" but the Container binding
    // is gone or no longer running, we hit this case after a wrangler
    // deploy rotation (CF tears down the old container; lifecycleState
    // still has the pre-rotation status). The previous logic fell through
    // to "unexpected_lifecycle_state" and never self-healed — clients got
    // permanent 503 until manual intervention. Treat this exactly like
    // "stopped" and restart the container.
    if (this.lifecycleState.containerStatus === "running") {
      console.warn(
        `[${requestId}] lifecycleState=running but container is not — treating as stopped`,
      );
      await this.transitionStatus("stopped", requestId);
      return this.startContainer(requestId, suppressLifecycleTelemetry);
    }

    if (
      this.lifecycleState.containerStatus === "degraded" ||
      this.lifecycleState.containerStatus === "stopped"
    ) {
      return this.startContainer(requestId, suppressLifecycleTelemetry);
    }

    if (this.lifecycleState.containerStatus === "starting") {
      // STALE-STARTING DETECTION (mirrors STALE-RUNNING above): a `"starting"`
      // older than STALE_STARTING_MS means the start that set it died WITHOUT
      // transitioning (isolate evicted mid-start, or a request flood interrupted
      // it). Because lifecycleState is loaded from storage on every isolate, that
      // stale `"starting"` would otherwise trap EVERY request in
      // waitForContainerReady forever (no self-heal — unlike `"running"` above);
      // this is the 2026-06-23 `_system` wedge (F-020). Treat it as stopped and
      // restart. A legitimately in-flight start has a recent startingAt_ms
      // (< STALE_STARTING_MS, which is > STARTUP_TIMEOUT_MS) → still waits.
      const startedAt = this.lifecycleState.startingAt_ms ?? 0;
      if (Date.now() - startedAt > STALE_STARTING_MS) {
        console.warn(
          `[${requestId}] lifecycleState=starting but stale (>${STALE_STARTING_MS}ms, no live start) — treating as stopped`,
        );
        await this.transitionStatus("stopped", requestId);
        return this.startContainer(requestId, suppressLifecycleTelemetry);
      }
      return this.waitForContainerReady(requestId);
    }

    return { ok: false, reason: "unexpected_lifecycle_state" };
  }

  /** Delegate container boot orchestration to the lifecycle domain module. */
  private startContainer(
    requestId: string,
    suppressLifecycleTelemetry = false,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    return runStartContainer(
      {
        container: this.state.container,
        env: this.env,
        doIdHash: this.doIdHash,
        getLifecycleState: () => this.lifecycleState,
        setLifecycleState: (state) => {
          this.lifecycleState = state;
        },
        transitionStatus: (status, id) => this.transitionStatus(status, id),
        updateLifecycleState: (state) => this.updateLifecycleState(state),
        waitForContainerReady: (id) => this.waitForContainerReady(id),
        armInactivityTimeout: (container, id) => this.armInactivityTimeout(container, id),
        waitForContainerHealth: (id, container) => this.waitForContainerHealth(id, container),
        destroyContainer: (id) => this.destroyContainer(id),
        installStagingD1BindingProxy: () => this.installStagingD1BindingProxy(),
        setAlarm: (when) => this.storage.setAlarm(when),
        suppressLifecycleTelemetry,
      },
      requestId,
    );
  }

  private async installStagingD1BindingProxy(deadline?: StagingD1HttpDeadline): Promise<void> {
    if (deadline !== undefined && !isStagingD1HttpDeadline(deadline, this.env.SENTRY_RELEASE ?? "")) throw new Error("HTTP deadline binding rejected");
    const localExports = (this.ctx as unknown as {
      exports: {
        StagingD1BindingProxy: (options: { props: StagingD1HttpDeadline | Record<string, never> }) => Fetcher;
      };
    }).exports;
    const worker = localExports.StagingD1BindingProxy({ props: deadline ?? {} });
    await installD1BindingProxy(this.state.container, worker);
  }

  /** Wait briefly for a container in "starting" state to become ready. */
  private async waitForContainerReady(
    requestId: string,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const deadline = Date.now() + STARTUP_TIMEOUT_MS;
    const container = this.state.container;
    while (Date.now() < deadline) {
      if (
        this.lifecycleState.containerStatus === "running" &&
        container !== undefined &&
        container.running
      ) {
        return { ok: true };
      }
      // M1: FAST-DEATH EXIT. A bad deploy (binary OOM/panic) flips the status to
      // the terminal-dead "stopped" state — there is nothing left starting to
      // wait for, so spinning the full STARTUP_TIMEOUT_MS only makes every queued
      // request hang ~90s before the inevitable 503. Bail immediately so the
      // caller returns a prompt 503 (and the next request triggers a restart via
      // ensureContainerRunning's stopped→startContainer branch). We break ONLY on
      // "stopped" (genuinely dead); "starting" is transient and still waits out
      // the 90s ceiling below, and "degraded" is handled on the next request.
      if (this.lifecycleState.containerStatus === "stopped") {
        console.error(`[${requestId}] container in terminal "stopped" state — fast-exit (no wait)`);
        return { ok: false, reason: "container_dead" };
      }
      await new Promise<void>((r) => setTimeout(r, 100));
    }
    console.error(`[${requestId}] timeout waiting for container to start`);
    return { ok: false, reason: "container_start_timeout" };
  }

  /**
   * Arm Cloudflare's OWN idle auto-destroy for this container.
   *
   * `container.setInactivityTimeout(ms)` is the platform-side reaper: workerd
   * destroys the container after `ms` without activity, with no help from this
   * Worker. It has been named in this file's header doc-comment since day one
   * (see the `state.container` capability list) and was NEVER CALLED — the repo
   * hand-rolled the alarm reaper in `alarm()` instead. That reaper shipped in
   * #927 and never moved the live instance count off 35 (5 regions x 7 x 4 GiB
   * resident, `active: 0` in regions with zero traffic).
   *
   * Platform-side is strictly stronger than ours: it survives DO eviction, a
   * broken alarm chain and a wedged isolate — precisely the failure modes that
   * made containers immortal. The alarm reaper is KEPT as defence in depth and
   * because it also stops re-arming the chain, letting the DO itself hibernate
   * (a live alarm chain bills DO duration on its own).
   *
   * ⚠️ The type declaration (`worker-configuration.d.ts`, `interface Container`)
   * carries NO doc-comment, so it is UNSPECIFIED whether the timer restarts on
   * container activity or is an absolute deadline from the moment it is armed.
   * Under the absolute reading, arming once at start would kill a BUSY
   * container mid-request one window later. So this is called at start AND
   * re-armed from `alarm()` while the container is non-idle — correct under
   * both readings: idempotent if the platform already tracks activity, a
   * sliding window if it does not. Re-arming rides the existing alarm and
   * never the request path; a per-request `await` here would tax the hot path.
   *
   * Never throws — a container that cannot arm its idle timer must still
   * serve. But it must not fail SILENTLY: an unarmed timer is exactly how this
   * leak survived a whole fix cycle, so a failure is logged loudly.
   */
  private async armInactivityTimeout(container: Container, requestId: string): Promise<void> {
    if (typeof container.setInactivityTimeout !== "function") {
      // Older workerd, or a test double predating the API: the alarm reaper in
      // alarm() remains the only reaper. Not an error, but not silent either.
      console.warn(
        `[${requestId}] container.setInactivityTimeout unavailable — ` +
          `platform idle auto-destroy NOT armed; relying on the alarm reaper alone`,
      );
      return;
    }
    try {
      await container.setInactivityTimeout(IDLE_TIMEOUT_MS);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(
        `[${requestId}] container.setInactivityTimeout(${IDLE_TIMEOUT_MS}) threw: ${msg} — ` +
          `platform idle auto-destroy NOT armed; relying on the alarm reaper alone`,
      );
    }
  }

  /**
   * Poll container health endpoint until healthy or timeout.
   * Uses HTTP GET /_health on the container port via getTcpPort fetcher.
   */
  private async waitForContainerHealth(
    requestId: string,
    container: Container,
  ): Promise<boolean> {
    const deadline = Date.now() + STARTUP_TIMEOUT_MS;
    let attempts = 0;
    while (Date.now() < deadline) {
      attempts++;
      if (!container.running) {
        // Container exited unexpectedly during startup
        break;
      }
      try {
        const fetcher = container.getTcpPort(CONTAINER_PORT);
        const healthReq = new Request(`http://localhost:${CONTAINER_PORT}/_health`, {
          method: "GET",
          headers: { "x-request-id": requestId },
        });
        const resp = await fetcher.fetch(healthReq);
        if (resp.status === 200) {
          this.healthFailures = 0;
          return true;
        }
      } catch (_err: unknown) {
        // Container still starting — retry
      }
      await new Promise<void>((r) => setTimeout(r, 500));
    }
    console.error(`[${requestId}] container health timed out after ${attempts} attempts`);
    return false;
  }

  /**
   * Health probe handler (/_do/health).
   * Also used by wrangler dev --local smoke test.
   *
   * Additionally carries the D1-placement INSTRUMENT (`d1_probe`) — see
   * {@link probeD1Latency}. Existing fields are untouched (something may parse
   * this); the instrument is purely additive.
   *
   * @param includeColo when true (`/_do/health?colo=1`) also resolve the DO's
   *   serving colo via a best-effort `cdn-cgi/trace` fetch. OFF by default so
   *   the ordinary probe makes no external request.
   */
  private async handleHealthProbe(requestId: string, includeColo = false): Promise<Response> {
    const container = this.state.container;
    const containerRunning = container !== undefined && container.running;
    const status = this.lifecycleState.containerStatus;

    // The instrument. Never throws (every failure is reported as a field).
    const d1Probe = await this.probeD1Latency(includeColo);

    const body = JSON.stringify({
      status: containerRunning ? "ok" : status,
      container_status: status,
      container_running: containerRunning,
      cold_start_count: this.lifecycleState.coldStartCount,
      last_health_check_ms: this.lifecycleState.lastHealthCheckMs,
      request_id: requestId,
      d1_probe: d1Probe,
    });
    return new Response(body, {
      status: containerRunning ? 200 : 503,
      headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
    });
  }

  /**
   * D1 PLACEMENT INSTRUMENT — measures, from INSIDE this DO, how far the DO is
   * from the D1 primary (ENAM) and from the nearest read replica.
   *
   * ## Why this exists
   *
   * The container reads D1 over the public REST API
   * (`crates/corelink-container/src/storage/d1_http.rs:92`), which ALWAYS hits
   * the ENAM primary — measured 79/86/99 ms in prod. A proposal to route those
   * reads through this DO (which holds the `CONFIG_DB` binding) is worth
   * somewhere between −70 ms and +65 ms, and the sign hinges on ONE unmeasured
   * fact: where this DO sits relative to the ENAM primary. A DO-issued primary
   * read of ≤25 ms means co-location (the proposal wins ~60-75 ms); ≥100 ms
   * means the DO is far (the proposal is a regression — the Worker's own
   * primary read from SAM measures 156 ms). This function IS that measurement.
   *
   * ## What it does NOT do
   *
   * It runs ONLY on `/_do/health`. Nothing on the request-serving path calls it,
   * and it neither starts nor touches the container.
   *
   * ## How to read the numbers
   *
   *   - `warmup_ms` is an UNCOUNTED first read whose sole job is to absorb
   *     connection setup so it is not charged to `primary`. It is reported, not
   *     hidden — it is also the honest "cold" number.
   *   - `primary.min_ms` is the decision number for the primary path;
   *     `samples_ms` is every sample in order so a warm/cold spread is visible.
   *   - `served_by_region` / `served_by_primary` / `served_by_colo` come from
   *     D1's own result `meta`. They are what distinguishes "the replica read
   *     landed on a real replica" from "the Sessions API silently served the
   *     primary" — a replica time equal to the primary time is meaningless
   *     without them.
   *   - A read that THROWS reports `ok: false` + a non-null `error`. It is NEVER
   *     reported as a fast number and never as a missing field.
   *   - `available: false` means the path could not be attempted at all
   *     (binding unbound / no Sessions API), which is DISTINCT from "attempted
   *     and failed" (`available: true, ok: false`).
   */
  private async probeD1Latency(includeColo: boolean): Promise<D1ProbeReport> {
    // Structural read of the binding: `Env.CONFIG_DB` is declared non-optional,
    // but a test double (or a stripped env) may simply not have it. Mirrors the
    // optional-binding pattern in index.ts (`env as unknown as { METADATA_KV?… }`).
    const binding = (this.env as unknown as { CONFIG_DB?: D1ProbeBinding }).CONFIG_DB;

    const doColo = includeColo ? await resolveDoColo() : { colo: null, error: null };

    if (binding === undefined || binding === null) {
      const unavailable = unavailablePath("CONFIG_DB binding is not bound");
      return {
        probe_version: D1_PROBE_VERSION,
        samples: D1_PROBE_SAMPLES,
        binding_bound: false,
        sessions_api_available: false,
        warmup_ms: null,
        warmup_error: "CONFIG_DB binding is not bound",
        primary: unavailable,
        replica: unavailable,
        do_colo: doColo.colo,
        do_colo_error: doColo.error,
      };
    }

    // Uncounted warm-up on the primary handle: the FIRST D1 call in a fresh
    // isolate pays connection setup, and charging that to `primary` would fake a
    // "the DO is far from ENAM" verdict. Reported separately, never dropped.
    const warmup = await timedD1Read(binding);

    const primary = await probeD1Path(binding);

    // Feature-detect the Sessions API EXACTLY as index.ts:1259-1260 does. A
    // runtime (or a test double) without it must degrade to primary-only, never
    // throw — the health probe outranks the instrument.
    const sessionsAvailable = typeof binding.withSession === "function";
    let replica: D1PathProbeResult;
    if (!sessionsAvailable) {
      replica = unavailablePath("Sessions API (withSession) not available on this binding");
    } else {
      try {
        // `first-unconstrained` = no bookmark constraint → nearest replica.
        const session = binding.withSession?.("first-unconstrained");
        replica =
          session === undefined || session === null
            ? unavailablePath("withSession returned no session handle")
            : await probeD1Path(session);
      } catch (err: unknown) {
        replica = { ...unavailablePath("withSession threw"), error: errText(err) };
      }
    }

    return {
      probe_version: D1_PROBE_VERSION,
      samples: D1_PROBE_SAMPLES,
      binding_bound: true,
      sessions_api_available: sessionsAvailable,
      warmup_ms: warmup.ms,
      warmup_error: warmup.error,
      primary,
      replica,
      do_colo: doColo.colo,
      do_colo_error: doColo.error,
    };
  }

  /**
   * Stop the container (/_do/stop or idle-timeout trigger).
   * Telemetry: emits corelink.do.container_died.v1 BEFORE destroying.
   */
  private async handleStop(requestId: string): Promise<Response> {
    const tenantHash = await hashForLog(this.lifecycleState.tenantId ?? "_unknown");

    // AUDIT BEFORE MUTATION
    await emitLifecycleEvent(
      this.env.PAGERDUTY_ROUTING_KEY ?? "",
      "corelink.do.container_died.v1",
      `CoreLink container stopped (requested) for tenant ${tenantHash}`,
      "info",
      tenantHash,
      this.doIdHash,
      this.lifecycleState.coldStartCount,
      this.env.ENVIRONMENT,
    );

    await this.destroyContainer(requestId);

    return new Response(
      JSON.stringify({ stopped: true, request_id: requestId }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Request-Id": requestId },
      },
    );
  }

  /** Destroy the container and update persisted state. */
  private async destroyContainer(requestId: string): Promise<void> {
    const container = this.state.container;
    if (container !== undefined && container.running) {
      try {
        await container.destroy();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message.slice(0, 80) : "unknown";
        console.error(`[${requestId}] container.destroy() threw: ${msg}`);
      }
    }
    await this.transitionStatus("stopped", requestId);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // State helpers
  // ──────────────────────────────────────────────────────────────────────────

  private async transitionStatus(
    status: ContainerStatus,
    _requestId: string,
  ): Promise<void> {
    await this.updateLifecycleState({ ...this.lifecycleState, containerStatus: status });
  }

  private async updateLifecycleState(newState: LifecycleState): Promise<void> {
    this.lifecycleState = newState;
    await this.storage.put("lifecycle", newState);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Alarm — periodic health check
  // ──────────────────────────────────────────────────────────────────────────
  override async alarm(): Promise<void> {
    if (this.httpClaim !== undefined) return this.expireHttpProbeContainer();
    // Retirement owns alarm deletion after Container stop settles. An alarm
    // arriving during an uncancellable stop must not submit parallel cleanup.
    if (this.probeRetired || this.isOldProbeObject()) return;
    return this.withProbeActivity(() => this.alarmActive());
  }

  private async alarmActive(): Promise<void> {
    // The alarm is the SOLE owner of both the health chain and the reaper, so
    // losing a link is losing the reaper — the immortal container re-entered
    // through a third door. Any throw below (a storage.put fault, the
    // PagerDuty POST, hashForLog) would otherwise end the chain permanently
    // once CF exhausts its bounded retries. Mirror the always-re-arm posture
    // of ReplicationCoordinatorDO.alarm(): re-arm in `finally` UNLESS this
    // tick deliberately ended the chain (`chainEnded`).
    let chainEnded = false;
    let cleanupPending = false;
    try {
      cleanupPending = await drainCredentialCleanupObligations(
        this.storage,
        this.env.CONFIG_DB,
        this.env.METADATA_KV,
        Date.now(),
      );
      chainEnded = await this.alarmTick();
    } finally {
      if (!chainEnded || cleanupPending) {
        await this.storage.setAlarm(Date.now() + HEALTH_CHECK_INTERVAL_MS);
      }
    }
  }

  /**
   * One alarm tick. Returns `true` when the chain was deliberately ENDED (the
   * container is dead or was just reaped) — the caller then does NOT re-arm,
   * which is what lets the DO hibernate instead of heartbeating a dead
   * container forever. Any other return (or a throw) leaves the chain armed.
   */
  private async alarmTick(): Promise<boolean> {
    const container = this.state.container;
    const status = this.lifecycleState.containerStatus;
    if (
      container === undefined ||
      !container.running ||
      (status !== "running" && status !== "degraded")
    ) {
      // Chain deliberately ENDS here (no reschedule): a dead container must
      // not keep the DO alive on a 30s alarm heartbeat — that is the other
      // half of the immortal-container bill. The next real request restarts
      // both the container and the alarm chain (ensureContainerRunning).
      // NB: "degraded" with a still-running container stays IN the chain —
      // it must remain subject to the idle reaper below, or a degraded
      // container becomes the one immortality path left.
      return true;
    }

    const requestId = "alarm-health-" + crypto.randomUUID().slice(0, 8);
    const now = Date.now();

    // ── Durable idle reaper ─────────────────────────────────────────────────
    // The reaper MUST live here, on the alarm (durable, storage-backed), not
    // in a setTimeout: the old in-memory idle timer evaporated on every
    // isolate eviction (deploy/recycle) while this alarm chain survived and
    // kept health-checking the container — so any once-started container
    // became IMMORTAL and was billed 24/7 (2026-07 invoice: ~13 GiB resident
    // memory around the clock, $84/mo, with $0.00 of real traffic).
    const lastActivity = this.lifecycleState.lastActivityMs;
    if (lastActivity === undefined) {
      // Pre-fix persisted state: start the idle clock now; reaps one idle
      // window later. Persisted immediately so an eviction can't reset it.
      await this.updateLifecycleState({ ...this.lifecycleState, lastActivityMs: now });
    } else if (now - lastActivity >= IDLE_TIMEOUT_MS) {
      const tenantHash = await hashForLog(this.lifecycleState.tenantId ?? "_unknown");
      // AUDIT BEFORE MUTATION
      await emitLifecycleEvent(
        this.env.PAGERDUTY_ROUTING_KEY ?? "",
        "corelink.do.container_died.v1",
        `CoreLink container stopped (idle timeout) for tenant ${tenantHash}`,
        "info",
        tenantHash,
        this.doIdHash,
        this.lifecycleState.coldStartCount,
        this.env.ENVIRONMENT,
      );
      // RE-CHECK before destroying. Every `await` above is a yield point where
      // a queued fetch() runs (the same concurrency rule the REV-S2
      // concurrent-start guard is built on), and emitLifecycleEvent is a real
      // outbound POST — seconds-scale. A request that arrived in that window
      // has already passed ensureContainerRunning and may be mid-proxy;
      // destroying now would kill it in flight. Abort and let the chain re-arm.
      const activityNow = this.lifecycleState.lastActivityMs ?? 0;
      if (Date.now() - activityNow < IDLE_TIMEOUT_MS) {
        return false; // raced with a live request — keep the container
      }
      await this.destroyContainer(requestId);
      return true; // chain ends — container dead, DO free to hibernate
    }

    if (status !== "running") {
      // Degraded-but-running: no health probe (preserved semantics), but the
      // chain stays alive so the reaper above still fires on idle expiry.
      // Persist the idle clock too — the degraded arm never wrote lifecycle,
      // so an eviction here would revert lastActivityMs to a stale value.
      await this.updateLifecycleState({ ...this.lifecycleState });
      return false;
    }

    // Re-arm the platform idle reaper. Reached only when the container is
    // running AND the reaper above did NOT find it idle, so this slides the
    // window for a container that is actually being used. Placed before the
    // health-probe dedupe below so a deduped double-fire still re-arms.
    // See armInactivityTimeout: the timer's reset semantics are unspecified,
    // and re-arming is what makes this correct under the absolute reading.
    await this.armInactivityTimeout(container, requestId);

    if (now - this.lifecycleState.lastHealthCheckMs < HEALTH_CHECK_INTERVAL_MS) {
      // Deduped double-fire: skip the probe but NEVER break the alarm chain —
      // a silent early-return here would orphan a running container with no
      // health checks AND no reaper. (Persist for the same reason as above.)
      await this.updateLifecycleState({ ...this.lifecycleState });
      return false;
    }

    try {
      const fetcher = container.getTcpPort(CONTAINER_PORT);
      const healthReq = new Request(`http://localhost:${CONTAINER_PORT}/_health`, {
        method: "GET",
        headers: { "x-request-id": requestId },
      });
      const resp = await fetcher.fetch(healthReq);
      if (resp.status === 200) {
        this.healthFailures = 0;
        await this.updateLifecycleState({ ...this.lifecycleState, lastHealthCheckMs: now });
      } else {
        this.healthFailures++;
        if (this.healthFailures >= MAX_HEALTH_FAILURES) {
          const tenantHash = await hashForLog(this.lifecycleState.tenantId ?? "_unknown");
          await emitLifecycleEvent(
            this.env.PAGERDUTY_ROUTING_KEY ?? "",
            "corelink.do.container_died.v1",
            `CoreLink container health degraded (${this.healthFailures} failures) for tenant ${tenantHash}`,
            "error",
            tenantHash,
            this.doIdHash,
            this.lifecycleState.coldStartCount,
            this.env.ENVIRONMENT,
          );
          await this.transitionStatus("degraded", requestId);
        }
      }
    } catch (_err: unknown) {
      this.healthFailures++;
      if (this.healthFailures >= MAX_HEALTH_FAILURES) {
        await this.transitionStatus("degraded", requestId);
      }
    }

    // Chain continues — alarm() re-arms in its `finally`.
    return false;
  }
}

// Re-export env augmentation so Env picks up secrets added in the DO layer
declare module "./index.js" {
  interface Env {
    PAGERDUTY_ROUTING_KEY?: string;
    // Brutal-audit M3 — container tuning knobs forwarded by container.start()
    // above (read in the container via const-aliased std::env::var). Optional:
    // unset ⇒ the container uses its built-in default.
    PAT_MINT_MAX_INFLIGHT?: string;
    PAT_MINT_MAX_PER_MINUTE?: string;
    QUOTA_COST_PER_OP_MICROS?: string;
    EXPORT_ROW_BUFFER_BYTES?: string;
    // Metadata KV is the edge PAT cache invalidation surface used by
    // credential-obligation drains. It is optional in local/test bindings;
    // revoke fails closed when an issued token requires cache eviction.
    METADATA_KV?: KVNamespace;
  }
}
