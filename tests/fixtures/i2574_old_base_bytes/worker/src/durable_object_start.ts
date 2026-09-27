/** Container start orchestration and environment wiring. */

import type { Container } from "@cloudflare/workers-types";
import type { Env } from "./index.js";
import { emitLifecycleEvent, hashForLog } from "./durable_object_probes.js";
import { patRotationEnv } from "./lib/pat_rotation_env.js";

type ContainerStatus = "stopped" | "starting" | "running" | "degraded";

/** Start a container with audit-before-mutation and fail-closed health gates. */
export interface StartContainerLifecycleState {
  readonly containerStatus: ContainerStatus;
  readonly coldStartCount: number;
  readonly tenantId: string | null;
  readonly lastHealthCheckMs: number;
  readonly lastActivityMs?: number;
  readonly startingAt_ms?: number;
}
export interface StartContainerContext {
  readonly container: Container | undefined;
  readonly env: Env;
  readonly doIdHash: string;
  getLifecycleState(): StartContainerLifecycleState;
  setLifecycleState(state: StartContainerLifecycleState): void;
  transitionStatus(status: ContainerStatus, requestId: string): Promise<void>;
  updateLifecycleState(state: StartContainerLifecycleState): Promise<void>;
  waitForContainerReady(requestId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  armInactivityTimeout(container: Container, requestId: string): Promise<void>;
  waitForContainerHealth(requestId: string, container: Container): Promise<boolean>;
  destroyContainer(requestId: string): Promise<void>;
  setAlarm(when: number): Promise<void>;
}

const CONTAINER_PORT = 50051;
const HEALTH_CHECK_INTERVAL_MS = 30_000;

export async function startContainer(
  ctx: StartContainerContext,
  requestId: string,
): Promise<{ ok: true } | { ok: false; reason: string }> {
    const container = ctx.container;
    if (container === undefined) {
      return { ok: false, reason: "no_container_binding" };
    }

    // CONCURRENT-START GUARD (REV-S2):
    // Cloudflare DOs are single-threaded but ASYNC-concurrent — each `await`
    // below (emitLifecycleEvent, transitionStatus, container.start) is a yield
    // point at which another queued fetch() can run. If two requests arrive
    // while status is "stopped"/"degraded", both pass the ensureContainerRunning
    // check and both enter startContainer, double-calling container.start() and
    // double-counting cold starts. Closing the race requires flipping the
    // IN-MEMORY status to "starting" SYNCHRONOUSLY here — before the first await
    // — so any concurrent request that runs ensureContainerRunning next sees
    // "starting" and falls into the waitForContainerReady branch instead of re-entering this method. (We avoid blockConcurrencyWhile here so we do not
    // serialize ALL fetches for the full ~90s startup window; the in-memory flip
    // is sufficient because the check and this flip are in the same microtask
    // turn with no intervening await.) The persisted write happens via
    // transitionStatus below; the in-memory field is the load-bearing guard.
    if (ctx.getLifecycleState().containerStatus === "starting") {
      // A concurrent caller already won the start; defer to the wait path.
      return ctx.waitForContainerReady(requestId);
    }
    // Synchronous in-memory flip (containerStatus is readonly → replace the object).
    // Stamp startingAt_ms so a start that later dies without transitioning is
    // detectable as stale by ensureContainerRunning (F-020 self-heal).
    ctx.setLifecycleState({
      ...ctx.getLifecycleState(),
      containerStatus: "starting",
      startingAt_ms: Date.now(),
    });

    const tenantHash = await hashForLog(ctx.getLifecycleState().tenantId ?? "_unknown");
    const newColdStartCount = ctx.getLifecycleState().coldStartCount + 1;

    // AUDIT BEFORE MUTATION
    await emitLifecycleEvent(
      ctx.env.PAGERDUTY_ROUTING_KEY ?? "",
      "corelink.do.cold_start.v1",
      `CoreLink DO cold start #${newColdStartCount} for tenant ${tenantHash}`,
      "info",
      tenantHash,
      ctx.doIdHash,
      newColdStartCount,
      ctx.env.ENVIRONMENT,
    );

    // Persist the "starting" status (the in-memory flip above already closed the
    // concurrent-start race; this durably records it across DO eviction).
    await ctx.transitionStatus("starting", requestId);

    try {
      // Start container — returns void; container begins asynchronously
      container.start({
        // Egress required (P0-5): the native container reaches R2 (S3 API) and
        // D1 (HTTP API) over the public internet — DECISION-GATE-1 Option A.
        // CF Workers has no VPC-style internal route to R2 for native containers.
        enableInternet: true,
        entrypoint: ["/usr/local/bin/corelink-server"],
        env: {
          RUST_LOG: "info",
          PORT: String(CONTAINER_PORT),
          // WP-S1 StorageEnv contract: all six must be present + non-empty for
          // the container to use real R2/D1 storage. Any missing/empty → the
          // container falls back to InMemory (dev/CI without secrets). These are
          // sourced from Worker vars (endpoint, db id) + secrets (keys, token).
          R2_S3_ENDPOINT: ctx.env.R2_S3_ENDPOINT ?? "",
          R2_S3_ACCESS_KEY_ID: ctx.env.R2_S3_ACCESS_KEY_ID ?? "",
          R2_S3_SECRET_ACCESS_KEY: ctx.env.R2_S3_SECRET_ACCESS_KEY ?? "",
          CLOUDFLARE_ACCOUNT_ID: ctx.env.CLOUDFLARE_ACCOUNT_ID ?? "",
          CF_API_TOKEN: ctx.env.CF_API_TOKEN ?? "",
          D1_DATABASE_ID: ctx.env.D1_DATABASE_ID ?? "",
          // Stream-5: internal PAT mint route gate secrets.
          // Container mounts `/_internal/pat/mint` only when both are non-empty.
          CORELINK_INTERNAL_AUTH_KEY: ctx.env.CORELINK_INTERNAL_AUTH_KEY ?? "",
          // CP-1 (go-live audit): the container's `resolve_internal_auth_key`
          // prefers a per-consumer DEDICATED key and falls back to the shared
          // one. Those dedicated keys MUST be forwarded or (a) the blast-radius
          // isolation is inert (everything gates on the shared key) AND (b) the
          // moment an operator provisions a dedicated key, the container — never
          // receiving it — 401s every mint/admin/erase call (a self-inflicted
          // outage). Forward them (empty when unset ⇒ shared fallback, unchanged).
          CORELINK_PAT_MINT_AUTH_KEY: ctx.env.CORELINK_PAT_MINT_AUTH_KEY ?? "",
          CORELINK_ADMIN_AUTH_KEY: ctx.env.CORELINK_ADMIN_AUTH_KEY ?? "",
          CORELINK_ERASE_AUTH_KEY: ctx.env.CORELINK_ERASE_AUTH_KEY ?? "",
          // Dual-key rotation: the OUTGOING erase key, accepted alongside the
          // current one by the container (`dsr::internal_auth_ok_any`) for the
          // duration of a rotation so an in-flight erase leg never 401s while the
          // DO containers cycle onto the new key. Empty when unset ⇒ single-key.
          CORELINK_ERASE_AUTH_KEY_PREVIOUS: ctx.env.CORELINK_ERASE_AUTH_KEY_PREVIOUS ?? "",
          // Edge-probe audit emit: the container's `POST /_internal/audit/cas-attempted`
          // gate reads a DEDICATED `CORELINK_AUDIT_ATTEMPTED_AUTH_KEY` with NO shared
          // fallback (it writes tenant-attributed audit rows for an arbitrary tenant).
          // Unforwarded, the route would stay unmounted no matter what the operator
          // provisions — the edge findMissingBlobs path would silently keep taking the
          // slow container route with no way to tell why.
          CORELINK_AUDIT_ATTEMPTED_AUTH_KEY: ctx.env.CORELINK_AUDIT_ATTEMPTED_AUTH_KEY ?? "",
          // H5/B054 dual-approval: the container's `POST /v1/admin/approve` and
          // `POST /_internal/audit/epoch-admin` Security-principal gates read
          // a DEDICATED `CORELINK_ADMIN_APPROVER_AUTH_KEY` (distinct from the
          // mutate/admin key so approve+mutate need different keys — real
          // two-person control). Forward it or the container 401s every approve
          // call the moment the dedicated key is bound (the CP-1 self-inflicted
          // outage this block guards against). Empty when unset ⇒ dedicated-only
          // runtime stays unmounted/fails closed; there is no shared fallback.
          CORELINK_ADMIN_APPROVER_AUTH_KEY: ctx.env.CORELINK_ADMIN_APPROVER_AUTH_KEY ?? "",
          // #634: the per-user DSR legitimacy-anchor route (`/_internal/dsr/anchor`)
          // reads a dedicated `CORELINK_DSR_ANCHOR_AUTH_KEY`; forward it too or the
          // container 401s every anchor call the moment the dedicated key is bound
          // (the exact CP-1 self-inflicted-outage this block guards against).
          CORELINK_DSR_ANCHOR_AUTH_KEY: ctx.env.CORELINK_DSR_ANCHOR_AUTH_KEY ?? "",
          // Read-only tenant-quota lookup (`/_internal/tenant/{tenant_id}/quota`):
          // the container's `tenant_quota_read::build_state_from_env` reads a
          // dedicated `CORELINK_QUOTA_READ_AUTH_KEY` (shared-key fallback). Forward
          // it or the container 401s every quota-read call the moment the dedicated
          // key is bound (the CP-1 self-inflicted-outage this block guards against).
          CORELINK_QUOTA_READ_AUTH_KEY: ctx.env.CORELINK_QUOTA_READ_AUTH_KEY ?? "",
          // B-074: forward the two money-path authorities so the container can
          // honor dedicated rotation. Omit an absent binding so the container
          // can use its documented shared fallback; an explicitly empty/short
          // binding remains present and therefore fails closed.
          ...(ctx.env.CORELINK_TIER_SELECT_AUTH_KEY === undefined
            ? {}
            : { CORELINK_TIER_SELECT_AUTH_KEY: ctx.env.CORELINK_TIER_SELECT_AUTH_KEY }),
          ...(ctx.env.CORELINK_DPA_ACCEPT_AUTH_KEY === undefined
            ? {}
            : { CORELINK_DPA_ACCEPT_AUTH_KEY: ctx.env.CORELINK_DPA_ACCEPT_AUTH_KEY }),
          // DSR customer portal (union #717): the receipt-JWT signer
          // (`dsr/portal.rs:659`) reads `DSR_RECEIPT_SIGNING_KEY`; forward it or a
          // bound CF secret silently no-ops and the portal falls back to a weak
          // default (the F8/ERASURE_SALT class of self-inflicted bug).
          DSR_RECEIPT_SIGNING_KEY: ctx.env.DSR_RECEIPT_SIGNING_KEY ?? "",
          // DPA click-through acceptance (money-path unblock): the container's
          // `/v1/onboarding/dpa-accept` route (`dpa_accept::build_state_from_env`)
          // reads `DPA_RECEIPT_SIGNING_KEY` (RSA PKCS#8/PKCS#1 PEM) from its OWN
          // process env to RS256-sign the acceptance receipt. It MUST be forwarded
          // or the route stays UNMOUNTED (fail-CLOSED) and every paid checkout
          // 403s `dpa_required` (the DPA row never gets written).
          DPA_RECEIPT_SIGNING_KEY: ctx.env.DPA_RECEIPT_SIGNING_KEY ?? "",
          ...patRotationEnv(ctx.env),
          // L3 money path: `POST /v1/onboarding/tier-select` runs INSIDE the
          // container and reads these from its OWN process env
          // (`tier_select::build_state_from_env` + `StripeRealClient::from_env`).
          // They MUST be forwarded or the route stays unmounted (404, missing
          // CORELINK_DPA_VERSION) and Stripe checkout 500s (missing price ids).
          STRIPE_SECRET_KEY: ctx.env.STRIPE_SECRET_KEY ?? "",
          STRIPE_AUTH_MODE: ctx.env.STRIPE_AUTH_MODE ?? "",
          STRIPE_WEBHOOK_SECRET: ctx.env.STRIPE_WEBHOOK_SECRET ?? "",
          STRIPE_PRICE_ID_SOLO: ctx.env.STRIPE_PRICE_ID_SOLO ?? "",
          STRIPE_PRICE_ID_STARTER: ctx.env.STRIPE_PRICE_ID_STARTER ?? "",
          STRIPE_PRICE_ID_TEAM: ctx.env.STRIPE_PRICE_ID_TEAM ?? "",
          STRIPE_PRICE_ID_PRO: ctx.env.STRIPE_PRICE_ID_PRO ?? "",
          STRIPE_PRICE_ID_MAX: ctx.env.STRIPE_PRICE_ID_MAX ?? "",
          // Runners-tier prices: the container's seed handler
          // (`build_runners_resolver` in main.rs) reads these from its OWN env
          // to map a Runners-tier Stripe subscription → `runners_entitlement`.
          // Absent ⇒ the Runners seed stays dormant (cache path only).
          STRIPE_PRICE_ID_RUNNER_STARTER: ctx.env.STRIPE_PRICE_ID_RUNNER_STARTER ?? "",
          STRIPE_PRICE_ID_RUNNER_PRO: ctx.env.STRIPE_PRICE_ID_RUNNER_PRO ?? "",
          STRIPE_PRICE_ID_RUNNER_TEAM: ctx.env.STRIPE_PRICE_ID_RUNNER_TEAM ?? "",
          STRIPE_PRICE_ID_RUNNER_SCALE: ctx.env.STRIPE_PRICE_ID_RUNNER_SCALE ?? "",
          STRIPE_PRICE_ID_RUNNER_MAX: ctx.env.STRIPE_PRICE_ID_RUNNER_MAX ?? "",
          CORELINK_DPA_VERSION: ctx.env.CORELINK_DPA_VERSION ?? "",
          // DSR Wave 1 (#254): the container's erasure adapters derive the
          // pseudonymization/idempotency salt from ERASURE_SALT_KEY. If absent the
          // container falls back to a PREDICTABLE non-secret salt — forward it so
          // the real secret is used (launch-required GDPR path).
          ERASURE_SALT_KEY: ctx.env.ERASURE_SALT_KEY ?? "",
          // DSR G3 (#269): the container signs an Ed25519 erasure attestation on
          // VerifiedComplete, reading the seed/key-id/region from these env vars
          // (`routes/dsr/attestation.rs` from_seed/key_id/resolve_region). They
          // MUST be forwarded or setting ERASURE_ATTESTATION_SEED_HEX later never
          // reaches the container and attestation silently no-ops (fail-OPEN) —
          // the exact ERASURE_SALT_KEY-class gap. (caught by check-env-contract.py)
          ERASURE_ATTESTATION_SEED_HEX: ctx.env.ERASURE_ATTESTATION_SEED_HEX ?? "",
          ERASURE_ATTESTATION_KEY_ID: ctx.env.ERASURE_ATTESTATION_KEY_ID ?? "",
          // CF-6: OPTIONAL dedicated audit-chain head-signing key (defaults to
          // reusing the erasure-attestation seed/key above when unset).
          AUDIT_CHAIN_SIGNING_SEED_HEX: ctx.env.AUDIT_CHAIN_SIGNING_SEED_HEX ?? "",
          AUDIT_CHAIN_SIGNING_KEY_ID: ctx.env.AUDIT_CHAIN_SIGNING_KEY_ID ?? "",
          // B-054 write-only link-key keyring. Forward byte-for-byte through
          // the Worker→DO→container boundary; the parked epoch runtime parses
          // it atomically into zeroizing memory and refuses malformed input.
          AUDIT_CHAIN_LINK_KEYS_JSON: ctx.env.AUDIT_CHAIN_LINK_KEYS_JSON ?? "",
          // B-054 independent witness client. Forward all four values; the
          // container refuses partial/malformed configuration and every v2
          // partition remains frozen when the complete set is absent.
          AUDIT_WITNESS_URL: ctx.env.AUDIT_WITNESS_URL ?? "",
          AUDIT_WITNESS_APPEND_TOKEN: ctx.env.AUDIT_WITNESS_APPEND_TOKEN ?? "",
          AUDIT_WITNESS_ID: ctx.env.AUDIT_WITNESS_ID ?? "",
          AUDIT_WITNESS_PUBLIC_KEYS_JSON: ctx.env.AUDIT_WITNESS_PUBLIC_KEYS_JSON ?? "",
          AUDIT_CHAIN_TRUST_ROOT_PUBLIC_KEYS_JSON:
            ctx.env.AUDIT_CHAIN_TRUST_ROOT_PUBLIC_KEYS_JSON ?? "",
          CORELINK_ADMIN_APPROVAL_TRUST_ROOTS_JSON:
            ctx.env.CORELINK_ADMIN_APPROVAL_TRUST_ROOTS_JSON ?? "",
          AUDIT_CHAIN_TRUST_UNSIGNED_RESUME: ctx.env.AUDIT_CHAIN_TRUST_UNSIGNED_RESUME ?? "",
          // Non-secret tuning knob (secrets-matrix #189): per-call row budget for
          // the audit/drain sweep. "" ⇒ container default (200). Forwarded so a
          // Worker-side var actually reaches the container process.
          AUDIT_DRAIN_BATCH_LIMIT: ctx.env.AUDIT_DRAIN_BATCH_LIMIT ?? "",
          // B-038 rollout flag (default OFF). "1"/"true" serialises audit drains
          // behind a per-partition lease + seal fence. Forwarded so the container
          // process actually sees the toggle (else setting it as a Worker var is
          // silently inert). Not a secret.
          AUDIT_DRAIN_LEASE_ENABLED: ctx.env.AUDIT_DRAIN_LEASE_ENABLED ?? "",
          NEAR_CEILING_ALERT_SINK: ctx.env.NEAR_CEILING_ALERT_SINK ?? "",
          // Sample floor before the rolling health probe is allowed to declare a
          // region unhealthy (`routes/failover.rs:228`). "" ⇒ container default
          // (50). Forwarded because the container reads it at construction — an
          // operator raising the floor during an incident would otherwise be
          // setting a Worker var the failover path never sees. Not a secret.
          FAILOVER_MIN_SAMPLES: ctx.env.FAILOVER_MIN_SAMPLES ?? "",
          // S-09 offsite archive (`POST /_internal/audit/archive`). Both are
          // non-secret tuning knobs; "" ⇒ container defaults (bucket
          // `corelink-audit-weur`; its intended 7-year native Bucket Lock is
          // not current provider evidence and is not S3 Compliance/WORM; plus
          // a 2000-row per-partition budget). Forwarded because the
          // container reads them at boot — an operator override that is not on
          // this list silently no-ops (the ERASURE_SALT_KEY-class bug).
          R2_AUDIT_BUCKET: ctx.env.R2_AUDIT_BUCKET ?? "",
          AUDIT_ARCHIVE_BATCH_LIMIT: ctx.env.AUDIT_ARCHIVE_BATCH_LIMIT ?? "",
          // Objects one `POST /_internal/cas/scrub` call resolves before it
          // truncates and hands back a cursor (`routes/cas_scrub.rs`,
          // `build_state_from_env`). "" ⇒ container default (500). Forwarded
          // because the container reads it at construction — an operator
          // retuning the sweep would otherwise be setting a Worker var the
          // scrubber never sees. Not a secret.
          CAS_SCRUB_OBJECT_BUDGET: ctx.env.CAS_SCRUB_OBJECT_BUDGET ?? "",
          // Container origin-timing detail phases (`oargon`/`opermit`/`ortier`).
          // "on" arms them; anything else (the production default) leaves their
          // time inside the `ohandler` phase and the header byte-identical.
          // Forwarded because the container reads it via std::env::var — a
          // Worker secret that is not on this list silently no-ops, which for a
          // diagnostic flag means it reads as "armed, and the phases just are
          // not there" rather than as a failure. See `detail_phases_enabled`
          // for why OFF is the load-bearing default.
          CORELINK_ORIGIN_TIMING_DETAIL: ctx.env.CORELINK_ORIGIN_TIMING_DETAIL ?? "",
          // CTRL-PRIV-001: server-held salt for the email_hash pseudonym. Unset →
          // legacy unsalted SHA-256 (zero regression); set → HMAC-SHA256. MUST be
          // forwarded or the container can't see it when the owner registers it.
          EMAIL_HASH_SALT: ctx.env.EMAIL_HASH_SALT ?? "",
          // Optional launch coupon id. Set → checkout pre-applies discounts[0][coupon]
          // (clean checkout→$0); unset → allow_promotion_codes=true (promo-code field).
          // MUST be forwarded or the container's Stripe client can't see it when set.
          STRIPE_LAUNCH_COUPON: ctx.env.STRIPE_LAUNCH_COUPON ?? "",
          ERASURE_ATTESTATION_REGION: ctx.env.ERASURE_ATTESTATION_REGION ?? "",
          // Brutal-audit #1 fix: the single-region assertion flag gates whether a
          // post-deletion attestation may sign with the env-default region. MUST be
          // forwarded or the operator flag silently never reaches the container.
          ERASURE_ATTESTATION_SINGLE_REGION: ctx.env.ERASURE_ATTESTATION_SINGLE_REGION ?? "",
          // corelink-runners auth seam (#261): `POST /internal/v1/auth/introspect`
          // mounts in the container only when FABRIC_INTROSPECT_AUTH_KEY (+ PAT +
          // D1) are present. Forward it or the route stays unmounted (404).
          FABRIC_INTROSPECT_AUTH_KEY: ctx.env.FABRIC_INTROSPECT_AUTH_KEY ?? "",
          // HuGR toolkits introspect consumer (#398): the per-consumer key the
          // container's auth_introspect gate ALSO accepts. Must be forwarded too —
          // else setting the worker secret never reaches the container and HuGR's
          // token 401s (the check-env-contract gap that caught this).
          FABRIC_INTROSPECT_AUTH_KEY_HUGR:
            ctx.env.FABRIC_INTROSPECT_AUTH_KEY_HUGR ?? "",
          // ASK-2 runner billing usage-push ingest: `POST /internal/v1/billing/usage`
          // mounts in the container only when BILLING_INGEST_AUTH_KEY (+ D1) are
          // present. Forward it or the route stays unmounted (404) — the same
          // env-contract class as FABRIC_INTROSPECT_AUTH_KEY above (check-env-contract.py).
          BILLING_INGEST_AUTH_KEY: ctx.env.BILLING_INGEST_AUTH_KEY ?? "",
          // Complete the env contract (2026-06-13 audit): every var the container
          // reads via env::var MUST be forwarded UNCONDITIONALLY, else setting the
          // secret later silently never reaches the container (the class of bug
          // that hid the ERASURE_SALT_KEY gap). Some of these ARE set in prod
          // (verified 2026-08-10: R2_TDK_HEX is populated on prod + all regionals,
          // so CAS uses real per-tenant HMAC prefix derivation — NOT the fallback;
          // the OCI signing key is set under the legacy HUGR_OCI_TOKEN_KEY name
          // below). Others remain unset; forwarding an empty string when a var is
          // unset is a harmless no-op that makes a future secret-set "just work".
          R2_TDK_HEX: ctx.env.R2_TDK_HEX ?? "",
          SIGNUP_TOKEN_KEY: ctx.env.SIGNUP_TOKEN_KEY ?? "",
          // OCI token-mint signing key — read by the container's OCI adapter.
          // (Gap caught by scripts/check-env-contract.py on its first run, 2026-06-13.)
          CORELINK_OCI_TOKEN_KEY: ctx.env.CORELINK_OCI_TOKEN_KEY ?? "",
          // Legacy alias of CORELINK_OCI_TOKEN_KEY (CAA-360 #8 name drift): the
          // prod Worker holds the OCI signing key under HUGR_OCI_TOKEN_KEY, and the
          // container reads it via the routes.rs `.or_else(...)` fallback. Forward
          // it too — otherwise that fallback is a silent no-op (the value never
          // reaches the container). Retire once the prod secret is renamed to the
          // canonical name. See crates/corelink-container/src/routes/oci.rs
          // (OCI_TOKEN_KEY_ENV_LEGACY).
          HUGR_OCI_TOKEN_KEY: ctx.env.HUGR_OCI_TOKEN_KEY ?? "",
          CORELINK_PORTAL_RETURN_URL: ctx.env.CORELINK_PORTAL_RETURN_URL ?? "",
          // B-083 BYOK AWS credentials are dedicated Worker secrets. Forward
          // them byte-for-byte to the native provider; absent values remain
          // empty and make provider construction fail closed before listener
          // bind in the byok-aws-real image.
          CORELINK_BYOK_KMS_ACCESS_KEY_ID:
            ctx.env.CORELINK_BYOK_KMS_ACCESS_KEY_ID ?? "",
          CORELINK_BYOK_KMS_SECRET_ACCESS_KEY:
            ctx.env.CORELINK_BYOK_KMS_SECRET_ACCESS_KEY ?? "",
          CORELINK_BYOK_KMS_SESSION_TOKEN:
            ctx.env.CORELINK_BYOK_KMS_SESSION_TOKEN ?? "",
          // BYOK (enterprise) provider regions/vault — off until explicitly provisioned.
          AWS_REGION: ctx.env.AWS_REGION ?? "",
          GCP_REGION: ctx.env.GCP_REGION ?? "",
          CORELINK_BYOK_AZURE_REGION: ctx.env.CORELINK_BYOK_AZURE_REGION ?? "",
          CORELINK_BYOK_AZURE_VAULT_URL: ctx.env.CORELINK_BYOK_AZURE_VAULT_URL ?? "",
          CORELINK_BYOK_VAULT_REGION: ctx.env.CORELINK_BYOK_VAULT_REGION ?? "",
          // Explicit deploy-time gate for the enterprise scheduler. A binary
          // compiled with a real provider must not make absent customer KMS
          // credentials a fatal dependency of the cache plane.
          CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED:
            ctx.env.CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED ?? "",
          // ADR-MULTI-REGION-V1 — per-region R2 bucket overrides.
          // Absent/empty → container defaults to IAD (corelink-ac-iad / iad).
          // Set by [env.prod-<region>].vars in wrangler.toml.
          R2_AC_BUCKET: ctx.env.R2_AC_BUCKET ?? "",
          R2_AC_REGION: ctx.env.R2_AC_REGION ?? "",
          R2_CHUNK_BUCKET: ctx.env.R2_CHUNK_BUCKET ?? "",
          R2_CHUNK_REGION: ctx.env.R2_CHUNK_REGION ?? "",
          // F7/F8 (2026-06-13 audit) — CAS residency. The container reads
          // R2_CAS_REGION/R2_CAS_BUCKET (`routes/cas.rs:125-126`) but they were
          // NOT forwarded, so the F7 residency fix (set R2_CAS_REGION per
          // regional env) would have silently no-op'd: the operator sets the
          // var, deploy succeeds, container keeps keying CAS under "iad". Each
          // [env.prod-<region>].vars now sets R2_CAS_REGION so EU/regional CAS
          // bytes key to their own region. Absent/empty → container defaults to
          // IAD (corelink-cas-prod / iad).
          R2_CAS_REGION: ctx.env.R2_CAS_REGION ?? "",
          R2_CAS_BUCKET: ctx.env.R2_CAS_BUCKET ?? "",
          // F8 — remaining container-read env vars missing from the forward
          // list: the AC R2 bucket prefix (`dsr/adapter_r2_ac.rs:68`) and the
          // Turborepo bucket (`storage/r2_kv.rs:178`). Unset in prod today
          // (defaults match intended values), but any operator override would
          // silently no-op without these — the ERASURE_SALT_KEY-class bug.
          R2_AC_BUCKET_PREFIX: ctx.env.R2_AC_BUCKET_PREFIX ?? "",
          R2_TURBO_BUCKET: ctx.env.R2_TURBO_BUCKET ?? "",
          // Brutal-audit M3 — container tuning knobs read via a const-aliased
          // `std::env::var(CONST)` (invisible to the old check-env-contract.py
          // string-literal scan, now caught). Each falls back to a built-in
          // default when unset, so an operator `wrangler secret put` was being
          // SILENTLY ignored — the ERASURE_SALT_KEY class. Forward them so an
          // override actually reaches the container (empty ⇒ default, unchanged):
          //   PAT_MINT_MAX_INFLIGHT     routes/internal_pat.rs:165 (MAX_INFLIGHT_MINTS_ENV)
          //   PAT_MINT_MAX_PER_MINUTE   routes/internal_pat.rs:298 (MAX_MINTS_PER_WINDOW_ENV)
          //   QUOTA_COST_PER_OP_MICROS  tenant_quota.rs:98       (COST_PER_OP_MICROS_ENV)
          //   EXPORT_ROW_BUFFER_BYTES   routes/audit_export/stream.rs:320 (ENV_EXPORT_ROW_BUFFER_BYTES)
          PAT_MINT_MAX_INFLIGHT: ctx.env.PAT_MINT_MAX_INFLIGHT ?? "",
          PAT_MINT_MAX_PER_MINUTE: ctx.env.PAT_MINT_MAX_PER_MINUTE ?? "",
          QUOTA_COST_PER_OP_MICROS: ctx.env.QUOTA_COST_PER_OP_MICROS ?? "",
          EXPORT_ROW_BUFFER_BYTES: ctx.env.EXPORT_ROW_BUFFER_BYTES ?? "",
          // F3.2 WP-E — client-side `_public` dedup flag. "0" (Roll-1) keeps
          // client OCI finalize per-tenant; a later roll flips it on. Empty ⇒
          // container default (OFF).
          OCI_PUBLIC_DEDUP_ENABLED: ctx.env.OCI_PUBLIC_DEDUP_ENABLED ?? "",
          OCI_UPSTREAM_ON_MISS: ctx.env.OCI_UPSTREAM_ON_MISS ?? "",
          // #2576: staging admission claims are accepted only for the staging
          // runtime and authenticated with this dedicated staging key.
          CORELINK_ENVIRONMENT: ctx.env.CORELINK_ENVIRONMENT ?? "",
          CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY:
            ctx.env.CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY ?? "",
        },
      });

      // Arm the PLATFORM idle reaper immediately — before the health poll, so
      // a container that starts and then wedges on /_health is still reaped by
      // Cloudflare even if every line below this one fails to run.
      await ctx.armInactivityTimeout(container, requestId);

      // Poll health until container is responsive or timeout
      const healthy = await ctx.waitForContainerHealth(requestId, container);
      if (!healthy) {
        await emitLifecycleEvent(
          ctx.env.PAGERDUTY_ROUTING_KEY ?? "",
          "corelink.do.container_died.v1",
          `CoreLink container failed health check on start for tenant ${tenantHash}`,
          "error",
          tenantHash,
          ctx.doIdHash,
          newColdStartCount,
          ctx.env.ENVIRONMENT,
        );
        // DESTROY, don't just re-label. `container.start()` already ran, so the
        // container may well be RESIDENT (up but wedged on /_health — the R2/S3
        // init alone was measured at 26s+). Marking lifecycle "stopped" without
        // destroying leaves it resident and BILLED with no alarm chain to reap
        // it — the same immortality this fix exists to close, entered through
        // the failure door. (This is the per-DO `container_start_threw` wedge
        // that previously cleared only on an image roll.)
        await ctx.destroyContainer(requestId);
        return { ok: false, reason: "container_health_check_failed" };
      }

      await ctx.updateLifecycleState({
        ...ctx.getLifecycleState(),
        containerStatus: "running",
        lastHealthCheckMs: Date.now(),
        lastActivityMs: Date.now(),
        coldStartCount: newColdStartCount,
      });

      // AUDIT AFTER SUCCESSFUL START
      await emitLifecycleEvent(
        ctx.env.PAGERDUTY_ROUTING_KEY ?? "",
        "corelink.do.container_started.v1",
        `CoreLink container started for tenant ${tenantHash}`,
        "info",
        tenantHash,
        ctx.doIdHash,
        newColdStartCount,
        ctx.env.ENVIRONMENT,
      );

      // Schedule alarm for periodic health checks (which also runs the
      // durable idle reaper — see alarm())
      const nextAlarm = Date.now() + HEALTH_CHECK_INTERVAL_MS;
      await ctx.setAlarm(nextAlarm);

      return { ok: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message.slice(0, 80) : "unknown";

      // ALREADY-RUNNING RACE (mirrors the idempotent-start guard at the top of
      // this method): `container.running` can flip true BETWEEN that guard and
      // this `start()` call (CF's start is async), so start() throws "start()
      // cannot be called on a container that is already running". The container
      // IS up — destroying it here would re-open the exact thrash the guard
      // closes. Treat it as started: health-gate the live container, don't
      // destroy on the throw.
      if (err instanceof Error && /already running/i.test(err.message)) {
        console.warn(
          `[${requestId}] start() raced an already-running container — health-gating instead of destroying`,
        );
        const healthy = await ctx.waitForContainerHealth(requestId, container);
        if (healthy) {
          await ctx.updateLifecycleState({
            ...ctx.getLifecycleState(),
            containerStatus: "running",
            lastHealthCheckMs: Date.now(),
            lastActivityMs: Date.now(),
          });
          return { ok: true };
        }
        await ctx.destroyContainer(requestId);
        return { ok: false, reason: "container_health_check_failed" };
      }

      console.error(`[${requestId}] container start error: ${msg}`);

      await emitLifecycleEvent(
        ctx.env.PAGERDUTY_ROUTING_KEY ?? "",
        "corelink.do.container_died.v1",
        `CoreLink container start threw for tenant ${tenantHash}`,
        "error",
        tenantHash,
        ctx.doIdHash,
        newColdStartCount,
        ctx.env.ENVIRONMENT,
      );

      // DESTROY, don't just re-label — see the health-check arm above: the
      // throw may have happened AFTER container.start() took effect, leaving a
      // resident, billed, un-reapable container.
      await ctx.destroyContainer(requestId);
      return { ok: false, reason: "container_start_threw" };
    }
  }
