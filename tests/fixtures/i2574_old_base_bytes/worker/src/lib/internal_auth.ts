/**
 * Shared inbound internal-auth gate for Worker-hosted internal endpoints.
 *
 * The `/internal/v1/auth/*` Worker routes that githugr's backend calls
 * server-to-server (`tenant/lookup`, `token-exchange`) are gated by a
 * constant-time compare of the caller-supplied `X-Corelink-Internal-Auth`
 * header against the `CORELINK_INTERNAL_AUTH_KEY` binding — the SAME shared
 * secret the container's `/_internal/pat/mint` and the runners-fabric
 * `/internal/v1/auth/introspect` gates use. The browser never holds this
 * secret; only githugr's www server (a trusted backend) does.
 *
 * Posture (fail-CLOSED):
 *   - secret unbound / too short → endpoint unavailable (503, NOT 403 — see
 *     the status-distinction note on `requireInternalAuth` below; a config
 *     fault is an outage, and a 403 is read as a FINAL denial by callers).
 *     We never serve an internal endpoint without a properly sized gate.
 *   - header missing / wrong → 401.
 *   - match → `null` (caller proceeds).
 *
 * The compare mirrors the padded `crypto.subtle.timingSafeEqual` gate index.ts
 * uses for `/_internal/*` (no length oracle; CAA-360 #27). It is replicated
 * locally — like `reapiError` is in the sibling lib modules — to avoid a
 * runtime import cycle (index.ts ⇄ lib/*).
 */

import type { Env } from "../index.js";

/** HTTP header carrying the shared internal-auth secret. */
const INTERNAL_AUTH_HEADER = "x-corelink-internal-auth";

/**
 * Minimum length (chars) of the internal-auth secret. Mirrors the container's
 * `build_state_from_env` floor (`openssl rand -hex 32` → 64 chars; the floor is
 * 32). A shorter/absent secret fails the endpoint CLOSED.
 */
const MIN_INTERNAL_AUTH_KEY_LEN = 32;

/**
 * Internal-auth CONSUMERS — the per-surface key-split axis (red-team #3).
 *
 * Mirrors the container's just-merged Rust split: each distinct internal
 * surface authenticates with its OWN key so that leaking one consumer's secret
 * does not unlock every `/_internal/*` route. Each consumer key FALLS BACK to
 * the shared `CORELINK_INTERNAL_AUTH_KEY` when its dedicated key is UNSET, so the
 * split can be rolled out per-consumer without a flag-day. NOT "unset or short":
 * a dedicated key that is SET but below the floor is refused fail-closed (see
 * {@link resolveConsumerKey}).
 *
 * WHAT THE SHARED KEY ACTUALLY IS. Enumerated exhaustively — re-derive with
 * `grep -rnE 'CORELINK_INTERNAL_AUTH_KEY|resolveConsumerKey|requireConsumerAuth|requireInternalAuth' worker/src/`
 * — the helper names are load-bearing: four of the six inbound gates contain NO
 * occurrence of the variable itself, they reach it through these functions, because a count in prose is
 * a claim and this one was wrong in several successive drafts. It is read in three
 * ROLES (direct reads; indirect re-presentation of an already-resolved key, e.g.
 * `index.ts:1984`, is role 2 by inheritance):
 *
 *   1. INBOUND gate credential, both arms fail-closed:
 *      (a) {@link resolveConsumerKey} — per-consumer. Two call sites: the
 *          `/_internal/*` edge gate (`index.ts`) and {@link requireConsumerAuth},
 *          the latter gating PAT-rotate (`auth_rotate.ts`) and runner mint +
 *          revoke (`runner_mint.ts`) => FOUR gates.
 *      (b) {@link requireInternalAuth} — shared-key ONLY; no per-consumer key
 *          exists for these. Same >= 32 floor, fails closed (503 unbound / 401
 *          mismatch), gating githugr tenant-lookup (`tenant_lookup.ts`) and
 *          session exchange's internal arm (`session_exchange.ts`). NO
 *          per-consumer isolation, so a shared-key holder passes them outright —
 *          the widest INBOUND exposure.
 *      => six inbound gates accept the shared key.
 *   2. OUTBOUND credential presented onward to the container:
 *      `env.<DEDICATED> ?? env.CORELINK_INTERNAL_AUTH_KEY` in `session_exchange.ts`
 *      (x2), `auth_rotate.ts` and `runner_mint.ts` — falls back on UNSET, but
 *      checks only `length === 0`: no >= 32 floor, no fail-closed refusal. AND the
 *      `onboarding` / tier-select-checkout arm in `index.ts`, which resolves
 *      its own money-path dedicated keys with the same 32-char shared fallback
 *      as the Rust container. Non-money onboarding routes retain the shared
 *      onboarding contract.
 *   3. The multi-region fan-out marker (`index.ts`): set on the service-binding
 *      forward and constant-time matched on receipt.
 *
 * `durable_object.ts` propagates the key into the container env; that is plumbing,
 * not a gate. `runner_mint`/`auth_rotate`/`session_exchange` appear in BOTH role 1
 * and role 2 — strict inbound, loose outbound — which is why a per-FILE split of
 * this surface keeps producing wrong sentences. The split is per-ROLE.
 *
 * FROZEN env names (identical to the Rust control-plane side):
 *   - pat_mint    → CORELINK_PAT_MINT_AUTH_KEY    (`/_internal/pat/mint` — signup + clw)
 *   - admin       → CORELINK_ADMIN_AUTH_KEY       (admin `/_internal/*`)
 *   - erase       → CORELINK_ERASE_AUTH_KEY       (erase `/_internal/dsr/*` cascade)
 *   - dsr_anchor  → CORELINK_DSR_ANCHOR_AUTH_KEY  (`/_internal/dsr/anchor` — per-user
 *                                                  DSR legitimacy anchor; held by
 *                                                  githugr, DISTINCT from the eraser's
 *                                                  ERASE key — a two-authority split)
 *   - runner_mint → CORELINK_RUNNER_MINT_AUTH_KEY (`/internal/v1/runner/{mint,revoke}`)
 *
 * `runner_mint` is WORKER-ONLY by design: the runner mint/revoke routes are
 * handled AT the Worker (not proxied to a container `/_internal/*` gate), and the
 * Worker→container mint authority call uses the shared key regardless. Giving the
 * untrusted runner dispatcher its OWN consumer key (distinct from signup's
 * `pat_mint`) means a leaked runner key can ONLY mint/revoke per-job runner PATs —
 * never the signup PAT-mint, erase, or admin surfaces (least privilege, A6).
 *
 * ## A missing key is an OUTAGE (503), not a denial (403) — 2026-08-02
 *
 * Both gates below distinguish two failures that used to share a status:
 *
 *   - the caller presented a wrong/absent header  → **401** (an authz verdict
 *     ABOUT THE CALLER: "you did not prove you may do this")
 *   - no properly-sized key is bound server-side  → **503** (a statement about
 *     US: "this endpoint cannot evaluate authz at all right now")
 *
 * Both still fail CLOSED — nothing is authorized either way. The distinction is
 * for the CALLER's retry logic, and it is load-bearing. The runner dispatcher
 * (corelink-runners `deploy/cloudflare/src/lib.ts`) branches on exactly this: a
 * 403 is treated as a HARD DENY and the job is dropped with no dead-letter and no
 * retry, while any 5xx falls open to a COLD spawn (the job still runs, just
 * without cache warm). GitHub delivers `workflow_job.queued` exactly once, so
 * "dropped" means dropped FOREVER.
 *
 * Under the old 403, an unbound secret therefore ate EVERY runner job in the
 * fleet, permanently and silently — and the only signal was a `spawn_forbidden`
 * counter indistinguishable from ordinary "customer not entitled" traffic. That
 * is a config fault wearing an authz costume; the body already said
 * "unavailable" while the status said "forbidden".
 *
 * This also RESTORES the frozen Rust contract rather than diverging from it: the
 * container returns 503 for the same condition (`routes/internal_pat.rs:21`,
 * ":755", ":785" — "the endpoint is unavailable (503) rather than silently
 * widening to the shared key"). The TypeScript side was the half that drifted.
 */
export type InternalConsumer =
  | "pat_mint"
  | "admin"
  | "erase"
  | "dsr_anchor"
  | "runner_mint"
  | "quota_read"
  | "audit_attempted";

/**
 * Consumers whose gate MUST be a DEDICATED key — a missing dedicated key
 * fail-CLOSES (503) instead of degrading to the shared `CORELINK_INTERNAL_AUTH_KEY`
 * (the shared-master-amplifier the 2026-08-19 red-team surfaced: a leaked shared
 * secret would read any tenant's quota the moment the dedicated quota_read key
 * went unset). Scoped to `quota_read` here — the LOW finding's exact surface, a
 * cross-tenant read whose container gate is also dedicated-only
 * (`tenant_quota_read.rs`). The broader control-plane exposure (pat_mint, erase,
 * dsr_anchor, runner_mint — all already reject the shared key at the edge in prod
 * because their dedicated keys ARE bound) is closed wholesale by the Inc-2
 * `/_internal/*` network lockdown (off the public edge), which makes the
 * shared-master-amplifier moot without churning those consumers' shared-fallback
 * test fixtures. `admin` is intentionally NOT dedicated-required (no dedicated key
 * in prod; runs on the shared key — Inc-2 closes its exposure too).
 */
const DEDICATED_REQUIRED_CONSUMERS: ReadonlySet<InternalConsumer> = new Set([
  "quota_read",
  // `audit_attempted` gates `/_internal/audit/cas-attempted`, whose container
  // gate (`routes/audit_cas_attempted.rs::build_state_from_env`) reads the
  // dedicated key ONLY and has no shared fallback. If the EDGE accepted the
  // shared key here, it would admit a caller the container then rejects — the
  // two gates must agree, and the stricter of the two is the contract.
  "audit_attempted",
]);

/**
 * Resolve the internal-auth key to verify against for a given consumer.
 *
 * Selection (matches the Rust contract exactly):
 *   1. consumer-specific key SET and >= MIN_INTERNAL_AUTH_KEY_LEN → use it;
 *   2. consumer-specific key SET but < MIN → `null`, REFUSING the shared
 *      fallback (fail-CLOSED, logged);
 *   3. consumer-specific key UNSET → the shared key iff >= MIN;
 *   4. else `null` → the caller MUST fail CLOSED (no properly sized gate bound).
 *
 * Arm 2 is the subtle one and this comment used to state its OPPOSITE ("a
 * too-short dedicated key is treated as ABSENT (falls through to the shared
 * key)"). It does not fall through. An operator who sets a dedicated key for a
 * consumer has declared that consumer should be ISOLATED, so silently serving it
 * the broad shared key on a typo would widen the blast radius exactly when the
 * operator was trying to narrow it. A sub-floor secret is a misconfiguration to
 * surface, not one to route around.
 *
 * @returns the chosen key string, or `null` when neither qualifies (fail-CLOSED).
 */
export function resolveConsumerKey(env: Env, consumer: InternalConsumer): string | null {
  const specific =
    consumer === "pat_mint"
      ? env.CORELINK_PAT_MINT_AUTH_KEY
      : consumer === "admin"
        ? env.CORELINK_ADMIN_AUTH_KEY
        : consumer === "erase"
          ? env.CORELINK_ERASE_AUTH_KEY
          : consumer === "dsr_anchor"
            ? env.CORELINK_DSR_ANCHOR_AUTH_KEY
            : consumer === "quota_read"
              ? env.CORELINK_QUOTA_READ_AUTH_KEY
              : consumer === "audit_attempted"
                ? env.CORELINK_AUDIT_ATTEMPTED_AUTH_KEY
                : env.CORELINK_RUNNER_MINT_AUTH_KEY;
  if (specific && specific.length > 0) {
    // A dedicated key was EXPLICITLY provided for this consumer.
    if (specific.length >= MIN_INTERNAL_AUTH_KEY_LEN) {
      return specific;
    }
    // Set but below the floor: a misconfiguration. Do NOT silently fall back to
    // the broad shared key — that would give this consumer a WIDER blast radius
    // than the operator intended (the whole point of a dedicated key is to
    // ISOLATE it). Fail LOUD + fail-CLOSED: this consumer's gate rejects
    // everything until the key is fixed or unset (deep-audit C/sub-floor).
    console.error(
      `[internal-auth] dedicated key for consumer "${consumer}" is set but ` +
        `< ${MIN_INTERNAL_AUTH_KEY_LEN} chars — REFUSING to fall back to the shared ` +
        `CORELINK_INTERNAL_AUTH_KEY (that would silently widen the blast radius). ` +
        `Fix the dedicated key to >= ${MIN_INTERNAL_AUTH_KEY_LEN} chars, or unset it ` +
        `to intentionally use the shared key.`,
    );
    return null;
  }
  // No dedicated key configured for this consumer. For a DEDICATED-REQUIRED
  // consumer this is a fail-CLOSED condition, NOT a licence to serve the broad
  // shared master key (2026-08-19 red-team, "leaked shared internal key →
  // cross-tenant disclosure" + the recurring shared-master-amplifier theme).
  // Silently degrading a privileged consumer to CORELINK_INTERNAL_AUTH_KEY on a
  // missing dedicated key is exactly how a single leaked shared secret unlocks
  // the whole control plane — so a missing dedicated key must 503, never widen.
  // Verified live 2026-08-19: pat_mint/erase/dsr_anchor/quota_read/runner_mint
  // all already reject the shared key at the edge (their dedicated keys ARE
  // bound), so this is a no-op for live traffic and only closes the
  // unset→shared-master regression. `admin` is intentionally NOT dedicated-
  // required: it has no dedicated key in prod and legitimately runs on the
  // shared key (its network exposure is the Inc-2 /_internal/* lockdown).
  if (DEDICATED_REQUIRED_CONSUMERS.has(consumer)) {
    console.error(
      `[internal-auth] no dedicated key bound for dedicated-required consumer ` +
        `"${consumer}" — REFUSING to fall back to the shared ` +
        `CORELINK_INTERNAL_AUTH_KEY (that would silently widen a single leaked ` +
        `shared secret to this privileged surface). Bind its dedicated key.`,
    );
    return null;
  }
  // Shared-allowed consumer (e.g. `admin`) → the shared key IS the intended
  // credential when no dedicated key is configured.
  const shared = env.CORELINK_INTERNAL_AUTH_KEY;
  if (shared && shared.length >= MIN_INTERNAL_AUTH_KEY_LEN) {
    return shared;
  }
  return null;
}

/**
 * Constant-time secret compare WITHOUT a length oracle (CAA-360 #27).
 *
 * The prior `ctEqStr` returned early on `a.length !== b.length`, taking a
 * timing path that depended on the provided length — a (weak) length oracle.
 * This mirrors the padded `crypto.subtle.timingSafeEqual` gate that
 * `index.ts` uses for `/_internal/*`: copy the provided bytes into a fixed
 * buffer sized to the EXPECTED length (zero-pad short input / truncate long
 * input), run exactly ONE `timingSafeEqual` over equal-length buffers, then AND
 * with a single length-equality bit. No branch depends on the provided length,
 * and a wrong length that happens to share the expected prefix is still
 * rejected by the length bit.
 *
 * The caller guarantees `expected` is non-empty (≥ MIN_INTERNAL_AUTH_KEY_LEN).
 *
 * Exported for reuse by the #11 fan-out metering gate in `index.ts`, which must
 * match a server-trusted fan-out marker against `CORELINK_INTERNAL_AUTH_KEY` in
 * constant time (a client-forged value must never match). Same canonical padded
 * `timingSafeEqual` semantics as the `/_internal/*` gate — no hand-rolled compare.
 */
export function constantTimeSecretEqual(expected: string, provided: string): boolean {
  const enc = new TextEncoder();
  const expectedBytes = enc.encode(expected);
  const providedBytes = enc.encode(provided);
  const fixed = new Uint8Array(expectedBytes.length);
  const copyLen =
    providedBytes.length < expectedBytes.length
      ? providedBytes.length
      : expectedBytes.length;
  fixed.set(providedBytes.subarray(0, copyLen));
  const bytesEqual = crypto.subtle.timingSafeEqual(fixed, expectedBytes);
  // Single integer compare (not a per-char path) → no length oracle; a length
  // mismatch can never authenticate even if the prefix bytes match.
  const lenEqual = providedBytes.length === expectedBytes.length;
  return bytesEqual && lenEqual;
}

/**
 * REAPI error envelope builder — local mirror (avoids the index.ts ⇄ lib import
 * cycle, same as the sibling lib modules). Shape is load-bearing:
 * `{ error, message, request_id }` + `X-Request-Id` header.
 */
function reapiError(error: string, message: string, status: number, requestId: string): Response {
  const body = { error, message, request_id: requestId };
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": requestId,
    },
  });
}

/**
 * Gate an inbound request on the shared internal-auth secret.
 *
 * @returns `null` when the caller is authorized (proceed); otherwise a
 *   fail-CLOSED error {@link Response} (**503** if the secret is unbound — an
 *   outage, not a verdict about the caller — 401 if the header is missing/wrong)
 *   that the caller must return verbatim. See the module header for why the
 *   distinction is load-bearing.
 */
export function requireInternalAuth(request: Request, env: Env, requestId: string): Response | null {
  const expected = env.CORELINK_INTERNAL_AUTH_KEY;
  if (!expected || expected.length < MIN_INTERNAL_AUTH_KEY_LEN) {
    // No properly sized secret bound → the internal endpoint is unavailable.
    // Fail CLOSED (never an open gate); do not reveal which precondition failed.
    // 503, NOT 403: nothing about the CALLER failed here, and a client that
    // treats 403 as final would give up on what is a transient config fault.
    return reapiError("SERVICE_UNAVAILABLE", "internal endpoint unavailable", 503, requestId);
  }
  const provided = request.headers.get(INTERNAL_AUTH_HEADER) ?? "";
  if (!constantTimeSecretEqual(expected, provided)) {
    return reapiError("UNAUTHORIZED", "internal auth required", 401, requestId);
  }
  return null;
}

/**
 * Gate an inbound request on a SPECIFIC internal-auth consumer's key.
 *
 * Resolves the consumer's dedicated key via {@link resolveConsumerKey} (the
 * #297 per-consumer-key + shared-fallback pattern): the dedicated key if set and
 * properly sized; `null` if it is SET but sub-floor (REFUSED — never widened to
 * the shared key); the shared `CORELINK_INTERNAL_AUTH_KEY` only when the
 * dedicated key is UNSET; else `null`. A
 * `null` resolution means NO properly sized gate is bound → fail CLOSED (**503**
 * — the endpoint cannot evaluate authz, which is an outage, not a denial).
 *
 * Used by the D-9 runner-mint / runner-revoke routes (`pat_mint` consumer →
 * `CORELINK_PAT_MINT_AUTH_KEY` with shared fallback), mirroring the container's
 * `/_internal/pat/mint` per-consumer gate so leaking one surface's secret does
 * not unlock the rest of the `/internal/*` family.
 *
 * @returns `null` when the caller is authorized (proceed); otherwise a
 *   fail-CLOSED error {@link Response} (**503** if no sized key is bound, 401 if
 *   the header is missing/wrong) that the caller must return verbatim.
 */
export function requireConsumerAuth(
  request: Request,
  env: Env,
  consumer: InternalConsumer,
  requestId: string,
): Response | null {
  const expected = resolveConsumerKey(env, consumer);
  if (expected === null) {
    // Neither the dedicated nor the shared key qualifies → unavailable.
    // Fail CLOSED; do not reveal which precondition failed. 503, NOT 403 — this
    // is the branch that ate every runner job in the fleet when a rotation left
    // a key unbound (see the module header).
    return reapiError("SERVICE_UNAVAILABLE", "internal endpoint unavailable", 503, requestId);
  }
  const provided = request.headers.get(INTERNAL_AUTH_HEADER) ?? "";
  if (!constantTimeSecretEqual(expected, provided)) {
    return reapiError("UNAUTHORIZED", "internal auth required", 401, requestId);
  }
  return null;
}

/**
 * Gate an operator-only endpoint on the dedicated admin key.
 *
 * This is intentionally stricter than {@link requireConsumerAuth}: the normal
 * `admin` consumer preserves the historical shared-key fallback for the
 * container's admin mutation surface, but diagnostic health data must never
 * become available merely because the broad shared key is configured. A
 * missing, empty, or sub-floor `CORELINK_ADMIN_AUTH_KEY` is therefore an
 * unavailable endpoint (503), while a missing or incorrect header is a caller
 * authentication failure (401).
 */
export function requireDedicatedAdminAuth(
  request: Request,
  env: Env,
  requestId: string,
): Response | null {
  const expected = env.CORELINK_ADMIN_AUTH_KEY;
  if (!expected || expected.length < MIN_INTERNAL_AUTH_KEY_LEN) {
    return reapiError("SERVICE_UNAVAILABLE", "internal endpoint unavailable", 503, requestId);
  }
  const provided = request.headers.get(INTERNAL_AUTH_HEADER) ?? "";
  if (!constantTimeSecretEqual(expected, provided)) {
    return reapiError("UNAUTHORIZED", "internal auth required", 401, requestId);
  }
  return null;
}
