/**
 * GitHub App install callback — the identity-gated install→map provisioning
 * (Option B: the signup-worker owns the install flow end-to-end).
 *
 * Flow: a Clerk-authed tenant clicks "Install" (admin-ui) → CoreLink mints a
 * signed `state = tenant_id` ([`./github_install_state`]) → GitHub App install →
 * GitHub redirects here (the App's `setup_url`) with `installation_id` + `state`.
 * This handler:
 *   1. VERIFIES the signed state → the authenticated `tenant_id` (403 if bad —
 *      NEVER binds a tenant off the raw installation id alone; that is the
 *      lazy-provision DP3 forbids).
 *   1b. PROVES installation ownership when OAuth creds are bound: exchanges the
 *      install-time OAuth `code` for a user token and requires the presented
 *      `installation_id` to be in the caller's `GET /user/installations` (403 if
 *      not) — the airtight isolation gate that makes flipping the App public safe.
 *   2. Mints a short-lived App JWT (RS256) and exchanges it for an installation
 *      access token, then lists the installation's repositories.
 *   3. Persists `tenant_gh_installation_map` + `runner_repo_allowlist` via the
 *      shared idempotent write ([`./github_provision.writeInstallationProvision`]).
 *   4. Redirects the browser back to the admin-ui with a result flag.
 *
 * Inert (503) until `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY` (PKCS#8 PEM) +
 * `INSTALL_STATE_SIGNING_KEY` are bound.
 */

import { writeInstallationProvision } from "./github_provision.js";
import { verifyInstallState } from "./github_install_state.js";
import { signupOwnershipContext } from "../signup_writer_ownership.js";
import type { StagingOwnershipContext } from "../staging_load_test_ownership.js";

export interface InstallCallbackEnv {
  /** Deployment environment and staging-only admission signing key. */
  ENVIRONMENT?: string;
  CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY?: string;
  /** Numeric GitHub App id (`iss` of the App JWT). */
  GITHUB_APP_ID?: string;
  /** App private key, **PKCS#8** PEM (`-----BEGIN PRIVATE KEY-----`). */
  GITHUB_APP_PRIVATE_KEY?: string;
  /** HMAC key for the signed install `state` (shared with the admin-ui mint). */
  INSTALL_STATE_SIGNING_KEY?: string;
  /**
   * GitHub App OAuth **client id** (public identifier, e.g. `Iv23li…`). When this
   * AND {@link GITHUB_APP_CLIENT_SECRET} are bound, the callback REQUIRES an OAuth
   * `code` (from "Request user authorization (OAuth) during installation") and
   * PROVES the caller controls the installation before binding it — the airtight
   * isolation gate that lets the App be flipped **public** for real self-serve.
   */
  GITHUB_APP_CLIENT_ID?: string;
  /** GitHub App OAuth **client secret** (paired with {@link GITHUB_APP_CLIENT_ID}). */
  GITHUB_APP_CLIENT_SECRET?: string;
  /**
   * "The App is (or is being) flipped **public**" signal (`"true"`/`"1"`). When
   * set, the callback REQUIRES the OAuth ownership proof and returns `403` if
   * {@link GITHUB_APP_CLIENT_ID}/{@link GITHUB_APP_CLIENT_SECRET} are unbound —
   * so "App public" and "ownership proof enforced" can NEVER diverge (a public
   * App with unbound OAuth creds is a cross-tenant install-hijack window). Unset
   * / falsey ⇒ the `public:false` org-only dogfood path, where the proof is
   * skipped when the creds are unbound (only org members can install).
   */
  GITHUB_APP_PUBLIC?: string;
  /** D1 binding holding the installation map + repo allowlist (0084/0085). */
  CONFIG_DB?: D1Database;
  /** admin-ui base to redirect back to after provisioning (optional). */
  ADMIN_UI_PUBLIC_URL?: string;
}

const GH_API = "https://api.github.com";

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return value.slice(0, end);
}

/** base64url (no padding) of raw bytes. */
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url of a JSON value's UTF-8 encoding. */
function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Decode a PKCS#8 PEM into its DER bytes for WebCrypto `importKey`. */
function pkcs8DerFromPem(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}

/**
 * Mint a short-lived RS256 App JWT (`iss`=app id, ~9-minute window with a 60s
 * backdated `iat` to tolerate clock skew — GitHub caps the App JWT at 10m).
 */
export async function mintAppJwt(
  appId: string,
  privateKeyPem: string,
  nowMs: number,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    // Workers accepts the ArrayBufferLike view returned by this decoder;
    // TS 6's lib.dom declaration is narrower than the runtime contract.
    pkcs8DerFromPem(privateKeyPem) as unknown as BufferSource,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const nowS = Math.floor(nowMs / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iat: nowS - 60, exp: nowS + 9 * 60, iss: appId };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${b64url(sig)}`;
}

const GH_HEADERS = {
  accept: "application/vnd.github+json",
  "user-agent": "corelink-signup-worker",
  "x-github-api-version": "2022-11-28",
} as const;

/** Exchange the App JWT for an installation access token. */
async function installationToken(jwt: string, installationId: string): Promise<string | null> {
  const resp = await fetch(
    `${GH_API}/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
    { method: "POST", headers: { ...GH_HEADERS, authorization: `Bearer ${jwt}` } },
  );
  if (!resp.ok) return null;
  const body = (await resp.json().catch(() => null)) as { token?: string } | null;
  return typeof body?.token === "string" ? body.token : null;
}

/** List the installation's repositories as `owner/repo` full names (paginated). */
async function installationRepos(token: string): Promise<string[]> {
  const out: string[] = [];
  for (let page = 1; page <= 10; page++) {
    const resp = await fetch(`${GH_API}/installation/repositories?per_page=100&page=${page}`, {
      headers: { ...GH_HEADERS, authorization: `Bearer ${token}` },
    });
    if (!resp.ok) break;
    const body = (await resp.json().catch(() => null)) as {
      repositories?: Array<{ full_name?: string }>;
    } | null;
    const repos = body?.repositories ?? [];
    for (const r of repos) {
      if (typeof r.full_name === "string" && r.full_name.length > 0) out.push(r.full_name);
    }
    if (repos.length < 100) break; // last page
  }
  return out;
}

const GH_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";

/**
 * Exchange the install-time OAuth `code` for a **user**-access-token. This is the
 * token that speaks for the human who performed the install (NOT the App), so it
 * is what lets us prove installation ownership. Returns null on any failure
 * (fail-CLOSED: an un-exchangeable code proves nothing → the caller denies).
 */
export async function exchangeOAuthCode(
  clientId: string,
  clientSecret: string,
  code: string,
): Promise<string | null> {
  const resp = await fetch(GH_OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "corelink-signup-worker",
    },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
  });
  if (!resp.ok) return null;
  const body = (await resp.json().catch(() => null)) as { access_token?: string } | null;
  return typeof body?.access_token === "string" && body.access_token.length > 0
    ? body.access_token
    : null;
}

/**
 * PROVE the OAuth'd user controls `installationId`: an installation appears in
 * `GET /user/installations` ONLY for a user who can administer it (GitHub gates
 * app installation on repo/org admin). So requiring the presented `installation_id`
 * to be in the caller's own installation list closes the cross-tenant hijack — a
 * tenant can no longer bind an installation they do not administer. Fail-CLOSED:
 * a non-OK response (revoked/insufficient token) returns false (deny), never a
 * silent pass.
 */
export async function userControlsInstallation(
  userToken: string,
  installationId: string,
): Promise<boolean> {
  const target = String(installationId);
  for (let page = 1; page <= 10; page++) {
    const resp = await fetch(`${GH_API}/user/installations?per_page=100&page=${page}`, {
      headers: { ...GH_HEADERS, authorization: `Bearer ${userToken}` },
    });
    if (!resp.ok) return false; // fail-CLOSED: cannot prove ownership → deny
    const body = (await resp.json().catch(() => null)) as {
      installations?: Array<{ id?: number }>;
    } | null;
    const list = body?.installations ?? [];
    for (const inst of list) {
      if (inst && String(inst.id) === target) return true;
    }
    if (list.length < 100) break; // last page
  }
  return false;
}

/** Redirect the browser back to the admin-ui (or a plain 200) with a result. */
function done(env: InstallCallbackEnv, ok: boolean, detail: string): Response {
  const configuredBase = env.ADMIN_UI_PUBLIC_URL;
  const base =
    configuredBase === undefined || configuredBase === null
      ? undefined
      : trimTrailingSlashes(configuredBase);
  if (base) {
    const q = ok ? "runner_install=ok" : `runner_install=error&reason=${encodeURIComponent(detail)}`;
    return new Response(null, { status: 302, headers: { location: `${base}/settings/runners?${q}` } });
  }
  return new Response(ok ? "runner install provisioned" : `runner install failed: ${detail}`, {
    status: ok ? 200 : 502,
    headers: { "cache-control": "no-store" },
  });
}

/**
 * `GET /install/github/callback?installation_id=…&state=…&setup_action=install`
 */
export async function handleInstallGithubCallback(
  request: Request,
  env: InstallCallbackEnv,
): Promise<Response> {
  const appId = env.GITHUB_APP_ID;
  const privateKey = env.GITHUB_APP_PRIVATE_KEY;
  const stateKey = env.INSTALL_STATE_SIGNING_KEY;
  const db = env.CONFIG_DB;
  if (!appId || !privateKey || !stateKey || !db) {
    // Inert until fully configured — never partial-provision.
    return new Response("github app install flow not configured", { status: 503 });
  }

  const url = new URL(request.url);
  let ownershipContext: StagingOwnershipContext | null;
  try {
    ownershipContext = await signupOwnershipContext(
      request,
      env.ENVIRONMENT,
      env.CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY,
    );
  } catch {
    return new Response("invalid_staging_ownership", { status: 403 });
  }
  const installationId = url.searchParams.get("installation_id");
  const state = url.searchParams.get("state");
  if (!installationId || !state) {
    return done(env, false, "missing installation_id or state");
  }

  // 1. IDENTITY: the signed state is the ONLY authenticated tenant binding.
  const verified = await verifyInstallState(state, stateKey, Date.now());
  if (!verified) {
    return new Response("invalid or expired install state", { status: 403 });
  }
  const tenantId = verified.tenantId;

  // 1b. OWNERSHIP PROOF (PREVENTION — the public-flip gate). The signed state
  //     proves the TENANT but NOT that this tenant performed THIS installation.
  //     When the App's OAuth credentials are bound, the caller MUST also present a
  //     valid install-time OAuth `code` ("Request user authorization during
  //     installation"): we exchange it for a USER token and require the presented
  //     `installation_id` to appear in that user's own `GET /user/installations`.
  //     A user can only list an installation they administer, so a tenant can no
  //     longer bind another party's installation to themselves (turns the #633
  //     DETECTION into real PREVENTION, and is what makes flipping the App public
  //     safe). Fail-CLOSED: creds bound but no code / bad exchange / not-controlled
  //     ⇒ 403, before any App-JWT mint or D1 write. When the creds are UNBOUND the
  //     check is skipped — that path is the `public:false` org-only dogfood, where
  //     only org members can install in the first place.
  const clientId = env.GITHUB_APP_CLIENT_ID;
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET;

  // STRUCTURAL GUARD (fail-CLOSED): if the App is public, the ownership proof is
  // MANDATORY. Skipping the proof is only safe on the `public:false` org-only
  // dogfood path (where GitHub itself limits who can install). If the App has
  // been flipped public but the OAuth creds are not yet bound, the proof below
  // would be silently skipped — reopening the cross-tenant install-hijack the
  // proof exists to close (binding rests only on a signed state + an enumerable
  // query-string installation_id). So "App public" and "proof enforced" are tied
  // together here: public + unbound creds ⇒ 403, before any App-JWT mint or D1
  // write. This makes it impossible to ship a public App without the gate.
  const appIsPublic =
    env.GITHUB_APP_PUBLIC === "true" || env.GITHUB_APP_PUBLIC === "1";
  if (appIsPublic && !(clientId && clientSecret)) {
    return new Response(
      "install ownership proof required: app is public but oauth creds are unbound",
      { status: 403 },
    );
  }

  if (clientId && clientSecret) {
    const code = url.searchParams.get("code");
    if (!code) {
      return new Response("install ownership proof required: missing oauth code", { status: 403 });
    }
    try {
      const userToken = await exchangeOAuthCode(clientId, clientSecret, code);
      if (!userToken) {
        return new Response("install ownership proof failed: oauth exchange", { status: 403 });
      }
      if (!(await userControlsInstallation(userToken, installationId))) {
        return new Response(
          "install ownership proof failed: caller does not control this installation",
          { status: 403 },
        );
      }
    } catch (e) {
      return done(env, false, `ownership check error: ${(e as Error).message}`);
    }
  }

  // 2. Mint the App JWT → installation token → repos.
  let repos: string[];
  try {
    const jwt = await mintAppJwt(appId, privateKey, Date.now());
    const token = await installationToken(jwt, installationId);
    if (!token) {
      console.error(
        `install callback: installation-token exchange returned no token installation_id=${installationId} (App JWT / GITHUB_APP_ID / private key?)`,
      );
      return done(env, false, "installation token exchange failed");
    }
    repos = await installationRepos(token);
  } catch (e) {
    console.error(
      `install callback: github api error installation_id=${installationId}: ${(e as Error).message}`,
    );
    return done(env, false, `github api error: ${(e as Error).message}`);
  }

  // 3. Persist the map + allowlist (idempotent, shared write path).
  // OBSERVABILITY: a live self-serve install returned 200 while provisioning
  // NOTHING (map row absent), and the catch below previously SWALLOWED the D1
  // error — leaving the callback un-debuggable from a `wrangler tail`. Log the
  // persist boundary (no token/state material — INV-NO-PII-IN-LOGS) so the exact
  // failure surfaces. `repos.length === 0` is itself a signal (App-token could
  // not enumerate the installation's repos ⇒ nothing to allowlist).
  try {
    console.log(
      `install callback: persisting installation_id=${installationId} tenant=${tenantId} repos=${repos.length}`,
    );
    await writeInstallationProvision(db, {
      installationId,
      tenantId,
      repos,
      nowMs: Date.now(),
      ownershipContext,
    });
    console.log(
      `install callback: persist OK installation_id=${installationId} repos=${repos.length}`,
    );
  } catch (e) {
    console.error(
      `install callback: persist FAILED installation_id=${installationId} tenant=${tenantId}: ${
        (e as Error).message
      }`,
    );
    return done(env, false, "provision persist failed");
  }

  // 4. Conflict guard (launch-audit HIGH — DETECTION half). The map's
  //    `installation_id` is a PRIMARY KEY written `INSERT OR IGNORE`
  //    (first-writer-wins). The signed state proves the TENANT but NOT that this
  //    tenant controls this installation — a caller could present another party's
  //    `installation_id`. So after the write, verify the row now bound points at
  //    THIS tenant; if a DIFFERENT tenant already owns the installation, refuse to
  //    report success, so a hijacked/mismatched binding surfaces as an error
  //    instead of being silently accepted. Best-effort: only a CONFIRMED
  //    cross-tenant row fails the callback (a read fault never blocks a legitimate
  //    provision — the honest flow always binds its own tenant, incl. `setup_url`
  //    re-provisions). FULL PREVENTION — proving the state-tenant owns the
  //    installation's GitHub account — needs a tenant↔GitHub-account link and
  //    GATES flipping the App public (see docs/knowledge/flows/runner-github-install).
  try {
    const bound = await db
      .prepare("SELECT tenant_id FROM tenant_gh_installation_map WHERE installation_id = ?1")
      .bind(installationId)
      .first<{ tenant_id: string }>();
    if (bound && bound.tenant_id !== tenantId) {
      return done(env, false, "installation is bound to a different tenant");
    }
  } catch {
    // Detection is best-effort; a read fault must not break a valid provision.
  }

  return done(env, true, `${repos.length} repos`);
}
