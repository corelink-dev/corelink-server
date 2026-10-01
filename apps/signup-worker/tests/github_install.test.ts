import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  INSTALL_STATE_TTL_MS,
  signInstallState,
  verifyInstallState,
} from "../src/webhooks/github_install_state.js";
import {
  exchangeOAuthCode,
  handleInstallGithubCallback,
  mintAppJwt,
  userControlsInstallation,
  type InstallCallbackEnv,
} from "../src/webhooks/github_install_callback.js";
import { handleAppManifestForm } from "../src/webhooks/github_app_manifest.js";

const KEY = "test-install-state-signing-key-0123456789";
const TENANT = "11111111-1111-4111-8111-111111111111";
const NOW = 1_800_000_000_000;

describe("GitHub App manifest URL normalization", () => {
  const longNonTrailingBase = `https://signup.example${"/".repeat(50_000)}x`;
  const cases = [
    ["normal trailing slashes", "https://signup.example///", "https://signup.example"],
    ["no trailing slash", "https://signup.example/path", "https://signup.example/path"],
    ["all slashes", "////", ""],
    ["empty", "", ""],
    ["interior slash run", "https://signup.example/a//b///", "https://signup.example/a//b"],
    ["long slash run followed by non-slash", longNonTrailingBase, longNonTrailingBase],
  ] as const;

  it.each(cases)(
    "preserves manifest base semantics for %s",
    async (_label, baseUrl, expectedBase) => {
      const response = handleAppManifestForm(
        new Request("https://signup.example/install/github/app/new?setup_token=fixture"),
        { GITHUB_APP_SETUP_TOKEN: "fixture", SIGNUP_WORKER_PUBLIC_URL: baseUrl },
      );
      const body = await response.text();
      expect(response.status).toBe(200);
      expect(body).toContain(`${expectedBase}/install/github/callback`);
      expect(body).toContain(`${expectedBase}/install/github/app/created`);
    },
  );
});

describe("install state sign/verify", () => {
  it("round-trips the tenant id within the TTL", async () => {
    const state = await signInstallState(TENANT, KEY, NOW);
    const v = await verifyInstallState(state, KEY, NOW + 1000);
    expect(v).toEqual({ tenantId: TENANT });
  });

  it("rejects a tampered signature", async () => {
    const state = await signInstallState(TENANT, KEY, NOW);
    const tampered = `${state.slice(0, -1)}${state.endsWith("a") ? "b" : "a"}`;
    expect(await verifyInstallState(tampered, KEY, NOW + 1000)).toBeNull();
  });

  it("rejects a swapped tenant id (signature no longer matches)", async () => {
    const state = await signInstallState(TENANT, KEY, NOW);
    const forged = state.replace(TENANT, "22222222-2222-4222-8222-222222222222");
    expect(await verifyInstallState(forged, KEY, NOW + 1000)).toBeNull();
  });

  it("rejects after expiry", async () => {
    const state = await signInstallState(TENANT, KEY, NOW);
    expect(await verifyInstallState(state, KEY, NOW + INSTALL_STATE_TTL_MS + 1)).toBeNull();
  });

  it("rejects a wrong signing key", async () => {
    const state = await signInstallState(TENANT, KEY, NOW);
    expect(await verifyInstallState(state, "different-key", NOW + 1000)).toBeNull();
  });

  it("rejects malformed input", async () => {
    expect(await verifyInstallState("garbage", KEY, NOW)).toBeNull();
    expect(await verifyInstallState("a.b", KEY, NOW)).toBeNull();
    expect(await verifyInstallState("a.notanumber.c", KEY, NOW)).toBeNull();
  });
});

/** Wrap raw PKCS#8 DER bytes into a PEM string (what the secret would hold). */
function pkcs8Pem(der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

describe("App JWT (RS256)", () => {
  it("produces a JWT whose signature verifies against the public key", async () => {
    const kp = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;

    const pem = pkcs8Pem(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    const jwt = await mintAppJwt("424242", pem, NOW);

    const parts = jwt.split(".");
    expect(parts).toHaveLength(3);
    const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

    // Verify the RS256 signature over `${header}.${payload}` with the public key.
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      kp.publicKey,
      b64urlToBytes(sigB64) as unknown as BufferSource,
      signingInput,
    );
    expect(ok).toBe(true);

    // Claims: iss = app id, exp within GitHub's 10-minute cap, iat backdated.
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64))) as {
      iss: string;
      iat: number;
      exp: number;
    };
    expect(payload.iss).toBe("424242");
    const nowS = Math.floor(NOW / 1000);
    expect(payload.iat).toBeLessThan(nowS); // backdated for clock skew
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(10 * 60); // <= GitHub cap
    expect(payload.exp).toBeGreaterThan(nowS);
  });
});

/** Build a minimal `Response`-like stub for the mocked fetch. */
function jsonResp(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

describe("install ownership proof (OAuth) — the public-flip isolation gate", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("exchangeOAuthCode returns the user access token on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        expect(url).toBe("https://github.com/login/oauth/access_token");
        return jsonResp(200, { access_token: "ghu_usertoken123" });
      }),
    );
    expect(await exchangeOAuthCode("Iv23liXXX", "secret", "code123")).toBe("ghu_usertoken123");
  });

  it("exchangeOAuthCode fails CLOSED (null) on a non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResp(401, { error: "bad_verification_code" })));
    expect(await exchangeOAuthCode("Iv23liXXX", "secret", "bad")).toBeNull();
  });

  it("exchangeOAuthCode fails CLOSED (null) when no access_token is returned", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResp(200, { error: "no_token" })));
    expect(await exchangeOAuthCode("Iv23liXXX", "secret", "code")).toBeNull();
  });

  it("userControlsInstallation is TRUE when the installation is in the user's list", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResp(200, { installations: [{ id: 999 }, { id: 144561227 }] })),
    );
    expect(await userControlsInstallation("ghu_tok", "144561227")).toBe(true);
  });

  it("userControlsInstallation is FALSE (hijack blocked) when the installation is NOT the caller's", async () => {
    // The attacker presents a victim's installation id they do not administer.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResp(200, { installations: [{ id: 999 }] })));
    expect(await userControlsInstallation("ghu_attacker", "144561227")).toBe(false);
  });

  it("userControlsInstallation fails CLOSED (false) on a non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResp(403, {})));
    expect(await userControlsInstallation("ghu_revoked", "144561227")).toBe(false);
  });

  it("userControlsInstallation paginates and finds an installation on a later page", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        // page 2 holds the target; page 1 is a full page of 100 non-matching ids
        // (a full page forces the loop to fetch the next). NB: match "&page=2"
        // precisely — "per_page=100" contains the substring "page=1".
        if (url.includes("&page=2")) {
          return jsonResp(200, { installations: [{ id: 144561227 }] });
        }
        return jsonResp(200, { installations: Array.from({ length: 100 }, (_, i) => ({ id: i })) });
      }),
    );
    expect(await userControlsInstallation("ghu_tok", "144561227")).toBe(true);
    expect(calls.some((u) => u.includes("page=2"))).toBe(true);
  });
});

/**
 * The STRUCTURAL public-flip gate (fix/ts-failclosed-middleware-and-oauth-public-gate):
 * "App public" and "OAuth ownership proof enforced" can never diverge. When
 * GITHUB_APP_PUBLIC is set, the callback REQUIRES the OAuth proof — so a public App
 * with unbound OAuth creds is a hard 403 (fail-CLOSED), never a silent skip that
 * would reopen the cross-tenant install-hijack. When NOT public (org-only dogfood),
 * the current skip-when-unbound is preserved.
 *
 * NB: each test uses a DISTINCT installation_id + tenant so the (stubbed) writes
 * never cross-pollinate between cases.
 */
describe("handleInstallGithubCallback — public-flip structural gate", () => {
  afterEach(() => vi.unstubAllGlobals());

  /** A D1 stub that records writes and reports NO prior conflicting row. */
  function makeDbStub(): { db: D1Database; writes: Array<{ sql: string; args: unknown[] }> } {
    const writes: Array<{ sql: string; args: unknown[] }> = [];
    const db = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            return {
              async run() {
                writes.push({ sql, args });
                return { success: true };
              },
              // Conflict-guard read-back: no prior row → null (no conflict).
              async first<T>(): Promise<T | null> {
                return null;
              },
            };
          },
        };
      },
      // No `batch` → writeInstallationProvision uses the sequential `.run()` path.
    } as unknown as D1Database;
    return { db, writes };
  }

  /** Route the GitHub API + OAuth calls the callback makes to canned responses. */
  function stubGithubFetch(installationId: string): void {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === "https://github.com/login/oauth/access_token") {
          return jsonResp(200, { access_token: "ghu_ownertoken" });
        }
        if (url.startsWith("https://api.github.com/user/installations")) {
          return jsonResp(200, { installations: [{ id: Number(installationId) }] });
        }
        if (url.includes("/access_tokens")) {
          return jsonResp(200, { token: "ghs_installtoken" });
        }
        if (url.startsWith("https://api.github.com/installation/repositories")) {
          return jsonResp(200, { repositories: [{ full_name: "octo/repo" }] });
        }
        return jsonResp(404, {});
      }),
    );
  }

  // One RSA key/PEM shared by the "binds" cases (App-JWT mint needs a real PKCS#8).
  let pem = "";
  beforeAll(async () => {
    const kp = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    pem = pkcs8Pem(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  });

  async function callbackUrl(
    installationId: string,
    tenantId: string,
    extra: Record<string, string> = {},
  ): Promise<string> {
    const state = await signInstallState(tenantId, KEY, NOW);
    const params = new URLSearchParams({ installation_id: installationId, state, ...extra });
    return `https://signup.example/install/github/callback?${params.toString()}`;
  }

  function baseEnv(db: D1Database): InstallCallbackEnv {
    return {
      GITHUB_APP_ID: "424242",
      GITHUB_APP_PRIVATE_KEY: pem,
      INSTALL_STATE_SIGNING_KEY: KEY,
      CONFIG_DB: db,
    };
  }

  it.each([
    ["trailing slashes", "https://admin.example///", "https://admin.example"],
    ["no trailing slash", "https://admin.example/path", "https://admin.example/path"],
    ["interior slash run", "https://admin.example/a//b///", "https://admin.example/a//b"],
    ["all slashes", "////", ""],
    ["empty", "", ""],
  ])("preserves redirect base semantics for %s", async (_label, configuredBase, expectedBase) => {
    const { db } = makeDbStub();
    const env = { ...baseEnv(db), ADMIN_UI_PUBLIC_URL: configuredBase };
    const response = await handleInstallGithubCallback(
      new Request("https://signup.example/install/github/callback"),
      env,
    );

    if (expectedBase) {
      expect(response.status).toBe(302);
      const expectedLocation =
        `${expectedBase}/settings/runners?` +
        "runner_install=error&reason=missing%20installation_id%20or%20state";
      expect(response.headers.get("location")).toBe(expectedLocation);
    } else {
      expect(response.status).toBe(502);
      expect(response.headers.get("location")).toBeNull();
    }
  });

  it("keeps an absent redirect base undefined", async () => {
    const { db } = makeDbStub();
    const response = await handleInstallGithubCallback(
      new Request("https://signup.example/install/github/callback"),
      baseEnv(db),
    );
    expect(response.status).toBe(502);
    expect(response.headers.get("location")).toBeNull();
  });

  it("(a) public + OAuth creds UNBOUND → 403 (fail-CLOSED, no bind)", async () => {
    const installationId = "500000001";
    const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const { db, writes } = makeDbStub();
    // Fetch must never be reached — the structural guard returns first.
    const fetchSpy = vi.fn(async () => jsonResp(500, {}));
    vi.stubGlobal("fetch", fetchSpy);

    const env: InstallCallbackEnv = { ...baseEnv(db), GITHUB_APP_PUBLIC: "true" };
    const res = await handleInstallGithubCallback(
      new Request(await callbackUrl(installationId, tenantId)),
      env,
    );

    expect(res.status).toBe(403);
    expect(await res.text()).toContain("app is public but oauth creds are unbound");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(writes).toHaveLength(0);
  });

  it("(b) public + creds BOUND + valid ownership proof → binds", async () => {
    const installationId = "500000002";
    const tenantId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const { db, writes } = makeDbStub();
    stubGithubFetch(installationId);

    const env: InstallCallbackEnv = {
      ...baseEnv(db),
      GITHUB_APP_PUBLIC: "true",
      GITHUB_APP_CLIENT_ID: "Iv23liXXX",
      GITHUB_APP_CLIENT_SECRET: "shhh",
    };
    const res = await handleInstallGithubCallback(
      new Request(await callbackUrl(installationId, tenantId, { code: "oauthcode123" })),
      env,
    );

    expect(res.status).toBe(200);
    // The installation→tenant map row was written under the state-authenticated tenant.
    const mapWrite = writes.find((w) => w.sql.includes("tenant_gh_installation_map"));
    expect(mapWrite).toBeDefined();
    expect(mapWrite?.args).toContain(tenantId);
    expect(mapWrite?.args).toContain(installationId);
  });

  it("(c) NON-public + creds UNBOUND → still binds (org-only dogfood skip preserved)", async () => {
    const installationId = "500000003";
    const tenantId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const { db, writes } = makeDbStub();
    stubGithubFetch(installationId);

    // GITHUB_APP_PUBLIC unset, no client id/secret → the proof is skipped.
    const env = baseEnv(db);
    const res = await handleInstallGithubCallback(
      new Request(await callbackUrl(installationId, tenantId)),
      env,
    );

    expect(res.status).toBe(200);
    const mapWrite = writes.find((w) => w.sql.includes("tenant_gh_installation_map"));
    expect(mapWrite).toBeDefined();
    expect(mapWrite?.args).toContain(tenantId);
  });
});
