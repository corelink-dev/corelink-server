/**
 * Regression lock for the GDPR/LGPD consent surface, which never reached a
 * backend at all.
 *
 * `apps/admin-ui/src/lib/consent-api.ts` handed BARE `/v1/...` paths to
 * `fetch()` from the browser. `/v1` is not a route in this Next app (no `/v1`
 * segment under `src/app`, no rewrite in `next.config.ts`) — it is a path on
 * the SEPARATE `corelink-api` origin. A bare `/v1/...` therefore resolved
 * against the page origin `humangr.com`, and the apex is a DIFFERENT
 * application (the `hugr-site` marketing Pages project). Measured live
 * 2026-08-03:
 *
 *   GET humangr.com/v1/consent/active             -> 200 text/html (marketing)
 *   GET humangr.com/corelink/v1/consent/active    -> 307
 *   GET corelink-api.humangr.com/v1/consent/active-> 401 (the real origin)
 *
 * This is NOT a basePath bug: `/corelink/v1/...` is not a route here either.
 * The calls have to go through the RESOLVED API BASE, the way `CustomerClient`
 * already does.
 *
 * The `200 text/html` is why nobody noticed: the fetch RESOLVES, then
 * `res.json()` throws, so all four consent screens reported a generic error
 * rather than a routing fault.
 *
 * Why the pre-existing suite could not catch this: every consent unit test
 * injects a stub `ConsentApi` (`src/app/[locale]/consent/__tests__/
 * test-utils.tsx`), so `defaultConsentApi` — the only code that builds a URL —
 * was never executed by any test. The test named "calls /v1/consent/history
 * with the correct page + page_size" asserts the QUERY object handed to the
 * stub and never observes a URL. These tests drive the real client.
 */

import * as React from "react";
import { render, cleanup, fireEvent, waitFor, screen } from "@testing-library/react";
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createConsentApi } from "@/lib/consent-api";
import { postConsent, DEFAULT_CONSENT } from "@/lib/consent";
import { ConsentDashboard } from "@/components/consent/ConsentDashboard";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(HERE, "..");
const SRC = path.join(APP_ROOT, "src");

// The consent screens now mint a Clerk session token through `useConsentApi`.
vi.mock("@clerk/nextjs", () => ({
  useAuth: () => ({ getToken: async () => "clerk_session_tok" }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const API = "https://corelink-api.test";

function captureFetch(captured: Array<{ url: string; init?: RequestInit }>, body: unknown): typeof fetch {
  return vi.fn(async (url: string, init?: RequestInit) => {
    captured.push({ url, init });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

// MUST await `fn()` inside the try: the base URL is resolved per request, so a
// non-await-aware helper would restore the env in `finally` before the request
// under test ever read it.
async function withApiUrlEnv<T>(
  value: string | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  const prev = process.env["NEXT_PUBLIC_CORELINK_API_URL"];
  if (value === undefined) delete process.env["NEXT_PUBLIC_CORELINK_API_URL"];
  else process.env["NEXT_PUBLIC_CORELINK_API_URL"] = value;
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env["NEXT_PUBLIC_CORELINK_API_URL"];
    else process.env["NEXT_PUBLIC_CORELINK_API_URL"] = prev;
  }
}

// ---------------------------------------------------------------------------
// 1. All five consent endpoints leave through the resolved API origin.
// ---------------------------------------------------------------------------

describe("consent API origin", () => {
  it("sends every endpoint to the resolved API base, never a bare /v1 path", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    const api = createConsentApi({ baseUrl: API, fetchImpl: captureFetch(captured, []) });

    await api.listActive();
    await api.grant({} as never).catch(() => {});
    await api.withdraw("csn_42", "no longer needed").catch(() => {});
    await api.history({ page: 2, page_size: 20 }).catch(() => {});
    await api.subprocessors().catch(() => {});

    const urls = captured.map((c) => c.url);
    expect(urls).toEqual([
      `${API}/v1/consent/active`,
      `${API}/v1/consent/grant`,
      `${API}/v1/consent/csn_42/withdraw`,
      `${API}/v1/consent/history?page=2&page_size=20`,
      `${API}/v1/subprocessors`,
    ]);
    // The defect shape: a same-origin absolute path. Any of these would be
    // answered by the apex marketing app with 200 text/html.
    for (const u of urls) expect(u.startsWith("/v1/")).toBe(false);
  });

  it("attaches the Clerk session bearer to every consent request", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    const api = createConsentApi({
      baseUrl: API,
      fetchImpl: captureFetch(captured, []),
      getToken: async () => "clerk_session_tok",
    });
    await api.listActive();
    const headers = captured[0]?.init?.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer clerk_session_tok");
  });

  it("sends NO Authorization header when no token supplier is wired (E2E mock parity)", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    const api = createConsentApi({ baseUrl: API, fetchImpl: captureFetch(captured, []) });
    await api.listActive();
    const headers = captured[0]?.init?.headers as Record<string, string>;
    expect(headers["authorization"]).toBeUndefined();
  });

  it("falls back to the basePath-prefixed same-origin /api, never a bare /v1 or bare /api", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    await withApiUrlEnv(undefined, async () => {
      const api = createConsentApi({ fetchImpl: captureFetch(captured, []) });
      await api.listActive();
    });
    expect(captured[0]?.url).toBe("/corelink/api/v1/consent/active");
  });

  it("honours NEXT_PUBLIC_CORELINK_API_URL as the origin (production shape)", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    await withApiUrlEnv("https://corelink-api.humangr.com", async () => {
      const api = createConsentApi({ fetchImpl: captureFetch(captured, []) });
      await api.listActive();
    });
    expect(captured[0]?.url).toBe("https://corelink-api.humangr.com/v1/consent/active");
  });
});

// ---------------------------------------------------------------------------
// 1b. End-to-end client wiring: a consent SCREEN rendered with no injected
//     `api` must reach the real origin WITH the Clerk bearer. This is the leg
//     that `createConsentApi` unit tests cannot prove — before the fix the
//     components defaulted to the module-level `defaultConsentApi`, which
//     carries no token supplier, so the surface could not have authenticated
//     even against a backend that existed.
// ---------------------------------------------------------------------------

describe("consent screens use the session-bound client by default", () => {
  it("ConsentDashboard fetches the resolved origin with the Clerk bearer", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", captureFetch(captured, []));

    await withApiUrlEnv(API, async () => {
      render(<ConsentDashboard locale="en" />);
      await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    });

    expect(captured[0]?.url).toBe(`${API}/v1/consent/active`);
    const headers = captured[0]?.init?.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer clerk_session_tok");
  });
});

// ---------------------------------------------------------------------------
// 1c. The consent routes are NOT under a <ClerkProvider>: the root
//     `src/app/layout.tsx` deliberately mounts none, and only
//     `[locale]/(authenticated)/layout.tsx` does — `[locale]/consent/*` is
//     outside that group, and `/consent/new` is deliberately public/pre-auth.
//     A bare `useAuth()` therefore THROWS and takes all four screens down.
//     This is the regression lock for that crash.
// ---------------------------------------------------------------------------

describe("consent screens survive with no ClerkProvider above them", () => {
  it("renders (unauthenticated) instead of throwing when Clerk is absent", async () => {
    const clerk = await import("@clerk/nextjs");
    const spy = vi.spyOn(clerk, "useAuth").mockImplementation(() => {
      throw new Error(
        "@clerk/nextjs: useAuth can only be used within the <ClerkProvider /> component",
      );
    });

    const captured: Array<{ url: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", captureFetch(captured, []));

    await withApiUrlEnv(API, async () => {
      // Must not throw.
      render(<ConsentDashboard locale="en" />);
      await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    });

    // Still correctly addressed — just with no bearer to send.
    expect(captured[0]?.url).toBe(`${API}/v1/consent/active`);
    const headers = captured[0]?.init?.headers as Record<string, string>;
    expect(headers["authorization"]).toBeUndefined();
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// 2. The cookie-banner consent POST (lib/consent.ts) — same defect.
// ---------------------------------------------------------------------------

describe("postConsent origin", () => {
  it("posts to the resolved API base, not the apex", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    await withApiUrlEnv(API, async () => {
      await postConsent(DEFAULT_CONSENT, captureFetch(captured, { accepted_at: "2026-05-14T12:00:00Z" }));
    });
    expect(captured[0]?.url).toBe(`${API}/v1/consent`);
    expect(captured[0]?.url.startsWith("/v1/")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2b. The sub-processors SERVER page read.
//     It used to try `/v1/subprocessors` (no handler exists anywhere) and
//     render whatever came back, so a list served from elsewhere could
//     disagree with the reviewed bundled list. B-316 (#2593) makes the
//     bundled JSON the only source: the page must not touch the network, even
//     when the API base resolves and would answer with a different list.
// ---------------------------------------------------------------------------

describe("sub-processors server page source", () => {
  it("renders the bundled list and never fetches a remote one", async () => {
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", captureFetch(captured, { version: "9.9.9", items: [] }));

    const mod = await import("@/app/[locale]/privacy/sub-processors/page");
    const { loadSubProcessors } = await import("@/content/load");
    let element: { props: { version: string; items: unknown[] } } | undefined;
    await withApiUrlEnv(API, async () => {
      element = (await mod.default({ params: Promise.resolve({ locale: "en" as never }) })) as never;
    });

    expect(captured).toHaveLength(0);
    const bundled = loadSubProcessors();
    expect(element?.props.version).toBe(bundled.version);
    expect(element?.props.items).toEqual(bundled.items);
    expect(bundled.items.length).toBe(8);
  });
});

// ---------------------------------------------------------------------------
// 3. The imperative confirm-dialog navigation — a genuine basePath bug.
// ---------------------------------------------------------------------------

describe("ConsentDashboard withdraw navigation basePath", () => {
  it("navigates to the /corelink-prefixed withdraw route, not the apex", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { assign, href: "https://humangr.com/corelink/en/consent" });

    const api = {
      listActive: async () => [
        { id: "csn_42", purpose: "billing", granted_at: "2026-04-01", status: "active" as const },
      ],
      grant: async () => ({ consent_id: "", audit_event_id: "", jwt_receipt: "" }),
      withdraw: async () => ({ withdrawn_at: "", jwt_receipt: "" }),
      history: async () => ({ rows: [], total: 0, page: 1 }),
      subprocessors: async () => [],
    };

    render(<ConsentDashboard api={api} locale="en" />);
    const btn = await screen.findByLabelText("Withdraw consent csn_42");
    fireEvent.click(btn);
    fireEvent.click(await screen.findByText("Continue to withdrawal"));

    await waitFor(() => expect(assign).toHaveBeenCalledTimes(1));
    // A bare `/en/consent/withdraw/csn_42` lands on the apex marketing app.
    expect(assign).toHaveBeenCalledWith("/corelink/en/consent/withdraw/csn_42");
  });
});

// ---------------------------------------------------------------------------
// 4. Class-closing guard: no bare `/v1…` literal handed to a network primitive.
// ---------------------------------------------------------------------------

describe("no bare /v1 absolute paths under src/", () => {
  function walk(dir: string, out: string[] = []): string[] {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      // Tests are not shipped code — they legitimately pass bare paths to a
      // client that prefixes the base, and assert on those literals.
      if (e.isDirectory()) {
        if (e.name !== "__tests__") walk(p, out);
      } else if (/\.(ts|tsx)$/.test(e.name) && !/\.(test|spec)\.tsx?$/.test(e.name)) {
        out.push(p);
      }
    }
    return out;
  }

  /**
   * Files whose `/v1…` literals are verified SAFE, with the reason. Every
   * entry was checked by hand; adding one is a review decision.
   */
  const EXEMPT = new Set([
    // Server-side clients that already prefix an API base before the path.
    "src/lib/customer-client.ts", // `request()` prepends resolveBaseUrl()
    "src/lib/admin-client.ts", // same shape
    "src/lib/consent-api.ts", // `request()` prepends resolveApiBaseUrl()
    "src/app/[locale]/onboarding/actions.ts", // "use server" + apiPost() prefixes a base
    "src/app/api/checkout/session/route.ts", // server route handler, apiPost()
    // Same-origin mock server: these ARE this app's own routes.
    "src/lib/e2e-mock-fixtures.ts",
    "src/app/api/v1/[...path]/route.ts",
    // The audit-visualization page prefixes its own base (owned by #983).
    "src/app/[locale]/(authenticated)/customer/audit/visualization/page.tsx",
  ]);

  it("every /v1 literal is either prefixed by an API base or an audited exemption", () => {
    const offenders: string[] = [];
    for (const file of walk(SRC)) {
      const rel = path.relative(APP_ROOT, file);
      if (EXEMPT.has(rel)) continue;
      const lines = fs.readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        // Only string literals that BEGIN with /v1 — a `${base}/v1/...` template
        // does not match, because the literal there starts with `${`.
        if (!/(^|[^$\w])[`"']\/v1(\/|["'`?])/.test(line)) return;
        // Comments and doc-prose reference these paths constantly.
        const t = line.trim();
        if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return;
        offenders.push(`${rel}:${i + 1}: ${t}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});
