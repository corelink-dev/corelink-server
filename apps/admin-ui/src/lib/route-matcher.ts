/**
 * Route matcher used by middleware (WI-S16-001).
 *
 * Returns `true` when the path should be PROTECTED (Clerk auth required).
 * Public exemptions: the `/` landing page, /sign-in, /sign-up,
 * /api/csp-report, /api/health, /api/newsletter/subscribe, /_next/*,
 * /locales/*, static asset prefixes, and the locale-prefixed public
 * marketing/compliance pages (pricing, legal, privacy, security, 403, and the
 * pre-auth consent-capture leaf /consent/new).
 *
 * basePath (`/corelink`) awareness — THE load-bearing invariant:
 *   Next **strips** `basePath` before the middleware runs, so a request to
 *   `humangr.com/corelink/dashboard` arrives here as `/dashboard`. Proven live
 *   2026-08-01: that request 307s with `redirect_url=%2Fdashboard`, the value
 *   the middleware built from `req.nextUrl.pathname`.
 *
 *   This header previously asserted the OPPOSITE — that OpenNext invokes the
 *   middleware with the pathname "STILL CARRYING" the basePath, unlike
 *   `next dev`. That claim was false, it was labelled load-bearing, and it
 *   caused two production outages by being believed:
 *     - `requestBasePath` branched on `startsWith("/corelink")`, never
 *       matched, and 307'd every logged-out user to the apex marketing site;
 *     - `signInRedirectPath` forwarded `returnTo` verbatim as "already
 *       surface-correct", sending the user to marketing AFTER signing in.
 *
 *   Consequences for this file: the MATCHERS are unaffected either way — they
 *   normalize through {@link stripBasePath}, which is idempotent, so a public
 *   path is public in both shapes. Only the RE-ATTACHMENT helpers
 *   ({@link requestBasePath}, {@link signInPathFor}, {@link signInRedirectPath})
 *   depended on the direction, and they now attach unconditionally rather than
 *   inferring the surface from the path. Regression-locked in
 *   tests/route-matcher.test.ts.
 */

/** The path prefix this app is mounted under on the path-based surface. */
export const APP_BASE_PATH = "/corelink";

export const PUBLIC_PATH_PREFIXES: readonly string[] = [
  "/sign-in",
  "/sign-up",
  "/api/csp-report",
  "/api/health",
  // Deliberately public top-of-funnel: the docs site POSTs here
  // cross-origin with no credentials (see the route's CORS notes).
  // Rate-limited per-IP in the route handler.
  "/api/newsletter/subscribe",
  "/_next/",
  "/locales/",
  "/favicon",
  "/robots.txt",
  "/sitemap.xml",
  "/llms.txt",
  "/pricing.txt",
];

/**
 * Public marketing/compliance pages that live under the `/[locale]/`
 * segment (and are also public at their locale-less shape). These must
 * never require auth: they are the pre-signup funnel (docs CTAs, footer
 * legal links) plus the canonical 403 landing RbacGuard links to.
 */
export const PUBLIC_LOCALE_PAGE_PREFIXES: readonly string[] = [
  "/pricing",
  "/legal",
  "/privacy",
  "/security",
  "/403",
  // ⛔ `/[locale]/consent/new` is RETIRED — the PAGE now calls `notFound()`
  // unconditionally (see `app/[locale]/consent/retired.ts`), so this entry no
  // longer serves a consent form to anyone; it makes the anonymous request
  // resolve straight to 404 instead of taking a pointless Clerk round-trip to
  // reach the same 404. It is kept for exactly that reason and because the
  // retirement must live in ONE place: flipping `CONSENT_UI_RETIRED` back to
  // `false` restores the previous behaviour with no edit here.
  //
  // Historical rationale (accurate until the retirement, and the state to
  // return to): the consent-CAPTURE page was a public, pre-auth compliance
  // surface — disclosed-purpose notice + grant form, no `auth()`/user-data
  // read, POSTing only to the backend `/v1/consent/grant`. It was one of the
  // three Lighthouse-audited public routes (S-16 DoD); Lighthouse now audits
  // `/en/pricing` in its place (see `lighthouserc.cjs`).
  // NOTE: intentionally the `/consent/new` LEAF, not the `/consent` tree —
  // `/consent/history` and `/consent/withdraw/:id` are user-specific and MUST
  // stay protected.
  "/consent/new",
];

// Locales per src/i18n/request.ts LOCALES. Kept as a literal so this
// module stays import-free (middleware bundles it for the edge runtime).
const LOCALE_SEGMENT_RE = /^\/(?:en|pt|es|de)(?=\/|$)/;

/**
 * Page routes mounted OUTSIDE `app/[locale]` — they have NO locale-prefixed
 * shape, and building one produces a URL with no matching route.
 *
 * The Clerk auth surfaces live at `app/sign-in/[[...sign-in]]` and
 * `app/sign-up/[[...sign-up]]`, and BOTH widgets pin `path` / `signInUrl` /
 * `signUpUrl` to `${APP_BASE_PATH}/sign-{in,up}` (regression-locked in
 * tests/clerk-basepath.test.tsx) — Clerk's `routing="path"` matches that one
 * literal against `window.location.pathname`, so there is exactly ONE legal
 * shape for these routes and it carries no locale segment.
 *
 * Live consequence of ignoring this (the pricing-CTA funnel break, fixed
 * 2026-08-03): `/corelink/en/sign-up` matches no route, so
 * {@link isPublicPath} classified it PROTECTED and the middleware bounced the
 * brand-new prospect to `/corelink/sign-in?redirect_url=%2Fcorelink%2Fen%2Fsign-up`
 * — the sign-IN screen, with a return target that does not exist. Every
 * "start free / upgrade" CTA on the public pricing page pointed there.
 *
 * Consumed by {@link isLocaleLessPath} (link builders) and
 * {@link canonicalAuthPathFor} (the middleware's self-healing redirect).
 */
export const LOCALE_LESS_PAGE_PREFIXES: readonly string[] = [
  "/sign-in",
  "/sign-up",
];

/**
 * True when `href` targets a route that exists ONLY in its locale-less shape
 * (see {@link LOCALE_LESS_PAGE_PREFIXES}) — i.e. a link builder must NOT
 * prepend a locale segment to it. Query/hash tolerant; basePath tolerant.
 */
export function isLocaleLessPath(href: string): boolean {
  const pathname = stripBasePath(href.split("?")[0]!.split("#")[0]!);
  for (const prefix of LOCALE_LESS_PAGE_PREFIXES) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return true;
  }
  return false;
}

/**
 * Self-healing canonicalization for the locale-prefixed auth URLs that have no
 * route: given a middleware pathname, return the surface-correct
 * (basePath-carrying) locale-LESS target, or `null` when the path is already
 * canonical / is not an auth path.
 *
 * This is the safety net behind the {@link LOCALE_LESS_PAGE_PREFIXES} fix: the
 * link builders now emit `/sign-up`, but any URL already in the wild (a
 * bookmark, an email, a stale `redirect_url`) would otherwise keep landing the
 * prospect on the sign-IN screen. Redirecting is strictly better than the
 * alternatives — a 404 is still a dead funnel, and making the locale shape
 * *render* would need a second Clerk mount fighting `routing="path"`.
 */
export function canonicalAuthPathFor(pathname: string): string | null {
  const stripped = stripBasePath(pathname || "/");
  // Only act when a locale segment is actually present — otherwise the
  // canonical path is what we were given and redirecting would loop.
  if (!LOCALE_SEGMENT_RE.test(stripped)) return null;
  const delocalized = stripped.replace(LOCALE_SEGMENT_RE, "") || "/";
  if (!isLocaleLessPath(delocalized)) return null;
  return `${requestBasePath(pathname)}${delocalized}`;
}

/**
 * Reduce a raw middleware pathname to its app-relative shape by removing the
 * `basePath` prefix. Tolerates the basePath being:
 *   - present  → `/corelink/sign-up`  (prod / OpenNext — the real shape)
 *   - absent   → `/sign-up`           (dev / `next dev` / unit tests)
 *   - doubled  → `/corelink/corelink/…` (defensive vs a future rewrite)
 * and returns "/" for the bare app root (`/corelink` or `/corelink/`).
 */
function stripBasePath(pathname: string): string {
  let p = pathname || "/";
  while (p === APP_BASE_PATH || p.startsWith(`${APP_BASE_PATH}/`)) {
    p = p.slice(APP_BASE_PATH.length) || "/";
  }
  return p;
}

/**
 * Paths that MUST run `clerkMiddleware` (so the server-side `auth()`
 * probe resolves) but own their signed-out handling themselves — the
 * middleware must NOT `auth.protect()` them. `/upgrade` performs its own
 * `/sign-in?redirect_url=…` round-trip preserving `?plan=` (see
 * `[locale]/upgrade/page.tsx` — it gates on exactly the predicate the
 * checkout POST authenticates with).
 */
export const SELF_GATED_PAGE_PREFIXES: readonly string[] = ["/upgrade"];

function matchesPagePrefix(pathname: string, prefixes: readonly string[]): boolean {
  const delocalized = stripBasePath(pathname).replace(LOCALE_SEGMENT_RE, "") || "/";
  for (const prefix of prefixes) {
    if (delocalized === prefix || delocalized.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  return false;
}

export function isPublicPath(pathname: string): boolean {
  const normalized = stripBasePath(pathname);
  // The root landing page is the public top-of-funnel (signup CTA target).
  if (normalized === "/") return true;
  for (const prefix of PUBLIC_PATH_PREFIXES) {
    // A public prefix is a path segment, not an arbitrary string prefix:
    // `/sign-in-evil` and `/api/healthcheck` must remain protected.
    // Normalize a trailing slash first so both `/locales/en` and a configured
    // `/locales/` prefix use the same boundary rule.
    const barePrefix = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
    if (normalized === barePrefix || normalized.startsWith(`${barePrefix}/`)) return true;
  }
  return matchesPagePrefix(normalized, PUBLIC_LOCALE_PAGE_PREFIXES);
}

/** See {@link SELF_GATED_PAGE_PREFIXES}. */
export function isSelfGatedPath(pathname: string): boolean {
  return matchesPagePrefix(pathname, SELF_GATED_PAGE_PREFIXES);
}

export function isProtectedPath(pathname: string): boolean {
  return !isPublicPath(pathname);
}

/**
 * The mount prefix a hand-built redirect must re-attach. Always
 * {@link APP_BASE_PATH} — the app is served on exactly ONE surface.
 *
 * This used to branch on whether `pathname` already carried `/corelink`, to
 * support the subdomain→path migration where the app answered on BOTH
 * the retired `corelink-app` subdomain (no prefix) and `humangr.com/corelink/*`. That
 * branch was wrong in production for two independent reasons, and the two
 * cancelled out into a silent breakage:
 *
 *   1. **Next strips `basePath` BEFORE middleware runs.** A request to
 *      `humangr.com/corelink/dashboard` reaches the middleware as `/dashboard`,
 *      so the `startsWith("/corelink")` test never matched and the function
 *      always returned "" — the branch written for the subdomain.
 *   2. **The subdomain surface is retired.** Both `corelink-app` and
 *      `corelink-admin` had their `custom_domain` bindings removed
 *      (`apps/admin-ui/wrangler.toml`), so the no-prefix surface the ""
 *      branch existed for no longer answers at all.
 *
 * Live consequence before this fix: `/corelink/dashboard` 307'd to
 * `humangr.com/sign-in`, which is the APEX MARKETING SITE (a different app,
 * 42 KB landing page) rather than this app's sign-in at `/corelink/sign-in`.
 * Every logged-out user sent to a protected route landed on marketing — the
 * user-visible "signup is broken" report.
 *
 * The unit tests did not catch it: they fed `signInPathFor` a pathname WITH the
 * prefix (an input the middleware never receives in production), and the
 * companion case asserted the no-prefix output as correct.
 *
 * (Next only auto-applies `basePath` to framework-generated links, never to
 * URLs the middleware builds by hand — hence the manual re-attachment.)
 */
export function requestBasePath(_pathname: string): string {
  return APP_BASE_PATH;
}

/** Surface-correct, app-absolute `/sign-in` path for the request's pathname. */
export function signInPathFor(pathname: string): string {
  return `${requestBasePath(pathname)}/sign-in`;
}

/**
 * Build the middleware's sign-in redirect target, preserving the post-auth
 * return URL.
 *
 * **`returnTo` is re-attached to the basePath, NOT passed through verbatim.**
 * It used to be forwarded raw, on the belief that the middleware's
 * `req.nextUrl.pathname` was "already surface-correct" — the same false premise
 * that broke {@link requestBasePath}. Next strips `basePath` before middleware
 * runs, so the caller's `pathname + search` is basePath-LESS, and the value
 * shipped to production was:
 *
 *     GET /corelink/dashboard
 *       -> 307 /corelink/sign-in?redirect_url=%2Fdashboard
 *                                             ^^^^^^^^^^^ apex, not this app
 *
 * `redirect_url` is consumed by **Clerk**, which navigates with a plain
 * assignment rather than Next's router — so nothing re-attaches the prefix
 * downstream, and `humangr.com/dashboard` is the hugr-site marketing landing
 * (HTTP 200, a different app). The sign-in PAGE was correct while the place it
 * sent you AFTER signing in was not: the funnel broke one hop later.
 *
 * Normalization is strip-then-attach, so it is idempotent and a caller that
 * already prefixed its own value cannot produce `/corelink/corelink/…`.
 */
export function signInRedirectPath(pathname: string, returnTo?: string): string {
  const base = signInPathFor(pathname);
  if (!returnTo) return base;
  const appAbsolute = `${requestBasePath(pathname)}${stripBasePath(returnTo)}`;
  return `${base}?redirect_url=${encodeURIComponent(appAbsolute)}`;
}

/**
 * Prefix an INTERNAL absolute href with the app {@link APP_BASE_PATH}, for the
 * hand-built links Next does NOT auto-basePath (a raw `<a href>` or the kit
 * `<Button href>` anchor — see the module header: Next only auto-applies
 * `basePath` to framework-generated links like `next/link`/`router.push`, never
 * to hrefs built by hand). Without this a `<Button href="/upgrade">` /
 * `<a href="/api/install/github">` navigates to `humangr.com/upgrade` (the apex
 * marketing site), NOT `humangr.com/corelink/upgrade` — the class of bug that
 * broke the runner Install button.
 *
 * Left UNTOUCHED: external (`http(s):`, `mailto:`, protocol-relative `//`),
 * hash-only (`#…`), relative (no leading `/`), and already-prefixed
 * (`/corelink…`) hrefs. Idempotent.
 */
export function withAppBasePath(href: string): string {
  if (!href.startsWith("/") || href.startsWith("//")) {
    return href; // relative, protocol-relative, or non-path (mailto:/http:) — leave as-is.
  }
  if (href === APP_BASE_PATH || href.startsWith(`${APP_BASE_PATH}/`)) {
    return href; // already prefixed — idempotent, never double-prefix.
  }
  return `${APP_BASE_PATH}${href}`;
}
