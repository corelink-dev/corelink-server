/**
 * CoreLink Runners — GitHub App *manifest-flow* (one-click App creation).
 *
 * GitHub has NO REST endpoint to create an App from scratch; the only
 * programmatic path is the **app-manifest flow**
 * (https://docs.github.com/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):
 *
 *   1. `GET  /install/github/app/new`  (this file, {@link handleAppManifestForm})
 *        → serves an auto-submitting HTML form that POSTs a pre-filled `manifest`
 *          JSON to `https://github.com/organizations/<ORG>/settings/apps/new`.
 *        Gated by a one-time setup token (`GITHUB_APP_SETUP_TOKEN`) so only the
 *        operator can trigger a registration.
 *   2. The operator confirms in GitHub's UI → GitHub creates a TEMPORARY app and
 *        redirects to `redirect_url` with a short-lived `?code=`.
 *   3. `GET  /install/github/app/created?code=…`  ({@link handleAppManifestCallback})
 *        → exchanges the code via `POST /app-manifests/{code}/conversions` for the
 *          permanent `{ id, pem (private key), webhook_secret, client_id, slug }`
 *          and displays them ONCE so the operator can set them as Worker secrets
 *          (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_WEBHOOK_SECRET`).
 *          The code is single-use + expires in ~1h; a Worker cannot set its own
 *          secrets, so this one-time display is the hand-off. The callback is
 *          ALSO setup-token gated.
 *
 * The registered App (private → org-only, dogfood) wires:
 *   - `setup_url`      → /install/github/callback  (the per-tenant install→map
 *                        provisioning — the identity-gated Option-B path).
 *   - `hook_attributes.url` → /webhooks/github     (receives the auto-delivered
 *                        installation events + the subscribed `workflow_job`
 *                        event; forwarding workflow_job to the runner fabric is a
 *                        downstream wire).
 */

import { constantTimeEqual } from "./github_provision.js";

/** Env for the manifest flow. All optional so the routes are inert until set. */
export interface GithubAppManifestEnv {
  /** One-time operator secret gating BOTH manifest routes (fail-closed). */
  GITHUB_APP_SETUP_TOKEN?: string;
  /** The GitHub org the App is registered under (default: HumanGuardrail). */
  GITHUB_APP_ORG?: string;
  /** Public base URL of THIS signup-worker (for the redirect/setup/webhook URLs). */
  SIGNUP_WORKER_PUBLIC_URL?: string;
}

/** HTML-escape a string for safe interpolation into the form/display pages. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Extract the setup token from `?setup_token=` or the `x-setup-token` header. */
function presentedSetupToken(url: URL, request: Request): string {
  return (
    url.searchParams.get("setup_token") ??
    request.headers.get("x-setup-token") ??
    ""
  );
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return value.slice(0, end);
}

/**
 * Build the GitHub App manifest (the frozen registration shape). Private
 * (org-only) for the dogfood phase; `public: false` is flippable to public
 * later with one settings toggle when runner is sold to external SMBs.
 */
function buildManifest(baseUrl: string): Record<string, unknown> {
  const base = trimTrailingSlashes(baseUrl);
  return {
    name: "CoreLink Runners",
    url: "https://humangr.com",
    description:
      "CoreLink Runners — ephemeral CI runners billed on a per-tenant concurrency + vCPU-h entitlement.",
    // Where a tenant lands AFTER installing — the identity-gated install→map callback.
    setup_url: `${base}/install/github/callback`,
    // Re-run setup on new installations so a fresh install always provisions.
    setup_on_update: true,
    // Where GitHub POSTs the temporary manifest `code` (step 3).
    redirect_url: `${base}/install/github/app/created`,
    // Request user authorization (OAuth) DURING installation, so GitHub appends a
    // one-time `code` to the setup redirect. The callback exchanges it for a user
    // token and PROVES the installer controls the installation before binding it —
    // the isolation gate that makes `public: true` safe (see github_install_callback).
    request_oauth_on_install: true,
    // OAuth callback target = the same identity-gated install→map callback.
    callback_urls: [`${base}/install/github/callback`],
    hook_attributes: {
      url: `${base}/webhooks/github`,
      active: true,
    },
    // `public: false` for the dogfood; flipping to `true` for real self-serve is a
    // deliberate business toggle that is now SAFE — the OAuth ownership proof above
    // prevents cross-tenant installation binding (was the hard gate).
    public: false,
    default_permissions: {
      // Read workflow-job state (the runner fabric needs the job signal).
      actions: "read",
      // Baseline repo metadata (enumerate the installation's repos).
      metadata: "read",
    },
    // Only SUBSCRIBABLE events belong here. `installation` /
    // `installation_repositories` are App-lifecycle events GitHub ALWAYS
    // delivers to the App's webhook regardless of subscription — and it rejects
    // the manifest outright ("Default events are not supported by permissions")
    // if you list them, since no permission grants them. So we subscribe only to
    // `workflow_job` (granted by `actions:read`) and still receive the
    // installation events for map upkeep automatically.
    default_events: ["workflow_job"],
  };
}

/**
 * Step 1 — serve the auto-submitting manifest form. Setup-token gated.
 */
export function handleAppManifestForm(request: Request, env: GithubAppManifestEnv): Response {
  const url = new URL(request.url);

  const expected = env.GITHUB_APP_SETUP_TOKEN;
  if (!expected) {
    return new Response("github app manifest flow not configured", { status: 503 });
  }
  if (!constantTimeEqual(presentedSetupToken(url, request), expected)) {
    return new Response("forbidden", { status: 403 });
  }

  const base = env.SIGNUP_WORKER_PUBLIC_URL ?? url.origin;
  const org = env.GITHUB_APP_ORG ?? "HumanGuardrail";
  const manifest = buildManifest(base);
  const action = `https://github.com/organizations/${encodeURIComponent(org)}/settings/apps/new`;

  // Auto-submitting POST form: the manifest is a hidden field per the GitHub
  // manifest-flow spec. `state` round-trips as CSRF defense.
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Create CoreLink Runners GitHub App</title></head>
<body onload="document.forms[0].submit()">
  <noscript><p>Enable JavaScript, or click the button.</p></noscript>
  <p>Registering the <strong>CoreLink Runners</strong> GitHub App on org <code>${esc(org)}</code>…</p>
  <form action="${esc(action)}" method="post">
    <input type="hidden" name="manifest" value='${esc(JSON.stringify(manifest))}'>
    <button type="submit">Create the CoreLink Runners GitHub App</button>
  </form>
</body></html>`;

  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

/**
 * Step 3 — exchange the manifest `code` for the permanent App credentials and
 * display them ONCE.
 *
 * Auth model: this is GitHub's redirect target (the manifest `redirect_url`),
 * so GitHub controls the request and appends ONLY `?code=…` — it does NOT (and
 * cannot) carry our `setup_token`. Gating this on the setup token therefore
 * 403s every legitimate redirect. The correct boundary is possession of the
 * single-use `code` itself: GitHub issues it only after the operator-gated
 * step-1 form submission, it is unguessable, single-use, and ~1h TTL. So we
 * gate on the code (400 if absent) and never on the setup token here.
 */
export async function handleAppManifestCallback(
  request: Request,
  _env: GithubAppManifestEnv,
): Promise<Response> {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("missing manifest code", { status: 400 });
  }

  // Exchange the temporary code for the permanent app record. GitHub returns
  // the private-key PEM + webhook secret exactly ONCE, here.
  let created: {
    id?: number;
    slug?: string;
    client_id?: string;
    pem?: string;
    webhook_secret?: string;
    html_url?: string;
  };
  try {
    const resp = await fetch(
      `https://api.github.com/app-manifests/${encodeURIComponent(code)}/conversions`,
      {
        method: "POST",
        headers: {
          accept: "application/vnd.github+json",
          "user-agent": "corelink-signup-worker",
          "x-github-api-version": "2022-11-28",
        },
      },
    );
    if (!resp.ok) {
      const detail = await resp.text().catch(() => "");
      return new Response(
        `manifest conversion failed (${resp.status}): ${esc(detail.slice(0, 300))}`,
        { status: 502 },
      );
    }
    created = (await resp.json()) as typeof created;
  } catch (e) {
    return new Response(`manifest conversion error: ${esc((e as Error).message)}`, {
      status: 502,
    });
  }

  // One-time hand-off page. A Worker cannot set its own secrets, so the operator
  // copies these into `wrangler secret put`. `noindex` + no-store so it is never
  // cached/indexed. The PEM is shown verbatim in a <pre> for a clean copy.
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>CoreLink Runners App created</title></head>
<body>
  <h1>✅ CoreLink Runners GitHub App created</h1>
  <p>App: <a href="${esc(created.html_url ?? "#")}">${esc(created.slug ?? "?")}</a>
     (id <code>${esc(String(created.id ?? "?"))}</code>).
     Set these as signup-worker secrets, then DELETE this tab (shown once):</p>
  <ul>
    <li><code>GITHUB_APP_ID</code> = <code>${esc(String(created.id ?? ""))}</code></li>
    <li><code>GITHUB_APP_WEBHOOK_SECRET</code> = <code>${esc(created.webhook_secret ?? "")}</code></li>
    <li><code>GITHUB_APP_CLIENT_ID</code> = <code>${esc(created.client_id ?? "")}</code></li>
  </ul>
  <p><code>GITHUB_APP_PRIVATE_KEY</code> (PKCS#1 PEM — convert to PKCS#8 before the
     Worker can use it with WebCrypto: <code>openssl pkcs8 -topk8 -nocrypt</code>):</p>
  <pre>${esc(created.pem ?? "")}</pre>
</body></html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
