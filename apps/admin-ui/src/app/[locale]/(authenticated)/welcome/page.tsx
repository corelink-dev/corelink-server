import * as React from "react";
import { redirect } from "next/navigation";
import Link from "next/link";
import type { Locale } from "@/i18n/messages";
import { InstallOneLiner } from "@/components/InstallOneLiner";
import { PatRevealCard } from "@/components/PatRevealCard";
import { Callout, Card, CodeBlock } from "@/components/ui/linear";
import { WelcomeStream } from "./WelcomeStream";

/**
 * /welcome — the single post-signup screen (PLG framework §4 step 3).
 *
 * Server component — reads `tenant_id` and `region` from Clerk publicMetadata
 * (session claims), and the one-time `pat_plaintext` SERVER-SIDE via the Clerk
 * Backend API from the user's `private_metadata` (populated by the signup-worker
 * `user.created` webhook, CTRL-CRED-001).
 *
 * SECURITY (2026-06-19, CRED-pat-plaintext): `pat_plaintext` is NO LONGER in
 * `public_metadata`/the session JWT. `public_metadata` carries only
 * `{tenant_id, region}` (legit session claims). The secret lives in
 * `private_metadata` (backend-only — never in the JWT, never readable by
 * `useUser()`), so it must be fetched here via `clerkClient().users.getUser()`.
 * Because this is a server component the plaintext reaches the browser only in
 * this single rendered response (shown once), then is cleared by the action.
 *
 * Three rendering branches:
 *  1. `pat_plaintext` present: one-time reveal panel (PAT + install one-liner
 *     + PatRevealCard for reveal/redact UX + next-step CTA cards)
 *  2. `tenant_id` present but no `pat_plaintext`: "already retrieved" panel
 *     with link to /customer/keys for rotation
 *  3. Neither present: redirect to /sign-up (webhook still running or session
 *     expired — user must re-authenticate)
 *
 * UI: migrated to the Linear design language (frozen kit + globals.css tokens),
 * matching the customer dashboard. The dark canvas is provided by wrapping the
 * page in `.cx-shell` / `.cx-main` (the same scope the customer surfaces use);
 * no shared layout is touched.
 *
 * CTRL-CRED-001: PAT plaintext is NEVER logged, NEVER passed to client-side
 * state beyond this render, NEVER stored in localStorage/sessionStorage/cookie.
 * It is cleared from Clerk privateMetadata by `clearPatPlaintext()` in
 * `./actions.ts` when the user confirms they have saved the token.
 */
type WelcomeClaims = {
  tenant_id?: string;
  region?: string;
};

export default async function WelcomePage(props: {
  params: Promise<{ locale: Locale }>;
}): Promise<React.ReactElement> {
  // params are awaited to satisfy the dynamic-route contract; the post-signup
  // redirects intentionally target the locale-less /sign-in (the only real
  // sign-in route — there is no [locale]/sign-in), matching the /upgrade page.
  await props.params;

  const mod = await import("@clerk/nextjs/server").catch(() => null);
  let claims: WelcomeClaims = {};
  let userId: string | null = null;
  if (mod) {
    try {
      const session = await (
        mod as {
          auth: () => Promise<{
            userId?: string | null;
            sessionClaims?: {
              publicMetadata?: WelcomeClaims;
            };
          }>;
        }
      ).auth();
      // Clerk v6: publicMetadata is nested under sessionClaims.publicMetadata.
      // public_metadata carries ONLY {tenant_id, region} now (the PAT moved to
      // private_metadata — see the SECURITY note above).
      claims = session.sessionClaims?.publicMetadata ?? {};
      userId = session.userId ?? null;
    } catch {
      // Defensive: `auth()` throws if the Clerk middleware request context is
      // unavailable for this render (an OpenNext edge edge-case). Never 500 the
      // post-signup landing — send the user to sign-in to re-establish a session
      // rather than crashing. The error.tsx boundary is the last-resort net.
      redirect("/sign-in");
    }
  }

  // Branch 3: no tenant provisioned yet — webhook still running or the session
  // carries no tenant. Send to sign-in to re-establish the session (a brand-new
  // signup whose webhook is mid-flight will have its tenant within ~2s).
  // p95 webhook latency target ≤ 2s (acceptance §2); rare edge case.
  if (!claims.tenant_id) {
    redirect("/sign-in");
  }

  const region = claims.region ?? "auto";

  // Read the one-time PAT plaintext SERVER-SIDE from Clerk private_metadata via
  // the Backend API. private_metadata is NEVER in the session claims/JWT, so it
  // can only be fetched here with CLERK_SECRET_KEY. Failures (missing key, API
  // error) degrade gracefully to the "already retrieved" branch — never 500 nor
  // leak — and never log the secret.
  let patPlaintext: string | undefined;
  if (mod && userId) {
    try {
      const clerk = await (
        mod as {
          clerkClient: () => Promise<{
            users: {
              getUser: (id: string) => Promise<{
                privateMetadata?: { pat_plaintext?: unknown };
              }>;
            };
          }>;
        }
      ).clerkClient();
      const u = await clerk.users.getUser(userId);
      const raw = u.privateMetadata?.pat_plaintext;
      if (typeof raw === "string" && raw.length > 0) {
        patPlaintext = raw;
      }
    } catch {
      // Backend API unavailable / not configured — fall through to branch 2.
      patPlaintext = undefined;
    }
  }

  // Branch 2: tenant provisioned, but PAT already retrieved (pat_plaintext
  // was cleared after first visit by clearPatPlaintext server action).
  if (!patPlaintext) {
    return (
      <div className="cx-shell lin">
        <main
          className="cx-main"
          data-testid="welcome-already-retrieved"
          aria-labelledby="welcome-heading"
        >
          <h1 id="welcome-heading">Welcome to CoreLink</h1>
          <p>
            Your tenant <code>{claims.tenant_id}</code> · region{" "}
            <code>{region}</code>
          </p>

          <Card title="Access token">
            <div role="status" data-testid="already-retrieved-notice">
              <Callout tone="warn">
                Your token was already retrieved. Tokens are shown once — rotate
                it from{" "}
                <Link href="/customer/keys" data-testid="rotate-keys-link">
                  your tokens page
                </Link>{" "}
                if you need a new one.
              </Callout>
            </div>
            <div className="lin-mt">
              <Link
                href="/customer"
                className="lin-btn lin-btn--primary lin-btn--sm"
                data-testid="go-to-customer-link"
              >
                Go to dashboard
              </Link>
            </div>
          </Card>
        </main>
      </div>
    );
  }

  // Branch 1: first visit — pat_plaintext present, render one-time reveal panel.
  const pat = patPlaintext;

  return (
    <div className="cx-shell lin">
      <main
        className="cx-main"
        data-testid="welcome-root"
        aria-labelledby="welcome-heading"
      >
        <h1 id="welcome-heading">Welcome to CoreLink</h1>
        <p>
          Your tenant <code>{claims.tenant_id}</code> · region{" "}
          <code>{region}</code>
        </p>

        {/* One-time PAT reveal */}
        <section
          data-testid="pat-reveal-section"
          aria-labelledby="welcome-token-h"
        >
          <h2 id="welcome-token-h">Your access token</h2>
          <p>
            Copy it now — it&rsquo;s shown once and can&rsquo;t be retrieved
            later.
          </p>
          <div className="lin-mt">
            <PatRevealCard patPlaintext={pat} />
          </div>
        </section>

        {/* Install one-liner */}
        <section
          data-testid="install-section"
          aria-labelledby="welcome-install-h"
        >
          <h2 id="welcome-install-h">Install the CLI</h2>
          <p>Run this one-liner to install and authenticate the CoreLink CLI.</p>
          <div className="lin-mt">
            <InstallOneLiner token={pat} />
          </div>
        </section>

        {/* Verify step */}
        <section data-testid="verify-section" aria-labelledby="welcome-verify-h">
          <h2 id="welcome-verify-h">Then verify</h2>
          <div className="lin-mt">
            <CodeBlock code="corelink whoami" lang="bash" />
          </div>
        </section>

        {/* Activation status stream */}
        <section
          data-testid="activation-section"
          aria-labelledby="welcome-activation-h"
        >
          <h2 id="welcome-activation-h">Activation status</h2>
          <div className="lin-mt">
            <WelcomeStream />
          </div>
          <div className="lin-mt">
            <Callout tone="info">
              After the CLI authenticates, run <code>corelink bazel-init</code>{" "}
              in your repo, then <code>bazel build //...</code> twice — the
              second build should report cache hits.
            </Callout>
          </div>
        </section>

        {/* Next-step CTA cards */}
        <section
          data-testid="next-steps-section"
          aria-labelledby="welcome-next-h"
        >
          <h2 id="welcome-next-h">Next steps</h2>
          <div className="lin-mt lin-checklist" data-testid="next-steps-cards">
            <Link
              href="https://humangr.com/corelink/docs/quickstart"
              data-testid="next-step-quickstart"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Card hover>
                <strong>Try the quickstart</strong>
                <div className="lin-card__meta">
                  Authenticate the CLI and run your first cached build.
                </div>
              </Card>
            </Link>

            <Link
              href="https://humangr.com/corelink/docs/integrations/bazel"
              data-testid="next-step-bazel"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Card hover>
                <strong>Configure Bazel</strong>
                <div className="lin-card__meta">
                  Point your <code>.bazelrc</code> at the CoreLink remote cache.
                </div>
              </Card>
            </Link>

            <Link
              href="https://humangr.com/corelink/docs/integrations/turborepo"
              data-testid="next-step-turbo"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Card hover>
                <strong>Configure Turborepo</strong>
                <div className="lin-card__meta">
                  Enable remote cache in your <code>turbo.json</code> with one
                  flag.
                </div>
              </Card>
            </Link>
          </div>
        </section>
      </main>
    </div>
  );
}
