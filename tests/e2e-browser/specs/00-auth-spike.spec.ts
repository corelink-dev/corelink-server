import { test, expect } from "@playwright/test";
import { setupClerkTestingToken } from "@clerk/testing/playwright";
import { randomBytes } from "node:crypto";

/**
 * PHASE-1 SPIKE — prove a REAL prod-accepted Clerk session in a browser.
 *
 * Creates a throwaway Clerk user + a one-time sign-in ticket via the Backend
 * API, then drives the REAL Clerk SDK in the browser (window.Clerk ticket
 * sign-in) on humangr.com/corelink. If /corelink/dashboard renders authed
 * (no bounce to /sign-in), the browser holds a session the prod worker accepts
 * — which the headless FAPI mint could not achieve (rejected 401). That
 * validates the whole money/DSR browser-driving approach.
 */

const CLERK_API = "https://api.clerk.com/v1";
const SK = process.env["CLERK_SECRET_KEY"] ?? "";

async function clerkPost(path: string, body: unknown): Promise<any> {
  const r = await fetch(`${CLERK_API}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${SK}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`Clerk ${path} → ${r.status} ${JSON.stringify(j).slice(0, 200)}`);
  return j;
}

test("real prod Clerk session loads the authed dashboard", async ({ page }) => {
  // 1) Backend API: throwaway user + one-time sign-in ticket.
  const email = `corelink-e2e-browser-${Date.now()}@corelink-e2e.dev`;
  const user = await clerkPost("/users", {
    email_address: [email],
    password: `Corelink-e2e-${randomBytes(24).toString("hex")}!A9`,
    skip_password_checks: true,
  });
  const userId = user.id as string;
  const ticket = (await clerkPost("/sign_in_tokens", { user_id: userId })).token as string;
  // eslint-disable-next-line no-console
  console.log(`[spike] user=${userId} ticket-len=${ticket.length}`);

  // 2) Arm the testing token (bot bypass) for this page.
  await setupClerkTestingToken({ page });

  // 3) Load the app so window.Clerk is present, then ticket sign-in.
  await page.goto("/corelink/sign-in");
  await page.waitForFunction(() => (window as any).Clerk !== undefined, { timeout: 30_000 });
  await page.evaluate(async () => {
    await (window as any).Clerk.load();
  });
  const signedIn = await page.evaluate(async (t: string) => {
    const clerk = (window as any).Clerk;
    const res = await clerk.client.signIn.create({ strategy: "ticket", ticket: t });
    if (res.status !== "complete") return { ok: false, status: res.status };
    await clerk.setActive({ session: res.createdSessionId });
    return { ok: true, status: res.status };
  }, ticket);
  // eslint-disable-next-line no-console
  console.log(`[spike] browser sign-in:`, JSON.stringify(signedIn));
  expect(signedIn.ok, `sign-in status=${signedIn.status}`).toBeTruthy();

  // 4) Navigate to the authed dashboard — a prod-accepted session must NOT bounce.
  await page.goto("/corelink/dashboard");
  await page.waitForLoadState("networkidle");
  const url = page.url();
  // eslint-disable-next-line no-console
  console.log(`[spike] post-dashboard url=${url}`);
  expect(url, "must not be bounced to sign-in").not.toContain("/sign-in");

  // 5) Prove the session is prod-ACCEPTED, not just present: reaching
  //    /corelink/dashboard without a bounce means the app middleware
  //    (server-side Clerk verification, the SAME verification the headless mint
  //    failed) accepted the session and rendered authed content. Assert the
  //    page is NOT a sign-in form (a bounced/failed session would render one).
  const isSignInForm = await page
    .locator('input[name="identifier"], input[type="password"], [data-clerk-sign-in]')
    .first()
    .isVisible()
    .catch(() => false);
  expect(isSignInForm, "dashboard must render authed, not a sign-in form").toBeFalsy();

  // 6) Cleanup: delete the throwaway user.
  await fetch(`${CLERK_API}/users/${userId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${SK}` },
  });
});
