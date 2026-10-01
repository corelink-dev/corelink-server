import { test, expect } from "../fixtures/auth.js";
import { isStripeCheckoutUrl } from "../stripe-checkout-url.mjs";

/**
 * MONEY JOURNEY — the black-box PAT suite gates this (needs a browser session).
 * A signed-in user upgrades to Pro: click → (DPA click-through if first time) →
 * the app POSTs /api/checkout/session → /v1/onboarding/tier-select → a REAL
 * Stripe Checkout session, and the browser is redirected to it. Reaching
 * checkout.stripe.com with a live session proves the whole money path
 * (tier-select → checkout_url) end-to-end for a real user.
 *
 * We stop AT the Stripe checkout page (do not submit the test card — reaching a
 * real hosted checkout session is the product-side proof; Stripe owns the rest).
 */

test("upgrade to Pro → DPA click-through → real Stripe checkout session", async ({
  authedPage: page,
}) => {
  // Capture the checkout/tier-select network to classify any failure.
  page.on("response", async (r) => {
    const u = r.url();
    if (u.includes("/checkout/session") || u.includes("tier-select") || u.includes("/onboarding")) {
      let detail = "";
      if (r.status() >= 500 || r.status() === 403) {
        detail = " body=" + (await r.text().catch(() => "?")).slice(0, 300);
      }
      // eslint-disable-next-line no-console
      console.log(`[money][net] ${r.request().method()} ${u.replace("https://humangr.com", "")} → ${r.status()}${detail}`);
    }
  });

  await page.goto("https://humangr.com/corelink/en/upgrade?plan=pro");
  await page.waitForLoadState("networkidle").catch(() => {});

  const openBtn = page.locator('[data-testid="upgrade-open-button"]');
  await expect(openBtn, "the upgrade button must render").toBeVisible({ timeout: 30_000 });
  await openBtn.click();

  // Two outcomes: (a) immediate redirect to Stripe (DPA already accepted), or
  // (b) the DPA click-through gate appears first (INV-ONBOARD-DPA-FIRST).
  const dpaGate = page.locator('[data-testid="upgrade-dpa-gate"]');
  const errorBox = page.locator('[data-testid="upgrade-error"]');
  await Promise.race([
    dpaGate.waitFor({ state: "visible", timeout: 20_000 }).catch(() => {}),
    page.waitForURL((url) => isStripeCheckoutUrl(url.href), { timeout: 20_000 }).catch(() => {}),
    errorBox.waitFor({ state: "visible", timeout: 20_000 }).catch(() => {}),
  ]);

  if (await errorBox.isVisible().catch(() => false)) {
    const msg = (await errorBox.textContent())?.trim() ?? "";
    throw new Error(`FINDING: checkout surfaced an error before Stripe: "${msg}"`);
  }

  if (await dpaGate.isVisible().catch(() => false)) {
    // eslint-disable-next-line no-console
    console.log("[money] DPA click-through gate rendered — scrolling + accepting");
    // Scroll the DPA text to the end to satisfy hasScrolledToEnd, then accept.
    const scroller = page.locator('[data-testid="dpa-scroller"]');
    await scroller.evaluate((el) => {
      el.scrollTop = el.scrollHeight;
      el.dispatchEvent(new Event("scroll"));
    });
    // The accept button enables once scrolled; it's the button inside the gate.
    const acceptBtn = dpaGate.getByRole("button").last();
    await expect(acceptBtn, "DPA accept button must enable after scroll").toBeEnabled({
      timeout: 15_000,
    });
    await acceptBtn.click();
  }

  // After DPA accept the component auto-retries the checkout → Stripe redirect.
  await page.waitForURL((url) => isStripeCheckoutUrl(url.href), { timeout: 45_000 });
  const url = page.url();
  // eslint-disable-next-line no-console
  console.log("[money] landed on Stripe checkout host: checkout.stripe.com");
  expect(isStripeCheckoutUrl(url), "must reach a real Stripe checkout session").toBe(true);
  // Sanity: Stripe's hosted checkout renders a pay/submit surface.
  await expect(page.locator("body")).toContainText(/pay|subscribe|corelink|pro/i, {
    timeout: 20_000,
  });
});
