import assert from "node:assert/strict";
import test from "node:test";
import { isStripeCheckoutUrl } from "./stripe-checkout-url.mjs";

test("accepts an HTTPS Stripe Checkout URL on the exact host", () => {
  assert.equal(
    isStripeCheckoutUrl("https://checkout.stripe.com/c/pay/cs_test_example"),
    true,
  );
});

test("rejects base-domain, suffix, userinfo, HTTP, and malformed lookalikes", () => {
  for (const value of [
    "https://stripe.com/checkout",
    "https://checkout.stripe.com.attacker.example/session",
    "https://checkout.stripe.com@attacker.example/session",
    "http://checkout.stripe.com/session",
    "not a URL",
  ]) {
    assert.equal(isStripeCheckoutUrl(value), false, `unexpectedly accepted ${value}`);
  }
});
