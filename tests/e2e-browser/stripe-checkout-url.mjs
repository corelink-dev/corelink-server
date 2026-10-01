export function isStripeCheckoutUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.hostname === "checkout.stripe.com";
  } catch {
    return false;
  }
}
