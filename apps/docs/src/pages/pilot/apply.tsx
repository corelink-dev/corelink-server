/**
 * Pilot signup form — `humangr.com/corelink/docs/pilot/apply`.
 *
 * R-prep wave-29 stream-2 deliverable. Pairs with the container-side handler
 * (`crates/corelink-container/src/routes/signup.rs`, stream-1):
 *   POST https://corelink-api.humangr.com/v1/signup/pilot/{token}
 *
 * The route mounts fail-CLOSED: the container only registers it when
 * `SIGNUP_TOKEN_KEY` is present and valid at boot (`routes.rs:789-797`), so an
 * unset secret is indistinguishable from "never implemented" — a silent 404.
 *
 * Validation rules (client-side; backend re-validates):
 *   - token: 32-char Crockford base32 (0-9A-HJKMNP-TV-Z, case-insensitive,
 *     normalised to upper-case before submit). Crockford excludes I, L, O, U
 *     to reduce ambiguity vs base32 RFC4648.
 *   - email: RFC 5322 lite (single `@`, dot in domain, ≤ 254 chars).
 *   - company: 1..120 chars, trimmed.
 *   - tierHint: enum (FREE / STANDARD / PRO / ENTERPRISE / undecided).
 *   - useCase: 1..280 chars (matches COPY.md form-field constraint).
 *
 * These are the component's internal names. On the wire they are sent as
 * `email` / `company_name` / `tier_hint` / `expected_use_case`, which is what
 * `PilotSignupBody` deserialises — see the submit handler.
 *
 * Success → /pilot/welcome (with `?slot=reserved` so welcome.tsx can
 *   conditionally show confetti without leaking the token).
 * Failure → inline `errorBox` with backend-message or fallback copy.
 *
 * Submission uses `fetch()` with `credentials: "omit"` (no cookies) and
 * `Content-Type: application/json` to match the wave-27 backend contract.
 */

import type { FormEvent, ReactElement } from "react";
import { useCallback, useState } from "react";
import Layout from "@theme/Layout";
import Translate, { translate } from "@docusaurus/Translate";
import styles from "./pilot.module.css";

// The route is served by the container behind the prod API host. The old
// dotted `signup.corelink.` name is NXDOMAIN (dotted scheme, retired — the
// flat `corelink-*.humangr.com` scheme is canonical), so every submission from
// this form failed at DNS: the pilot intake was advertised as open and could
// not accept a single application.
const SIGNUP_ENDPOINT = "https://corelink-api.humangr.com/v1/signup/pilot";

// Crockford base32 alphabet (32 chars, no I/L/O/U; case-insensitive on input).
const CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{32}$/;

// RFC 5322 lite: single @, dot in domain part, ≤ 254 chars.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const TIER_HINTS = ["undecided", "FREE", "STANDARD", "PRO", "ENTERPRISE"] as const;
type TierHint = (typeof TIER_HINTS)[number];

type FieldErrors = Partial<{
  token: string;
  email: string;
  company: string;
  tierHint: string;
  useCase: string;
}>;

type SubmitState =
  | { readonly kind: "idle" }
  | { readonly kind: "submitting" }
  | { readonly kind: "error"; readonly message: string };

function validate(input: {
  token: string;
  email: string;
  company: string;
  tierHint: string;
  useCase: string;
}): FieldErrors {
  const errors: FieldErrors = {};
  const tokenNormalised = input.token.trim().toUpperCase();
  if (!CROCKFORD_RE.test(tokenNormalised)) {
    errors.token = translate({
      id: "pilot.apply.error.token",
      message:
        "Token must be 32 Crockford base32 characters (0–9, A–Z excluding I, L, O, U).",
      description: "Pilot apply form — token validation error",
    });
  }
  if (input.email.length > 254 || !EMAIL_RE.test(input.email)) {
    errors.email = translate({
      id: "pilot.apply.error.email",
      message: "Enter a valid work email address.",
      description: "Pilot apply form — email validation error",
    });
  }
  const companyTrim = input.company.trim();
  if (companyTrim.length < 1 || companyTrim.length > 120) {
    errors.company = translate({
      id: "pilot.apply.error.company",
      message: "Company name is required (1–120 characters).",
      description: "Pilot apply form — company validation error",
    });
  }
  if (!TIER_HINTS.includes(input.tierHint as TierHint)) {
    errors.tierHint = translate({
      id: "pilot.apply.error.tier",
      message: "Pick one of the available tier hints.",
      description: "Pilot apply form — tier hint validation error",
    });
  }
  const useCaseTrim = input.useCase.trim();
  if (useCaseTrim.length < 1 || useCaseTrim.length > 280) {
    errors.useCase = translate({
      id: "pilot.apply.error.useCase",
      message: "Tell us in 1–280 characters how you'd use CoreLink.",
      description: "Pilot apply form — use-case validation error",
    });
  }
  return errors;
}

function backendErrorMessage(status: number, raw: string): string {
  // 401 — NOT 400 — is the token verdict. The route returns 401 for a
  // malformed, expired or forged token and 400 for a body that fails field
  // validation; this mapping used to be inverted, so a bad token produced the
  // generic "signup failed" and a bad field told the applicant their token was
  // invalid. Both are recoverable errors, and telling someone the wrong one
  // sends them to re-request a token they already have.
  if (status === 401) {
    return translate({
      id: "pilot.apply.backend.invalidToken",
      message:
        "Invalid or expired token. Tokens are one-shot and tied to your outreach email — check the latest email or contact pilot@humangr.com.",
      description: "Pilot apply form — backend 401 (token rejected)",
    });
  }
  if (status === 400 || status === 422) {
    // 400 = the handler's own field validation; 422 = axum's Json extractor
    // refusing the body shape. The 422 body is plain text, not JSON, so the
    // `message`-field fallback below cannot surface anything useful for it.
    return translate({
      id: "pilot.apply.backend.badRequest",
      message:
        "One of the fields was rejected. Check the email, company and use-case fields and try again — or send the details to pilot@humangr.com.",
      description: "Pilot apply form — backend 400/422 (body rejected)",
    });
  }
  if (status === 429) {
    return translate({
      id: "pilot.apply.backend.rateLimited",
      message:
        "Rate limited. Wait a few minutes and try again — or reach pilot@humangr.com if this persists.",
      description: "Pilot apply form — backend 429 fallback",
    });
  }
  if (status === 503) {
    return translate({
      id: "pilot.apply.backend.closed",
      message:
        "Signup pipeline closed — all 10 pilot slots are currently reserved. Watch for GA at humangr.com/corelink/docs or email pilot@humangr.com to join the waitlist.",
      description: "Pilot apply form — backend 503 fallback",
    });
  }
  // Best-effort surface of backend JSON `message` field if present.
  try {
    const parsed = JSON.parse(raw) as { message?: unknown };
    if (typeof parsed.message === "string" && parsed.message.length > 0) {
      return parsed.message;
    }
  } catch {
    // raw was not JSON — fall through.
  }
  return translate({
    id: "pilot.apply.backend.generic",
    message:
      "Signup failed. Please retry, or contact pilot@humangr.com with the timestamp.",
    description: "Pilot apply form — backend generic fallback",
  });
}

export default function PilotApply(): ReactElement {
  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [tierHint, setTierHint] = useState<TierHint>("undecided");
  const [useCase, setUseCase] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});
  const [submit, setSubmit] = useState<SubmitState>({ kind: "idle" });

  const onSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>): Promise<void> => {
      event.preventDefault();
      const fieldErrors = validate({ token, email, company, tierHint, useCase });
      setErrors(fieldErrors);
      if (Object.keys(fieldErrors).length > 0) {
        return;
      }

      setSubmit({ kind: "submitting" });
      const tokenNormalised = token.trim().toUpperCase();
      try {
        const response = await fetch(
          `${SIGNUP_ENDPOINT}/${encodeURIComponent(tokenNormalised)}`,
          {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/json" },
            // Wire field names are snake_case and are NOT the component's
            // internal camelCase state names. `PilotSignupBody` in
            // crates/corelink-container/src/routes/signup.rs derives a plain
            // serde `Deserialize` with no rename attribute, so axum's Json
            // extractor rejects the whole request with 422 before the handler
            // runs if any name differs — which is what the form used to do on
            // every single submission.
            body: JSON.stringify({
              email: email.trim(),
              company_name: company.trim(),
              tier_hint: tierHint,
              expected_use_case: useCase.trim(),
            }),
          },
        );
        if (!response.ok) {
          const raw = await response.text().catch(() => "");
          setSubmit({
            kind: "error",
            message: backendErrorMessage(response.status, raw),
          });
          return;
        }
        // Success — redirect to welcome page. `?slot=reserved` lets welcome.tsx
        // gate the confetti without leaking the (one-shot) token in URL params.
        window.location.assign("/pilot/welcome?slot=reserved");
      } catch (err) {
        setSubmit({
          kind: "error",
          message: translate({
            id: "pilot.apply.backend.network",
            message:
              "Network error contacting corelink-api.humangr.com. Retry, or email pilot@humangr.com.",
            description: "Pilot apply form — network/fetch failure",
          }),
        });
      }
    },
    [token, email, company, tierHint, useCase],
  );

  const isSubmitting = submit.kind === "submitting";

  return (
    <Layout
      title={translate({
        id: "pilot.apply.meta.title",
        message: "Apply for CoreLink pilot — signup",
        description: "Pilot apply page — <title>",
      })}
      description={translate({
        id: "pilot.apply.meta.description",
        message:
          "Token-gated CoreLink pilot signup. Free 30-day pilot of a shared content-addressable cache. Pre-GA.",
        description: "Pilot apply page — meta description",
      })}
    >
      <main className={styles.page}>
        <div className={styles.banner} role="note">
          <Translate
            id="pilot.apply.banner"
            description="Pilot apply page — pre-GA reminder banner"
          >
            {
              "Pilot tier: free 100 GB CAS + 10k audit events / month during " +
              "eval (30-day); auto-convert to STANDARD at GA."
            }
          </Translate>
        </div>

        <h1 className={styles.heroTitle}>
          <Translate
            id="pilot.apply.title"
            description="Pilot apply page — H1"
          >
            Reserve your pilot slot
          </Translate>
        </h1>
        <p className={styles.heroSub}>
          <Translate
            id="pilot.apply.intro"
            description="Pilot apply page — intro paragraph"
          >
            {
              "Tokens are one-shot, tied to the email we sent you. " +
              "We review applications within 2 business days. " +
              "No card required during the pilot."
            }
          </Translate>
        </p>

        {submit.kind === "error" ? (
          <div className={styles.errorBox} role="alert" aria-live="polite">
            {submit.message}
          </div>
        ) : null}

        <form
          className={styles.form}
          onSubmit={onSubmit}
          noValidate
          aria-describedby="pilot-apply-intro"
        >
          <div className={styles.field}>
            <label className={styles.label} htmlFor="pilot-token">
              <Translate id="pilot.apply.field.token" description="Pilot apply — token label">
                Pilot token
              </Translate>
            </label>
            <input
              id="pilot-token"
              className={styles.input}
              type="text"
              autoComplete="off"
              spellCheck={false}
              inputMode="text"
              maxLength={64}
              required
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-invalid={Boolean(errors.token)}
              aria-describedby="pilot-token-hint pilot-token-error"
            />
            <span id="pilot-token-hint" className={styles.hint}>
              <Translate
                id="pilot.apply.field.token.hint"
                description="Pilot apply — token hint"
              >
                32-character Crockford base32, from your outreach email.
              </Translate>
            </span>
            {errors.token ? (
              <span id="pilot-token-error" className={styles.fieldError}>
                {errors.token}
              </span>
            ) : null}
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="pilot-email">
              <Translate id="pilot.apply.field.email" description="Pilot apply — email label">
                Work email
              </Translate>
            </label>
            <input
              id="pilot-email"
              className={styles.input}
              type="email"
              autoComplete="email"
              maxLength={254}
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-invalid={Boolean(errors.email)}
              aria-describedby="pilot-email-error"
            />
            {errors.email ? (
              <span id="pilot-email-error" className={styles.fieldError}>
                {errors.email}
              </span>
            ) : null}
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="pilot-company">
              <Translate id="pilot.apply.field.company" description="Pilot apply — company label">
                Company name
              </Translate>
            </label>
            <input
              id="pilot-company"
              className={styles.input}
              type="text"
              autoComplete="organization"
              maxLength={120}
              required
              value={company}
              onChange={(e) => setCompany(e.target.value)}
              aria-invalid={Boolean(errors.company)}
              aria-describedby="pilot-company-error"
            />
            {errors.company ? (
              <span id="pilot-company-error" className={styles.fieldError}>
                {errors.company}
              </span>
            ) : null}
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="pilot-tier">
              <Translate id="pilot.apply.field.tier" description="Pilot apply — tier label">
                Expected tier at GA (hint)
              </Translate>
            </label>
            <select
              id="pilot-tier"
              className={styles.select}
              value={tierHint}
              onChange={(e) => setTierHint(e.target.value as TierHint)}
              aria-invalid={Boolean(errors.tierHint)}
            >
              {TIER_HINTS.map((tier) => (
                <option key={tier} value={tier}>
                  {tier}
                </option>
              ))}
            </select>
            <span className={styles.hint}>
              <Translate
                id="pilot.apply.field.tier.hint"
                description="Pilot apply — tier hint"
              >
                Best guess — not a commitment.
              </Translate>
            </span>
            {errors.tierHint ? (
              <span className={styles.fieldError}>{errors.tierHint}</span>
            ) : null}
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="pilot-usecase">
              <Translate
                id="pilot.apply.field.useCase"
                description="Pilot apply — use-case label"
              >
                Expected use case (one sentence)
              </Translate>
            </label>
            <textarea
              id="pilot-usecase"
              className={styles.textarea}
              maxLength={280}
              required
              value={useCase}
              onChange={(e) => setUseCase(e.target.value)}
              aria-invalid={Boolean(errors.useCase)}
              aria-describedby="pilot-usecase-hint pilot-usecase-error"
            />
            <span id="pilot-usecase-hint" className={styles.hint}>
              <Translate
                id="pilot.apply.field.useCase.hint"
                description="Pilot apply — use-case hint"
              >
                280-char max. Example: "Shared remote cache for our Bazel monorepo."
              </Translate>
            </span>
            {errors.useCase ? (
              <span id="pilot-usecase-error" className={styles.fieldError}>
                {errors.useCase}
              </span>
            ) : null}
          </div>

          <div>
            <button
              type="submit"
              className={styles.ctaPrimary}
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <Translate
                  id="pilot.apply.submit.busy"
                  description="Pilot apply — submit button while submitting"
                >
                  Reserving…
                </Translate>
              ) : (
                <Translate
                  id="pilot.apply.submit"
                  description="Pilot apply — submit button"
                >
                  Reserve my slot
                </Translate>
              )}
            </button>
          </div>
        </form>
      </main>
    </Layout>
  );
}
