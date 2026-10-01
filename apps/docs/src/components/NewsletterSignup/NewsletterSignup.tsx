/**
 * NewsletterSignup — email-only capture form for the public docs site.
 *
 * Per the channels audit + solo-SaaS playbook: visitors who land on docs
 * but aren't customers yet should be able to follow CoreLink's progress
 * (release notes, design essays, post-mortems). This is a passive,
 * opt-in capture — never a modal, never a paywall.
 *
 * Architecture:
 *   - Docusaurus serves docs as static HTML on Cloudflare Pages. There
 *     is no server runtime here, so the form POSTs to the admin-ui
 *     Next.js app at `/api/newsletter/subscribe` (configurable via the
 *     `subscribeUrl` prop — defaults to the production admin-ui origin).
 *   - The admin-ui route holds the `RESEND_API_KEY` secret server-side
 *     and forwards the contact to Resend's Audience API. The key never
 *     reaches the browser.
 *
 * UX contract:
 *   - One input (email), one button, one status line.
 *   - Submit disabled during fetch.
 *   - On success: form acknowledges receipt of the request. The API also
 *     returns success for some upstream 4xx responses, and a confirmation
 *     email depends on the audience's double-opt-in configuration, so the
 *     page must not claim a subscription or confirmation email occurred.
 *   - On HTTP error: inline error message, form re-armed.
 *   - On network failure: same — never a thrown promise, never a
 *     blank screen.
 *
 * Accessibility:
 *   - `<label>` associated via `htmlFor`/`id`.
 *   - Status updates fire on a live region (`aria-live="polite"`) so
 *     screen readers announce success/error.
 *   - Error state mirrored on `aria-invalid` for the input.
 */

import { useCallback, useId, useState, type FormEvent, type ReactElement } from "react";
import styles from "./NewsletterSignup.module.css";

/**
 * Default admin-ui origin. The deployed docs site needs to POST
 * cross-origin; the matching route handler echoes a permissive CORS
 * header for `*.humangr.com` origins (see
 * `apps/admin-ui/src/app/api/newsletter/subscribe/route.ts`).
 */
const DEFAULT_SUBSCRIBE_URL = "https://humangr.com/corelink/api/newsletter/subscribe";

export interface NewsletterSignupProps {
  /**
   * Tag the submission with the placement (e.g. "docs-home",
   * "docs-blog"). Surfaces in Resend as the `x-corelink-source`
   * header on the upstream call.
   */
  readonly source?: string;
  /**
   * Locale slug (e.g. "en-US", "pt-BR"). Defaults to "en-US" if the
   * component is rendered server-side without a context.
   */
  readonly locale?: string;
  /**
   * Override the admin-ui endpoint (used in tests + local dev).
   */
  readonly subscribeUrl?: string;
  /**
   * Override the visible title (so the pt-BR/es-419/de MDX can pass
   * a translated string without forking the component).
   */
  readonly title?: string;
  readonly subtitle?: string;
  readonly placeholder?: string;
  readonly cta?: string;
  readonly successMessage?: string;
  readonly errorMessage?: string;
  readonly invalidEmailMessage?: string;
  readonly privacyNote?: string;
}

type FormState =
  | { phase: "idle" }
  | { phase: "submitting" }
  | { phase: "success" }
  | { phase: "error"; message: string };

// Mirror of the server-side regex — keeps the round-trip fast for
// obvious typos. Server is authoritative.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function NewsletterSignup(props: NewsletterSignupProps): ReactElement {
  const {
    source = "docs",
    locale = "en-US",
    subscribeUrl = DEFAULT_SUBSCRIBE_URL,
    title = "Follow CoreLink",
    subtitle = "Release notes, design essays, and post-mortems. About one email a month. Unsubscribe anytime.",
    placeholder = "you@company.com",
    cta = "Subscribe",
    successMessage = "Thanks. We received your request.",
    errorMessage = "Something went wrong. Please try again in a moment.",
    invalidEmailMessage = "Please enter a valid email address.",
    privacyNote,
  } = props;

  const inputId = useId();
  const statusId = useId();
  const [email, setEmail] = useState("");
  const [state, setState] = useState<FormState>({ phase: "idle" });

  const onSubmit = useCallback(
    async (e: FormEvent<HTMLFormElement>): Promise<void> => {
      e.preventDefault();
      const trimmed = email.trim().toLowerCase();
      if (!EMAIL_RE.test(trimmed)) {
        setState({ phase: "error", message: invalidEmailMessage });
        return;
      }
      setState({ phase: "submitting" });
      try {
        const resp = await fetch(subscribeUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: trimmed, source, locale }),
          // No credentials — the endpoint is anonymous by design.
          credentials: "omit",
        });
        if (!resp.ok) {
          setState({ phase: "error", message: errorMessage });
          return;
        }
        setState({ phase: "success" });
        setEmail("");
      } catch {
        setState({ phase: "error", message: errorMessage });
      }
    },
    [email, invalidEmailMessage, errorMessage, subscribeUrl, source, locale],
  );

  if (state.phase === "success") {
    return (
      <section className={styles.root} aria-labelledby={`${inputId}-title`}>
        <h2 id={`${inputId}-title`} className={styles.title}>
          {title}
        </h2>
        <p
          className={`${styles.status} ${styles.statusSuccess}`}
          role="status"
          aria-live="polite"
        >
          {successMessage}
        </p>
      </section>
    );
  }

  const isSubmitting = state.phase === "submitting";
  const isError = state.phase === "error";

  return (
    <section className={styles.root} aria-labelledby={`${inputId}-title`}>
      <h2 id={`${inputId}-title`} className={styles.title}>
        {title}
      </h2>
      <p className={styles.subtitle}>{subtitle}</p>
      <form className={styles.form} onSubmit={onSubmit} noValidate>
        <label htmlFor={inputId} className="u-sr-only">
          Email address
        </label>
        <input
          id={inputId}
          className={styles.input}
          type="email"
          name="email"
          autoComplete="email"
          inputMode="email"
          required
          placeholder={placeholder}
          value={email}
          onChange={(e): void => setEmail(e.target.value)}
          disabled={isSubmitting}
          aria-invalid={isError || undefined}
          aria-describedby={statusId}
        />
        <button
          type="submit"
          className={styles.button}
          disabled={isSubmitting || email.length === 0}
        >
          {isSubmitting ? "..." : cta}
        </button>
      </form>
      <p
        id={statusId}
        className={`${styles.status} ${isError ? styles.statusError : ""}`}
        role="status"
        aria-live="polite"
      >
        {isError ? state.message : ""}
      </p>
      {privacyNote ? <p className={styles.privacy}>{privacyNote}</p> : null}
    </section>
  );
}
