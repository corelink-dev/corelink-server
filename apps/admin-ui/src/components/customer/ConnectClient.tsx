// Connect a tool (W2) — per-surface copy-paste config to point a build tool at
// the tenant's CoreLink cache. Tokens are ALWAYS referenced via an env var
// (CORELINK_TOKEN), NEVER inlined as `--pat` (CTRL-CRED-001, a hard rule).
//
// Data-truth: the cache-surface endpoints are [live]; the token itself is minted
// on /customer/keys (this screen only teaches how to wire it). There is no wired
// "test connection" endpoint, so the test affordance is a teaching Callout — it
// never fakes a success.

"use client";

import React from "react";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  HelpPopover,
  InlineError,
  Skeleton,
  SnippetTabs,
} from "@/components/ui/linear";
import { useCustomerClient } from "@/lib/use-customer-client";
import type { ConnectSurface, CustomerOverview, CustomerPat } from "@/lib/customer-types";

// Prod API origin (NEXT_PUBLIC_CORELINK_API_URL is inlined at build time). We
// keep a stable default so the snippets are copy-paste-ready even before the
// env var resolves in a given environment.
const API_ORIGIN =
  (typeof process !== "undefined" ? process.env?.NEXT_PUBLIC_CORELINK_API_URL : undefined) ??
  "https://corelink-api.humangr.com";

// Live docs site (the dotted `docs.` name under the apex never resolved).
const DOCS_ROOT = "https://humangr.com/corelink/docs";
const DOCS = `${DOCS_ROOT}/integrations`;

// The env-var name every snippet reads its token from. Referenced, never inlined.
const TOKEN_ENV = "CORELINK_TOKEN";

interface SurfaceDef extends ConnectSurface {
  /** One-line "what this does" shown next to the tab in the surface guide. */
  what: string;
  /** Plain-language HelpPopover body. */
  help: string;
}

function buildSurfaces(origin: string, tenantId: string): SurfaceDef[] {
  return [
    {
      id: "bazel",
      label: "Bazel",
      lang: "python",
      what: "Remote cache for Bazel via the REAPI v2 endpoint (cache only — no remote execution).",
      help: "Adds a Bazel remote cache. Reads $" +
        TOKEN_ENV +
        " into the gRPC/HTTP Authorization header — no token is written into .bazelrc.",
      docsHref: `${DOCS}/bazel`,
      code: `# .bazelrc — CoreLink remote cache (Bazel REAPI v2)
# Export your token first (never commit it):
#   export ${TOKEN_ENV}=<paste a PAT from /customer/keys>
build --remote_cache=${origin}/bazel/v2
build --remote_header=x-corelink-tenant=${tenantId}
build --remote_header=authorization="Bearer \${${TOKEN_ENV}}"
build --remote_upload_local_results=true`,
    },
    {
      id: "turbo",
      label: "Turborepo",
      lang: "bash",
      what: "Shared remote cache for Turborepo tasks across your team and CI.",
      help: "Points Turborepo's remote cache at CoreLink. The token is passed via the TURBO_TOKEN env var, sourced from $" +
        TOKEN_ENV +
        ".",
      docsHref: `${DOCS}/turborepo`,
      code: `# Turborepo remote cache (env only — nothing secret in turbo.json)
export TURBO_API=${origin}
export TURBO_TEAM=${tenantId}
export TURBO_TOKEN="\${${TOKEN_ENV}}"

# then run as usual — cache hits/misses go to CoreLink:
turbo run build --remote-only`,
    },
    {
      id: "sccache",
      label: "sccache",
      lang: "bash",
      what: "Compiler cache (C/C++/Rust) over the WebDAV surface for sccache.",
      help: "Configures sccache to use CoreLink over WebDAV. The bearer token is read from $" +
        TOKEN_ENV +
        " — never embedded in the URL.",
      docsHref: `${DOCS}/sccache-cargo`,
      code: `# sccache → CoreLink (WebDAV backend) — needs sccache >= 0.15
export SCCACHE_WEBDAV_ENDPOINT=${origin}/cargo/${tenantId}
export SCCACHE_WEBDAV_TOKEN="\${${TOKEN_ENV}}"
export SCCACHE_MULTILEVEL_CHAIN="disk,webdav"   # local disk in front of CoreLink
export SCCACHE_DIR="$HOME/.cache/sccache"       # where the local layer lives
export RUSTC_WRAPPER=sccache

# Without SCCACHE_MULTILEVEL_CHAIN sccache is remote-only: it picks exactly one
# backend, so every single cache read becomes a network round trip.

# verify it is wired:
sccache --show-stats`,
    },
    {
      id: "npm",
      label: "npm",
      lang: "bash",
      what: "Pull public npm dependencies through the shared `_public` mirror.",
      help: "Routes npm installs through CoreLink's `_public` mirror (shared, deduplicated). The auth token comes from $" +
        TOKEN_ENV +
        " via .npmrc's env-var interpolation.",
      docsHref: `${DOCS}/npm`,
      code: `# .npmrc — CoreLink _public npm mirror (auth via env, not inline)
registry=${origin}/_public/npm/
//${API_HOST(origin)}/_public/npm/:_authToken=\${${TOKEN_ENV}}

# then install as normal:
npm install`,
    },
    {
      id: "pip",
      label: "pip",
      lang: "bash",
      what: "Pull public PyPI packages through the shared `_public` mirror.",
      help: "Points pip at CoreLink's `_public` PyPI mirror. Credentials are injected from $" +
        TOKEN_ENV +
        " into the index URL at runtime — nothing secret is stored on disk.",
      docsHref: `${DOCS}/pip`,
      code: `# pip → CoreLink _public PyPI mirror (token from env, not committed)
export PIP_INDEX_URL="https://token:\${${TOKEN_ENV}}@${API_HOST(origin)}/_public/pypi/simple/"

# then install as normal:
pip install -r requirements.txt`,
    },
    {
      id: "cas",
      label: "CAS (curl)",
      lang: "bash",
      what: "Raw content-addressable store — a direct put/get to prove the wiring.",
      help: "The native CAS surface: content addressed by BLAKE3. Use it to smoke-test your token. The bearer is read from $" +
        TOKEN_ENV +
        " so it never lands in your shell history as a literal.",
      docsHref: `${DOCS}/raw-curl`,
      code: `# Native CAS — write one blob, then read it back (token via env only)
#   export ${TOKEN_ENV}=<paste a PAT from /customer/keys>
# Needs b3sum (macOS: brew install b3sum; Linux: cargo install b3sum) —
# CAS digests are BLAKE3, not SHA-256.
HASH=$(printf 'hello corelink' | b3sum --no-names)

# PUT:
printf 'hello corelink' | curl -sS -X PUT \\
  -H "authorization: Bearer \${${TOKEN_ENV}}" \\
  --data-binary @- "${origin}/v1/cas/${tenantId}/$HASH"

# GET (should echo it straight back):
curl -sS -H "authorization: Bearer \${${TOKEN_ENV}}" "${origin}/v1/cas/${tenantId}/$HASH"`,
    },
  ];
}

// Host portion of the origin, for registry lines that need a bare host.
function API_HOST(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }
}

export function ConnectClient(): React.ReactElement {
  const client = useCustomerClient();
  const [overview, setOverview] = React.useState<CustomerOverview | null>(null);
  const [pats, setPats] = React.useState<CustomerPat[] | null>(null);
  const [error, setError] = React.useState<unknown>(null);
  const [reloadKey, setReloadKey] = React.useState(0);

  React.useEffect(() => {
    let alive = true;
    setError(null);
    setOverview(null);
    setPats(null);
    client
      .getOverview()
      .then((d) => {
        if (alive) setOverview(d);
      })
      .catch((e: unknown) => {
        if (alive) setError(e);
      });
    // Token-awareness (best-effort): a keys-list failure must NOT break Connect —
    // it only decides whether the CTA nudges "mint a token first". Default to an
    // empty list on error so the guide still renders.
    client
      .listKeys()
      .then((r) => {
        if (alive) setPats(r.pats);
      })
      .catch(() => {
        if (alive) setPats([]);
      });
    return () => {
      alive = false;
    };
  }, [client, reloadKey]);

  if (error != null) {
    return (
      <InlineError
        error={error}
        onRetry={() => setReloadKey((k) => k + 1)}
      />
    );
  }

  if (overview == null) {
    return (
      <Card>
        <Skeleton rows={4} />
      </Card>
    );
  }

  const surfaces = buildSurfaces(API_ORIGIN, overview.tenant_id);

  // pats === null → keys not yet known (still loading / errored to []); once known,
  // an active PAT is any row without a revoked_at timestamp.
  const keysKnown = pats != null;
  const hasActivePat = pats != null && pats.some((p) => p.revoked_at == null);
  const needsToken = keysKnown && !hasActivePat;

  return (
    <div data-testid="connect-root">
      <Callout tone="info">
        Your snippets read the token from a <code>${TOKEN_ENV}</code> environment variable.
        Mint one, then export it before you run a build — CoreLink never asks you to paste a
        token inline (that would leak it into shell history and config files).
      </Callout>

      <div className="lin-mt">
        {needsToken ? (
          <Callout tone="warn">
            You don&apos;t have an active token yet — mint one before wiring a tool. Every
            snippet below reads it from <code>${TOKEN_ENV}</code>.
          </Callout>
        ) : null}
        <div className={needsToken ? "lin-mt" : undefined}>
          <Button
            href="./keys"
            variant={needsToken ? "primary" : "ghost"}
            size="sm"
          >
            {needsToken ? "Mint a token first" : "Manage tokens"}
          </Button>
        </div>
      </div>

      <Card
        className="lin-mt-lg"
        title="Point a build tool at your cache"
        meta={`Endpoint ${API_ORIGIN} · tenant ${overview.tenant_id}`}
        actions={
          <Button href={DOCS_ROOT} variant="ghost" size="sm" target="_blank" rel="noopener noreferrer">
            Docs
          </Button>
        }
      >
        <SnippetTabs
          tabs={surfaces.map((s) => ({
            id: s.id,
            label: s.label,
            code: s.code,
            lang: s.lang,
          }))}
        />
      </Card>

      <div className="lin-mt-lg" data-testid="connect-guide">
        {surfaces.map((s, i) => (
          <Card
            key={s.id}
            className={i > 0 ? "lin-mt" : undefined}
            title={s.label}
            actions={
              <>
                <HelpPopover label={`About ${s.label}`}>{s.help}</HelpPopover>
                <Button href={s.docsHref} variant="ghost" size="sm" target="_blank" rel="noopener noreferrer">
                  Docs
                </Button>
              </>
            }
          >
            <p className="lin-t2">{s.what}</p>
          </Card>
        ))}
      </div>

      <Card className="lin-mt-lg" title="Test connection">
        <Callout tone="info">
          There is no “test” button here on purpose — the real proof is a real hit. Run one of
          the snippets above (the CAS/curl tab is the quickest smoke test), then your first
          cache request shows up on <a href=".">Home</a>. When it does, you are connected.
        </Callout>
        <EmptyState
          title="No hits from this tool yet"
          body="Run a build (or the CAS put/get) with $CORELINK_TOKEN exported. Your first request will land on Home — we don't fake a success here."
        />
      </Card>

      <div className="lin-mt-lg">
        <Callout tone="warn">
          Keep <code>${TOKEN_ENV}</code> in your shell env or CI secrets — never commit it and
          never pass a token as an inline <code>--pat</code> flag. Rotate or revoke it any time
          from your keys page.
          <div className="lin-mt">
            <Button href="./keys" variant="ghost" size="sm">
              Manage tokens
            </Button>
          </div>
        </Callout>
      </div>
    </div>
  );
}

export default ConnectClient;
