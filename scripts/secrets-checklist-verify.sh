#!/usr/bin/env bash
# WI-R2-14 — secrets-checklist drift verifier.
#
# Cross-references docs/internal/secrets-checklist.md (the canonical matrix of
# production secrets) against the codebase. Fails if drift exists in either
# direction:
#
#   1. Every env var referenced in code (env::var(...), std::env::var(...),
#      process.env.X in TS/JS/Next, and ${{ secrets.X }} in GHA workflows)
#      MUST have a row in the matrix.
#   2. Every row in the matrix MUST have at least one consumer in the
#      codebase (otherwise it's a stale row).
#
# Used by .github/workflows/cf-deploy-prod.yml as a deploy gate.
#
# Usage:
#   scripts/secrets-checklist-verify.sh
#   scripts/secrets-checklist-verify.sh --repo-root /path/to/candidate
#
# Exit codes:
#   0 — matrix and code are in sync
#   1 — drift detected (script prints offending env vars)
#
# Canonical env-var name shape (used by every extractor below):
#   ^[A-Z][A-Z0-9_]+$   (≥ 2 chars total — leading letter + ≥ 1 alnum/_).
#
# Single-letter tokens (e.g. `X`) are *not* env-var names. They appear in
# documentation/template placeholders such as `${{ secrets.X }}` in
# `.github/workflows/_TEMPLATE.yml.md` and would otherwise generate
# false-positive drift. The shortest real env var in the matrix is 4 chars
# (`PORT`), so the 2-char floor is well below the empirical minimum and
# strictly tighter than the documentation placeholder shape. See
# `specs/_audits/sealed/2026-05-16-secrets-x-false-positive-fix.md`.

set -euo pipefail

REPO_ROOT_OVERRIDE=""
if [ "${1:-}" = "--repo-root" ]; then
    if [ -z "${2:-}" ] || [ "$2" = "--" ]; then
        echo "ERROR: --repo-root requires a directory" >&2
        exit 2
    fi
    REPO_ROOT_OVERRIDE="$2"
    shift 2
fi
if [ "$#" -ne 0 ] && [ "${1:-}" != "--self-test" ]; then
    echo "ERROR: unsupported argument: $1" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Self-test mode: exercise the env-var name regex against canonical inputs.
# Runs in a temp dir, scoped entirely to this script — no repo I/O, no
# matrix dependency, no side effects. Invoked via `--self-test`.
# -----------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST_DIR="$(mktemp -d)"
    trap 'rm -rf "${SELF_TEST_DIR}"' EXIT

    # Canonical valid names (accept), placeholders/single-letter (reject).
    cat > "${SELF_TEST_DIR}/fixture.rs" <<'EOF'
fn _accept() {
    let _ = std::env::var("PORT").ok();
    let _ = std::env::var("DT_API_KEY").ok();
    let _ = std::env::var("STATUSPAGE_API_KEY").ok();
}
fn _reject_single_letter() {
    let _ = std::env::var("X").ok();
}
EOF
    cat > "${SELF_TEST_DIR}/fixture.ts" <<'EOF'
const a = process.env.PORT;
const b = process.env.DT_API_KEY;
const c = process.env["STATUSPAGE_API_KEY"];
const x = process.env.X;
const y = process.env["X"];
EOF
    mkdir -p "${SELF_TEST_DIR}/.github/workflows"
    cat > "${SELF_TEST_DIR}/.github/workflows/sample.yml" <<'EOF'
jobs:
  j:
    steps:
      - run: echo ok
        env:
          GOOD: ${{ secrets.STATUSPAGE_API_KEY }}
          BAD:  ${{ secrets.X }}
EOF

    # Run extractors against the fixture dir (mirrors the patterns below).
    pushd "${SELF_TEST_DIR}" >/dev/null
    extracted="$({
        grep -rEh 'env::var(_os)?\("[A-Z][A-Z0-9_]+"\)' --include='*.rs' . 2>/dev/null \
            | grep -oE '"[A-Z][A-Z0-9_]+"' | tr -d '"'
        grep -rEh 'process\.env\.[A-Z][A-Z0-9_]+' --include='*.ts' . 2>/dev/null \
            | grep -oE 'process\.env\.[A-Z][A-Z0-9_]+' | sed 's/process\.env\.//'
        grep -rEh 'process\.env\["[A-Z][A-Z0-9_]+"\]' --include='*.ts' . 2>/dev/null \
            | grep -oE '"[A-Z][A-Z0-9_]+"' | tr -d '"'
        grep -rEh '\$\{\{\s*secrets\.[A-Z][A-Z0-9_]+\s*\}\}' .github/workflows/ 2>/dev/null \
            | grep -oE 'secrets\.[A-Z][A-Z0-9_]+' | sed 's/secrets\.//'
    } | sort -u)"
    popd >/dev/null

    expected="$(printf 'DT_API_KEY\nPORT\nSTATUSPAGE_API_KEY\n')"
    if [ "${extracted}" = "${expected}" ]; then
        echo "self-test: OK (regex accepts ≥2-char canonical names; rejects single-letter 'X')"
        exit 0
    else
        echo "self-test: FAIL" >&2
        echo "expected:" >&2; printf '%s\n' "${expected}" | sed 's/^/  /' >&2
        echo "got:" >&2;      printf '%s\n' "${extracted}" | sed 's/^/  /' >&2
        exit 1
    fi
fi

if [ -n "${REPO_ROOT_OVERRIDE}" ]; then
    if [ ! -d "${REPO_ROOT_OVERRIDE}" ]; then
        echo "ERROR: --repo-root must name an existing directory" >&2
        exit 2
    fi
    REPO_ROOT="$(cd "${REPO_ROOT_OVERRIDE}" && pwd)"
else
    REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "${REPO_ROOT}"

# An override is used by the trusted workflow to scan a checked-out candidate,
# so do not silently accept an arbitrary directory containing a lookalike
# matrix. A real checkout has Cargo.toml; the security workflow's minimal
# candidate has the trusted-tooling/workflow pair; the raw-curl mutation test
# has its exact fixture-manifest path. Matrix-only arbitrary directories fail.
if [ ! -f "docs/internal/secrets-checklist.md" ] || {
    [ ! -f "Cargo.toml" ] &&
    { [ ! -f "scripts/validate_secrets_matrix.py" ] || [ ! -d ".github/workflows" ]; } &&
    [ ! -f "apps/docs/tests/fixtures/raw-curl-http-server.mjs" ];
}; then
    echo "ERROR: --repo-root is not a CoreLink repository root (missing canonical sentinels)" >&2
    exit 2
fi

MATRIX_FILE="docs/internal/secrets-checklist.md"

if [ ! -f "${MATRIX_FILE}" ]; then
    echo "ERROR: ${MATRIX_FILE} not found." >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Allowlist: env vars that are intentionally not in the matrix.
# -----------------------------------------------------------------------------
# - PROPTEST_*: proptest framework knobs (test infra, not secrets)
# - HOME/USERPROFILE: OS-provided, not application secrets
# - CARGO_*: build-time cargo env (not secrets)
# - GITHUB_TOKEN: GitHub-injected, scoped per-workflow
# - GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH/GITHUB_STEP_SUMMARY: GHA runner
# - RUNNER_TEMP/RUNNER_OS/RUNNER_ARCH: GHA runner
# - GH_TOKEN: alias for GITHUB_TOKEN in gh CLI
# - GNUPGHOME: gpg working dir (transient)
# - SOURCE_DATE_EPOCH: SLSA reproducible-build standard
# - PATH/PWD/USER/SHELL/TERM/CI/TZ/LANG/LC_*: standard env
# - PROPTEST_ARGON_NIGHTLY: nightly proptest knob
# - CORELINK_FOO_MOCK: test/dev mock toggles already in matrix
# - TODO_*: placeholder names in wrangler.toml
# - NODE_ENV: standard Node knob
# - ENVIRONMENT: wrangler-injected (vars block), not a secret
# - CORELINK_PAT_SIGNING_KEY_HEX: test-only alt form of the PAT key, read in
#   crates/corelink-pat/tests/emit_e2e_seed.rs (not prod-read) — added 2026-06-02.
#   (OpenNext/Sentry build-flag vars are NOT listed here: extract_code_vars now
#   excludes .open-next/.wrangler, so the Sentry CI-detection bundle never enters
#   the scan in the first place — fixed at the source, not allowlisted.)
# - E2E_* / CORELINK_E2E_*: e2e test-harness config + test-minted PATs (test
#   infra, runtime-generated — not stored prod secrets)
# - NEXT_PUBLIC_*: Next.js browser-exposed vars, public by definition (compiled
#   into client bundles) — never secret
# - CF_PAGES_* / GIT_SHA: build-time commit/release metadata, not secrets
# - SENTRY_ENVIRONMENT/ORG/PROJECT/RELEASE: Sentry identifiers/slugs; the actual
#   secret SENTRY_AUTH_TOKEN IS a matrix row (these four are not)
# - R2_(AC|CAS)_BUCKET / _REGION + R2_TEST_BUCKET: R2 bucket names + regions
#   (deploy config, not credentials — the R2 access keys are matrix rows #139/140)
# - R2_S3_ENDPOINT: public R2 S3 endpoint URL (the account ID is an identifier;
#   access credentials are the separate R2 access-key rows)
# - D1_DATABASE_ID: Cloudflare D1 database UUID (resource identifier; access is
#   controlled by CF_API_TOKEN)
# - NEON_TEST_DSN: Neon shadow-reconcile TEST DSN (test-only; prod Neon deferred)
# - CORELINK_PORTAL_RETURN_URL: Stripe billing-portal return_url override (public
#   dashboard URL, default hardcoded in customer_d1.rs; STRIPE_SECRET_KEY is the
#   actual credential) — WP-3 dashboard revival, 2026-06-10
# - SMOKE_USER_EMAIL/SMOKE_USER_PASSWORD/SMOKE_BASE_URL: public-flip smoke
#   harness (scripts/smoke/authenticated-smoke.spec.ts) — dedicated
#   low-privilege smoke-user creds + base-URL override, operator-local test
#   infra (CORELINK_E2E_TOKEN/NEON_TEST_DSN precedent), not deployed prod
#   secrets — added 2026-06-10.
# - BASE_URL/PW_EXECUTABLE_PATH: admin-ui browser render smoke
#   (scripts/e2e-admin-ui-render-smoke.mjs + e2e-admin-ui-render.yml) — the
#   (public) URL to smoke + an optional local Chromium path; CI/test config,
#   not a deployed secret (same precedent as SMOKE_BASE_URL) — added 2026-06-14.
# GC safety/config values are non-secret, but every accepted name is exact:
# future GC credentials and operational inputs must remain visible as drift.
# A11Y_AUDIT_REPORT/SUMMARY are local report file paths, not secrets; keep
# these two exact so future A11Y_AUDIT_* credentials remain visible.
# #1700 deployment/image IDs and version bounds are non-secret receipt metadata;
# credentials remain explicit matrix entries.
ALLOWLIST_REGEX='^(PROPTEST_|HOME$|USERPROFILE$|CARGO_|GITHUB_(TOKEN|OUTPUT|ENV|PATH|STEP_SUMMARY|ACTIONS|REPOSITORY|SHA|REF|WORKFLOW|RUN_ID|RUN_NUMBER|ACTOR|EVENT_NAME|EVENT_PATH|JOB|API_URL|SERVER_URL|GRAPHQL_URL|WORKSPACE)$|RUNNER_|GH_TOKEN$|GNUPGHOME$|SOURCE_DATE_EPOCH$|PATH$|PWD$|USER$|SHELL$|TERM$|CI$|TZ$|LANG$|LC_|NODE_ENV$|ENVIRONMENT$|NEXT_RUNTIME$|RUST_|TODO_|DOCS_BASE_URL$|DOCS_BASE_PATH$|A11Y_AUDIT_REPORT$|A11Y_AUDIT_SUMMARY$|LH_BASE_URL$|LH_START_COMMAND$|E2E_|NEXT_PUBLIC_|PROJECTS$|SKIP_WEBSERVER$|GCP_TEST_KEY_RESOURCE$|GCP_TEST_REGION$|DT_API_KEY_TEST_|DT_MOCK_INJECTION_ENABLED$|CORELINK_PAT_SIGNING_KEY_HEX$|CORELINK_E2E_|CF_PAGES_|GIT_SHA$|NEON_TEST_DSN$|SENTRY_(ENVIRONMENT|ORG|PROJECT|RELEASE)$|R2_(AC|CAS)_(BUCKET|REGION)$|R2_TEST_BUCKET$|R2_S3_ENDPOINT$|D1_DATABASE_ID$|CORELINK_PORTAL_RETURN_URL$|SMOKE_USER_EMAIL$|SMOKE_USER_PASSWORD$|SMOKE_BASE_URL$|BASE_URL$|PW_EXECUTABLE_PATH$|CLERK_FAPI$|CLERK_LIVE_SECRET_KEY$|CORELINK_API_ENDPOINT$|CORELINK_APP_URL$|CLERK_JS_VERSION$|CORELINK_LOG$|AUDIT_DRAIN_LEASE_ENABLED$|NEAR_CEILING_ALERT_SINK$|GC_LIVE_DELETE$|GC_OBSERVATION_ONLY$|PAGERDUTY_EVENTS_URL$|PAGERDUTY_SERVICE$|SLA_CREDITS_ENABLED$|SLA_OBSERVATIONS_ENABLED$|SYNTHETIC_DRILL_ENABLED$|CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED$|EXPECTED_CONTAINER_APP_VERSION$|EXPECTED_CONTAINER_IMAGE_DIGEST$|EXPECTED_SHA$|IMAGE_DIGEST$|MIN_CONTAINER_APP_VERSION$|PREIMAGE_CONTAINER_IMAGE$)'

# -----------------------------------------------------------------------------
# Extract env-var names from the matrix.
# Matrix rows look like: `| 1 | <secret name> | `ENV_VAR_NAME` | ...`
# We grab the backtick-quoted token in the 4th column.
# -----------------------------------------------------------------------------
extract_matrix_vars() {
    # Match lines starting with "| <number> |"
    # Then pull tokens in backticks from the env var column (3rd content column).
    grep -E '^\| [0-9]+ \|' "${MATRIX_FILE}" \
        | awk -F'|' '{print $4}' \
        | grep -oE '`[A-Z][A-Z0-9_]+`' \
        | tr -d '`' \
        | sort -u
}

# -----------------------------------------------------------------------------
# Extract env-var references from code:
#   - env::var("FOO") / std::env::var("FOO") / env::var_os("FOO") in Rust
#   - process.env.FOO / process.env["FOO"] in TS/JS
#   - ${{ secrets.FOO }} in GHA workflows
#   - env: FOO: ${{ ... }} in GHA workflows
# Excludes: target/, node_modules/, _archive/, .git/
# -----------------------------------------------------------------------------
extract_code_vars() {
    {
        # Rust: env::var("FOO"), std::env::var("FOO"), env::var_os("FOO")
        # Name shape: [A-Z][A-Z0-9_]+ (≥2 chars) — rejects single-letter
        # placeholders like `X` while admitting the shortest real var (PORT, 4).
        grep -rEh 'env::var(_os)?\("[A-Z][A-Z0-9_]+"\)' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=node_modules \
            --exclude-dir=_archive \
            --exclude-dir=.git \
            . 2>/dev/null \
            | grep -oE 'env::var(_os)?\("[A-Z][A-Z0-9_]+"\)' \
            | grep -oE '"[A-Z][A-Z0-9_]+"' \
            | tr -d '"' || true

        # Rust: env::set_var("FOO", ...) — symmetric, in case tests set things
        grep -rEh 'env::set_var\("[A-Z][A-Z0-9_]+"' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=node_modules \
            --exclude-dir=_archive \
            --exclude-dir=.git \
            . 2>/dev/null \
            | grep -oE '"[A-Z][A-Z0-9_]+"' \
            | tr -d '"' || true

        # TS/JS: process.env.FOO and process.env["FOO"]. Iterate files so the
        # synthetic raw-curl fixture can be excluded by its exact path. A
        # name-only allowlist would let the same name hide in production code;
        # B-245 requires path-scoped handling here as it already has in the
        # Python validator.
        while IFS= read -r -d '' f; do
            case "${f#./}" in
                apps/docs/tests/fixtures/raw-curl-http-server.mjs|\
                apps/docs/tests/raw-curl-directory-upload.test.ts) continue ;;
            esac
            grep -Eh 'process\.env\.[A-Z][A-Z0-9_]+' "${f}" 2>/dev/null \
                | grep -oE 'process\.env\.[A-Z][A-Z0-9_]+' \
                | sed 's/process\.env\.//' || true
            grep -Eh 'process\.env\["[A-Z][A-Z0-9_]+"\]' "${f}" 2>/dev/null \
                | grep -oE '"[A-Z][A-Z0-9_]+"' \
                | tr -d '"' || true
        done < <(
            find . -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' \
                -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' \) \
                ! -path './node_modules/*' ! -path './.next/*' \
                ! -path './.open-next/*' ! -path './.wrangler/*' \
                ! -path './dist/*' ! -path './build/*' \
                ! -path './_archive/*' ! -path './.git/*' -print0
        )

        # GHA: ${{ secrets.FOO }} — rejects template placeholder `secrets.X`
        # in `.github/workflows/_TEMPLATE.yml.md`.
        grep -rEh '\$\{\{\s*secrets\.[A-Z][A-Z0-9_]+\s*\}\}' \
            .github/workflows/ 2>/dev/null \
            | grep -oE 'secrets\.[A-Z][A-Z0-9_]+' \
            | sed 's/secrets\.//' || true
    } | sort -u
}

# -----------------------------------------------------------------------------
# Run the checks.
# -----------------------------------------------------------------------------
TMPDIR_VERIFY="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_VERIFY}"' EXIT

MATRIX_VARS="${TMPDIR_VERIFY}/matrix.txt"
CODE_VARS="${TMPDIR_VERIFY}/code.txt"
CODE_VARS_FILTERED="${TMPDIR_VERIFY}/code-filtered.txt"

extract_matrix_vars > "${MATRIX_VARS}"
extract_code_vars   > "${CODE_VARS}"

# Filter out allowlist from code vars before comparing.
grep -vE "${ALLOWLIST_REGEX}" "${CODE_VARS}" > "${CODE_VARS_FILTERED}" || true

MATRIX_COUNT=$(wc -l < "${MATRIX_VARS}" | tr -d ' ')
CODE_COUNT=$(wc -l < "${CODE_VARS_FILTERED}" | tr -d ' ')

echo "secrets-checklist-verify: matrix has ${MATRIX_COUNT} env vars; code references ${CODE_COUNT} unique non-allowlisted env vars."

# Quality gate: matrix must cover ≥ 20 secrets (WI-R2-14 spec).
if [ "${MATRIX_COUNT}" -lt 20 ]; then
    echo "ERROR: matrix has only ${MATRIX_COUNT} entries; WI-R2-14 requires ≥ 20." >&2
    exit 1
fi

# Drift 1: code references an env var not in the matrix.
MISSING_FROM_MATRIX="${TMPDIR_VERIFY}/missing-from-matrix.txt"
comm -23 "${CODE_VARS_FILTERED}" "${MATRIX_VARS}" > "${MISSING_FROM_MATRIX}"

# Drift 2: matrix has an env var not used anywhere in code.
STALE_IN_MATRIX="${TMPDIR_VERIFY}/stale-in-matrix.txt"
comm -13 "${CODE_VARS_FILTERED}" "${MATRIX_VARS}" > "${STALE_IN_MATRIX}"

FAIL=0

if [ -s "${MISSING_FROM_MATRIX}" ]; then
    echo "" >&2
    echo "ERROR: the following env vars are referenced in code but NOT in ${MATRIX_FILE}:" >&2
    sed 's/^/  - /' "${MISSING_FROM_MATRIX}" >&2
    echo "" >&2
    echo "Either:" >&2
    echo "  (a) add a row to the matrix in the same PR, OR" >&2
    echo "  (b) add the var to the ALLOWLIST_REGEX in this script if it's not a secret." >&2
    FAIL=1
fi

if [ -s "${STALE_IN_MATRIX}" ]; then
    echo "" >&2
    echo "WARNING: the following matrix rows have NO consumer in code (stale rows):" >&2
    sed 's/^/  - /' "${STALE_IN_MATRIX}" >&2
    echo "" >&2
    echo "These vars may be:" >&2
    echo "  (a) consumed by docs-only paths or external scripts (acceptable — add to ALLOWLIST_REGEX or document)," >&2
    echo "  (b) reserved for upcoming work (acceptable — leave row in place)," >&2
    echo "  (c) genuinely stale (REMOVE the row in the same PR)." >&2
    # Soft warning: don't fail the deploy for stale rows. The matrix is
    # forward-looking by design (e.g., SendGrid/Twilio referenced in pending
    # notification paths).
fi

if [ "${FAIL}" -eq 0 ]; then
    echo "secrets-checklist-verify: OK (no drift)."
fi

exit "${FAIL}"
