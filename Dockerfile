# syntax=docker/dockerfile:1.6
# Multi-stage build otimizado pra Cloudflare Containers.
# Target: menor imagem possível, binário estaticamente linkado.
#
# === 2026-05-28 cache-invalidation fix (WHY this layout) ===
#
# The PRIOR layout used a stub-build trick (write empty `main.rs`+`lib.rs`,
# `cargo build -p corelink-server`, delete the stubs, COPY real source,
# rebuild) to keep transitive deps in a cached image layer. That layout
# shipped a prod incident: a one-file fix in `crates/corelink-container/
# src/routes/cas.rs` produced bit-identical image hashes on three
# consecutive `wrangler containers build` invocations, blocking deploy.
#
# Root cause: the stub build leaves a `target/` populated with cargo
# fingerprints derived from the stub source contents. That target/ ends
# up baked into the cached image layer. On the subsequent real-source
# `cargo build`, cargo's incremental compilation walks those fingerprints
# and — under certain inputs (subtle file-mtime or content-hash overlap,
# and confirmed under `wrangler containers build`'s caching path which
# isn't cleared by `docker buildx prune -af`) — concludes the
# `corelink-server` crate doesn't need recompilation. Result: the
# release binary at `/build/target/release/corelink-server` is the
# STUB binary, not the real one. The `COPY --from=builder` then ships
# that stub-derived binary, layer hash unchanged across builds.
#
# Fix (chosen for minimum complexity + maximum correctness): replace the
# stub-build trick with BuildKit cache mounts for both `$CARGO_HOME`
# (registry/git) AND `/build/target`. Both live outside the image layer
# tree, so:
#   1. The image layer for the build RUN step is content-addressed only
#      by the COPY inputs + RUN script — no stale fingerprint state can
#      hide in it across builds.
#   2. `cargo build` still gets full incremental + dep cache benefits on
#      warm rebuilds via the cache mount.
#   3. We copy the binary OUT of the cache mount to `/out/` within the
#      same RUN step so the runtime stage's `COPY --from=builder`
#      can find it (cache mounts only exist during their RUN step).
#
# We additionally pass `CARGO_INCREMENTAL=0`: in release-profile builds
# incremental adds little (per cargo docs) and removes the precise
# class of fingerprint-staleness that bit us. Clean release rebuilds of
# the bin crate on warm cache are still cheap (deps cached in mount).
#
# Cold-build cost: unchanged from prior layout (~10–15 min on amd64).
# Warm-build cost: comparable (a few min for a one-file edit) — the cargo
# cache mount still holds compiled DEPS; only the ~93 first-party crates are
# force-cleaned+recompiled (see the "first-party clean" RUN step below).
# Layer-hash invariant: any change under `crates/`, `tools/`,
# `tests/`, `migrations/`, `apps/migrate-single-to-multi-region/`,
# `Cargo.toml`, or `Cargo.lock` busts the build RUN step and produces
# a fresh binary in the output image.
#
# === 2026-06-21 RECURRENCE: stale FIRST-PARTY .rlib in the target mount ===
#
# The 2026-05-28 mount layout fixed stale IMAGE LAYERS but the stale-BINARY
# class recurred: cargo reused stale first-party `.rlib`s from the persistent
# `id=corelink-target` mount on a committed source change. Robust fix lives on
# the build RUN step below — force-clean exactly the first-party workspace
# members (via `cargo metadata --no-deps`) before building, keeping the dep
# cache. See that step's comment for the full root-cause + rationale.
#
# Wave-33 Stage 2.B.2 — Dockerfile referenced a `src/` at repo root that
# never existed; binary lives in `crates/corelink-container/`. The
# `[workspace]` Cargo resolver requires every member's manifest before
# scheduling any build, so we copy the whole workspace tree.

# ---- Build stage ----
# HO-1: digest-pinned per Wave-32 Phase E audit (supply-chain integrity).
# Tag rust:1.91-slim-bookworm is preserved alongside the digest for human
# readability; the digest is the authoritative reference. Refresh both
# together when bumping the Rust toolchain.
FROM rust:1.91-slim-bookworm@sha256:ac77791dbc2ab3cd3ab732fe9b45b0414a794743da99e679fa99e8faa3b6c1e3 AS builder

# Deps pra compilar protos e linkagem.
# `jq` is builder-only (never copied into the runtime stage): the build RUN
# step below uses it to parse `cargo metadata --no-deps` into the exact set of
# first-party workspace member packages to force-clean from the cargo target
# cache mount (see the "first-party clean" comment on the build RUN step).
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    pkg-config \
    libssl-dev \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace manifest + lock + per-crate manifests + sources.
# Copying the entire `crates/` + `tools/` tree is unavoidable because the
# workspace resolver reads every member's `Cargo.toml` before scheduling
# any build; restricting the copy to manifests-only would require a
# parallel manifest-only synthetic tree (adds drift risk for marginal
# cache savings on a workspace with 120+ members).
#
# All COPY layers below feed the cache key of the build RUN step. Any
# source-byte change under these paths invalidates the build layer and
# forces a fresh `cargo build` against the cache-mounted state.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tools ./tools
# Wave-32 Phase E APPLY fix: all workspace members outside crates/ and tools/
# must be present so cargo can resolve the workspace manifest tree. These are
# Rust-only dirs; the non-Rust apps (admin-ui, docs, server) are NOT workspace
# members and are deliberately excluded to keep the build context minimal.
COPY apps/migrate-single-to-multi-region ./apps/migrate-single-to-multi-region
COPY tests ./tests
# Wave-32 Phase E APPLY fix: many crates embed SQL migration files via
# include_str!("../../../migrations/d1/*.sql") at compile time. The
# migrations/ directory must be present in the build context.
COPY migrations ./migrations

# Single build RUN with BuildKit cache mounts.
#
# - `--mount=type=cache,target=/usr/local/cargo/registry` caches the
#   crates.io index + downloaded crate sources across builds.
# - `--mount=type=cache,target=/usr/local/cargo/git` caches git-deps.
# - `--mount=type=cache,target=/build/target,id=corelink-target` caches
#   compiled artifacts + cargo's incremental fingerprint database.
#   `sharing=locked` (default) so concurrent builds don't corrupt it.
#
# Cache mounts are RUN-scoped — they don't appear in the resulting image
# layer. That's the whole point: the build layer hash depends on COPY
# content + RUN script only, never on accumulated cargo state. After
# `cargo build` completes, we copy the binary out of the cache mount
# into `/out/` so the runtime stage's `COPY --from=builder` can read it
# (runtime stage can't see this stage's cache mounts).
#
# `CARGO_INCREMENTAL=0` — release builds don't benefit much from
# incremental, and removing it eliminates the fingerprint-staleness
# class that the prior stub-build layout could trigger.
#
# === 2026-06-21 RECURRENCE FIX — first-party clean (WHY this RUN step) ===
#
# The 2026-05-28 cache-MOUNT layout (above) fixed stale-IMAGE-LAYER staleness
# but did NOT fully fix stale-BINARY staleness, and the bug RECURRED: a
# committed source change under `crates/corelink-container` or
# `crates/corelink-adapter-host` (and, in principle, ANY first-party crate)
# sometimes did NOT recompile — `cargo build` reused a stale `.rlib` from the
# persistent `id=corelink-target` cache mount despite `CARGO_INCREMENTAL=0`.
#
# Root cause: the COPY layers bust the *image-layer* cache key, so this RUN
# step re-executes on any source change — but the `/build/target` CACHE MOUNT
# is, by design, NOT part of that image layer. It survives across builds and
# carries cargo's compiled `.rlib`s + fingerprint database. Under the
# `wrangler containers build` / BuildKit caching path, cargo's fingerprint
# check has been observed to conclude a first-party crate is up-to-date and
# reuse the stale artifact, even though its source bytes changed. The old
# workaround was to manually prepend a `cargo clean -p corelink-server
# -p corelink-adapter-host` — but that hard-codes two crates and misses every
# other first-party crate the binary links (corelink-byok, corelink-ac, …).
#
# Robust fix (keeps the dep cache, never a cold rebuild): before `cargo build`,
# force-clean EXACTLY the first-party workspace members — and only those — out
# of the target mount. The authoritative member list is `cargo metadata
# --no-deps` (93 members today; auto-tracks adds/removes — no hard-coded list
# to drift). `cargo clean --release -p <member>...` removes only those crates'
# release artifacts + fingerprints; every third-party dependency `.rlib` stays
# in the mount (and the registry/git source caches are untouched), so the
# rebuild recompiles ONLY first-party code and relinks. Result: any committed
# first-party source change ALWAYS yields a fresh binary, while a warm build is
# still cheap (deps cached) — a clean of 93 small first-party crates is far
# cheaper than a cold rebuild of the full dependency graph.
#
# We pin the toolchain default before `cargo metadata` (the metadata read needs
# a usable cargo; it does not compile anything). `--locked` keeps Cargo.lock
# authoritative for both the metadata read and the build.
ENV CARGO_INCREMENTAL=0
# BYOK KMS provider for both production binaries. EMPTY by default: the shipped
# image links no KMS provider (owner decision 2026-10-02, #1648 / #1676).
# Customer-key activation then answers 501, and a tenant whose BYOK state is
# not `inactive` is refused fail-closed. #1800 had made the real provider
# mandatory at boot, so the image with `byok-aws-real` but no KMS credentials
# exited with code 1 on every start.
# Arming BYOK is an image change: set this default to `byok-aws-real` in the
# same rollout that provisions CORELINK_BYOK_KMS_ACCESS_KEY_ID and
# CORELINK_BYOK_KMS_SECRET_ACCESS_KEY on every production Worker. A rollout
# replaces every container, so armed and unarmed processes never keep serving
# side by side. Any other value fails the build.
ARG CORELINK_BYOK_PROVIDER_FEATURE=
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=corelink-cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=corelink-cargo-git \
    --mount=type=cache,target=/build/target,id=corelink-target,sharing=locked \
    set -eu; \
    FIRST_PARTY="$(cargo metadata --no-deps --format-version 1 --locked \
        | jq -r '.packages[].name')"; \
    echo "Force-cleaning first-party workspace members from the target cache mount:"; \
    echo "$FIRST_PARTY" | tr '\n' ' '; echo; \
    CLEAN_ARGS=""; \
    for pkg in $FIRST_PARTY; do CLEAN_ARGS="$CLEAN_ARGS -p $pkg"; done; \
    # shellcheck disable=SC2086 -- $CLEAN_ARGS is an intentional list of -p flags
    cargo clean --release --locked $CLEAN_ARGS; \
    case "$CORELINK_BYOK_PROVIDER_FEATURE" in \
        ""|byok-aws-real) ;; \
        *) echo "unsupported CORELINK_BYOK_PROVIDER_FEATURE" >&2; exit 1 ;; \
    esac; \
    # shellcheck disable=SC2086 -- an empty value must expand to no arguments
    cargo build --release --locked -p corelink-server --bin corelink-server \
        ${CORELINK_BYOK_PROVIDER_FEATURE:+--features $CORELINK_BYOK_PROVIDER_FEATURE}; \
    # Keep the fixture-only Gate 4 binary below, but ship the native
    # production-capable sweep under a distinct name.  The two targets have
    # intentionally different contracts and must not overwrite each other.
    # shellcheck disable=SC2086 -- an empty value must expand to no arguments
    cargo build --release --locked -p corelink-server --bin corelink-gc-sweep-production \
        ${CORELINK_BYOK_PROVIDER_FEATURE:+--features $CORELINK_BYOK_PROVIDER_FEATURE}; \
    cargo build --release --locked -p corelink-gc --bin gc_sweep; \
    mkdir -p /out; \
    cp /build/target/release/corelink-server /out/corelink-server; \
    cp /build/target/release/corelink-gc-sweep-production /out/corelink-gc-sweep-production; \
    cp /build/target/release/gc_sweep /out/gc_sweep

# ---- Runtime base stage ----
# HO-1: digest-pinned per Wave-32 Phase E audit (supply-chain integrity).
FROM debian:bookworm-slim@sha256:b29f74a267526ae6ea104eed6c46133b0ca70ce812525df8cd5817698f0a624a AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 corelink \
 && useradd --system --uid 1000 --gid corelink corelink

# GNU timeout and date are supplied by Debian's base coreutils package.
# Keep this native oracle target before Rust artifacts are copied into the image.
COPY scripts/issue_1700_native_supervisor.sh /usr/local/bin/corelink-staging-probe-supervisor
RUN chmod 0755 /usr/local/bin/corelink-staging-probe-supervisor \
 && test -x /usr/bin/timeout \
 && test -x /usr/bin/date

USER corelink

# ---- Runtime image ----
FROM runtime-base AS runtime

# Binary copied out of the builder's cache mount into /out/ (see build
# RUN step above). The cache mount itself is not visible to this stage.
COPY --from=builder /out/corelink-server /usr/local/bin/corelink-server
# Native production-capable sweep. It is separately invoked and remains
# fail-closed unless an owner explicitly supplies a tenant/region scope.
COPY --from=builder /out/corelink-gc-sweep-production /usr/local/bin/corelink-gc-sweep-production
# `gc_sweep` is deliberately a separately invoked utility: the server
# entrypoint remains unchanged and the sweep defaults to non-destructive mode
# unless its explicit gate is armed.
COPY --from=builder /out/gc_sweep /usr/local/bin/gc_sweep

USER corelink

# Consolidated runtime env (HO-3a — per Wave-32 Phase E audit).
ENV RUST_LOG=info \
    PORT=50051

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/corelink-server"]
