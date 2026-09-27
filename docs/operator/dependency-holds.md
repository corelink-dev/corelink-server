# Dependency holds

Honest, evidenced record of dependency majors (Rust and JS/TS) that are
**intentionally held back** — each one was actually attempted (bump → resolve →
compile/lint/build), broke for a specific, captured reason, and was reverted
rather than force-adopted with a hack. This file is **documentation, not a gate**:
it converts vague "we're behind on deps" into a tracked, reproducible hold with the
exact upstream condition that unblocks each one.

Do **not** force any of these green with `#[allow]` / `[patch]` / pin-around /
blanket `eslint-disable` / `@ts-ignore` / skipped tests — a break is a hold, not a
bypass. Revisit each when its named upstream ships.

## corelink-runners image family (B-114/B-135/B-138) — HELD

This is a cross-repository hold, not a missing CoreLink Server implementation.
The image, its `RunnerDevEnvDO` Dockerfile, the image-build workflow, OCI labels,
and the runner-container disk are owned by the sibling `corelink-runners`
repository. The `corelink-server` Actions token cannot inspect the sibling
repository from this CI token, so a local green check cannot prove an image
exists, that its build trigger is real, that an OCI label has a consumer, or
that the build no longer hits `ENOSPC` during containerd import.

Machine boundary: cannot inspect the sibling repository from this CI token;
must not be closed by a corelink-server-only green check; do not re-run the failed image build from this repository.

The dependency chain is intentionally recorded as one hold:

- B-114 remains parked while the DevEnv image/Dockerfile and a reproducible digest
  workflow are unresolved. Removing a server-side reference is not proof that
  the sibling feature was removed.
- B-135 is closed by the exact sibling receipt in
  `docs/campaigns/remediation/B-135-corelink-runners-closure.md`: PR #561's
  tested head/tree and delivered `main` merge/tree are pinned, and the receipt
  records the `pull_request` secretless build-only lane plus removal of the
  unconsumed `corelink.*` OCI labels. This closes the trigger/label finding
  only; it does not claim image publication, repin, rollout, or disk capacity.
  The server must not invent a consumer or treat those labels as GitHub runner
  labels; `runs-on: corelink` is the only local routing contract.
- B-138 remains parked while the sibling build's disk peak is unresolved. Do not
  re-run that failed image build from this repository; choose a measured
  sibling-side remedy (capacity, smaller materialization, or direct registry
  output) before spending another build.

`scripts/verify_runner_image_boundary.py --self-test` is the cheap local
boundary check. It keeps B-114/B-138 `parked`/`manual`, validates B-135's exact
receipt and done status, rejects stale hold prose, invented DevEnv image or
OCI-label wiring, requires the local container-build preflight to fail before
the first `buildctl ... build` invocation, and runs bounded in-memory mutations
of each control. The guard parses active shell commands, ignoring YAML/shell
comments and echo/string bait, and requires the executable `for`/`if`/`exit 1`
sequence. It does not claim to close the sibling image publication, repin,
rollout, or disk-capacity items.

Rust toolchain of record for these attempts: **rustc/cargo 1.91.1**
(`1.91.1-x86_64-apple-darwin`).

---

## rusqlite 0.32 → 0.40  — HELD (2026-07-09)

**Owners:** `corelink-container` (pkg `corelink-server`), `corelink-ops`
(both `features = ["bundled"]`).

**What happens:** resolves fine (`rusqlite 0.40.1` pulls
`libsqlite3-sys 0.38.1`), then the `libsqlite3-sys` **build script** fails to
compile:

```
error[E0658]: use of unstable library feature `cfg_select`
   --> libsqlite3-sys-0.38.1/build.rs:110:9
    |
110 |         cfg_select! {
    = note: see issue #115585 <https://github.com/rust-lang/rust/issues/115585>
error: could not compile `libsqlite3-sys` (build script) due to 1 previous error
```

**Root cause:** `rusqlite 0.40` requires `libsqlite3-sys ^0.38`, and
`libsqlite3-sys 0.38`'s `build.rs` uses the `cfg_select!` macro, which is an
**unstable** library feature (`cfg_select`, rust-lang/rust#115585) not stabilized
on the pinned toolchain (1.91.1). Cannot be worked around without a nightly/newer
stable, which would be a toolchain change, not a dependency change.

**Unblock condition:** bump the pinned toolchain to a rustc that has stabilized
`cfg_select` (or a future `libsqlite3-sys` release that drops the unstable macro
from its build script). Re-attempt the bump then.

---

## password-hash 0.5 → 0.6  — HELD (2026-07-09)

**Owners:** `corelink-auth`, `corelink-pat` (both
`features = ["alloc", "rand_core"]`); `corelink-worker` (dev-dependency,
`features = ["alloc"]`).

**What happens:** resolves by **adding** `password-hash 0.6.1` *alongside* the
existing `password-hash 0.5.0` (the latter is still pulled by `argon2 0.5.3`),
then fails to compile:

```
error[E0432]: unresolved imports `password_hash::Salt`, `password_hash::SaltString`
  --> crates/corelink-pat/src/argon.rs:34:21
   | use password_hash::{Salt, SaltString};
   |                     ^^^^  ^^^^^^^^^^ no `SaltString` in the root, no `Salt` in the root
error[E0412]: cannot find type `Salt` in crate `password_hash`
  --> crates/corelink-pat/src/mint.rs:157:30
```

**Root cause:** `password-hash 0.6` reorganized its public API — the `Salt` /
`SaltString` types are no longer re-exported from the crate root — AND `argon2 0.5`
still pins `password-hash ^0.5`, so the two majors coexist and `argon2 0.5`'s API
surfaces the *0.5* salt types, not the 0.6 ones. password-hash cannot be bumped in
isolation: it is a **coordinated bump with `argon2` (0.5 → 0.6)** plus source
changes to the moved import paths. That is out of scope for a single-dep bump and
out of scope for a Cargo-only change.

**Unblock condition:** bump `argon2 0.5 → 0.6` in lockstep (argon2 0.6 pairs with
password-hash 0.6 and re-exports the salt types) and update the `use
password_hash::{Salt, SaltString}` import sites in `corelink-pat` (and the argon2
call sites in `corelink-auth`). Do it as one `argon2 + password-hash` PR.

---

## rand_chacha 0.9 → 0.10  — HELD (2026-07-09)

**Owners:** 22 crates (`corelink-ac`, `corelink-cas`, `corelink-gc`,
`corelink-worker`, the billing family, the privacy family, `corelink-ops`,
`corelink-telemetry`, `corelink-tracing`, …).

**What happens:** resolves cleanly (`rand_chacha 0.10.0` pulling
`rand_core 0.10.1`, which is already in the graph) and **21 of the 22 owners
compile**. Only `corelink-worker`'s timing-padding middleware (behind the
`tower-middleware` feature) breaks:

```
error[E0599]: no function or associated item named `seed_from_u64` found for struct `ChaCha20Rng`
   --> crates/corelink-worker/src/middleware/timing_padding/padding.rs:42:40
    | 42 | let mut rng = ChaCha20Rng::seed_from_u64(request_id_seed);
note: there are multiple different versions of crate `rand_core` in the dependency graph
    | use rand::{rngs::OsRng, Rng, SeedableRng, TryRngCore};
    |                              ----------- `SeedableRng` imported here doesn't correspond
    |                                          to the right version of crate `rand_core`
```

(same failure at `stats.rs:174`).

**Root cause:** `rand_chacha 0.10` implements `rand_core 0.10`'s `SeedableRng`,
but `corelink-worker` imports `SeedableRng` from `rand` 0.9 (which re-exports
`rand_core 0.9`'s trait) and calls `ChaCha20Rng::seed_from_u64(...)`. Because
`rand` is still on `rand_core 0.9`, the trait the code has in scope does not match
the trait the 0.10 RNG type implements, so `seed_from_u64` is not found. This
exactly confirms the pre-bump hypothesis (mixed `rand_core` majors). Splitting the
dep (worker pinned to 0.9 while the other 21 owners go 0.10) would leave the SAME
dependency at two majors across the tree — a split-version inconsistency the
zero-debt mandate forbids — so the whole bump is held rather than partially
adopted.

**Unblock condition:** either (a) migrate `corelink-worker`'s `timing_padding`
module to seed `ChaCha20Rng` via `rand_chacha`'s own `SeedableRng`
(`use rand_chacha::rand_core::SeedableRng`) at both call sites, or (b) bump `rand`
to a release that rides `rand_core 0.10` and do the whole `rand` + `rand_chacha`
family in one PR. Either is a source change beyond a Cargo-only bump.

---

## eslint 9.39.4 → 10.6.0  (+ @eslint/js 9.39.4 → 10.0.1)  — HELD (2026-07-09)

- **Packages:** `apps/admin-ui`, `apps/docs`
- **Blocking error** (both `admin-ui` and `docs` lint, identical):

  ```
  ESLint: 10.6.0
  TypeError: Error while loading rule 'react/display-name': contextOrFilename.getFilename is not a function
      at resolveBasedir (.../eslint-plugin-react@7.37.5/lib/util/version.js:31)
  ```

- **Root cause:** ESLint 10 removed the deprecated `context.getFilename()` method.
  `eslint-plugin-react@7.37.5` (the latest release, pulled transitively via
  `eslint-config-next@16.2.10` → `eslint-plugin-react: ^7.37.0`, and directly in docs)
  still calls it. `eslint-plugin-react@latest` declares `peerDependencies.eslint`
  `^3 || ^4 || ^5 || ^6 || ^7 || ^8 || ^9.7` — **no published version supports ESLint 10.**
- **Unblocks when:** `eslint-plugin-react` ships a release that drops the
  `context.getFilename()` call and widens its ESLint peer to `^10`, and
  `eslint-config-next` picks it up.

---

## typescript 6.0.3 → 7.0.2  — HELD (2026-07-09)

- **Packages:** all 6 (`admin-ui`, `docs`, `analytics-worker`, `get-corelink-worker`,
  `signup-worker`, `worker`)
- **Blocking errors** (TS 7.0.2 is the native Go compiler — it ships the `tsc` CLI but
  not the classic in-process JS Compiler API that the toolchain consumes):

  1. `apps/admin-ui` — `next build`:

     ```
     Running TypeScript ...
     It looks like you're trying to use TypeScript but do not have the required package(s) installed.
     ...
     The "id" argument must be of type string. Received undefined
     Next.js build worker exited with code: 1 and signal: null
     ```
     (Next 16's type-check step cannot load the TS 7 Compiler API, decides TS is "not
     installed", tries to auto-install, and the build worker crashes.)

  2. `apps/docs` — `tsc --noEmit`:

     ```
     tsconfig.json(4,5): error TS5102: Option 'baseUrl' has been removed. Please remove it from your configuration.
     ```
     (`@docusaurus/tsconfig` sets `baseUrl`; TS 7 removed the option.)

  3. `apps/docs` — `eslint`:

     ```
     @typescript-eslint/typescript-estree@8.61.1 ... getWatchProgramsForProjects.js:45
     ```
     (`@typescript-eslint` 8.61 peer is `typescript >=4.8.4 <6.1.0`; it crashes loading
     the removed watch-program API under TS 7.)

- **Note:** the 4 worker packages typecheck clean under TS 7 (they use the `tsc` CLI
  only), but TS 7 is held as a single unit rather than split-braining the monorepo's
  TypeScript major across packages for marginal benefit.
- **Unblocks when:** Next.js ships TS-7-native Compiler-API support, `@docusaurus/tsconfig`
  drops `baseUrl`, and `@typescript-eslint` ships a TS-7-compatible release (peer widened
  past `<6.1.0`).

## @cloudflare/workers-types 4 → 5  — HELD (2026-07-09)

- **Packages:** `worker`, `apps/analytics-worker`, `apps/get-corelink-worker`,
  `apps/signup-worker` (kept on a single version across all 4 workers for consistency).
- **Blocking error** — `worker/` vitest gate runs `npm install` (the lockfile is
  gitignored there, and npm — unlike pnpm — is strict about peer resolution):

  ```
  npm error While resolving: @sentry/cloudflare@10.64.0
  npm error   peerOptional @cloudflare/workers-types@"^4.x" from @sentry/cloudflare@10.64.0
  npm error Found: @cloudflare/workers-types@5.20260708.1
  ```

- **Root cause:** `@sentry/cloudflare@10.64.0` declares
  `peerOptional @cloudflare/workers-types@"^4.x"`. `npm install` (the actual worker
  vitest gate) refuses to resolve `^5` against that `^4.x` peer and fails with `ERESOLVE`.
  `pnpm` tolerates the `peerOptional` mismatch (which is why a local pnpm-only test
  passed), but **npm is the gate** — so `^5` is not cleanly adoptable. Per policy a break
  is a hold, not a bypass: no `--legacy-peer-deps`, no `overrides`, no split-version.
- **Unblocks when:** `@sentry/cloudflare` ships a release widening its
  `@cloudflare/workers-types` peer to `^5` (or drops the peer).

---

_Last reviewed: 2026-07-09 (branches `deps/rust-majors-frontier` + `deps/js-majors-frontier`)._
