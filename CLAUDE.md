# CLAUDE.md

Context for AI agents working in this repo. Keep it lean + high-signal.

## What CoreLink is

A **multi-tenant content-addressable cache + storage-governance platform** on
Cloudflare (Workers + Durable Objects + Containers + R2 + D1). **95 Rust packages**
in the workspace — the population guard is `cargo metadata --no-deps --format-version=1`,
never a listing of `crates/`: that directory holds **75** of them, and 20 live under `tests/`, `tools/` and
`apps/` (the 12 `e2e-*` suites among them). Directory name is also not package
name — `crates/corelink-container` is the package `corelink-server`,
`crates/tenant-path` is `corelink-tenant-path`, `tools/dt-cli` is
`corelink-dt-cli`. A sweep that greps paths is blind to a fifth of the workspace
and mislabels three of the rest; this line said "~73" until 2026-08-30, and
nothing compared it to either real number.
Sold **self-serve to SMBs** — NOT enterprise, and NOT "just a build cache."
It already exposes multiple cache surfaces: native CAS/AC, **Bazel REAPI v2**
(`routes/bazel_v2.rs`), **Turborepo** (`routes/turbo_v8.rs`), and **sccache** (WebDAV).

## Architecture wiki (OKF)

`docs/knowledge/` is the **code-grounded architecture wiki** — **174 OKF concepts**
(recount with `python3 scripts/validate_okf.py`; `index.md` and `log.md` are reserved),
each naming the `source_files` it explains (anti-drift gated against them).
Browse `docs/knowledge/index.md`, or the rendered site `docs/okf-wiki-site/index.html` (search + cross-link graph; regen via `scripts/okf_render.py`). **Rule: before modifying a
subsystem, load its concepts first** — don't work blind. Query them with
`python3 scripts/okf_context.py --file <path>` / `--tag <area>` (add `--full`
for bodies), or invoke the **`okf-context`** skill.

## Working on this repo — gotchas that actually bite

- **Toolchain:** the rustup proxy is broken. Put the toolchain on PATH:
  `PATH="$HOME/.rustup/toolchains/1.91.1-x86_64-apple-darwin/bin:$PATH" cargo …`
- **The self-hosted CI runners ARE the founder's Mac.** Heavy compiles + CI bursts
  overload it (it has crashed). Use `CARGO_BUILD_JOBS=4` for local builds; don't run
  big compiles while CI is hammering; cancel storms; keep the dependabot backlog low
  (a pile of open dependabot PRs + auto-rebase re-floods the Mac on every main merge).
- **Cloudflare secrets are write-only** — you can list deployed secret *names* via the
  CF API but never read values back. Real values live only in `.env.local` (gitignored,
  must be backed up). `CLOUDFLARE_API_TOKEN` in `.env.local` has D1 + Workers read/write.
- **`.env.local` keys are TEST keys** (`sk_test_…`). Live keys are the operator's
  launch-day step (their Clerk/Stripe dashboards).

## Gates (must stay green before merge)

- B-098 spec population → **490 full-schema + 11 YAML-only (501 total)**. `python3 scripts/validate_specs.py` currently reports 488 schema-valid, 11 YAML-only, and 2 missing-front-matter failures.
- Secrets matrix: `bash scripts/secrets-checklist-verify.sh` (OK, no drift) +
  `python3 scripts/validate_secrets_matrix.py` (code_only=0). Both exclude build output
  (`.open-next`/`.wrangler`) — don't let them scan generated bundles.
- `feat:`/`fix:` commits **require a CHANGELOG.md `[Unreleased]` entry** (changelog gate).
- Commits need a **`Signed-off-by:`** trailer (DCO).
- Branch protection `required checks = []`, but **merge only when CI is green** (impeccable).
- `corelink-container` (pkg `corelink-server`) is on the **proptest-density allowlist**.

## ⛔ Before merging ANY PR — do not skip

**Merge with ONE command: `bash scripts/pre-merge-gate-check.sh --merge <PR>`.**
It gates, then `gh pr merge --squash` only if every check is green — the merge
is unreachable otherwise — deletes the merged remote branch itself, and exits on
whether the PR merged, not on whether local cleanup worked (#1051). A **draft**
is refused outright, `--admin-reason` included (#1048). **Never chain
`pre-merge-gate-check.sh <PR> | tail -N && gh pr merge`:** a pipeline's exit
status is `tail`'s, so the gate's refusal is discarded — that is how #1049
merged with 4 checks pending. The report-only form (no flag) is unchanged: run
it and merge ONLY if it prints all-green. The heavy gates (coverage / CodeQL /
ffi-matrix / reproducible-build / cas-foundation) were moved OFF per-PR
(2026-06-02) — no `pull_request`, no `push` lane on any of them — so nothing
gates on them between runs. **Cadence, verified against each workflow's actual
`on:` block (2026-08-16), not assumed:**
- **CodeQL** (`codeql.yml`) — genuinely nightly: `schedule: '30 5 * * *'` +
  `workflow_dispatch`. The only one of this group still on a real clock.
- **coverage** (`coverage.yml`), **cas-foundation** (`cas_foundation.yml`),
  **reproducible-build** (`reproducible-build.yml`) — all **`workflow_dispatch`-only
  today**. coverage and cas-foundation each had a weekly `schedule:` cron that is
  now **commented out** in-file, parked pending a fix. They do NOT run
  automatically at all — only on-demand or when a PR happens to touch a
  workflow that dispatches them. **reproducible-build was re-enabled 2026-08-24**
  (B-016): its zero successful runs were structural, not flaky — it hashed a wasm
  artifact the build cannot produce. It now builds the shipped `corelink-cli`
  binary twice and diffs the bytes; run 32726344224 is the first green one ever
  (bit-identical). Still dispatch-only: two full release builds do not belong on
  a PR.
- **ffi-matrix** (`ffi-matrix-ci.yml`) — **`workflow_dispatch`-only**, no
  `schedule:` in the file at all (matches the standing note that this lane
  "never worked" and is parked).
- **s10-ship-gate — DELETED.** It was a per-sprint SEAL gate
  (`s10-ship-gate.yml`, along with the sibling s07/s08/s09/gc-ship-gate
  files); all were `disabled_manually` with their sprints long sealed, and
  PR #1091 (2026-08-12) removed all 5 as dead weight. There is nothing named
  `s10-ship-gate` left to dispatch.
- **TLA+** (`tla_check.yml`) — path-scoped `pull_request` (only on PRs
  touching `specs/tla/**` / the runner scripts / itself) + `workflow_dispatch`.
  Its cron was removed 2026-08-02 as redundant with the PR trigger, so it is
  **not** on a nightly or weekly clock — it runs when the relevant paths
  change, and on demand otherwise.

None of the above run automatically on an unrelated PR today; if a PR touches
their surface, dispatch the relevant ones explicitly (`gh workflow run
<file>.yml`) rather than assuming a cron will catch it. The checks that REMAIN
on a PR by default are the fast, load-bearing ones and they MUST be green.
Never blind `--admin` merge; if you must `--admin`, state the documented
infra/flake reason explicitly — `--merge --admin-reason "<why>"`, which the
script refuses on draft/pending/conflicting/missing-gate states (those never ran).
(A green PR now takes minutes, not 30+.)

**2026-08-02 correction — the "cron only" rule no longer covers everything it
used to.** 14 workflows that DID have a `pull_request` trigger were still also
running a daily cron, i.e. re-verifying byte-identical code on a clock. Their
crons were removed (`tla_check`, `region_pinning`, `cargo-deny`, `s07/s08/s09-
ship-gate`, `corelink-worker/meta/hash/reapi/client-verify/adapter-host`,
`tenant-path`, `corelink-server`). They are PR-gated and on-demand now.

**The rule to apply going forward: a cron earns its keep ONLY when something can
change WITHOUT a commit** — CVE feeds (cargo-audit / semgrep / CodeQL / trivy /
pnpm-audit), prod state (e2e-prod / canaries / smoke), backups, cert + infra
drift, billing reconciliation, DR drills. Those keep their schedules. Anything
that only changes when code changes belongs on a PR/push trigger. Measured
before the change: 10 of the previous 14 days had ZERO commits to `main`, while
the self-hosted Mac — the founder's own machine — burned ~8.8 h/day on scheduled
jobs, 75% of which failed.

## The backlog

`BACKLOG.md` (repo root) is the **single source of truth** for open work across all
three repos. Not session notes, not memory files, not a chat thread — if it is not
in `BACKLOG.md`, it is not tracked. Every item carries a `verify` command that
decides whether its own claim still holds; `python3 scripts/backlog_verify.py`
runs them and fails on DRIFTED (the item and the repo disagree) or STALE (a
`verify: manual` item older than 14 days). **Read it before planning anything, and
when you finish an item, update its status — finishing the work turns the gate red
until you do.** Fix the item or fix the world; never delete the check.

## Workflow

- Owner mandate: **zero debt, no loose ends, impeccable repo.** Verify claims; never
  loosen rigor without an explicit waiver.
- Use the `/techlead` skill to review before merging. Branch → PR → merge (no direct
  pushes to `main`). End commit messages with the
  `Co-Authored-By: Claude …` trailer; end PR bodies with the Generated-with footer.

### Delivery anchor — throughput is a correctness property

For backlog orchestration, activity is not delivery. Tokens spent, agents spawned,
plans written, tests run and local candidates produced count as work in progress;
only a merged change plus the corresponding `BACKLOG.md` state transition counts
as delivered backlog progress.

- **Integration lane stays hot.** While a cold-LAND candidate exists, the lead's
  next action is to integrate it through all existing required gates or record the
  exact blocking SHA/gate. Do not run another full census, redesign the plan or
  investigate unrelated infrastructure first.
- **Merge serialization never serializes authorship.** A serial merge queue is not
  permission to idle disjoint authors. Keep at least half of available agent slots
  on new, file-disjoint implementation whenever that many executable items exist;
  use the remainder for repair and cold review.
- **Stack to avoid duplicate CI.** Build the integration queue on the last
  certified candidate tree. After its parent squash-merges, reanchor the child on
  the new `main` and compare trees. If the reanchored tree is byte-identical, reuse
  tree-bound heavy-CI evidence and rerun only commit/head-bound gates plus exact-SHA
  cold review. Any tree difference invalidates the evidence and requires the full
  applicable CI bundle again.
- **Partition tests by evidence scope.** Authors run their WP's focal behavior and
  mutation tests plus cheap commit-bound checks; they do not each repeat universal
  repository suites. The lead runs specs, OKF, docs-reality, secrets, global
  workflow validation and other path-equivalent/heavy gates once on the cumulative
  stacked bundle tree. A gate stays per-WP only when combining candidates would
  obscure which invariant or mutation it proves.
- **A pending planning PR is not a fleet stop.** A reviewed contract may be consumed
  read-only from its candidate tree while authors branch from current `main`; the
  lead revalidates the contract before integration. Halt only on a concrete stale
  invariant or file collision, not because the ledger has not merged yet.
- **Census is incremental.** Recount only after `BACKLOG.md` or `main` changes in a
  way that affects the population. Do not repeatedly rediscover the same queue.
- **Checkpoint the delivery ratio.** Every orchestration handoff records merged
  items, open items, landable candidates and active author lanes. Two consecutive
  checkpoints with zero merge/state transitions while a LAND candidate existed is
  an orchestration failure: stop planning and drain the integration queue.

## Don't touch

Other projects share the parent dir (`hugr-wallet`, `HuGR-Smith`, `HuGR-Arsenal`,
Datadog/other runners, `hugr-juiceshop`, etc.). **Only work on CoreLink.**

## Product strategy & roadmap

- **Launch (now):** the cache + storage-governance product. Auth = **Clerk**, billing =
  **Stripe** (the already-built, audited path — not the wallet, not Keycloak).
  Keystone in flight: the `tier_select.rs` checkout backend.
- **Expansion campaign #1 (post-launch, phase 3):** **CI / build-acceleration** —
  ephemeral runners on cheap third-party infra (Hetzner-class) + the cache. It is a
  **feature / natural evolution of CoreLink, NOT a separate product.** The economic
  engine: the cache makes builds **faster (customer loves it) AND cheaper to run (our
  margin)** — a true **win-win** — and there is a **network-effect moat** with a narrow,
  implemented boundary: public pip wheels/sdists and Homebrew bottles are shared
  cross-tenant; npm shares only unscoped package metadata (tarball bytes remain
  per-tenant); and OCI shares owner-pinned digests in `_public` when its boot flags are
  enabled. Native CAS, Bazel, Turborepo, sccache, and private package content remain
  tenant-isolated. More customers can warm those eligible public artifacts for one
  another, while private content stays isolated. Solo $30/mo, COGS ~$5 (~80% margin).
  Tailwind: GitHub starts charging for self-hosted runners Mar 2026.
  **Full brief: `marketing/expansion/ci-build-acceleration.md`.**
