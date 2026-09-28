/**
 * Vitest configuration for the CoreLink worker package.
 *
 * Test strategy:
 * - Unit tests run in the standard Node.js environment.
 *   These test pure functions: route matching, auth middleware, CORS, error
 *   envelopes, timing-pad, and the DO state machine. They do NOT require
 *   a live Cloudflare Workers runtime.
 *
 * - Workerd integration tests (`*.miniflare.test.ts`) run in a REAL workerd
 *   runtime via the separate `vitest.miniflare.config.mts` — programmatic
 *   Miniflare v4 loading the freshly-built bundle by `scriptPath` (+ nodejs_compat).
 *   They cover DO dispatch / cross-tenant isolation / CORS end-to-end, which the
 *   node pool can't exercise. Excluded from THIS (node) config below; both run in
 *   the `worker-vitest` CI gate.
 *
 * Coverage provider: istanbul (v8 requires node:inspector which is not
 * available in the Workers runtime; istanbul works on any JS runtime).
 *
 * (Historical note: an older comment here claimed vitest-pool-workers couldn't be
 * used because miniflare resolved as v3-vs-v4 — that was never true in this tree
 * (only miniflare v4 resolves). The real past breakage was a stale `dist/index.js`
 * loaded as a string; the miniflare harness now always rebuilds + loads via
 * scriptPath. See vitest.miniflare.config.mts.)
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // *.miniflare.test.ts run under vitest.miniflare.config.mts (workerd pool), not the node pool.
    exclude: ["tests/**/*.miniflare.test.ts"],
    globals: true,
    coverage: {
      provider: "istanbul",
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.d.ts",
      ],
      // ── Coverage floor (WP-3, 2026-08-29) ────────────────────────────────
      // These thresholds existed since the file was written but had NEVER once
      // executed: `.github/workflows/worker-vitest.yml` ran `npx vitest run`
      // with no `--coverage`, and vitest only evaluates `thresholds` when the
      // coverage provider is actually enabled. A dormant threshold is not a
      // gate. The workflow now runs `npx vitest run --coverage`.
      //
      // Consequence of that dormancy, measured 2026-08-29 on origin/main: the
      // numbers below had already ROTTED past the old values unnoticed —
      // src/index.ts was written down as 90% lines and actually sits at 77.13%.
      // Every value here is therefore RE-BASELINED against a real measured run
      // and set BELOW it with slack, so the gate is green today and red on the
      // next regression. A floor above reality is an ignored red check, not
      // rigor. Ratchet these UP as coverage improves; never write an
      // aspirational number here.
      //
      // Measured 2026-08-29 (provider: istanbul, include src/**/*.ts):
      //   total                     L 84.97  S 84.01  F 90.55  B 78.14
      //   src/index.ts              L 77.13  S 77.35  F 75.00  B 72.45
      //   src/durable_object.ts     L 81.69  S 80.33  F 88.88  B 79.88
      //   src/rollout_controller.ts L 100    S 100    F 100    B 100
      thresholds: {
        // Global floor across all src files combined (measured 84.97 lines).
        lines: 80,
        functions: 85,
        branches: 73,
        statements: 79,
        "src/index.ts": {
          // Was 90/95/75/90 — unmeetable and never evaluated. Re-baselined
          // below the measured 77.13/75/72.45/77.35. The gap between this
          // floor and the old aspiration is real test debt, not a licence:
          // raise these back up by ADDING tests, never by editing the number.
          lines: 72,
          functions: 70,
          branches: 67,
          statements: 72,
        },
        "src/durable_object.ts": {
          // Was 35/60/25/35 — so loose it could not have caught a collapse.
          // The historical comment claimed ~41% because the CF Container API
          // is unreachable from Node.js; the file actually measures 81.69%
          // lines today, so the floor TIGHTENS from 35 to 76.
          lines: 76,
          functions: 83,
          branches: 74,
          statements: 75,
        },
        "src/rollout_controller.ts": {
          // Was 0/0/0/0 — a threshold that cannot fail. The Phase B stub is in
          // fact fully covered (100% on every axis), so the floor TIGHTENS from
          // 0 to 90 and now catches deletion of its tests.
          lines: 90,
          functions: 90,
          branches: 90,
          statements: 90,
        },
      },
      reporter: ["text", "json"],
    },
    setupFiles: ["./tests/setup.ts"],
  },
  resolve: {
    alias: {
      "cloudflare:workers": new URL("./tests/cloudflare_workers_node_stub.ts", import.meta.url).pathname,
    },
    extensions: [".ts", ".js", ".mts", ".mjs"],
  },
});
