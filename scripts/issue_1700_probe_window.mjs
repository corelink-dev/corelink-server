// Dependency-free source of truth for the staging proof admission window.
// Keep this import safe before pnpm dependencies are installed.
export const PROBE_WINDOW = Object.freeze({
  cron: "*/2 * * * *",
  starts_ms: 1790964000000,
  last_entry_ms: 1790971200000,
  expires_ms: 1790975700000,
  nonce: "issue-1700-recovery-20261002-v15",
});

export function isApprovedProbeWindow(value) {
  return value !== null && typeof value === "object" &&
    value.cron === PROBE_WINDOW.cron &&
    value.starts_ms === PROBE_WINDOW.starts_ms &&
    value.last_entry_ms === PROBE_WINDOW.last_entry_ms &&
    value.expires_ms === PROBE_WINDOW.expires_ms &&
    value.nonce === PROBE_WINDOW.nonce &&
    Object.keys(value).sort().join(",") === "cron,expires_ms,last_entry_ms,nonce,starts_ms";
}

export function deploymentWindowAllows(now = Date.now(), cleanupBudgetMs = 75 * 60_000) {
  return isApprovedProbeWindow(PROBE_WINDOW) && Number.isSafeInteger(now) &&
    Number.isSafeInteger(cleanupBudgetMs) && cleanupBudgetMs >= 0 &&
    now >= PROBE_WINDOW.starts_ms && now < PROBE_WINDOW.starts_ms + 20 * 60_000 &&
    now + cleanupBudgetMs < PROBE_WINDOW.last_entry_ms;
}
