// Dependency-free source of truth for the staging proof admission window.
// Keep this import safe before pnpm dependencies are installed.
export const PROBE_WINDOW = Object.freeze({
  cron: "*/2 * * * *",
  starts_ms: 1790924400000,
  last_entry_ms: 1790931600000,
  expires_ms: 1790936100000,
  nonce: "issue-1700-recovery-20261002-v13",
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
