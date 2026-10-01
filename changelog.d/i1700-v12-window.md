### Fixed

- **#1700 native staging proof moved from the expired v11 window to v12.** The
  v11 tuple (`issue-1700-recovery-20261001-v11`, 2026-10-01T20:00Z–23:15Z) expired
  without a dispatch and is never reused. Every compiled consumer (native window
  JSON, Worker cleanup window, PID1 supervisor, deploy guard, HTTP/runtime
  receipt validators, rollback quiescence and i2575 readiness) now binds
  `issue-1700-recovery-20261002-v12`: dispatch 2026-10-02T15:00Z–15:20Z, last
  admission 17:00Z inclusive, expiry 18:15Z exclusive. The legacy scheduled path
  stays HTTP-only for v12. Source only: no provider call, dispatch or deploy.
