### Fixed

- **#1700 native staging proof moved from the v12 window to the earlier v13
  window.** The v12 tuple (`issue-1700-recovery-20261002-v12`,
  2026-10-02T15:00Z–18:15Z) was never dispatched and is never reused. Every
  compiled consumer (native window JSON, Worker cleanup window, PID1 supervisor,
  deploy guard, HTTP/runtime receipt validators, rollback quiescence and i2575
  readiness) now binds `issue-1700-recovery-20261002-v13`: dispatch
  2026-10-02T07:00Z–07:20Z, last admission 09:00Z inclusive, expiry 10:15Z
  exclusive (exactly v12 − 8 h). The legacy scheduled path stays HTTP-only for
  v13. Source only: no provider call, dispatch or deploy.
