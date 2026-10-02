### Fixed

- **#1700 native staging proof moved from the failed v13 window to the v14
  window.** V13 (run 36976287686) passed every read check and the preimage
  capture, then failed closed at the first bootstrap write; an independent
  readback showed no provider change, and its nonce
  `issue-1700-recovery-20261002-v13` is never reused. Every compiled consumer
  (native window JSON, Worker cleanup window, PID1 supervisor, deploy guard,
  HTTP/runtime receipt validators, rollback quiescence and i2575 readiness) now
  binds `issue-1700-recovery-20261002-v14`: dispatch 2026-10-02T10:00Z–10:20Z,
  last admission 12:00Z inclusive, expiry 13:15Z exclusive (exactly v13 + 3 h).
  The legacy scheduled path stays HTTP-only for v14. Source only: no provider
  call, dispatch or deploy.
