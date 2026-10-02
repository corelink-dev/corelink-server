### Fixed

- **#1700 native staging proof moved from the failed v13 window to the v15
  window.** V13 (run 36976287686) passed every read check and the preimage
  capture, then failed closed at the first bootstrap write; an independent
  readback showed no provider change, and its nonce
  `issue-1700-recovery-20261002-v13` is never reused. The interim v14 tuple
  (`issue-1700-recovery-20261002-v14`, 2026-10-02T10:00Z–13:15Z) expired
  without being dispatched and is never reused. Every compiled consumer
  (native window JSON, Worker cleanup window, PID1 supervisor, deploy guard,
  HTTP/runtime receipt validators, rollback quiescence and i2575 readiness) now
  binds `issue-1700-recovery-20261002-v15`: dispatch 2026-10-02T18:00Z–18:20Z,
  last admission 20:00Z inclusive, expiry 21:15Z exclusive (exactly v14 + 8 h).
  The legacy scheduled path stays HTTP-only for v14 and v15; tests reject the
  v11–v14 tuples and nonces. Source only: no provider call, dispatch or deploy.
- **#1700 bootstrap failures are now classified in the receipt instead of all
  reading `bootstrap_unknown`.** V13's secret PUT was refused about 0.9 s after
  the request, and nothing recorded the HTTP status or Cloudflare error codes.
  The first failed provider call now writes an allowlisted `failure` object to
  the bootstrap ledger: a fixed `phase` (for example `prepare_put_secret`), an
  `endpoint_label`, `http_status`, up to 8 integer `errors[].code`, a
  `cf_message_class` from a small allowlist, the failed `validation_failed`
  check for a refused 2xx, and `timed_out` and `aborted`. It never records a
  body, URL, ID, token or secret. A failed `Start owned temporary HTTP
  bootstrap` step prints this as one re-validated line. Acceptance and
  fail-closed behaviour are unchanged; rollback quiescence requires
  `failure` to be null.
