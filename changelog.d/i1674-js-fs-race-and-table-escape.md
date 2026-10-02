### Fixed

- **Two real JavaScript CodeQL findings from #1674: a file-system race in the
  issue-1700 bootstrap shutdown, and incomplete escaping in the REAPI docs
  generator.** `shutdownBroker` checked the broker-process ownership record
  with `lstat` and then read it again by path. That record names the PID that
  shutdown may signal, so a file swapped in between the two calls would be
  trusted without being checked. It is now opened once with
  `O_NOFOLLOW | O_NONBLOCK`, checked with `fstat` on that handle, and read
  from that same handle with a 4096-byte limit. `mdEscape` in
  `gen-reapi-docs.ts` turned `|` into `\|` but left backslashes alone, so a
  type name containing `\|` became `\\|`, which ends the GFM table cell.
  Backslashes are now escaped first. The generated MDX does not change,
  because no current proto type name contains a backslash. New tests fail on
  the old code: two of three new bootstrap tests, and the new docs test after
  the backslash escape is removed.
