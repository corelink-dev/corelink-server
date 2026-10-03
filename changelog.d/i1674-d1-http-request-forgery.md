### Security

- **The container's D1 HTTP client now builds its request URL from fixed
  literals and validated ids only (#1674, CodeQL `rust/request-forgery` at
  `storage/d1_http.rs` lines 268 and 316).** `D1HttpClient` used to format
  `CLOUDFLARE_ACCOUNT_ID` and `D1_DATABASE_ID` into a stored URL string with
  no check, so a value containing `/`, `@`, `%2F`, `..`, `?`, `#` or a newline
  would have changed the host or path of every D1 call. Each id must now be
  1-64 characters from `[0-9A-Za-z_-]` (RFC 3986 unreserved characters
  without `.` and `~`), and anything else is refused before a client exists.
  The ids are kept as codes into a fixed 64-character table, and the URL is
  rendered for each request from the fixed Cloudflare or staging-proxy origin
  and path plus characters looked up in that table, so no configured byte is
  copied into it. The loopback test seam is limited the same way: a loopback
  IP, an explicit port, and the path `/` or `/d1`. Every id accepted today
  (production, staging and the test fixtures) produces a byte-identical URL,
  including the exact path the staging D1 binding proxy admits.
