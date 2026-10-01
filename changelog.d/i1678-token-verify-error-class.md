### Fixed

- **The B-216 DSR receiver read-only readback now says why Cloudflare token verification was inconclusive (#1678).** `verify_unknown` used to collapse a timeout, a transport error, a non-200 response, malformed JSON and malformed verification fields into one status. The receipt now carries an allowlisted `verification` summary — HTTP status, error class, active status, and token-ID shape — and never the response body, the token, or the token ID.
