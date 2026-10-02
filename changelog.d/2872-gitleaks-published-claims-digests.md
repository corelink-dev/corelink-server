### Fixed

- **gitleaks no longer reports the published-claims census digests as API
  keys, and only those lines are exempt.** Refreshing the census digest for
  the REAPI docs test (#2872) made the `gitleaks` PR scan fail with one
  `generic-api-key` finding in `scripts/published_claims_inventory.json`. The
  file path contains `reapi`, the heuristic reads the `api` inside it as a
  keyword, and the 64-hex digest after it scores above the entropy floor. A new
  `generic-api-key` allowlist in `.gitleaks.toml` accepts a line only when it is
  in that exact repo-relative file **and** the whole line is a census entry: a
  key under `README.md`, `apps/docs/`, `marketing/` or `legal/`, with an
  extension the census collects and a lowercase 64-hex value. The roots and
  extensions are the ones in `scripts/published_claims_census.py`, and its
  `validate()` recomputes every digest from the file it names.
  `condition = "AND"` is set on purpose. gitleaks ORs allowlist predicates by
  default, and under OR the path match alone would exempt every finding in
  this file. The older B-094 entry is built that way, and a probe with
  gitleaks 8.30.1 confirmed it exempts a non-digest credential line in its
  own file. New cells in `scripts/tests/gitleaks-shape-regression.sh`, which
  the gitleaks workflow runs on every PR, cover each part of the rule. They
  scan from a relative source, as the CI range scan does, and each mutation
  they include fails the matching cell. The PR range now scans clean with
  gitleaks 8.30.1.
