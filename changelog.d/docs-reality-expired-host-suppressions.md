### Fixed

- **Docs Reality Gate green again without blanket re-dating.** The 21 hostname
  suppressions that expired on 2026-09-30 were resolved one by one: 17 dead hosts
  were removed from or corrected on every shipped surface (docs site and its
  translations, admin console links, `SECURITY.md`, release notes, marketing, code
  comments and tests) and retired; 4 were renewed to 2026-10-31 with a written
  reason. A suppression must now list the exact files it covers, so a mention of
  the same dead host anywhere else fails the gate. Console links written in place
  of a dead host now name pages the admin console actually renders: the PCI-DSS
  trust page's CSP check fetches the rendered pricing page and refuses anything
  but a 200 HTML response, and the status page's Admin Console component points
  at the tenant list rather than an `/admin` path with no page.
