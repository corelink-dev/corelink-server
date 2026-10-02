### Fixed

- **#1700: the staging bootstrap no longer writes a script-level Worker secret,
  because Cloudflare refuses that write after every rollback.** V15 (run
  37044496198) failed closed at its first write. The redacted receipt said
  `phase=prepare_put_secret http_status=400 cf_error_codes=10215`. Code 10215
  means "Secret edit failed. Latest version of your Worker isn't currently
  deployed". A read-only check confirmed that `corelink-staging`'s newest upload
  (#23, a prior rollback upload) was not the deployed version (#17, the
  preimage). This workflow's own rollback, which uploads and then redeploys the
  exact preimage version, always leaves that state, so the old design could
  never run twice. The admin key now rides only the candidate version. The
  broker proves that the exact deployed preimage *version* is key-free. It then
  writes the key once to an exclusive, owner-only file, which the deploy step
  passes to `wrangler deploy --secrets-file` and removes. Before enabling
  workers.dev, bind requires the candidate version to carry the key as
  `secret_text`, with every other secret exactly the preimage's. Cleanup now
  only disables workers.dev. The exact preimage restore removes the key, and a
  new read-only `verify_restored` readback proves after each restore that the
  restored version is active at 100% with no key and no key file. Review
  hardening adds four things. First, a bind that fails after parsing its
  candidate stays fenced as `bind_failed` instead of `unknown`, so cleanup can
  re-prove ownership and disable an attempted workers.dev enable. Second, an
  `EXIT` trap guarantees the exact Worker preimage restore once broker cleanup
  succeeded, even when the Container checks fail. Third, secrets are compared by
  name and type. Fourth, a preimage carrying any other secret is refused,
  because inherited values cannot be proven. Broker
  contract v2 drops the `secret_put_*`, `secret_delete_*`, `post_secret` and
  `post_delete` fields. Rollback quiescence reads v2. The broker makes at most
  15 management API calls, none to a secrets or settings path.
- **#1700 native staging proof moved to the v16 window.** The window uses
  nonce `issue-1700-recovery-20261002-v16`. Dispatch runs 2026-10-02T21:06Z–21:26Z,
  last admission is 23:06Z inclusive and expiry is 2026-10-03T00:21Z
  exclusive. This is the earliest 2-minute bucket at least 3 h after 18:05Z
  (v15 + 11,160,000 ms). The failed-closed v15 nonce is never reused. v16 joins
  the HTTP-only nonce list, and tests reject the v11–v15 tuples. Source only:
  no provider write, dispatch or deploy.
