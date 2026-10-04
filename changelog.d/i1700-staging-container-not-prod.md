### Fixed

- **#1700: the staging container no longer exits at boot because it looks like
  half-armed production.** The container treats any non-empty `R2_AC_REGION`,
  `R2_CAS_REGION` or `R2_AC_BUCKET` as an independent prod signal. It then
  refuses to boot (`prod_controls_not_fully_armed`, exit 1) unless every prod
  control is armed: StorageEnv, `PAT_SIGNING_KEY`, the native PAT verifier,
  quota, byte cap, request count, the erasure and email salts, and the tier
  prices. The staging topology sets all three vars (`iad`,
  `corelink-ac-iad-staging`) and arms none of those controls; the staging Worker
  has no R2 S3 keys, no `CLOUDFLARE_ACCOUNT_ID` and no secrets. So every staging
  native start, including the #1700 HTTP probe's supervisor, which execs
  `corelink-server`, died before BYOK or any route existed. #2895 does not
  change that path. The Durable Object now forwards those three vars to the
  container empty only when `ENVIRONMENT=staging`, in the same pattern it
  already uses for `CF_API_TOKEN`. Nothing changes Worker-side: `R2_CAS_REGION`
  still drives the Worker's quota, routing and metering. The staging container
  has no StorageEnv, so no R2 path reads them, and their `iad` defaults equal
  staging's values. Prod, regional prod and every other environment forward
  byte-for-byte, and `main.rs` is untouched, so prod still refuses to boot when
  not fully armed. A new vitest observes `container.start({ env })` for staging
  and prod environments, and derives the signal set from `main.rs`.
