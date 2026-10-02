### Fixed

- **Production containers exited with code 1 on every boot, because the BYOK
  data plane refused to start without KMS credentials (#1648, B-063).**
  #1800 made `DataPlaneByok::from_env` build the AWS KMS provider at boot, and
  the production image is compiled with `byok-aws-real`. No production Worker
  has `CORELINK_BYOK_KMS_*` or `AWS_*` credentials, so from the 2026-09-30
  image rollout on, every container start exited at boot. On 2026-10-02 the
  Cloudflare instance events for the `_system` container showed
  `ContainerStarted`, then `VMStopped` with `container_exit_code: 1` 0.3–0.4 s
  later. The Durable Object then returned 503 `CONTAINER_UNAVAILABLE`, and the
  hourly archive cron logged `status=503 incomplete=true`.

  A real-provider binary whose credentials were never provisioned now checks
  `tenant_byok_config` before deciding. If no tenant is `active`, `partial` or
  `shredded`, it boots without the BYOK data plane, like the no-provider
  build, and logs `byok_data_plane_unarmed`. No tenant can become active in
  that state, because the activation route needs the same provider and returns
  501 before any D1 write. If any tenant is engaged, boot is still refused.
  Credentials that are provisioned but broken still fail as before. An
  unreadable probe answer refuses boot.
