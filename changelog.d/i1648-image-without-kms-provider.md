### Fixed

- **The production image now links no KMS provider, so containers boot without
  KMS credentials (#1648, B-063, B-083).** #1800 made the container build the
  AWS KMS provider at boot, and the image was compiled with `byok-aws-real`.
  No production Worker has `CORELINK_BYOK_KMS_*` credentials, so after the
  2026-09-30 IAD image rollout every container start exited with code 1.
  Cloudflare instance events for the `_system` container show
  `ContainerStarted`, then `VMStopped` with `container_exit_code: 1` 0.3–0.4 s
  later. The Durable Object then answered 503 `CONTAINER_UNAVAILABLE`, and the
  hourly audit drain and archive calls both failed with that status.

  The owner deferred BYOK/AWS (#1653, #2165) and accepted BYOK failing closed
  (#1676). The provider is now chosen by one Dockerfile build argument,
  `ARG CORELINK_BYOK_PROVIDER_FEATURE=`, which is empty by default. That is the
  no-provider build: customer-key activation answers 501. Arming BYOK is an
  image change: set the default to `byok-aws-real` in the same rollout that
  provisions the KMS credentials. A rollout replaces every container, so armed
  and unarmed processes never keep serving side by side. Any other value fails
  the build. The #2165 ECR lane now builds the armed variant explicitly.
