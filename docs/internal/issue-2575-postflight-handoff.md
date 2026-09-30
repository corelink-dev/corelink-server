# #2575 staging probe handoff

The #2575 protected workflow checks two immutable #1700 receipts before making any gRPC request: the route-free deployment/runtime artifact and the Custom Domain publish artifact. It binds both to the same protected main SHA, checks the deployment's Worker version and Container image digest against the protected variables, and checks the public endpoint receipt for the canonical host, Worker, healthy HTTPS/DNS, required runtime bindings, and no conflicting Worker Route. The Custom Domain receipt omits account and zone IDs in its already-exact shape; the verifier relies on that artifact's exact workflow SHA, whose publisher validates the pinned account and zone before emitting it.

Before dispatch, the #1700 owner provisions the ephemeral `CORELINK_STAGING_GRPC_PROBE_TOKEN` and staging probe variables from those verified receipts. The token must expire within 15 minutes. The workflow reads the token only in the single client step and does not print or artifact it.

After the probe, the #1700 owner removes these exact entries from the protected GitHub `staging` environment and the corresponding staging Worker runtime configuration, then reads back that each is absent or disabled:

- Secret `CORELINK_STAGING_GRPC_PROBE_TOKEN`
- Variables `CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS`, `CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA`, `CORELINK_STAGING_GRPC_PROBE_WORKER_NAME`, `CORELINK_STAGING_GRPC_PROBE_WORKER_VERSION_ID`, and `CORELINK_STAGING_GRPC_PROBE_CONTAINER_IMAGE_DIGEST`

The owner also performs an anonymous native gRPC request to the canonical endpoint and records the terminal unauthenticated status. Attach a redacted postflight receipt to #2575 containing the exact SHA, Worker version, image digest, endpoint, completion time, each named removal/readback outcome, and anonymous status/trailer names. Never include the token value.

The probe workflow's `GITHUB_TOKEN` has only contents-read and actions-read permissions. It cannot remove protected environment secrets or variables, and the #2575 client has no provider mutation credential. Therefore a successful client artifact alone does not close #2575; closure requires the #1700 owner's postflight receipt and the root's external readiness/cleanup handoff.
