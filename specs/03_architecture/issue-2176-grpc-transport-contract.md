---
id: "ISSUE-2176-GRPC-TRANSPORT-CONTRACT"
type: "architecture"
doc_status: "ACTIVE"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-09-25"
updated: "2026-10-01"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
tags: ["architecture", "grpc", "transport", "staging", "issue-2176"]
---

# Issue #2176 gRPC transport contract

**BLOCKED — no general public gRPC claim.**

Native gRPC remains denied at the first public Worker Fetch boundary with
`503`, `cache-control: no-store`, and no reflected request data. The only
source-level exception is an additive, protected staging diagnostic for these
two exact RPC paths:

- `/corelink.staging.v1.TransportProbe/Unary`
- `/corelink.staging.v1.TransportProbe/Stream`

The exception is not a product transport admission and does not prove a live
runtime. It exists only to make one protected standard-client diagnostic
possible after a separately reviewed provider/configuration receipt.

## Staging diagnostic boundary

The Worker accepts a diagnostic request only when all of the following hold
before Durable Object selection:

- `POST`, HTTPS, `staging.corelink.humangr.com`, ordinary port, and no
  userinfo, query, or fragment;
- exact `application/grpc` or `application/grpc+proto`, and exactly
  `TE: trailers`;
- one of the two paths above;
- protected account `6a1fc1c626fc2628823e60b9db01f5cd`, Worker
  `corelink-staging`, and both environment bindings equal `staging`;
- a protected, ephemeral `CORELINK_STAGING_GRPC_PROBE_TOKEN` of at least
  32 bytes, presented unchanged as `Authorization: Bearer <token>` and
  compared with the existing constant-time helper;
- canonical nonsecret expiry and deployment SHA bindings, with expiry strictly
  in the next 15 minutes.

Mode flags, arbitrary strings, caller headers, a deployment assertion, or an
unverified account cannot authorize the exception. Missing, malformed,
expired, production, unsupported, or uncertain inputs fail closed before the
dedicated `_staging_grpc_probe_v1` Durable Object. Every other gRPC-shaped
request, including gRPC-Web and unsupported methods, retains the public deny.

The dedicated DO rechecks the protected binding before tenant resolution,
durable rate limiting, cache routing, or normal response transforms. It uses
only `container.getTcpPort(50051)`. The single localhost Request reconstruction
preserves the original body, headers, `Authorization`, cancellation signal, and
uses `redirect: manual`; every upstream response other than HTTP status `200`,
or any response carrying `Location`, fails closed, while a status-`200`
nonredirect native gRPC Response is returned unchanged. The
Container independently authenticates before its probe service
executes.

No REST, HTTP/1 substitute, gRPC-Web, cache write, customer lookup, request
body parsing, token logging, response cache write, production entry, or
fallback is permitted.

## Runtime proof remains separate

The protected runtime workflow must verify the deployed account/Worker/version,
the exact protected bindings, and compatibility flags required for incoming
request cancellation and subrequest signal passthrough. A standard external
gRPC client then proves TLS/ALPN, native framing, metadata, unary and stream
frames, terminal `grpc-status`, cancellation, and cleanup. Until that receipt
exists, this contract makes no live capability claim.

## Trusted policy transition

The public index, gate, this contract, and the protected verifier are immutable
to ordinary candidates. A root-reviewed BASE policy prerequisite may admit one
closed-world diagnostic delivery whose source hashes and transitive Worker/DO
closure are fixed in the protected verifier. A candidate never authorizes its
own checker, workflow, contract, or path set.
