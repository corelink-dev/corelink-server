---
type: "CacheSurface"
title: "Authenticated REAPI ByteStream contract"
description: "The unmounted REAPI ByteStream service contract over the authenticated tenant-scoped ingress and the production-decorated CAS handlers."
source_files:
  - "crates/corelink-container/src/reapi_bytestream.rs"
  - "crates/corelink-container/src/reapi_bytestream/tests.rs"
  - "crates/corelink-container/src/reapi_ingress.rs"
  - "crates/corelink-container/src/reapi_ingress/validation.rs"
source_blobs:
  - "crates/corelink-container/src/reapi_bytestream.rs@abc060543e50cce761fb00e2ec5e7e223007d55e"
  - "crates/corelink-container/src/reapi_bytestream/tests.rs@e802e80fb72d621c28b603facbe53a782bd8dad8"
  - "crates/corelink-container/src/reapi_ingress.rs@3d1fed6de23011955eda97fc5eab65950100a83f"
  - "crates/corelink-container/src/reapi_ingress/validation.rs@b7f5d1045997e7b7e733bea9fcbb95caa97a6881"
checkpoint_sha: "84fb91fdece139e532092b68dde700d6b1fd10f4"
provenance: "AUTHORED"
timestamp: "2026-09-23T00:00:00Z"
---

# Authenticated REAPI ByteStream contract

`ReapiByteStreamService` remains a dependency-only service. It consumes the #2177 ingress bundle and gRPC remains unmounted until #2176 supplies the transport proof. It creates no local cache, upload-resume state, route, or storage handler.

Every read authenticates and binds the REAPI instance to the PAT tenant before one decorated CAS read. The completed handler response is then emitted in 64 KiB frames while the admission lease and ByteStream buffer permit stay live. The declared SHA-256 digest size caps each payload at the configured 5 MiB CAS ceiling; three operations may buffer a body concurrently within the declared container read and write budgets.

Every write requires a write-capable PAT, exact upload resource name, ordered offsets, an explicit `finish_write`, request-stream EOF, declared byte count, and SHA-256 match before its exactly once decorated CAS persistence call. Requiring EOF rejects delayed replay frames before persistence; the initial request frame is released after copying so it does not retain a second body-sized allocation. The decorated handler retains tenant prefixes, tombstones, quota, byte accounting, audit, and BYOK controls. Quota, audit, backend, and validation failures surface as gRPC errors and never create speculative persistence.

`QueryWriteStatus` returns `UNIMPLEMENTED`: this service does not claim a durable upload state it does not have.

## Acceptance and invariants

- Missing, invalid, or read-only PATs; tenant mismatch; and malformed resource names fail before any CAS handler call.
- Reads validate offset and limit, cap the decorated handler read to the declared digest size, and emit frames no larger than 64 KiB.
- Writes reject offset replay or gaps, incomplete streams, post-terminal frames, oversize bodies, declared-size mismatch, and SHA-256 mismatch before persistence.
- A valid write calls the decorated tenant-scoped CAS handler exactly once. Quota, audit, tombstone, and backend failures fail closed.
- Buffering is bounded to 5 MiB per operation and three active ByteStream operations, within the container read/write budgets.
- Resumable state, local cache fallbacks, REST conversion, public mounts, and token recording are absent.

Completion requires the trusted exact-PR-head workflow below to pass its source mutation contract and focused Rust behavior suite. The PR is stacked on approved ingress #2223 and carries a separate DCO sign-off.

## Hosted quality gate

`.github/workflows/issue-2181-reapi-bytestream-contract.yml` checks out the immutable pull-request head SHA with checkout credentials disabled, proves `HEAD` equals that SHA, runs the issue-specific mutation contract, and runs the focused Rust tests. Local build, test, lint, and formatting commands are intentionally not part of this attempt; formatting and compilation are verified in GitHub Actions.

# Citations

1. `crates/corelink-container/src/reapi_bytestream.rs:22-48` — payload, chunk, concurrency, and container-budget bounds.
2. `crates/corelink-container/src/reapi_bytestream.rs:69-121` — authenticated read validation, one decorated read, and bounded frame emission.
3. `crates/corelink-container/src/reapi_bytestream.rs:126-207` — ordered, EOF-final, hash-checked write followed by exactly one decorated persistence call.
4. `crates/corelink-container/src/reapi_bytestream.rs:223-255` — tonic service contract and explicit unsupported resume behavior.
5. `crates/corelink-container/src/reapi_bytestream/tests.rs:150-581` — behavior and adversarial coverage for storage denial, ranges, size limits, offsets, audit/quota failure, and resume.
6. `crates/corelink-container/src/reapi_ingress.rs:160-187` — tenant-scoped SHA-256 CAS handler request with a pre-materialization byte limit.
7. `crates/corelink-container/src/reapi_ingress/validation.rs:48-118` — canonical tenant-bound read/upload resource validation.
