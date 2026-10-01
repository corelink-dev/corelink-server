---
schema: corelink-ownership/1.1
document: reference
package: corelink-dpa-acceptance
manifest: crates/corelink-dpa-acceptance/Cargo.toml
source_commit: cca798ff5bc2df660ecf2570ed243eb9775ff3d0
profile: S
state: draft
evidence_set: corelink-dpa-acceptance-structural-normalization-20260921
---

# corelink-dpa-acceptance — reference

Source/static ownership reference for a pure-logic consent service. No configured keys, legal corpus, durable store, onboarding traffic, deployment, or runtime outcome was observed.

[Identity](#r01) · [Boundary](#r02) · [Map](#r03) · [Contracts](#r04) · [Invariants](#r05) · [Configuration](#r06) · [Failures](#r07) · [Evidence](#r08).

<a id="r01"></a>
## R01 — Identity and role

Record index: [API-001](#api-001) · [API-002](#api-002) · [API-003](#api-003) · [API-004](#api-004) · [API-005](#api-005)

| Field | Source/static fact |
|---|---|
| Package | `corelink-dpa-acceptance`; `crates/corelink-dpa-acceptance/Cargo.toml` |
| Role | Pure-logic consent capture/orchestration with trait seams and in-memory fakes |
| Public areas | proof schema, locale registry/enforcement, receipt JWT, service, audit, notification, store, errors |
| Declared test targets | locale mismatch, idempotency, JWT signature, replay protection, integration acceptance flow |
| Implementation / runtime | source read; runtime not observed |

<a id="r02"></a>
## R02 — Boundary and ownership

| Surface | Owner in this package | Explicit limit |
|---|---|---|
| Consent proof and receipt shapes | `schema` | Does not authenticate or route HTTP |
| Locale/hash/JWT decisions | `locale`, `jwt`, `service` | Does not provide legal text or keys |
| Audit, notification, persistence seams | traits and in-memory implementations | Does not prove audit delivery, email, or D1 persistence |
| Static consumer paths | privacy façade, container, e2e signup flow | Presence/reference is not runtime reachability |

<a id="r03"></a>
## R03 — Implementation map

| Module | Source responsibility |
|---|---|
| `audit` | `DpaAuditEvent`, `DpaAuditSink`, in-memory capture |
| `error` | non-exhaustive `DpaAcceptanceError` taxonomy |
| `jwt` | RS256 `sign_receipt`/`verify_receipt`, claims, PEM wrappers |
| `locale` | three-locale registry, SHA-256 notice/IP hashes, match enforcement |
| `notify` | `NotificationSink` and in-memory envelope capture |
| `schema` | tenant/signup context, closed locale/jurisdiction, proof/request/receipt |
| `service` | ordered acceptance orchestration, JTI and clock seams |
| `store` | store trait, record, mutex-backed in-memory implementation |

<a id="r04"></a>
## R04 — Public contracts

<a id="api-001"></a>
### API-001 — Consent capture

`ConsentProofPayload` carries six capture/control values — `notice_text_hash`, `notice_version`, `dpa_version`, `locale`, `wording_id`, and `ui_capture_ts` — plus server-overwritten `submission_ts`; `DpaAcceptanceRequest` wraps it. Source: `schema.rs`. The package exposes the fields but cannot prove a client submitted them or that legal wording exists.

<a id="api-002"></a>
[↩](#r01)
### API-002 — Locale and notice hash

`LocaleBcp47` permits `en-US`, `pt-BR`, and `es-419`; `enforce_locale_match` rejects unequal server-resolved and payload values. `LocaleNoticeRegistry::hash_for` hashes registered text; absent registration returns `None`. Source: `locale.rs`.

<a id="api-003"></a>
[↩](#r01)
### API-003 — Acceptance and idempotency

`DpaAcceptanceService::accept` receives a `TenantCtx` and request. A matching existing `signup_id`/tenant/payload returns its stored identity; a divergent reuse reports `IdempotencyConflict`. Source: `service.rs`, `store.rs`. Atomicity beyond the provided store trait is unknown.

<a id="api-004"></a>
[↩](#r01)
### API-004 — Cryptographic receipt

`sign_receipt` produces an RS256 JWT with `kid`; `verify_receipt` checks RS256 and, when supplied, exact `kid`, returning `JwtReceiptClaims`. Claims include subject, DPA version, acceptance time, jurisdiction, JTI, issue, and expiry. Source: `jwt.rs`. No actual PEM/key lifecycle is observed.

<a id="api-005"></a>
[↩](#r01)
### API-005 — Effect seams

`DpaAuditSink::emit`, `DpaAcceptanceStore::{lookup,insert_idempotent}`, and `NotificationSink::send` expose fallible effect boundaries. In-memory implementations exist for source/test use. Source: `audit.rs`, `store.rs`, `notify.rs`.
[↩](#r01)

<a id="r05"></a>
## R05 — State, ordering, and falsifiable invariants

| ID | Rule | Source enforcement / falsifier |
|---|---|---|
| INV-001 | unequal resolved/payload locale returns `LocaleMismatch` after a mismatch audit attempt | `service.rs`; unequal locale that reaches store falsifies it |
| INV-002 | unregistered or mismatching notice hash does not reach acceptance persistence | `service.rs`; row after either failure falsifies it |
| INV-003 | equal replay identity returns the original JTI; divergent reuse returns `IdempotencyConflict` | `service.rs`, `store.rs`; a second JTI or accepted divergence falsifies it |
| INV-004 | a receipt accepted by `verify_receipt` was decoded with RS256 and the requested `kid` matched | `jwt.rs`; altered token/wrong `kid` accepted falsifies it |
| INV-005 | accepted audit emission precedes `insert_idempotent`; audit failure prevents that insert path | `service.rs`; mutation after failed accepted audit falsifies it |
| INV-006 | `accepted_ip_hash` derives SHA-256 over raw IP bytes followed by salt, not a raw-IP field in `DpaAcceptanceRecord` | `locale.rs`, `store.rs`; raw IP record field falsifies it |

The service’s replay envelope is rebuilt from stored identifiers rather than newly signed; it is not asserted here to be an original JWT. `dpa.replay_detected` exists in audit taxonomy, but this source pass does not establish an active service verify/replay ledger path.

<a id="r06"></a>
## R06 — Configuration and data boundary

The constructor requires an opaque `IpHashSalt`, validated as exactly 32 non-zero bytes; there is no default salt. The container refuses to mount the DPA-accept route unless `DPA_ACCEPT_IP_HASH_SALT` provides those bytes as 64 hexadecimal characters. Tests inject deterministic fixture salts. These are configuration requirements, not evidence that production secret provisioning is configured. The manifest declares `jsonwebtoken` with `rust_crypto`; this documents cryptographic code dependency, not key custody or operational cryptography.

<a id="r07"></a>
## R07 — Failure taxonomy

`DpaAcceptanceError` distinguishes locale/hash/notice registration/idempotency/JWT/store/audit/notification failures. Source comments describe downstream HTTP mapping, D1, and email intent, but this reference makes no claim that those mappings or systems operate. Notification failure follows persistence in this service flow and therefore has no rollback guarantee in this package.

<a id="r08"></a>
## R08 — Evidence and unknowns

Evidence class is SOURCE plus static references: manifest, all eight `src` modules, declared test files, and source references in privacy/container/e2e signup flow. The source calls the proof “six-field” while its public struct also exposes server-stamped `submission_ts`; this reference treats only the six client capture/control values as the capture set. Unknown: canonical legal content and its versions, configured RSA material/rotation, durable storage behavior, audit/email delivery, route mount, onboarding traffic, deployment, runtime results, and independent review.
