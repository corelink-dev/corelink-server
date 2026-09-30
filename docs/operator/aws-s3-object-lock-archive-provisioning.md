# AWS S3 Object-Lock archive: proposed path and provisioning gate

## Decision

AWS S3 Object Lock is the proposed backend family for the Compliance archive.
No AWS account, bucket, region, jurisdiction mapping, retention term, legal
hold policy, credential, or target-bound provider proof is approved here. The
present Cloudflare R2 archive remains non-WORM and is not changed by this
document or the inactive Terraform module.

Amazon S3 requires Object Lock to be enabled when a bucket is created. Its
Compliance retention mode prevents deletion or overwrite before the retention
date, and S3 provides object-retention and legal-hold read APIs. Those facts
make S3 suitable to evaluate against `ObjectLockArchiveAdapter`; they do not
prove any CoreLink target has the contract.

## Repository-owned implementation

`infra/terraform/modules/audit-object-lock-aws` is the inactive provisioning
template. It creates a new S3 bucket with Object Lock enabled, versioning,
Compliance default retention, public-access blocks, server-side encryption,
and a dedicated writer role. The writer role can read Object Lock state and
write objects under `audit/*`; it cannot read object payloads, delete objects,
or override retention. Its legal-hold permission is condition-bound to
setting a hold `ON`; it cannot release a hold. S3 applies the bucket's
Compliance default retention to writer puts.

The module is not called from an environment root. It must stay inactive until
the prerequisites below are approved. Terraform apply remains manual and
subject to the repository's existing plan and dual-approval procedure.

## External blocker

Security, Compliance, residency, and procurement must approve all of the
following for one exact target before an immutable archive route can be
enabled:

1. The AWS account, S3 region, jurisdiction-to-region mapping, and archive
   bucket name.
2. The Compliance retention term, legal-hold process and owners, including
   the conditions under which a hold can be released.
3. Separate writer, provisioning, break-glass, and live-probe identities. The
   writer has no delete permission; no principal used by the application may
   bypass the retention control.
4. An externally durable audit source that records S3 object data events for
   the target, such as an approved CloudTrail trail or CloudTrail Lake store,
   and the retention/access policy for its receipt.
5. A redacted, authenticated live-probe record for that account and bucket.

Consequently, `VerifiedObjectLockArchive::connect` must not be wired into an
archive route. This is a production-approval blocker, not a reason to represent
R2, lifecycle rules, conditional writes, or an in-memory adapter as WORM.

## Synthetic prelaunch proof and production gate

The protected canonical-main workflow can run a synthetic-only technical
proof before production approvals, using a new run/attempt-derived bucket and
no archive or tenant data. This does not assert that the target is a
non-production account, establish residency, or enable a production route.
Root authorization fixes the exact account/region, ≤USD 5 ceiling, and cleanup
custody before provider mutation. Production deployment still requires the
external decisions above. Runtime uses four pairwise-distinct OIDC roles:
probe (create/configure and denied delete), workload writer (one put only),
read-only audit reconciler, and cleanup. Central IAM provisioning is separate
from the runtime workflow; break-glass is separately human-controlled. The
workload writer cannot delete versions, bypass retention, or release holds.

1. Read the bucket Object Lock configuration and verify the configured default
   mode is `COMPLIANCE` and retention is the approved value.
2. Put a unique test object with `COMPLIANCE` retention and legal hold enabled.
3. Read back the object's retain-until timestamp and legal-hold state; both
   must exactly match the request.
4. IAM-simulate `s3:DeleteObjectVersion` as allowed for the exact probe role and
   object, then permanently delete the exact version before expiry. Only S3
   `AccessDenied` qualifies; `InvalidRequest`, policy-deny context, or success
   fails closed.
5. A dedicated B-046 trail must be actively logging, validate log files, and
   select S3 `PutObject`/`DeleteObject` data events for the new probe prefix.
   A separate read-only reconcile operation polls the hourly digest chain,
   downloads only exact S3 log URIs reported valid by `validate-logs`, then
   binds the exact-run events to bucket/key/version and distinct assumed-role
   sessions (writer for PutObject, probe for denied DeleteObject). CloudTrail
   Lake is neither required nor queried.
6. Record region readback; the synthetic proof makes no jurisdiction or
   `ArchiveResidency` claim.

Any missing configuration, authorization failure, incomplete readback,
unavailable audit receipt, or deletion success is a failed negotiation before
production archival. Do not write production archive data while the probe is
incomplete.

## Runtime handoff after approval

The eventual AWS S3 implementation must receive configuration only from the
approved deployment secret/configuration system: the exact bucket, AWS region,
jurisdiction, location class, approved retention/hold policy identifier, and
redacted evidence reference. It must use a short-lived workload identity for
the dedicated writer role; do not commit access keys, session tokens, account
IDs, bucket names, or live receipt values.

It must construct `VerifiedObjectLockArchive` before its first put, send the
requested compliance retention and legal-hold settings on the object write,
read both back, verify the expected residency, and attach a durable audit
receipt. It must not mount an immutable archive route or perform a fallback
write if any of those steps fails.

The generated SDK `PutObject` output used here exposes a provider request ID
but no modeled write timestamp. The receipt's S3 request ID is the
provider-issued correlation value. Its `observed_at_unix_ms` field is the
adapter's local clock reading immediately after the successful response; it is
not an S3 event timestamp. Use the dedicated protected CloudTrail trail's
digest-validated S3 log objects as the external audit record. `LookupEvents` is
management-event history and cannot prove S3 object data events; CloudTrail
Lake is intentionally not part of this synthetic proof route.

Capability negotiation requires a separate probe configuration and the exact
key/version of an already locked synthetic object. The adapter constructs both
the probe S3 and STS clients from that one configuration, verifies the observed
STS ARN against the approved probe principal, and accepts only a structured S3
`AccessDenied` with a provider request ID for that exact version. Before that
delete attempt, a protected permission verifier must return a durable receipt
bound to the exact STS principal, bucket, key, version, and
`s3:DeleteObjectVersion` action. The protected workflow independently records
the effective policy simulation for that same binding. A caller-supplied string,
missing or mismatched evidence, missing probe, identity mismatch, successful
delete, or other service error fails closed. The archive writer never receives
delete permission.

The template writer policy grants no delete or retention-override authority.
It permits setting legal hold only to `ON`. The runtime adapter stays
feature-gated and is not wired to a production route until Security,
Compliance, and Legal approve the production target and policy.

## Migration and rollback

`0144_cas_retention_compliance_metadata.sql` uses the SQLite table rebuild
required to widen the original Governance-only `CHECK`. It copies every legacy
row and restores its tenant-leftmost primary key and expiry index before adding
Compliance metadata. Forward rollout applies the migration before any writer
can accept Compliance rows. A rollback after a Compliance row exists is
one-way: it must fail closed and use a forward repair. It must never shorten
retention, delete a locked version, erase its metadata, or route it to R2.

## Hosted proof entrypoint

`.github/workflows/aws-s3-object-lock-live-proof.yml` is the live-proof
entrypoint. It accepts no role, bucket, region, or account from dispatch
inputs; it runs only from protected canonical `main`, waits on the
`s3-object-lock-live-proof` environment, and obtains short-lived credentials
through GitHub OIDC. Protected variables identify the exact account, region,
four distinct runtime roles (probe, one-put workload writer, read-only audit
reconciler, and cleanup), bucket prefix, dedicated trail ARN, CloudTrail log
bucket/prefix, cost ceiling (≤USD 5), and named cost and cleanup owners. The
synthetic proof creates one new bucket and one object
with one-day COMPLIANCE retention and legal hold ON. It uploads a
`PROVISIONAL_DIGEST_PENDING` hashed custody record even when a post-create
check fails. A separate `reconcile` operation authenticates the exact source
run/attempt, validates the hourly trail digest, binds PutObject to the writer
session and denied DeleteObject to the probe session for the exact bucket/key/
version, then publishes a separate redacted final receipt. No jurisdiction or
production-readiness claim follows from this
technical proof. Cleanup is separately dispatched for the exact source run and
attempt, and refuses before retention expiry or absent explicit cleanup
authorization; ambiguity preserves the object and its evidence.

The adapter's durable audit event and write receipt both carry the exact S3
bucket. A failed put or post-write verification attempts an append-only failure
receipt containing the tenant-safe key, exact version when available, bucket,
and stable failure class. Failure-audit persistence errors fail the operation
closed. Migration `0144` has SQLite coverage for Governance row preservation,
Compliance constraints, tenant/mode scoping, replay-safe Governance insertion,
indexes, and primary-key preservation. The DSR Governance verification query
filters `mode = 'governance'` explicitly.

## Sources

- [Amazon S3 Object Lock overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html)
- [Configuring S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)
- [Managing Object Lock retention and legal holds](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [ADR-0100 R2 capability gate](../knowledge/adr/adr-0100-r2-object-lock-capability-gate.md)
- [ADR-0101 archive adapter contract](../knowledge/adr/adr-0101-object-lock-archive-adapter-contract.md)
