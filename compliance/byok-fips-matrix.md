---
doc_id: "COMPLIANCE-BYOK-FIPS-MATRIX"
id: "COMPLIANCE-BYOK-FIPS-MATRIX"
type: "compliance_doc"
doc_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-14"
updated: "2026-05-14"
owner: "Gustavo Schneiter"
status: "ACTIVE"
wi_scope:
  - "WI-S14-004"  # AWS row — SEALED this WI
  - "WI-S14-005"  # GCP / Azure / Vault rows — populated next WI
review_cadence: "quarterly"
next_review: "2026-08-14"
references:
  - "NIST FIPS 140-3 (CMVP)"
  - "NIST FIPS 140-2 (legacy — sunset 2026-09-22)"
  - "NIST SP 800-57 Pt 1 Rev 5"
  - "NIST SP 800-130"
  - "NIST FIPS 197 (AES)"
  - "NIST FIPS 186-5 (Ed25519)"
---

# BYOK FIPS Compliance Matrix

> **Provider-module scope, not CoreLink feature availability.** The certificate
> references below concern third-party KMS modules. They do not establish an
> available CoreLink BYOK service, customer-controlled key lifecycle, or a
> kill-switch timing SLO. CoreLink's shipped-runtime lifecycle and p99 remain
> unverified under #1653/#2165; no tier currently offers BYOK.

This document records the FIPS certification status for each KMS provider
considered in CoreLink's proposed BYOK design.

> **Quarterly review required.** Any change to a provider's NIST CMVP module
> status must trigger an alert and immediate update to this document.

---

## Summary table

| Provider | FIPS Level | CMVP Certificate | Notes | WI |
|---|---|---|---|---|
| **AWS KMS** | **FIPS 140-3 Level 1** | `#4523` | Default; no extra config. | WI-S14-004 ✓ |
| GCP Cloud KMS (HSM tier — CoreLink production target) | **FIPS 140-2 Level 3** | `#3318` (Marvell LiquidSecurity HSM) | HSM tier mandatory for production; software tier (`#3978`, L1) staging-only. | WI-S14-005 + R2-7 ✓ |
| Azure Key Vault Premium | FIPS 140-2 Level 2 | `#3516` (Azure Premium HSM) | HSM-backed; L2 validated. | WI-S14-005 + R2-8 ✓ |
| Azure Managed HSM / Dedicated HSM | FIPS 140-2 Level 3 | `#4332` (Marvell LiquidSecurity, Azure-deployed) | Mandatory for customers requiring L3; selected by `*.managedhsm.azure.net` host suffix. | WI-S14-005 + R2-8 ✓ |
| HashiCorp Vault Enterprise | FIPS 140-3 Level 1 | TBD (WI-S14-005) | Vault Enterprise FIPS build. | WI-S14-005 |

---

## AWS KMS — FIPS 140-3 Level 1 (WI-S14-004)

**Status:** ACTIVE — certified.

| Field | Value |
|---|---|
| FIPS Standard | FIPS 140-3 |
| Security Level | Level 1 |
| NIST CMVP Certificate | `#4523` |
| Module Name | AWS Key Management Service HSM |
| Cryptographic Operations | AES-256 (FIPS 197), RSA-2048, EC P-256, HMAC-SHA-256 |
| Key wrapping algorithm | AES-256 symmetric key wrap |
| Region availability | All AWS commercial + GovCloud regions |
| Endpoint for FIPS | `kms.us-east-1.amazonaws.com` (standard) / `kms-fips.us-east-1.amazonaws.com` (explicit FIPS TLS endpoint) |
| CoreLink configuration | Standard SDK; FIPS 140-3 L1 is the default for all `kms:Encrypt` / `kms:Decrypt` |
| IAM scope | `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` — minimal |

### References

- AWS KMS FIPS 140-3 documentation:
  <https://docs.aws.amazon.com/kms/latest/developerguide/keystore-cloudhsm.html#fips-140-3>
- NIST CMVP module search: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
- AWS GovCloud FIPS endpoint: <https://docs.aws.amazon.com/general/latest/gr/kms.html>

### Envelope encryption algorithms (AWS KMS path)

| Layer | Algorithm | Standard |
|---|---|---|
| DEK generation | CSPRNG (OS `getrandom`; AES-CTR-DRBG or Hash-DRBG) | NIST SP 800-90A |
| Body encryption | AES-256-GCM | FIPS 197 + NIST SP 800-38D |
| Nonce | 96-bit random per-write | NIST SP 800-38D §8.2.1 |
| DEK wrap | AES-256 key wrap via AWS KMS | FIPS 197 + SP 800-38F |
| AAD | `{"tenant_id": "...", "blob_hash": "..."}` | Provider-enforced |

---

## GCP Cloud KMS — FIPS 140-2 Level 1 (default) / Level 3 (HSM tier) — WI-S14-005 + R2-7

**Status:** ACTIVE — populated in WI-S14-005 + R2-7.

> GCP Cloud KMS exposes two `protectionLevel` values per CryptoKeyVersion:
>
> | `protectionLevel` | Backing module | FIPS standard |
> |---|---|---|
> | `SOFTWARE` (default) | Google Tink-backed AES module | **FIPS 140-2 Level 1** (NIST CMVP #3978) |
> | `HSM` | Marvell LiquidSecurity HSM | **FIPS 140-2 Level 3** (NIST CMVP #3318) |
> | `EXTERNAL` / `EXTERNAL_VPC` | Customer-supplied HSM | Per the external HSM's own certification |
>
> **Future design requirement:** if CoreLink offers GCP BYOK, production use
> would require the `HSM` tier; software tier would remain staging-only.
> CoreLink has no production BYOK customers. The proposed onboarding policy is
> not proof of an operational customer lifecycle; `GcpKmsRealProvider::check_access`
> does not currently parse the protection level back.
>
> FIPS 140-3 certification of the GCP Cloud KMS module is tracked quarterly by
> the Crypto SME. This row will be updated when GCP publishes a 140-3 CMVP
> certificate.

| Field | Value (HSM tier — CoreLink production target) |
|---|---|
| FIPS Standard | FIPS 140-2 |
| Security Level | **Level 3** (HSM tier) — physical tamper response, role-based identity-based auth |
| NIST CMVP Certificate | `#3318` (Marvell LiquidSecurity HSM) |
| Cryptographic Operations | AES-256 (FIPS 197), RSA-2048, EC P-256, HMAC-SHA-256 |
| Key wrapping algorithm | AES-256 symmetric key wrap |
| Region availability | All Cloud KMS regions supporting HSM tier (most commercial regions) |
| Endpoint | `cloudkms.googleapis.com` (REST v1) |
| AAD mechanism | `additionalAuthenticatedData` (raw bytes) — server-enforced |
| IAM scope (minimal) | `roles/cloudkms.cryptoKeyEncrypterDecrypter` + `roles/cloudkms.viewer` on the specific key |
| CoreLink configuration | `corelink-byok-gcp` with `production` feature; ADC via `GOOGLE_APPLICATION_CREDENTIALS`, Workload Identity, or `gcloud` user creds |

### References

- GCP Cloud KMS protection levels: <https://cloud.google.com/kms/docs/algorithms#protection_levels>
- GCP Cloud KMS HSM FIPS 140-2 L3: <https://cloud.google.com/kms/docs/hsm>
- NIST CMVP #3318 (Marvell LiquidSecurity HSM): <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318>
- NIST CMVP #3978 (Google KMS module — software tier): <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3978>

---

## Azure Key Vault Premium — FIPS 140-2 Level 2 (WI-S14-005)

**Status:** PENDING — populated in WI-S14-005.

> Azure Key Vault Premium tier uses HSM-backed keys certified to FIPS 140-2 Level 2
> (HSM module).  Upgrade to 140-3 pending Azure CMVP resubmission.

---

## HashiCorp Vault Enterprise — FIPS 140-3 Level 1 (WI-S14-005)

**Status:** PENDING — populated in WI-S14-005.

> HashiCorp Vault Enterprise ships a dedicated FIPS build (`vault-enterprise-fips1402`)
> using a FIPS 140-3 validated cryptographic module.  Customer-hosted on FIPS-validated
> infrastructure; mTLS auth; transit secrets engine for DEK wrap.

---

## Waiver policy

Per `_spec_contract.md §19`, the following cannot be waived:

- FIPS documentation per provider is **non-waivable** before S-14 GA gate.
- AWS KMS FIPS 140-3 L1 documented here satisfies the WI-S14-004 gate.
- GCP / Azure / Vault rows must be populated before WI-S14-005 SEAL.

---

## Changelog

| Date | WI | Change |
|---|---|---|
| 2026-05-14 | WI-S14-004 | Initial creation — AWS KMS FIPS 140-3 L1 row added. |
| 2026-05-14 | R2-7 (WI-S14-005 follow-up) | GCP Cloud KMS HSM-tier row promoted to FIPS 140-2 **Level 3** (CMVP #3318); `GcpKmsRealProvider` shipped with `production` feature. |
reviewers: []
tags: ["byok", "fips-140-2", "fips-140-3", "nist-cmvp", "compliance", "s14"]
---

# BYOK FIPS Compliance Matrix — CoreLink S-14

> **Historical design snapshot.** The rows and procedures below record a
> proposed integration design, not currently offered CoreLink BYOK controls,
> customer notifications, runtime guarantees, or Legal approval. The current
> prelaunch limitation above governs availability.

> **NIST SP 800-57 Pt 1 Rev 5** (key management) + **NIST SP 800-130** (cryptographic
> key management framework) + **NIST SP 800-90A** (DRBG for DEK generation) apply
> to all four providers.
>
> **Quarterly review**: Crypto SME reviews NIST CMVP certificate status per provider
> and updates this document. Calendar reminder in ops runbook. Next review: 2026-08-14.
>
> **Future customer disclosure:** any future BYOK signup would require reviewed
> provider-specific FIPS terms. No current BYOK signup or customer notice is claimed.

## Provider Matrix

| Provider | FIPS Level | NIST CMVP Module ID | Tier Requirement | Notes |
|---|---|---|---|---|
| **AWS KMS** | FIPS 140-3 Level 1 | #4177 (AWS HSM; 2024) | Any KMS region | Historical module reference; proposed Enterprise default, not a CoreLink service offering. |
| **GCP Cloud KMS** | FIPS 140-2 Level 1 (software) / **Level 3 (HSM tier)** | #3978 (software) / **#3318 (HSM — Marvell LiquidSecurity)** | **HSM tier mandatory for production**; software permitted only for staging | GCP committed to FIPS 140-3 for the software module; quarterly review tracks. HSM tier is the CoreLink production target (R2-7). |
| **Azure Key Vault** | FIPS 140-2 Level 2 | #3516 (Azure HSM; Premium) | **Premium HSM tier mandatory** | Standard tier = Level 1; CoreLink BYOK requires Premium HSM at provisioning. |
| **HashiCorp Vault Enterprise** | FIPS 140-3 Level 1 | Pending CMVP (2026-Q2) | Vault Enterprise FIPS build | Customer-hosted. OSS Vault is NOT FIPS-certified. mTLS auth mandatory. |

## FIPS Level Hierarchy

```
FIPS 140-3 Level 1 > FIPS 140-2 Level 2 > FIPS 140-2 Level 1 > None
```

- **FIPS 140-3 Level 1**: AWS KMS (#4177), HashiCorp Vault Enterprise (pending CMVP).
- **FIPS 140-2 Level 2**: Azure Key Vault Premium HSM (#3516).
- **FIPS 140-2 Level 1**: GCP Cloud KMS software tier (#3978; staging-only).
- **FIPS 140-2 Level 3**: GCP Cloud KMS **HSM tier** (#3318 Marvell LiquidSecurity HSM; CoreLink production target).

## Proposed controls requiring runtime evidence

### 1. Envelope Encryption

The proposed design calls for DEK material to be:
- Generated via OS CSPRNG (`getrandom::getrandom`; NIST SP 800-90A approved DRBG).
- **Never BLAKE3-derived or deterministic** (Lote 10.14 codex P1 fix: deterministic DEK =
  compromise propagation across blobs sharing the same content hash).
- AES-256-GCM body encryption; nonce 96-bit random per write.
- DEK cache 5 min TTL hard limit (INV-BYOK-CRYPTO-SOVEREIGNTY; no exception; no advisory mode).

### 2. AAD Binding per Provider

| Provider | AAD Mechanism | CoreLink Encoding |
|---|---|---|
| AWS KMS | `encryption_context` HashMap | JSON Value → HashMap<String, String> |
| GCP KMS | `additional_authenticated_data` | JSON Value → UTF-8 bytes |
| Azure Key Vault | Custom AES-GCM layer (inner) | JSON Value → AES-GCM AAD; GCM tag enforces binding |
| HashiCorp Vault | `context` base64 | JSON Value → base64(UTF-8 JSON bytes) |

> **Azure custom AAD flow** (ADR-S14-001): Azure wrapKey (RSA-OAEP-256) does not
> support AAD natively. CoreLink applies an inner AES-256-GCM encryption layer with
> AAD before calling wrapKey. The GCM authentication tag enforces AAD binding;
> tag mismatch on unwrap = `BYOKError::AesGcm`. Adds ~2ms overhead.

### 3. mTLS Auth (Vault only)

- Client certificate presented to Vault server (mutual TLS).
- CA certificate pinned; connection rejected if Vault presents different CA.
- Cert expiry alert: ≤ 30 days remaining → `BYOKError::MtlsCertExpiringSoon` +
  SEV-3 alert + customer notification. Renewal flow: runbook RB-BYOK-VAULT-CERT-RENEWAL.

### 4. Key Lifecycle

- BYOK CMK overlap: **7 days** (INV-KEY-OVERLAP; CTRL-KEY-010/011/012).
- CMK rotation: re-wrap flow (unwrap DEK with old CMK + wrap with new CMK; atomic).
- CMK revoke → DEK cache eviction and failed reads are a proposed target
  (INV-BYOK-CRYPTO-SOVEREIGNTY; kill switch WI-S14-006). No production-binary
  timing or customer guarantee is established by this matrix.

## Quarterly Review Cadence

| Quarter | Review Date | Reviewer | Actions |
|---|---|---|---|
| 2026 Q3 | 2026-08-14 | Crypto SME (TBD) | Verify NIST CMVP status; GCP 140-3 upgrade check; Vault CMVP certificate |
| 2026 Q4 | 2026-11-14 | Crypto SME (TBD) | — |
| 2027 Q1 | 2027-02-14 | Crypto SME (TBD) | — |

## References

- NIST SP 800-57 Pt 1 Rev 5: https://doi.org/10.6028/NIST.SP.800-57pt1r5
- NIST SP 800-130: https://doi.org/10.6028/NIST.SP.800-130
- NIST SP 800-90A Rev 1: https://doi.org/10.6028/NIST.SP.800-90Ar1
- NIST CMVP Search: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- AWS KMS CMVP #4177: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4177
- GCP KMS CMVP #3978: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3978
- Azure Key Vault CMVP #3516: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3516
- ADR-S14-001: `specs/03_architecture/adrs/ADR-S14-001-byok-cross-provider-azure-aad-vault-mtls.md`

## Change Log

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-05-14 | Gustavo (via Claude Sonnet 4.6) | Initial 4-provider FIPS compliance matrix (WI-S14-004 AWS + WI-S14-005 GCP/Azure/Vault). |
