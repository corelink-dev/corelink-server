# Signing trust after the owner migration

New CoreLink deployment and supply-chain acceptance trusts only
`corelink-dev/corelink-server`. A signature by a previous owner is not authority
for a new release, deploy, or evidence delivery. Retention or control of former
GitHub organization names is not assumed.

| Path | Purpose and trust |
|---|---|
| `CosignIdentityPattern::corelink_release()` | New deployment acceptance; current owner only. The verifier also enforces the current repository independently of caller-supplied regexes. No historical deploy policy. |
| `BuilderIdentity::from_exact` / `from_org_pattern` | Current supply-chain acceptance; only current server SANs match, including when a caller supplies a legacy identity. |
| `BuilderIdentity::from_historical_exact` / `from_historical_org_pattern` | Explicit inspection of retained historical evidence. Caller chooses an exact SAN or repository; legacy owners remain valid only in this scope. |
| Pentest pack `How to verify` | New evidence delivery; current owner only. |
| Pentest pack `Historical artifacts only` | Separate command for retained artifacts; previous owners and current owner accepted. Never a current acceptance gate. |
| Basic SLSA example and public verifier rustdoc | Current release acceptance. |
| Paranoid SLSA example | Historical artifact inspection with its retained exact HumanGuardrail SAN and an explicit historical constructor. |
| SLSA adversarial/property fixtures | Historical artifact verification with explicit historical constructors; payload and SAN bytes retained. |
| Deploy verifier, examples and adversarial/property/chaos tests | Synthesized new deployments, not retained signed evidence. Their simulated successful SAN is current; legacy SAN rejection is tested separately. OCI distribution references are unchanged. |
| `corelink-supply-verify` CLI | Purpose is not explicit in its interface; conservatively current-only through ordinary BuilderIdentity constructors. Legacy `--expected-builder` arguments fail identity matching. Its pinned old-owner help text needs I3. |

Migration PLAN section 4.2 assigns the unpinned signing examples and acceptance
tests to I4, the pinned CLI examples/reporting to I3 (including their preparation
seed re-pin), the release workflow identity to I2a, and the SLSA internal guide to
P3. The general identity resolver and other current projection markers remain I1.

I4 also includes the pre-existing RE2 anchor correction on the evidence-pack
command. It remains an explicit separate commit in the branch history; no
history is rewritten. Rust uses its regex engine, while the printed cosign
commands use Go-compatible `^` and `$` anchors.
