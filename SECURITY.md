# Security Policy

CoreLink takes the security of its software, services, and users seriously.
This document explains how to report a vulnerability, what we commit to in
return, and the timeline you can expect.

GitHub auto-detects this file and surfaces it on the repository **Security**
tab. The same content (slightly expanded with legal language and
out-of-scope items) lives at:

- Customer-facing portal: <https://humangr.com/corelink/docs/security/policy>
- RFC 9116 contact card: <https://corelink-docs.humangr.com/.well-known/security.txt>
- Canonical spec: `specs/_security/vulnerability-disclosure-policy.md`

---

## Supported Versions

We patch the **latest minor** of the latest **major** release line. Older
lines are unsupported and will not receive backports.

| Version | Supported          | Notes                                   |
| ------- | ------------------ | --------------------------------------- |
| 1.0.x   | :white_check_mark: | Active. CRITICAL/HIGH fixes within SLA. |
| < 1.0   | :x:                | Pre-GA. Please upgrade.                 |

A version is "supported" if it is the active maintenance line. Once a new
minor line ships (e.g., 1.1.0), the previous minor enters a 30-day
deprecation window during which only CRITICAL fixes are backported.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Use one
of the channels below.

### Primary: email

- **Email:** `security@humangr.com`
- **PGP:** no key is published at this time (the `security.txt` contact card
  omits its `Encryption` field for the same reason). Send reports over plain
  email.
- **Subject prefix:** `[VULN]` followed by a short description.

### Alternative: web form

- Not available. A web-form address was listed here, but no such form was
  ever served; email is the only intake channel.

### Include in your report

1. A clear description of the issue and the impact you believe it has.
2. Reproduction steps. Ideally a self-contained script or Docker image.
3. Affected version(s), endpoint(s), or component(s).
4. Your assessment of severity (CVSS v3.1 score preferred).
5. Whether you intend to disclose publicly, and on what timeline.
6. How you would like to be credited (or that you prefer to remain
   anonymous).

---

## Our Response SLA

| Stage                            | Target                                       |
| -------------------------------- | -------------------------------------------- |
| Acknowledge receipt              | within **24 hours**                          |
| Initial triage (severity + ack)  | within **72 hours**                          |
| Status update cadence            | every **7 days** until closed                |
| Fix or mitigation — **CRITICAL** | within **24 hours**                          |
| Fix or mitigation — **HIGH**     | within **7 days**                            |
| Fix or mitigation — **MEDIUM**   | within **30 days**                           |
| Fix or mitigation — **LOW**      | within **90 days** or next routine release   |
| Public credit (if desired)       | at coordinated disclosure                    |

Times are measured in calendar hours/days from receipt of a well-formed
report. We will tell you in the first acknowledgement which severity
bucket we have placed the report in and why.

---

## Coordinated Disclosure Timeline

We follow a **90-day coordinated disclosure** model by default, aligned
with Google Project Zero norms:

- **D+0** — report received, acknowledged.
- **D+3** — triage complete, severity confirmed, fix owner assigned.
- **D+0 .. D+90** — fix developed, tested, and released.
- **D+90** — public advisory + CVE issued (whether or not fix is in
  customer hands; we will not sit on disclosure indefinitely).

We are **flexible**:

- For CRITICAL findings already exploited in the wild, we will disclose
  faster, after a 7-day patch window.
- For LOW findings where the reporter prefers a longer embargo, we can
  extend up to 120 days by mutual agreement.
- A 14-day grace period is granted automatically if a fix is in QA at
  D+90.

---

## Safe Harbor

We will **not pursue legal action** against researchers who:

1. Make a good-faith effort to comply with this policy.
2. Avoid privacy violations, destruction of data, and interruption or
   degradation of our services.
3. Only interact with accounts they own or with explicit permission from
   the account holder.
4. Do not exploit a vulnerability beyond the minimum necessary to confirm
   it.
5. Give us a reasonable amount of time to resolve the issue before
   disclosing it publicly.

Full safe-harbor language is in
`specs/_security/vulnerability-disclosure-policy.md` §6.

---

## Reward Program

For the GA launch we offer:

- A **thank you in the changelog and release notes**.
- A **place in our Hall of Fame**: <https://humangr.com/corelink/docs/security/hall-of-fame>.
- **CoreLink swag** (T-shirt, stickers, optional hardware key) for any
  finding rated MEDIUM or higher.

A monetary reward program is **planned post-GA**. Indicative bands (subject
to Finance + Legal sign-off):

| Severity | Indicative reward (post-GA) |
| -------- | --------------------------- |
| CRITICAL | $ TBD                       |
| HIGH     | $ TBD                       |
| MEDIUM   | $ TBD                       |
| LOW      | swag + Hall of Fame credit  |

Findings reported before the bounty program goes live are **eligible for
retroactive payment** at our discretion if the program launches within 12
months of the report.

---

## Hall of Fame

We thank the following researchers for their responsible disclosures.
(Placeholder — list will be populated as reports come in.)

| Researcher | Date | Severity | Finding (sanitised) |
| ---------- | ---- | -------- | ------------------- |
| _(empty — be the first!)_ | | | |

---

## Out of Scope

The following are explicitly **out of scope** and will be closed without
triage:

- Denial-of-service attacks against production systems (testing is OK
  against your own self-hosted instance).
- Social engineering of CoreLink staff, contractors, or customers.
- Physical attacks against CoreLink offices or data centres.
- Issues exclusively affecting outdated browsers (anything Google's
  current support matrix has dropped) or unsupported clients.
- Vulnerabilities in third-party services not operated by CoreLink (please
  report those to the relevant vendor).
- Theoretical findings without a working proof-of-concept.
- Reports generated by automated scanners with no human analysis.
- Reports that violate the law or our [Terms of Service](https://humangr.com/corelink/docs/legal/terms).

A more exhaustive list is in
`specs/_security/vulnerability-disclosure-policy.md` §7.

---

## Disclosure Channels

After a fix is released we publish:

- A **GitHub Security Advisory** with CVE.
- A note in the release **CHANGELOG**.
- A blog post for HIGH/CRITICAL findings.
- A customer email for CRITICAL findings impacting hosted tenants.

---

## Related Documents

- Customer-facing policy: <https://humangr.com/corelink/docs/security/policy>
- Spec: `specs/_security/vulnerability-disclosure-policy.md`
- Operator runbook: `specs/_runbooks/RB-SECURITY-VULNERABILITY-INTAKE.md`
- Pentest finding response runbook: `specs/_runbooks/RB-PENTEST-FINDING-RESPONSE.md`
- Security model: `specs/03_architecture/security_model.md`
- RFC 9116 contact card: [`/.well-known/security.txt`](apps/docs/static/.well-known/security.txt)

---

---

## Operational Security Notes

### 2026-06-10 — Actions fork-PR policy + SHA-pinning baseline

**Repository visibility.**
The repo is currently **private**. GitHub does not expose the
"Fork pull request workflows → Require approval for all outside collaborators"
setting for private repos (the option is absent from Settings → Actions).

**Action required if the repo is ever made public:** immediately navigate to
Settings → Actions → General → Fork pull request workflows and set the policy
to **"Require approval for all outside collaborators"** before any external
contributor can open a PR. The CI runs on the founder's Mac (self-hosted
runner); a fork PR that executes arbitrary workflow code is a direct RCE
vector onto that machine.

**SHA-pinning.**
`actions/permissions sha_pinning_required=true` was confirmed enabled via the
GitHub API on 2026-06-10. All workflows in `.github/workflows/` were already
SHA-pinned prior to this date (enforced by the `action-sha-audit` required
check). No workflow updates are needed as a result; this note records the
baseline verification.

_Last updated: 2026-06-10._
