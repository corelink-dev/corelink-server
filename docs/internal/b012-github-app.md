# B-012 GitHub App provisioning packet

This repository uses a private GitHub App to create automatic pull requests.
Each creator job mints a one-hour installation token for exactly
`HuGR-dev/corelink-server`; no PAT or installation token is stored as a durable
Actions secret. The owner installed `corelink-bot-ci` with the permissions
listed below and verified the App-authored hosted DCO/rustfmt proof recorded in
`evidence/owner-actions/B-012/bot-pr-checks.json`.

## App manifest

Create the App from the GitHub App manifest flow while authenticated as an
owner of `HuGR-dev`. The manifest is intentionally limited to the permissions
needed by the five automatic PR creators:

```json
{
  "name": "corelink-bot-ci",
  "url": "https://github.com/HuGR-dev/corelink-server",
  "redirect_url": "https://github.com/HuGR-dev/corelink-server",
  "public": false,
  "default_permissions": {
    "contents": "write",
    "pull_requests": "write",
    "metadata": "read"
  },
  "default_events": []
}
```

Use the organization App settings flow at
`https://github.com/organizations/HuGR-dev/settings/apps/new`, choose the
manifest option, and paste the JSON above. Leave webhooks and all other event
subscriptions disabled. Install the resulting App on **Only select
repositories** → `corelink-server`.

Record the following metadata in the owner’s password manager. Do not put the
private key, its hash, or a secret value in this repository:

| Item | Required value |
| --- | --- |
| App name | `corelink-bot-ci` |
| Installation owner | `HuGR-dev` |
| Installation repository | `corelink-server` only |
| App permissions | `contents: write`, `pull_requests: write`, `metadata: read` |
| Webhooks/events | disabled / none |
| Repository secret 1 | `CORELINK_BOT_APP_ID` = numeric App ID |
| Repository secret 2 | `CORELINK_BOT_APP_PRIVATE_KEY` = generated PEM |
| Durable installation token | forbidden |
| PAT (`BOT_PR_TOKEN`) | forbidden and must remain absent |

## Secret storage

Check names only, then provide values through protected stdin. The PEM must
come from the one-time App key download or password manager; it must never be
an argument, shell history entry, log line, commit, or evidence field.

```bash
gh secret list --repo HuGR-dev/corelink-server
printf '%s' "$APP_ID" | gh secret set CORELINK_BOT_APP_ID \
  --repo HuGR-dev/corelink-server --body-stdin
gh secret set CORELINK_BOT_APP_PRIVATE_KEY \
  --repo HuGR-dev/corelink-server --body-stdin < /protected/path/corelink-bot-ci.pem
gh secret list --repo HuGR-dev/corelink-server
```

The final listing should show the two names and must not be copied into an
issue comment or evidence file with timestamps or values. If `BOT_PR_TOKEN`
exists, stop and revoke it before enabling this App path.

## Workflow contract

The five creators invoke the pinned
`actions/create-github-app-token@def152b8a737443d7af6c5722c6389146fe90c90`
action with `owner: corelink-dev`, `repositories: corelink-server`,
  `permission-metadata: read`, `permission-contents: write`, and
  `permission-pull-requests: write`. The
checkout, branch push, PR creation, comment, and draft-release steps consume
only `steps.app-token.outputs.token`; a missing App secret fails the job before
any mutation. `scripts/verify_bot_pr_auth.py` is the fail-closed static guard;
it requires every mint step to name exactly `owner: corelink-dev` and ignores
commented-out owners.

The owner was `HuGR-dev` until the 2026-10-02 migration: that organisation
became unreachable and the repository was recreated in `corelink-dev`. The App setup
procedure and the installation record above describe the HuGR-dev install. The
App must be created and installed again on `corelink-dev` before these
creators can mint a token.

The App cannot merge a PR through repository automation: generated PRs still
require the normal human review and branch protection rules. App installation
and repository secret changes require an organization/repository owner.

The `pull_request` drift checks in `api-reference-sync.yml` and
`subprocessors-sync.yml` are fork-safe read-only jobs. Their default
`GITHUB_TOKEN` has no pull-request write permission, and checkout does not
persist credentials. The trusted post-merge/scheduled creator jobs use the
short-lived App token for every write.

## Rotation and revocation

Rotate the App private key at least every 90 days, or immediately on suspected
exposure. Generate a replacement key in the App settings, update
`CORELINK_BOT_APP_PRIVATE_KEY` through protected stdin, run one bounded probe,
then revoke the previous key. For full revocation, uninstall the App from
`corelink-server`, delete both repository secrets, and review open bot branches
and PRs. Never revoke release credentials as part of this procedure.

## Verified hosted proof

On 2026-09-22, the owner verified the App's selected-repository installation,
secret-name metadata, and an App-authored PR. The proof PR was closed unmerged
after the hosted DCO and rustfmt jobs both completed successfully on GitHub
Actions with the `ubuntu-latest` label and no approval pending. The sanitized
receipt at `evidence/owner-actions/B-012/bot-pr-checks.json` records each
workflow run URL and its `job_urls` array, runner names and labels, conclusions,
and timestamps. `python3 -S scripts/verify_b012_bot_pr_evidence.py` validates
that receipt; the B-012 contract workflow also checks that the owner packet and
`BACKLOG.md` remain aligned.

The proof establishes those hosted checks for one App-authored PR. It does not
claim that each automatic PR creator ran or that the separate self-hosted
runner labelled `corelink` is online. Never include a JWT, private key, App
installation ID, installation token, or secret value in the receipt.
