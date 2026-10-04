#!/usr/bin/env bash
set -euo pipefail

# The run must come from the configured server repository: exact
# GITHUB_REPOSITORY and numeric GITHUB_REPOSITORY_ID, both read from
# config/github-identity.json. The resolver refuses an unread (0) ID.
python3 -I "$(dirname "${BASH_SOURCE[0]}")/server_repository.py" --require-github-context >/dev/null
[[ "${GITHUB_REF:-}" == "refs/heads/main" && "${REF_PROTECTED:-}" == "true" ]]
[[ "${CONFIRM:-}" == "i1721-r2-lock-proof" ]]
[[ "${EXPECTED_SHA:-}" =~ ^[0-9a-f]{40}$ && "${EXPECTED_SHA:-}" == "${GITHUB_SHA:-}" ]]
