# B-063 partition replay evidence

This repository check is the offline evidence boundary for issue #1648. It
does not contact D1, R2, the container endpoint, GitHub, or PagerDuty. An
authorized operator may save one redacted read-only D1 population as:

```json
{
  "partition": {"tenant_id": "<stable-redaction>", "region": "enam"},
  "rows": []
}
```

Each row must retain `id`, `tenant_id`, `region`, `sequence_number`,
`prev_hash`, `chain_hash`, `enqueued_at`, `canonical_jcs`, `algorithm_id`,
`epoch_id`, and `link_key_id`. Payload bytes stay in the operator's ephemeral
input and are not committed as evidence.

Run:

```sh
python3 scripts/verify_b063_archive_replay.py --input /path/to/redacted.json
```

For the independent R2 object-chain verifier, the existing
`audit-chain-daily-verify` workflow has a closed `build_only` dispatch mode.
Use it only from protected `main`, with `expected_sha` equal to the exact
dispatched commit SHA. It runs on standard GitHub-hosted macOS arm64, has only
`contents:read`, and skips the normal Ubuntu smoke job and seven-day R2/PagerDuty
job (the build-only job runs its own empty-input smoke check). The artifact contains
the native verifier and `provenance.json`; it contains no archive object or
production receipt. Validate the artifact's commit, run URL, source blob,
crate Rust tree digest, lockfile digest, runner architecture, and binary SHA-256
against GitHub's run/artifact metadata before use. The run must be successful
and its SHA must still be the protected-main commit being investigated.

Run the downloaded native verifier locally against an operator-captured,
scope-approved object file, keeping the payload private. Sealed archive lines
require `--verify-day`, and the filename must preserve the authenticated R2
object key under a `chunks/` staging directory; do not rename the object to a
generic filename. Substitute the UTC day and exact key established by the
private read receipt:

```sh
shasum -a 256 verifier
./verifier --verify-day YYYY-MM-DD \
  /private/path/to/.audit-verify-staging/chunks/<exact-authenticated-R2-object-key>
```

The binary is an offline verifier only. A successful check establishes the
object's internal chain validity; it does not prove bucket inventory
completeness, retention, replay exclusion, or the absence of another chain.
Do not upload object bytes as a GitHub artifact or paste verifier output that
contains customer identifiers into a public issue.

The verifier applies the production reader's deterministic
`ORDER BY sequence_number, id`, recomputes the BLAKE3 link from
`prev_hash || canonical_jcs`, checks contiguous sequence and tenant/region
isolation, and reports zero D1/R2 writes. `drainable` is exit 0;
`quarantine_required` is exit 1 and identifies the first break; malformed,
mixed-tenant, or hash-invalid input is `fail_closed` with exit 2.

This artifact cannot close B-063/#1648. Closure still requires the issue's
three distinct zero-failure production population reads and three complete
green `audit-archive-lag` runs after an authorized repair.
