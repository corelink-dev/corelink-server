"""Bounded source contract for the protected Cloudflare handoff workflow."""

from __future__ import annotations


def verify_workflow(source: str) -> None:
    required = (
        "python3 - <<'PY' | env -u CF_BOOTSTRAP_ADMIN_TOKEN node",
        "const expectedMode = process.argv[4];",
        'if (plaintext.length === 0) throw new Error("empty payload");',
        'payload.mode !== expectedMode || payload.github_sha !== expectedSha',
        'payload.github_run_id !== expectedRunId',
        'schema: "corelink-cloudflare-token-handoff-envelope-v1"',
        'envelope.mode !== expectedMode || envelope.github_sha !== expectedSha',
        'envelope.github_run_id !== expectedRunId',
        'envelope.recipient_key_sha256 !== expectedKeyHash',
        'if: always()\n        env:\n          MODE: ${{ inputs.mode }}\n          EXPECTED_SHA: ${{ github.sha }}',
        'MINT_OUTCOME: ${{ steps.mint_token.outcome }}',
        'if [[ "$MINT_OUTCOME" == success',
        'echo "valid=$valid" >> "$GITHUB_OUTPUT"',
        "if: success() && steps.validate_handoff.outputs.valid == 'true'",
        'VALID_HANDOFF: ${{ steps.validate_handoff.outputs.valid }}',
        'if [[ "$VALID_HANDOFF" == true && -s "$RUNNER_TEMP/cf-handoff/handoff.enc.json" ]]',
        "if: failure() && steps.check_handoff.outputs.exists == 'true' && steps.validate_handoff.outputs.valid == 'true'",
        "if: always() && steps.upload_ciphertext.outcome != 'success' && steps.upload_recovery.outcome != 'success'",
        'if [[ ! -s "$TOKEN_STATE_FILE" ]]',
        'token_id = state.get("token_id")',
        'f"https://api.cloudflare.com/client/v4/user/tokens/{token_id}"',
        'method="DELETE"',
        'result.get("success") is not True',
        'token_revoked": True',
        'path: ${{ runner.temp }}/cf-handoff/handoff.enc.json',
        'r2-2564-mint) test "$CONFIRM" = \'mint-r2-2564-corelink-b068-r2-isolated-20260926-staging\' ;;',
        'worker-1700-mint) test "$CONFIRM" = \'mint-worker-1700-staging-only\' ;;',
        'group_id = "2efd5506f9c8494dacb1fa10a3e7d5b6"',
        'group_id = "e086da7e2179491d91ee5f35b3ca210a"',
        'resource = f"com.cloudflare.edge.r2.bucket.{account}_default_{bucket}"',
        'resource = f"com.cloudflare.api.account.{account}"',
    )
    missing = [fragment for fragment in required if fragment not in source]
    if missing:
        raise AssertionError(f"workflow contract missing {len(missing)} required gate(s): {missing}")

    # The run-scoped marker must be written as soon as Cloudflare returns an ID,
    # before any subsequent payload failure can make the encrypted handoff fail.
    marker = source.index('fd = os.open(os.environ["TOKEN_STATE_FILE"]')
    missing_value = source.index('raise SystemExit("Cloudflare token response omitted secret value")')
    if marker > missing_value:
        raise AssertionError("token marker is written after payload construction can fail")

    forbidden = (
        "steps.check_handoff.outputs.exists == 'true'\n        uses:",
        'path: ${{ runner.temp }}/cf-handoff/token-id.json',
        'path: ${{ runner.temp }}/cf-handoff/recipient.pem',
        "echo \"$plaintext\"",
        "console.log(plaintext",
    )
    present = [fragment for fragment in forbidden if fragment in source]
    if present:
        raise AssertionError(f"workflow contract contains forbidden gate or artifact path: {present}")


def verify_negative_controls(source: str) -> None:
    """Mutation oracle: dropping any cleanup or pre-upload gate must fail."""
    mutations = (
        ('if (plaintext.length === 0) throw new Error("empty payload");', ""),
        ('payload.mode !== expectedMode || payload.github_sha !== expectedSha ||', "payload.github_sha !== expectedSha ||"),
        ("if: success() && steps.validate_handoff.outputs.valid == 'true'", "if: always()"),
        ("steps.validate_handoff.outputs.valid == 'true'", "steps.check_handoff.outputs.exists == 'true'"),
        ("steps.upload_recovery.outcome != 'success'", "steps.upload_recovery.outcome == 'success'"),
        ('if [[ ! -s "$TOKEN_STATE_FILE" ]]', 'if [[ -e "$TOKEN_STATE_FILE" ]]'),
        ('if (plaintext.length === 0) throw new Error("empty payload");', 'if (plaintext.length === 0) {}'),
    )
    for before, after in mutations:
        if before not in source:
            raise AssertionError(f"negative control anchor not found: {before}")
        mutated = source.replace(before, after, 1)
        try:
            verify_workflow(mutated)
        except AssertionError:
            continue
        raise AssertionError(f"contract accepted negative control mutation: {before}")
