#!/usr/bin/env python3
"""Fail-closed structural verifier for the protected GPG audit contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/i1664-gpg-release-identity-audit.yml"
RUNNER = ROOT / "scripts/run_i2587_gpg_audit.py"
CI_WORKFLOW = ROOT / ".github/workflows/i2587-gpg-audit-ci.yml"
PUBLIC_KEY_FIXTURE = ROOT / "tests/fixtures/i2571-release-pubkey.asc"


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate(workflow: str, runner: str, ci_workflow: str) -> None:
    for trigger in ("workflow_dispatch: {}", "permissions:\n  contents: read"):
        require(trigger in workflow, f"protected audit missing {trigger!r}")
    require(workflow.count("workflow_dispatch:") == 1, "protected audit must be manual-only")
    require("pull_request:" not in workflow and "push:" not in workflow and "schedule:" not in workflow, "protected audit must not run automatically")
    for gate in (
        "github.repository == 'HuGR-dev/corelink-server'",
        "github.repository_id == '1232040291'",
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        "github.ref_protected",
        "environment: release-key-audit",
        "persist-credentials: false",
    ):
        require(gate in workflow, f"protected audit missing dispatch guard {gate!r}")
    for secret_name in ("GPG_PRIVATE_KEY", "GPG_PRIVATE_KEY_PASS", "GPG_KEY_ID", "GPG_KEY_FINGERPRINT"):
        require(f"secrets.{secret_name}" in workflow, f"protected audit missing {secret_name} binding")
        require(workflow.count(f"secrets.{secret_name} }}") == 1, f"{secret_name} must be bound once")
    require("contents: write" not in workflow and "id-token: write" not in workflow, "protected audit has write authority")
    for forbidden in ("upload-artifact", "gh release", "git tag", "softprops/action-gh-release", "notarytool", "timestamp"):
        require(forbidden.lower() not in workflow.lower(), f"protected workflow includes forbidden operation {forbidden!r}")

    for literal in (
        'EXPECTED_FINGERPRINT = "795253CEBD6D54C862CFC4A3EC0AD89A75EC6756"',
        'EXPECTED_PRIMARY_UID = "CoreLink Release Signing (corelink-cli release signing key) <releases@humangr.com>"',
        'fingerprint != EXPECTED_FINGERPRINT',
        'key_id != EXPECTED_FINGERPRINT[-16:]',
        'def validate_configured_binding(',
        'PRIMARY_UID_EXPORT_FILTER = "keep-uid=primary -t"',
        '["--export-filter", PRIMARY_UID_EXPORT_FILTER, "--export", EXPECTED_FINGERPRINT]',
        '"--with-colons", "--fixed-list-mode", "--with-fingerprint", "--show-keys"',
        'input_bytes=primary_public_key.stdout',
        'public[1][:1] in {"r", "e", "d", "i", "n"}',
        'int(public[6]) <= now_epoch',
        'uid != EXPECTED_PRIMARY_UID',
        'def check_secret_listing(',
        'def run_passphrase_probe(',
        '"--passphrase-fd"',
        '"--detach-sign"',
        'os.devnull',
        'PROBE_BYTES = b"CoreLink protected GPG access audit probe v1\\n"',
        'stdout=subprocess.PIPE',
        'stderr=subprocess.PIPE',
        'shutil.rmtree(temp_root)',
        '"GITHUB_STEP_SUMMARY"',
        '"protected_secret_names": EXPECTED_SECRET_NAMES',
        '"revoked": False',
    ):
        require(literal in runner, f"protected audit implementation missing {literal!r}")
    require(runner.count('if key_id != EXPECTED_FINGERPRINT[-16:]') == 2, "configured and imported key IDs must both match all 16 suffix digits")
    for forbidden in ("--sign", "--sign-with", "--detach-sign --armor", "gh release", "git tag", "upload-artifact", "GPG_PRIVATE_KEY}", "echo $GPG_"):
        require(forbidden.lower() not in runner.lower(), f"protected audit implementation has unsafe form {forbidden!r}")
    require(re.search(r"(?<![A-Za-z0-9_])print\s*\(\s*env\s*\[", runner) is None, "protected audit prints environment data")
    require("--detach-sign" in runner and '"--output",\n            os.devnull' in runner, "probe signature must be sent directly to /dev/null")
    require("input=PROBE_BYTES" in runner, "only the fixed synthetic probe may be signed")
    require("except subprocess.TimeoutExpired" in runner and "process.kill()" in runner, "probe process must be bounded and killed on timeout")
    require("except OSError" in runner and "process.communicate()" in runner, "probe process cleanup missing")

    require("pull_request:" in ci_workflow and "workflow_dispatch:" not in ci_workflow, "credentialless CI must be PR-only")
    require("permissions:\n  contents: read" in ci_workflow, "credentialless CI permissions are not read-only")
    require("scripts/verify_i2587_gpg_audit.py --self-test" in ci_workflow, "credentialless CI omits the contract verifier")
    require(ci_workflow.count("tests/test_i2587_gpg_audit.py") == 3, "credentialless CI must trigger on and run synthetic adversarial tests")
    require(ci_workflow.count("tests/fixtures/i2571-release-pubkey.asc") == 2, "credentialless CI must trigger on the public-key fixture")
    require(PUBLIC_KEY_FIXTURE.is_file() and PUBLIC_KEY_FIXTURE.stat().st_size < 4096, "public-key fixture missing or unexpectedly large")
    require("secrets." not in ci_workflow and "upload-artifact" not in ci_workflow, "credentialless CI can read secrets or upload artifacts")
    exact_head_ref = "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
    require(ci_workflow.count(f"ref: {exact_head_ref}") == 1, "credentialless CI checkout must pin PR head with a safe push fallback")
    require(ci_workflow.count(f"EXPECTED_SHA: {exact_head_ref}") == 1, "credentialless CI must compare the checkout to the exact candidate SHA")
    require('[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]]' in ci_workflow, "credentialless CI does not verify the checked-out SHA")

    require("def validate_probe_result(returncode: int, *, passphrase_expected_to_work: bool)" in runner, "passphrase result is not checked")
    require('fail("protected-passphrase-not-required-or-agent-cached")' in runner, "unprotected or cached-key success is accepted")
    require('passphrase=WRONG_PASSPHRASE' in runner and 'passphrase=env["GPG_PRIVATE_KEY_PASS"]' in runner, "wrong-passphrase and configured-passphrase probes are missing")
    require(runner.index('passphrase=WRONG_PASSPHRASE') < runner.index('passphrase=env["GPG_PRIVATE_KEY_PASS"]'), "configured passphrase must only be tried after wrong-passphrase rejection")
    require(runner.count("terminate_ephemeral_agent(gnupghome)") == 3, "ephemeral GPG agent must be cleared before probes, between probes, and during cleanup")
    require("try:\n        temp_root = Path(tempfile.mkdtemp" in runner and "        os.chmod(temp_root, 0o700)\n        gnupghome = temp_root / \"gnupg\"\n        gnupghome.mkdir(mode=0o700)" in runner, "temporary keyring setup must be inside cleanup-protected try/finally")


def self_test() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    runner = RUNNER.read_text(encoding="utf-8")
    ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    exact_head_ref = "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
    validate(workflow, runner, ci_workflow)
    mutations = (
        (workflow.replace("GPG_KEY_FINGERPRINT: ${{ secrets.GPG_KEY_FINGERPRINT }}", "# fingerprint binding removed", 1), runner, ci_workflow),
        (workflow.replace("environment: release-key-audit", "# environment removed", 1), runner, ci_workflow),
        (workflow.replace("permissions:\n  contents: read", "permissions:\n  contents: write", 1), runner, ci_workflow),
        (workflow + "\n  push:\n", runner, ci_workflow),
        (workflow.replace("persist-credentials: false", "persist-credentials: true", 1), runner, ci_workflow),
        (workflow + "\n      - uses: actions/upload-artifact@v4\n", runner, ci_workflow),
        (workflow, runner.replace('fingerprint != EXPECTED_FINGERPRINT', 'fingerprint.endswith(EXPECTED_FINGERPRINT[-16:])', 1), ci_workflow),
        (workflow, runner.replace('key_id != EXPECTED_FINGERPRINT[-16:]', 'key_id[-8:] != EXPECTED_FINGERPRINT[-8:]', 1), ci_workflow),
        (workflow, runner.replace('"--export-filter", PRIMARY_UID_EXPORT_FILTER, "--export", EXPECTED_FINGERPRINT', '"--export", EXPECTED_FINGERPRINT', 1), ci_workflow),
        (workflow, runner.replace('"--passphrase-fd"', '"--passphrase"', 1), ci_workflow),
        (workflow, runner.replace('"--output",\n            os.devnull', '"--output",\n            "signature.asc"', 1), ci_workflow),
        (workflow, runner.replace('input=PROBE_BYTES', 'input=env["RELEASE_BYTES"]', 1), ci_workflow),
        (workflow, runner.replace('shutil.rmtree(temp_root)', '# cleanup removed', 1), ci_workflow),
        (workflow, runner.replace('"revoked": False', '"revoked": "unknown"', 1), ci_workflow),
        (workflow, runner.replace('PROBE_BYTES = b"CoreLink protected GPG access audit probe v1\\n"', 'PROBE_BYTES = b"release payload\\n"', 1), ci_workflow),
        (workflow, runner.replace('EXPECTED_PRIMARY_UID = "CoreLink Release Signing (corelink-cli release signing key) <releases@humangr.com>"', 'EXPECTED_PRIMARY_UID = "wrong UID"', 1), ci_workflow),
        (workflow, runner, ci_workflow.replace('permissions:\n  contents: read', 'permissions:\n  contents: write', 1)),
        (workflow, runner, ci_workflow.replace('tests/test_i2587_gpg_audit.py', 'tests/other.py', 1)),
        (workflow, runner, ci_workflow.replace(f"ref: {exact_head_ref}", "ref: ${{ github.sha }}", 1)),
        (workflow, runner, ci_workflow.replace('[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]]', '[[ -n "$EXPECTED_SHA" ]]', 1)),
        (workflow, runner.replace('fail("protected-passphrase-not-required-or-agent-cached")', 'return None', 1), ci_workflow),
        (workflow, runner.replace('passphrase=WRONG_PASSPHRASE', 'passphrase=env["GPG_PRIVATE_KEY_PASS"]', 1), ci_workflow),
        (workflow, runner.replace('try:\n        temp_root = Path(tempfile.mkdtemp', 'temp_root = Path(tempfile.mkdtemp', 1), ci_workflow),
    )
    for index, fixture in enumerate(mutations, 1):
        try:
            validate(*fixture)
        except ContractError:
            continue
        raise ContractError(f"adversarial mutation {index} survived")
    print(f"GPG audit contract valid; {len(mutations)} adversarial mutations rejected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test()
        validate(
            WORKFLOW.read_text(encoding="utf-8"),
            RUNNER.read_text(encoding="utf-8"),
            CI_WORKFLOW.read_text(encoding="utf-8"),
        )
        print("GPG audit contract valid")
        return 0
    except (ContractError, OSError) as error:
        print(f"GPG audit contract invalid: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
