#!/usr/bin/env python3
"""Fail-closed static contract for the credentialless Windows readiness probe."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE_WORKFLOW = ROOT / ".github/workflows/issue-2586-windows-readiness.yml"
CI_WORKFLOW = ROOT / ".github/workflows/issue-2586-windows-contract.yml"
SIGN_WORKFLOW = ROOT / ".github/workflows/sign-windows.yml"
SCRIPT = ROOT / "scripts/windows_signing_readiness.ps1"
ACTIONLINT_CONFIG = ROOT / ".actionlint.yaml"
EXPECTED_SECRETS = [
    "WINDOWS_CODE_SIGNING_CERT",
    "WINDOWS_CODE_SIGNING_PASSWORD",
    "WINDOWS_CODE_SIGNING_FINGERPRINT",
    "WINDOWS_CODE_SIGNING_SUBJECT",
]
EXPECTED_PUBLIC_VARS = [
    "WINDOWS_CODE_SIGNING_ISSUER",
    "WINDOWS_CODE_SIGNING_NOT_BEFORE",
    "WINDOWS_CODE_SIGNING_EXPIRES_AT",
    "WINDOWS_SIGNING_RENEWAL_OWNER",
    "WINDOWS_SIGNING_RENEWAL_DATE",
]
EXPECTED_ACTIONLINT_VARS = sorted(EXPECTED_PUBLIC_VARS)
EXPECTED_TIMESTAMP_POLICY = "DigiCert RFC 3161 http://timestamp.digicert.com; SHA-256 file and timestamp digests; not invoked"
RECEIPT_FIELDS = [
    "schema_version", "evidence_type", "repository", "workflow", "commit_sha",
    "run_id", "run_url", "observed_at", "actor_role", "approved_operation",
    "certificate", "chain_revocation", "timestamp_policy", "result",
    "artifact_signature", "final_byte_verification", "renewal",
]
CERTIFICATE_RECEIPT_FIELDS = [
    "issuer_match", "subject_match", "sha256_fingerprint", "valid_from", "expires_at"
]
CHAIN_RECEIPT_FIELDS = ["status", "mode"]
RENEWAL_RECEIPT_FIELDS = ["owner", "date"]
ALLOWED_PATHS = {
    ".actionlint.yaml",
    ".github/workflows/issue-2586-windows-readiness.yml",
    ".github/workflows/issue-2586-windows-contract.yml",
    "scripts/windows_signing_readiness.ps1",
    "scripts/verify_i2586_windows_readiness.py",
    "tests/test_i2586_windows_readiness.py",
}


def top_level_on_triggers(text: str) -> list[str]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"on:\s*", line)), None)
    if start is None:
        return []
    keys: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        match = re.match(r"^  ([A-Za-z_][A-Za-z0-9_-]*):(?:\s|$)", line)
        if match:
            keys.append(match.group(1))
    return keys


def pull_request_paths(text: str) -> list[str]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"  pull_request:\s*", line)), None)
    if start is None:
        return []
    paths: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace():
            break
        if re.fullmatch(r"  [A-Za-z_][A-Za-z0-9_-]*:\s*", line):
            break
        match = re.fullmatch(r"\s{6}-\s+(.+?)\s*", line)
        if match:
            paths.append(match.group(1).strip("'\""))
    return paths


def actionlint_config_vars(text: str) -> list[str]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"config-variables:\s*", line)), None)
    if start is None:
        return []
    names: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        match = re.fullmatch(r"\s{2}-\s+([A-Z][A-Z0-9_]*)\s*", line)
        if match:
            names.append(match.group(1))
    return names


def workflow_secret_names(text: str) -> list[str]:
    return re.findall(r"^\s{10}(WINDOWS_CODE_SIGNING_[A-Z_]+):\s*\$\{\{\s*secrets\.(WINDOWS_CODE_SIGNING_[A-Z_]+)\s*}}\s*$", text, re.M)


def workflow_public_var_names(text: str) -> list[tuple[str, str]]:
    return re.findall(r"^\s{10}([A-Z][A-Z0-9_]+):\s*\$\{\{\s*vars\.([A-Z][A-Z0-9_]+)\s*}}\s*$", text, re.M)


def permission_blocks(text: str, parent_indents: set[int]) -> list[list[str]]:
    lines = text.splitlines()
    blocks: list[list[str]] = []
    for index, line in enumerate(lines):
        indent = len(line) - len(line.lstrip())
        if indent not in parent_indents or line.strip() != "permissions:":
            continue
        children: list[str] = []
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            child_indent = len(child) - len(child.lstrip())
            if child_indent <= indent:
                break
            if child_indent == indent + 2:
                children.append(child.strip())
        blocks.append(children)
    return blocks


def step_run_body(text: str, step_name: str) -> list[str]:
    block = step_block(text, step_name)
    if not block:
        return []
    run_index = next((i for i, line in enumerate(block) if re.match(r"^\s+run:\s*\|\s*$", line)), None)
    if run_index is None:
        return []
    run_indent = len(block[run_index]) - len(block[run_index].lstrip())
    body: list[str] = []
    for line in block[run_index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= run_indent:
            break
        body.append(line[run_indent + 2 :] if len(line) >= run_indent + 2 else "")
    return body


def active_shell_commands(body: list[str]) -> set[str]:
    """Normalize executable bash condition lines while ignoring comments."""
    commands: set[str] = set()
    for line in body:
        command = line.strip()
        if not command or command.startswith("#"):
            continue
        if command.startswith("if [[") and command.endswith("; then"):
            command = command[3:-6].strip()
        commands.add(command)
    return commands


def step_block(text: str, step_name: str) -> list[str]:
    lines = text.splitlines()
    step_index = next((i for i, line in enumerate(lines) if re.fullmatch(r"\s*- name: " + re.escape(step_name), line)), None)
    if step_index is None:
        return []
    step_indent = len(lines[step_index]) - len(lines[step_index].lstrip())
    step_end = next(
        (i for i in range(step_index + 1, len(lines)) if
         len(lines[i]) - len(lines[i].lstrip()) == step_indent and lines[i].lstrip().startswith("- ")),
        len(lines),
    )
    return lines[step_index:step_end]


def step_scalar_run(text: str, step_name: str) -> str | None:
    block = step_block(text, step_name)
    run = next((line for line in block[1:] if re.match(r"^\s+run:\s*[^|>]", line)), None)
    return run.split("run:", 1)[1].strip() if run else None


def signer_contract_names(text: str) -> list[str]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"    secrets:\s*", line)), None)
    if start is None:
        return []
    names: list[str] = []
    for line in lines[start + 1 :]:
        if line and (not line[0].isspace() or len(line) - len(line.lstrip()) <= 4):
            break
        if line.startswith("      ") and not line.startswith("        "):
            match = re.fullmatch(r"      (WINDOWS_CODE_SIGNING_[A-Z_]+):\s*(?:#.*)?", line)
            if match:
                names.append(match.group(1))
            elif "WINDOWS_CODE_SIGNING_" in line and not line.lstrip().startswith("#"):
                names.append("<invalid-contract-entry>")
            elif "WINDOWS_CODE_SIGNING_" in line and line.lstrip().startswith("#"):
                names.append("<commented-contract-entry>")
    return names


def validate_texts(probe: str, ci: str, signer: str, script: str, actionlint_config: str) -> list[str]:
    errors: list[str] = []
    if top_level_on_triggers(probe) != ["workflow_dispatch"]:
        errors.append("readiness workflow must have only the manual workflow_dispatch trigger")
    for required in (
        "github.repository_id == '",
        "github.ref == 'refs/heads/main' && github.ref_protected",
        "runs-on: windows-2022",
        "environment: production",
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "-ExpectedOperation 'authenticode-credential-binding-metadata-only'",
        f"-TimestampPolicy '{EXPECTED_TIMESTAMP_POLICY}'",
    ):
        if required not in probe:
            errors.append(f"readiness workflow missing protected boundary: {required}")
    actual_secret_refs = [secret for _binding, secret in workflow_secret_names(probe)]
    actual_secret_bindings = [binding for binding, _secret in workflow_secret_names(probe)]
    if actual_secret_refs != EXPECTED_SECRETS or actual_secret_bindings != EXPECTED_SECRETS:
        errors.append("readiness workflow secret bindings must exactly match the four contracted names in order")
    actual_vars = workflow_public_var_names(probe)
    if [value for _binding, value in actual_vars] != EXPECTED_PUBLIC_VARS or [binding for binding, _value in actual_vars] != EXPECTED_PUBLIC_VARS:
        errors.append("readiness workflow public metadata and renewal vars must match approved names in order")
    if re.findall(r"\bvars\.([A-Z][A-Z0-9_]*)\b", probe) != EXPECTED_PUBLIC_VARS:
        errors.append("readiness workflow contains missing, duplicate, or unapproved vars references")
    if permission_blocks(probe, {0, 4}) != [["contents: read"], ["contents: read"]]:
        errors.append("readiness workflow permissions must be exactly contents: read at workflow and job scope")
    if signer_contract_names(signer) != EXPECTED_SECRETS:
        errors.append("sign-windows workflow_call contract changed, was reordered, duplicated, commented, or renamed")
    if "http://timestamp.digicert.com" not in signer or "/fd SHA256" not in signer or "/td SHA256" not in signer:
        errors.append("DigiCert RFC 3161 and SHA-256 policy no longer matches the signing workflow contract")
    if re.search(r"secrets\.(?!WINDOWS_CODE_SIGNING_(?:CERT|PASSWORD|FINGERPRINT|SUBJECT)\b)", probe):
        errors.append("readiness workflow references a secret outside the four-name contract")
    if re.search(r"(?i)(upload-artifact|upload-release-asset|gh\s+(?:release|api)|GITHUB_TOKEN|id-token:|signing[_ -]?key)", probe):
        errors.append("readiness workflow contains a publication, token, or signing surface")

    if top_level_on_triggers(ci) != ["pull_request", "workflow_dispatch"]:
        errors.append("credentialless CI workflow must accept only scoped PR and manual dispatch triggers")
    if sorted(pull_request_paths(ci)) != sorted(ALLOWED_PATHS):
        errors.append("credentialless CI pull-request trigger paths must exactly match the exclusive ownership map")
    for required in (
        "github.repository_id == vars.CORELINK_SERVER_REPO_ID",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.event.pull_request.head.ref == 'codex/issue-2586-no-sign-readiness-20260925'",
        "github.event.pull_request.base.ref == 'main'",
        "github.ref == 'refs/heads/codex/issue-2586-no-sign-readiness-20260925'",
    ):
        if ci.count(required) != 2:
            errors.append("credentialless CI jobs must restrict PR and dispatch events to the owned repository and branch")
            break
    configured_vars = actionlint_config_vars(actionlint_config)
    if any(configured_vars.count(name) != 1 for name in EXPECTED_ACTIONLINT_VARS):
        errors.append("actionlint config must define each approved Windows public var exactly once")
    if permission_blocks(ci, {0, 4}) != [["contents: read"], ["contents: read"]]:
        errors.append("credentialless CI workflow permissions must remain read-only")
    expected_checkout_ref = "          ref: ${{ github.event.pull_request.head.sha || inputs.candidate_sha }}"
    if re.findall(r"^\s{10}ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\|\|\s*inputs\.candidate_sha\s*}}\s*$", ci, re.M) != [expected_checkout_ref] * 2:
        errors.append("both CI jobs must use the exact candidate SHA as checkout ref")
    for step_name in ("Fetch the protected main base", "Bind exact head and base"):
        if len(re.findall(r"^\s*- name: " + re.escape(step_name) + r"\s*$", ci, re.M)) != 1:
            errors.append(f"CI pack must contain exactly one {step_name} step")
    protected_checkout = step_block(ci, "Fetch the protected main base")
    active_checkout = [line for line in protected_checkout if not line.lstrip().startswith("#")]
    checkout_requirements = (
        r"\s*- name: Fetch the protected main base",
        r"\s+uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7\.0\.0",
        r"\s+ref: refs/heads/main",
        r"\s+path: trusted-main",
        r"\s+persist-credentials: false",
    )
    if not active_checkout or any(
        not any(re.fullmatch(pattern, line) for line in active_checkout)
        for pattern in checkout_requirements
    ):
        errors.append("CI pack must fetch protected main as a separate credentialless checkout")
    for required in (
        "type: string",
        "EXPECTED_SHA: ${{ github.event.pull_request.head.sha || inputs.candidate_sha }}",
        "REQUESTED_BASE_SHA: ${{ inputs.target_base_sha }}",
        "PR_HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}",
        "PR_HEAD_REF: ${{ github.event.pull_request.head.ref }}",
        "PR_BASE_REF: ${{ github.event.pull_request.base.ref }}",
        "runs-on: ubuntu-24.04",
        "runs-on: windows-2022",
        "python3 -S -m unittest -q tests/test_i2586_windows_readiness.py",
        "scripts/windows_signing_readiness.ps1 -SelfTest",
        "persist-credentials: false",
    ):
        if required not in ci:
            errors.append(f"credentialless CI pack missing exact-head or focused check: {required}")
    if ci.count("ref: ${{ github.event.pull_request.head.sha || inputs.candidate_sha }}") != 2:
        errors.append("both credentialless runner jobs must check out the exact candidate SHA")
    binding_commands = {
        '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]',
        '[[ "$GITHUB_SHA" == "$EXPECTED_SHA" ]]',
        '[[ "$REQUESTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$REQUESTED_BASE_SHA" == "$EXPECTED_BASE" ]]',
        '[[ "$GITHUB_EVENT_NAME" == pull_request ]]',
        '[[ "$PR_HEAD_REPO" == "$GITHUB_REPOSITORY" ]]',
        '[[ "$PR_HEAD_REF" == codex/issue-2586-no-sign-readiness-20260925 ]]',
        '[[ "$PR_BASE_REF" == main ]]',
        '[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]]',
        'git fetch "$GITHUB_WORKSPACE/trusted-main" refs/heads/main:refs/remotes/target/main',
        'TRUSTED_MAIN_SHA="$(git rev-parse refs/remotes/target/main)"',
        'EXPECTED_BASE="$(git merge-base "$TRUSTED_MAIN_SHA" "$EXPECTED_SHA")"',
        'TARGET_BASE_SHA="$EXPECTED_BASE"',
        '[[ "$actual_paths" == "$expected_paths" ]]',
    }
    if not binding_commands.issubset(active_shell_commands(step_run_body(ci, "Bind exact head and base"))):
        errors.append("credentialless CI pack does not bind head and target base to protected main using executable checks")
    binding_body = [
        line for line in step_run_body(ci, "Bind exact head and base")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    path_literals = []
    for line in binding_body:
        token = line.strip().split(maxsplit=1)[0].strip("'\"") if line.strip() else ""
        if token in ALLOWED_PATHS:
            path_literals.append(token)
    if sorted(path_literals) != sorted(ALLOWED_PATHS):
        errors.append("credentialless CI pack path boundary does not match the exclusive ownership map")
    if step_scalar_run(ci, "Run synthetic metadata fixtures only") != "./scripts/windows_signing_readiness.ps1 -SelfTest":
        errors.append("Windows CI job must execute the credentialless PowerShell self-test as its actual step command")
    powershell_checkout = step_block(ci, "Check out the PowerShell self-test script")
    checkout_input_lines = [line for line in powershell_checkout if re.match(r"^ {10}[a-z][a-z0-9-]*:", line)]
    checkout_input_names = [line.strip().split(":", 1)[0] for line in checkout_input_lines]
    sparse_values = [match.group(1) for line in checkout_input_lines if (match := re.fullmatch(r" {10}sparse-checkout:\s*(.*?)\s*", line))]
    sparse_mode_values = [match.group(1) for line in checkout_input_lines if (match := re.fullmatch(r" {10}sparse-checkout-cone-mode:\s*(.*?)\s*", line))]
    exact_sparse_checkout = (
        checkout_input_names == ["ref", "fetch-depth", "persist-credentials", "sparse-checkout", "sparse-checkout-cone-mode"]
        and sparse_values == ["scripts/windows_signing_readiness.ps1"]
        and sparse_mode_values == ["false"]
    )
    if not exact_sparse_checkout:
        errors.append("Windows CI checkout must select only the PowerShell self-test script with non-cone sparse checkout")
    # The only variable the credentialless pack may read is the non-secret
    # server repository ID its routine guard compares against.
    if re.search(r"(?i)(secrets\.|vars\.(?!CORELINK_SERVER_REPO_ID\b)|sign-windows\.yml)", ci) or re.search(
        r"(?im)^\s*(?:gh\s+workflow\s+run\s+issue-2586-windows-readiness\.yml\b|gh\s+api\s+repos/\S+/actions/workflows/issue-2586-windows-readiness\.yml/dispatches\b)", ci
    ):
        errors.append("credentialless CI pack accesses secrets or executes the readiness workflow")
    for path in sorted(ALLOWED_PATHS):
        if path not in ci:
            errors.append(f"credentialless CI path boundary omits {path}")

    for forbidden in (
        r"(?i)\bsigntool\b", r"(?i)\bosslsigncode\b", r"(?i)\bopenssl\b",
        r"(?i)\bgh\s+(?:release|api)\b", r"(?i)actions/upload-",
        r"(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b",
        r"(?i)\b(?:Set-AuthenticodeSignature|Sign-File|Timestamp-File)\b",
        r"(?i)\b(?:Export-PfxCertificate|Export-Certificate)\b",
    ):
        if re.search(forbidden, probe + "\n" + ci + "\n" + script):
            errors.append(f"forbidden signing, export, or publication command found: {forbidden}")
    if not re.search(r"(?is)finally\s*\{.*?if\s*\(\$null\s*-ne\s*\$pfxBytes\)\s*\{\s*\[Array\]::Clear\(\$pfxBytes,\s*0,\s*\$pfxBytes\.Length\)\s*\}.*?\[Environment\]::SetEnvironmentVariable\(\$name,\s*\$null\)", script):
        errors.append("PowerShell implementation lacks finally cleanup for in-memory PFX bytes and secret environment values")
    if re.search(r"(?i)(New-TemporaryFile|WriteAllBytes|WriteAllText|Set-Content.+(?:\.pfx|\.p12)|ConvertTo-SecureString.+File)", script):
        errors.append("PowerShell implementation must not persist certificate or password material to disk")
    if not re.search(r"(?is)RevocationMode\s*=.*?::Online", script) or not re.search(r"(?is)RevocationFlag\s*=.*?::EntireChain", script):
        errors.append("PowerShell implementation must check the full chain online for revocation")
    if "EphemeralKeySet" not in script or "HasPrivateKey" not in script or "GetRSAPrivateKey" not in script:
        errors.append("PowerShell implementation must import ephemerally and verify private-key association")
    schema = re.search(r"(?is)\$script:ReceiptFields\s*=\s*@\((.*?)\)", script)
    actual_fields = re.findall(r"'([a-z0-9_]+)'", schema.group(1)) if schema else []
    if actual_fields != RECEIPT_FIELDS:
        errors.append("PowerShell receipt fields do not exactly match the approved readiness schema")
    for array_name, expected_fields in (
        ("CertificateReceiptFields", CERTIFICATE_RECEIPT_FIELDS),
        ("ChainReceiptFields", CHAIN_RECEIPT_FIELDS),
        ("RenewalReceiptFields", RENEWAL_RECEIPT_FIELDS),
    ):
        nested = re.search(r"(?is)\$script:" + array_name + r"\s*=\s*@\((.*?)\)", script)
        found = re.findall(r"'([a-z0-9_]+)'", nested.group(1)) if nested else []
        if found != expected_fields:
            errors.append(f"PowerShell {array_name} do not match the frozen redacted receipt schema")
    return errors


def validate(root: Path = ROOT) -> list[str]:
    paths = [
        root / ".actionlint.yaml",
        root / ".github/workflows/issue-2586-windows-readiness.yml",
        root / ".github/workflows/issue-2586-windows-contract.yml",
        root / ".github/workflows/sign-windows.yml",
        root / "scripts/windows_signing_readiness.ps1",
    ]
    missing = [str(path.relative_to(root)) for path in paths if not path.is_file()]
    if missing:
        return [f"required contract file missing: {path}" for path in missing]
    config, probe, ci, signer, script = (path.read_text(encoding="utf-8") for path in paths)
    return validate_texts(probe, ci, signer, script, config)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run verifier negative controls")
    args = parser.parse_args()
    if args.self_test:
        probe = PROBE_WORKFLOW.read_text(encoding="utf-8")
        ci = CI_WORKFLOW.read_text(encoding="utf-8")
        signer = SIGN_WORKFLOW.read_text(encoding="utf-8")
        script = SCRIPT.read_text(encoding="utf-8")
        config = ACTIONLINT_CONFIG.read_text(encoding="utf-8")
        accepted = validate_texts(probe, ci, signer, script, config)
        if accepted:
            print("self-test baseline unexpectedly rejected: " + "; ".join(accepted), file=sys.stderr)
            return 1
        mutations = (
            (probe.replace("  workflow_dispatch:\n", "  push:\n    branches: [main]\n  workflow_dispatch:\n", 1), ci, signer, script, config),
            (probe.replace("secrets.WINDOWS_CODE_SIGNING_CERT", "secrets.WINDOWS_CODE_SIGNING_PASSWORD", 1), ci, signer, script, config),
            (probe, ci + "\n      - name: unsafe\n        run: gh release publish\n", signer, script, config),
            (probe, ci, signer.replace("      WINDOWS_CODE_SIGNING_PASSWORD:", "      # WINDOWS_CODE_SIGNING_PASSWORD:", 1), script, config),
            (probe, ci, signer.replace("      WINDOWS_CODE_SIGNING_FINGERPRINT:", "      WINDOWS_CODE_SIGNING_SUBJECT:\n      WINDOWS_CODE_SIGNING_FINGERPRINT:", 1), script, config),
            (probe, ci, signer.replace("WINDOWS_CODE_SIGNING_FINGERPRINT", "__TEMP_FINGERPRINT__", 1).replace("WINDOWS_CODE_SIGNING_SUBJECT", "WINDOWS_CODE_SIGNING_FINGERPRINT", 1).replace("__TEMP_FINGERPRINT__", "WINDOWS_CODE_SIGNING_SUBJECT", 1), script, config),
            (probe, ci, signer, script.replace("$null -ne $pfxBytes", "$false -and $null -ne $pfxBytes", 1), config),
            (probe, ci, signer, script.replace("GetRSAPrivateKey", "GetPublicKey", 1), config),
            (probe, ci.replace("ref: ${{ github.event.pull_request.head.sha || inputs.candidate_sha }}", "ref: main", 1), signer, script, config),
            (probe, ci.replace('[[ "$REQUESTED_BASE_SHA" == "$EXPECTED_BASE" ]]', '# [[ "$REQUESTED_BASE_SHA" == "$EXPECTED_BASE" ]]', 1), signer, script, config),
            (probe, ci.replace("      - tests/test_i2586_windows_readiness.py", "      # - tests/test_i2586_windows_readiness.py", 1), signer, script, config),
            (probe, ci, signer, script, config.replace("  - WINDOWS_SIGNING_RENEWAL_OWNER\n", "  # - WINDOWS_SIGNING_RENEWAL_OWNER\n", 1)),
        )
        for index, fixture in enumerate(mutations, start=1):
            if not validate_texts(*fixture):
                print(f"self-test negative control {index} was accepted", file=sys.stderr)
                return 1
        print("issue-2586 verifier negative controls passed")
        return 0
    errors = validate()
    if errors:
        print("issue-2586 Windows readiness contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("issue-2586 Windows readiness contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
