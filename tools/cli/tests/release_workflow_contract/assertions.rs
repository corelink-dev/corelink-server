//! Structural regression tests for the public CLI release root.
//!
//! These tests deliberately inspect the workflow text.  The critical contract
//! spans GitHub Actions, the installer, and three independent signing lanes;
//! a Rust-only unit test cannot observe it.  Keep the mutation controls here so
//! a superficially valid workflow cannot silently repoint, skip tool validation,
//! or stop publishing the files downstream signers request.

use std::path::PathBuf;

pub(super) fn release_workflow() -> Result<String, String> {
    load_workflow("release-cli.yml")
}

pub(super) fn load_workflow(name: &str) -> Result<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".github/workflows")
        .join(name);
    std::fs::read_to_string(path).map_err(|_| format!("{name} workflow must be readable"))
}

pub(super) fn load_script(name: &str) -> Result<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts")
        .join(name);
    std::fs::read_to_string(path).map_err(|_| format!("{name} script must be readable"))
}

pub(super) fn load_repo_file(name: &str) -> Result<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name);
    std::fs::read_to_string(path).map_err(|_| format!("{name} must be readable"))
}

fn job_section<'a>(workflow: &'a str, name: &str) -> &'a str {
    let marker = format!("\n  {name}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow job must exist: {name}"))
        + marker.len();
    let tail = &workflow[start..];
    let end = tail
        .lines()
        .enumerate()
        .find_map(|(line, text)| {
            (text.starts_with("  ") && !text.starts_with("    ") && text.ends_with(':')).then(
                || {
                    tail.lines()
                        .take(line)
                        .map(|item| item.len() + 1)
                        .sum::<usize>()
                },
            )
        })
        .unwrap_or(tail.len());
    &tail[..end]
}

fn assert_gh_install_precedes_use(name: &str, section: &str) {
    let install = section
        .find("- name: Install checksum-pinned GitHub CLI 2.79.0")
        .unwrap_or_else(|| panic!("{name} must install the checksum-pinned GitHub CLI"));
    let installer = section[install..]
        .find("python3 scripts/install_pinned_gh.py --output \"${GH_BIN}\"")
        .unwrap_or_else(|| panic!("{name} must use the shared pinned GitHub CLI installer"))
        + install;
    let path = section[install..]
        .find("${RUNNER_TEMP}/corelink-pinned-gh\" >> \"${GITHUB_PATH}\"")
        .unwrap_or_else(|| panic!("{name} must place the installed CLI first on PATH"))
        + install;
    let guard = section
        .find("- name: Verify pinned GitHub CLI")
        .unwrap_or_else(|| panic!("{name} must retain the exact version guard"));
    let command = section[guard..]
        .find("gh --version")
        .unwrap_or_else(|| panic!("{name} must execute the CLI version guard"))
        + guard;
    let use_index = ["gh api ", "gh release "]
        .iter()
        .filter_map(|marker| section.find(marker))
        .min()
        .unwrap_or_else(|| panic!("{name} must contain a GitHub CLI consumer"));
    assert!(
        install < installer
            && installer < path
            && path < guard
            && guard < command
            && command < use_index,
        "{name} must provision checksum-pinned gh before checking and consuming it"
    );
}

pub(super) fn assert_pinned_gh_contract(
    caller: &str,
    linux_signer: &str,
    slsa: &str,
    installer: &str,
    checksums: &str,
) {
    for required in [
        "VERSION = \"2.79.0\"",
        "CHECKSUMS = Path(__file__).with_name(f\"gh_{VERSION}_checksums.json\")",
        "verify_digest(archive, expected)",
        "verify_binary(output)",
    ] {
        assert!(
            installer.contains(required),
            "pinned gh installer missing {required}"
        );
    }
    assert!(
        checksums.contains("\"version\": \"2.79.0\""),
        "gh checksum manifest must pin 2.79.0"
    );
    assert!(
        checksums.contains("gh_2.79.0_linux_amd64.tar.gz")
            && checksums
                .contains("e7af0c72a607c0528fda1989f7c8e3be85e67d321889002af0e2938ad9c8fb68"),
        "official Linux gh release archive must use its pinned SHA-256"
    );
    for job in [
        "release",
        "final-manifest",
        "publish-release",
        "verify-draft-release",
    ] {
        assert_gh_install_precedes_use(job, job_section(caller, job));
    }
    assert_gh_install_precedes_use("Linux signer", job_section(linux_signer, "sign"));
    assert_gh_install_precedes_use("SLSA consumer", job_section(slsa, "attest-final-inventory"));
}

pub(super) fn assert_windows_build_steps_use_bash(workflow: &str) {
    for name in [
        "Validate matrix target values before shell use",
        "Set SOURCE_DATE_EPOCH",
        "Set RUSTFLAGS path-remap",
        "Build (cargo zigbuild) — Linux + Windows",
    ] {
        let marker = format!("- name: {name}\n");
        let start = workflow
            .find(&marker)
            .unwrap_or_else(|| panic!("release build step missing: {name}"));
        let tail = &workflow[start..];
        let end = tail.find("\n      - name:").unwrap_or(tail.len());
        let step = &tail[..end];
        let shell = step.find("        shell: bash\n");
        let run = step.find("        run:");
        assert!(
            step.matches("        shell:").count() == 1
                && shell.is_some()
                && run.is_some()
                && shell < run,
            "Bash syntax step must select exactly one Bash shell: {name}"
        );
    }
}

fn assert_initial_release_target_inventory(workflow: &str) {
    let matrix = workflow
        .split_once("      matrix:\n        target:\n")
        .expect("release target matrix must be present")
        .1
        .split_once("\n    steps:")
        .expect("release target matrix must end before job steps")
        .0;
    let mut targets: Vec<_> = matrix
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- triple: "))
        .collect();
    targets.sort_unstable();
    let mut expected = vec![
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-gnu",
    ];
    expected.sort_unstable();
    assert_eq!(
        targets,
        expected,
        "initial release matrix must contain exactly the Linux x86_64, Linux aarch64, and Windows x86_64 targets"
    );
}

pub(super) fn assert_release_contract(workflow: &str) {
    assert_initial_release_target_inventory(workflow);
    for required in [
        "description: \"Existing cli-vMAJOR.MINOR.PATCH tag bound to the exact source commit\"",
        "HuGR-Labs/corelink-cli",
        "EXPECTED_ZIG_VERSION=0.16.0",
        "tool: cargo-zigbuild@0.19.8",
        "command -v cargo-zigbuild",
        "cargo-zigbuild --help >/dev/null",
        "CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}",
        "- name: Enable Git long paths for Windows checkout",
        "run: git config --global core.longpaths true",
        "- name: Checkout",
        "corelink-package-${TARGET_NAME}",
        "Validate matrix target values before shell use",
        "- name: Set up pinned Python for deterministic Windows packaging",
        "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
        "python-version: \"3.12\"",
        "shell: pwsh",
        "python -c $pythonCode",
        "New-Item -ItemType Directory -Path (Join-Path $PWD 'out') -Force | Out-Null",
        "ZipInfo(\"corelink.exe\", (1980, 1, 1, 0, 0, 0))",
        "info.create_system=0",
        "info.external_attr=0",
        "info.compress_type=ZIP_STORED",
        "assert check.namelist()==[\"corelink.exe\"]",
        "assert hashlib.sha256(archived).digest()==hashlib.sha256(payload).digest()",
        "Set-Content -LiteralPath $sidecar -Value \"$actual  $([IO.Path]::GetFileName($file))\" -NoNewline -Encoding ascii",
        "$expected = (Get-Content -LiteralPath $sidecar).Split(' ')[0]",
        "if ($actual -ne $expected) { throw \"SHA-256 sidecar mismatch: $file\" }",
        "Get-FileHash -LiteralPath $file -Algorithm SHA256",
        "signer_name: corelink-linux-arm64",
        "${TARGET_SIGNER_NAME}.tar.gz",
        "$archive = Join-Path $PWD \"out\\${env:TARGET_SIGNER_NAME}.zip\"",
        "(cd dist && shasum -a 256 -c \"$(basename \"$CHECKSUM\")\")",
        "Read back published artifacts and verify release-root digests",
        "--pattern 'corelink-*'",
        "(cd \"$PUBLISHED\" && shasum -a 256 -c checksums.txt)",
        "CORELINK_CLI_RELEASE_TOKEN is required only to publish",
        "--notes-file /tmp/release-notes.md --draft",
        "Bind staged artifacts to the immutable source manifest",
        "staging-manifest.json",
        "final-manifest:",
        "RELEASE_API=\"${RUNNER_TEMP}/corelink-final-manifest-release.json\"",
        "case \"${STAGING_ASSET_COUNT}\" in",
        "--pattern 'corelink-*' --pattern checksums.txt --pattern release-manifest.json",
        "cli_release_manifest.py verify --directory final-assets",
        "STAGING_ASSET_ID=\"$(python3 - \"${RELEASE_API}\"",
        "gh api --method DELETE \"repos/HuGR-Labs/corelink-cli/releases/assets/${STAGING_ASSET_ID}\"",
        "STAGING_ASSET_COUNT=\"$(gh api \"repos/HuGR-Labs/corelink-cli/releases/tags/${TAG}\"",
        "release-slsa3:",
        "release-slsa3:\n    needs: [final-manifest, release-readiness, release]\n    # Called workflows cannot elevate the caller's token permissions. Grant\n    # OIDC only to this provenance call; all other release jobs retain the\n    # workflow-level contents:read default.\n    permissions:\n      attestations: write\n      contents: read\n      id-token: write\n    uses: ./.github/workflows/release-slsa3.yml\n    with:\n      release_tag: ${{ inputs.release_tag }}\n      source_sha: ${{ needs.release.outputs.source_sha }}\n      manifest_sha256: ${{ needs.final-manifest.outputs.sha256 }}\n      release_mode: ${{ needs.final-manifest.outputs.release_mode }}",
        "publish-release:\n    name: publish verified signed release\n    needs: [release-slsa3, release-readiness, final-manifest, release, sign-windows]\n    if: >-\n      always() && inputs.release_mode == 'signed-public'",
        "Verify complete authenticated inventory before publication",
        "gh release download \"${TAG}\" --repo HuGR-Labs/corelink-cli --dir \"${PUBLISHED}\" --clobber",
        "scripts/verify_cli_release_inventory.py",
        "uses: ./.github/workflows/sign-linux.yml",
        "uses: ./.github/workflows/sign-windows.yml",
        "tag: ${{ needs.release.outputs.validated_tag }}",
    ] {
        assert!(
            workflow.contains(required),
            "missing release invariant: {required}"
        );
    }
    assert!(
        !workflow.contains("--repo HumanGuardrail/corelink-cli"),
        "the cross-repository release target must not regress to the 404 home"
    );
    assert!(
        !workflow.contains("Swatinem/rust-cache@"),
        "a release publisher must not consume a mutable build cache"
    );
    assert!(
        !workflow.contains("ditto -c -k --sequesterRsrc --keepParent"),
        "the Windows archive must not nest corelink.exe below a ditto parent directory"
    );
    for unsupported in [
        "cargo-zigbuild --version",
        "cargo-zigbuild -V",
        "cargo zigbuild --version",
        "cargo zigbuild -V",
    ] {
        assert!(
            !workflow.contains(unsupported),
            "the release workflow must not use an unsupported cargo-zigbuild probe: {unsupported}"
        );
    }
    let longpaths = workflow
        .find("- name: Enable Git long paths for Windows checkout")
        .unwrap();
    let checkout = workflow.find("- name: Checkout").unwrap();
    assert!(
        longpaths < checkout,
        "Windows long paths must be enabled before checkout"
    );
}

pub(super) fn assert_release_tag_shell_boundary(workflow: &str) {
    for required in [
        "validated_tag: ${{ steps.validate-release-tag.outputs.tag }}",
        "- name: Validate release tag before shell use",
        "id: validate-release-tag",
        "INPUT_TAG: ${{ inputs.release_tag }}",
        "case \"${INPUT_TAG}\" in",
        r#"[[ "${INPUT_TAG}" =~ ^cli-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]"#,
        r#"printf 'tag=%s\n' "${INPUT_TAG}" >> "${GITHUB_OUTPUT}""#,
        "TAG: ${{ steps.validate-release-tag.outputs.tag }}",
        "gh release create \"${TAG}\"",
        "gh release upload \"${TAG}\"",
        "gh release download \"${TAG}\"",
    ] {
        assert!(
            workflow.contains(required),
            "release tag boundary is missing: {required}"
        );
    }
    let validation = workflow
        .find("- name: Validate release tag before shell use")
        .unwrap();
    for command in [
        "gh release create \"${TAG}\"",
        "gh release upload \"${TAG}\"",
        "gh release download \"${TAG}\"",
    ] {
        assert!(
            validation < workflow.find(command).unwrap(),
            "release command must follow validation: {command}"
        );
    }
    assert!(
        !workflow.contains("gh release upload \"${{ inputs.release_tag }}\"")
            && !workflow.contains("gh release download \"${{ inputs.release_tag }}\""),
        "release commands must consume validated TAG"
    );
}

pub(super) fn assert_draft_only_release_contract(workflow: &str) {
    for required in [
        "release_mode:\n        description: \"Draft-only by default; signed-public requires every production signature gate\"\n        required: true\n        type: choice\n        default: draft-only",
        "options:\n          - draft-only\n          - signed-public",
        "if: inputs.release_mode == 'signed-public'\n    needs: [sign-linux, release]",
        "Linux artifacts have detached GPG signatures. The Windows artifact is unsigned and deferred; no Authenticode or RFC 3161 timestamp is claimed.",
        "draft-only mode refuses to overwrite or resume a non-empty draft",
        "draft-only mode requires exactly one staging manifest and refuses retry/replacement",
        "scripts/cli_release_draft_manifest.py create",
        "scripts/cli_release_draft_manifest.py verify-manifest",
        "scripts/verify_cli_release_draft.py",
        "needs.sign-windows.result == 'skipped'",
        "always() && inputs.release_mode == 'draft-only'",
        "always() && inputs.release_mode == 'signed-public' &&\n      needs.release.outputs.release_mode == 'signed-public' &&",
        "needs.sign-windows.result == 'success'",
        "GPG_PACKET_READY",
    ] {
        assert!(workflow.contains(required), "draft-only release contract missing {required}");
    }
}

pub(super) fn assert_downstream_signer_contract(name: &str, workflow: &str) {
    for required in [
        "CORELINK_CLI_RELEASE_TOKEN",
        "RELEASE_REPOSITORY: HuGR-Labs/corelink-cli",
        "--repo \"${RELEASE_REPOSITORY}\"",
    ] {
        assert!(
            workflow.contains(required),
            "{name} is missing cross-repository signer invariant: {required}"
        );
    }
    assert!(
        !workflow.contains("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"),
        "{name} must not use the source-repository GITHUB_TOKEN for a CLI release asset"
    );
    for required in [
        "workflow_call:",
        "INPUT_TAG: ${{ inputs.tag }}",
        "source_sha:",
        "staging_manifest_sha256:",
        "INPUT_SOURCE_SHA: ${{ inputs.source_sha }}",
        "STAGING_MANIFEST_SHA256: ${{ inputs.staging_manifest_sha256 }}",
        "shasum -a 256 ./assets/staging-manifest.json",
        "git rev-list -n 1 \"${INPUT_TAG}\"",
        "staging-manifest.json",
        "scripts/cli_release_manifest.py verify",
        "RAW_ASSET:",
        "case \"${INPUT_TAG}\" in cli-v*) ;; *)",
        "git show-ref --verify --quiet \"refs/tags/${INPUT_TAG}\"",
        "fetch-tags: true",
        "persist-credentials: false",
    ] {
        assert!(
            workflow.contains(required),
            "{name} is missing reusable-signer tag invariant: {required}"
        );
    }
    assert!(
        !workflow.contains("workflow_run:"),
        "{name} must not use workflow_run for a privileged release signer"
    );
    assert!(
        !workflow.contains("workflow_dispatch:"),
        "{name} must not expose a privileged manual signing entrypoint"
    );
    assert!(
        !workflow.contains("--password \"${APPLE_NOTARIZATION_PASSWORD}\""),
        "{name} must not expose an Apple notarization password on argv"
    );
    if name == "sign-windows.yml" {
        assert!(
            workflow.contains(
                "Copy-Item ./assets/extracted/corelink.exe ./assets/corelink-windows-x86_64.exe -Force"
            ),
            "a raw Windows release executable must be replaced with signed bytes"
        );
        assert!(
            workflow.contains("runs-on: windows-2022")
                && workflow.contains("signtool.exe")
                && workflow.contains("Import-PfxCertificate")
                && workflow.contains("/sha1 $cert.Thumbprint"),
            "Windows signing must use the hosted signtool certificate store without a password argv"
        );
    }
    if name == "sign-linux.yml" {
        assert!(
            workflow.contains("for target in \"${ASSET}\" \"${RAW_ASSET}\"; do"),
            "the raw Linux executable and archive must both receive detached signatures"
        );
    }
    if name == "notarize-macos.yml" {
        assert!(
            workflow.contains("spctl --assess --type execute --verbose=4 \"${BINARY}\""),
            "macOS Gatekeeper assessment is mandatory"
        );
        assert!(
            !workflow.contains("spctl --assess --type execute --verbose=4 \"${BINARY}\" || true"),
            "macOS Gatekeeper assessment must not be bypassed"
        );
        assert!(
            workflow.contains("cp \"${BINARY}\" \"./assets/${RAW_ASSET}\""),
            "the raw macOS release executable must be replaced after stapling"
        );
    }
    assert!(
        !workflow.contains("${GITHUB_ENV}"),
        "{name} must not propagate signer state through GITHUB_ENV"
    );
    assert!(
        !workflow.contains("workflow_run:"),
        "{name} must not use workflow_run for a privileged release signer"
    );
}

pub(super) fn assert_checksum_refresh_contract(name: &str, workflow: &str) {
    for required in [
        "--pattern 'corelink-*.sha256'",
        "LC_ALL=C sort corelink-*.sha256 > checksums.txt",
        "shasum -a 256 \"${ASSET}\" > \"${ASSET}.sha256\"",
        "./assets/checksums.txt",
        "Read back signer-updated release checksums",
        "shasum -a 256 -c checksums.txt",
    ] {
        assert!(
            workflow.contains(required),
            "{name} is missing signed-asset checksum refresh invariant: {required}"
        );
    }
}

pub(super) fn assert_slsa_contract(workflow: &str) {
    for required in [
        "workflow_call:",
        "manifest_sha256:",
        "SOURCE_SHA: ${{ inputs.source_sha }}",
        "release-manifest.json",
        "--pattern checksums.txt",
        "test \"${GITHUB_REF}\" = \"refs/tags/${TAG}\"",
        "test \"${GITHUB_SHA}\" = \"${SOURCE_SHA}\"",
        "contents: read",
        "attestations: write",
        "id-token: write",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "subject-checksums: provenance-subjects.sha256",
        "provenance.intoto.jsonl.bundle",
        "gh attestation verify",
        "--signer-workflow \"${REPO}/.github/workflows/release-slsa3.yml\"",
        "--source-ref",
        "--source-digest",
        "--cert-oidc-issuer \"https://token.actions.githubusercontent.com\"",
        "test \"${STAGING_ASSET_COUNT}\" = \"0\"",
    ] {
        assert!(
            workflow.contains(required),
            "release-slsa3 missing immutable-inventory/OIDC invariant: {required}"
        );
    }
}

pub(super) fn assert_publication_inventory_contract(workflow: &str) {
    for required in [
        "Verify complete authenticated inventory before publication",
        "immediately before the irreversible draft=false",
        "gh api \"repos/HuGR-Labs/corelink-cli/releases/tags/${TAG}\" > \"${API_JSON}\"",
        "FINAL_ASSETS=\"${RUNNER_TEMP}/corelink-publish-assets-final\"",
        "gh release download \"${TAG}\" --repo HuGR-Labs/corelink-cli \\",
        "--dir \"${PUBLISHED}\" --clobber",
        "scripts/verify_cli_release_inventory.py",
        "gh attestation verify",
        "--signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/release-slsa3.yml\"",
        "--cert-oidc-issuer \"https://token.actions.githubusercontent.com\"",
        "gh release edit \"${TAG}\" --repo HuGR-Labs/corelink-cli --draft=false",
    ] {
        assert!(
            workflow.contains(required),
            "publication inventory control missing: {required}"
        );
    }
}

pub(super) fn assert_retry_manifest_contract(workflow: &str) {
    let retry = workflow
        .split("            signed-public)\n")
        .nth(1)
        .and_then(|rest| rest.split("                0)\n").nth(1))
        .and_then(|rest| rest.split("                1)\n").next());
    assert!(
        retry.is_some(),
        "final-manifest retry branch must be present"
    );
    if let Some(retry) = retry {
        for required in [
            "--pattern 'corelink-*' --pattern checksums.txt --pattern release-manifest.json",
            "manifest.get(\"staging_manifest_sha256\") != sys.argv[2]",
            "manifest.get(\"tag\") != sys.argv[3]",
            "manifest.get(\"source_sha\") != sys.argv[4]",
            "cli_release_manifest.py verify --directory final-assets",
        ] {
            assert!(
                retry.contains(required),
                "retry branch missing inventory proof: {required}"
            );
        }
    }
}

pub(super) fn assert_inventory_helper_contract(script: &str) {
    for required in [
        "staging-manifest.json",
        "METADATA",
        "provenance.intoto.jsonl.bundle",
        "signed_statement",
        "dsseEnvelope",
        "subject_digests",
        "verify_checksums(directory, artifacts)",
        "CHECKSUM_LINE",
        "release inventory is not closed-world",
        "except (OSError, ValueError, json.JSONDecodeError)",
    ] {
        assert!(
            script.contains(required),
            "release inventory helper control missing: {required}"
        );
    }
}

pub(super) fn assert_rekor_helper_contract(script: &str) {
    for required in [
        "tlogEntries",
        "if not entries:",
        "inclusionProof",
        "canonicalizedBody",
        "expected = hashlib.sha256(payload_path.read_bytes()).hexdigest()",
        "_inclusion_root",
        "inclusionProof.rootHash",
        "integrated_time is None",
        "digest.lower() == expected",
    ] {
        assert!(
            script.contains(required),
            "Rekor verifier control missing: {required}"
        );
    }
}
