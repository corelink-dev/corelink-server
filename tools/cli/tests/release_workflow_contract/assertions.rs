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
        .find(
            "python3 scripts/verify_pinned_gh.py --binary \"${RUNNER_TEMP}/corelink-pinned-gh/gh\"",
        )
        .unwrap_or_else(|| panic!("{name} must verify the absolute checksum-pinned CLI"))
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
    assert!(
        !section.contains("2025-09-08"),
        "{name} must not retain the obsolete pinned CLI build date"
    );
}

pub(super) fn assert_pinned_gh_contract(
    caller: &str,
    linux_signer: &str,
    slsa: &str,
    installer: &str,
    checksums: &str,
    verifier: &str,
    smoke: &str,
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
    for required in [
        "from install_pinned_gh import InstallError, VERSION, verify_binary",
        "verify_binary(binary)",
        "shutil.which(\"gh\")",
        "PATH does not resolve gh to the checksum-pinned executable",
        "re.escape(VERSION)",
        "date.fromisoformat(match.group(1))",
    ] {
        assert!(
            verifier.contains(required),
            "pinned gh verifier missing {required}"
        );
    }
    for required in [
        "(\"release-cli.yml\", \"release\", \"release\")",
        "(\"release-cli.yml\", \"final-manifest\", \"final-manifest\")",
        "(\"release-cli.yml\", \"publish-release\", \"publish-release\")",
        "(\"release-cli.yml\", \"verify-draft-release\", \"verify-draft-release\")",
        "(\"sign-linux.yml\", \"sign\", \"Linux signer\")",
        "(\"release-slsa3.yml\", \"attest-final-inventory\", \"SLSA consumer\")",
        "\"release-cli.yml\": 8",
        "\"sign-linux.yml\": 4",
        "\"release-slsa3.yml\": 3",
        "GH_TOKEN",
        "OLD_DATE = \"2025-09-08\"",
        "yaml.safe_load",
        "step.get(\"shell\") == \"bash\"",
        "\"if\" not in step",
        "def manual_installer_step() -> str:",
        "def assert_manual_installer_path(runner_temp: Path, python_dir: str) -> None:",
        "assert_manual_installer_path(runner_temp, python_dir)",
        "manual setup must reject the runner's earlier system gh PATH",
        "manual setup must reject a later PATH override that selects system gh",
        "for label, run in consumers",
        "[\"bash\", \"--noprofile\", \"--norc\", \"-e\", \"-o\", \"pipefail\", \"-c\", run]",
        "mutant.returncode == 23",
        "stale_date_result.returncode != 0",
        "actual Bash guard must reject an unpinned PATH executable",
        "wrong_result.returncode != 0",
        "def assert_bundle_suffix_behavior(binary: Path, runner_temp: Path) -> None:",
        "bundle file extension not supported",
        "pinned gh must accept `.json` and proceed to parse the bundle without network credentials",
        "target_counts == TARGET_STEP_COUNTS",
        "missing destination read credential mutation must be rejected",
    ] {
        assert!(
            smoke.contains(required),
            "pinned gh six-consumer smoke missing {required}"
        );
    }
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

pub(super) fn assert_pinned_gh_hosted_smoke(pack: &str) {
    let section = job_section(pack, "contract");
    for required in [
        "fetch-depth: 0",
        "Install Python contract dependencies",
        "Install checksum-pinned Linux gh and execute all six exact guard steps",
        "persist-credentials: false",
        "GH_TOKEN: \"\"",
        "GH_ENTERPRISE_TOKEN: \"\"",
        "GITHUB_ENTERPRISE_TOKEN: \"\"",
        "python3 -B scripts/test_pinned_gh_consumers.py",
    ] {
        assert!(
            section.contains(required),
            "credentialless pinned gh pack missing {required}"
        );
    }
    assert!(
        !section.contains("${{ secrets."),
        "pinned gh consumer smoke must not receive repository secrets"
    );

    let manual = job_section(pack, "verify-preserved-cli-017-draft");
    let install = manual
        .find("python3 -B scripts/install_pinned_gh.py --output \"${GH_BIN}\"")
        .expect("manual verifier must install checksum-pinned gh");
    let path = manual
        .find("export PATH=\"${RUNNER_TEMP}/corelink-pinned-gh:${PATH}\"")
        .expect("manual verifier must prepend pinned gh to its current-step PATH");
    let verify = manual
        .find("python3 -B scripts/verify_pinned_gh.py --binary \"${GH_BIN}\"")
        .expect("manual verifier must validate pinned gh after prepending PATH");
    assert!(
        install < path && path < verify,
        "manual verifier must install, prepend, then verify the pinned CLI"
    );
    assert!(
        manual.contains("${RUNNER_TEMP}/corelink-pinned-gh\" >> \"${GITHUB_PATH}\""),
        "manual verifier must preserve the pinned CLI PATH for its later steps"
    );
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
        "--create-or-reuse-empty-draft",
        "--notes-file /tmp/release-notes.md --format id",
        "Bind staged artifacts to the immutable source manifest",
        "staging-manifest.json",
        "cli_release_draft_manifest.py write-checksums",
        "final-manifest:",
        "RELEASE_API=\"${RUNNER_TEMP}/corelink-final-manifest-release.json\"",
        "case \"${STAGING_ASSET_COUNT}\" in",
        "--pattern 'corelink-*' --pattern checksums.txt --pattern release-manifest.json",
        "cli_release_manifest.py verify --directory final-assets",
        "STAGING_ASSET_ID=\"$(python3 - \"${RELEASE_API}\"",
        "gh api --method DELETE \"repos/HuGR-Labs/corelink-cli/releases/assets/${STAGING_ASSET_ID}\"",
        "--release-id \"${RELEASE_ID}\" --expected-state draft",
        "release-slsa3:",
        "release-slsa3:\n    needs: [final-manifest, release-readiness, release]\n    if: >-\n      always() &&\n      needs.final-manifest.result == 'success' &&\n      needs.release-readiness.result == 'success' &&\n      needs.release.result == 'success'\n    # Called workflows cannot elevate the caller's token permissions. Grant\n    # OIDC only to this provenance call; all other release jobs retain the\n    # workflow-level contents:read default.\n    permissions:\n      attestations: write\n      contents: read\n      id-token: write\n    uses: ./.github/workflows/release-slsa3.yml\n    with:\n      release_tag: ${{ inputs.release_tag }}\n      source_sha: ${{ needs.release.outputs.source_sha }}\n      manifest_sha256: ${{ needs.final-manifest.outputs.sha256 }}\n      release_mode: ${{ needs.final-manifest.outputs.release_mode }}\n      release_id: ${{ needs.release.outputs.release_id }}",
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

pub(super) fn assert_stable_release_id_contract(workflow: &str, slsa: &str, helper: &str) {
    for required in [
        "release_id: ${{ steps.create-release.outputs.release_id }}",
        "--expected-state draft --allow-absent --create-or-reuse-empty-draft",
        "--notes-file /tmp/release-notes.md --format id",
        "RELEASE_ID: ${{ needs.release.outputs.release_id }}",
        "release_id: ${{ needs.release.outputs.release_id }}",
        "--method PATCH \"repos/HuGR-Labs/corelink-cli/releases/${RELEASE_ID}\"",
        "--expected-state published",
    ] {
        assert!(
            workflow.contains(required),
            "stable release-ID contract missing: {required}"
        );
    }
    assert!(
        !workflow.contains("releases/tags/"),
        "the production caller must not use tag lookups for cross-repository releases"
    );
    for required in [
        "release_id:",
        "RELEASE_ID: ${{ inputs.release_id }}",
        "--release-id \"${RELEASE_ID}\" --expected-state draft",
    ] {
        assert!(
            slsa.contains(required),
            "SLSA stable release-ID contract missing: {required}"
        );
    }
    assert!(
        !slsa.contains("releases/tags/"),
        "the SLSA consumer must not use tag lookups for an unpublished draft"
    );
    for required in [
        "--paginate",
        "--slurp",
        "releases?per_page=100",
        "releases/{release_id}",
        "expected_state == \"draft\"",
        "expected_state == \"published\"",
        "len(matches) != 1",
        "release ID changed during resolution",
        "allow_absent and (release_id is not None or expected_state != \"draft\")",
        "def create_or_reuse_empty_draft(",
        "def gh_json_input(",
        "\"--method\", \"POST\", \"--input\", \"-\"",
        "release collection contains duplicate matching tags",
        "existing draft is non-empty; refusing overwrite or resume",
        "created release title does not match the request",
        "new draft unexpectedly contains assets",
        "if release.get(\"tag_name\") != tag:",
        "if release.get(\"prerelease\") is not False:",
        "if draft is not True or published_at is not None:",
        "release = validate_release(\n        created,\n        repository=repository,\n        tag=tag,\n        expected_state=\"draft\",",
        "if release[\"assets\"]:\n            raise ReleaseApiError(\"existing draft is non-empty; refusing overwrite or resume\")",
    ] {
        assert!(
            helper.contains(required),
            "release API resolver missing fail-closed rule: {required}"
        );
    }
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
        "--create-or-reuse-empty-draft",
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
        "--create-or-reuse-empty-draft",
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
        "--create-or-reuse-empty-draft",
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
    if name == "sign-linux.yml" {
        for required in [
            "Build canonical checksum index from named sidecars",
            "cli_release_draft_manifest.py write-checksums",
            "--directory \"${CHECKSUM_DIRECTORY}\"",
        ] {
            assert!(
                workflow.contains(required),
                "{name} is missing canonical checksum ordering invariant: {required}"
            );
        }
        assert!(
            !workflow.contains("LC_ALL=C sort corelink-*.sha256 > checksums.txt"),
            "Linux signer must not sort checksum rows by digest"
        );
    } else {
        assert!(
            workflow.contains("LC_ALL=C sort corelink-*.sha256 > checksums.txt"),
            "{name} legacy signer checksum refresh must remain present"
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
        "gh release upload \"${TAG}\" --repo HuGR-Labs/corelink-cli \\\n                provenance.intoto.jsonl provenance.intoto.jsonl.bundle",
        "scripts/normalize_cli_attestation_bundle.py",
        "NORMALIZED_BUNDLE=\"${RUNNER_TEMP}/corelink-slsa-bundle-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.json\"",
        "gh attestation verify",
        "--bundle \"${NORMALIZED_BUNDLE}\" --repo \"${REPO}\"",
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
        "--release-id \"${RELEASE_ID}\" --expected-state draft > \"${API_JSON}\"",
        "FINAL_ASSETS=\"${RUNNER_TEMP}/corelink-publish-assets-final\"",
        "gh release download \"${TAG}\" --repo HuGR-Labs/corelink-cli \\",
        "--dir \"${PUBLISHED}\" --clobber",
        "scripts/verify_cli_release_inventory.py",
        "scripts/normalize_cli_attestation_bundle.py",
        "NORMALIZED_BUNDLE=\"${RUNNER_TEMP}/corelink-publish-bundle-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.json\"",
        "gh attestation verify",
        "--bundle \"${NORMALIZED_BUNDLE}\"",
        "--signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/release-slsa3.yml\"",
        "--cert-oidc-issuer \"https://token.actions.githubusercontent.com\"",
        "gh api --method PATCH \"repos/HuGR-Labs/corelink-cli/releases/${RELEASE_ID}\"",
        "--tag \"${TAG}\" --release-id \"${RELEASE_ID}\" --expected-state published",
    ] {
        assert!(
            workflow.contains(required),
            "publication inventory control missing: {required}"
        );
    }
    assert_eq!(
        workflow.matches("gh attestation verify").count(),
        2,
        "signed-public and draft verifier must remain the only release-cli attestation loops"
    );
    assert_eq!(
        workflow
            .matches("--bundle \"${NORMALIZED_BUNDLE}\"")
            .count(),
        2,
        "both release-cli attestation loops must use a normalized private bundle"
    );
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
