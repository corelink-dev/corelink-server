use super::*;

fn replace_nth(text: &str, needle: &str, replacement: &str, occurrence: usize) -> String {
    let index = text
        .match_indices(needle)
        .nth(occurrence)
        .map(|(index, _)| index)
        .expect("requested test mutation occurrence must exist");
    format!(
        "{}{}{}",
        &text[..index],
        replacement,
        &text[index + needle.len()..]
    )
}

#[test]
fn release_workflow_preserves_the_installer_and_signer_contract_and_rejects_mutations(
) -> Result<(), String> {
    let workflow = release_workflow()?;
    assert_release_contract(&workflow);
    assert_windows_build_steps_use_bash(&workflow);
    let linux_signer = load_workflow("sign-linux.yml")?;
    let slsa = load_workflow("release-slsa3.yml")?;
    let installer = load_script("install_pinned_gh.py")?;
    let verifier = load_script("verify_pinned_gh.py")?;
    let smoke = load_script("test_pinned_gh_consumers.py")?;
    let release_api = load_script("cli_release_api.py")?;
    let pack = load_workflow("issue-2572-draft-contract.yml")?;
    let checksum_manifest = load_repo_file("scripts/gh_2.79.0_checksums.json")?;
    assert_pinned_gh_contract(
        &workflow,
        &linux_signer,
        &slsa,
        &installer,
        &checksum_manifest,
        &verifier,
        &smoke,
    );
    assert_pinned_gh_hosted_smoke(&pack);
    assert_draft_only_release_contract(&workflow);
    assert_release_tag_shell_boundary(&workflow);
    assert_publication_inventory_contract(&workflow);
    assert_retry_manifest_contract(&workflow);
    assert_stable_release_id_contract(&workflow, &slsa, &release_api);

    let unnormalized_public_bundle = workflow.replacen(
        "--bundle \"${NORMALIZED_BUNDLE}\"",
        "--bundle \"${FINAL_ASSETS}/provenance.intoto.jsonl.bundle\"",
        1,
    );
    assert_ne!(unnormalized_public_bundle, workflow, "bundle mutation must take effect");
    assert!(
        std::panic::catch_unwind(|| assert_publication_inventory_contract(&unnormalized_public_bundle))
            .is_err(),
        "both real release-cli GH attestation calls must use normalized private bundle paths"
    );

    let missing_release_id = workflow.replace(
        "release_id: ${{ needs.release.outputs.release_id }}",
        "release_id input removed",
    );
    assert_ne!(
        missing_release_id, workflow,
        "release ID mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_stable_release_id_contract(
            &missing_release_id,
            &slsa,
            &release_api
        ))
        .is_err(),
        "the caller must not omit the exact release ID from the SLSA consumer"
    );
    let tag_lookup_regression = workflow.replace(
        "--release-id \"${RELEASE_ID}\" --expected-state draft",
        "releases/tags/${TAG}",
    );
    assert_ne!(
        tag_lookup_regression, workflow,
        "tag-lookup mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_stable_release_id_contract(
            &tag_lookup_regression,
            &slsa,
            &release_api
        ))
        .is_err(),
        "the production caller must reject regressions to draft-incompatible tag lookup"
    );
    let duplicate_acceptance =
        release_api.replace("if len(matches) != 1:", "if len(matches) == 0:");
    assert_ne!(
        duplicate_acceptance, release_api,
        "duplicate-match mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_stable_release_id_contract(
            &workflow,
            &slsa,
            &duplicate_acceptance
        ))
        .is_err(),
        "the resolver must reject zero/multiple ambiguous release matches"
    );
    for (mutated, label) in [
        (
            release_api.replace("if release.get(\"tag_name\") != tag:", "if False:"),
            "create response must bind exact tag",
        ),
        (
            release_api.replace(
                "if draft is not True or published_at is not None:",
                "if False:",
            ),
            "create response must remain unpublished draft",
        ),
        (
            release_api.replace(
                "if release.get(\"prerelease\") is not False:",
                "if False:",
            ),
            "create response must reject prerelease",
        ),
        (
            release_api.replace(
                "if release[\"assets\"]:\n            raise ReleaseApiError(\"existing draft is non-empty; refusing overwrite or resume\")",
                "if False:\n            raise ReleaseApiError(\"existing draft is non-empty; refusing overwrite or resume\")",
            ),
            "existing non-empty draft must not be reused",
        ),
    ] {
        assert_ne!(mutated, release_api, "{label} mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_stable_release_id_contract(
                &workflow, &slsa, &mutated
            ))
            .is_err(),
            "{label} mutation must be rejected"
        );
    }

    let no_credentialless_smoke = pack.replace(
        "python3 -B scripts/test_pinned_gh_consumers.py",
        "echo pinned gh smoke skipped",
    );
    assert_ne!(
        no_credentialless_smoke, pack,
        "smoke removal mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_pinned_gh_hosted_smoke(&no_credentialless_smoke))
            .is_err(),
        "the issue pack must reject removal of the actual-binary six-consumer smoke"
    );

    for (mutant, label) in [
        (
            workflow.replacen("default: draft-only", "default: signed-public", 1),
            "draft-only must remain the default",
        ),
        (
            workflow.replace(
                "always() && inputs.release_mode == 'signed-public' &&",
                "always() && true &&",
            ),
            "draft-only must never reach public publication",
        ),
        (
            workflow.replace(
                "if: inputs.release_mode == 'signed-public'\n    needs: [sign-linux, release]",
                "if: always()\n    needs: [sign-linux, release]",
            ),
            "Windows signer must stay out of draft-only mode",
        ),
    ] {
        assert_ne!(mutant, workflow, "{label} mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_draft_only_release_contract(&mutant)).is_err(),
            "draft-only release contract accepted {label}"
        );
    }

    for (mutant, label) in [
        (
            workflow.replace(
                "- name: Validate matrix target values before shell use\n        shell: bash",
                "- name: Validate matrix target values before shell use\n        shell: pwsh",
            ),
            "matrix validator forced through PowerShell",
        ),
        (
            workflow.replace(
                "- name: Set SOURCE_DATE_EPOCH\n        shell: bash",
                "- name: Set SOURCE_DATE_EPOCH\n        shell: pwsh",
            ),
            "source epoch Bash omitted",
        ),
        (
            workflow.replace(
                "- name: Set RUSTFLAGS path-remap\n        shell: bash",
                "- name: Set RUSTFLAGS path-remap\n        shell: pwsh",
            ),
            "path-remap Bash omitted",
        ),
        (
            workflow.replace(
                "          RUSTFLAGS: ${{ env.RUSTFLAGS }}\n        shell: bash\n        run:",
                "          RUSTFLAGS: ${{ env.RUSTFLAGS }}\n        shell: pwsh\n        run:",
            ),
            "cross-platform build shell changed",
        ),
    ] {
        assert_ne!(mutant, workflow, "{label} mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_windows_build_steps_use_bash(&mutant)).is_err(),
            "build shell contract accepted {label}"
        );
    }

    let install_command = "python3 scripts/install_pinned_gh.py --output \"${GH_BIN}\"";
    let missing_command = "python3 scripts/missing-pinned-gh.py --output \"${GH_BIN}\"";
    for occurrence in 0..4 {
        let no_caller_install =
            replace_nth(&workflow, install_command, missing_command, occurrence);
        assert!(
            std::panic::catch_unwind(|| assert_pinned_gh_contract(
                &no_caller_install,
                &linux_signer,
                &slsa,
                &installer,
                &checksum_manifest,
                &verifier,
                &smoke
            ))
            .is_err(),
            "each GH-using caller job must reject missing pinned gh provisioning"
        );
    }
    let no_linux_install = linux_signer.replace(install_command, missing_command);
    assert!(
        std::panic::catch_unwind(|| assert_pinned_gh_contract(
            &workflow,
            &no_linux_install,
            &slsa,
            &installer,
            &checksum_manifest,
            &verifier,
            &smoke
        ))
        .is_err(),
        "the Linux signing job must reject missing pinned gh provisioning"
    );
    let no_slsa_install = slsa.replace(install_command, missing_command);
    assert!(
        std::panic::catch_unwind(|| assert_pinned_gh_contract(
            &workflow,
            &linux_signer,
            &no_slsa_install,
            &installer,
            &checksum_manifest,
            &verifier,
            &smoke
        ))
        .is_err(),
        "the SLSA job must reject missing pinned gh provisioning"
    );
    let no_slsa_guard = slsa.replace(
        "      - name: Verify pinned GitHub CLI\n        shell: bash\n        run: python3 scripts/verify_pinned_gh.py --binary \"${RUNNER_TEMP}/corelink-pinned-gh/gh\"\n",
        "      - name: SLSA CLI version guard removed\n",
    );
    assert_ne!(
        no_slsa_guard, slsa,
        "SLSA version guard mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_pinned_gh_contract(
            &workflow,
            &linux_signer,
            &no_slsa_guard,
            &installer,
            &checksum_manifest,
            &verifier,
            &smoke
        ))
        .is_err(),
        "the SLSA job must reject a missing pinned gh version guard"
    );

    let bad_digest = checksum_manifest.replace(
        "e7af0c72a607c0528fda1989f7c8e3be85e67d321889002af0e2938ad9c8fb68",
        &"0".repeat(64),
    );
    assert_ne!(
        bad_digest, checksum_manifest,
        "gh checksum mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_pinned_gh_contract(
            &workflow,
            &linux_signer,
            &slsa,
            &installer,
            &bad_digest,
            &verifier,
            &smoke
        ))
        .is_err(),
        "the gh download digest must be frozen"
    );

    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-gnu",
    ] {
        let target_line = format!("          - triple: {target}");
        let missing_target = workflow.replacen(&target_line, "          - triple: removed", 1);
        assert_ne!(missing_target, workflow, "target mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_release_contract(&missing_target)).is_err(),
            "release contract accepted missing required target {target}"
        );
    }

    for apple_target in ["x86_64-apple-darwin", "aarch64-apple-darwin"] {
        let windows_target = "          - triple: x86_64-pc-windows-gnu";
        let reintroduced_apple = workflow.replacen(
            windows_target,
            &format!("          - triple: {apple_target}\n{windows_target}"),
            1,
        );
        assert_ne!(
            reintroduced_apple, workflow,
            "Apple mutation must take effect"
        );
        assert!(
            std::panic::catch_unwind(|| assert_release_contract(&reintroduced_apple)).is_err(),
            "release contract accepted reintroduced Apple target {apple_target}"
        );
    }

    for (mutant, label) in [
        (
            workflow.replace("tool: cargo-zigbuild@0.19.8", "tool: cargo-zigbuild@0.19.7"),
            "cargo-zigbuild pin downgrade",
        ),
        (
            workflow.replace("command -v cargo-zigbuild", "command lookup removed"),
            "cargo-zigbuild PATH check removal",
        ),
        (
            workflow.replace(
                "cargo-zigbuild --help >/dev/null",
                "cargo-zigbuild --version",
            ),
            "unsupported cargo-zigbuild version probe",
        ),
        (
            workflow.replace("run: git config --global core.longpaths true", "run: true"),
            "Windows long paths setup removal",
        ),
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_release_contract(&mutant)).is_err(),
            "release structural contract accepted {label}"
        );
    }

    let unvalidated_release_command = workflow.replace(
        "gh release upload \"${TAG}\"",
        "gh release upload \"${{ inputs.release_tag }}\"",
    );
    assert!(
        std::panic::catch_unwind(|| {
            assert_release_tag_shell_boundary(&unvalidated_release_command)
        })
        .is_err(),
        "a release command bypassing validated output must fail the structural control"
    );

    let stale_home = workflow.replace("HuGR-Labs/corelink-cli", "HumanGuardrail/corelink-cli");
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&stale_home)).is_err(),
        "the stale 404 release home must fail the structural control"
    );
    let no_readback = workflow.replace(
        "Read back published artifacts and verify release-root digests",
        "readback removed",
    );
    let public_before_signing = workflow.replace(
        "--expected-state draft --allow-absent --create-or-reuse-empty-draft",
        "--expected-state draft --allow-absent",
    );
    assert_ne!(
        public_before_signing, workflow,
        "draft creation mutation must take effect"
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&public_before_signing)).is_err(),
        "a release must remain draft until the chained signing/SLSA gates succeed"
    );
    let no_final_slsa = workflow.replace("release-slsa3:", "slsa removed:");
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&no_final_slsa)).is_err(),
        "SLSA must remain a terminal chained stage before publication"
    );
    let slsa_without_release = workflow.replace(
        "needs: [final-manifest, release-readiness, release]",
        "needs: [final-manifest, release-readiness]",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&slsa_without_release)).is_err(),
        "provenance must directly depend on the staged release"
    );
    for mutation in [
        workflow.replace(
            "      always() &&\n      needs.final-manifest.result",
            "      needs.final-manifest.result",
        ),
        workflow.replace(
            "needs.final-manifest.result == 'success'",
            "needs.final-manifest.result != 'success'",
        ),
        workflow.replace(
            "needs.release-readiness.result == 'success'",
            "needs.release-readiness.result != 'success'",
        ),
        workflow.replace(
            "needs.release.result == 'success'",
            "needs.release.result != 'success'",
        ),
    ] {
        assert_ne!(mutation, workflow, "SLSA gate mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_release_contract(&mutation)).is_err(),
            "draft-only skipped Windows ancestry must not bypass the exact successful SLSA prerequisites"
        );
    }
    let publish_without_release = workflow.replace(
        "needs: [release-slsa3, release-readiness, final-manifest, release, sign-windows]",
        "needs: [release-slsa3, release-readiness, final-manifest]",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&publish_without_release)).is_err(),
        "publication must directly depend on the staged release"
    );
    let missing_caller_oidc = workflow.replace(
        "      id-token: write\n    uses: ./.github/workflows/release-slsa3.yml",
        "      OIDC permission removed\n    uses: ./.github/workflows/release-slsa3.yml",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&missing_caller_oidc)).is_err(),
        "the reusable SLSA caller must explicitly grant its OIDC permission"
    );
    let orphan_staging_asset = workflow.replace(
        "gh api --method DELETE \"repos/HuGR-Labs/corelink-cli/releases/assets/${STAGING_ASSET_ID}\"",
        "staging asset cleanup removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&orphan_staging_asset)).is_err(),
        "a staging manifest left on the public release must fail the structural control"
    );
    let late_reintroduced = workflow.replace(
        "Verify complete authenticated inventory before publication",
        "publication inventory check removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&late_reintroduced)).is_err(),
        "late staging reintroduction and unmatched assets must be rejected immediately before publication"
    );
    let api_failure_ignored = workflow.replace(
        "--tag \"${TAG}\" --release-id \"${RELEASE_ID}\" --expected-state draft > \"${API_JSON}\"",
        "python3 scripts/cli_release_api.py --release-id \"${RELEASE_ID}\" || true",
    );
    assert!(
        std::panic::catch_unwind(|| assert_publication_inventory_contract(&api_failure_ignored))
            .is_err(),
        "an authenticated release API failure must not be ignored"
    );
    let wrong_publication_identity = workflow.replace(
        "--signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/release-slsa3.yml\"",
        "--signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/release-cli.yml\"",
    );
    assert!(
        std::panic::catch_unwind(|| assert_publication_inventory_contract(
            &wrong_publication_identity
        ))
        .is_err(),
        "the final publication verifier must require the exact signer workflow identity"
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&no_readback)).is_err(),
        "removing published-artifact digest verification must fail the control"
    );
    let retry_without_reverification = workflow.replacen(
        "cli_release_manifest.py verify --directory final-assets",
        "retry inventory verification removed",
        1,
    );
    assert!(
        std::panic::catch_unwind(|| assert_retry_manifest_contract(&retry_without_reverification))
            .is_err(),
        "the existing-manifest retry must re-verify the downloaded inventory"
    );

    for name in ["sign-linux.yml", "sign-windows.yml", "notarize-macos.yml"] {
        let signer = load_workflow(name)?;
        assert_downstream_signer_contract(name, &signer);
        assert_checksum_refresh_contract(name, &signer);
    }

    let windows = load_workflow("sign-windows.yml")?;
    assert!(
        workflow.contains("sign-windows:\n    if: inputs.release_mode == 'signed-public'\n    needs: [sign-linux, release]"),
        "Windows signing must wait for Linux through a release-root needs edge"
    );
    assert!(
        !windows.contains("workflow_dispatch:"),
        "privileged signer dispatch must remain disabled"
    );
    let slsa = load_workflow("release-slsa3.yml")?;
    for required in [
        "CORELINK_CLI_RELEASE_TOKEN",
        "HuGR-Labs/corelink-cli",
        "gh release upload \"${TAG}\" --repo HuGR-Labs/corelink-cli",
    ] {
        assert!(
            slsa.contains(required),
            "release-slsa3 missing release-root invariant: {required}"
        );
    }
    assert_slsa_contract(&slsa);
    for forbidden in [
        "printf '%s\\n' \"${{ needs.build-artifacts.outputs.subject-list }}\"",
        "\"release\":\"${{ github.event.release.tag_name || inputs.release_tag }}\"",
    ] {
        assert!(
            !slsa.contains(forbidden),
            "release-slsa3 must not shell-expand dynamic release data: {forbidden}"
        );
    }

    let stale_signer_home = load_workflow("sign-windows.yml")?.replace(
        "RELEASE_REPOSITORY: HuGR-Labs/corelink-cli",
        "RELEASE_REPOSITORY: HumanGuardrail/corelink-cli",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "sign-windows.yml",
            &stale_signer_home
        ))
        .is_err(),
        "a signer targeting the stale release home must fail the structural control"
    );
    let unrefreshed_checksum = load_workflow("notarize-macos.yml")?.replace(
        "LC_ALL=C sort corelink-*.sha256 > checksums.txt",
        "checksum refresh removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_checksum_refresh_contract(
            "notarize-macos.yml",
            &unrefreshed_checksum
        ))
        .is_err(),
        "a signed archive without aggregate checksum refresh must fail the structural control"
    );
    let nested_windows_archive = workflow.replace(
        "ZipInfo(\"corelink.exe\", (1980, 1, 1, 0, 0, 0))",
        "ZipInfo(\"nested/corelink.exe\", (1980, 1, 1, 0, 0, 0))",
    );
    assert!(
        std::panic::catch_unwind(|| assert_release_contract(&nested_windows_archive)).is_err(),
        "a nested ditto Windows archive must fail the structural control"
    );
    for (mutant, label) in [
        (
            workflow.replace(
                "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
                "uses: actions/setup-python@v7",
            ),
            "unpinned Windows packaging Python setup",
        ),
        (
            workflow.replace("python-version: \"3.12\"", "python-version: \"3.13\""),
            "changed Windows packaging Python version",
        ),
        (
            workflow.replace("python -c $pythonCode", "python --version"),
            "missing deterministic Windows packaging invocation",
        ),
        (
            workflow.replace(
                "Set-Content -LiteralPath $sidecar -Value \"$actual  $([IO.Path]::GetFileName($file))\" -NoNewline -Encoding ascii",
                "sidecar write removed",
            ),
            "missing Windows packaging checksum sidecar write",
        ),
        (
            workflow.replace(
                "$expected = (Get-Content -LiteralPath $sidecar).Split(' ')[0]",
                "$expected = '0'",
            ),
            "missing Windows packaging checksum sidecar read",
        ),
        (
            workflow.replace(
                "if ($actual -ne $expected) { throw \"SHA-256 sidecar mismatch: $file\" }",
                "sidecar verification removed",
            ),
            "missing Windows packaging checksum sidecar verification",
        ),
    ] {
        assert_ne!(mutant, workflow, "{label} mutation must take effect");
        assert!(
            std::panic::catch_unwind(|| assert_release_contract(&mutant)).is_err(),
            "release contract accepted {label}"
        );
    }
    let workflow_run_signer = load_workflow("notarize-macos.yml")?.replace(
        "workflow_call:",
        "workflow_run:\n    workflows: [\"sign-windows\"]",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "notarize-macos.yml",
            &workflow_run_signer
        ))
        .is_err(),
        "a downstream signer must not regress from a reusable workflow to workflow_run"
    );

    let public_unsigned_windows = load_workflow("sign-windows.yml")?.replace(
        "Copy-Item ./assets/extracted/corelink.exe ./assets/corelink-windows-x86_64.exe -Force",
        "raw Windows asset copy removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "sign-windows.yml",
            &public_unsigned_windows
        ))
        .is_err(),
        "a public raw Windows executable must be replaced by signed bytes"
    );
    let bypassed_gatekeeper = load_workflow("notarize-macos.yml")?.replace(
        "spctl --assess --type execute --verbose=4 \"${BINARY}\"",
        "spctl --assess --type execute --verbose=4 \"${BINARY}\" || true",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "notarize-macos.yml",
            &bypassed_gatekeeper
        ))
        .is_err(),
        "Gatekeeper assessment must not be bypassed"
    );
    let unsigned_linux_raw = load_workflow("sign-linux.yml")?.replace(
        "for target in \"${ASSET}\" \"${RAW_ASSET}\"; do",
        "for target in \"${ASSET}\"; do",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "sign-linux.yml",
            &unsigned_linux_raw
        ))
        .is_err(),
        "a public raw Linux executable must retain its detached-signature gate"
    );
    let argv_notary_password = load_workflow("notarize-macos.yml")?.replace(
        "xcrun notarytool submit ./submission.zip \\",
        "xcrun notarytool submit ./submission.zip --password \"${APPLE_NOTARIZATION_PASSWORD}\" \\",
    );
    assert!(
        std::panic::catch_unwind(|| assert_downstream_signer_contract(
            "notarize-macos.yml",
            &argv_notary_password
        ))
        .is_err(),
        "notary credentials must never regress onto argv"
    );
    let unbound_slsa_oidc = slsa.replace(
        "test \"${GITHUB_REF}\" = \"refs/tags/${TAG}\"",
        "tag-bound OIDC check removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&unbound_slsa_oidc)).is_err(),
        "SLSA OIDC must remain bound to the exact tag"
    );
    let unchecked_inventory = slsa.replace(
        "--pattern checksums.txt",
        "inventory checksum fetch removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&unchecked_inventory)).is_err(),
        "SLSA must attest the exact manifest inventory, including checksums"
    );
    let writable_slsa_source =
        slsa.replace("contents: read", "contents: write # privilege regression");
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&writable_slsa_source)).is_err(),
        "SLSA provenance must not regain source-repository contents write"
    );
    let unpinned_slsa_action = slsa.replace(
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "actions/attest-build-provenance@v4",
    );
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&unpinned_slsa_action)).is_err(),
        "the GitHub provenance action must remain SHA-pinned"
    );
    let unbound_signer = slsa.replace(
        "--signer-workflow \"${REPO}/.github/workflows/release-slsa3.yml\"",
        "--signer-workflow \"${REPO}/.github/workflows/release-cli.yml\"",
    );
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&unbound_signer)).is_err(),
        "the GitHub attestation signer identity must remain exact"
    );
    let unnormalized_slsa_bundle = slsa.replace(
        "--bundle \"${NORMALIZED_BUNDLE}\" --repo \"${REPO}\"",
        "--bundle provenance.intoto.jsonl.bundle --repo \"${REPO}\"",
    );
    assert_ne!(unnormalized_slsa_bundle, slsa, "bundle mutation must take effect");
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&unnormalized_slsa_bundle)).is_err(),
        "SLSA GH attestation must use the normalized local bundle path"
    );
    let reintroduced_staging_manifest = slsa.replace(
        "test \"${STAGING_ASSET_COUNT}\" = \"0\"",
        "staging inventory check removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_slsa_contract(&reintroduced_staging_manifest)).is_err(),
        "the provenance generator must reject a staging manifest in its exact inventory"
    );
    let inventory_helper = load_script("verify_cli_release_inventory.py")?;
    assert_inventory_helper_contract(&inventory_helper);
    let unmatched_asset = inventory_helper.replace(
        "release inventory is not closed-world",
        "inventory check removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_inventory_helper_contract(&unmatched_asset)).is_err(),
        "an unmatched public release asset must fail the closed-world helper contract"
    );
    let orphaned_staging =
        inventory_helper.replace("if \"staging-manifest.json\" in api_names:", "if False:");
    assert!(
        std::panic::catch_unwind(|| assert_inventory_helper_contract(&orphaned_staging)).is_err(),
        "a late staging-manifest reintroduction must fail the helper contract"
    );
    let checksum_bypass = inventory_helper.replace(
        "verify_checksums(directory, artifacts)",
        "checksum verification removed",
    );
    assert!(
        std::panic::catch_unwind(|| assert_inventory_helper_contract(&checksum_bypass)).is_err(),
        "the closed-world checksum contents check must remain wired into publication"
    );
    Ok(())
}
