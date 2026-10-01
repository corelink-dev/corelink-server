//! Structural regression tests for the public CLI release root.
//!
//! These tests deliberately inspect the workflow text.  The critical contract
//! spans GitHub Actions, the installer, and three independent signing lanes;
//! a Rust-only unit test cannot observe it.  Keep the mutation controls here so
//! a superficially valid workflow cannot silently repoint, skip tool validation,
//! or stop publishing the files downstream signers request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed to use these primitives"
)]

#[path = "release_workflow_contract/assertions.rs"]
#[expect(
    dead_code,
    reason = "assert_rekor_helper_contract has had no caller since #1838 retired the Rekor \
              lane; it can only be deleted inside assertions.rs, which the issue-2572 gate \
              keeps closed-world. Once it is gone this `expect` is unfulfilled and fails \
              `-D warnings`."
)]
mod assertions;
#[path = "release_workflow_contract/cases.rs"]
mod cases;

use assertions::*;

fn assert_managed_cli_provenance_contract(caller: &str, generator: &str) {
    assert!(
        generator.contains("actions/attest-build-provenance@"),
        "CLI provenance must use GitHub's managed provenance action"
    );
    assert!(
        generator.lines().any(|line| {
            line.split_whitespace().any(|token| {
                token.starts_with("actions/attest-build-provenance@")
                    && token.rsplit_once('@').is_some_and(|(_, sha)| {
                        sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
        }),
        "GitHub's provenance action must be pinned to a full commit SHA"
    );
    for required in [
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "provenance.intoto.jsonl",
        "provenance.intoto.jsonl.bundle",
        "--cert-oidc-issuer \"https://token.actions.githubusercontent.com\"",
        "--signer-workflow \"${REPO}/.github/workflows/release-slsa3.yml\"",
        "--source-ref",
        "--source-digest",
        "subject-checksums: provenance-subjects.sha256",
        "subject-list",
        "release-manifest.json",
    ] {
        assert!(
            generator.contains(required),
            "CLI provenance contract missing {required}"
        );
    }
    assert!(
        caller.contains("provenance.intoto.jsonl")
            && caller.contains("provenance.intoto.jsonl.bundle"),
        "release caller must publish both standard SLSA provenance assets"
    );
    assert!(
        caller.contains("scripts/verify_cli_release_inventory.py")
            && caller.contains("--provenance"),
        "release publication must verify provenance subjects against the exact uploaded inventory"
    );
}

fn assert_issue_1724_ci_pack(workflow: &str) {
    for required in [
        "# This is the explicit #1724 pack.",
        "workflow_dispatch:",
        "candidate_sha:",
        "base_sha:",
        "Full 40-character commit SHA to prove",
        "github.repository_id == '1232040291'",
        "ref: ${{ inputs.candidate_sha }}",
        "fetch-depth: 4",
        "BASE_SHA: ${{ inputs.base_sha }}",
        "persist-credentials: false",
        "Bind the pack to the requested immutable candidate",
        "candidate_sha must be a lowercase 40-character SHA",
        "[[ \"${CANDIDATE_SHA}\" =~ ^[0-9a-f]{40}$ ]]",
        "test \"$(git rev-parse HEAD)\" = \"${CANDIDATE_SHA}\"",
        "base_sha must be a lowercase 40-character SHA",
        "git cat-file -e \"${BASE_SHA}^{commit}\"",
        "git merge-base --is-ancestor \"${BASE_SHA}\" HEAD",
        "cargo test --locked -p corelink-cli --test release_workflow_contract -- --nocapture",
        "actionlint_1.7.12_linux_amd64.tar.gz",
        "Install Python contract dependencies",
        "python3 -m pip install --requirement requirements-ci.txt",
        "Verify B-112 release build and signing gates",
        "python3 scripts/verify_b112_release_root_cause.py --root .",
        "Verify issue-2050 CLI release dry-run contract",
        "python3 scripts/verify_i2050_release_dryrun_contract.py contract --base-sha \"${CORELINK_BASE_SHA}\"",
        "Validate the CLI release workflow schemas",
        ".github/workflows/issue-1724-cli-provenance.yml",
        ".github/workflows/issue-2050-cli-release-dry-run.yml",
        ".github/workflows/release-cli.yml",
        "timeout-minutes: 15",
        "runs-on: ubuntu-24.04",
    ] {
        assert!(
            workflow.contains(required),
            "#1724 CI pack missing {required}"
        );
    }
    for forbidden in ["\n  pull_request:", "gh release ", "cosign ", "secrets."] {
        assert!(
            !workflow.contains(forbidden),
            "#1724 CI pack must remain structural and non-publishing: {forbidden}"
        );
    }
    assert!(
        !workflow.contains("python3 -S scripts/verify_b112_release_root_cause.py")
            && !workflow.contains("python3 -S scripts/verify_i2050_release_dryrun_contract.py"),
        "PyYAML dependent release verifiers must run with normal site packages enabled"
    );
}

#[test]
fn cli_provenance_uses_managed_generator_and_exact_release_identity() -> Result<(), String> {
    let caller = release_workflow()?;
    let generator = load_workflow("release-slsa3.yml")?;
    assert_managed_cli_provenance_contract(&caller, &generator);

    let ci_pack = load_workflow("issue-1724-cli-provenance.yml")?;
    assert_issue_1724_ci_pack(&ci_pack);

    for (mutant, label) in [
        (
            generator.replace(
                "actions/attest-build-provenance@",
                "actions/attest-build-provenance@v4",
            ),
            "unpinned generator",
        ),
        (
            generator.replace(
                "--signer-workflow \"${REPO}/.github/workflows/release-slsa3.yml\"",
                "--signer-workflow \"${REPO}/.github/workflows/release-cli.yml\"",
            ),
            "wrong signer workflow identity",
        ),
        (
            generator.replace(
                "subject-checksums: provenance-subjects.sha256",
                "subject-checksums: wrong-subjects.sha256",
            ),
            "tampered subject",
        ),
        (
            generator.replace("actions/attest-build-provenance@", "local-generator@"),
            "unmanaged builder",
        ),
        (
            generator.replace(
                "https://token.actions.githubusercontent.com",
                "https://wrong-issuer.example",
            ),
            "wrong Fulcio issuer",
        ),
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_managed_cli_provenance_contract(&caller, &mutant))
                .is_err(),
            "mutation control accepted {label}"
        );
    }
    let automatic_pack = ci_pack.replacen("  workflow_dispatch:\n", "  pull_request:\n", 1);
    assert!(
        std::panic::catch_unwind(|| assert_issue_1724_ci_pack(&automatic_pack)).is_err(),
        "#1724 CI pack must reject an automatic PR trigger"
    );
    Ok(())
}
