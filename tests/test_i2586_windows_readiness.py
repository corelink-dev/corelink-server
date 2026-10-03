"""Adversarial tests for the issue-2586 credentialless Windows probe contract."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_i2586_windows_readiness import (
    ALLOWED_PATHS,
    ACTIONLINT_CONFIG,
    CI_WORKFLOW,
    PROBE_WORKFLOW,
    RECEIPT_FIELDS,
    SCRIPT,
    SIGN_WORKFLOW,
    validate_texts,
)


class WindowsReadinessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.probe = PROBE_WORKFLOW.read_text(encoding="utf-8")
        cls.ci = CI_WORKFLOW.read_text(encoding="utf-8")
        cls.signer = SIGN_WORKFLOW.read_text(encoding="utf-8")
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.actionlint_config = ACTIONLINT_CONFIG.read_text(encoding="utf-8")

    def assert_rejected(self, *, probe=None, ci=None, signer=None, script=None, actionlint_config=None) -> None:
        errors = validate_texts(
            self.probe if probe is None else probe,
            self.ci if ci is None else ci,
            self.signer if signer is None else signer,
            self.script if script is None else script,
            self.actionlint_config if actionlint_config is None else actionlint_config,
        )
        self.assertTrue(errors)

    def test_current_workflows_and_script_satisfy_the_contract(self) -> None:
        self.assertEqual(validate_texts(self.probe, self.ci, self.signer, self.script, self.actionlint_config), [])

    def test_probe_rejects_push_trigger(self) -> None:
        self.assert_rejected(probe=self.probe.replace("  workflow_dispatch:\n", "  push:\n    branches: [main]\n  workflow_dispatch:\n", 1))

    def test_probe_rejects_wrong_runner_or_unprotected_environment(self) -> None:
        self.assert_rejected(probe=self.probe.replace("runs-on: windows-2022", "runs-on: ubuntu-latest", 1))
        self.assert_rejected(probe=self.probe.replace("environment: production", "environment: staging", 1))

    def test_probe_rejects_secret_name_drift_or_extra_secret(self) -> None:
        self.assert_rejected(probe=self.probe.replace("secrets.WINDOWS_CODE_SIGNING_CERT", "secrets.WINDOWS_CODE_SIGNING_SUBJECT", 1))
        self.assert_rejected(probe=self.probe.replace("secrets.WINDOWS_CODE_SIGNING_SUBJECT", "secrets.WINDOWS_CODE_SIGNING_SUBJECT\n          EXTRA: ${{ secrets.EXTRA }}", 1))

    def test_probe_rejects_public_metadata_variable_drift_or_fallback(self) -> None:
        self.assert_rejected(probe=self.probe.replace("vars.WINDOWS_CODE_SIGNING_ISSUER", "vars.WINDOWS_CODE_SIGNING_SUBJECT", 1))
        self.assert_rejected(probe=self.probe.replace("vars.WINDOWS_SIGNING_RENEWAL_DATE", "vars.WINDOWS_SIGNING_RENEWAL_DATE || vars.OLD_DATE", 1))
        self.assert_rejected(probe=self.probe.replace("REPOSITORY: ${{ github.repository }}", "EXTRA: ${{ vars.EXTRA }}\n          REPOSITORY: ${{ github.repository }}", 1))
        self.assert_rejected(probe=self.probe.replace("WINDOWS_CODE_SIGNING_ISSUER: ${{ vars.WINDOWS_CODE_SIGNING_ISSUER }}", "# WINDOWS_CODE_SIGNING_ISSUER: ${{ vars.WINDOWS_CODE_SIGNING_ISSUER }}", 1))

    def test_probe_rejects_job_level_write_permissions(self) -> None:
        self.assert_rejected(probe=self.probe.replace("      contents: read\n    steps:", "      contents: read\n      actions: write\n    steps:", 1))

    def test_signer_secret_contract_rejects_reordering_duplicates_comments_and_fallbacks(self) -> None:
        reordered = self.signer.replace("WINDOWS_CODE_SIGNING_FINGERPRINT", "__TEMP_FINGERPRINT__", 1)
        reordered = reordered.replace("WINDOWS_CODE_SIGNING_SUBJECT", "WINDOWS_CODE_SIGNING_FINGERPRINT", 1)
        reordered = reordered.replace("__TEMP_FINGERPRINT__", "WINDOWS_CODE_SIGNING_SUBJECT", 1)
        self.assert_rejected(signer=reordered)
        duplicate = self.signer.replace("WINDOWS_CODE_SIGNING_SUBJECT", "WINDOWS_CODE_SIGNING_FINGERPRINT", 1)
        self.assert_rejected(signer=duplicate)
        commented = self.signer.replace("      WINDOWS_CODE_SIGNING_PASSWORD:", "      # WINDOWS_CODE_SIGNING_PASSWORD:", 1)
        self.assert_rejected(signer=commented)
        fallback = self.probe.replace("WINDOWS_CODE_SIGNING_PASSWORD: ${{ secrets.WINDOWS_CODE_SIGNING_PASSWORD }}", "WINDOWS_CODE_SIGNING_PASSWORD: ${{ secrets.WINDOWS_CODE_SIGNING_PASSWORD || secrets.FALLBACK }}")
        self.assert_rejected(probe=fallback)

    def test_certificate_fail_closed_contract_covers_public_allowlist_and_cleanup(self) -> None:
        for required in (
            "Issuer", "Subject", "Fingerprint", "NotBefore", "ExpiresAt",
            "HasPrivateKey", "ChainRevocationPassed", "ExpectedOperation",
            "RenewalOwner", "RenewalDate", "finally", "Array]::Clear",
            "EphemeralKeySet", "GetRSAPrivateKey", "RevocationMode",
            "RevocationFlag", "expectedRunUrl", "timestamp_policy", "artifact_signature",
            "final_byte_verification",
        ):
            self.assertIn(required, self.script)
        self.assertEqual(len(RECEIPT_FIELDS), 17)
        self.assertEqual(
            ALLOWED_PATHS,
            {
                ".actionlint.yaml",
                ".github/workflows/issue-2586-windows-readiness.yml",
                ".github/workflows/issue-2586-windows-contract.yml",
                "scripts/windows_signing_readiness.ps1",
                "scripts/verify_i2586_windows_readiness.py",
                "tests/test_i2586_windows_readiness.py",
            },
        )
        self.assertNotIn("github.actor", self.probe)
        self.assertNotIn("upload-artifact", self.probe)

    def test_receipt_and_operation_drift_fail(self) -> None:
        self.assert_rejected(script=self.script.replace("final_byte_verification", "byte_verification", 1))
        self.assert_rejected(probe=self.probe.replace("authenticode-credential-binding-metadata-only", "sign-and-publish", 1))
        self.assert_rejected(signer=self.signer.replace("http://timestamp.digicert.com", "http://unapproved.invalid", 1))
        self.assert_rejected(script=self.script.replace("'issuer_match', 'subject_match'", "'issuer_match', 'subject', 'subject_match'", 1))

    def test_exact_head_pack_binds_protected_main_and_executable_commands(self) -> None:
        self.assert_rejected(ci=self.ci.replace('EXPECTED_BASE="$(git merge-base "$TRUSTED_MAIN_SHA" "$EXPECTED_SHA")"', 'EXPECTED_BASE="$(git merge-base "$TARGET_BASE_SHA" "$EXPECTED_SHA")"', 1))
        self.assert_rejected(ci=self.ci.replace('            [[ "$REQUESTED_BASE_SHA" == "$EXPECTED_BASE" ]]', '            # [[ "$REQUESTED_BASE_SHA" == "$EXPECTED_BASE" ]]', 1))
        self.assert_rejected(ci=self.ci.replace("      contents: read\n    steps:", "      contents: read\n      actions: write\n    steps:", 1))
        self.assert_rejected(ci=self.ci.replace("          ref: refs/heads/main", "          # ref: refs/heads/main", 1))
        self.assert_rejected(ci=self.ci.replace("            tests/test_i2586_windows_readiness.py | sort)", "            # tests/test_i2586_windows_readiness.py | sort)", 1))

    def test_contract_pr_trigger_and_actionlint_vars_are_exact(self) -> None:
        self.assert_rejected(ci=self.ci.replace("      - .actionlint.yaml\n", "", 1))
        self.assert_rejected(ci=self.ci.replace('github.event.pull_request.head.repo.full_name == github.repository', "", 1))
        self.assert_rejected(ci=self.ci.replace('            [[ "$PR_HEAD_REF" == codex/issue-2586-no-sign-readiness-20260925 ]]', '            # [[ "$PR_HEAD_REF" == codex/issue-2586-no-sign-readiness-20260925 ]]', 1))
        self.assert_rejected(actionlint_config=self.actionlint_config.replace("  - WINDOWS_CODE_SIGNING_ISSUER\n", "  # - WINDOWS_CODE_SIGNING_ISSUER\n", 1))

    def test_credentialless_pack_keeps_the_repository_id_guard_and_no_other_variable(self) -> None:
        guard = "github.repository_id == vars.CORELINK_SERVER_REPO_ID"
        self.assertEqual(self.ci.count(guard), 2)
        self.assert_rejected(ci=self.ci.replace(guard, "github.repository_id != ''", 1))
        self.assert_rejected(ci=self.ci.replace(guard, f"{guard} && vars.EXTRA == 'x'", 1))

    def test_windows_powershell_job_checkout_stays_sparse(self) -> None:
        self.assert_rejected(ci=self.ci.replace("          sparse-checkout: scripts/windows_signing_readiness.ps1\n", "", 1))
        self.assert_rejected(ci=self.ci.replace("          sparse-checkout-cone-mode: false\n", "          sparse-checkout-cone-mode: true\n", 1))
        self.assert_rejected(ci=self.ci.replace(
            "          sparse-checkout: scripts/windows_signing_readiness.ps1\n",
            "          sparse-checkout: |\n            scripts/windows_signing_readiness.ps1\n            docs/**\n",
            1,
        ))
        self.assert_rejected(ci=self.ci.replace(
            "          sparse-checkout: scripts/windows_signing_readiness.ps1\n",
            "          sparse-checkout: scripts/**\n",
            1,
        ))

    def test_receipt_schema_rejects_nested_fields_that_could_disclose_names(self) -> None:
        self.assert_rejected(script=self.script.replace("'issuer_match', 'subject_match', 'sha256_fingerprint'", "'issuer_match', 'subject_match', 'subject', 'sha256_fingerprint'", 1))
        self.assertIn("$entry.Value.PSObject.Properties.Name", self.script)

    def test_signing_timestamp_publication_and_export_surfaces_fail(self) -> None:
        self.assert_rejected(script=self.script + "\n& signtool sign app.exe\n")
        self.assert_rejected(script=self.script + "\n& signtool timestamp app.exe\n")
        self.assert_rejected(script=self.script + "\nInvoke-WebRequest https://example.invalid/release\n")
        self.assert_rejected(script=self.script + "\nExport-PfxCertificate -Cert $certificate -FilePath out.pfx\n")

    def test_cleanup_bypass_fails(self) -> None:
        self.assert_rejected(script=self.script.replace("[Array]::Clear($pfxBytes, 0, $pfxBytes.Length)", "# cleanup bypass", 1))


if __name__ == "__main__":
    unittest.main()
