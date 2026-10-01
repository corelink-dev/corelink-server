"""Credentialless synthetic tests for the protected GPG audit contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import run_i2587_gpg_audit as audit  # noqa: E402
from scripts import verify_i2587_gpg_audit as contract  # noqa: E402


NOW = 1_800_000_000
FINGERPRINT = audit.EXPECTED_FINGERPRINT
KEY_ID = FINGERPRINT[-16:]
UID = audit.EXPECTED_PRIMARY_UID


def listing(*, fingerprint: str = FINGERPRINT, key_id: str = KEY_ID, uid: str = UID, expiry: int = NOW + 1000, validity: str = "-", uid_validity: str = "u") -> str:
    return "\n".join(
        (
            f"pub:{validity}:4096:1:{key_id}:1780000000:{expiry}::u:::scESC:",
            f"fpr:::::::::{fingerprint}:",
            f"uid:{uid_validity}::::::::{uid}:",
            "sub:-:4096:1:1234567890ABCDEF:1780000000:0:::::s:",
        )
    )


def secret_listing(*, key_id: str = KEY_ID, fingerprint: str = FINGERPRINT, validity: str = "-") -> str:
    return "\n".join(
        (
            f"sec:{validity}:4096:1:{key_id}:1780000000:0::u:::scESC:",
            f"fpr:::::::::{fingerprint}:",
        )
    )


class GpgAuditContractTest(unittest.TestCase):
    def test_primary_uid_export_filter_on_public_fixture_and_legacy_failure(self) -> None:
        fixture = ROOT / "tests/fixtures/i2571-release-pubkey.asc"
        self.assertEqual(fixture.read_bytes(), (ROOT / "docs/internal/gpg-release-pubkey.asc").read_bytes())
        self.assertEqual(audit.PRIMARY_UID_EXPORT_FILTER, "keep-uid=primary -t")
        with tempfile.TemporaryDirectory(prefix="i2571-public-gpg-fixture-") as home:
            env = {**os.environ, "GNUPGHOME": home, "LC_ALL": "C"}
            imported = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--import", str(fixture)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=20,
            )
            self.assertEqual(imported.returncode, 0)
            good = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--export-filter", audit.PRIMARY_UID_EXPORT_FILTER,
                 "--export", FINGERPRINT],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=20,
            )
            self.assertEqual(good.returncode, 0, good.stderr.decode("utf-8", errors="replace"))
            self.assertTrue(good.stdout)
            inspected = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--with-colons", "--fixed-list-mode",
                 "--with-fingerprint", "--show-keys"],
                input=good.stdout, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=20,
            )
            self.assertEqual(inspected.returncode, 0)
            parsed = audit.parse_identity(inspected.stdout.decode("utf-8"), now_epoch=NOW)
            self.assertEqual(parsed["fingerprint"], FINGERPRINT)
            self.assertEqual(parsed["primary_uid"], UID)
            legacy = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--export-filter", "keep-uid=primary",
                 "--export", FINGERPRINT],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=20,
            )
            self.assertNotEqual(legacy.returncode, 0)

    def test_synthetic_expected_identity_is_bound(self) -> None:
        observed = audit.parse_identity(listing(), now_epoch=NOW)
        self.assertEqual(observed["fingerprint"], FINGERPRINT)
        self.assertEqual(observed["key_id"], KEY_ID)
        self.assertEqual(observed["primary_uid"], UID)

    def test_rejects_wrong_fingerprint_and_suffix_only_configuration(self) -> None:
        for fingerprint in ("A" * 40, "0000000000000000" + FINGERPRINT[-16:]):
            with self.subTest(fingerprint=fingerprint):
                with self.assertRaises(audit.AuditError):
                    audit.parse_identity(listing(fingerprint=fingerprint), now_epoch=NOW)
        with self.assertRaises(audit.AuditError):
            audit.normalize_fingerprint(KEY_ID)
        with self.assertRaises(audit.AuditError):
            audit.validate_configured_binding("A" * 40, KEY_ID)
        with self.assertRaises(audit.AuditError):
            audit.validate_configured_binding(FINGERPRINT, "0000000000000000")

    def test_rejects_wrong_key_id_and_primary_uid(self) -> None:
        with self.assertRaises(audit.AuditError):
            audit.parse_identity(listing(key_id="0000000000000000"), now_epoch=NOW)
        with self.assertRaises(audit.AuditError):
            audit.parse_identity(listing(uid="Wrong release identity"), now_epoch=NOW)

    def test_rejects_expired_revoked_or_unusable_identity(self) -> None:
        fixtures = (
            listing(expiry=NOW),
            listing(validity="r"),
            listing(uid_validity="r"),
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture.splitlines()[0]):
                with self.assertRaises(audit.AuditError):
                    audit.parse_identity(fixture, now_epoch=NOW)

    def test_requires_protected_private_key_and_exact_fingerprint(self) -> None:
        with self.assertRaises(audit.AuditError):
            audit.check_secret_listing("sec:-:4096:1:0000000000000000:1780000000:0::u:::scESC:\n")
        with self.assertRaises(audit.AuditError):
            audit.check_secret_listing(secret_listing(fingerprint="A" * 40))
        with self.assertRaises(audit.AuditError):
            audit.check_secret_listing(secret_listing(validity="r"))

    def test_missing_private_key_or_passphrase_fails_before_keyring_creation(self) -> None:
        base = {
            "GITHUB_REPOSITORY": audit.EXPECTED_REPOSITORY,
            "GPG_PRIVATE_KEY": "synthetic-invalid-key-data",
            "GPG_PRIVATE_KEY_PASS": "synthetic-invalid-passphrase",
            "GPG_KEY_ID": KEY_ID,
            "GPG_KEY_FINGERPRINT": FINGERPRINT,
            "RUNNER_TEMP": "/path/that/is/not/used",
        }
        for missing in ("GPG_PRIVATE_KEY", "GPG_PRIVATE_KEY_PASS"):
            env = dict(base)
            env.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(audit.AuditError):
                audit.run_audit(env)

    def test_wrong_passphrase_must_fail_and_cached_or_unprotected_success_is_rejected(self) -> None:
        audit.validate_probe_result(1, passphrase_expected_to_work=False)
        audit.validate_probe_result(0, passphrase_expected_to_work=True)
        with self.assertRaisesRegex(audit.AuditError, "not-required-or-agent-cached"):
            audit.validate_probe_result(0, passphrase_expected_to_work=False)
        with self.assertRaisesRegex(audit.AuditError, "access-failed"):
            audit.validate_probe_result(1, passphrase_expected_to_work=True)

    def test_receipt_contains_only_allowlisted_metadata_and_secret_names(self) -> None:
        env = {
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        result = audit.receipt(audit.parse_identity(listing(), now_epoch=NOW), env)
        serialized = json.dumps(result)
        for marker in ("PRIVATE KEY", "private_key_value", "passphrase-value", "token-value", "gustavomhss"):
            self.assertNotIn(marker, serialized)
        self.assertEqual(result["protected_secret_names"], audit.EXPECTED_SECRET_NAMES)
        self.assertFalse(result["revoked"])
        self.assertIn("/dev/null", result["access_result"])

    def test_structural_verifier_rejects_live_scope_and_receipt_drift(self) -> None:
        workflow = contract.WORKFLOW.read_text(encoding="utf-8")
        runner = contract.RUNNER.read_text(encoding="utf-8")
        ci = contract.CI_WORKFLOW.read_text(encoding="utf-8")
        contract.validate(workflow, runner, ci)
        with self.assertRaises(contract.ContractError):
            contract.validate(workflow.replace("github.ref_protected", "true", 1), runner, ci)
        with self.assertRaises(contract.ContractError):
            contract.validate(workflow, runner.replace('"revoked": False', '"revoked": "unknown"', 1), ci)


if __name__ == "__main__":
    unittest.main()
