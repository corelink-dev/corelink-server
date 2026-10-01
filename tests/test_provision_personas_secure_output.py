import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/e2e-real-client/provision-personas.py"
SPEC = importlib.util.spec_from_file_location("provision_personas", SCRIPT)
provision_personas = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(os.environ, {
    "CORELINK_INTERNAL_AUTH_KEY": "test-only-placeholder",
    "CLOUDFLARE_API_TOKEN": "test-only-placeholder",
}):
    SPEC.loader.exec_module(provision_personas)


class ProvisionPersonaOutputTests(unittest.TestCase):
    def test_main_writes_private_file_under_permissive_umask_and_masks_all_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personas.env"
            values = {
                "CORELINK_E2E_PAT_ADMIN": "pat-secret-value",
                "CORELINK_E2E_INTROSPECT_KEY": "introspect-secret-value",
                "CORELINK_E2E_TEAM_INVITE_EMAIL": "private-person@example.invalid",
            }
            output = io.StringIO()
            previous_umask = os.umask(0)
            try:
                with mock.patch.object(provision_personas, "provision", return_value=values), \
                     mock.patch.object(provision_personas.sys, "argv", [str(SCRIPT), str(target)]), \
                     contextlib.redirect_stdout(output):
                    provision_personas.main()
            finally:
                os.umask(previous_umask)

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            file_content = target.read_text(encoding="utf-8")
            self.assertIn("export CORELINK_E2E_PAT_ADMIN='pat-secret-value'", file_content)
            for secret in values.values():
                self.assertNotIn(secret, output.getvalue())
            self.assertIn("CORELINK_E2E_PAT_ADMIN=<set>", output.getvalue())

    def test_existing_regular_file_is_tightened_before_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personas.env"
            target.write_text("old-value\n", encoding="utf-8")
            target.chmod(0o644)
            old_inode = target.stat().st_ino

            provision_personas.write_secret_env(target, {"CORELINK_E2E_PAT_ADMIN": "new-secret"})

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertNotEqual(target.stat().st_ino, old_inode)
            self.assertIn("new-secret", target.read_text(encoding="utf-8"))

    def test_existing_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.txt"
            outside.write_text("untouched\n", encoding="utf-8")
            target = Path(tmp) / "personas.env"
            target.symlink_to(outside)

            with self.assertRaises((SystemExit, OSError)):
                provision_personas.write_secret_env(target, {"CORELINK_E2E_PAT_ADMIN": "secret"})

            self.assertTrue(target.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "untouched\n")

    def test_existing_non_regular_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personas.env"
            target.mkdir()

            with self.assertRaises(SystemExit):
                provision_personas.write_secret_env(target, {"CORELINK_E2E_PAT_ADMIN": "secret"})

            self.assertTrue(target.is_dir())

    def test_shell_metacharacters_round_trip_as_literal_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personas.env"
            marker = Path(tmp) / "command-ran"
            value = f"space and newline\nquote ' \"; $(touch {marker}) `touch {marker}` ; $HOME"

            provision_personas.write_secret_env(target, {"CORELINK_E2E_TEST_VALUE": value})
            sourced = subprocess.run(
                ["/bin/sh", "-c", '. "$1"; printf "%s" "$CORELINK_E2E_TEST_VALUE"', "sh", str(target)],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(sourced.stdout, value)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
