from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_issue_2699_cloudflare_handoff import (
    verify_negative_controls,
    verify_workflow,
)


WORKFLOW = ROOT / ".github/workflows/cloudflare-scoped-token-handoff.yml"
WORKFLOW_SOURCE = WORKFLOW.read_text(encoding="utf-8")


def encryptor_source() -> str:
    marker = "cat > \"$RUNNER_TEMP/cf-handoff/encrypt.js\" <<'JS'\n"
    start = WORKFLOW_SOURCE.index(marker) + len(marker)
    end = WORKFLOW_SOURCE.index("\n          JS", start)
    return WORKFLOW_SOURCE[start:end]


class CloudflareHandoffContract(unittest.TestCase):
    def test_static_gates_and_mutation_controls(self) -> None:
        verify_workflow(WORKFLOW_SOURCE)
        verify_negative_controls(WORKFLOW_SOURCE)

    def test_empty_input_is_rejected_without_creating_an_envelope(self) -> None:
        self._run_encryptor(b"", expect_success=False)

    def test_valid_payload_is_bound_to_mode_and_exact_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encryptor, public, output, _ = self._fixtures(root)
            completed = subprocess.run(
                ["node", str(encryptor), str(public), str(output), "r2-2564-mint", "a" * 40, "12345"],
                input=self._payload(),
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
            validate = subprocess.run(
                ["node", str(encryptor), "--validate", str(output), str(public), "r2-2564-mint", "a" * 40, "12345"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stderr.decode(errors="replace"))
            envelope = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(envelope["mode"], "r2-2564-mint")
            self.assertEqual(envelope["github_sha"], "a" * 40)
            self.assertTrue(envelope["ciphertext_b64"])
            wrong_mode = subprocess.run(
                ["node", str(encryptor), "--validate", str(output), str(public), "worker-1700-mint", "a" * 40, "12345"],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(wrong_mode.returncode, 0)
            wrong_sha = subprocess.run(
                ["node", str(encryptor), "--validate", str(output), str(public), "r2-2564-mint", "b" * 40, "12345"],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(wrong_sha.returncode, 0)

    def test_failed_producer_pipeline_cannot_encrypt_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encryptor, public, output, _ = self._fixtures(root)
            command = (
                "set -euo pipefail; "
                "python3 -c 'raise SystemExit(7)' | "
                f"node {self._quote(encryptor)} {self._quote(public)} {self._quote(output)} "
                "r2-2564-mint " + "a" * 40 + " 12345"
            )
            result = subprocess.run(["bash", "-c", command], capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_mint_success_handoff_failure_selects_exact_token_revoke(self) -> None:
        source = WORKFLOW_SOURCE
        self.assertLess(source.index('fd = os.open(os.environ["TOKEN_STATE_FILE"]'), source.index('raise SystemExit("Cloudflare token response omitted secret value")'))
        revoke_gate = "if: always() && steps.upload_ciphertext.outcome != 'success' && steps.upload_recovery.outcome != 'success'"
        self.assertIn(revoke_gate, source)
        self.assertIn('if [[ ! -s "$TOKEN_STATE_FILE" ]]', source)
        self.assertIn('token_id = state.get("token_id")', source)
        self.assertIn('f"https://api.cloudflare.com/client/v4/user/tokens/{token_id}"', source)
        self.assertIn('method="DELETE"', source)
        self.assertIn('result.get("success") is not True', source)

    @staticmethod
    def _quote(path: Path) -> str:
        return "'" + str(path).replace("'", "'\\''") + "'"

    @staticmethod
    def _payload() -> bytes:
        return json.dumps(
            {
                "schema": "corelink-cloudflare-token-handoff-v1",
                "mode": "r2-2564-mint",
                "github_sha": "a" * 40,
                "github_run_id": "12345",
                "token_id": "12345678123412341234123456789012",
                "secret_values": {
                    "R2_S3_ACCESS_KEY_ID": "12345678123412341234123456789012",
                    "R2_S3_SECRET_ACCESS_KEY": "b" * 64,
                },
            },
            separators=(",", ":"),
        ).encode()

    @staticmethod
    def _fixtures(root: Path) -> tuple[Path, Path, Path, Path]:
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(root / "private.pem")],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(root / "private.pem"), "-pubout", "-out", str(root / "public.pem")],
            check=True,
            capture_output=True,
        )
        encryptor = root / "encrypt.js"
        encryptor.write_text(encryptor_source(), encoding="utf-8")
        return encryptor, root / "public.pem", root / "handoff.enc.json", root / "private.pem"

    def _run_encryptor(self, payload: bytes, *, expect_success: bool) -> bool:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encryptor, public, output, _ = self._fixtures(root)
            result = subprocess.run(
                ["node", str(encryptor), str(public), str(output), "r2-2564-mint", "a" * 40, "12345"],
                input=payload,
                capture_output=True,
                check=False,
            )
            if expect_success:
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertTrue(output.is_file() and output.stat().st_size > 0)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
            return output.exists()


if __name__ == "__main__":
    unittest.main()
