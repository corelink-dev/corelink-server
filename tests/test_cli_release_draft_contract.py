"""Focused negatives for the separate, unsigned-Windows draft inventory."""
from __future__ import annotations

import hashlib
import json
import shutil
import base64
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import cli_release_draft_manifest as draft
from scripts import cli_release_manifest as production
from scripts import verify_cli_release_draft as draft_verifier


TAG = "cli-v0.1.3"
SOURCE = "a" * 40


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_checksums(directory: Path) -> None:
    names = sorted(
        path.name for path in directory.iterdir()
        if path.is_file() and (
            path.name in production.BASE_PAYLOADS
            or path.name in {f"{name}.asc" for name in production.LINUX_PAYLOADS}
        )
    )
    for name in names:
        (directory / f"{name}.sha256").write_text(f"{sha(directory / name)}  {name}\n", encoding="utf-8")
    checksum_names = sorted(name for name in names)
    (directory / "checksums.txt").write_text(
        "".join(f"{sha(directory / name)}  {name}\n" for name in checksum_names), encoding="utf-8"
    )


class DraftManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.staged = self.root / "staged"
        self.final = self.root / "final"
        self.staged.mkdir()
        for name in production.BASE_PAYLOADS:
            (self.staged / name).write_bytes(f"staged:{name}".encode())
        write_checksums(self.staged)
        self.staging_manifest = self.staged / "staging-manifest.json"
        production.create(self.staged, self.staging_manifest, TAG, SOURCE)
        shutil.copytree(self.staged, self.final, ignore=shutil.ignore_patterns("staging-manifest.json"))
        for name in production.LINUX_PAYLOADS:
            (self.final / name).write_bytes(f"signed:{name}".encode())
            (self.final / f"{name}.asc").write_bytes(f"signature:{name}".encode())
        write_checksums(self.final)
        self.manifest = self.final / "release-manifest.json"
        draft.create(self.final, self.manifest, TAG, SOURCE, self.staging_manifest)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_draft_manifest_is_typed_and_production_loader_rejects_it(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(value["version"], 3)
        self.assertEqual(value["mode"], "draft-only")
        self.assertEqual(value["windows_signature_status"], "unsigned-deferred")
        self.assertEqual(set(draft.load_manifest(self.manifest, TAG, SOURCE)), production.FINAL_INVENTORY)
        with self.assertRaises(ValueError):
            production.load(self.manifest, TAG, SOURCE)

    def test_wrong_mode_identity_or_inventory_is_rejected(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        for key, replacement in (("mode", "signed-public"), ("windows_signature_status", "authenticode")):
            changed = dict(value)
            changed[key] = replacement
            candidate = self.root / f"bad-{key}.json"
            candidate.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(ValueError):
                draft.load_manifest(candidate, TAG, SOURCE)
        with self.assertRaises(ValueError):
            draft.load_manifest(self.manifest, "cli-v9.9.9", SOURCE)
        extra = self.final / "unexpected-apple.dmg"
        extra.write_bytes(b"not allowed")
        self.manifest.unlink()
        with self.assertRaises(ValueError):
            draft.create(self.final, self.root / "extra.json", TAG, SOURCE, self.staging_manifest)

    def test_windows_final_bytes_must_equal_staging(self) -> None:
        name = "corelink-windows-x86_64.exe"
        (self.final / name).write_bytes(b"modified Windows bytes")
        write_checksums(self.final)
        self.manifest.unlink()
        with self.assertRaisesRegex(ValueError, "Windows artifact"):
            draft.create(self.final, self.root / "tampered.json", TAG, SOURCE, self.staging_manifest)

    def test_verifier_rejects_published_or_wrong_tag_api_before_byte_checks(self) -> None:
        api_path = self.root / "release.json"
        base = {"tag_name": TAG, "draft": True, "published_at": None, "prerelease": False, "assets": []}
        for changes in ({"draft": False}, {"tag_name": "cli-v0.1.2"}, {"published_at": "2026-10-01T00:00:00Z"}):
            api_path.write_text(json.dumps(base | changes), encoding="utf-8")
            with self.assertRaises(ValueError):
                draft_verifier.verify(api_path, self.final, self.manifest, self.final / "provenance.intoto.jsonl",
                                      self.final / "provenance.intoto.jsonl.bundle", self.root / "pub.asc",
                                      TAG, SOURCE, sha(self.manifest))

    def test_final_manifest_verifies_bytes_and_rejects_tampering(self) -> None:
        with patch.object(draft, "_gpg_verify"):
            digest_map = draft.verify_manifest(
                self.final, self.manifest, self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest)
            )
        self.assertEqual(set(digest_map), production.FINAL_INVENTORY)
        (self.final / "corelink-windows-x86_64.exe").write_bytes(b"tampered after manifest")
        with patch.object(draft, "_gpg_verify"):
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                draft.verify_manifest(
                    self.final, self.manifest, self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest)
                )

    def test_linux_gpg_status_must_match_the_frozen_fingerprint(self) -> None:
        public_key = self.root / "release-public-key.asc"
        public_key.write_text("public-key fixture", encoding="utf-8")
        imported = subprocess.CompletedProcess([], 0, "", "")
        valid = subprocess.CompletedProcess(
            [], 0, f"[GNUPG:] VALIDSIG {draft.EXPECTED_GPG_FINGERPRINT} 20261001\n", ""
        )
        artifact_map = draft.load_manifest(self.manifest, TAG, SOURCE)
        with patch.object(draft.subprocess, "run", side_effect=[imported, valid, valid, valid, valid]) as run:
            draft._gpg_verify(self.final, artifact_map, public_key)
        self.assertEqual(run.call_count, 5)
        wrong = subprocess.CompletedProcess([], 0, f"[GNUPG:] VALIDSIG {'0' * 40} 20261001\n", "")
        with patch.object(draft.subprocess, "run", side_effect=[imported, wrong]):
            with self.assertRaisesRegex(ValueError, "wrong fingerprint"):
                draft._gpg_verify(self.final, artifact_map, public_key)

    def test_release_readback_binds_exact_api_assets_and_slsa_subjects(self) -> None:
        artifacts = json.loads(self.manifest.read_text(encoding="utf-8"))["artifacts"]
        subjects = [
            {"name": item["name"], "digest": {"sha256": item["sha256"]}}
            for item in artifacts
        ]
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": subjects}
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        provenance = self.final / "provenance.intoto.jsonl"
        bundle = self.final / "provenance.intoto.jsonl.bundle"
        provenance.write_bytes(payload + b"\n")
        bundle.write_text(json.dumps({"dsseEnvelope": {"payload": base64.b64encode(payload).decode()}}), encoding="utf-8")
        api = self.root / "release-api.json"
        names = set(draft.load_manifest(self.manifest, TAG, SOURCE)) | draft.METADATA_ASSETS
        api.write_text(json.dumps({
            "tag_name": TAG, "draft": True, "published_at": None, "prerelease": False,
            "assets": [{"name": name, "id": index, "digest": f"sha256:{sha(self.final / name)}"}
                       for index, name in enumerate(sorted(names), 1)],
        }), encoding="utf-8")
        with patch.object(draft, "_gpg_verify"):
            draft_verifier.verify(api, self.final, self.manifest, provenance, bundle,
                                  self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest))
        statement["subject"] = subjects[:-1]
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        provenance.write_bytes(payload + b"\n")
        bundle.write_text(json.dumps({"dsseEnvelope": {"payload": base64.b64encode(payload).decode()}}), encoding="utf-8")
        api_value = json.loads(api.read_text(encoding="utf-8"))
        for asset in api_value["assets"]:
            asset["digest"] = f"sha256:{sha(self.final / asset['name'])}"
        api.write_text(json.dumps(api_value), encoding="utf-8")
        with patch.object(draft, "_gpg_verify"):
            with self.assertRaisesRegex(ValueError, "SLSA subjects"):
                draft_verifier.verify(api, self.final, self.manifest, provenance, bundle,
                                      self.root / "unused-public-key", TAG, SOURCE, sha(self.manifest))


if __name__ == "__main__":
    unittest.main()
