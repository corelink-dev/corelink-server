from __future__ import annotations

import hashlib
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_cli_attestation_bundle import BundleCopyError, normalize


class NormalizeAttestationBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "provenance.intoto.jsonl.bundle"
        self.payload = b'{"dsseEnvelope":{"payload":"immutable original bytes"}}\n'
        self.source.write_bytes(self.payload)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_supported_suffix_copy_preserves_every_byte_and_is_private(self) -> None:
        destination = self.root / "verify.bundle.json"
        digest = normalize(self.source, destination)
        self.assertEqual(destination.read_bytes(), self.payload)
        self.assertEqual(self.source.read_bytes(), self.payload)
        self.assertEqual(digest, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_jsonl_suffix_is_supported(self) -> None:
        destination = self.root / "verify.jsonl"
        self.assertEqual(normalize(self.source, destination), hashlib.sha256(self.payload).hexdigest())

    def test_unsupported_suffix_is_rejected_without_output(self) -> None:
        destination = self.root / "verify.bundle"
        with self.assertRaisesRegex(BundleCopyError, "supported .json or .jsonl"):
            normalize(self.source, destination)
        self.assertFalse(destination.exists())

    def test_existing_destination_is_never_overwritten(self) -> None:
        destination = self.root / "verify.json"
        destination.write_bytes(b"preserve-existing")
        with self.assertRaises(BundleCopyError):
            normalize(self.source, destination)
        self.assertEqual(destination.read_bytes(), b"preserve-existing")

    def test_symlink_source_is_rejected(self) -> None:
        link = self.root / "linked.bundle"
        link.symlink_to(self.source)
        with self.assertRaises(BundleCopyError):
            normalize(link, self.root / "verify.json")

    def test_directory_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(BundleCopyError, "regular file"):
            normalize(self.root, self.root / "verify.json")


if __name__ == "__main__":
    unittest.main()
