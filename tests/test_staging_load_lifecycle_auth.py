from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/staging_load_lifecycle_auth.py"
SPEC = importlib.util.spec_from_file_location("staging_load_lifecycle_auth", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StagingLoadLifecycleAuthTests(unittest.TestCase):
    def test_v1_and_v2_golden_vectors_match_the_frozen_rust_wire(self) -> None:
        self.assertEqual(
            MODULE.mint("v1", MODULE.GOLDEN_KEY, "123", "cas", MODULE.GOLDEN_SHA, issued=100, nonce=MODULE.GOLDEN_NONCE, lifetime_ms=100),
            MODULE.GOLDEN_V1,
        )
        self.assertEqual(
            MODULE.mint("v2", MODULE.GOLDEN_KEY, "123", "cas", MODULE.GOLDEN_SHA, issued=100, nonce=MODULE.GOLDEN_NONCE, lifetime_ms=100),
            MODULE.GOLDEN_V2,
        )

    def test_lifecycle_mints_a_fresh_256_bit_nonce_each_time(self) -> None:
        first = MODULE.mint("v1", MODULE.GOLDEN_KEY, "123", "cas", MODULE.GOLDEN_SHA, issued=100)
        second = MODULE.mint("v1", MODULE.GOLDEN_KEY, "123", "cas", MODULE.GOLDEN_SHA, issued=100)
        self.assertNotEqual(first.split(".")[7], second.split(".")[7])
        self.assertEqual(len(first.split(".")[7]), 64)

    def test_rejects_noncanonical_or_overlong_claim_inputs(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.mint("v1", MODULE.GOLDEN_KEY, "0123", "cas", MODULE.GOLDEN_SHA)
        with self.assertRaises(ValueError):
            MODULE._canonical("v1", "123", "cas", MODULE.GOLDEN_SHA, 100, 900_101, MODULE.GOLDEN_NONCE)

    def test_seal_receipt_requires_exact_identity_order_and_256_cap(self) -> None:
        receipt = {
            "schema": "corelink.staging-load-test-seal-receipt.v1",
            "run_id": "123",
            "scenario": "cas",
            "target_deployment_sha": MODULE.GOLDEN_SHA,
            "state": "sealed",
            "resources": {resource: 0 for resource in MODULE.RESOURCE_CLASSES},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seal.json"
            path.write_text(json.dumps(receipt))
            MODULE.validate_seal_receipt(str(path), "123", "cas", MODULE.GOLDEN_SHA)
            receipt["resources"] = dict(reversed(tuple(receipt["resources"].items())))
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                MODULE.validate_seal_receipt(str(path), "123", "cas", MODULE.GOLDEN_SHA)
            receipt["resources"] = {resource: 0 for resource in MODULE.RESOURCE_CLASSES}
            receipt["resources"]["cas_reference"] = 257
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                MODULE.validate_seal_receipt(str(path), "123", "cas", MODULE.GOLDEN_SHA)
            receipt["resources"] = {resource: 0 for resource in MODULE.RESOURCE_CLASSES}
            receipt["unexpected"] = "locator-like-value"
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                MODULE.validate_seal_receipt(str(path), "123", "cas", MODULE.GOLDEN_SHA)

    def test_seal_receipt_rejects_duplicate_json_keys(self) -> None:
        raw = (
            '{"schema":"corelink.staging-load-test-seal-receipt.v1",'
            '"schema":"forged","run_id":"123","scenario":"cas",'
            f'"target_deployment_sha":"{MODULE.GOLDEN_SHA}",'
            '"state":"sealed","resources":{'
            + ",".join(f'"{resource}":0' for resource in MODULE.RESOURCE_CLASSES)
            + "}}"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seal.json"
            path.write_text(raw)
            with self.assertRaises(ValueError):
                MODULE.validate_seal_receipt(str(path), "123", "cas", MODULE.GOLDEN_SHA)


if __name__ == "__main__":
    unittest.main()
