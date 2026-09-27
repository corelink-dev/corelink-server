"""Focused B-035 contract and mutation tests.

These tests are intentionally repository-only.  Cloudflare proof is a separate
read-only ``--live`` invocation and must not receive credentials in this suite.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_b035_tls_surfaces as verify


class B035TlsSurfaceTests(unittest.TestCase):
    def test_inventory_enumerates_exactly_eight_promises(self) -> None:
        report = verify.inventory()
        self.assertEqual(report["instrument_count"], 8)
        self.assertEqual(report["status"], "truthful_exact_inventory")
        self.assertTrue(
            all(row["claim_count"] == 1 for row in report["instruments"])
        )
        self.assertTrue(
            all(row["claim_matches_expected"] for row in report["instruments"])
        )
        self.assertEqual(report["external_surface"]["protocol_floor"], "TLS 1.2")
        self.assertIn("no cipher-suite floor", report["external_surface"]["cipher_policy"])

    def test_surface_inventory_is_source_bound_and_covers_route_families(self) -> None:
        report = verify.inventory()
        surfaces = report["external_surface"]["named_surfaces"]
        self.assertGreaterEqual(len(surfaces), 21)
        self.assertEqual(
            report["external_surface"]["source_validation"]["status"],
            "all_markers_match",
        )
        self.assertTrue(
            all(
                {"name", "kind", "hostname", "enforcement", "source", "status"}
                <= set(surface)
                for surface in surfaces
            )
        )
        hostnames = {surface["hostname"] for surface in surfaces}
        self.assertIn("humangr.com/corelink/*", hostnames)
        self.assertIn("humangr.com/corelink/docs", hostnames)
        self.assertIn("humangr.com/corelink/docs/*", hostnames)
        self.assertIn("api.humangr.com/*", hostnames)
        self.assertIn("<region>.api.humangr.com/*", hostnames)
        self.assertIn("events.pagerduty.com/v2/enqueue", hostnames)
        self.assertIn(
            "github.com/HuGR-Labs/corelink-cli/releases/latest/download", hostnames
        )
        self.assertTrue(
            all(boundary["status"] for boundary in verify.PROVIDER_BOUNDARIES)
        )

    def test_active_route_rename_fails_closed_even_with_stale_comment(self) -> None:
        rule = verify.SURFACE_SOURCE_RULES["corelink-api"]
        path = verify.ROOT / rule["path"]
        source = path.read_text(encoding="utf-8")
        active_declaration = f'pattern = "{rule["value"]}"'
        self.assertEqual(source.count(active_declaration), 1)
        renamed = source.replace(
            active_declaration,
            active_declaration.replace(rule["value"], "renamed.invalid/*"),
            1,
        )
        mutated = (
            f'# stale route tombstone: {active_declaration}\n' + renamed
        )
        self.assertIn(f'# stale route tombstone: {active_declaration}', mutated)
        report = verify.inventory_from_overrides(
            verify.ROOT, {}, {rule["path"]: mutated}
        )
        self.assertEqual(report["status"], "drift_or_incomplete")
        self.assertTrue(
            any(
                error.startswith("corelink-api:")
                for error in report["external_surface"]["source_validation"]["errors"]
            )
        )

    def test_each_instrument_is_required_and_missing_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for instrument in verify.INSTRUMENTS:
                source = verify.ROOT / instrument.path
                target = root / instrument.path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

            removed = root / verify.INSTRUMENTS[0].path
            removed.unlink()
            code, report = verify.verify(root, live=False)

        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "verification_error")

    def test_correcting_any_claim_fails_closed(self) -> None:
        instrument = verify.INSTRUMENTS[0]
        original = (verify.ROOT / instrument.path).read_text(encoding="utf-8")
        claim_pattern = re.compile(
            r"\s+".join(re.escape(part) for part in instrument.claim.split())
        )
        corrected, replacements = claim_pattern.subn(
            "TLS 1.3 minimum", original, count=1
        )
        self.assertEqual(replacements, 1)
        report = verify.inventory_from_overrides(
            verify.ROOT, {instrument.path: corrected}
        )
        self.assertEqual(report["status"], "drift_or_incomplete")

    def test_additional_unqualified_tls_13_claim_fails_closed(self) -> None:
        instrument = verify.INSTRUMENTS[0]
        original = (verify.ROOT / instrument.path).read_text(encoding="utf-8")
        mutated = original + "\nAdditional promise: TLS 1.3+.\n"
        report = verify.inventory_from_overrides(
            verify.ROOT, {instrument.path: mutated}
        )
        self.assertEqual(report["status"], "drift_or_incomplete")

    def test_live_mode_without_credentials_is_fail_closed(self) -> None:
        with patch.dict(
            verify.os.environ,
            {"CLOUDFLARE_API_TOKEN": "", "CF_API_TOKEN": ""},
            clear=False,
        ):
            code, report = verify.verify(verify.ROOT, live=True)
        self.assertEqual(code, 2)
        self.assertEqual(report["live_floor"]["status"], "credential_unavailable")


if __name__ == "__main__":
    unittest.main()
