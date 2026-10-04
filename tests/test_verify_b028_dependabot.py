#!/usr/bin/env python3
"""Focused tests for the fail-closed B-028 Dependabot verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_b028", ROOT / "scripts/verify_b028_dependabot.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)
RESOLVER = sys.modules[VERIFY.resolve_server_repository.__module__]


def _read_back_fixture_identity():
    # The committed config/github-identity.json may still hold the unread ID 0,
    # which the resolver refuses; keep its owner and names, fill synthetic IDs.
    document = copy.deepcopy(RESOLVER.read_identity_document())
    document["current"]["owner_id"] = 987650000
    for offset, key in enumerate(RESOLVER.REPOSITORY_KEYS, start=1):
        document["current"]["repos"][key]["id"] = 987650000 + offset
    return RESOLVER.parse_identity(document).require_read_back()


FIXTURE_IDENTITY = _read_back_fixture_identity()
FIXTURE_SERVER = FIXTURE_IDENTITY.repository("server").full_name


def alert(number: int, package: str, ghsa: str, severity: str = "high", patched=None) -> dict:
    return {
        "number": number,
        "state": "open",
        "dependency": {"package": {"name": package}},
        "security_advisory": {
            "ghsa_id": ghsa,
            "severity": severity,
            "vulnerabilities": [{"first_patched_version": patched}],
        },
    }


EXPECTED = [
    alert(26, "image-size", "GHSA-w3rx-r6r6-pgpr"),
    alert(27, "image-size", "GHSA-5p2g-fcmc-qvqq"),
    alert(28, "extract-zip", "GHSA-jmr9-qjv8-65gv"),
    alert(33, "fast-uri", "GHSA-5jgf-p345-68v8"),
    alert(34, "fast-uri", "GHSA-fph4-wmhf-6fwf"),
    alert(35, "qs", "GHSA-x5fp-wj9c-mxmx", severity="medium"),
    alert(36, "fast-uri", "GHSA-f65p-4m7j-42xc"),
    alert(37, "fast-uri", "GHSA-jqff-g426-hqxp"),
    alert(38, "qs", "GHSA-4mjr-xmp4-gh2g", severity="medium"),
]


class B028VerifierTests(unittest.TestCase):
    def test_nested_paginated_old_main_census_passes(self):
        self.assertEqual(
            VERIFY.verify_alerts(VERIFY._flatten_pages([EXPECTED[:4], EXPECTED[4:]])),
            [(n, *VERIFY.EXPECTED_OLD_MAIN_ALERTS[n]) for n in sorted(VERIFY.EXPECTED_OLD_MAIN_ALERTS)],
        )

    def test_new_open_alert_is_drift(self):
        with self.assertRaisesRegex(VERIFY.CensusError, "census drifted"):
            VERIFY.verify_alerts(EXPECTED + [alert(39, "fast-uri", "GHSA-new")])

    def test_post_merge_receipt_mutated_with_historical_open_alerts_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            relative = Path(VERIFY.POST_MERGE_SNAPSHOT)
            receipt_path = root / relative
            receipt_path.parent.mkdir(parents=True)

            receipt_source = ROOT / relative
            historical_source = ROOT / "docs/security/b028-dependabot-census-2026-09-06.json"
            receipt = json.loads(receipt_source.read_text(encoding="utf-8"))
            historical = json.loads(historical_source.read_text(encoding="utf-8"))
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            VERIFY.verify_baseline_snapshot(root)

            # Mutate the zero-alert receipt with the exact, already-recorded
            # pre-merge alerts. No alert facts are invented for this control.
            receipt["alerts"] = historical["alerts"]
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            with self.assertRaisesRegex(VERIFY.CensusError, "must contain no open alerts"):
                VERIFY.verify_baseline_snapshot(root)

    def test_published_patch_on_residual_forces_retriage(self):
        with self.assertRaisesRegex(VERIFY.CensusError, "census drifted"):
            VERIFY.verify_alerts([alert(26, "image-size", "GHSA-w3rx-r6r6-pgpr", patched={"identifier": "2.0.3"})])

    def test_api_failure_is_not_an_empty_census(self):
        result = type("Result", (), {"returncode": 1, "stderr": "HTTP 403", "stdout": ""})()
        repo = VERIFY.resolve_server_repository(FIXTURE_SERVER, identity=FIXTURE_IDENTITY)
        with patch.object(VERIFY.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(VERIFY.CensusError, "not an empty census"):
                VERIFY.read_alerts(repo, None)
        self.assertEqual(
            run.call_args.args[0][-1],
            f"/repos/{FIXTURE_SERVER}/dependabot/alerts",
        )
        # The pre-recreate destination is no longer an authorized server name.
        with self.assertRaises(ValueError):
            VERIFY.resolve_server_repository("HuGR-dev/corelink-server", identity=FIXTURE_IDENTITY)

    def test_cli_checks_lockfile_and_fixture(self):
        overrides = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.REQUIRED_OVERRIDES)
        local = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.LOCAL_OVERRIDES)
        lock = "\n".join(f"  {entry}:" for entry in VERIFY.REQUIRED_LOCK_ENTRIES)
        lock += "\n" + "\n".join(f"  {key}@{value}:" for key, value in VERIFY.LOCAL_OVERRIDES)
        lock += "\n" + overrides
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "package.json").write_text("{" + overrides + "," + local + "}", encoding="utf-8")
            (root / "pnpm-lock.yaml").write_text(lock, encoding="utf-8")
            for relative, markers in VERIFY.VENDOR_MARKERS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(markers), encoding="utf-8")
            snapshot = root / VERIFY.BASELINE_SNAPSHOT
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text(
                (ROOT / VERIFY.BASELINE_SNAPSHOT).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            fixture = root / "alerts.json"
            fixture.write_text(json.dumps([EXPECTED]), encoding="utf-8")
            self.assertEqual(
                VERIFY.main(["--root", str(root), "--alerts-file", str(fixture)]),
                0,
            )

    def test_published_vulnerable_node_is_rejected_even_with_local_override(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            overrides = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.REQUIRED_OVERRIDES)
            local = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.LOCAL_OVERRIDES)
            (root / "package.json").write_text("{" + overrides + "," + local + "}", encoding="utf-8")
            lock = "\n".join(f"  {entry}:" for entry in VERIFY.REQUIRED_LOCK_ENTRIES)
            lock += "\n" + "\n".join(f"  {key}@{value}:" for key, value in VERIFY.LOCAL_OVERRIDES)
            lock += "\n  extract-zip@2.0.1:\n"
            (root / "pnpm-lock.yaml").write_text(lock + "\n" + overrides, encoding="utf-8")
            for relative, markers in VERIFY.VENDOR_MARKERS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(markers), encoding="utf-8")
            with self.assertRaisesRegex(VERIFY.CensusError, "stale"):
                VERIFY.verify_lockfile(root)

    def test_mutation_removing_exclusive_create_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            overrides = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.REQUIRED_OVERRIDES)
            local = "\n".join(f'"{key}": "{value}"' for key, value in VERIFY.LOCAL_OVERRIDES)
            (root / "package.json").write_text("{" + overrides + "," + local + "}", encoding="utf-8")
            lock = "\n".join(f"  {entry}:" for entry in VERIFY.REQUIRED_LOCK_ENTRIES)
            lock += "\n" + "\n".join(f"  {key}@{value}:" for key, value in VERIFY.LOCAL_OVERRIDES)
            (root / "pnpm-lock.yaml").write_text(lock + "\n" + overrides, encoding="utf-8")
            for relative, markers in VERIFY.VENDOR_MARKERS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(markers), encoding="utf-8")
            path = root / "vendor/extract-zip/index.js"
            path.write_text("\n".join(marker for marker in VERIFY.VENDOR_MARKERS[str(path.relative_to(root))] if marker != "flags: 'wx'"), encoding="utf-8")
            with self.assertRaisesRegex(VERIFY.CensusError, "flags: 'wx'"):
                VERIFY.verify_lockfile(root)


if __name__ == "__main__":
    unittest.main()
