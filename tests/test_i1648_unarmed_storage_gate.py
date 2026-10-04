"""Offline source-wiring checks; Rust list behavior runs in the hosted PR lane."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(os.environ.get("CORELINK_SOURCE_ROOT", Path(__file__).resolve().parents[1]))
PARTS = ROOT / "crates/corelink-container/src/storage/r2_s3_parts"


class UnarmedStorageGateTests(unittest.TestCase):
    def check_entry(self, name: str, error: str) -> None:
        source = (PARTS / name).read_text()
        entry = source.split("    fn acquire_byok_data(", 1)[1].split(
            "    fn validate_byok_return(", 1
        )[0]
        check = (
            "check_unarmed_byok_access(\n"
            "            self.byok_config_cache.as_deref(),\n"
            "            self.tcs_resolver.is_some(),\n"
            "            tenant,\n"
            f"        )\n        .map_err({error}::Internal)?;"
        )
        self.assertIn(check, entry, f"{name}: missing propagated unarmed refusal")
        self.assertLess(entry.index(check), entry.index("if let Some(context)"))
        self.assertLess(entry.index(check), entry.index("self.byok_runtime_gate.as_ref()"))

    def test_cas_checks_unarmed_config_before_any_bypass(self) -> None:
        self.check_entry("cas_core.rs", "CasHandlerError")

    def test_ac_checks_unarmed_config_before_any_bypass(self) -> None:
        self.check_entry("ac_handler.rs", "AcHandlerError")

    def test_both_list_paths_propagate_entry_refusal_before_r2(self) -> None:
        for name in ("ac_core.rs", "ac_list.rs"):
            with self.subTest(path=name):
                source = (PARTS / name).read_text().split("    fn list(", 1)[1]
                check = "self.acquire_byok_data(&req.tenant, DataOperation::Read, None)?"
                self.assertIn(check, source)
                self.assertLess(source.index("ListAttempted"), source.index(check))
                self.assertLess(source.index(check), source.index("self.client.list_objects_page("))

    def test_shared_check_preserves_exemptions_and_propagates_config_errors(self) -> None:
        source = (PARTS / "client_types.rs").read_text()
        self.assertIn("fn check_unarmed_byok_access(", source)
        check = source.split("fn check_unarmed_byok_access(", 1)[1].split(
            "\nimpl R2S3Client", 1
        )[0]
        for required in (
            "if armed || tenant == crate::adapter_cache::PUBLIC_NAMESPACE",
            "let Some(cache) = cache else",
            "handle.block_on(cache.get(tenant))",
            '.map_err(|error| format!("byok config read: {error}"))?',
            "let Some(cfg) = cfg else",
            "match unarmed_engagement(&cfg)",
            "ByokEngagement::Plaintext => Ok(())",
            'ByokEngagement::FailClosed(why) => Err(format!("byok {why} (fail-closed)"))',
            'Err(format!("byok {UNARMED_REFUSAL} (fail-closed)"))',
        ):
            self.assertIn(required, check)

    def test_reverting_fixes_in_temporary_copies_is_detected(self) -> None:
        targets = [
            f"UnarmedStorageGateTests.{name}"
            for name in (
                "test_cas_checks_unarmed_config_before_any_bypass",
                "test_ac_checks_unarmed_config_before_any_bypass",
                "test_both_list_paths_propagate_entry_refusal_before_r2",
                "test_shared_check_preserves_exemptions_and_propagates_config_errors",
            )
        ]
        mutations = []
        for name, error in (("cas_core.rs", "CasHandlerError"), ("ac_handler.rs", "AcHandlerError")):
            check = (
                "        check_unarmed_byok_access(\n"
                "            self.byok_config_cache.as_deref(),\n"
                "            self.tcs_resolver.is_some(),\n"
                "            tenant,\n"
                f"        )\n        .map_err({error}::Internal)?;\n"
            )
            mutations.append((name, check, "", f"revert {name} unarmed entry check"))
        mutations.extend([
            ("client_types.rs", '.map_err(|error| format!("byok config read: {error}"))?',
             ".unwrap_or(None)", "swallow config-source failure"),
            ("client_types.rs", 'ByokEngagement::FailClosed(why) => Err(format!("byok {why} (fail-closed)"))',
             "ByokEngagement::FailClosed(_) => Ok(())", "allow engaged tenant"),
        ])
        with tempfile.TemporaryDirectory(prefix="i1648-unarmed-mutation-") as temp:
            tree = Path(temp)
            copied_parts = tree / PARTS.relative_to(ROOT)
            copied_parts.mkdir(parents=True)
            for name in ("cas_core.rs", "ac_handler.rs", "client_types.rs", "ac_core.rs", "ac_list.rs"):
                shutil.copy2(PARTS / name, copied_parts / name)
            command = [sys.executable, str(Path(__file__).resolve()), *targets]
            env = {**os.environ, "CORELINK_SOURCE_ROOT": str(tree)}
            green = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(green.returncode, 0, green.stdout + green.stderr)
            for name, original, replacement, label in mutations:
                with self.subTest(mutation=label):
                    path = copied_parts / name
                    pristine = path.read_text()
                    self.assertEqual(pristine.count(original), 1, label)
                    path.write_text(pristine.replace(original, replacement, 1))
                    try:
                        red = subprocess.run(command, env=env, capture_output=True, text=True)
                        self.assertNotEqual(red.returncode, 0, label)
                        self.assertIn("FAILED (failures=1)", red.stderr, red.stderr)
                        print(f"mutation killed: {label}")
                    finally:
                        path.write_text(pristine)


if __name__ == "__main__":
    unittest.main()
