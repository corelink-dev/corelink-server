from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_b098_repo_hygiene.py"
spec = importlib.util.spec_from_file_location("b098_verifier", SCRIPT)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


class B098VerifierTests(unittest.TestCase):
    def test_repository_is_open_only_for_the_missing_external_release(self) -> None:
        result = verifier.audit(ROOT)
        self.assertEqual(result.issues, ())
        self.assertEqual(result.status, "open")
        self.assertEqual(result.semver_tags, ())
        self.assertEqual(result.package_count, 95)
        self.assertEqual(result.crate_dir_count, 75)
        self.assertEqual(result.okf_count, 174)
        self.assertEqual((result.specs_schema_count, result.specs_yaml_only_count), (490, 11))

    def test_lint_inheritance_mutation_reopens_the_guard(self) -> None:
        tracker = (ROOT / "crates/corelink-runbook-tracker/Cargo.toml").read_text()
        mutated = tracker.replace(
            "[lints]\nworkspace = true",
            '[lints.rust]\nunsafe_code = "forbid"',
            1,
        )
        result = verifier.audit(ROOT, tracker_text=mutated)
        self.assertTrue(any("inherit" in issue for issue in result.issues))
        self.assertTrue(any("local rust/clippy" in issue for issue in result.issues))

    def test_each_documented_population_count_is_mutation_sensitive(self) -> None:
        claude = (ROOT / "CLAUDE.md").read_text()
        mutated = claude.replace("**174 OKF concepts**", "**173 OKF concepts**", 1)
        result = verifier.audit(ROOT, claude_text=mutated)
        self.assertTrue(any("okf_count" in issue for issue in result.issues))

        mutated = claude.replace(
            "**490 full-schema + 11 YAML-only (501 total)",
            "**489 full-schema + 11 YAML-only (500 total)",
            1,
        )
        result = verifier.audit(ROOT, claude_text=mutated)
        self.assertTrue(any("specs_schema_count" in issue for issue in result.issues))
        self.assertTrue(any("specs_total_count" in issue for issue in result.issues))

    def test_semver_classifier_does_not_confuse_cli_tags_with_release_tags(self) -> None:
        self.assertTrue(verifier.SEMVER_TAG.fullmatch("v1.0.0"))
        self.assertTrue(verifier.SEMVER_TAG.fullmatch("v1.2.3-rc.1"))
        self.assertFalse(verifier.SEMVER_TAG.fullmatch("cli-v0.1.0"))
        self.assertFalse(verifier.SEMVER_TAG.fullmatch("v1.0"))
        self.assertFalse(verifier.SEMVER_TAG.fullmatch("v01.2.3"))

    def test_only_canonical_ga_tag_can_change_closure_status(self) -> None:
        base = verifier.Audit(95, 75, 173, 488, 11, ("v0.1.0",), ())
        self.assertEqual(base.status, "open")
        canonical = verifier.Audit(95, 75, 173, 488, 11, ("v1.0.0-GA",), ())
        self.assertEqual(canonical.status, "ready-to-close")
        invalid = verifier.Audit(95, 75, 173, 488, 11, ("v1.0.0-GA",), ("bad signature",))
        self.assertEqual(invalid.status, "invalid")

    def test_cut_contract_is_signed_strict_and_evidence_bound(self) -> None:
        cut = (ROOT / "scripts/cut-v1-0-0-ga-tag.sh").read_text()
        draft = (ROOT / "docs/release/v1.0.0-GA-tag-draft-final.txt").read_text()
        self.assertIn('git tag -s "$TAG_NAME"', cut)
        self.assertNotIn('git tag -a "$TAG_NAME"', cut)
        self.assertIn("--expected-main-sha is mandatory", cut)
        self.assertIn("git verify-tag", cut)
        self.assertIn("framework tag signature does not verify", cut)
        self.assertIn('cutover.get("greenlights") != {"passed": 6, "total": 6}', cut)
        self.assertIn("two-key signoff reuses one cryptographic key", cut)
        self.assertIn("server-release provenance record", draft)
        self.assertIn("does not claim SLSA provenance for CLI artifacts", draft)
        self.assertIn("makes no GA-live claim for", draft)

    def test_release_governance_receipt_is_typed_and_fail_closed(self) -> None:
        receipt_path = ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json"
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertEqual(receipt["receipt_type"], "b098_ga_release_governance_blocker")
        self.assertEqual(receipt["release_state"]["local_semver_tags"], [])
        self.assertEqual(
            {row["id"] for row in receipt["blockers"] if row["status"] == "BLOCKED"},
            {
                "ops-authority",
                "framework-promotion",
                "cutover-attestation",
                "deployment-readback",
                "bundled-ci",
                "two-key-signoff",
            },
        )
        self.assertTrue(any("independent Ops signoff" in value for value in receipt["non_claims"]))
        self.assertNotIn("signers", receipt)

    def test_dual_hat_adr_is_not_treated_as_release_authority(self) -> None:
        adr = (ROOT / "specs/03_architecture/adrs/ADR-0034b-framework-reviewer-dual-hat-fallback.md").read_text()
        self.assertIn('doc_status: "DRAFT"', adr)
        self.assertIn("**PROPOSED**", adr)
        receipt = json.loads(
            (ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json").read_text()
        )
        dual_hat = next(row for row in receipt["owner_decisions"] if row["decision"] == "dual_hat_release_path")
        self.assertEqual(dual_hat["status"], "NOT_INVOKED")
        self.assertEqual(dual_hat["sha256"], verifier.DUAL_HAT_ADR_SHA256)

    def test_recursive_duplicate_json_keys_fail_closed(self) -> None:
        receipt_path = ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json"
        receipt_text = receipt_path.read_text()
        top_duplicate = receipt_text[:-2] + ',"status":"BLOCKED"\n}\n'
        nested_duplicate = receipt_text.replace(
            '"release_state": {', '"release_state": {"remote_release_tag_present": false,', 1
        )
        for label, mutated in {"top-level": top_duplicate, "nested": nested_duplicate}.items():
            with self.subTest(label=label):
                issues = verifier._check_governance_receipt(
                    ROOT, (), package_count=95, crate_dir_count=75, okf_count=173,
                    specs_schema_count=488, specs_yaml_only_count=11, receipt_text=mutated,
                )
                self.assertTrue(any("receipt is invalid" in issue for issue in issues))
        policy = (ROOT / ".github/release-signing-policy.json").read_text().rstrip()[:-1]
        policy_duplicate = policy + ',"version":1}\n'
        self.assertTrue(any("invalid JSON" in issue for issue in verifier._check_signing_policy(ROOT, policy_text=policy_duplicate)))

    def test_dual_hat_adr_hash_and_content_mutations_fail_closed(self) -> None:
        receipt = json.loads(
            (ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json").read_text()
        )
        dual_hat = next(row for row in receipt["owner_decisions"] if row["decision"] == "dual_hat_release_path")
        adr = (ROOT / verifier.DUAL_HAT_ADR).read_text()
        self.assertTrue(verifier._check_dual_hat_adr(ROOT, dual_hat, adr_text=adr.replace('doc_status: "DRAFT"', 'doc_status: "ACTIVE"', 1)))
        mutated = deepcopy(dual_hat)
        mutated["sha256"] = "0" * 64
        self.assertTrue(verifier._check_dual_hat_adr(ROOT, mutated, adr_text=adr))

    def test_live_origin_check_is_bounded_and_exact(self) -> None:
        def fake(output: str, *, returncode: int = 0):
            return lambda *args, **kwargs: SimpleNamespace(returncode=returncode, stdout=output, stderr="remote error")

        clean = fake(f"{'b' * 40}\trefs/heads/main\n")
        self.assertEqual(verifier._check_live_origin(ROOT, (), run_command=clean), [])
        stale_ref = fake(f"{'b' * 40}\trefs/tags/v1.0.0-GA\n")
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=stale_ref))
        malformed = fake("not-a-ref\n")
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=malformed))
        failed = fake("", returncode=2)
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=failed))

        for length in (41, 63):
            with self.subTest(oid_length=length):
                malformed_oid = fake(f"{'b' * length}\trefs/heads/main\n")
                self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=malformed_oid))
        self.assertEqual(
            verifier._check_live_origin(ROOT, (), run_command=fake(f"{'b' * 64}\trefs/heads/main\n")),
            [],
        )
        zero_oid = fake(f"{'0' * 40}\trefs/heads/main\n")
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=zero_oid))
        duplicate_same = fake(
            f"{'b' * 40}\trefs/heads/main\n{'b' * 40}\trefs/heads/main\n"
        )
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=duplicate_same))
        duplicate_different = fake(
            f"{'b' * 40}\trefs/heads/main\n{'c' * 40}\trefs/heads/main\n"
        )
        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=duplicate_different))

        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(kwargs.get("args", args[0] if args else "git"), 10)

        self.assertTrue(verifier._check_live_origin(ROOT, (), run_command=timeout))

    def test_receipt_deletion_and_each_schema_bypass_fail_closed(self) -> None:
        receipt_path = ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json"
        baseline = json.loads(receipt_path.read_text())

        missing_root = ROOT / "this-root-does-not-exist"
        issues = verifier._check_governance_receipt(
            missing_root, (), package_count=95, crate_dir_count=75, okf_count=173,
            specs_schema_count=488, specs_yaml_only_count=11,
        )
        self.assertTrue(any("receipt is missing" in issue for issue in issues))

        mutations = {
            "top-level deletion": lambda value: value.pop("status"),
            "all-zero checkpoint": lambda value: value.__setitem__("checkpoint_sha", "0" * 40),
            "41-character checkpoint": lambda value: value.__setitem__("checkpoint_sha", "a" * 41),
            "63-character checkpoint": lambda value: value.__setitem__("checkpoint_sha", "a" * 63),
            "older reachable checkpoint": lambda value: value.__setitem__(
                "checkpoint_sha", subprocess.check_output(
                    ["git", "rev-parse", "1126e25d294ae16e73efa70004642e34f223285d^"],
                    cwd=ROOT, text=True,
                ).strip(),
            ),
            "future timestamp": lambda value: value.__setitem__("captured_at", "2999-01-01T00:00:00Z"),
            "stale timestamp": lambda value: value.__setitem__("captured_at", "2020-01-01T00:00:00Z"),
            "remote field bypass": lambda value: value["release_state"].__setitem__("remote_ops_signoff_anchor_present", True),
            "owner decision bypass": lambda value: value["owner_decisions"][0].__setitem__("status", "APPROVED"),
            "blocker required deletion": lambda value: value["blockers"][0].__setitem__("required", ""),
            "blocker evidence mutation": lambda value: value["blockers"][0].__setitem__("evidence", "forged.json"),
            "non-claim deletion": lambda value: value.__setitem__("non_claims", value["non_claims"][:-1]),
            "reference mutation": lambda value: value["references"].append("forged.txt"),
            "hygiene extra field": lambda value: value["repository_hygiene"].__setitem__("extra", 1),
            "census checkpoint binding mutation": lambda value: value["census_binding"].__setitem__(
                "checkpoint_sha", value["census_binding"]["checkpoint_sha"][:-1] + "0"
            ),
            "census capture scope mutation": lambda value: value["census_binding"].__setitem__(
                "capture_scope", "historical-tree"
            ),
            "census hash mutation": lambda value: value["census_binding"].__setitem__(
                "sha256", "0" * 64
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                mutated = deepcopy(baseline)
                mutate(mutated)
                issues = verifier._check_governance_receipt(
                    ROOT, (), package_count=95, crate_dir_count=75, okf_count=173,
                    specs_schema_count=488, specs_yaml_only_count=11,
                    receipt_text=json.dumps(mutated),
                )
                self.assertTrue(issues, label)

    def test_census_deletion_and_each_metadata_bypass_fail_closed(self) -> None:
        census_path = ROOT / "docs/handoff/2026-09-09-b098-ops-authority-census.md"
        baseline = census_path.read_text()
        issues = verifier._check_census(ROOT / "this-root-does-not-exist")
        self.assertTrue(any("census is missing" in issue for issue in issues))

        mutations = {
            "all-zero checkpoint": ("checkpoint_sha: \"aaa53b1e404b719dc04d60f34ca301039abb19ec\"", "checkpoint_sha: \"0000000000000000000000000000000000000000\""),
            "unrelated checkpoint": ("checkpoint_sha: \"aaa53b1e404b719dc04d60f34ca301039abb19ec\"", "checkpoint_sha: \"721e536619a487fda15db1a226941b12dc257a8a\""),
            "future timestamp": ("timestamp: \"2026-09-22T07:55:57Z\"", "timestamp: \"2999-01-01T00:00:00Z\""),
            "provenance mutation": ("provenance: \"AUTHORED\"", "provenance: \"UNTRUSTED\""),
            "object mutation": ("08fa5a6906ce4bd7895e0a75badac671651b2bb9", "0" * 40),
            "allowlist object mutation": ("dfd72d7f31980aa452bfd67628e635a769b3207f", "0" * 40),
            "frontmatter deletion": ("remote_status: \"ABSENT\"\n", ""),
            "remote status mutation": ("remote_status: \"ABSENT\"", "remote_status: \"PRESENT\""),
            "remote deletion": ("- `refs/tags/release-evidence-v1.0.0-GA`", ""),
        }
        for label, (needle, replacement) in mutations.items():
            with self.subTest(label=label):
                self.assertIn(needle, baseline)
                issues = verifier._check_census(ROOT, census_text=baseline.replace(needle, replacement, 1))
                self.assertTrue(issues, label)
        for length in (41, 63):
            with self.subTest(checkpoint_length=length):
                mutated = baseline.replace(
                    'checkpoint_sha: "aaa53b1e404b719dc04d60f34ca301039abb19ec"',
                    f'checkpoint_sha: "{"a" * length}"',
                    1,
                )
                self.assertTrue(verifier._check_census(ROOT, census_text=mutated))

        receipt_text = (ROOT / "evidence/owner-actions/B-098/release-governance-blocker-2026-09-09.json").read_text()
        for label, replacement in {
            "receipt census checkpoint drift": (
                'checkpoint_sha: "aaa53b1e404b719dc04d60f34ca301039abb19ec"',
                'checkpoint_sha: "' + "a" * 40 + '"',
            ),
            "receipt census capture drift": (
                'capture_scope: "current-tree"',
                'capture_scope: "historical-tree"',
            ),
        }.items():
            with self.subTest(label=label):
                needle, value = replacement
                mutated_census = baseline.replace(needle, value, 1)
                issues = verifier._check_governance_receipt(
                    ROOT, (), package_count=95, crate_dir_count=75, okf_count=173,
                    specs_schema_count=488, specs_yaml_only_count=11,
                    receipt_text=receipt_text, census_text=mutated_census,
                )
                self.assertTrue(issues, label)

    def test_signing_policy_deletion_and_each_schema_bypass_fail_closed(self) -> None:
        policy_path = ROOT / ".github/release-signing-policy.json"
        baseline = json.loads(policy_path.read_text())
        mutations = {
            "version mutation": lambda value: value.__setitem__("version", 2),
            "roles deletion": lambda value: value.pop("roles"),
            "extra role": lambda value: value["roles"].__setitem__("reviewer", {}),
            "owner fingerprint mutation": lambda value: value["roles"]["owner"].__setitem__("fingerprint", "0" * 40),
            "ops principal mutation": lambda value: value["roles"]["ops"].__setitem__("principal", "ops@example.test"),
            "ops field deletion": lambda value: value["roles"]["ops"].pop("fingerprint"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                mutated = deepcopy(baseline)
                mutate(mutated)
                issues = verifier._check_signing_policy(ROOT, policy_text=json.dumps(mutated))
                self.assertTrue(issues, label)

        issues = verifier._check_signing_policy(ROOT / "this-root-does-not-exist")
        self.assertTrue(any("policy is missing" in issue for issue in issues))

    def test_missing_population_guard_fails_closed(self) -> None:
        claude = (ROOT / "CLAUDE.md").read_text()
        with self.assertRaises(verifier.VerificationError):
            verifier.audit(ROOT, claude_text=claude.replace("**95 Rust packages**", "95 packages", 1))

    def test_duplicate_spec_population_guard_fails_closed(self) -> None:
        claude = (ROOT / "CLAUDE.md").read_text()
        census = "**490 full-schema + 11 YAML-only (501 total)"
        mutated = claude.replace(census, f"{census}\n{census}", 1)
        with self.assertRaises(verifier.VerificationError):
            verifier.audit(ROOT, claude_text=mutated)

    def test_cargo_metadata_package_ids_are_unique_and_well_formed(self) -> None:
        def mocked_metadata(packages: object):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"packages": packages}),
                stderr="",
            )

        cases = {
            "duplicate ids": [
                {"id": "path+first#1.0.0"},
                {"id": "path+first#1.0.0"},
            ],
            "missing id": [{"name": "first"}],
            "non-string id": [{"id": 1}],
            "non-object package": ["path+first#1.0.0"],
        }
        for label, packages in cases.items():
            with self.subTest(label=label), patch.object(
                verifier.subprocess, "run", return_value=mocked_metadata(packages)
            ):
                with self.assertRaises(verifier.VerificationError):
                    verifier.package_count(ROOT)

        unique = [
            {"id": "path+first#1.0.0"},
            {"id": "path+second#1.0.0"},
            {"id": "registry+https://github.com/rust-lang/crates.io-index#third@1.0.0"},
        ]
        with patch.object(
            verifier.subprocess, "run", return_value=mocked_metadata(unique)
        ):
            self.assertEqual(verifier.package_count(ROOT), len(unique))

    def test_cli_reports_open_without_mutating_refs(self) -> None:
        before = subprocess.check_output(["git", "show-ref", "--tags"], cwd=ROOT, text=True)
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=ROOT, text=True, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("B-098 open", completed.stdout)
        after = subprocess.check_output(["git", "show-ref", "--tags"], cwd=ROOT, text=True)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
