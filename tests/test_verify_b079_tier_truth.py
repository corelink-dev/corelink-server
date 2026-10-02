"""Focused tests for the B-079 structural proof and its mutation teeth."""

from __future__ import annotations

import importlib.util
import io
import itertools
import string
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_b079_tier_truth.py"
SPEC = importlib.util.spec_from_file_location("verify_b079_tier_truth", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class B079VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = verifier.source_files()

    def test_current_contract_is_consistent(self) -> None:
        verifier.validate(self.files)

    def test_adversarial_mutations_are_rejected(self) -> None:
        verifier.mutation_checks(self.files)

    def test_third_value_cannot_hide_behind_matching_prose(self) -> None:
        docs = self.files["docs"]
        changed = docs.replace("| 1 000 | 5 000 |", "| 2 000 | 10 000 |", 1)
        mutated = {**self.files, "docs": changed}
        with self.assertRaises(verifier.VerificationError):
            verifier.validate(mutated)

    def test_rust_constant_bait_in_block_comment_cannot_shadow_live_value(self) -> None:
        rust = self.files["rust"]
        live = "pub const BUSINESS_REFILL_RPS: u32 = 1000;"
        changed = rust.replace(live, "pub const BUSINESS_REFILL_RPS: u32 = 2000;", 1)
        bait = "/* pub const BUSINESS_REFILL_RPS: u32 = 1000; */\n"
        changed = bait + changed
        self.assertEqual(verifier.rust_constant(changed, "BUSINESS_REFILL_RPS"), 2000)
        with self.assertRaises(verifier.VerificationError):
            verifier.validate({**self.files, "rust": changed})

    def test_html_commented_business_row_is_not_a_published_row(self) -> None:
        docs = self.files["docs"]
        marker = "| Business | `pro`, `max` | 1 000 | 5 000 | Production teams. `pro` and `max` share the Business bucket. |"
        self.assertEqual(docs.count(marker), 1)
        changed = docs.replace(marker, f"<!--\n{marker}\n-->", 1)
        with self.assertRaises(verifier.VerificationError) as failure:
            verifier.validate({**self.files, "docs": changed})
        self.assertIn("expected exactly one published Business rate row", str(failure.exception))

    def test_duplicate_live_constant_is_ambiguous_not_first_match_wins(self) -> None:
        rust = self.files["rust"]
        declaration = "pub const BUSINESS_REFILL_RPS: u32 = 1000;"
        changed = rust.replace(declaration, f"{declaration}\n{declaration}", 1)
        with self.assertRaises(verifier.VerificationError) as failure:
            verifier.rust_constant(changed, "BUSINESS_REFILL_RPS")
        self.assertIn("is ambiguous", str(failure.exception))

    def test_pricing_comment_bait_cannot_shadow_live_max_card(self) -> None:
        pricing = self.files["pricing"]
        changed = pricing.replace("usdMonthlyBase: 149,", "usdMonthlyBase: 150,", 1)
        bait = "/* max: {\n  retentionDays: 365,\n  usdMonthlyBase: 149,\n} */\n"
        changed = bait + changed
        self.assertEqual(verifier.pricing_max_contract(changed), (150, 365))
        with self.assertRaises(verifier.VerificationError):
            verifier.validate({**self.files, "pricing": changed})

    def test_rust_raw_string_fallback_bait_cannot_shadow_live_arm(self) -> None:
        rust = self.files["rust"]
        opening = "pub fn tier_for_billing_label(label: &str) -> Tier {"
        bait = (
            opening
            + '\n    let _bait = r#"\n        _ => Tier::Team,\n    "#;'
        )
        changed = rust.replace(opening, bait, 1)
        live = "        _ => Tier::Team,\n"
        prefix, suffix = changed.rsplit(live, 1)
        changed = prefix + "        _ => Tier::Enterprise,\n" + suffix
        with self.assertRaises(verifier.VerificationError):
            verifier.validate({**self.files, "rust": changed})

    def test_duplicate_live_string_fallback_is_ambiguous(self) -> None:
        rust = self.files["rust"]
        arm = "        _ => Tier::Team,\n"
        changed = rust.replace(arm, arm + arm, 1)
        with self.assertRaises(verifier.VerificationError) as failure:
            verifier.validate({**self.files, "rust": changed})
        self.assertIn("wildcard fallback is ambiguous", str(failure.exception))

    def test_overlong_malformed_source_is_rejected_before_structural_scans(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.validate({**self.files, "rust": "pub fn " + " " * 20_000})

    def test_legitimate_longer_line_within_cap_remains_supported(self) -> None:
        changed = {**self.files, "docs": self.files["docs"] + "\n" + " " * 200}
        verifier.validate(changed)

    def test_reader_rejects_oversized_bytes_before_decoding(self) -> None:
        class OversizedBytes(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                self.requested_size = size
                return b"x" * size

        source = OversizedBytes()
        with patch.object(Path, "open", return_value=source):
            with self.assertRaisesRegex(verifier.VerificationError, "exceeds bounded input size"):
                verifier.read(verifier.RUST_PATH)
        self.assertEqual(source.requested_size, verifier.MAX_PROOF_BYTES + 1)


def reference_label_arm(line: str) -> str | None:
    """Independent spec of the masked-arm shape (#1674), without regexes.

    Blanks and pipes only, then ``=>``, blanks, ``Tier::`` plus ASCII
    letters, blanks, one optional comma, blanks.  ``str.isspace`` is the
    same set as the regex ``\\s``.
    """
    head, arrow, tail = line.partition("=>")
    if not arrow or any(not (char.isspace() or char == "|") for char in head):
        return None
    tail = tail.lstrip()
    if not tail.startswith("Tier::"):
        return None
    letters = tail[len("Tier::"):]
    name_length = len(letters) - len(letters.lstrip(string.ascii_letters))
    if name_length == 0:
        return None
    rest = letters[name_length:].lstrip()
    if rest.startswith(","):
        rest = rest[1:].lstrip()
    return "Tier::" + letters[:name_length] if rest == "" else None


class B079LabelArmShapeTests(unittest.TestCase):
    def test_masked_arm_shape_matches_its_independent_spec_exhaustively(self) -> None:
        # While authoring #1674 the replaced regex and LABEL_ARM_SHAPE agreed
        # on 602,234 strings (fullmatch, match and search: spans and group);
        # this test also passes with the replaced pattern put back.
        tokens = (" ", "\t", "|", "=>", "=", ">", "Tier::Pro", "Tier::", "x", ",", "\n", "\x0b", "\u00a0")
        total = matched = 0
        disagreements = []
        for length in range(5):
            for parts in itertools.product(tokens, repeat=length):
                line = "".join(parts)
                found = verifier.LABEL_ARM_SHAPE.fullmatch(line)
                if (found and found.group(1)) != reference_label_arm(line):
                    disagreements.append(line)
                total += 1
                matched += found is not None
        self.assertEqual(disagreements, [])
        # 268 is also the replaced regex's positive count on this domain.
        self.assertEqual((total, matched), (30_941, 268))

    def test_real_and_masked_billing_arms_keep_their_tier(self) -> None:
        cases = (
            ('        "starter" | "team" => Tier::Team,', None),
            ("                  |        => Tier::Team,", "Tier::Team"),
            ("  |  |  => Tier::Business , ", "Tier::Business"),
            ("=>Tier::Free", "Tier::Free"),
            ("        _ => Tier::Team,", None),
            ("  | => Tier::Team,,", None),
            ("  | => Tier::Team2,", None),
            ("|" + " |" * 5 + "x", None),
        )
        for line, tier in cases:
            with self.subTest(line=line):
                found = verifier.LABEL_ARM_SHAPE.fullmatch(line)
                self.assertEqual(found and found.group(1), tier)
        body = verifier.function_body(verifier.source_files()["rust"], "tier_for_billing_label")
        self.assertEqual(verifier.rust_label_arm(body, "max"), "Tier::Business")
        self.assertEqual(verifier.rust_label_arm(body, "starter"), "Tier::Team")

    def test_pipe_run_redos_witness_finishes_in_bounded_time(self) -> None:
        # "|" + " |" * 20 + "x" took 1.4 s with the replaced regex and each
        # extra separator roughly doubled it.  Drive a line at the proof's
        # line cap through the real resolver (the only caller of the shape)
        # in a child process, so a regression fails on the timeout instead of
        # hanging the suite.
        program = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('b079_redos', sys.argv[1])\n"
            "verifier = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = verifier\n"
            "spec.loader.exec_module(verifier)\n"
            "line = '|' + ' |' * ((verifier.MAX_PROOF_LINE_CHARS - 2) // 2) + 'x'\n"
            "assert len(line) <= verifier.MAX_PROOF_LINE_CHARS\n"
            "try:\n"
            "    verifier.rust_label_arm(line + '\\n', 'max')\n"
            "except verifier.VerificationError as error:\n"
            "    print(error)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", program, str(SCRIPT)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["missing Rust billing mapping for 'max'"])


if __name__ == "__main__":
    unittest.main()
