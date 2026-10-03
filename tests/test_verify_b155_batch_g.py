"""Focused semantic tests for B-126's closed zero-oversized predicate."""

from __future__ import annotations

import copy
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def _current_line(target: str, pattern: str) -> str:
    """Return the live guard line; a rendered literal ID changes with config."""
    match = re.search(pattern, (ROOT / target).read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError(f"guard line not found in {target}: {pattern}")
    return match.group(0)


SCRIPT = ROOT / "scripts/verify_b155_batch_g.py"
SPEC = importlib.util.spec_from_file_location("b155_batch_g", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class B126BatchVerifierTests(unittest.TestCase):
    def test_baseline_population_is_green(self) -> None:
        verifier.verify_b126()

    def test_empty_population_is_red(self) -> None:
        with patch.object(verifier, "code_files", return_value=[]):
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b126()

    def test_synthetic_oversized_population_is_red(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.py"
            path.write_text("pass\n" * 1001, encoding="utf-8")
            with patch.object(verifier, "code_files", return_value=[path]):
                with self.assertRaises(verifier.CheckError):
                    verifier.verify_b126()

    def test_restored_at_limit_population_is_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.py"
            path.write_text("pass\n" * 1000, encoding="utf-8")
            with patch.object(verifier, "code_files", return_value=[path]):
                verifier.verify_b126()


class B110WorkflowVerifierTests(unittest.TestCase):
    def _mutated_text(self, target: str, old: str, new: str) -> object:
        original = verifier.text
        # A mutation whose anchor is absent would leave the file unchanged and
        # let the assertion pass on an unmutated tree: fail loudly instead.
        if old not in original(target):
            raise AssertionError(f"mutation anchor missing from {target}: {old!r}")

        def read(candidate: str) -> str:
            source = original(candidate)
            if candidate == target:
                source = source.replace(old, new, 1)
            return source

        return patch.object(verifier, "text", side_effect=read)

    def test_baseline_trust_and_capacity_are_green(self) -> None:
        verifier.verify_b110()

    def test_untrusted_trigger_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/coverage.yml",
            "  workflow_dispatch:\n",
            "  push:\n",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_unprotected_mutation_writer_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/mutation-nightly.yml",
            " && github.ref_protected",
            "",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_or_bypass_in_mutation_guard_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/mutation-nightly.yml",
            " && github.repository_id == vars.CORELINK_SERVER_REPO_ID",
            " || github.repository_id == vars.CORELINK_SERVER_REPO_ID",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_always_or_trust_predicate_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/mutation-nightly.yml",
            "if: always() && github.repository",
            "if: always() || github.repository",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_or_bypass_in_oidc_guard_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/cas_foundation.yml",
            " && github.ref_protected",
            " || github.ref_protected",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_multiline_or_bypass_in_every_trusted_guard_is_red(self) -> None:
        mutations = (
            (
                ".github/workflows/cas_foundation.yml",
                _current_line(
                    ".github/workflows/cas_foundation.yml",
                    r"if: github\.event_name == 'workflow_dispatch' && github\.repository_id == '[0-9]+' && "
                    r"github\.ref == 'refs/heads/main' && github\.ref_protected",
                ),
            ),
            (
                ".github/workflows/mutation-nightly.yml",
                "if: always() && github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected",
            ),
            (
                ".github/workflows/semgrep.yml",
                "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected",
            ),
        )
        for target, old in mutations:
            with self.subTest(target=target):
                mutation = self._mutated_text(
                    target,
                    old,
                    old + "\n      || github.event_name == 'workflow_dispatch'",
                )
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_folded_multiline_or_bypass_is_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        folded = (
            "if: >-\n"
            "      github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' &&\n"
            "      github.ref == 'refs/heads/main' && github.ref_protected ||\n"
            "      github.event_name == 'workflow_dispatch'"
        )
        mutation = self._mutated_text(target, old, folded)
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_yaml_encoded_or_bypass_variants_are_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        for encoded_or in (r"\x7c\x7c", r"\u007c\u007c", r"\U0000007c\U0000007c"):
            with self.subTest(encoded_or=encoded_or):
                new = (
                    'if: "github.repository_id == vars.CORELINK_SERVER_REPO_ID && '
                    "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
                    f"github.ref_protected {encoded_or} github.event_name == 'workflow_dispatch'\""
                )
                mutation = self._mutated_text(target, old, new)
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_yaml_backslash_newline_encoded_or_variants_are_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        head = (
            'if: "github.repository_id == vars.CORELINK_SERVER_REPO_ID && '
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
            "github.ref_protected "
        )
        tail = " github.event_name == 'workflow_dispatch'\""
        variants = (
            ("lf", "\\x7c", "\\x7c", "\n", "      "),
            ("crlf", "\\x7c", "\\x7c", "\r\n", "      "),
            ("multiple", "\\x7c", "\\x7c", "\n", "            "),
            ("indent", "\\x7c", "\\x7c", "\n", "                  "),
            ("unicode", "\\u007c", "\\u007c", "\n", "      "),
        )
        for name, first_pipe, second_pipe, newline, indentation in variants:
            with self.subTest(name=name):
                # YAML resolves `\\x7c\\` + physical newline + `\\x7c` (and
                # the corresponding Unicode form) to the forbidden `||`.
                continuation = (
                    head
                    + first_pipe
                    + "\\"
                    + newline
                    + indentation
                    + second_pipe
                    + tail
                )
                if name == "multiple":
                    continuation = (
                        head
                        + first_pipe
                        + "\\"
                        + newline
                        + indentation
                        + second_pipe
                        + "\\"
                        + newline
                        + indentation
                        + second_pipe
                        + tail
                    )
                mutation = self._mutated_text(target, old, continuation)
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_yaml_tag_and_anchor_encoded_or_variants_are_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        encoded = r"\x7c\x7c"
        expression = (
            '"github.repository_id == vars.CORELINK_SERVER_REPO_ID && '
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
            f"github.ref_protected {encoded} github.event_name == 'workflow_dispatch'\""
        )
        # !!str is actionlint-valid; anchors and aliases are rejected by the
        # actionlint version used for this repository but must fail closed here
        # as well if a parser accepts them in a future version.
        for prefix in ("!!str ", "&guard ", "!!str &guard "):
            with self.subTest(prefix=prefix):
                mutation = self._mutated_text(target, old, f"if: {prefix}{expression}")
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_yaml_block_scalar_tag_and_anchor_variants_are_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        encoded = r"\x7c\x7c"
        expression = (
            '"github.repository_id == vars.CORELINK_SERVER_REPO_ID && '
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
            f"github.ref_protected {encoded} github.event_name == 'workflow_dispatch'\""
        )
        for prefix in ("!!str ", "&guard ", "!!str &guard "):
            with self.subTest(prefix=prefix):
                folded = f"if: >-\n      {prefix}{expression}"
                mutation = self._mutated_text(target, old, folded)
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_yaml_actionlint_valid_anchor_alias_variants_are_red(self) -> None:
        target = ".github/workflows/semgrep.yml"
        old = "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected"
        encoded = r"\x7c\x7c"
        expression = (
            '"github.repository_id == vars.CORELINK_SERVER_REPO_ID && '
            "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
            f"github.ref_protected {encoded} github.event_name == 'workflow_dispatch'\""
        )
        # Anchoring a tagged scalar and consuming it through an alias is valid
        # YAML/actionlint syntax; the semantic if value is still untrusted.
        for declaration in ("&guard !!str", "!!str &guard"):
            with self.subTest(declaration=declaration):
                replacement = (
                    "env:\n"
                    f"      TRUST_GUARD: {declaration} {expression}\n"
                    "    if: *guard"
                )
                mutation = self._mutated_text(target, old, replacement)
                with mutation:
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()

    def test_ref_split_or_cancelling_heavy_build_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/cas_foundation.yml",
            'group: "corelink-heavy-cargo-build"',
            'group: "corelink-heavy-cargo-build-${{ github.ref }}"',
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_dead_write_permission_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/coverage.yml",
            "  contents: read\n",
            "  contents: read\n  pull-requests: write\n",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_semgrep_permission_expansion_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/semgrep.yml",
            "  contents: read\n",
            "  contents: read\n  actions: read\n",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_unguarded_corelink_job_with_write_permission_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/ffi-matrix-ci.yml",
            "  contents: read\n",
            "  contents: write\n",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_inline_write_permission_on_new_corelink_job_is_red(self) -> None:
        mutation = self._mutated_text(
            ".github/workflows/coverage.yml",
            "  coverage:\n",
            "  injected-write:\n"
            "    runs-on: corelink\n"
            "    permissions: { contents: write }\n"
            "    steps:\n"
            "      - run: echo injected\n"
            "  coverage:\n",
        )
        with mutation:
            with self.assertRaises(verifier.CheckError):
                verifier.verify_b110()

    def test_packet_load_bearing_fields_are_authoritative(self) -> None:
        fields = (
            ("owner", "owner"),
            ("status", "open"),
            ("action_type", "other_action"),
            ("procedure", ["RUN: noop", "RUN: noop"]),
            ("expected_postcondition", "B-110 is parked"),
            ("retry_and_rollback", "no rollback"),
            ("references", ["BACKLOG.md#B-110"]),
            (
                "inputs_and_credentials_boundary",
                {
                    "inputs": ["wrong input"],
                    "credentials": verifier.B110_INPUTS_AND_CREDENTIALS_BOUNDARY["credentials"],
                },
            ),
            (
                "inputs_and_credentials_boundary",
                {
                    "inputs": verifier.B110_INPUTS_AND_CREDENTIALS_BOUNDARY["inputs"],
                    "credentials": "wrong credential boundary",
                },
            ),
        )
        for field, value in fields:
            with self.subTest(field=field):
                packet = copy.deepcopy(verifier.packet_item("B-110"))
                packet[field] = value
                with patch.object(verifier, "packet_item", return_value=packet):
                    with self.assertRaises(verifier.CheckError):
                        verifier.verify_b110()


if __name__ == "__main__":
    unittest.main()
