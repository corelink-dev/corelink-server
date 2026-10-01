#!/usr/bin/env python3
"""Focused positive and fail-closed mutation tests for #1648 build-only mode."""

from pathlib import Path
import unittest

from verify_i1648_verifier_build_only_workflow import WORKFLOW, verify


ROOT = Path(__file__).resolve().parents[1]


class BuildOnlyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / WORKFLOW).read_text()

    def test_current_workflow_satisfies_guard(self) -> None:
        verify(self.source)

    def test_rejects_open_ended_mode(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace("options: [full, build_only]", "options: [full, build_only, production]", 1))

    def test_rejects_unpinned_main_sha(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"$EXPECTED_SHA" == "$GITHUB_SHA"', '"$EXPECTED_SHA" != "$GITHUB_SHA"', 1))

    def test_rejects_non_main_ref(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"$GITHUB_REF" == "refs/heads/main"', '"$GITHUB_REF" == "refs/heads/release"', 1))

    def test_rejects_production_job_in_build_only(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace("inputs.mode != 'build_only'", "inputs.mode == 'full'", 1))

    def test_rejects_secret_in_provenance(self) -> None:
        with self.assertRaises(AssertionError):
            verify(self.source.replace('"workflow": os.environ["GITHUB_WORKFLOW"],', '"token": os.environ["CF_API_TOKEN"],', 1))


if __name__ == "__main__":
    unittest.main()
