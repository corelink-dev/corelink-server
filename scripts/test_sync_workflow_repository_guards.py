#!/usr/bin/env python3
"""Teeth for scripts/sync_workflow_repository_guards.py.

Every defect class the guard claims to catch is planted in a throwaway tree and
must fail naming the planted file; the clean tree must pass; and the real tree
is probed once with a planted name guard so the check is shown to engage the
actual workflow corpus, not only fixtures.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sync_workflow_repository_guards as guards  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

ROUTINE = """name: routine
on:
  pull_request:
permissions:
  contents: read
jobs:
  contract:
    if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    steps:
      - env:
          SERVER_REPOSITORY_MATCH: ${{ github.repository_id == vars.CORELINK_SERVER_REPO_ID }}
        run: test "$SERVER_REPOSITORY_MATCH" = true
"""

PRIVILEGED = """name: privileged
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  deploy:
    if: github.repository_id == '{literal}' && github.ref == 'refs/heads/main' && github.ref_protected
    environment: production
    runs-on: ubuntu-24.04
    steps:
      - run: echo deploy
"""

OIDC = """name: oidc
on:
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  sign:
    if: ${{{{ github.repository_id == '{literal}' }}}}
    runs-on: ubuntu-24.04
    steps:
      - run: echo sign
"""

FORK_CHECK = """name: fork
on:
  pull_request:
jobs:
  health:
    if: github.repository_id == vars.CORELINK_SERVER_REPO_ID && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.id == github.repository_id)
    runs-on: ubuntu-24.04
    steps:
      - run: echo ok
"""


class Tree:
    def __init__(self, files: dict[str, str], server_id: object | None = 4242) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for relative, text in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        if server_id is not None:
            config = self.root / "config/github-identity.json"
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(
                json.dumps({"schema": 1, "current": {"owner": "corelink-dev", "owner_id": 1,
                                                     "repos": {"server": {"name": "corelink-server", "id": server_id}}}}),
                encoding="utf-8",
            )

    def __enter__(self) -> Path:
        return self.root

    def __exit__(self, *exc: object) -> None:
        self._tmp.cleanup()


def clean_files(literal: str = "4242") -> dict[str, str]:
    return {
        ".github/workflows/routine.yml": ROUTINE,
        ".github/workflows/privileged.yml": PRIVILEGED.format(literal=literal),
        ".github/workflows/oidc.yml": OIDC.format(literal=literal),
        ".github/workflows/fork.yml": FORK_CHECK,
    }


class SyncWorkflowRepositoryGuardTests(unittest.TestCase):
    def assert_finding(self, report: guards.Report, path: str, fragment: str) -> None:
        matches = [f for f in report.findings if f.path == path and fragment in f.message]
        self.assertTrue(matches, f"expected a finding on {path} containing {fragment!r}; got {report.findings}")

    def test_clean_tree_passes_value_check_and_counts_both_forms(self) -> None:
        with Tree(clean_files()) as root:
            report = guards.check(root, pending={})
        self.assertEqual(report.findings, [])
        self.assertEqual(report.workflows, 4)
        self.assertEqual(report.routine, {".github/workflows/routine.yml": 2, ".github/workflows/fork.yml": 1})
        self.assertEqual(sorted(report.privileged), [".github/workflows/oidc.yml", ".github/workflows/privileged.yml"])

    def test_each_planted_defect_fails_and_names_the_file(self) -> None:
        cases = {
            "name guard": (ROUTINE.replace("github.repository_id == vars.CORELINK_SERVER_REPO_ID &&", "github.repository == 'acme/corelink-server' &&", 1), "repository name guard"),
            "event repository guard": (ROUTINE.replace("github.repository_id == vars.CORELINK_SERVER_REPO_ID &&", "github.event.repository.full_name == 'acme/x' &&", 1), "event repository literal guard"),
            "shell name guard": (ROUTINE.replace('test "$SERVER_REPOSITORY_MATCH" = true', 'test "$GITHUB_REPOSITORY" = acme/corelink-server'), "shell repository comparison"),
            "shell id guard": (ROUTINE.replace('test "$SERVER_REPOSITORY_MATCH" = true', 'test "${GITHUB_REPOSITORY_ID}" -eq 77'), "shell repository comparison"),
            "retired id": (ROUTINE + "# pinned to 1232040291\n", "retired repository ID 1232040291"),
            "retired clone id": (ROUTINE + "# pinned to 1380335483\n", "retired repository ID 1380335483"),
            "literal in routine": (ROUTINE.replace("vars.CORELINK_SERVER_REPO_ID &&", "'4242' &&", 1), "routine workflow pins a literal"),
            "unknown rhs": (ROUTINE.replace("vars.CORELINK_SERVER_REPO_ID &&", "inputs.repo_id &&", 1), "not a canonical guard"),
            "negated": (ROUTINE.replace("github.repository_id == vars", "github.repository_id != vars", 1), "negated repository-ID comparison"),
            "reversed": (ROUTINE.replace("github.repository_id == vars.CORELINK_SERVER_REPO_ID &&", "github.event_name == 'pull_request' && '4242' == github.repository_id &&", 1), "reversed repository-ID comparison"),
        }
        for label, (text, fragment) in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, ROUTINE, "the mutation did not apply")
                files = clean_files()
                files[".github/workflows/routine.yml"] = text
                with Tree(files) as root:
                    report = guards.check(root, pending={})
                self.assert_finding(report, ".github/workflows/routine.yml", fragment)

    def test_vars_form_in_privileged_workflows_fails(self) -> None:
        for name, template in (("privileged.yml", PRIVILEGED), ("oidc.yml", OIDC)):
            with self.subTest(workflow=name):
                files = clean_files()
                mutated = template.format(literal="4242").replace("'4242'", "vars.CORELINK_SERVER_REPO_ID")
                self.assertNotIn("'4242'", mutated)
                files[f".github/workflows/{name}"] = mutated
                with Tree(files) as root:
                    report = guards.check(root, pending={})
                self.assert_finding(report, f".github/workflows/{name}", "privileged workflow uses the routine vars guard")

    def test_value_check_refuses_missing_zero_invalid_and_mismatched_ids(self) -> None:
        cases = {"missing": (None, "is missing"), "zero": (0, "has not been read back"),
                 "bool": (True, "not a non-negative integer"), "string": ("4242", "not a non-negative integer")}
        for label, (server_id, fragment) in cases.items():
            with self.subTest(config=label):
                with Tree(clean_files(), server_id=server_id) as root:
                    report = guards.check(root, pending={})
                    structure = guards.check(root, structure_only=True, pending={})
                self.assert_finding(report, "config/github-identity.json", fragment)
                self.assertEqual(structure.findings, [])
        with Tree(clean_files(literal="0")) as root:
            report = guards.check(root, pending={})
        self.assert_finding(report, ".github/workflows/privileged.yml", "differs from config/github-identity.json")
        self.assert_finding(report, ".github/workflows/oidc.yml", "differs from config/github-identity.json")

    def test_write_renders_only_privileged_literals_and_refuses_unread_id(self) -> None:
        with Tree(clean_files(literal="0"), server_id=0) as root:
            changed, problems = guards.write(root, pending={})
            self.assertEqual(changed, 0)
            self.assertTrue(problems and "has not been read back" in problems[0])
            self.assertIn("== '0'", (root / ".github/workflows/privileged.yml").read_text())
        with Tree(clean_files(literal="0")) as root:
            before = (root / ".github/workflows/routine.yml").read_text()
            changed, problems = guards.write(root, pending={})
            self.assertEqual((changed, problems), (2, []))
            self.assertIn("github.repository_id == '4242'", (root / ".github/workflows/privileged.yml").read_text())
            self.assertIn("github.repository_id == '4242'", (root / ".github/workflows/oidc.yml").read_text())
            self.assertEqual((root / ".github/workflows/routine.yml").read_text(), before)
            self.assertEqual(guards.check(root, pending={}).findings, [])

    def test_ledger_rows_must_be_live_and_shrink(self) -> None:
        files = clean_files()
        files[".github/workflows/legacy.yml"] = ROUTINE.replace(
            "github.repository_id == vars.CORELINK_SERVER_REPO_ID &&", "github.repository == 'acme/corelink-server' &&", 1)
        with Tree(files) as root:
            self.assertEqual(guards.check(root, pending={".github/workflows/legacy.yml": "pending elsewhere"}).findings, [])
            self.assert_finding(guards.check(root, pending={}), ".github/workflows/legacy.yml", "repository name guard")
            stale = guards.check(root, pending={".github/workflows/routine.yml": "already migrated"})
            self.assert_finding(stale, ".github/workflows/routine.yml", "stale ledger entry")
            missing = guards.check(root, pending={".github/workflows/gone.yml": "deleted"})
            self.assert_finding(missing, ".github/workflows/gone.yml", "does not exist")
            blank = guards.check(root, pending={".github/workflows/legacy.yml": " "})
            self.assert_finding(blank, ".github/workflows/legacy.yml", "no reason")

    def test_empty_population_unparseable_and_guardless_trees_fail(self) -> None:
        with Tree({}, server_id=4242) as root:
            self.assert_finding(guards.check(root, pending={}), ".github/workflows", "population is empty")
        files = clean_files()
        files[".github/workflows/broken.yml"] = "jobs: [unclosed\n"
        with Tree(files) as root:
            self.assert_finding(guards.check(root, pending={}), ".github/workflows/broken.yml", "cannot classify workflow")
        guardless = {".github/workflows/plain.yml": "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: true\n"}
        with Tree(guardless) as root:
            self.assert_finding(guards.check(root, structure_only=True, pending={}), ".github/workflows", "found nothing to check")

    def test_real_tree_structure_is_clean_and_ledger_is_live(self) -> None:
        report = guards.check(ROOT, structure_only=True)
        self.assertEqual([str(f) for f in report.findings], [])
        self.assertGreater(report.workflows, 200)
        self.assertGreater(len(report.routine), 40)
        self.assertGreater(len(report.privileged), 20)

    def test_real_tree_mutations_engage_the_actual_corpus(self) -> None:
        routine_path = ".github/workflows/corelink-server.yml"
        privileged_path = ".github/workflows/admin-ui-deploy.yml"
        routine_text = (ROOT / routine_path).read_text(encoding="utf-8")
        privileged_text = (ROOT / privileged_path).read_text(encoding="utf-8")
        planted = routine_text.replace(
            "github.repository_id == vars.CORELINK_SERVER_REPO_ID",
            "github.repository == 'HuGR-dev/corelink-server'", 1)
        self.assertNotEqual(planted, routine_text, "the routine mutation did not apply")
        report = guards.check(ROOT, structure_only=True, overrides={routine_path: planted})
        self.assert_finding(report, routine_path, "repository name guard")
        # The literal is '0' until --write renders the read-back ID; match either.
        downgraded = re.sub(r"github\.repository_id == '[0-9]+'",
                            "github.repository_id == vars.CORELINK_SERVER_REPO_ID", privileged_text, count=1)
        self.assertNotEqual(downgraded, privileged_text, "the privileged mutation did not apply")
        report = guards.check(ROOT, structure_only=True, overrides={privileged_path: downgraded})
        self.assert_finding(report, privileged_path, "privileged workflow uses the routine vars guard")
        no_op = routine_text + "\n# trailing comment without identity\n"
        self.assertEqual(guards.check(ROOT, structure_only=True, overrides={routine_path: no_op}).findings, [])

    def test_cli_exit_codes(self) -> None:
        self.assertEqual(guards.main(["--structure-only"]), 0)


if __name__ == "__main__":
    unittest.main()
