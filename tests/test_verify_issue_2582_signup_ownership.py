"""Teeth for the #2582 signup-ownership change-scope gate.

The gate is closed-world: every changed path must be in ALLOWED. The one
declared exception is an ADDED, flat, lowercase changelog.d fragment, because
changelog-validate requires one on every feat:/fix: PR. These tests pin both
halves: the fragment is admitted, and every neighbouring shape stays refused.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = Path("scripts/verify_issue_2582_signup_ownership.py")
SELF = "tests/test_verify_issue_2582_signup_ownership.py"
CENSUS_SOURCES = (
    Path("crates/corelink-container/src/routes/signup.rs"),
    Path("crates/corelink-container/src/signup_d1_http.rs"),
    Path("apps/signup-worker/src/webhooks/clerk.ts"),
    Path("apps/signup-worker/src/webhooks/github_provision.ts"),
    Path("apps/signup-worker/src/signup_writer_ownership.ts"),
)
SIGNUP = CENSUS_SOURCES[0]
FRAGMENT = "changelog.d/2582-signup-scope-fragment.md"
EXISTING_FRAGMENT = Path("changelog.d/existing-fragment.md")
README = Path("changelog.d/README.md")

_spec = importlib.util.spec_from_file_location("verify_issue_2582_signup_ownership", REPO / SCRIPT)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


class ScopeUnitTests(unittest.TestCase):
    def test_added_flat_fragment_is_admitted_beside_a_signup_change(self) -> None:
        self.assertEqual(gate.out_of_scope_paths({str(SIGNUP), FRAGMENT}, {FRAGMENT}), [])

    def test_fragment_without_git_added_status_stays_out_of_scope(self) -> None:
        # Modified or deleted: changed, but not in the --diff-filter=A set.
        for added in (frozenset(), frozenset({str(SIGNUP)})):
            with self.subTest(added=sorted(added)):
                self.assertEqual(gate.out_of_scope_paths({str(SIGNUP), FRAGMENT}, added), [FRAGMENT])

    def test_neighbouring_shapes_stay_out_of_scope_even_when_added(self) -> None:
        for foreign in (
            "changelog.d/README.md",
            "changelog.d/Upper.md",
            "changelog.d/../x.md",
            "changelog.d/sub/x.md",
            "changelog.d/.hidden.md",
            "changelog.d/-dash.md",
            "changelog.d/x.md.txt",
            "changelog.d/x.md\n",
            "changelog.d/x.MD",
            "xchangelog.d/x.md",
            "docs/changelog.d/x.md",
            "CHANGELOG.md",
            "apps/signup-worker/src/lib/d1.ts",
            "crates/corelink-container/src/storage/staging_load_test_admission.rs",
        ):
            with self.subTest(foreign=foreign):
                self.assertEqual(gate.out_of_scope_paths({str(SIGNUP), foreign}, {foreign}), [foreign])

    def test_gate_admits_its_own_test_file(self) -> None:
        self.assertEqual(gate.out_of_scope_paths({SELF}, frozenset()), [])


class ScopeAgainstRealGitHistory(unittest.TestCase):
    """Run the shipped script exactly as CI does, against a real git history."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.git("init", "-q")
        for relative in (SCRIPT, *CENSUS_SOURCES):
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, self.root / relative)
        for relative in (EXISTING_FRAGMENT, README):
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.root / relative).write_text("### Fixed\n\n- base\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
             "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *args],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def candidate(self, *edits: Path, delete: tuple[Path, ...] = (), touch_signup: bool = True) -> str:
        self.git("checkout", "-q", "--detach", self.base)
        for relative in ((SIGNUP,) if touch_signup else ()) + edits:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("// candidate edit\n")
        for relative in delete:
            self.git("rm", "-q", str(relative))
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "candidate")
        return self.git("rev-parse", "HEAD")

    def run_gate(self, head: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": os.environ.get("PATH", ""), "EXPECTED_BASE": self.base, "EXPECTED_HEAD": head}
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT)],
            cwd=self.root, env=env, capture_output=True, text=True, check=False,
        )

    def assert_refused_naming(self, head: str, path: str) -> None:
        result = self.run_gate(head)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("out-of-scope changed paths", result.stderr)
        self.assertIn(path, result.stderr)

    def test_signup_change_alone_passes(self) -> None:
        result = self.run_gate(self.candidate())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("census: PASS", result.stdout)

    def test_signup_change_with_added_fragment_passes(self) -> None:
        result = self.run_gate(self.candidate(Path(FRAGMENT)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("census: PASS", result.stdout)

    def test_modified_or_deleted_fragment_and_changelog_md_are_refused(self) -> None:
        for edit in (EXISTING_FRAGMENT, README, Path("CHANGELOG.md"), Path("changelog.d/nested/x.md")):
            with self.subTest(edit=str(edit)):
                self.assert_refused_naming(self.candidate(edit), str(edit))
        with self.subTest(edit="delete existing fragment"):
            self.assert_refused_naming(self.candidate(delete=(EXISTING_FRAGMENT,)), str(EXISTING_FRAGMENT))

    def test_forbidden_shared_path_is_still_refused_beside_a_fragment(self) -> None:
        shared = "apps/signup-worker/src/lib/d1.ts"
        self.assert_refused_naming(self.candidate(Path(FRAGMENT), Path(shared)), shared)

    def test_empty_diff_is_a_named_failure_not_a_pass(self) -> None:
        result = self.run_gate(self.candidate(touch_signup=False))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("empty changed-path list", result.stderr)


if __name__ == "__main__":
    unittest.main()
