#!/usr/bin/env python3
"""Teeth for scripts/rust_affected_packages.py (the rust-affected-tests selector).

Each case plants one shape the selector claims to handle in a synthetic
workspace and asserts the exact package set — or the named failure. The
fixture deliberately makes directory name differ from package name
(`crates/c-dir` is `pkg-c`), puts a member outside `crates/`, nests one
package inside another, and routes one member through an EXTERNAL crate chain,
because those are the shapes a path-regex selector gets wrong.

Run:  python3 -m unittest tests/test_rust_affected_packages.py -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Iterable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rust_affected_packages.py"
_spec = importlib.util.spec_from_file_location("rust_affected_packages", SCRIPT)
assert _spec is not None and _spec.loader is not None
rap = importlib.util.module_from_spec(_spec)
sys.modules["rust_affected_packages"] = rap
_spec.loader.exec_module(rap)

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

# name -> (dir, version)
MEMBERS = {
    "a": ("crates/a", "0.1.0"),
    "b": ("crates/b", "0.1.0"),
    "pkg-c": ("crates/c-dir", "0.1.0"),
    "d": ("tools/d", "0.1.0"),
    "e": ("crates/e", "0.1.0"),
    "f": ("crates/f", "0.1.0"),
    "g": ("crates/g", "0.1.0"),
    "a-sub": ("crates/a/sub", "0.1.0"),
}
EXTERNAL = {"serde": "1.0.1", "zlib": "1.2.0"}
# (dependent, dependency, kind) — kind None is a normal edge.
EDGES = [
    ("b", "a", None),
    ("pkg-c", "b", "build"),
    ("d", "b", "dev"),
    ("e", "d", None),
    ("f", "serde", None),
    ("serde", "zlib", None),
]

ROOT_MANIFEST = """\
[workspace]
resolver = "2"
members = [
    "crates/a",
    "crates/b",
    "crates/c-dir",
    "tools/d",
    "crates/e",
    "crates/f",
    "crates/g",
    "crates/a/sub",
]

[workspace.lints.clippy]
unwrap_used = "deny"
"""


def _member_id(root: Path, name: str) -> str:
    directory, version = MEMBERS[name]
    return f"path+file://{root / directory}#{name}@{version}"


def _ext_id(name: str) -> str:
    return f"{REGISTRY}#{name}@{EXTERNAL[name]}"


def _id(root: Path, name: str) -> str:
    return _member_id(root, name) if name in MEMBERS else _ext_id(name)


def build_metadata(root: Path) -> dict:
    packages = []
    for name, (directory, version) in MEMBERS.items():
        packages.append({"id": _member_id(root, name), "name": name, "version": version, "source": None,
                         "manifest_path": str(root / directory / "Cargo.toml")})
    for name, version in EXTERNAL.items():
        packages.append({"id": _ext_id(name), "name": name, "version": version, "source": REGISTRY,
                         "manifest_path": f"/registry/{name}-{version}/Cargo.toml"})
    nodes = {p["id"]: {"id": p["id"], "dependencies": [], "deps": [], "features": []} for p in packages}
    for dependent, dependency, kind in EDGES:
        node = nodes[_id(root, dependent)]
        node["dependencies"].append(_id(root, dependency))
        node["deps"].append({"name": dependency, "pkg": _id(root, dependency),
                             "dep_kinds": [{"kind": kind, "target": None}]})
    return {
        "packages": packages,
        "workspace_members": [_member_id(root, n) for n in MEMBERS],
        "workspace_default_members": [_member_id(root, n) for n in MEMBERS],
        "resolve": {"nodes": list(nodes.values()), "root": None},
        "workspace_root": str(root),
        "target_directory": str(root / "target"),
        "version": 1,
        "metadata": None,
    }


def lock_text(overrides: dict[str, str] | None = None, *, drop: tuple[str, ...] = (), reverse: bool = False) -> str:
    overrides = overrides or {}
    entries = []
    deps_of: dict[str, list[str]] = {}
    for dependent, dependency, _kind in EDGES:
        deps_of.setdefault(dependent, []).append(dependency)
    for name, (_directory, version) in MEMBERS.items():
        entries.append((name, overrides.get(name, version), None, deps_of.get(name, [])))
    for name, version in EXTERNAL.items():
        entries.append((name, overrides.get(name, version), REGISTRY, deps_of.get(name, [])))
    if reverse:
        entries.reverse()
    out = ["version = 4", ""]
    for name, version, source, deps in entries:
        if name in drop:
            continue
        out.append("[[package]]")
        out.append(f'name = "{name}"')
        out.append(f'version = "{version}"')
        if source:
            out.append(f'source = "{source}"')
        if deps:
            out.append("dependencies = [" + ", ".join(f'"{d}"' for d in deps) + "]")
        out.append("")
    return "\n".join(out)


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "Cargo.toml").write_text(ROOT_MANIFEST, encoding="utf-8")
        (self.root / "Cargo.lock").write_text(lock_text(), encoding="utf-8")
        self.metadata = build_metadata(self.root)
        self.ws = rap.load_workspace(self.metadata)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def base_file(self, name: str, text: str) -> Path:
        path = self.root / f"base-{name}"
        path.write_text(text, encoding="utf-8")
        return path

    def select(self, *paths: str, **kwargs) -> "rap.Selection":
        return rap.select(self.ws, list(paths), **kwargs)


class PathOwnership(Fixture):
    def test_closure_follows_normal_and_build_edges_and_stops_after_one_dev_hop(self) -> None:
        selection = self.select("crates/a/src/lib.rs")
        # b depends on a; pkg-c build-depends on b; d dev-depends on b.
        # e depends on d, but only d's TESTS see b, so e is out.
        self.assertEqual(selection.packages, ["a", "b", "d", "pkg-c"])
        self.assertEqual(selection.mode, rap.MODE_PACKAGES)

    def test_directory_name_is_not_package_name(self) -> None:
        selection = self.select("crates/c-dir/src/lib.rs")
        self.assertEqual(selection.packages, ["pkg-c"])
        self.assertEqual(selection.cargo_args(), ["-p", "pkg-c"])

    def test_member_outside_crates_is_owned(self) -> None:
        self.assertEqual(self.select("tools/d/src/main.rs").packages, ["d", "e"])

    def test_nested_package_wins_over_its_parent(self) -> None:
        self.assertEqual(self.select("crates/a/sub/src/lib.rs").packages, ["a-sub"])

    def test_directory_prefix_is_not_a_string_prefix(self) -> None:
        # crates/a must not own crates/ab/… — a bare startswith would.
        selection = self.select("crates/ab/src/lib.rs")
        self.assertEqual(selection.mode, rap.MODE_NONE)
        self.assertEqual(selection.rows[0][1], rap.MODE_NONE)

    def test_path_outside_every_package_selects_nothing_with_a_reason(self) -> None:
        selection = self.select("docs/readme.md")
        self.assertEqual((selection.mode, selection.packages), (rap.MODE_NONE, []))
        self.assertIn("outside every package directory", selection.rows[0][2])

    def test_unrelated_package_stays_out(self) -> None:
        self.assertNotIn("g", self.select("crates/a/src/lib.rs", "tools/d/x.rs").packages)

    def test_empty_change_list_is_a_failure_not_a_pass(self) -> None:
        with self.assertRaisesRegex(rap.SelectionError, "EMPTY"):
            self.select()


class WorkspaceWide(Fixture):
    def test_toolchain_pin_selects_the_whole_workspace(self) -> None:
        selection = self.select("rust-toolchain.toml")
        self.assertEqual(selection.mode, rap.MODE_WORKSPACE)
        self.assertEqual(len(selection.packages), len(MEMBERS))
        self.assertEqual(selection.cargo_args(), ["--workspace"])

    def test_cargo_config_selects_the_whole_workspace(self) -> None:
        self.assertEqual(self.select(".cargo/config.toml").mode, rap.MODE_WORKSPACE)

    def test_lane_definition_selects_the_whole_workspace(self) -> None:
        for path in sorted(rap.LANE_FILES):
            with self.subTest(path=path):
                self.assertEqual(self.select(path).mode, rap.MODE_WORKSPACE)

    def test_full_closure_is_spelled_as_workspace(self) -> None:
        paths = [f"{directory}/src/lib.rs" for directory, _ in MEMBERS.values()]
        self.assertEqual(self.select(*paths).cargo_args(), ["--workspace"])


class Lockfile(Fixture):
    def test_external_bump_selects_members_through_the_external_chain(self) -> None:
        base = self.base_file("lock", lock_text({"zlib": "1.1.0"}))
        selection = self.select("Cargo.lock", base_lock=base)
        # zlib changed; serde depends on zlib; f depends on serde.
        self.assertEqual(selection.packages, ["f"])
        self.assertIn("zlib 1.2.0", selection.rows[0][2])

    def test_member_entry_change_selects_that_member_and_its_dependents(self) -> None:
        base = self.base_file("lock", lock_text({"a": "0.0.9"}))
        self.assertEqual(self.select("Cargo.lock", base_lock=base).packages, ["a", "b", "d", "pkg-c"])

    def test_reordered_lockfile_selects_nothing_with_a_reason(self) -> None:
        base = self.base_file("lock", lock_text(reverse=True))
        selection = self.select("Cargo.lock", base_lock=base)
        self.assertEqual(selection.mode, rap.MODE_NONE)
        self.assertIn("no [[package]] entry differs", selection.rows[0][2])

    def test_header_change_selects_the_whole_workspace(self) -> None:
        base = self.base_file("lock", lock_text().replace("version = 4", "version = 3", 1))
        self.assertEqual(self.select("Cargo.lock", base_lock=base).mode, rap.MODE_WORKSPACE)

    def test_entry_unknown_to_metadata_fails_closed(self) -> None:
        (self.root / "Cargo.lock").write_text(lock_text({"zlib": "9.9.9"}), encoding="utf-8")
        base = self.base_file("lock", lock_text())
        with self.assertRaisesRegex(rap.SelectionError, "zlib 9.9.9 is not in the cargo metadata"):
            self.select("Cargo.lock", base_lock=base)

    def test_missing_base_lock_fails_closed(self) -> None:
        with self.assertRaisesRegex(rap.SelectionError, "--base-lock is required"):
            self.select("Cargo.lock")

    def test_lockfile_without_entries_fails_closed(self) -> None:
        base = self.base_file("lock", "version = 4\n")
        with self.assertRaisesRegex(rap.SelectionError, "no \\[\\[package\\]\\] entries"):
            self.select("Cargo.lock", base_lock=base)

    def test_unparseable_lockfile_fails_closed(self) -> None:
        base = self.base_file("lock", "[[package]\nname=")
        with self.assertRaisesRegex(rap.SelectionError, "does not parse"):
            self.select("Cargo.lock", base_lock=base)


class RootManifest(Fixture):
    def test_comment_only_edit_selects_nothing_with_a_reason(self) -> None:
        base = self.base_file("toml", "# an old comment\n" + ROOT_MANIFEST)
        selection = self.select("Cargo.toml", base_manifest=base)
        self.assertEqual(selection.mode, rap.MODE_NONE)
        self.assertIn("comments or formatting only", selection.rows[0][2])

    def test_added_member_is_seeded(self) -> None:
        base = self.base_file("toml", ROOT_MANIFEST.replace('    "crates/g",\n', ""))
        self.assertEqual(self.select("Cargo.toml", base_manifest=base).packages, ["g"])

    def test_added_member_that_is_not_a_package_fails_closed(self) -> None:
        (self.root / "Cargo.toml").write_text(
            ROOT_MANIFEST.replace('    "crates/g",\n', '    "crates/g",\n    "crates/ghost",\n'), encoding="utf-8")
        base = self.base_file("toml", ROOT_MANIFEST)
        with self.assertRaisesRegex(rap.SelectionError, "crates/ghost"):
            self.select("Cargo.toml", base_manifest=base)

    def test_lints_change_selects_the_whole_workspace(self) -> None:
        base = self.base_file("toml", ROOT_MANIFEST.replace('unwrap_used = "deny"', 'unwrap_used = "warn"'))
        selection = self.select("Cargo.toml", base_manifest=base)
        self.assertEqual(selection.mode, rap.MODE_WORKSPACE)
        self.assertIn("workspace.lints", selection.rows[0][2])

    def test_missing_base_manifest_fails_closed(self) -> None:
        with self.assertRaisesRegex(rap.SelectionError, "--base-manifest is required"):
            self.select("Cargo.toml")


class MetadataShape(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.metadata = build_metadata(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_resolve_graph_fails_closed(self) -> None:
        self.metadata["resolve"] = None
        with self.assertRaisesRegex(rap.SelectionError, "no resolve graph"):
            rap.load_workspace(self.metadata)

    def test_zero_members_fails_closed(self) -> None:
        self.metadata["workspace_members"] = []
        with self.assertRaisesRegex(rap.SelectionError, "ZERO workspace members"):
            rap.load_workspace(self.metadata)

    def test_edges_without_dep_kinds_are_treated_as_build_edges(self) -> None:
        for node in self.metadata["resolve"]["nodes"]:
            for dep in node["deps"]:
                dep.pop("dep_kinds")
        ws = rap.load_workspace(self.metadata)
        # Without kinds, d -> b is no longer known to be dev-only, so e is
        # pulled in: an over-selection, never a miss.
        self.assertEqual(rap.select(ws, ["crates/a/src/lib.rs"]).packages, ["a", "b", "d", "e", "pkg-c"])


class CommandLine(Fixture):
    def run_main(self, *argv: str) -> tuple[int, dict[str, str]]:
        metadata_path = self.root / "metadata.json"
        metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        outputs = self.root / "outputs.txt"
        outputs.write_text("", encoding="utf-8")
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        # Keep fixture reports out of the REAL job: no step-summary append, and
        # no `::error` line reaching the runner log as a live annotation.
        environment = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        with mock.patch.dict(os.environ, environment, clear=True), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            code = rap.main(["--metadata", str(metadata_path), "--step-outputs", str(outputs), *argv])
        values = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())
        return code, values

    def test_writes_step_outputs_from_a_nul_separated_change_list(self) -> None:
        changed = self.root / "changed.bin"
        changed.write_bytes(b"crates/c-dir/src/lib.rs\0docs/x.md\0")
        code, values = self.run_main("--changed", str(changed))
        self.assertEqual(code, 0)
        self.assertEqual(values, {"mode": "packages", "count": "1", "packages": "pkg-c", "cargo_args": "-p pkg-c"})

    def test_all_selects_the_workspace(self) -> None:
        code, values = self.run_main("--all", "manual dispatch")
        self.assertEqual((code, values["mode"], values["cargo_args"]), (0, "workspace", "--workspace"))
        self.assertEqual(values["count"], str(len(MEMBERS)))

    def test_failure_exits_non_zero_and_writes_no_outputs(self) -> None:
        changed = self.root / "changed.bin"
        changed.write_bytes(b"")
        code, values = self.run_main("--changed", str(changed))
        self.assertEqual((code, values), (1, {}))
        self.assertIn("the change list is EMPTY", self.stderr.getvalue())


WORKFLOW = ROOT / ".github" / "workflows" / "rust-affected-tests.yml"
_GLOB_LINE = re.compile(r"^\s*- '(?P<glob>[^']+)'(?:\s+#.*)?$")


def marked_globs(text: str, event: str) -> list[str]:
    """The `paths:` globs between `# rust-affected-paths:begin|end <event>`.

    Strict on purpose: a missing or repeated marker, a block that does not
    open with `paths:`, any line that is not a single-quoted list item, or an
    empty list is a ValueError — never a shorter list.
    """
    lines = text.splitlines()
    begins = [i for i, line in enumerate(lines) if line.strip() == f"# rust-affected-paths:begin {event}"]
    ends = [i for i, line in enumerate(lines) if line.strip() == f"# rust-affected-paths:end {event}"]
    if len(begins) != 1 or len(ends) != 1 or ends[0] < begins[0]:
        raise ValueError(f"expected exactly one begin/end marker pair for {event!r}, got {len(begins)}/{len(ends)}")
    body = [line for line in lines[begins[0] + 1:ends[0]] if line.strip()]
    if not body or body[0].strip() != "paths:":
        raise ValueError(f"the {event!r} block does not open with `paths:`")
    globs = []
    for line in body[1:]:
        match = _GLOB_LINE.match(line)
        if match is None:
            raise ValueError(f"unrecognised line in the {event!r} paths block: {line!r}")
        globs.append(match.group("glob"))
    if not globs:
        raise ValueError(f"the {event!r} paths block is EMPTY")
    return globs


def glob_matches(glob: str, path: str) -> bool:
    """GitHub path-filter semantics: `**` crosses `/`, `*` and `?` do not, and
    `**/x` also matches a root-level `x` (GitHub's own cheat sheet example)."""
    pattern, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            pattern, i = pattern + "(?:.*/)?", i + 3
        elif glob.startswith("**", i):
            pattern, i = pattern + ".*", i + 2
        elif glob[i] == "*":
            pattern, i = pattern + "[^/]*", i + 1
        elif glob[i] == "?":
            pattern, i = pattern + "[^/]", i + 1
        else:
            pattern, i = pattern + re.escape(glob[i]), i + 1
    return re.fullmatch(pattern, path) is not None


def uncovered(globs: list[str], paths: Iterable[str]) -> list[str]:
    return sorted(p for p in paths if not any(glob_matches(g, p) for g in globs))


# Every path the selector gives a whole-workspace or diff-specific meaning to
# must actually START the workflow, or that meaning is dead code.
MUST_TRIGGER = sorted(rap.LANE_FILES | rap.WORKSPACE_WIDE_FILES
                      | {rap.ROOT_MANIFEST, rap.LOCKFILE, "tests/test_rust_affected_packages.py",
                         "tools/cli/src/main.rs", "tests/e2e-dsr/Cargo.toml"})


class TriggerFilter(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_pull_request_and_push_filters_are_identical(self) -> None:
        self.assertEqual(marked_globs(self.text, "pull_request"), marked_globs(self.text, "push"))

    def test_every_selector_input_triggers_the_workflow(self) -> None:
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                self.assertEqual(uncovered(marked_globs(self.text, event), MUST_TRIGGER), [])

    def test_teeth_a_dropped_glob_is_named(self) -> None:
        planted = self.text.replace("      - 'rust-toolchain.toml'\n", "", 1)
        self.assertNotEqual(planted, self.text)
        self.assertEqual(uncovered(marked_globs(planted, "pull_request"), MUST_TRIGGER), ["rust-toolchain.toml"])

    def test_teeth_missing_marker_fails(self) -> None:
        planted = self.text.replace("# rust-affected-paths:end push", "# end", 1)
        with self.assertRaisesRegex(ValueError, "marker pair for 'push'"):
            marked_globs(planted, "push")

    def test_teeth_unrecognised_line_fails_instead_of_shrinking(self) -> None:
        planted = self.text.replace("      - 'Cargo.lock'\n", "      - Cargo.lock\n", 1)
        with self.assertRaisesRegex(ValueError, "unrecognised line"):
            marked_globs(planted, "pull_request")

    def test_glob_semantics(self) -> None:
        self.assertTrue(glob_matches("**/*.rs", "src/lib.rs"))
        self.assertTrue(glob_matches("**/clippy.toml", "clippy.toml"))
        self.assertTrue(glob_matches("**/Cargo.toml", "tools/sdks/go/Cargo.toml"))
        self.assertFalse(glob_matches("**/clippy.toml", "notclippy.toml"))
        self.assertTrue(glob_matches("crates/**", "crates/a/b/c.md"))
        self.assertFalse(glob_matches("rust-toolchain", "rust-toolchain.toml"))
        self.assertFalse(glob_matches("*.rs", "src/lib.rs"))


def marked_script(text: str, marker: str) -> str:
    """The shell between `# <marker>:begin` and `# <marker>:end`, dedented.

    Strict like `marked_globs`: a missing or repeated marker, or an empty body,
    is a ValueError — never a shorter script that would test nothing.
    """
    lines = text.splitlines()
    begins = [i for i, line in enumerate(lines) if line.strip() == f"# {marker}:begin"]
    ends = [i for i, line in enumerate(lines) if line.strip() == f"# {marker}:end"]
    if len(begins) != 1 or len(ends) != 1 or ends[0] < begins[0]:
        raise ValueError(f"expected exactly one {marker} begin/end pair, got {len(begins)}/{len(ends)}")
    body = textwrap.dedent("\n".join(lines[begins[0] + 1:ends[0]]))
    if not body.strip():
        raise ValueError(f"the {marker} script is EMPTY")
    return body + "\n"


KNOWN = "tests::b126_t1_files_remain_below_the_1000_line_ceiling"
ENTRY = f"corelink-server --bin=corelink-server {KNOWN}\n"
FAKE_CARGO = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_CARGO_LOG"
if [ "$1" = pkgid ]; then
  printf '%s\\n' "${FAKE_PKGID:-}"
  exit 0
fi
printf '%s\\n' "$FAKE_CARGO_OUT"
exit "$FAKE_CARGO_RC"
"""


class KnownFailures(unittest.TestCase):
    """Runs the workflow's strict expected-failure step verbatim against a fake
    `cargo`, one planted cargo outcome per case."""

    def setUp(self) -> None:
        self.script = marked_script(WORKFLOW.read_text(encoding="utf-8"), "rust-affected-xfail")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.bin = Path(self._tmp.name) / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text(FAKE_CARGO, encoding="utf-8")
        cargo.chmod(0o755)
        self.log = Path(self._tmp.name) / "cargo.log"

    def run_step(self, *, scope: str = "--workspace", ledger: str = ENTRY,
                 out: str = "", rc: int = 0) -> tuple[int, str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "CARGO_SCOPE": scope,
            "KNOWN_FAILING": ledger,
            "FAKE_CARGO_LOG": str(self.log),
            "FAKE_CARGO_OUT": out,
            "FAKE_CARGO_RC": str(rc),
        }
        proc = subprocess.run(["bash", "-c", self.script], env=env, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout + proc.stderr

    def cargo_calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def test_still_failing_is_green_and_runs_exactly_that_test(self) -> None:
        code, log = self.run_step(out=f"running 1 test\ntest {KNOWN} ... FAILED\n", rc=101)
        self.assertEqual(code, 0, log)
        self.assertIn("still fails", log)
        self.assertEqual(self.cargo_calls(), [
            f"test --locked -p corelink-server --bin=corelink-server -- --exact --color never {KNOWN}"])

    def test_now_passing_is_red_and_says_delete_the_entry(self) -> None:
        code, log = self.run_step(out=f"running 1 test\ntest {KNOWN} ... ok\n", rc=0)
        self.assertEqual(code, 1, log)
        self.assertIn(f"known failure '{KNOWN}' now PASSES", log)

    def test_compile_error_is_not_mistaken_for_the_failure(self) -> None:
        code, log = self.run_step(out="error[E0425]: cannot find value `x` in this scope\n", rc=101)
        self.assertEqual(code, 1, log)
        self.assertIn("did not run and fail (cargo exit 101)", log)

    def test_a_filter_that_matches_nothing_is_red(self) -> None:
        code, log = self.run_step(out="running 0 tests\n\ntest result: ok. 0 passed\n", rc=0)
        self.assertEqual(code, 1, log)
        self.assertIn("did not run and fail (cargo exit 0)", log)

    def test_another_test_failing_does_not_count(self) -> None:
        code, log = self.run_step(out=f"test {KNOWN}_and_more ... FAILED\n", rc=101)
        self.assertEqual(code, 1, log)
        self.assertIn("did not run and fail", log)

    def test_only_libtests_own_verdict_line_counts(self) -> None:
        # The verdict is the whole line; the same words quoted inside other
        # output (indented here) are not libtest saying this test failed.
        code, log = self.run_step(out=f"  test {KNOWN} ... FAILED\n", rc=101)
        self.assertEqual(code, 1, log)
        self.assertIn("did not run and fail", log)

    def test_failed_line_with_a_zero_exit_is_red(self) -> None:
        code, log = self.run_step(out=f"test {KNOWN} ... FAILED\n", rc=0)
        self.assertEqual(code, 1, log)
        self.assertIn("did not run and fail (cargo exit 0)", log)

    def test_unselected_package_is_not_run(self) -> None:
        code, log = self.run_step(scope="-p corelink-hash", out=f"test {KNOWN} ... ok\n", rc=0)
        self.assertEqual(code, 0, log)
        self.assertIn("corelink-server is not selected", log)
        self.assertEqual(self.cargo_calls(), [])

    def test_package_selected_by_dash_p_is_run(self) -> None:
        code, log = self.run_step(scope="-p corelink-hash -p corelink-server",
                                  out=f"test {KNOWN} ... ok\n", rc=0)
        self.assertEqual(code, 1, log)
        self.assertEqual(len(self.cargo_calls()), 1)

    def test_malformed_entry_is_red(self) -> None:
        code, log = self.run_step(ledger=f"corelink-server {KNOWN}\n")
        self.assertEqual(code, 1, log)
        self.assertIn("malformed KNOWN_FAILING entry", log)
        self.assertEqual(self.cargo_calls(), [])

    def test_empty_ledger_runs_nothing(self) -> None:
        code, log = self.run_step(ledger="\n")
        self.assertEqual(code, 0, log)
        self.assertIn("known failures run: 0", log)

    def test_teeth_missing_marker_fails(self) -> None:
        planted = WORKFLOW.read_text(encoding="utf-8").replace("# rust-affected-xfail:end", "# end", 1)
        with self.assertRaisesRegex(ValueError, "rust-affected-xfail begin/end pair"):
            marked_script(planted, "rust-affected-xfail")


class FakeCargoStep(unittest.TestCase):
    """Base: run one marked workflow script verbatim against the fake cargo."""

    MARKER = ""

    def setUp(self) -> None:
        self.script = marked_script(WORKFLOW.read_text(encoding="utf-8"), self.MARKER)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.bin = Path(self._tmp.name) / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text(FAKE_CARGO, encoding="utf-8")
        cargo.chmod(0o755)
        self.log = Path(self._tmp.name) / "cargo.log"

    def run_step(self, *, scope: str, debt: str, out: str = "", rc: int = 0,
                 pkgid: str = "") -> tuple[int, str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "CARGO_SCOPE": scope,
            "CLIPPY_DEBT": debt,
            "SELECTED": "n",
            "FAKE_CARGO_LOG": str(self.log),
            "FAKE_CARGO_OUT": out,
            "FAKE_CARGO_RC": str(rc),
            "FAKE_PKGID": pkgid,
        }
        proc = subprocess.run(["bash", "-c", self.script], env=env, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout + proc.stderr

    def cargo_calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


DEBT = "corelink-server 3\n"


class ClippyScope(FakeCargoStep):
    """The strict `-D warnings` run must leave out exactly the CLIPPY_DEBT packages."""

    MARKER = "rust-affected-clippy-scope"

    def strict_call(self) -> str:
        calls = [c for c in self.cargo_calls() if c.startswith("clippy ")]
        self.assertEqual(len(calls), 1, calls)
        return calls[0]

    def test_workspace_excludes_each_debt_package(self) -> None:
        code, log = self.run_step(scope="--workspace", debt=DEBT)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.strict_call(),
                         "clippy --locked --keep-going --all-targets --workspace --exclude corelink-server -- -D warnings")

    def test_dash_p_drops_only_the_debt_package(self) -> None:
        code, log = self.run_step(scope="-p corelink-hash -p corelink-server -p corelink-cli", debt=DEBT)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.strict_call(),
                         "clippy --locked --keep-going --all-targets -p corelink-hash -p corelink-cli -- -D warnings")

    def test_only_debt_packages_selected_runs_no_strict_lint(self) -> None:
        code, log = self.run_step(scope="-p corelink-server", debt=DEBT)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("every selected package carries declared CLIPPY_DEBT", log)

    def test_empty_debt_lints_the_scope_unchanged(self) -> None:
        code, log = self.run_step(scope="-p corelink-server", debt="\n")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.strict_call(),
                         "clippy --locked --keep-going --all-targets -p corelink-server -- -D warnings")

    def test_strict_lint_failure_fails_the_step(self) -> None:
        code, log = self.run_step(scope="--workspace", debt=DEBT, rc=101)
        self.assertEqual(code, 101, log)

    def test_empty_scope_is_refused(self) -> None:
        code, log = self.run_step(scope="", debt=DEBT)
        self.assertEqual(code, 1, log)
        self.assertIn("refusing to lint nothing", log)


PKGID = "path+file:///w/crates/corelink-container#corelink-server@0.1.2"


def diagnostic(line: int, *, package_id: str = PKGID, code: str = "clippy::indexing_slicing",
               primary: bool = True, level: str = "warning", text: str = "indexing may panic",
               invoked_at: int | None = None) -> str:
    spans = [{"file_name": "crates/corelink-container/src/x.rs", "line_start": line,
              "column_start": 5, "is_primary": primary}]
    rendered = f"{level}: {text} at x.rs:{line}\n"
    if invoked_at is not None:
        rendered += f"  in this macro invocation at x.rs:{invoked_at}\n"
    return json.dumps({
        "reason": "compiler-message",
        "package_id": package_id,
        "message": {"level": level, "message": text, "code": {"code": code}, "spans": spans,
                    "rendered": rendered},
    })


def stream(*lines: str) -> str:
    return "\n".join([*lines, json.dumps({"reason": "build-finished", "success": True})])


class ClippyDebt(FakeCargoStep):
    """The ratchet: distinct diagnostics of a CLIPPY_DEBT package must equal its entry."""

    MARKER = "rust-affected-clippy-debt"

    def run_debt(self, out: str, *, debt: str = DEBT, scope: str = "--workspace", rc: int = 0) -> tuple[int, str]:
        return self.run_step(scope=scope, debt=debt, out=out, rc=rc, pkgid=PKGID)

    def test_equal_count_is_green_and_capped_at_warn(self) -> None:
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(2), diagnostic(3)))
        self.assertEqual(code, 0, log)
        self.assertIn("3 distinct diagnostics, declared 3", log)
        self.assertEqual(self.cargo_calls(), [
            "pkgid -p corelink-server",
            "clippy --locked --keep-going --all-targets -p corelink-server --message-format=json "
            "-- -D warnings --cap-lints warn"])

    def test_growth_is_red_and_lists_the_diagnostics(self) -> None:
        code, log = self.run_debt(stream(*(diagnostic(n) for n in range(1, 5))))
        self.assertEqual(code, 1, log)
        self.assertIn("GREW from 3 to 4", log)
        self.assertIn("indexing may panic at x.rs:4", log)

    def test_shrinking_is_red_until_the_entry_is_lowered(self) -> None:
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(2)))
        self.assertEqual(code, 1, log)
        self.assertIn("lower its CLIPPY_DEBT entry to 2", log)

    def test_zero_debt_says_delete_the_entry(self) -> None:
        code, log = self.run_debt(stream())
        self.assertEqual(code, 1, log)
        self.assertIn("delete its CLIPPY_DEBT entry", log)

    def test_the_same_span_in_lib_and_lib_test_counts_once(self) -> None:
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(1), diagnostic(2), diagnostic(3)))
        self.assertEqual(code, 0, log)

    def test_two_macro_invocations_sharing_a_span_count_twice(self) -> None:
        # A new call of an existing macro is new debt even though the lint's
        # primary span (inside the macro body) is unchanged.
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(2), diagnostic(3, invoked_at=40),
                                         diagnostic(3, invoked_at=41)))
        self.assertEqual(code, 1, log)
        self.assertIn("GREW from 3 to 4", log)

    def test_other_packages_and_spanless_summaries_do_not_count(self) -> None:
        other = diagnostic(9, package_id="path+file:///w/crates/corelink-billing#0.1.2")
        summary = diagnostic(10, primary=False, text="3 warnings emitted")
        note = diagnostic(11, level="note")
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(2), diagnostic(3), other, summary, note))
        self.assertEqual(code, 0, log)

    def test_a_hard_build_error_is_not_debt(self) -> None:
        code, log = self.run_debt(stream(diagnostic(1), diagnostic(2), diagnostic(3)), rc=101)
        self.assertEqual(code, 1, log)
        self.assertIn("a hard error, not lint debt", log)

    def test_unselected_package_is_not_linted(self) -> None:
        code, log = self.run_debt(stream(), scope="-p corelink-hash")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("not selected by this change", log)

    def test_malformed_entries_are_red(self) -> None:
        for entry in ("corelink-server\n", "corelink-server 0\n", "corelink-server many\n", "corelink-server 3 x\n"):
            with self.subTest(entry=entry):
                code, log = self.run_debt(stream(), debt=entry)
                self.assertEqual(code, 1, log)
                self.assertIn("malformed CLIPPY_DEBT entry", log)

    def test_the_committed_ledger_is_well_formed(self) -> None:
        match = re.search(r"^      CLIPPY_DEBT: \|\n((?:        \S.*\n)+)", WORKFLOW.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(match, "CLIPPY_DEBT block not found")
        assert match is not None
        for line in match.group(1).splitlines():
            self.assertRegex(line.strip(), r"^[a-z0-9][a-z0-9_-]* [1-9][0-9]*$")


if __name__ == "__main__":
    unittest.main()
