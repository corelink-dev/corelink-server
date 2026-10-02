#!/usr/bin/env python3
"""Teeth for the rust-affected-tests lane: its selector
(scripts/rust_affected_packages.py), its clippy debt baseline
(scripts/rust_clippy_debt.py) and the scripts its workflow runs.

Each selector case plants one shape the selector claims to handle in a synthetic
workspace and asserts the exact package set — or the named failure. The
fixture deliberately makes directory name differ from package name
(`crates/c-dir` is `pkg-c`), puts a member outside `crates/`, nests one
package inside another, and routes one member through an EXTERNAL crate chain,
because those are the shapes a path-regex selector gets wrong. The workflow's
marked shell steps run verbatim against a fake `cargo`, and its job timeouts
are held to the lane's time budget.

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
from collections import Counter
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
DEBT_SCRIPT = ROOT / "scripts" / "rust_clippy_debt.py"
_debt_spec = importlib.util.spec_from_file_location("rust_clippy_debt", DEBT_SCRIPT)
assert _debt_spec is not None and _debt_spec.loader is not None
rcd = importlib.util.module_from_spec(_debt_spec)
sys.modules["rust_clippy_debt"] = rcd
_debt_spec.loader.exec_module(rcd)

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

    def test_every_lane_file_named_by_path_selects_the_whole_workspace(self) -> None:
        # Named literally, not read back from LANE_FILES: dropping one from
        # that set must turn this red. The teeth file is among them because
        # the select job runs it against the workflow's own scripts.
        for path in (".github/workflows/rust-affected-tests.yml", "scripts/rust_affected_packages.py",
                     "scripts/rust_clippy_debt.py", "tests/test_rust_affected_packages.py",
                     ".github/rust-affected-tests/clippy-debt/corelink-server.txt"):
            with self.subTest(path=path):
                selection = self.select(path)
                self.assertEqual((selection.mode, selection.cargo_args()), (rap.MODE_WORKSPACE, ["--workspace"]))
                self.assertIn("this lane's own definition", selection.rows[0][2])

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
        self.assertEqual(values, {"mode": "packages", "count": "1", "packages": "pkg-c", "cargo_args": "-p pkg-c",
                                  "test_matrix": '{"include":[{"shard":"1-of-1","count":"1","cargo_args":"-p pkg-c"}]}'})

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
                         ".github/rust-affected-tests/clippy-debt/corelink-server.txt",
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


FAKE_CARGO = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_CARGO_LOG"
if [ "$1" = pkgid ]; then
  printf '%s\\n' "${FAKE_PKGID:-}"
  exit 0
fi
printf '%s\\n' "$FAKE_CARGO_OUT"
exit "$FAKE_CARGO_RC"
"""


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
        self.debt_dir = Path(self._tmp.name) / "clippy-debt"
        self.debt_dir.mkdir()
        self.regenerated_dir = Path(self._tmp.name) / "regenerated"

    def run_step(self, *, scope: str, debt: str, out: str = "", rc: int = 0,
                 pkgid: str = "") -> tuple[int, str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "CARGO_SCOPE": scope,
            "CLIPPY_DEBT": debt,
            "CLIPPY_DEBT_DIR": str(self.debt_dir),
            "CLIPPY_DEBT_REGENERATED": str(self.regenerated_dir),
            "SELECTED": "n",
            "FAKE_CARGO_LOG": str(self.log),
            "FAKE_CARGO_OUT": out,
            "FAKE_CARGO_RC": str(rc),
            "FAKE_PKGID": pkgid,
        }
        # From the repo root: the step calls scripts/rust_clippy_debt.py by
        # its repo-relative path, exactly as the job does after checkout.
        proc = subprocess.run(["bash", "-c", self.script], env=env, cwd=ROOT, capture_output=True, text=True,
                              check=False)
        return proc.returncode, proc.stdout + proc.stderr

    def cargo_calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


DEBT = "corelink-server\n"


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
SOURCE = "crates/corelink-container/src/x.rs"


def span(line: int, text: str, highlight: str, *, file_name: str = SOURCE, primary: bool = True,
         expansion: dict | None = None) -> dict:
    """A rustc JSON span over one source line, highlighting `highlight`."""
    start = text.index(highlight) + 1
    return {"file_name": file_name, "line_start": line, "line_end": line, "column_start": start,
            "column_end": start + len(highlight), "is_primary": primary,
            "text": [{"text": text, "highlight_start": start, "highlight_end": start + len(highlight)}],
            "expansion": expansion}


def macro(line: int, text: str, highlight: str, name: str = "check!") -> dict:
    return {"span": span(line, text, highlight), "macro_decl_name": name, "def_site_span": None}


def diagnostic(line: int = 1, text: str = "    let a = v[0];", highlight: str = "v[0]", *,
               code: str = "clippy::indexing_slicing", message: str = "indexing may panic",
               package_id: str = PKGID, level: str = "warning", spans: list | None = None,
               expansion: dict | None = None) -> str:
    if spans is None:
        spans = [span(line, text, highlight, expansion=expansion)]
    return json.dumps({
        "reason": "compiler-message",
        "package_id": package_id,
        "message": {"level": level, "message": message, "code": {"code": code} if code else None,
                    "spans": spans, "children": [],
                    "rendered": f"{level}: {message}\n  --> {SOURCE}:{line}\n"},
    })


ARTIFACT = json.dumps({"reason": "compiler-artifact", "package_id": PKGID, "target": {"name": "corelink_server"}})


def stream(*lines: str, artifact: bool = True, finished: bool | None = True) -> str:
    out = [ARTIFACT] if artifact else []
    out.extend(lines)
    if finished is not None:
        out.append(json.dumps({"reason": "build-finished", "success": finished}))
    return "\n".join(out)


A = dict(line=10, text="    let a = v[0];", highlight="v[0]")
B = dict(line=20, text="    let b = w[1..];", highlight="w[1..]", message="slicing may panic")
C = dict(line=30, text="    let c = parse(x).expect(\"ok\");", highlight="parse(x).expect(\"ok\")",
         code="clippy::expect_used", message="used `expect()` on a `Result` value")
NEW_UNWRAP = dict(line=40, text="    let d = parse(y).unwrap();", highlight="parse(y).unwrap()",
                  code="clippy::unwrap_used", message="used `unwrap()` on a `Result` value")


def baseline_of(*diagnostics: str) -> str:
    found = rcd.occurrences(stream(*diagnostics), PKGID)
    return rcd.render_baseline("corelink-server", Counter(o.identity for o in found))


def check(baseline: str, *diagnostics: str) -> tuple[bool, str]:
    found = rcd.occurrences(stream(*diagnostics), PKGID)
    ok, report = rcd.compare("corelink-server", found, rcd.read_baseline(baseline))
    return ok, "\n".join(report)


class DebtIdentity(unittest.TestCase):
    """scripts/rust_clippy_debt.py: debt is compared diagnostic by diagnostic."""

    def setUp(self) -> None:
        self.baseline = baseline_of(diagnostic(**A), diagnostic(**B), diagnostic(**C))

    def test_unchanged_debt_is_green(self) -> None:
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**B), diagnostic(**C))
        self.assertTrue(ok, report)
        self.assertIn("3 distinct diagnostics, baseline lists 3", report)

    def test_swapping_a_fixed_diagnostic_for_a_new_one_is_red(self) -> None:
        # The count-only ratchet passed this: 3 before, 3 after.
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**B), diagnostic(**NEW_UNWRAP))
        self.assertFalse(ok, report)
        self.assertIn("1 NEW diagnostic(s)", report)
        self.assertIn("parse(y).unwrap()", report)
        self.assertIn(f"{SOURCE}:40", report)
        self.assertIn("lost 1 diagnostic(s)", report)

    def test_growth_is_red(self) -> None:
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**B), diagnostic(**C),
                           diagnostic(**NEW_UNWRAP))
        self.assertFalse(ok, report)
        self.assertIn("1 NEW diagnostic(s)", report)
        self.assertNotIn("lost", report)

    def test_a_fixed_diagnostic_must_leave_the_baseline(self) -> None:
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**B))
        self.assertFalse(ok, report)
        self.assertIn("lost 1 diagnostic(s)", report)
        self.assertIn("parse(x).expect", report)

    def test_moving_a_diagnostic_to_another_line_is_the_same_diagnostic(self) -> None:
        moved = {**A, "line": 112}
        ok, report = check(self.baseline, diagnostic(**moved), diagnostic(**B), diagnostic(**C))
        self.assertTrue(ok, report)

    def test_reindenting_the_flagged_line_is_the_same_diagnostic(self) -> None:
        reindented = {**A, "text": "        let a = v[0];"}
        ok, report = check(self.baseline, diagnostic(**reindented), diagnostic(**B), diagnostic(**C))
        self.assertTrue(ok, report)

    def test_editing_the_flagged_code_is_a_new_diagnostic(self) -> None:
        edited = {**A, "text": "    let a = v[0] + 1;"}
        ok, report = check(self.baseline, diagnostic(**edited), diagnostic(**B), diagnostic(**C))
        self.assertFalse(ok, report)
        self.assertIn("1 NEW diagnostic(s)", report)

    def test_the_same_diagnostic_from_lib_and_lib_test_counts_once(self) -> None:
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**A), diagnostic(**B), diagnostic(**C))
        self.assertTrue(ok, report)

    def test_a_second_copy_of_identical_code_is_new(self) -> None:
        copy_of_a = {**A, "line": 11}
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**copy_of_a), diagnostic(**B),
                           diagnostic(**C))
        self.assertFalse(ok, report)
        self.assertIn("NEW x1 (occurs 2, baseline lists 1)", report)

    def test_two_invocations_of_one_macro_are_two_diagnostics(self) -> None:
        # Both share the primary span inside the macro body; only the call
        # site tells them apart.
        body = dict(line=5, text="        $v[0]", highlight="$v[0]")
        first = diagnostic(**body, expansion=macro(40, "    check!(a);", "check!(a)"))
        second = diagnostic(**body, expansion=macro(41, "    check!(b);", "check!(b)"))
        baseline = baseline_of(first)
        ok, report = check(baseline, first, second)
        self.assertFalse(ok, report)
        self.assertIn("check!(b)", report)

    def test_other_packages_notes_and_spanless_summaries_do_not_count(self) -> None:
        other = diagnostic(line=9, package_id="path+file:///w/crates/corelink-billing#0.1.2")
        summary = diagnostic(spans=[], message="3 warnings emitted", code="")
        note = diagnostic(line=11, level="note")
        not_primary = diagnostic(spans=[span(12, "    let z = v[0];", "v[0]", primary=False)])
        ok, report = check(self.baseline, diagnostic(**A), diagnostic(**B), diagnostic(**C), other, summary,
                           note, not_primary)
        self.assertTrue(ok, report)

    def test_machine_specific_paths_are_normalised(self) -> None:
        here = "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.1/src/de.rs"
        there = "/Users/me/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.1/src/de.rs"
        out = "/w/target/debug/build/corelink-server-0123456789abcdef/out/proto.rs"
        self.assertEqual(rcd._path(here), rcd._path(there))
        self.assertEqual(rcd._path(here), "<registry>/serde-1.0.1/src/de.rs")
        self.assertEqual(rcd._path(out), "<out:corelink-server>/proto.rs")
        self.assertEqual(rcd._path(SOURCE), SOURCE)

    def test_long_spans_stay_exact_but_bounded(self) -> None:
        long_a, long_b = "x" * 500 + "a", "x" * 500 + "b"
        self.assertNotEqual(rcd._bounded(long_a), rcd._bounded(long_b))
        self.assertLess(len(rcd._bounded(long_a)), rcd.TEXT_LIMIT + 40)

    def test_zero_debt_says_delete_the_entry(self) -> None:
        ok, report = check(rcd.BASELINE_HEADER.format(package="corelink-server"))
        self.assertFalse(ok, report)
        self.assertIn("delete its CLIPPY_DEBT entry", report)

    def test_rendered_baseline_round_trips(self) -> None:
        found = rcd.occurrences(stream(diagnostic(**A), diagnostic(**A, expansion=macro(3, "m!();", "m!()"))), PKGID)
        current = Counter(o.identity for o in found)
        self.assertEqual(rcd.read_baseline(rcd.render_baseline("p", current)), current)


class DebtFailClosed(unittest.TestCase):
    def test_truncated_stream_fails(self) -> None:
        with self.assertRaisesRegex(rcd.DebtError, "did not end in one successful build-finished"):
            rcd.occurrences(stream(diagnostic(**A), finished=None), PKGID)

    def test_failed_build_fails(self) -> None:
        with self.assertRaisesRegex(rcd.DebtError, "did not end in one successful build-finished"):
            rcd.occurrences(stream(diagnostic(**A), finished=False), PKGID)

    def test_a_package_clippy_never_checked_fails(self) -> None:
        with self.assertRaisesRegex(rcd.DebtError, "no compiler-artifact"):
            rcd.occurrences(stream(artifact=False), PKGID)

    def test_garbled_json_fails(self) -> None:
        with self.assertRaisesRegex(rcd.DebtError, "not JSON"):
            rcd.occurrences(stream("{not json"), PKGID)

    def test_hand_edited_baseline_fails(self) -> None:
        good = baseline_of(diagnostic(**A))
        entry = good.splitlines()[-1]
        for bad, reason in ((good.replace(entry, entry.replace(", ", ",  ", 1)), "canonical"),
                            (good.replace(entry, "[1, 2]"), "is not \\[code"),
                            (good.replace(entry, "{oops"), "not JSON")):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(rcd.DebtError, reason):
                    rcd.read_baseline(bad)

    def test_unsorted_baseline_fails(self) -> None:
        lines = baseline_of(diagnostic(**A), diagnostic(**C)).splitlines()
        entries = [line for line in lines if not line.startswith("#")]
        self.assertEqual(len(entries), 2)
        with self.assertRaisesRegex(rcd.DebtError, "not sorted"):
            rcd.read_baseline("\n".join(reversed(entries)))


class ClippyDebtStep(FakeCargoStep):
    """The workflow's baseline step, run verbatim against a fake cargo."""

    MARKER = "rust-affected-clippy-debt"

    def write_baseline(self, text: str) -> None:
        (self.debt_dir / "corelink-server.txt").write_text(text, encoding="utf-8")

    def run_debt(self, out: str, *, debt: str = DEBT, scope: str = "--workspace", rc: int = 0) -> tuple[int, str]:
        return self.run_step(scope=scope, debt=debt, out=out, rc=rc, pkgid=PKGID)

    def test_matching_baseline_is_green_and_capped_at_warn(self) -> None:
        self.write_baseline(baseline_of(diagnostic(**A), diagnostic(**B)))
        code, log = self.run_debt(stream(diagnostic(**A), diagnostic(**B)))
        self.assertEqual(code, 0, log)
        self.assertIn("2 distinct diagnostics, baseline lists 2", log)
        self.assertEqual(list(self.regenerated_dir.iterdir()), [])
        self.assertEqual(self.cargo_calls(), [
            "pkgid -p corelink-server",
            "clippy --locked --keep-going --all-targets -p corelink-server --message-format=json "
            "-- -D warnings --cap-lints warn"])

    def test_a_swap_is_red_and_leaves_the_matching_baseline_for_upload(self) -> None:
        self.write_baseline(baseline_of(diagnostic(**A), diagnostic(**B), diagnostic(**C)))
        code, log = self.run_debt(stream(diagnostic(**A), diagnostic(**B), diagnostic(**NEW_UNWRAP)))
        self.assertEqual(code, 1, log)
        self.assertIn("1 NEW diagnostic(s)", log)
        self.assertIn("corelink-server.txt in the clippy-debt-baselines artifact", log)
        regenerated = (self.regenerated_dir / "corelink-server.txt").read_text(encoding="utf-8")
        self.assertEqual(regenerated, baseline_of(diagnostic(**A), diagnostic(**B), diagnostic(**NEW_UNWRAP)))

    def test_missing_baseline_is_red(self) -> None:
        code, log = self.run_debt(stream())
        self.assertEqual(code, 1, log)
        self.assertIn("reviewed baseline", log)
        self.assertEqual(self.cargo_calls(), [])

    def test_a_hard_build_error_is_not_debt(self) -> None:
        self.write_baseline(baseline_of(diagnostic(**A)))
        code, log = self.run_debt(stream(diagnostic(**A)), rc=101)
        self.assertEqual(code, 1, log)
        self.assertIn("a hard error, not lint debt", log)

    def test_unselected_package_is_not_linted(self) -> None:
        self.write_baseline(baseline_of(diagnostic(**A)))
        code, log = self.run_debt(stream(), scope="-p corelink-hash")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.cargo_calls(), [])
        self.assertIn("not selected by this change", log)

    def test_malformed_entries_are_red(self) -> None:
        self.write_baseline(baseline_of(diagnostic(**A)))
        for entry in ("corelink-server 349\n", "Corelink-Server\n", "../corelink-server\n"):
            with self.subTest(entry=entry):
                code, log = self.run_debt(stream(), debt=entry)
                self.assertEqual(code, 1, log)
                self.assertIn("malformed CLIPPY_DEBT entry", log)


def workflow_env_block(name: str) -> list[str]:
    """The lines of a `<name>: |` block scalar in the workflow, stripped."""
    match = re.search(rf"^(?P<indent> +){name}: \|\n(?P<body>(?:(?P=indent)  \S.*\n)+)",
                      WORKFLOW.read_text(encoding="utf-8"), re.M)
    if match is None:
        raise ValueError(f"{name} block not found")
    return [line.strip() for line in match.group("body").splitlines()]


def workflow_scalar(name: str) -> str:
    matches = re.findall(rf"^ +{name}: (\S+)$", WORKFLOW.read_text(encoding="utf-8"), re.M)
    if len(matches) != 1:
        raise ValueError(f"expected one {name}, got {matches}")
    return matches[0]


class CommittedDebtLedger(unittest.TestCase):
    """CLIPPY_DEBT and the baseline directory name the same packages, and every
    committed baseline is canonical and non-empty."""

    def test_ledger_and_baselines_agree(self) -> None:
        packages = workflow_env_block("CLIPPY_DEBT")
        directory = ROOT / workflow_scalar("CLIPPY_DEBT_DIR")
        self.assertTrue(packages)
        for name in packages:
            self.assertRegex(name, r"^[a-z0-9][a-z0-9_-]*$")
        self.assertEqual(sorted(p.name for p in directory.iterdir()), sorted(f"{n}.txt" for n in packages))
        for name in packages:
            with self.subTest(package=name):
                baseline = rcd.read_baseline((directory / f"{name}.txt").read_text(encoding="utf-8"))
                self.assertGreater(sum(baseline.values()), 0)
                files = {identity[2] for identity in baseline}
                self.assertTrue(all(f.startswith("crates/") for f in files), files)


class Shards(Fixture):
    def test_workspace_is_dealt_round_robin_into_disjoint_shards(self) -> None:
        selection = self.select("rust-toolchain.toml")
        shards = selection.test_shards(3)
        self.assertEqual([s["shard"] for s in shards], ["1-of-3", "2-of-3", "3-of-3"])
        dealt = [s["cargo_args"].split()[1::2] for s in shards]
        self.assertTrue(all(arg == "-p" for s in shards for arg in s["cargo_args"].split()[0::2]))
        self.assertEqual(sorted(name for names in dealt for name in names), sorted(MEMBERS))
        self.assertEqual(dealt[0], selection.packages[0::3])
        self.assertEqual([s["count"] for s in shards], [str(len(names)) for names in dealt])

    def test_a_small_selection_gets_no_empty_shard(self) -> None:
        shards = self.select("crates/c-dir/src/lib.rs").test_shards(3)
        self.assertEqual(shards, [{"shard": "1-of-1", "count": "1", "cargo_args": "-p pkg-c"}])

    def test_an_empty_selection_has_no_shards(self) -> None:
        self.assertEqual(self.select("docs/readme.md").test_shards(3), [])

    def test_zero_shards_fails_closed(self) -> None:
        with self.assertRaisesRegex(rap.SelectionError, "at least 1"):
            self.select("crates/a/src/lib.rs").test_shards(0)

    def test_step_outputs_carry_the_matrix(self) -> None:
        metadata_path = self.root / "metadata.json"
        metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        outputs = self.root / "outputs.txt"
        environment = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        with mock.patch.dict(os.environ, environment, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = rap.main(["--metadata", str(metadata_path), "--step-outputs", str(outputs),
                             "--test-shards", "2", "--all", "manual"])
        self.assertEqual(code, 0)
        values = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())
        matrix = json.loads(values["test_matrix"])
        self.assertEqual([s["shard"] for s in matrix["include"]], ["1-of-2", "2-of-2"])


def job_blocks(text: str) -> dict[str, list[str]]:
    """Top-level jobs of the workflow, each as its own lines. Strict: the
    `jobs:` key must exist and every job must be a two-space-indented key."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "jobs:"]
    if len(starts) != 1:
        raise ValueError(f"expected one top-level `jobs:`, got {len(starts)}")
    blocks: dict[str, list[str]] = {}
    current = None
    for line in lines[starts[0] + 1:]:
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if header:
            current = header.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    if not blocks:
        raise ValueError("no jobs found")
    return blocks


def job_timeouts_and_needs(text: str) -> tuple[dict[str, int], dict[str, list[str]]]:
    timeouts: dict[str, int] = {}
    needs: dict[str, list[str]] = {}
    for job, body in job_blocks(text).items():
        found = [re.fullmatch(r"    timeout-minutes: (\d+)", line) for line in body]
        values = [int(m.group(1)) for m in found if m]
        if len(values) != 1:
            raise ValueError(f"job {job!r} must set exactly one job-level timeout-minutes, got {values}")
        timeouts[job] = values[0]
        listed = [re.fullmatch(r"    needs: (?:\[(.*)\]|(\S+))", line) for line in body]
        matched = [m for m in listed if m]
        needs[job] = ([n.strip() for n in (matched[0].group(1) or matched[0].group(2)).split(",")]
                      if matched else [])
    return timeouts, needs


def critical_path_minutes(text: str) -> int:
    timeouts, needs = job_timeouts_and_needs(text)

    def finish(job: str, seen: tuple[str, ...] = ()) -> int:
        if job in seen:
            raise ValueError(f"needs cycle through {job}")
        return timeouts[job] + max((finish(dep, seen + (job,)) for dep in needs[job]), default=0)

    return max(finish(job) for job in timeouts)


BUDGET_MINUTES = 25


class TimeBudget(unittest.TestCase):
    """The lane's worst case — every job on the critical path running to its
    timeout — stays under the 25-minute budget."""

    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_every_job_has_a_timeout_and_the_critical_path_fits(self) -> None:
        timeouts, needs = job_timeouts_and_needs(self.text)
        self.assertEqual(sorted(timeouts), ["clippy", "select", "test", "verdict"])
        self.assertEqual(needs["verdict"], ["select", "clippy", "test"])
        self.assertLess(critical_path_minutes(self.text), BUDGET_MINUTES)

    def test_the_test_job_is_sharded_by_the_select_job(self) -> None:
        body = "\n".join(job_blocks(self.text)["test"])
        self.assertIn("      matrix: ${{ fromJSON(needs.select.outputs.test_matrix) }}", body)
        self.assertIn("          CARGO_SCOPE: ${{ matrix.cargo_args }}", body)
        self.assertGreater(int(re.search(r"TEST_SHARDS: '(\d+)'", self.text).group(1)), 1)

    def test_teeth_a_long_timeout_breaks_the_budget(self) -> None:
        needle = "    timeout-minutes: 15\n    strategy:\n"
        self.assertEqual(self.text.count(needle), 1)
        planted = self.text.replace(needle, "    timeout-minutes: 60\n    strategy:\n", 1)
        self.assertGreaterEqual(critical_path_minutes(planted), BUDGET_MINUTES)

    def test_teeth_a_job_without_a_timeout_fails(self) -> None:
        needle = "    timeout-minutes: 2\n"
        self.assertEqual(self.text.count(needle), 1)
        with self.assertRaisesRegex(ValueError, "verdict"):
            job_timeouts_and_needs(self.text.replace(needle, "", 1))


if __name__ == "__main__":
    unittest.main()
