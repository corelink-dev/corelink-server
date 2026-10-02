#!/usr/bin/env python3
"""rust_affected_packages — choose the workspace packages a change can break.

Used by `.github/workflows/rust-affected-tests.yml` to decide which packages
get `cargo clippy` and `cargo test` on a pull request or a push to main.

WHAT IT SELECTS
---------------
1. Every changed path is mapped to the workspace package whose manifest
   directory contains it (longest directory wins). The package list comes from
   `cargo metadata` — never from a listing of `crates/`: 20 of the workspace's
   packages live under `tests/`, `tools/` and `apps/`, and directory name is
   not package name (`crates/corelink-container` is `corelink-server`).
2. `Cargo.lock` is compared ENTRY BY ENTRY with the base revision. Every
   `[[package]]` entry that is new or different seeds the packages that
   resolve it. A lockfile bump therefore selects exactly the members that can
   observe it, not the whole workspace and not nothing.
3. The root `Cargo.toml` is compared as parsed TOML, so comment-only edits
   select nothing. A change confined to `workspace.members` seeds the members
   it adds; any other change (dependencies, lints, profiles, patches) applies
   to every package and selects the whole workspace.
4. Toolchain and cargo configuration (`rust-toolchain.toml`,
   `.cargo/config.toml`, `clippy.toml`) and this lane's own definition (the
   workflow, its two scripts, their teeth file and the reviewed clippy debt
   baselines under `.github/rust-affected-tests/`) select the whole workspace.
5. The seeds are closed over the `cargo metadata` resolve graph: every package
   that depends on a seed through a normal or build edge, transitively, plus
   every package that dev-depends on anything in that closure (its tests
   compile against it). Dev edges are not followed further: a package's
   dev-dependencies are not part of what its own dependents build.

WHAT IT DOES NOT SEE — stated, not hidden
-----------------------------------------
* Files OUTSIDE every package directory that a package reads anyway: an
  `include_str!("../../../migrations/d1/…")`, or a test that opens a repo
  file at run time. Such a path selects nothing here. The construct has
  unbounded spellings, so this script does not pretend to detect it; dispatch
  the workflow (whole workspace) when such an input changes.
* A path inside a nested non-member manifest (the `fuzz/` crates excluded
  from the workspace) selects its ENCLOSING package — an over-selection, never
  a miss.

FAIL-CLOSED
-----------
Every way of not getting a list is a named failure, never an empty success:
unreadable metadata, zero workspace members, an empty change list, a
lockfile or manifest that will not parse, a lockfile entry `cargo metadata`
does not resolve, an added workspace member that is not a package. The
selection MAY legitimately be empty — a comment-only root-manifest edit — but
only when every changed path carries a named reason for selecting nothing,
and the report prints each one.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable

# This lane's own definition. A change here can alter what any package is
# checked with, so it proves itself against the whole workspace. The teeth file
# is part of the definition: the select job runs it, and it holds the
# workflow's marked scripts to their contract.
LANE_FILES = frozenset(
    {
        ".github/workflows/rust-affected-tests.yml",
        "scripts/rust_affected_packages.py",
        "scripts/rust_clippy_debt.py",
        "tests/test_rust_affected_packages.py",
    }
)

# The lane's reviewed data (the clippy debt baselines). Every path under it is
# part of the lane's definition too.
LANE_DIR = ".github/rust-affected-tests/"

# Configuration every package is compiled or linted under.
WORKSPACE_WIDE_FILES = frozenset(
    {
        "rust-toolchain.toml",
        "rust-toolchain",
        ".cargo/config.toml",
        ".cargo/config",
        "clippy.toml",
        ".clippy.toml",
    }
)

ROOT_MANIFEST = "Cargo.toml"
LOCKFILE = "Cargo.lock"

MODE_PACKAGES = "packages"
MODE_WORKSPACE = "workspace"
MODE_NONE = "none"


class SelectionError(RuntimeError):
    """The selection could not be computed; the lane must fail, not guess."""


@dataclass(frozen=True)
class Workspace:
    """The parts of `cargo metadata` the selection needs."""

    root: Path
    member_names: dict[str, str]  # package id -> package name
    member_dirs: tuple[tuple[str, str], ...]  # (repo-relative dir, id), longest first
    reverse_strong: dict[str, frozenset[str]]  # id -> ids depending via normal/build
    reverse_dev: dict[str, frozenset[str]]  # id -> ids dev-depending on it
    ids_by_name_version: dict[tuple[str, str], frozenset[str]]

    def owner_of(self, path: str) -> str | None:
        for directory, package_id in self.member_dirs:
            if path == directory or path.startswith(directory + "/"):
                return package_id
        return None

    def id_for_dir(self, directory: str) -> str | None:
        for member_dir, package_id in self.member_dirs:
            if member_dir == directory:
                return package_id
        return None


@dataclass
class Selection:
    mode: str
    packages: list[str]
    rows: list[tuple[str, str, str]] = field(default_factory=list)  # path, verdict, detail

    def cargo_args(self) -> list[str]:
        if self.mode == MODE_WORKSPACE:
            return ["--workspace"]
        args: list[str] = []
        for name in self.packages:
            args.extend(["-p", name])
        return args

    def test_shards(self, shards: int) -> list[dict[str, str]]:
        """Split the selection into at most `shards` disjoint `-p` lists for the
        test job's matrix. Round-robin over the sorted names: deterministic,
        every selected package in exactly one shard, no shard empty."""
        _require(shards >= 1, f"--test-shards must be at least 1, got {shards}")
        if self.mode == MODE_NONE:
            return []
        _require(bool(self.packages), f"mode {self.mode} selected no packages")
        count = min(shards, len(self.packages))
        out = []
        for index in range(count):
            names = self.packages[index::count]
            out.append({
                "shard": f"{index + 1}-of-{count}",
                "count": str(len(names)),
                "cargo_args": " ".join(arg for name in names for arg in ("-p", name)),
            })
        return out


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SelectionError(message)


def load_workspace(metadata: dict) -> Workspace:
    """Index `cargo metadata --format-version 1` output (WITH the resolve graph)."""
    _require(isinstance(metadata, dict), "cargo metadata output is not a JSON object")
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    resolve = metadata.get("resolve")
    root = metadata.get("workspace_root")
    _require(isinstance(packages, list) and packages, "cargo metadata lists no packages")
    _require(isinstance(members, list) and members, "cargo metadata lists ZERO workspace members — "
             "a selection over an empty workspace would pass while checking nothing")
    _require(isinstance(resolve, dict) and isinstance(resolve.get("nodes"), list) and resolve["nodes"],
             "cargo metadata has no resolve graph (was it run with --no-deps?) — "
             "the reverse-dependency closure cannot be computed without it")
    _require(isinstance(root, str) and root, "cargo metadata has no workspace_root")

    root_path = Path(root)
    by_id = {}
    for package in packages:
        _require(isinstance(package, dict) and isinstance(package.get("id"), str),
                 "cargo metadata has a package entry without an id")
        by_id[package["id"]] = package

    member_names: dict[str, str] = {}
    dirs: list[tuple[str, str]] = []
    for package_id in members:
        package = by_id.get(package_id)
        _require(package is not None, f"workspace member {package_id} has no package entry")
        name = package.get("name")
        manifest = package.get("manifest_path")
        _require(isinstance(name, str) and name, f"workspace member {package_id} has no name")
        _require(isinstance(manifest, str) and manifest, f"workspace member {name} has no manifest_path")
        relative = os.path.relpath(os.path.dirname(manifest), root)
        _require(not relative.startswith(".."), f"workspace member {name} lives outside the workspace root")
        member_names[package_id] = name
        dirs.append((PurePosixPath(*Path(relative).parts).as_posix(), package_id))
    dirs.sort(key=lambda item: len(item[0]), reverse=True)

    strong: dict[str, set[str]] = {}
    dev: dict[str, set[str]] = {}
    for node in resolve["nodes"]:
        _require(isinstance(node, dict) and isinstance(node.get("id"), str), "resolve node without an id")
        deps = node.get("deps")
        _require(isinstance(deps, list), f"resolve node {node['id']} has no deps list")
        for dep in deps:
            target = dep.get("pkg") if isinstance(dep, dict) else None
            _require(isinstance(target, str), f"resolve node {node['id']} has a dep without pkg")
            kinds = dep.get("dep_kinds")
            # A cargo too old to report dep_kinds gets the conservative answer:
            # every edge is a build edge, which can only over-select.
            kind_set = {k.get("kind") for k in kinds} if isinstance(kinds, list) and kinds else {None}
            if kind_set & {None, "build"}:
                strong.setdefault(target, set()).add(node["id"])
            if "dev" in kind_set:
                dev.setdefault(target, set()).add(node["id"])

    name_version: dict[tuple[str, str], set[str]] = {}
    for package in packages:
        key = (package.get("name"), package.get("version"))
        name_version.setdefault(key, set()).add(package["id"])

    return Workspace(
        root=root_path,
        member_names=member_names,
        member_dirs=tuple(dirs),
        reverse_strong={k: frozenset(v) for k, v in strong.items()},
        reverse_dev={k: frozenset(v) for k, v in dev.items()},
        ids_by_name_version={k: frozenset(v) for k, v in name_version.items()},
    )


def _parse_toml(text: str, label: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise SelectionError(f"{label} does not parse as TOML: {error}") from error


def _lock_entries(text: str, label: str) -> tuple[dict, dict[tuple, dict]]:
    data = _parse_toml(text, label)
    entries = data.get("package")
    _require(isinstance(entries, list) and entries,
             f"{label} has no [[package]] entries — a lockfile that resolves nothing is broken, not empty")
    index: dict[tuple, dict] = {}
    for entry in entries:
        _require(isinstance(entry, dict) and isinstance(entry.get("name"), str)
                 and isinstance(entry.get("version"), str),
                 f"{label} has a [[package]] entry without a name and version")
        index[(entry["name"], entry["version"], entry.get("source"))] = entry
    rest = {k: v for k, v in data.items() if k != "package"}
    return rest, index


def lockfile_seeds(base_text: str, head_text: str, workspace: Workspace) -> tuple[str, set[str], str]:
    """Return (verdict, seed ids, detail) for a Cargo.lock change."""
    base_rest, base = _lock_entries(base_text, "base Cargo.lock")
    head_rest, head = _lock_entries(head_text, "head Cargo.lock")
    if base_rest != head_rest:
        header_keys = sorted(k for k in set(base_rest) | set(head_rest) if base_rest.get(k) != head_rest.get(k))
        return MODE_WORKSPACE, set(), f"lockfile header changed ({', '.join(header_keys)})"
    changed = sorted(key for key, entry in head.items() if base.get(key) != entry)
    if not changed:
        return MODE_NONE, set(), "no [[package]] entry differs (removals only, or reordering)"
    seeds: set[str] = set()
    for name, version, _source in changed:
        ids = workspace.ids_by_name_version.get((name, version))
        _require(bool(ids), f"Cargo.lock entry {name} {version} is not in the cargo metadata resolve graph — "
                 "the lockfile and the metadata disagree, so no selection can be trusted")
        seeds |= ids
    shown = ", ".join(f"{n} {v}" for n, v, _ in changed[:8])
    more = f" (+{len(changed) - 8} more)" if len(changed) > 8 else ""
    return MODE_PACKAGES, seeds, f"{len(changed)} lock entr{'y' if len(changed) == 1 else 'ies'} changed: {shown}{more}"


def _differing_keys(base: dict, head: dict, prefix: str = "") -> list[str]:
    out = []
    for key in sorted(set(base) | set(head)):
        if base.get(key) == head.get(key):
            continue
        dotted = f"{prefix}{key}"
        if prefix == "" and key == "workspace" and isinstance(base.get(key), dict) and isinstance(head.get(key), dict):
            out.extend(_differing_keys(base[key], head[key], "workspace."))
        else:
            out.append(dotted)
    return out


def manifest_seeds(base_text: str, head_text: str, workspace: Workspace) -> tuple[str, set[str], str]:
    """Return (verdict, seed ids, detail) for a root Cargo.toml change."""
    base = _parse_toml(base_text, "base Cargo.toml")
    head = _parse_toml(head_text, "head Cargo.toml")
    if base == head:
        return MODE_NONE, set(), "parsed manifest is identical (comments or formatting only)"
    base_rest = copy.deepcopy(base)
    head_rest = copy.deepcopy(head)
    base_members = base_rest.get("workspace", {}).pop("members", [])
    head_members = head_rest.get("workspace", {}).pop("members", [])
    if base_rest != head_rest:
        keys = _differing_keys(base_rest, head_rest)
        return MODE_WORKSPACE, set(), f"workspace-wide manifest keys changed: {', '.join(keys)}"
    _require(isinstance(base_members, list) and isinstance(head_members, list),
             "workspace.members is not a list")
    added = sorted(set(head_members) - set(base_members))
    if not added:
        return MODE_NONE, set(), "workspace.members only lost or reordered entries"
    seeds = set()
    for member in added:
        normalized = PurePosixPath(member).as_posix()
        package_id = workspace.id_for_dir(normalized)
        _require(package_id is not None, f"workspace.members gained {member!r}, which cargo metadata does not "
                 "report as a package directory (a glob, or a path that is not a package)")
        seeds.add(package_id)
    return MODE_PACKAGES, seeds, f"workspace.members gained {', '.join(added)}"


def closure(seed_ids: Iterable[str], workspace: Workspace) -> set[str]:
    """Names of the members a change to `seed_ids` can break."""
    strong = set(seed_ids)
    stack = list(strong)
    while stack:
        current = stack.pop()
        for dependent in workspace.reverse_strong.get(current, ()):
            if dependent not in strong:
                strong.add(dependent)
                stack.append(dependent)
    tested = set(strong)
    for package_id in strong:
        tested |= workspace.reverse_dev.get(package_id, frozenset())
    return {workspace.member_names[i] for i in tested if i in workspace.member_names}


def _read(path: Path | None, label: str) -> str:
    _require(path is not None, f"{label} is required because that file changed")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise SelectionError(f"cannot read {label} at {path}: {error}") from error


def select(
    workspace: Workspace,
    changed_paths: list[str],
    *,
    base_manifest: Path | None = None,
    base_lock: Path | None = None,
) -> Selection:
    _require(bool(changed_paths), "the change list is EMPTY — the workflow only runs when Rust inputs "
             "changed, so an empty diff means the diff computation broke, not that nothing changed")
    rows: list[tuple[str, str, str]] = []
    seeds: set[str] = set()
    whole = False
    for path in changed_paths:
        if path in LANE_FILES or path.startswith(LANE_DIR):
            whole = True
            rows.append((path, MODE_WORKSPACE, "this lane's own definition changed; it proves itself on every package"))
        elif path in WORKSPACE_WIDE_FILES:
            whole = True
            rows.append((path, MODE_WORKSPACE, "toolchain/cargo configuration applies to every package"))
        elif path == LOCKFILE:
            verdict, ids, detail = lockfile_seeds(
                _read(base_lock, "--base-lock"), _read(workspace.root / LOCKFILE, "head Cargo.lock"), workspace)
            whole |= verdict == MODE_WORKSPACE
            seeds |= ids
            rows.append((path, verdict, detail))
        elif path == ROOT_MANIFEST:
            verdict, ids, detail = manifest_seeds(
                _read(base_manifest, "--base-manifest"), _read(workspace.root / ROOT_MANIFEST, "head Cargo.toml"),
                workspace)
            whole |= verdict == MODE_WORKSPACE
            seeds |= ids
            rows.append((path, verdict, detail))
        else:
            owner = workspace.owner_of(path)
            if owner is None:
                rows.append((path, MODE_NONE, "outside every package directory"))
            else:
                seeds.add(owner)
                rows.append((path, MODE_PACKAGES, f"inside package {workspace.member_names[owner]}"))

    if whole:
        return Selection(MODE_WORKSPACE, sorted(workspace.member_names.values()), rows)
    names = sorted(closure(seeds, workspace))
    if not names:
        # Legitimate ONLY because every row above carries its own reason; a
        # seed that resolved to no member would be a bug, so refuse it.
        _require(not seeds, "seeds were found but the closure named no workspace member")
        return Selection(MODE_NONE, [], rows)
    if set(names) == set(workspace.member_names.values()):
        # Same population, stated as `--workspace` rather than 95 `-p` flags.
        return Selection(MODE_WORKSPACE, names, rows)
    return Selection(MODE_PACKAGES, names, rows)


def select_all(workspace: Workspace, reason: str) -> Selection:
    return Selection(MODE_WORKSPACE, sorted(workspace.member_names.values()), [("*", MODE_WORKSPACE, reason)])


def render(selection: Selection, total_members: int) -> str:
    lines = ["| changed path | effect | why |", "|---|---|---|"]
    for path, verdict, detail in selection.rows:
        lines.append(f"| `{path}` | {verdict} | {detail} |")
    lines.append("")
    if selection.mode == MODE_NONE:
        lines.append(f"**Selected 0 of {total_members} packages** — every changed path above names why it "
                     "selects nothing, so clippy and tests are skipped by decision, not by accident.")
    else:
        scope = "the whole workspace" if selection.mode == MODE_WORKSPACE else "the affected closure"
        lines.append(f"**Selected {len(selection.packages)} of {total_members} packages ({scope}):** "
                     + ", ".join(f"`{n}`" for n in selection.packages))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--metadata", type=Path, required=True,
                        help="output of `cargo metadata --format-version 1 --locked` (with the resolve graph)")
    parser.add_argument("--changed", type=Path, help="NUL-separated changed paths (`git diff --name-only -z`)")
    parser.add_argument("--all", metavar="REASON", help="select the whole workspace, for this stated reason")
    parser.add_argument("--base-manifest", type=Path, help="root Cargo.toml at the base revision")
    parser.add_argument("--base-lock", type=Path, help="Cargo.lock at the base revision")
    parser.add_argument("--step-outputs", type=Path,
                        help="append mode/count/packages/cargo_args/test_matrix here")
    parser.add_argument("--test-shards", type=int, default=1,
                        help="split the test job's selection into at most this many matrix shards")
    args = parser.parse_args(argv)

    try:
        try:
            metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SelectionError(f"cannot read cargo metadata from {args.metadata}: {error}") from error
        workspace = load_workspace(metadata)
        if args.all:
            selection = select_all(workspace, args.all)
        else:
            _require(args.changed is not None, "pass --changed or --all")
            try:
                raw = args.changed.read_bytes()
            except OSError as error:
                raise SelectionError(f"cannot read the change list {args.changed}: {error}") from error
            paths = [p for p in raw.decode("utf-8").split("\0") if p]
            selection = select(workspace, paths, base_manifest=args.base_manifest, base_lock=args.base_lock)
        shards = selection.test_shards(args.test_shards)
    except SelectionError as error:
        print(f"::error title=rust-affected-tests selection::{error}", file=sys.stderr)
        return 1

    report = render(selection, len(workspace.member_names))
    if shards:
        report += "\n\n**Test shards:** " + "; ".join(
            f"{shard['shard']}: {shard['count']} package(s)" for shard in shards)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### rust-affected-tests selection\n\n" + report + "\n")
    if args.step_outputs:
        with args.step_outputs.open("a", encoding="utf-8") as handle:
            handle.write(f"mode={selection.mode}\n")
            handle.write(f"count={len(selection.packages)}\n")
            handle.write(f"packages={' '.join(selection.packages)}\n")
            handle.write(f"cargo_args={' '.join(selection.cargo_args())}\n")
            handle.write(f"test_matrix={json.dumps({'include': shards}, separators=(',', ':'))}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
