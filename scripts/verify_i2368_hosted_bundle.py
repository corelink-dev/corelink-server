#!/usr/bin/env python3
"""Fail-closed static proof for the exact 20-job #2368 hosted migration.

Workflow YAML is treated as inert text. This tool does not run job commands,
mutants, deployment steps, or any provider/repository write operation.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path


class ContractError(RuntimeError):
    pass


SCOPE = {
    ".github/workflows/mutation-nightly.yml": {
        "mutants": "ubuntu-24.04",
        "aggregate": "ubuntu-24.04",
    },
    ".github/workflows/mutation-pr.yml": {"mutants-diff": "ubuntu-24.04"},
    ".github/workflows/nightly.yml": {
        "tlc-extended": "macos-15-intel",
        "proptest-extended": "macos-15-intel",
        "fuzz-matrix": "macos-15-intel",
    },
    ".github/workflows/proptest-density-gate.yml": {
        "density-gate": "ubuntu-24.04",
    },
    ".github/workflows/region_pinning.yml": {
        "migration-check": "ubuntu-24.04",
        "clippy-and-existing-tests": "ubuntu-24.04",
        "proptest-30k": "ubuntu-24.04",
        "adversarial-tests": "ubuntu-24.04",
        "rb-region-leak-dry-run": "ubuntu-24.04",
        "workflow-yaml-smoke": "ubuntu-24.04",
        "region-pinning-gate": "ubuntu-24.04",
        "proptest-100k-nightly": "ubuntu-24.04",
    },
    ".github/workflows/tenant-path.yml": {
        "pr-gate": "ubuntu-24.04",
        "fuzz-smoke": "macos-15-intel",
        "fuzz-nightly": "macos-15-intel",
        "mutants-nightly": "macos-15-intel",
    },
    ".github/workflows/workspace-lint.yml": {
        "clippy-workspace": "macos-15-intel",
    },
}
TARGET_COUNT = 20
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8"
STABLE_SETUP = {
    (".github/workflows/mutation-pr.yml", "mutants-diff"),
    (".github/workflows/nightly.yml", "proptest-extended"),
    *((".github/workflows/region_pinning.yml", job) for job in (
        "clippy-and-existing-tests", "proptest-30k", "adversarial-tests", "proptest-100k-nightly"
    )),
    *((".github/workflows/tenant-path.yml", job) for job in ("pr-gate", "mutants-nightly")),
    (".github/workflows/workspace-lint.yml", "clippy-workspace"),
}
NIGHTLY_SETUP = {
    (".github/workflows/nightly.yml", "fuzz-matrix"),
    *((".github/workflows/tenant-path.yml", job) for job in ("fuzz-smoke", "fuzz-nightly")),
}
PACK_FILES = {
    *SCOPE,
    ".github/workflows/issue-2386-hosted-runner-contract.yml",
    "scripts/verify_i2368_hosted_bundle.py",
}
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
RUNNER_LINE = re.compile(r"^    runs-on:\s*(.*?)\s*(?:#.*)?$")
CHECKOUT = "uses: actions/checkout@"
SHA = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise ContractError(message)


def job_blocks(text: str, relative: str) -> tuple[list[str], dict[str, list[str]]]:
    lines = text.splitlines()
    try:
        start = lines.index("jobs:")
    except ValueError:
        fail(f"{relative}: missing jobs mapping")
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[start + 1 :]:
        match = JOB_HEADER.match(line)
        if match:
            current = match.group(1)
            if current in jobs:
                fail(f"{relative}: duplicate job {current}")
            jobs[current] = [line]
        elif current is not None:
            jobs[current].append(line)
    if not jobs:
        fail(f"{relative}: no jobs found")
    return lines[:start], jobs


def noncomment(lines: list[str]) -> list[str]:
    return [line.rstrip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def projection(
    lines: list[str], *, runner_mutable: bool, credentials_mutable: bool, setup_mutable: bool = False
) -> list[str]:
    skipped: set[int] = set()
    if setup_mutable:
        index = 0
        while index < len(lines):
            if "name: Install the workspace-pinned toolchain on this isolated hosted runner" in lines[index] or "name: Install the Darwin nightly toolchain on this isolated hosted runner" in lines[index]:
                indent = len(lines[index]) - len(lines[index].lstrip())
                end = next((cursor for cursor in range(index + 1, len(lines)) if lines[cursor].startswith(" " * indent + "- ")), len(lines))
                skipped.update(range(index, end))
                index = end
            else:
                index += 1
    result: list[str] = []
    for index, line in enumerate(lines):
        if index in skipped:
            continue
        if runner_mutable and RUNNER_LINE.match(line):
            result.append("    runs-on: <runner>")
        elif credentials_mutable and re.match(r"^\s+persist-credentials:\s*", line):
            continue
        elif credentials_mutable and line.strip() == "with:":
            indent = len(line) - len(line.lstrip())
            children = []
            for following in lines[index + 1 :]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                if following.strip() and not following.lstrip().startswith("#") and not following.strip().startswith("persist-credentials:"):
                    children.append(following)
            if not children:
                continue
            result.append(line.rstrip())
        elif line.strip() and not line.lstrip().startswith("#"):
            result.append(line.rstrip())
    return result


def checkout_steps(lines: list[str]) -> list[list[str]]:
    found: list[list[str]] = []
    for index, line in enumerate(lines):
        if CHECKOUT not in line:
            continue
        indent = len(line) - len(line.lstrip())
        step_indent = indent if line.lstrip().startswith("- uses:") else indent - 2
        end = len(lines)
        for cursor in range(index + 1, len(lines)):
            if lines[cursor].startswith(" " * step_indent + "- "):
                end = cursor
                break
        found.append(lines[index:end])
    return found


def validate_toolchain_setup(lines: list[str], relative: str, job: str) -> list[str]:
    steps: list[list[str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if "name: Install the workspace-pinned toolchain on this isolated hosted runner" not in line and "name: Install the Darwin nightly toolchain on this isolated hosted runner" not in line:
            index += 1
            continue
        indent = len(line) - len(line.lstrip())
        end = next((cursor for cursor in range(index + 1, len(lines)) if lines[cursor].startswith(" " * indent + "- ")), len(lines))
        steps.append(lines[index:end])
        index = end
    expected_kind = "stable" if (relative, job) in STABLE_SETUP else "nightly" if (relative, job) in NIGHTLY_SETUP else None
    if expected_kind is None:
        if steps:
            fail(f"{relative}:{job}: unexpected toolchain provisioning step")
        return []
    if len(steps) != 1:
        fail(f"{relative}:{job}: expected one pinned {expected_kind} toolchain setup")
    label = "workspace-pinned" if expected_kind == "stable" else "Darwin nightly"
    expected = [
        f"      - name: Install the {label} toolchain on this isolated hosted runner",
        f"        uses: {TOOLCHAIN_ACTION}",
        "        with:",
        "          toolchain: 1.91.1" if expected_kind == "stable" else "          toolchain: nightly-x86_64-apple-darwin",
    ]
    if expected_kind == "stable":
        expected.append("          components: clippy,rustfmt")
    if noncomment(steps[0]) != expected:
        fail(f"{relative}:{job}: hosted toolchain setup differs from the pinned prerequisite")
    return steps


def validate_candidate(root: Path) -> None:
    seen = 0
    nightly_extra = {"mutants-workspace"}
    for relative, expected in SCOPE.items():
        try:
            header, jobs = job_blocks((root / relative).read_text(encoding="utf-8"), relative)
        except OSError as error:
            fail(f"{relative}: unreadable: {error}")
        wanted = set(expected)
        if relative.endswith("/nightly.yml"):
            # The existing #1863 campaign job is outside #2368's closed 20-job
            # census. It must remain present and hosted, but is not migration scope.
            if not nightly_extra.issubset(jobs):
                fail(f"{relative}: missing separately-owned job {sorted(nightly_extra - jobs.keys())}")
        if not wanted.issubset(jobs):
            fail(f"{relative}: missing scoped jobs {sorted(wanted - jobs.keys())}")
        for job, expected_runner in expected.items():
            seen += 1
            block = jobs[job]
            runners = [match.group(1).strip() for line in block if (match := RUNNER_LINE.match(line))]
            if runners != [expected_runner]:
                fail(f"{relative}:{job}: expected runner {expected_runner!r}, got {runners}")
            checkouts = checkout_steps(block)
            for step in checkouts:
                if not any(re.fullmatch(r"\s+persist-credentials:\s*false\s*(?:#.*)?", line) for line in step):
                    fail(f"{relative}:{job}: checkout must set persist-credentials: false")
            validate_toolchain_setup(block, relative, job)
        if relative.endswith("/nightly.yml"):
            extra = jobs["mutants-workspace"]
            runner = [match.group(1).strip() for line in extra if (match := RUNNER_LINE.match(line))]
            if runner != ["ubuntu-latest"]:
                fail("nightly.yml:mutants-workspace changed; it is outside the #2368 migration scope")
    if seen != TARGET_COUNT:
        fail(f"closed #2368 census contains {seen} jobs, expected {TARGET_COUNT}")

    # This job has repository write authority. The static pack never runs it;
    # retain the protected-main dispatch guard and least-privilege permissions.
    _, mutation_jobs = job_blocks(
        (root / ".github/workflows/mutation-nightly.yml").read_text(encoding="utf-8"),
        ".github/workflows/mutation-nightly.yml",
    )
    aggregate = "\n".join(mutation_jobs["aggregate"])
    for token in (
        "github.repository_id == vars.CORELINK_SERVER_REPO_ID",
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        "github.ref_protected",
        "contents: write",
        "issues: write",
    ):
        if token not in aggregate:
            fail(f"mutation-nightly.yml:aggregate lost protected write guard {token!r}")


def tree_files(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        relative_paths = [Path(item.decode("utf-8")) for item in listed if item]
    except subprocess.CalledProcessError:
        # A temporary archive is also accepted for local checks; it contains
        # only the protected tree and therefore has no ignored runtime files.
        relative_paths = [path.relative_to(root) for path in root.rglob("*") if path.is_file()]
    for relative in relative_paths:
        path = root / relative
        relative = path.relative_to(root)
        if ".git" in relative.parts or "__pycache__" in relative.parts or path.suffix == ".pyc" or not path.is_file():
            continue
        result[relative.as_posix()] = path
    return result


def changed_paths(base_root: Path, candidate_root: Path) -> set[str]:
    base_files = tree_files(base_root)
    candidate_files = tree_files(candidate_root)
    paths = set(base_files) | set(candidate_files)
    return {
        relative
        for relative in paths
        if relative not in base_files
        or relative not in candidate_files
        or base_files[relative].read_bytes() != candidate_files[relative].read_bytes()
    }


def validate_immutable(base_root: Path, candidate_root: Path) -> None:
    changed = changed_paths(base_root, candidate_root)
    forbidden = changed - PACK_FILES
    if forbidden:
        fail(f"changed paths escape #2368/CI-pack boundary: {sorted(forbidden)}")
    missing = set(SCOPE) - changed
    if missing:
        fail(f"scoped workflow files were not changed: {sorted(missing)}")

    for relative, target_jobs in SCOPE.items():
        try:
            base_header, base_jobs = job_blocks((base_root / relative).read_text(encoding="utf-8"), relative)
            candidate_header, candidate_jobs = job_blocks((candidate_root / relative).read_text(encoding="utf-8"), relative)
        except OSError as error:
            fail(f"{relative}: unreadable during immutable comparison: {error}")
        if noncomment(base_header) != noncomment(candidate_header):
            fail(f"{relative}: workflow triggers, permissions, or top-level policy changed")
        if base_jobs.keys() != candidate_jobs.keys():
            fail(f"{relative}: job inventory changed")
        for job in base_jobs:
            is_target = job in target_jobs
            setup_mutable = (relative, job) in STABLE_SETUP or (relative, job) in NIGHTLY_SETUP
            if projection(base_jobs[job], runner_mutable=is_target, credentials_mutable=is_target) != projection(
                candidate_jobs[job], runner_mutable=is_target, credentials_mutable=is_target, setup_mutable=setup_mutable
            ):
                fail(f"{relative}:{job}: command or job semantics changed outside runner/checkout policy")


def assert_exact_head(root: Path, expected: str) -> None:
    if SHA.fullmatch(expected) is None:
        fail("expected head must be a full lowercase SHA")
    try:
        actual = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        fail(f"candidate HEAD could not be read: {error}")
    if actual != expected:
        fail(f"candidate checkout is {actual}, expected {expected}")


def fixture(root: Path, hosted: bool) -> None:
    for relative, jobs in SCOPE.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "name: fixture",
            "on:",
            "  pull_request:",
            "permissions:",
            "  contents: read",
            "jobs:",
        ]
        all_jobs = dict(jobs)
        if relative.endswith("/nightly.yml"):
            all_jobs["mutants-workspace"] = "ubuntu-latest"
        for job, desired in all_jobs.items():
            runner = desired if hosted or job == "mutants-workspace" else (
                "[self-hosted, mac, corelink-builder]" if desired == "macos-15-intel" else "corelink"
            )
            lines.extend((f"  {job}:", f"    runs-on: {runner}"))
            if job == "aggregate":
                lines.extend((
                    "    if: always() && github.repository_id == vars.CORELINK_SERVER_REPO_ID && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected",
                    "    permissions:",
                    "      contents: write",
                    "      issues: write",
                ))
            lines.extend(("    steps:", "      - uses: actions/checkout@0123456789012345678901234567890123456789"))
            if hosted and job in SCOPE[relative]:
                lines.extend(("        with:", "          persist-credentials: false"))
            kind = "stable" if (relative, job) in STABLE_SETUP else "nightly" if (relative, job) in NIGHTLY_SETUP else None
            if hosted and kind:
                label = "workspace-pinned" if kind == "stable" else "Darwin nightly"
                lines.extend((
                    f"      - name: Install the {label} toolchain on this isolated hosted runner",
                    f"        uses: {TOOLCHAIN_ACTION}",
                    "        with:",
                    "          toolchain: 1.91.1" if kind == "stable" else "          toolchain: nightly-x86_64-apple-darwin",
                ))
                if kind == "stable":
                    lines.append("          components: clippy,rustfmt")
            lines.extend(("      - run: echo safe", ""))
        target.write_text("\n".join(lines), encoding="utf-8")


def expect_rejected(callable_, description: str) -> None:
    try:
        callable_()
    except ContractError:
        return
    fail(f"negative control escaped: {description}")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        base = root / "base"
        candidate = root / "candidate"
        fixture(base, hosted=False)
        fixture(candidate, hosted=True)
        validate_candidate(candidate)
        validate_immutable(base, candidate)

        target = candidate / next(iter(SCOPE))
        original = target.read_text(encoding="utf-8")
        for runner in ("corelink", "[self-hosted, mac, corelink-builder]"):
            target.write_text(original.replace("runs-on: ubuntu-24.04", f"runs-on: {runner}", 1), encoding="utf-8")
            expect_rejected(lambda: validate_candidate(candidate), f"forbidden runner {runner}")
        target.write_text(original.replace("persist-credentials: false", "persist-credentials: true", 1), encoding="utf-8")
        expect_rejected(lambda: validate_candidate(candidate), "persisted checkout token")
        target.write_text(original.replace("echo safe", "echo write", 1), encoding="utf-8")
        expect_rejected(lambda: validate_immutable(base, candidate), "changed command")
        target.write_text(original, encoding="utf-8")

        target = candidate / ".github/workflows/mutation-nightly.yml"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace("pull_request:", "schedule:\n  - cron: '0 0 * * *'", 1), encoding="utf-8")
        expect_rejected(lambda: validate_immutable(base, candidate), "changed trigger")
        target.write_text(original.replace("contents: read", "contents: write", 1), encoding="utf-8")
        expect_rejected(lambda: validate_immutable(base, candidate), "changed top-level permissions")
        target.write_text(original.replace("github.ref_protected", "true", 1), encoding="utf-8")
        expect_rejected(lambda: validate_candidate(candidate), "weakened aggregate no-write guard")
        target.write_text(original, encoding="utf-8")
        aggregate_start = original.index("  aggregate:")
        target.write_text(
            original[:aggregate_start]
            + original[aggregate_start:].replace("echo safe", "echo altered", 1),
            encoding="utf-8",
        )
        expect_rejected(lambda: validate_immutable(base, candidate), "changed aggregate command")
        target.write_text(original, encoding="utf-8")

        target = candidate / ".github/workflows/nightly.yml"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace("runs-on: ubuntu-latest", "runs-on: corelink", 1), encoding="utf-8")
        expect_rejected(lambda: validate_candidate(candidate), "changed out-of-scope mutants-workspace runner")
        target.write_text(original, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-root", type=Path)
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--expected-head")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            if args.base_root or args.candidate_root or args.expected_head:
                fail("--self-test cannot be combined with candidate arguments")
            self_test()
        elif args.base_root and args.candidate_root and args.expected_head:
            assert_exact_head(args.candidate_root, args.expected_head)
            validate_candidate(args.candidate_root)
            validate_immutable(args.base_root, args.candidate_root)
        else:
            fail("pass --self-test or --base-root, --candidate-root, and --expected-head")
    except (ContractError, OSError, subprocess.CalledProcessError) as error:
        print(f"#2368 hosted bundle: FAIL: {error}", file=sys.stderr)
        return 1
    print("#2368 hosted bundle: PASS (20 jobs; YAML-only, no runtime mutations executed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
