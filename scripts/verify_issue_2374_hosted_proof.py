#!/usr/bin/env python3
"""Exact-baseline and local-denial proof for the #2374 runner migration.

The target workflows are inspected as inert YAML. Original write-bearing shell
commands and pinned actions run with disposable event data against local GitHub
CLI/REST mocks that reject every write. No target workflow is dispatched.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from verify_hosted_runner_migration_contract import ContractError, job_blocks


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    ".github/workflows/bot-pr-has-checks.yml": {"audit"},
    ".github/workflows/coverage.yml": {"coverage"},
    ".github/workflows/dependabot-auto-merge.yml": {"auto-merge"},
    ".github/workflows/dependabot-policy-trust-boundary.yml": {"trust-boundary-teeth"},
    ".github/workflows/dependabot-policy.yml": {"sentinel", "policy-gate"},
    ".github/workflows/lockfile-diff.yml": {"lockfile-diff"},
    ".github/workflows/permission-matrix.yml": {"permission-matrix"},
    ".github/workflows/pr-labels.yml": {"label", "size"},
    ".github/workflows/stale.yml": {"stale"},
    ".github/workflows/welcome-first-pr.yml": {"welcome"},
}
RUN_STEPS = {
    ".github/workflows/bot-pr-has-checks.yml": {"audit": {"automation-created open PRs are actually gated"}},
    ".github/workflows/coverage.yml": {"coverage": {"Run coverage (HTML + SUMMARY.txt)", "Render PR comment body", "Append step summary"}},
    ".github/workflows/dependabot-auto-merge.yml": {"auto-merge": {
        "Log Dependabot PR metadata", "Compute auto-merge eligibility", "Annotate major-update block",
        "Annotate non-security minor block", "Enable auto-merge (security-patch only)",
        "Audit log emission", "Annotate metric (structured log)"}},
    ".github/workflows/dependabot-policy-trust-boundary.yml": {"trust-boundary-teeth": {
        "Prepare hermetic checker interpreter (BASE tree)", "Statically reject B-133 control mutations (BASE checker)",
        "Prove host-toolchain channel guard (BASE tree)", "Prove Dependabot trust-boundary teeth (BASE tree)"}},
    ".github/workflows/dependabot-policy.yml": {
        "sentinel": {"Pass-through (non-dependabot PR)"},
        "policy-gate": {"Prepare hermetic checker interpreter (BASE tree)", "Assert trust-boundary wiring (BASE checker)",
                        "Verify fetched PR history (fail-closed)", "Prepare isolated Cargo policy tree (PR data only)",
                        "Use the workspace-pinned host toolchain (provisions nothing)", "Run cargo-deny licenses (fail-closed)",
                        "Banned-license signature scan (Cargo.lock)", "npm banned-license scan",
                        "Forbid skip-hook / skip-ci flags", "Forbid governance-file modifications",
                        "Verify required checks are present", "Policy-gate audit log"}},
    ".github/workflows/lockfile-diff.yml": {"lockfile-diff": {
        "Assert the workspace-pinned toolchain (rust-toolchain.toml)", "Generate Cargo.lock diff",
        "Run cargo-deny (license summary)", "Post PR comment with diff + cargo-deny summary"}},
    ".github/workflows/permission-matrix.yml": {"permission-matrix": {
        "Run mutation self-test", "Validate published claims against applied gates",
        "Install pytest (venv on system python3)", "Run validator regression suite"}},
    ".github/workflows/pr-labels.yml": {"label": set(), "size": {"Apply size:* label"}},
    ".github/workflows/stale.yml": {"stale": set()},
    ".github/workflows/welcome-first-pr.yml": {"welcome": {"Greet first-time contributor"}},
}
MUTATION_MARKERS = {
    "auto-merge": "gh pr merge --auto",
    "lockfile-diff": "Post PR comment with diff",
    "label": "actions/labeler@",
    "size": "gh pr edit",
    "stale": "actions/stale@",
    "welcome": "gh api",
    "coverage": "actions/upload-artifact@",
}
SHA = re.compile(r"[0-9a-f]{40}")
POLICY_CARGO_DENY_COMMAND = (
    'cargo deny --manifest-path "$POLICY_TREE/Cargo.toml" check --config "$DENY_CONFIG" licenses bans'
)
POLICY_CARGO_DENY_OLD_INVALID_COMMAND = (
    'cargo deny --manifest-path "$POLICY_TREE/Cargo.toml" --config "$DENY_CONFIG" check licenses bans'
)

SOCKET_GUARD_SOURCE = r'''
"use strict";
const net = require("node:net");
const nativeConnect = net.Socket.prototype.connect;
function blocked(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}
function portNumber(value) {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^[0-9]{1,5}$/.test(value)) return Number(value);
  return null;
}
net.Socket.prototype.connect = function (...args) {
  let target = args[0];
  let positional = args;
  if (Array.isArray(target) && args.length === 1 && target.length === 2 &&
      target[0] && typeof target[0] === "object" &&
      (typeof target[1] === "function" || target[1] === null)) {
    positional = target;
    target = positional[0];
  }
  let host;
  let port;
  if (typeof target === "number") {
    port = target;
    host = typeof positional[1] === "string" ? positional[1] : null;
  } else if (target && typeof target === "object" && !Array.isArray(target)) {
    port = portNumber(target.port);
    host = typeof target.host === "string" ? target.host :
      (typeof target.hostname === "string" ? target.hostname : null);
    if (target.path || target.socketPath) {
      blocked("I2374_ACTION_EGRESS_BLOCKED", "Unix socket destinations are outside the local API mock");
    }
  } else {
    blocked("I2374_ACTION_EGRESS_BLOCKED", "unrecognized Socket.connect arguments");
  }

  const configured = process.env.I2374_ACTION_ALLOWED_PORT;
  const allowedPort = /^[1-9][0-9]{0,4}$/.test(configured || "") ? Number(configured) : null;
  if (!allowedPort || allowedPort > 65535 || !port || port < 1 || port > 65535) {
    blocked("I2374_ACTION_EGRESS_BLOCKED_PORT", "local API mock port is missing or invalid");
  }
  if (port !== allowedPort || host !== "127.0.0.1") {
    blocked("I2374_ACTION_EGRESS_BLOCKED", `denied Socket.connect destination ${String(host)}:${port}`);
  }
  return nativeConnect.apply(this, positional);
};
'''


def fail(message: str) -> None:
    raise ContractError(message)


def read_workflows(root: Path) -> dict[str, str]:
    result = {}
    for path in FILES:
        try:
            result[path] = (root / path).read_text(encoding="utf-8")
        except OSError as error:
            fail(f"{path}: unreadable: {error}")
    return result


def root_section(text: str, key: str, *, required: bool = True) -> tuple[str, ...]:
    lines = text.splitlines()
    try:
        start = next(
            index for index, line in enumerate(lines)
            if line.startswith(key + ":") and not line.startswith((" ", "\t"))
        )
    except StopIteration:
        if required:
            fail(f"workflow missing {key!r} section")
        return ()
    selected = []
    for line in lines[start:]:
        if selected and line and not line[0].isspace() and not line.startswith("#"):
            break
        if line.lstrip().startswith("#") or not line.strip():
            continue
        selected.append(line.rstrip())
    return tuple(selected)


def job_setting(lines: list[str], setting: str) -> tuple[str, ...]:
    """Capture one job-level scalar, including folded `if:` continuations."""
    for index, line in enumerate(lines):
        match = re.match(r"^    " + re.escape(setting) + r":(?:\s*(.*))?$", line)
        if not match:
            continue
        result = [line.strip()]
        if match.group(1) in (None, "", "|", ">", "|-", ">-"):
            for continuation in lines[index + 1:]:
                if continuation.startswith("    ") and not continuation.startswith("      "):
                    break
                if continuation.strip() and not continuation.lstrip().startswith("#"):
                    result.append(continuation.strip())
        return tuple(result)
    return ()


def run_blocks(lines: list[str]) -> tuple[str, ...]:
    blocks = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not match:
            index += 1
            continue
        base_indent = len(match.group(1))
        declaration = match.group(2)
        if declaration not in {"|", ">-", "|-", ">"}:
            blocks.append(declaration)
            index += 1
            continue
        index += 1
        body = []
        while index < len(lines):
            current = lines[index]
            if current.strip() and len(current) - len(current.lstrip()) <= base_indent:
                break
            if current.strip() and not current.lstrip().startswith("#"):
                body.append(current.strip())
            index += 1
        blocks.append("\n".join(body))
    return tuple(blocks)


def commands_preserve_intent(relative: str, job: str, original: tuple[str, ...], candidate: tuple[str, ...]) -> bool:
    if relative == ".github/workflows/dependabot-policy.yml" and job == "policy-gate":
        original = tuple(
            block.replace(POLICY_CARGO_DENY_OLD_INVALID_COMMAND, POLICY_CARGO_DENY_COMMAND)
            for block in original
        )
    return original == candidate


def step_blocks(lines: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    active: str | None = None
    for line in lines:
        match = re.match(r"^      - name: (.+)$", line)
        if match:
            active = match.group(1)
            if active in result:
                fail(f"duplicate workflow step name: {active}")
            result[active] = [line]
        elif active is not None and (line.startswith("      - ") or (line and not line.startswith(" "))):
            active = None
        elif active is not None:
            result[active].append(line)
    return result


def step_value(lines: list[str], key: str, indent: int = 8) -> tuple[str, ...]:
    pattern = re.compile(r"^" + " " * indent + re.escape(key) + r":(?:\s*(.*))?$")
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue
        result = [line.strip()]
        if match.group(1) in (None, "", "|", ">", "|-", ">-"):
            for continuation in lines[index + 1:]:
                if continuation.strip() and len(continuation) - len(continuation.lstrip()) <= indent:
                    break
                if continuation.strip() and not continuation.lstrip().startswith("#"):
                    result.append(continuation.strip())
        return tuple(result)
    return ()


def action_reference(lines: list[str]) -> tuple[str, ...]:
    values = step_value(lines, "uses")
    if not values:
        return ()
    return (values[0].split("#", 1)[0].strip(),)


STEP_RENAMES = {}


def verify_step_semantics(relative: str, job: str, candidate: list[str], baseline: list[str], channel: str) -> None:
    old_steps, new_steps = step_blocks(baseline), step_blocks(candidate)
    allowed_added: set[str] = set()
    mapped_names: set[str] = set()
    for old_name, old_step in old_steps.items():
        key = (relative, job, old_name)
        new_name = STEP_RENAMES.get(key, old_name)
        new_step = new_steps.get(new_name)
        if new_step is None:
            fail(f"{relative}:{job}: original step {old_name!r} is missing")
        mapped_names.add(new_name)
        old_uses, new_uses = action_reference(old_step), action_reference(new_step)
        if old_uses != new_uses:
            fail(f"{relative}:{job}:{old_name}: action pin changed")
        if not commands_preserve_intent(relative, job, run_blocks(old_step), run_blocks(new_step)):
            fail(f"{relative}:{job}:{old_name}: original command changed")
        if step_value(old_step, "if") != step_value(new_step, "if"):
            fail(f"{relative}:{job}:{old_name}: step condition changed")
        if step_value(old_step, "env") != step_value(new_step, "env"):
            fail(f"{relative}:{job}:{old_name}: step environment changed")
        for setting in ("id", "shell", "working-directory", "timeout-minutes", "continue-on-error"):
            if step_value(old_step, setting) != step_value(new_step, setting):
                fail(f"{relative}:{job}:{old_name}: step {setting} changed")
        old_with = list(step_value(old_step, "with"))
        new_with = list(step_value(new_step, "with"))
        old_with = [line for line in old_with if line != "persist-credentials: false"]
        new_with = [line for line in new_with if line != "persist-credentials: false"]
        extra_toolchain = f"toolchain: {channel}"
        new_with = [line for line in new_with if line != extra_toolchain]
        if old_with == ["with:"]:
            old_with = []
        if new_with == ["with:"]:
            new_with = []
        if old_with != new_with:
            fail(f"{relative}:{job}:{old_name}: action inputs changed")
    unexpected = set(new_steps) - mapped_names - allowed_added
    if unexpected:
        fail(f"{relative}:{job}: unexpected new workflow steps: {sorted(unexpected)}")


def verify_baseline(candidate: Path, baseline: Path) -> None:
    """Reject changes to event, permission, serialization, or command semantics."""
    old_coverage = (baseline / "scripts/coverage.sh").read_text(encoding="utf-8")
    new_coverage = (candidate / "scripts/coverage.sh").read_text(encoding="utf-8")
    unsupported = "cargo llvm-cov report --workspace --summary-only $COV_FLAGS"
    supported = "cargo llvm-cov report --summary-only $COV_FLAGS"
    nested_html_output = '--output-dir "$COV_OUT/html" $COV_FLAGS'
    canonical_html_output = '--output-dir "$COV_OUT" $COV_FLAGS'
    expected_coverage = old_coverage.replace(unsupported, supported, 1).replace(
        nested_html_output, canonical_html_output, 1
    )
    coverage_already_canonical = (
        old_coverage == new_coverage
        and unsupported not in old_coverage
        and supported in old_coverage
        and canonical_html_output in old_coverage
    )
    if not coverage_already_canonical and (
        old_coverage.count(unsupported) != 1
        or old_coverage.count(nested_html_output) != 1
        or new_coverage != expected_coverage
    ):
        fail("scripts/coverage.sh must contain only the authorized report and canonical HTML output fixes")

    allowed_paths = set(FILES) | {
        ".github/workflows/issue-2374-hosted-policy-proof.yml",
        "scripts/verify_issue_2374_hosted_proof.py",
        "scripts/coverage.sh",
        "scripts/test_coverage_summary_command.py",
        "scripts/test_dependabot_policy_trust_boundary.sh",
        "crates/corelink-container/tests/signup_pilot_live_d1.rs",
    }
    git_root = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    if git_root.returncode == 0:
        baseline_sha = subprocess.run(
            ["git", "-C", str(baseline), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        changed = set(subprocess.run(
            ["git", "-C", str(candidate), "diff", "--name-only", baseline_sha, "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines())
        unlisted = changed - allowed_paths
        if unlisted:
            fail(f"change escaped authorized #2374 paths: {sorted(unlisted)}")
    for relative, expected_jobs in FILES.items():
        candidate_text = (candidate / relative).read_text(encoding="utf-8")
        baseline_text = (baseline / relative).read_text(encoding="utf-8")
        for section in ("name", "on", "permissions"):
            if root_section(candidate_text, section) != root_section(baseline_text, section):
                fail(f"{relative}: {section} changed from the immutable baseline")

        def concurrency_values(text: str) -> tuple[str, ...]:
            values = []
            for line in root_section(text, "concurrency", required=False):
                if re.match(r"^  (group|cancel-in-progress):", line):
                    values.append(line.strip())
            return tuple(values)

        if concurrency_values(candidate_text) != concurrency_values(baseline_text):
            fail(f"{relative}: concurrency behavior changed")

        candidate_jobs = job_blocks(candidate_text, relative)
        baseline_jobs = job_blocks(baseline_text, relative)
        if candidate_jobs.keys() != expected_jobs or baseline_jobs.keys() != expected_jobs:
            fail(f"{relative}: job inventory differs from the closed issue scope")
        for job in expected_jobs:
            for setting in ("name", "if", "timeout-minutes", "permissions", "env", "needs", "strategy", "environment", "container", "services", "continue-on-error", "defaults", "outputs", "uses", "with"):
                if job_setting(candidate_jobs[job], setting) != job_setting(baseline_jobs[job], setting):
                    fail(f"{relative}:{job}: {setting} changed from the baseline")
            if not commands_preserve_intent(relative, job, run_blocks(baseline_jobs[job]), run_blocks(candidate_jobs[job])):
                fail(f"{relative}:{job}: inline command changed from the immutable baseline")
            candidate_secrets = sorted(re.findall(r"\$\{\{\s*secrets\.[^}]+}}", "\n".join(candidate_jobs[job])))
            baseline_secrets = sorted(re.findall(r"\$\{\{\s*secrets\.[^}]+}}", "\n".join(baseline_jobs[job])))
            if candidate_secrets != baseline_secrets:
                fail(f"{relative}:{job}: secret references changed")
            channel = re.search(r"(?m)^channel\s*=\s*[\"']([^\"']+)[\"']", (candidate / "rust-toolchain.toml").read_text(encoding="utf-8"))
            if not channel:
                fail("workspace rust-toolchain.toml has no pinned channel")
            verify_step_semantics(relative, job, candidate_jobs[job], baseline_jobs[job], channel.group(1))

def verify_inventory(root: Path) -> None:
    policy_text = (root / ".github/workflows/dependabot-policy.yml").read_text(encoding="utf-8")
    if POLICY_CARGO_DENY_COMMAND not in policy_text:
        fail("Dependabot policy must use cargo-deny's supported `check --config` ordering")
    if POLICY_CARGO_DENY_OLD_INVALID_COMMAND in policy_text:
        fail("Dependabot policy still contains cargo-deny's invalid `--config ... check` ordering")
    if 'cargo llvm-cov report --summary-only $COV_FLAGS' not in (root / "scripts/coverage.sh").read_text(encoding="utf-8"):
        fail("coverage script must use the supported cargo-llvm-cov report argument shape")

    if sum(len(jobs) for jobs in FILES.values()) != 12:
        fail("the frozen scope must contain exactly twelve jobs")
    checkout_count = 0
    for relative, expected in FILES.items():
        jobs = job_blocks((root / relative).read_text(encoding="utf-8"), relative)
        if jobs.keys() != expected:
            fail(f"{relative}: job inventory drifted: {sorted(jobs)}")
        for job, lines in jobs.items():
            runner = [line.strip() for line in lines if line.startswith("    runs-on:")]
            if runner != ["runs-on: ubuntu-24.04"]:
                fail(f"{relative}:{job}: runner must be ubuntu-24.04")

    for relative, expected in FILES.items():
        jobs = job_blocks((root / relative).read_text(encoding="utf-8"), relative)
        for job, lines in jobs.items():
            for index, line in enumerate(lines):
                if "uses: actions/checkout@" not in line:
                    continue
                checkout_count += 1
                indent = len(line) - len(line.lstrip())
                step_indent = indent - 2
                end = len(lines)
                for cursor in range(index + 1, len(lines)):
                    if lines[cursor].startswith(" " * step_indent + "- "):
                        end = cursor
                        break
                block = "\n".join(lines[index:end])
                if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", block):
                    fail(f"{relative}:{job}: checkout must disable credential persistence")
                for action in re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", block):
                    if action.startswith("./"):
                        continue
                    reference = action.rsplit("@", 1)[-1]
                    if SHA.fullmatch(reference) is None:
                        fail(f"{relative}:{job}: action is not pinned to a full SHA: {action}")
    if checkout_count != 9:
        fail(f"the frozen scope must contain exactly nine checkouts, found {checkout_count}")

    texts = read_workflows(root)
    for relative, job in (
        (".github/workflows/dependabot-auto-merge.yml", "auto-merge"),
        (".github/workflows/dependabot-policy.yml", "policy-gate"),
    ):
        block = "\n".join(job_blocks(texts[relative], relative)[job])
        if "github.actor == 'dependabot[bot]'" not in block or "github.event.pull_request.user.login == 'dependabot[bot]'" not in block:
            fail(f"{relative}:{job}: Dependabot-only boundary is missing")

    label_jobs = job_blocks(texts[".github/workflows/pr-labels.yml"], ".github/workflows/pr-labels.yml")
    for job in ("label", "size"):
        block = "\n".join(label_jobs[job])
        for association in ("OWNER", "MEMBER", "COLLABORATOR"):
            if f"author_association == '{association}'" not in block:
                fail(f"pr-labels.yml:{job}: trusted-association boundary lost {association}")

    trust = texts[".github/workflows/dependabot-policy-trust-boundary.yml"]
    policy = texts[".github/workflows/dependabot-policy.yml"]
    for required in ("working-directory: _base", "--untrusted-tree", "persist-credentials: false"):
        if required not in trust:
            fail(f"dependabot trust boundary lost {required!r}")
    if "working-directory: _pr-data" in policy or "working-directory: _pr-data" in trust:
        fail("untrusted PR data is used as an executable working directory")

    for job, marker in MUTATION_MARKERS.items():
        present = any(marker in text for text in texts.values())
        if not present:
            fail(f"mutation path marker for {job} disappeared")

    actual_run_steps: dict[str, dict[str, set[str]]] = {}
    for relative in FILES:
        actual_run_steps[relative] = {}
        for job, lines in job_blocks((root / relative).read_text(encoding="utf-8"), relative).items():
            actual_run_steps[relative][job] = {
                name for name, block in step_blocks(lines).items()
                if any(line.startswith("        run:") for line in block)
            }
    if actual_run_steps != RUN_STEPS:
        fail("scoped inline command inventory changed; update and execute every exact run block in the proof harness")


def verify_bot_audit_fixture(root: Path) -> None:
    """Run the workflow's actual inline audit script against a local fake gh."""
    path = root / ".github/workflows/bot-pr-has-checks.yml"
    source = path.read_text(encoding="utf-8")
    block = job_blocks(source, str(path))["audit"]
    joined = "\n".join(block)
    marker = "python3 - <<'PY'"
    if marker not in joined:
        fail("bot-pr-has-checks audit no longer has the bounded inline script")
    body = joined.split(marker, 1)[1].split("\n          PY", 1)[0]
    audit_script = textwrap.dedent(body)

    with tempfile.TemporaryDirectory(prefix="i2374-audit-") as directory:
        tmp = Path(directory)
        script = tmp / "audit.py"
        script.write_text(audit_script, encoding="utf-8")
        fakebin = tmp / "bin"
        fakebin.mkdir()
        gh = fakebin / "gh"
        gh.write_text(fake_gh_source(), encoding="utf-8")
        gh.chmod(0o755)
        base_env = {
            **os.environ,
            "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
            "REPO": "HuGR-dev/corelink-server",
            "REPOSITORY_ID": "1232040291",
            "GITHUB_STEP_SUMMARY": str(tmp / "summary.md"),
            "GH_TRACE": str(tmp / "gh-trace.jsonl"),
        }
        missing = subprocess.run(
            [sys.executable, str(script)], env={**base_env, "FIXTURE_CHECKS": "0", "FIXTURE_STATUSES": "0"},
            capture_output=True, text=True,
        )
        if missing.returncode != 1 or "NO CHECKS" not in missing.stdout:
            fail("bot audit fixture did not fail a mature PR with no checks/statuses: "
                 f"rc={missing.returncode} stdout={missing.stdout[-250:]!r} stderr={missing.stderr[-250:]!r}")
        present = subprocess.run(
            [sys.executable, str(script)], env={**base_env, "FIXTURE_CHECKS": "1", "FIXTURE_STATUSES": "0"},
            capture_output=True, text=True,
        )
        if present.returncode != 0 or "present (not proof of success)" not in present.stdout:
            fail("bot audit fixture did not pass a PR with a present check run")


def verify_read_only_fixtures(root: Path) -> None:
    verify_bot_audit_fixture(root)
    subprocess.run(["bash", "scripts/test_dependabot_policy_trust_boundary.sh"], cwd=root, check=True)
    subprocess.run([sys.executable, "scripts/validate_permission_matrix.py", "--self-test"], cwd=root, check=True)
    subprocess.run([sys.executable, "scripts/validate_permission_matrix.py"], cwd=root, check=True)
    subprocess.run(["bash", "scripts/test_ci_use_host_toolchain.sh"], cwd=root, check=True)


def named_run_block(root: Path, relative: str, job: str, step_name: str) -> str:
    lines = job_blocks((root / relative).read_text(encoding="utf-8"), relative)[job]
    wanted = "      - name: " + step_name
    try:
        start = next(index for index, line in enumerate(lines) if line == wanted)
    except StopIteration:
        fail(f"{relative}:{job}: missing proof step {step_name!r}")
    run_index = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("        run:")), None)
    if run_index is None:
        fail(f"{relative}:{job}:{step_name}: missing run block")
    declaration = lines[run_index].split("run:", 1)[1].strip()
    body = []
    if declaration in {"|", ">-", "|-", ">"}:
        for line in lines[run_index + 1:]:
            if line.strip() and len(line) - len(line.lstrip()) <= 8:
                break
            body.append(line)
        return textwrap.dedent("\n".join(body))
    return declaration


def fake_gh_source() -> str:
    return """#!/usr/bin/env python3
import datetime, json, os, sys
args = sys.argv[1:]
joined = " ".join(args)
verb = args[0] if args else ""
sub = args[1] if len(args) > 1 else ""
method = "GET"
for index, arg in enumerate(args[:-1]):
    if arg in {"-X", "--method"}:
        method = args[index + 1].upper()
        break
write = (method in {"POST", "PUT", "PATCH", "DELETE"} or
         (verb == "pr" and sub in {"merge", "edit", "comment"}) or
         (verb == "issue" and sub == "comment") or
         (verb == "label" and sub == "create"))
record = {"args": args, "method": method if verb == "api" else ("WRITE" if write else "READ"),
          "outcome": "denied" if write else "read-only-fixture"}
with open(os.environ["GH_TRACE"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(record) + "\\n")
if write:
    print("mock GitHub denied write: " + joined, file=sys.stderr)
    raise SystemExit(86)
if verb == "api":
    path = next((arg for arg in args if arg.startswith("repos/") or arg.startswith("search/")), args[-1])
    if path.endswith("/pulls?state=open&per_page=100"):
        created = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(json.dumps([{"number":314,"title":"fixture","user":{"login":"fixture"},"created_at":created,"head":{"ref":"bot/api-reference-sync-fixture","sha":"a"*40}}]))
    elif "/check-runs?" in path:
        print(json.dumps({"total_count": int(os.environ.get("FIXTURE_CHECKS", "1")), "check_runs": [
            {"name":"dco"},
            {"name":"PR gate (crate-scoped clippy + tests)"},
            {"name":"cargo-deny (license + advisories + sources + bans)"},
            {"name":"cargo-audit PR gate"},
            {"name":"secrets-matrix drift gate"}
        ]}))
    elif "/status?" in path:
        print(json.dumps({"total_count": int(os.environ.get("FIXTURE_STATUSES", "0"))}))
    elif "pulls/314/files" in path:
        print("src/example.rs\\t3\\t2")
    elif "search/issues" in path:
        print("1" if "--jq" in args else json.dumps({"total_count": 1}))
    else:
        raise SystemExit("unexpected read-only gh API path: " + path)
    raise SystemExit(0)
if verb in {"pr", "issue"} and sub == "view":
    if "--jq" in args:
        print("")
    else:
        print(json.dumps({"labels": [], "comments": []}))
    raise SystemExit(0)
raise SystemExit("unexpected gh command: " + joined)
"""


class LocalGitHubHandler(BaseHTTPRequestHandler):
    """Read-only REST fixtures used to execute pinned actions with writes denied."""

    requests: list[dict[str, object]] = []
    labels: set[str] = set()
    accept_writes = False
    now = datetime.now(timezone.utc)

    def log_message(self, *_args: object) -> None:
        return

    def _send(self, status: int, payload: object) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _record(self) -> dict[str, object]:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            body: object = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw.decode("utf-8", errors="replace")
        record = {"method": self.command, "path": urlsplit(self.path).path, "body": body}
        self.requests.append(record)
        return record

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._record()
        path = urlsplit(self.path).path
        if path.endswith("/pulls/314/files"):
            self._send(200, [{"filename": "infra/staging/topology.json", "additions": 3, "deletions": 2, "status": "modified"}])
        elif path.endswith("/pulls/314"):
            self._send(200, {"number": 314, "title": "fixture", "draft": False, "labels": [], "base": {"ref": "main"}, "head": {"ref": "fixture", "sha": "a" * 40}})
        elif path.endswith("/issues/314/labels"):
            self._send(200, [{"name": label} for label in sorted(self.labels)])
        elif path.endswith("/labels"):
            self._send(200, [{"name": label, "color": "ededed"} for label in sorted(self.labels)])
        elif path.endswith("/issues"):
            page = int(parse_qs(urlsplit(self.path).query).get("page", ["1"])[0])
            if page > 1:
                self._send(200, [])
                return
            old = lambda days: (self.now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._send(200, [
                {"number": 315, "title": "stale fixture", "body": "", "state": "open", "created_at": old(80), "updated_at": old(80), "labels": [], "assignees": [], "milestone": None, "pull_request": None},
                {"number": 316, "title": "close fixture", "body": "", "state": "open", "created_at": old(100), "updated_at": old(80), "labels": [{"name": "stale"}], "assignees": [], "milestone": None, "pull_request": None},
            ])
        elif "/comments" in path:
            self._send(200, [])
        else:
            self._send(200, {})

    def _deny_write(self) -> None:
        record = self._record()
        status = 201 if self.accept_writes else 403
        record["status"] = status
        self._send(status, {"message": "mock accepted write" if self.accept_writes else "issue-2374 proof mock denies all writes"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path.endswith("/graphql"):
            record = self._record()
            body = record.get("body")
            query = body.get("query", "") if isinstance(body, dict) else ""
            if "query" in query.lower() and "mutation" not in query.lower():
                self._send(200, {"data": {
                    "viewer": {"login": "issue-2374-fixture"},
                    "repository": {"pullRequest": {"comments": {
                        "nodes": [], "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }}},
                }})
                return
            status = 201 if self.accept_writes else 403
            record["status"] = status
            self._send(status, {"message": "mock accepted write" if self.accept_writes else "issue-2374 proof mock denies all writes"})
            return
        self._deny_write()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._deny_write()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._deny_write()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._deny_write()


def action_step_inputs(root: Path, relative: str, job: str, step_name: str) -> dict[str, str]:
    lines = job_blocks((root / relative).read_text(encoding="utf-8"), relative)[job]
    wanted = "      - name: " + step_name
    try:
        start = next(index for index, line in enumerate(lines) if line == wanted)
    except StopIteration:
        fail(f"{relative}:{job}: missing action step {step_name!r}")
    end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith("      - ")), len(lines))
    step = lines[start:end]
    try:
        with_index = next(index for index, line in enumerate(step) if line == "        with:")
    except StopIteration:
        return {}
    inputs: dict[str, str] = {}
    index = with_index + 1
    while index < len(step) and (not step[index].strip() or step[index].startswith("          ")):
        match = re.match(r"^          ([a-zA-Z0-9_-]+):(?:\s*(.*))?$", step[index])
        if not match:
            index += 1
            continue
        key, value = match.group(1), (match.group(2) or "")
        if value in {"|", "|-", ">", ">-"}:
            body = []
            index += 1
            while index < len(step) and (not step[index].strip() or step[index].startswith("            ")):
                body.append(step[index][12:] if step[index].startswith("            ") else "")
                index += 1
            inputs[key] = "\n".join(body).rstrip()
            continue
        inputs[key] = value.strip("'\"")
        index += 1
    return inputs


def run_pinned_action(
    action_root: Path, action: str, root: Path, api_url: str, event_path: Path,
    tmp: Path, guard_path: Path,
) -> None:
    action_dir = action_root / action
    metadata = (action_dir / "action.yml").read_text(encoding="utf-8")
    main = re.search(r"(?m)^\s*main:\s*['\"]?([^\s'\"]+)", metadata)
    if not main:
        fail(f"{action}: action.yml does not declare a node entrypoint")
    entrypoint = action_dir / main.group(1)
    if not entrypoint.is_file():
        fail(f"{action}: pinned entrypoint is missing: {entrypoint}")
    output_path = tmp / f"{action}-output.txt"
    output_path.touch()
    env = {
        **os.environ,
        "GITHUB_API_URL": api_url,
        "GITHUB_SERVER_URL": api_url.rsplit("/api/v3", 1)[0],
        "GITHUB_REPOSITORY": "HuGR-dev/corelink-server",
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_WORKSPACE": str(root),
        "GITHUB_RUN_ID": "2374",
        "GITHUB_RUN_NUMBER": "1",
        "GITHUB_OUTPUT": str(output_path),
        "GITHUB_TOKEN": "fixture-token-never-valid-outside-local-mock",
        "INPUT_GITHUB_TOKEN": "fixture-token-never-valid-outside-local-mock",
        "INPUT_REPO-TOKEN": "fixture-token-never-valid-outside-local-mock",
        "I2374_ACTION_ALLOWED_PORT": str(urlsplit(api_url).port or ""),
    }
    env["NODE_OPTIONS"] = f"--require={guard_path}"
    in_inputs = False
    current_input: str | None = None
    for line in metadata.splitlines():
        if line == "inputs:":
            in_inputs = True
            continue
        if in_inputs and line and not line[0].isspace():
            break
        if not in_inputs:
            continue
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current_input = match.group(1)
            continue
        default = re.match(r"^    default:\s*(.*?)\s*$", line)
        if current_input and default:
            key = "INPUT_" + current_input.upper()
            env.setdefault(key, default.group(1).strip("'\""))
    workflow, job, step = {
        "labeler": (".github/workflows/pr-labels.yml", "label", "Apply labels"),
        "stale": (".github/workflows/stale.yml", "stale", "Mark + close stale items"),
        "sticky": (".github/workflows/coverage.yml", "coverage", "Sticky PR comment"),
    }[action]
    if action == "sticky":
        env["GITHUB_EVENT_NAME"] = "pull_request"
    for key, value in action_step_inputs(root, workflow, job, step).items():
        env["INPUT_" + key.upper().replace("_", "-")] = value
    if action == "sticky":
        env["INPUT_MESSAGE"] = "Disposable coverage fixture body"
    env["INPUT_REPO-TOKEN"] = "fixture-token-never-valid-outside-local-mock"
    before = len(LocalGitHubHandler.requests)
    result = subprocess.run(["node", str(entrypoint)], cwd=root, env=env, capture_output=True, text=True)
    new_requests = LocalGitHubHandler.requests[before:]
    if result.returncode == 0 and not any(request["method"] in {"POST", "PUT", "PATCH", "DELETE"} for request in new_requests):
        fail(f"{action}: action completed without reaching a denied write boundary")


def verify_pinned_mutating_actions(root: Path, action_root: Path) -> None:
    labels_file = root / ".github/labeler.yml"
    labels = set(re.findall(r"(?m)^\"([^\"]+)\":$", labels_file.read_text(encoding="utf-8")))
    event_path = root / "target/issue-2374-event.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(json.dumps({
        "repository": {"full_name": "HuGR-dev/corelink-server"},
        "pull_request": {"number": 314, "title": "fixture", "draft": False, "labels": [], "base": {"ref": "main"}, "head": {"ref": "fixture", "sha": "a" * 40}},
    }), encoding="utf-8")
    LocalGitHubHandler.requests = []
    LocalGitHubHandler.labels = labels | {"size:XS", "stale"}
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalGitHubHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    api_url = f"http://127.0.0.1:{server.server_port}/api/v3"
    try:
        with tempfile.TemporaryDirectory(prefix="i2374-actions-") as directory:
            tmp = Path(directory)
            guard_path = tmp / "socket-guard.cjs"
            guard_path.write_text(SOCKET_GUARD_SOURCE, encoding="utf-8")
            run_pinned_action(action_root, "labeler", root, api_url, event_path, tmp, guard_path)
            run_pinned_action(action_root, "stale", root, api_url, event_path, tmp, guard_path)
            run_pinned_action(action_root, "sticky", root, api_url, event_path, tmp, guard_path)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        event_path.unlink(missing_ok=True)
    writes = [
        request for request in LocalGitHubHandler.requests
        if request["method"] in {"POST", "PUT", "PATCH", "DELETE"}
        and not (
            str(request.get("path", "")).endswith("/graphql")
            and isinstance(request.get("body"), dict)
            and "query" in str(request["body"].get("query", "")).lower()
            and "mutation" not in str(request["body"].get("query", "")).lower()
        )
    ]
    all_requests = json.dumps(LocalGitHubHandler.requests)
    if "/pulls/314/files" not in all_requests or not any("/issues/314/labels" in str(request.get("path")) for request in writes):
        fail(f"pinned labeler did not reach its denied fixture label write: {LocalGitHubHandler.requests}")
    if not any("/issues/315/labels" in str(request.get("path")) for request in writes):
        fail("pinned stale action did not attempt to mark the aged issue fixture")
    if not any(request.get("method") == "POST" and "/issues/314/comments" in str(request.get("path")) for request in writes):
        fail("pinned coverage comment action did not attempt its fixture comment")
    if not writes or any(request.get("status") != 403 for request in writes):
        fail(f"pinned action REST writes were not all denied: {writes}")


def verify_socket_guard_controls() -> None:
    """Prove local success, lookalike denial before DNS, and missing-port denial."""
    LocalGitHubHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalGitHubHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="i2374-socket-guard-") as directory:
            tmp = Path(directory)
            guard_path = tmp / "socket-guard.cjs"
            guard_path.write_text(SOCKET_GUARD_SOURCE, encoding="utf-8")
            port = server.server_port

            positive = r'''const http = require("node:http");
const port = Number(process.env.I2374_ACTION_ALLOWED_PORT);
http.get({ hostname: "127.0.0.1", port, path: "/api/v3/guard-positive" }, response => {
  response.resume();
  response.on("end", () => { if (response.statusCode !== 200) process.exitCode = 1; });
}).on("error", () => { process.exitCode = 1; });
'''
            negative = r'''const http = require("node:http");
let lookedUp = false;
try {
  const request = http.get({
    hostname: "api.github.com.evil.invalid", port: 443,
    lookup(_host, _options, callback) { lookedUp = true; callback(new Error("lookup must not run")); },
  }, () => { process.exitCode = 1; });
  request.on("error", error => {
    if (error.code !== "I2374_ACTION_EGRESS_BLOCKED" || lookedUp) process.exitCode = 1;
  });
} catch (error) {
  if (error.code !== "I2374_ACTION_EGRESS_BLOCKED" || lookedUp) process.exitCode = 1;
}
'''
            wrapped_null_negative = r'''const net = require("node:net");
let lookedUp = false;
try {
  new net.Socket().connect([{
    host: "api.github.com.evil.invalid", port: 443,
    lookup(_host, _options, callback) { lookedUp = true; callback(new Error("lookup must not run")); },
  }, null]);
  process.exitCode = 1;
} catch (error) {
  if (error.code !== "I2374_ACTION_EGRESS_BLOCKED" || lookedUp) process.exitCode = 1;
}
'''
            wrapped_null_positive = r'''const net = require("node:net");
const port = Number(process.env.I2374_ACTION_ALLOWED_PORT);
const socket = new net.Socket();
socket.on("connect", () => socket.destroy());
socket.on("error", () => { process.exitCode = 1; });
socket.connect([{host: "127.0.0.1", port}, null]);
'''
            missing_port = r'''const net = require("node:net");
try {
  new net.Socket().connect({ host: "127.0.0.1", port: Number(process.env.I2374_PROBE_PORT) });
  process.exitCode = 1;
} catch (error) {
  if (error.code !== "I2374_ACTION_EGRESS_BLOCKED_PORT") process.exitCode = 1;
}
'''

            def probe(source: str, *, allowed_port: int | None) -> None:
                env = {**os.environ, "NODE_OPTIONS": f"--require={guard_path}", "I2374_PROBE_PORT": str(port)}
                if allowed_port is None:
                    env.pop("I2374_ACTION_ALLOWED_PORT", None)
                else:
                    env["I2374_ACTION_ALLOWED_PORT"] = str(allowed_port)
                result = subprocess.run(["node", "-e", source], env=env, capture_output=True, text=True)
                if result.returncode != 0:
                    fail(f"socket guard control failed: {result.stderr or result.stdout}")

            probe(positive, allowed_port=port)
            probe(negative, allowed_port=port)
            probe(wrapped_null_negative, allowed_port=port)
            probe(wrapped_null_positive, allowed_port=port)
            probe(missing_port, allowed_port=None)
            if not any(str(request.get("path", "")).endswith("/guard-positive") for request in LocalGitHubHandler.requests):
                fail("local positive socket control did not reach the mock handler")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def verify_mock_deny_negative_control() -> None:
    """Prove an accepting mock response is distinguishable from a denial."""
    LocalGitHubHandler.requests = []
    LocalGitHubHandler.accept_writes = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalGitHubHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        request = Request(f"http://127.0.0.1:{server.server_port}/api/v3/repos/fixture/issues/1/comments",
                          data=b'{"body":"disposable"}', method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            if response.status != 201:
                fail("mock acceptance negative control did not receive the configured response")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        LocalGitHubHandler.accept_writes = False
    accepted = [request for request in LocalGitHubHandler.requests if request["method"] in {"POST", "PUT", "PATCH", "DELETE"}]
    if len(accepted) != 1 or accepted[0].get("status") != 201:
        fail("mock acceptance negative control did not record the local write")
    if all(request.get("status") == 403 for request in accepted):
        fail("mock acceptance escaped the deny-all response assertion")


def run_gh_script(script: str, fakebin: Path, trace: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        env={**os.environ, **env, "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
             "GH_TRACE": str(trace)},
        capture_output=True, text=True,
    )


def verify_original_write_commands(root: Path) -> None:
    """Execute the workflow's actual mutating shell commands against local gh."""
    with tempfile.TemporaryDirectory(prefix="i2374-writes-") as directory:
        tmp = Path(directory)
        fakebin = tmp / "bin"
        fakebin.mkdir()
        gh = fakebin / "gh"
        gh.write_text(fake_gh_source(), encoding="utf-8")
        gh.chmod(0o755)
        trace = tmp / "gh-trace.jsonl"

        cases = [
            (".github/workflows/dependabot-auto-merge.yml", "auto-merge", "Enable auto-merge (security-patch only)",
             {"GITHUB_TOKEN":"fixture", "PR_URL":"https://example.invalid/pr/314", "DEP_NAMES":"fixture", "ECOSYSTEM":"cargo"}, [("pr", "merge")]),
            (".github/workflows/pr-labels.yml", "size", "Apply size:* label",
             {"GH_TOKEN":"fixture", "PR":"314", "REPO":"HuGR-dev/corelink-server"}, [("label", "create"), ("pr", "edit")]),
            (".github/workflows/welcome-first-pr.yml", "welcome", "Greet first-time contributor",
             {"GH_TOKEN":"fixture", "REPO":"HuGR-dev/corelink-server", "EVENT":"pull_request_target", "NUMBER":"314", "AUTHOR":"FixtureHuman", "ISSUE_MESSAGE":"fixture issue", "PR_MESSAGE":"fixture PR"}, [("pr", "comment")]),
            (".github/workflows/lockfile-diff.yml", "lockfile-diff", "Post PR comment with diff + cargo-deny summary",
             {"GITHUB_TOKEN":"fixture", "PR_NUMBER":"314", "REPO":"HuGR-dev/corelink-server", "TOTAL_CHANGED":"1", "DENY_EXIT":"0"}, [("pr", "comment")]),
        ]
        for relative, job, step, env, expected_writes in cases:
            trace.unlink(missing_ok=True)
            script = named_run_block(root, relative, job, step)
            script = script.replace("${{github.server_url}}", "https://github.com").replace("${{github.run_id}}", "1")
            if relative == ".github/workflows/lockfile-diff.yml":
                (tmp / "deny-output.txt").write_text("fixture cargo-deny output\n", encoding="utf-8")
            completed = run_gh_script(script, fakebin, trace, env)
            records = [line for line in trace.read_text(encoding="utf-8").splitlines() if line]
            if not records:
                fail(f"{relative}:{step}: fake GitHub did not record a request")
            decoded = list(map(json.loads, records))
            observed = [(item["args"][0], item["args"][1]) for item in decoded if item["outcome"] == "denied"]
            if observed != expected_writes:
                fail(f"{relative}:{step}: expected mocked write requests {expected_writes}, got {observed}")
            if any(item["outcome"] == "denied" and item["method"] != "WRITE" for item in decoded):
                fail(f"{relative}:{step}: write request did not use the deny-by-default sink")
            # The lockfile notifier catches a failed comment to emit an annotation;
            # all other original write commands must observe the denial as failure.
            if completed.returncode == 0 and relative != ".github/workflows/lockfile-diff.yml":
                fail(f"{relative}:{step}: command ignored the denied local write")

        eligibility = named_run_block(root, ".github/workflows/dependabot-auto-merge.yml", "auto-merge", "Compute auto-merge eligibility")
        output_path = tmp / "eligibility-output.txt"
        selected = subprocess.run(["bash", "-euo", "pipefail", "-c", eligibility],
                                  env={**os.environ, "UPDATE_TYPE": "version-update:semver-patch",
                                       "PR_TITLE": "[security] fixture update", "LABELS_JSON": "[]",
                                       "GITHUB_OUTPUT": str(output_path)}, capture_output=True, text=True)
        decision = output_path.read_text(encoding="utf-8") if output_path.is_file() else ""
        if selected.returncode != 0 or "eligible=true" not in decision or "is_security=true" not in decision:
            fail("Dependabot auto-merge decision command did not select the security-patch fixture")

        sentinel = named_run_block(root, ".github/workflows/dependabot-policy.yml", "sentinel", "Pass-through (non-dependabot PR)")
        passed = subprocess.run(["bash", "-euo", "pipefail", "-c", sentinel], capture_output=True, text=True)
        if passed.returncode != 0 or "policy gate not applicable" not in passed.stdout:
            fail("Dependabot sentinel command did not execute its non-Dependabot pass path")

        # Execute the lockfile generator itself over disposable before/after inputs.
        diff_root = tmp / "lockfiles"
        (diff_root / "base").mkdir(parents=True)
        (diff_root / "head").mkdir()
        (diff_root / "base/Cargo.lock").write_text('[[package]]\nname = "fixture"\nversion = "1.0.0"\n', encoding="utf-8")
        (diff_root / "head/Cargo.lock").write_text('[[package]]\nname = "fixture"\nversion = "1.0.0"\n\n[[package]]\nname = "fixture-added"\nversion = "2.0.0"\n', encoding="utf-8")
        generator = named_run_block(root, ".github/workflows/lockfile-diff.yml", "lockfile-diff", "Generate Cargo.lock diff")
        generated = subprocess.run(["bash", "-euo", "pipefail", "-c", generator], cwd=diff_root,
                                   env={**os.environ, "GITHUB_OUTPUT": str(diff_root / "output"),
                                        "GITHUB_STEP_SUMMARY": str(diff_root / "summary")},
                                   capture_output=True, text=True)
        if generated.returncode != 0 or "+1 added" not in generated.stdout:
            fail(f"lockfile-diff generator failed on disposable lockfiles: {generated.stderr[-500:]} {generated.stdout[-300:]}")
        if "total_changed=1" not in (diff_root / "output").read_text(encoding="utf-8"):
            fail("lockfile-diff generator did not emit the expected change count")

        # Execute the policy-gate status-check command against a two-commit PR fixture.
        git_root = tmp / "policy-pr"
        git_root.mkdir()
        subprocess.run(["git", "init", "-q", str(git_root)], check=True)
        subprocess.run(["git", "-C", str(git_root), "config", "user.name", "issue-2374 fixture"], check=True)
        subprocess.run(["git", "-C", str(git_root), "config", "user.email", "fixture@example.invalid"], check=True)
        (git_root / "Cargo.lock").write_text("fixture base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(git_root), "add", "Cargo.lock"], check=True)
        subprocess.run(["git", "-C", str(git_root), "commit", "-qm", "base"], check=True)
        (git_root / "Cargo.lock").write_text("fixture candidate\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(git_root), "commit", "-qam", "fixture dependency update"], check=True)
        trace.unlink(missing_ok=True)
        required_check = named_run_block(root, ".github/workflows/dependabot-policy.yml", "policy-gate", "Verify required checks are present")
        checked = run_gh_script(required_check, fakebin, trace,
                                {"GH_TOKEN": "fixture", "REPO": "HuGR-dev/corelink-server",
                                 "PR_HEAD_SHA": "a" * 40, "UNTRUSTED_TREE": str(git_root)})
        if checked.returncode != 0 or "All 5 resolved required status checks are present" not in checked.stdout:
            fail(f"Dependabot policy check command failed against fixture API: {checked.stderr[-500:]} {checked.stdout[-500:]}")

        # cargo-deny is checked byte-for-byte against the immutable baseline,
        # but it is outside this write-boundary execution proof.


def run_original_shell(root: Path, relative: str, job: str, step: str, *, cwd: Path,
                       env: dict[str, str] | None = None, replacements: dict[str, str] | None = None,
                       expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    """Execute one exact workflow run block with only fixture substitutions."""
    script = named_run_block(root, relative, job, step)
    for source, value in (replacements or {}).items():
        script = script.replace(source, value)
    result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=cwd,
                            env={**os.environ, **(env or {})}, capture_output=True, text=True)
    if (result.returncode == 0) != expect_success:
        expected = "success" if expect_success else "failure"
        fail(f"{relative}:{step}: expected {expected}, got rc={result.returncode}: {result.stderr[-600:]} {result.stdout[-250:]}")
    return result


def _git_fixture(directory: Path, *, candidate_files: dict[str, str], merge_message: str = "fixture candidate") -> Path:
    """Create a PR-shaped two-parent merge; changed fixture files are on parent two."""
    directory.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(directory)], check=True)
    subprocess.run(["git", "-C", str(directory), "config", "user.name", "issue-2374 fixture"], check=True)
    subprocess.run(["git", "-C", str(directory), "config", "user.email", "fixture@example.invalid"], check=True)
    for relative, contents in {"Cargo.toml": '[workspace]\nmembers = []\nresolver = "2"\n',
                               "Cargo.lock": "version = 4\n", "deny.toml": '[licenses]\nallow = ["MIT"]\n',
                               "fixture-base.txt": "base\n"}.items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    subprocess.run(["git", "-C", str(directory), "add", "."], check=True)
    subprocess.run(["git", "-C", str(directory), "commit", "-qm", "base"], check=True)
    base = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    (directory / "fixture-left.txt").write_text("left parent\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(directory), "add", "fixture-left.txt"], check=True)
    subprocess.run(["git", "-C", str(directory), "commit", "-qm", "first PR parent"], check=True)
    left = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "-C", str(directory), "checkout", "-qb", "fixture-right", base], check=True)
    for relative, contents in candidate_files.items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    subprocess.run(["git", "-C", str(directory), "add", "."], check=True)
    subprocess.run(["git", "-C", str(directory), "commit", "-qm", merge_message], check=True)
    right = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], check=True,
                           capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "-C", str(directory), "checkout", "-q", left], check=True)
    subprocess.run(["git", "-C", str(directory), "merge", "--no-ff", "-qm", "fixture PR merge", right], check=True)
    return directory


def verify_remaining_original_commands(root: Path, baseline: Path) -> None:
    """Run scoped inline commands not already covered by the focused command/action fixtures."""
    with tempfile.TemporaryDirectory(prefix="i2374-all-commands-") as directory:
        tmp = Path(directory)
        coverage_dir = tmp / "target/coverage"
        coverage_dir.mkdir(parents=True)
        (coverage_dir / "SUMMARY.txt").write_text("fixture coverage summary\n", encoding="utf-8")
        coverage_output, coverage_summary = tmp / "coverage-output", tmp / "step-summary"
        run_original_shell(root, ".github/workflows/coverage.yml", "coverage", "Render PR comment body",
                           cwd=tmp, env={"GITHUB_OUTPUT": str(coverage_output)},
                           replacements={"${{ github.event.pull_request.number || 'main' }}": "314"})
        run_original_shell(root, ".github/workflows/coverage.yml", "coverage", "Append step summary",
                           cwd=tmp, env={"GITHUB_STEP_SUMMARY": str(coverage_summary)})
        if "fixture coverage summary" not in coverage_output.read_text(encoding="utf-8") or "fixture coverage summary" not in coverage_summary.read_text(encoding="utf-8"):
            fail("coverage render/summary commands omitted fixture data")

        auto = ".github/workflows/dependabot-auto-merge.yml"
        auto_env = {"UPDATE_TYPE": "version-update:semver-patch", "DEPENDENCY_TYPE": "direct",
                    "DEPENDENCY_NAMES": "fixture-crate", "PACKAGE_ECOSYSTEM": "cargo",
                    "PR_TITLE": "[security] fixture update", "PR_LABELS": '["security"]',
                    "LABELS_JSON": '["security"]', "DEP_NAMES": "fixture-crate",
                    "ECOSYSTEM": "cargo", "PR_NUMBER": "314"}
        run_original_shell(root, auto, "auto-merge", "Log Dependabot PR metadata", cwd=tmp, env=auto_env)
        run_original_shell(root, auto, "auto-merge", "Annotate major-update block", cwd=tmp, env=auto_env,
                           replacements={"${{ steps.metadata.outputs.dependency-names }}": "fixture-crate"})
        run_original_shell(root, auto, "auto-merge", "Annotate non-security minor block", cwd=tmp)
        auto_expr = {"${{ steps.decide.outputs.eligible }}": "true", "${{ steps.decide.outputs.is_security }}": "true",
                     "${{ steps.metadata.outputs.update-type }}": "version-update:semver-patch",
                     "${{ steps.metadata.outputs.package-ecosystem }}": "cargo",
                     "${{ steps.metadata.outputs.dependency-names }}": "fixture-crate",
                     "${{ github.event.pull_request.number }}": "314", "${{ github.event.pull_request.head.sha }}": "a" * 40,
                     "${{ github.repository }}": "HuGR-dev/corelink-server"}
        run_original_shell(root, auto, "auto-merge", "Audit log emission", cwd=tmp, env=auto_env, replacements=auto_expr)
        run_original_shell(root, auto, "auto-merge", "Annotate metric (structured log)", cwd=tmp,
                           env=auto_env, replacements=auto_expr)

        npm_repo = _git_fixture(tmp / "npm-clean", candidate_files={
            "apps/fixture/package.json": '{"name":"fixture","license":"MIT"}\n'})
        for relative in (".github/workflows/dependabot-policy.yml",
                         ".github/workflows/dependabot-policy-trust-boundary.yml",
                         "scripts/check_dependabot_policy_trusted_tree.py",
                         "scripts/test_dependabot_policy_trust_boundary.sh",
                         "scripts/test_ci_use_host_toolchain.sh", "scripts/prepare_b133_python.sh",
                         "scripts/ci-use-host-toolchain.sh", "rust-toolchain.toml"):
            target = npm_repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((baseline / relative).read_bytes())
        policy_env = {"UNTRUSTED_TREE": str(npm_repo), "POLICY_TREE": str(tmp / "policy-tree"),
                      "CARGO_HOME": str(tmp / "cargo-home"), "DENY_CONFIG": str(baseline / "deny.toml"),
                      "REPO": "HuGR-dev/corelink-server", "PR_HEAD_SHA": "a" * 40, "GH_TOKEN": "fixture-token"}
        policy = ".github/workflows/dependabot-policy.yml"
        run_original_shell(root, policy, "policy-gate", "Verify fetched PR history (fail-closed)", cwd=baseline, env=policy_env)
        cargo_lock = tmp / "policy-tree/Cargo.lock"
        cargo_lock.parent.mkdir(parents=True)
        cargo_lock.write_text("version = 4\n", encoding="utf-8")
        scan_env = {**policy_env, "POLICY_TREE": str(tmp / "policy-tree")}
        run_original_shell(root, policy, "policy-gate", "Banned-license signature scan (Cargo.lock)",
                           cwd=baseline, env=scan_env)
        cargo_lock.write_text('[[package]]\nname = "fixture"\nversion = "1.0.0"\nlicense = "AGPL-3.0"\n', encoding="utf-8")
        run_original_shell(root, policy, "policy-gate", "Banned-license signature scan (Cargo.lock)",
                           cwd=baseline, env=scan_env, expect_success=False)
        run_original_shell(root, policy, "policy-gate", "npm banned-license scan", cwd=baseline, env=policy_env)
        banned = _git_fixture(tmp / "npm-banned", candidate_files={
            "apps/fixture/package.json": '{"name":"fixture","license":"AGPL-3.0"}\n'})
        run_original_shell(root, policy, "policy-gate", "npm banned-license scan", cwd=baseline,
                           env={**policy_env, "UNTRUSTED_TREE": str(banned)}, expect_success=False)
        skip = _git_fixture(tmp / "skip-hook", candidate_files={"src/fixture.rs": "fn fixture() {}\n"},
                            merge_message="fixture [skip ci]")
        run_original_shell(root, policy, "policy-gate", "Forbid skip-hook / skip-ci flags", cwd=baseline,
                           env={**policy_env, "UNTRUSTED_TREE": str(skip)}, expect_success=False)
        run_original_shell(root, policy, "policy-gate", "Forbid skip-hook / skip-ci flags", cwd=baseline,
                           env=policy_env)
        governance = _git_fixture(tmp / "governance", candidate_files={"deny.toml": '[licenses]\nallow = ["AGPL-3.0"]\n'})
        run_original_shell(root, policy, "policy-gate", "Forbid governance-file modifications", cwd=baseline,
                           env={**policy_env, "UNTRUSTED_TREE": str(governance)}, expect_success=False)
        run_original_shell(root, policy, "policy-gate", "Forbid governance-file modifications", cwd=baseline,
                           env=policy_env)

        b133 = tmp / "b133-python"
        b133_env = {"B133_PYTHON": str(b133), "B133_UNTRUSTED_TREE": str(npm_repo),
                    "UNTRUSTED_TREE": str(npm_repo)}
        run_original_shell(root, ".github/workflows/dependabot-policy.yml", "policy-gate",
                           "Prepare hermetic checker interpreter (BASE tree)", cwd=baseline, env=b133_env)
        run_original_shell(root, policy, "policy-gate", "Assert trust-boundary wiring (BASE checker)",
                           cwd=baseline, env=b133_env)
        run_original_shell(root, ".github/workflows/dependabot-policy-trust-boundary.yml", "trust-boundary-teeth",
                           "Prepare hermetic checker interpreter (BASE tree)", cwd=baseline, env=b133_env)
        run_original_shell(root, ".github/workflows/dependabot-policy-trust-boundary.yml", "trust-boundary-teeth",
                           "Statically reject B-133 control mutations (BASE checker)", cwd=baseline, env=b133_env)
        run_original_shell(root, ".github/workflows/dependabot-policy-trust-boundary.yml", "trust-boundary-teeth",
                           "Prove host-toolchain channel guard (BASE tree)", cwd=baseline)
        run_original_shell(root, ".github/workflows/dependabot-policy-trust-boundary.yml", "trust-boundary-teeth",
                           "Prove Dependabot trust-boundary teeth (BASE tree)", cwd=baseline)

        toolchain_path = tmp / "github-path"
        run_original_shell(root, policy, "policy-gate", "Use the workspace-pinned host toolchain (provisions nothing)",
                           cwd=baseline, env={"HOST_TRIPLE": "x86_64-unknown-linux-gnu", "GITHUB_PATH": str(toolchain_path)})
        run_original_shell(root, ".github/workflows/lockfile-diff.yml", "lockfile-diff",
                           "Assert the workspace-pinned toolchain (rust-toolchain.toml)", cwd=root)

        audit_replacements = {"${{ github.event.pull_request.number }}": "314",
                              "${{ steps.metadata.outputs.package-ecosystem }}": "cargo",
                              "${{ steps.metadata.outputs.dependency-names }}": "fixture-crate",
                              "${{ steps.metadata.outputs.update-type }}": "version-update:semver-patch",
                              "${{ github.event.pull_request.head.sha }}": "a" * 40}
        run_original_shell(root, policy, "policy-gate", "Policy-gate audit log", cwd=tmp,
                           env={"PR_NUMBER": "314", "ECOSYSTEM": "cargo", "DEP_NAMES": "fixture-crate",
                                "UPDATE_TYPE": "version-update:semver-patch"}, replacements=audit_replacements)


def verify_policy_gate_cargo_deny(root: Path, baseline: Path) -> None:
    """Execute the exact policy command and reject its unsupported former order."""
    if not shutil.which("cargo-deny"):
        fail("cargo-deny is not installed in the hosted proof job")
    version = subprocess.run(["cargo", "deny", "--version"], check=True, capture_output=True, text=True).stdout.strip()
    if not re.search(r"(?:^|\s)0\.19\.8(?:$|\s)", version):
        fail(f"hosted proof requires workflow-pinned cargo-deny 0.19.8, got {version!r}")
    with tempfile.TemporaryDirectory(prefix="i2374-policy-") as directory:
        tmp = Path(directory)
        fixture = _git_fixture(tmp / "policy-pr", candidate_files={
            "apps/fixture/package.json": '{"name":"fixture","license":"MIT"}\\n',
            "Cargo.toml": (
                '[package]\n'
                'name = "issue-2374-policy-fixture"\n'
                'version = "0.1.0"\n'
                'edition = "2021"\n'
                'license = "MIT"\n\n'
                '[workspace]\n'
                'members = ["."]\n'
                'resolver = "2"\n'
            ),
            "Cargo.lock": (
                "# This file is automatically @generated by Cargo.\n"
                "# It is not intended for manual editing.\n\n"
                "version = 4\n\n"
                "[[package]]\n"
                'name = "issue-2374-policy-fixture"\n'
                'version = "0.1.0"\n'
            ),
            "src/lib.rs": "//! Disposable package for the hosted cargo-deny proof.\n",
        })
        for relative in (
            ".github/workflows/dependabot-policy.yml",
            "scripts/check_dependabot_policy_trusted_tree.py",
            "scripts/test_dependabot_policy_trust_boundary.sh",
            "scripts/test_ci_use_host_toolchain.sh",
            "scripts/prepare_b133_python.sh",
            "scripts/ci-use-host-toolchain.sh",
            "rust-toolchain.toml",
        ):
            target = fixture / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((baseline / relative).read_bytes())
        env = {**os.environ, "UNTRUSTED_TREE": str(fixture), "POLICY_TREE": str(tmp / "policy-tree"),
               "CARGO_HOME": str(tmp / "cargo-home"), "DENY_CONFIG": str(tmp / "deny.toml")}
        policy = ".github/workflows/dependabot-policy.yml"
        run_original_shell(root, policy, "policy-gate", "Prepare isolated Cargo policy tree (PR data only)",
                           cwd=baseline, env=env)
        # The real policy step copies manifests and lock data only, then makes
        # them read-only. Keep candidate source out of the policy tree and add
        # a harness-owned target so Cargo sees a valid disposable package.
        policy_tree = tmp / "policy-tree"
        (policy_tree / "src").mkdir(parents=True)
        (policy_tree / "src/lib.rs").write_text(
            "//! Synthetic target for the disposable cargo-deny fixture.\n",
            encoding="utf-8",
        )
        # Cargo-deny 0.19.8 refreshes the throwaway lockfile. Grant write
        # access only to that disposable lockfile after the original setup.
        (policy_tree / "Cargo.lock").chmod(0o644)
        command = named_run_block(root, policy, "policy-gate", "Run cargo-deny licenses (fail-closed)")
        checked = subprocess.run(["bash", "-euo", "pipefail", "-c", command], cwd=baseline,
                                 env=env, capture_output=True, text=True)
        if checked.returncode != 0:
            fail(f"Dependabot policy cargo-deny command failed: {checked.stderr[-1000:]} {checked.stdout[-500:]}")
        old_order = command.replace(POLICY_CARGO_DENY_COMMAND, POLICY_CARGO_DENY_OLD_INVALID_COMMAND)
        if old_order == command:
            fail("cargo-deny old-order negative control could not find the canonical command")
        rejected = subprocess.run(["bash", "-euo", "pipefail", "-c", old_order], cwd=baseline,
                                  env=env, capture_output=True, text=True)
        if rejected.returncode == 0 or "unexpected argument '--config'" not in rejected.stderr:
            fail("cargo-deny old-order negative control was not rejected as invalid syntax: "
                 f"rc={rejected.returncode} stderr={rejected.stderr[-700:]}")
        print("cargo-deny syntax negative control: old `--config ... check` ordering rejected")


def verify_negative_controls(root: Path, baseline: Path) -> None:
    """Require mutations to the runner, credentials, protection, or identity to fail."""
    with tempfile.TemporaryDirectory(prefix="i2374-negative-") as directory:
        temp_root = Path(directory)
        for relative in FILES:
            target = temp_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / relative).read_bytes())
        (temp_root / "rust-toolchain.toml").write_bytes((root / "rust-toolchain.toml").read_bytes())
        (temp_root / "scripts").mkdir()
        (temp_root / "scripts/coverage.sh").write_bytes((root / "scripts/coverage.sh").read_bytes())

        cases = [
            (".github/workflows/bot-pr-has-checks.yml", "runs-on: ubuntu-24.04", "runs-on: corelink", verify_inventory),
            (".github/workflows/coverage.yml", "persist-credentials: false", "persist-credentials: true", verify_inventory),
            (".github/workflows/bot-pr-has-checks.yml", "  schedule:", "  pull_request:", verify_baseline),
            (".github/workflows/permission-matrix.yml", "  contents: read", "  contents: write", verify_baseline),
            (".github/workflows/lockfile-diff.yml", "gh', 'pr', 'comment", "gh', 'pr', 'merge", verify_baseline),
            (".github/workflows/pr-labels.yml", "actions/labeler@b8dd2d9be0f68b860e7dae5dae7d772984eacd6d", "actions/labeler@a8dd2d9be0f68b860e7dae5dae7d772984eacd6d", verify_baseline),
            (".github/workflows/pr-labels.yml", "sync-labels: false", "sync-labels: true", verify_baseline),
        ]
        for relative, old, new, check in cases:
            target = temp_root / relative
            original = target.read_text(encoding="utf-8")
            if old not in original:
                fail(f"negative-control anchor missing from {relative}: {old!r}")
            target.write_text(original.replace(old, new, 1), encoding="utf-8")
            try:
                check(temp_root, baseline) if check is verify_baseline else check(temp_root)
            except (ContractError, subprocess.CalledProcessError):
                target.write_text(original, encoding="utf-8")
                continue
            fail(f"negative control escaped: {relative} mutation {old!r}")
        verify_mock_deny_negative_control()


def self_test(root: Path, baseline: Path | None) -> None:
    verify_inventory(root)
    if baseline is not None:
        verify_negative_controls(root, baseline)
    verify_read_only_fixtures(root)
    verify_original_write_commands(root)


def verify_coverage_receipt(root: Path) -> None:
    artifact_id = os.environ.get("COVERAGE_ARTIFACT_ID", "")
    artifact_url = os.environ.get("COVERAGE_ARTIFACT_URL", "")
    artifact_digest = os.environ.get("COVERAGE_ARTIFACT_DIGEST", "")
    if not artifact_id.isdigit():
        fail("coverage artifact receipt is missing a numeric artifact id")
    if not artifact_url.startswith("https://github.com/") or "/actions/runs/" not in artifact_url:
        fail("coverage artifact receipt URL does not identify this GitHub Actions run")
    if re.fullmatch(r"[0-9a-f]{64}", artifact_digest) is None:
        fail("coverage artifact receipt is missing the SHA-256 digest")
    if not (root / "target/coverage/html/index.html").is_file():
        fail("coverage HTML report is missing after the upload step")
    if not (root / "target/coverage/SUMMARY.txt").is_file():
        fail("coverage summary is missing after the upload step")
    print(f"coverage artifact receipt: PASS id={artifact_id} sha256={artifact_digest}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--baseline-root", type=Path)
    parser.add_argument("--actions-root", type=Path)
    parser.add_argument("--expected-head")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-coverage-receipt", action="store_true")
    args = parser.parse_args()
    if args.verify_coverage_receipt:
        try:
            verify_coverage_receipt(args.root)
        except ContractError as error:
            print(f"issue-2374 hosted proof: FAIL: {error}", file=sys.stderr)
            return 1
        return 0
    try:
        if args.self_test:
            if args.expected_head:
                fail("--self-test cannot be combined with --expected-head")
            self_test(args.root, args.baseline_root)
        else:
            if not args.expected_head or SHA.fullmatch(args.expected_head) is None:
                fail("expected-head must be a full lowercase SHA")
            actual = subprocess.run(
                ["git", "-C", str(args.root), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            if actual != args.expected_head:
                fail(f"candidate HEAD {actual} does not equal {args.expected_head}")
            verify_inventory(args.root)
            if args.baseline_root:
                verify_baseline(args.root, args.baseline_root)
                verify_negative_controls(args.root, args.baseline_root)
            verify_read_only_fixtures(args.root)
            verify_original_write_commands(args.root)
            verify_socket_guard_controls()
            if not args.actions_root:
                fail("exact hosted proof requires checked-out sources for the pinned mutating actions")
            verify_pinned_mutating_actions(args.root, args.actions_root)
            if not args.baseline_root:
                fail("exact hosted proof requires --baseline-root for immutable comparison")
            verify_remaining_original_commands(args.root, args.baseline_root)
            verify_policy_gate_cargo_deny(args.root, args.baseline_root)
    except (ContractError, subprocess.CalledProcessError) as error:
        print(f"issue-2374 hosted proof: FAIL: {error}", file=sys.stderr)
        return 1
    print("issue-2374 hosted proof: PASS (original write-bearing commands and pinned actions reached the local deny-all GitHub boundary)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
