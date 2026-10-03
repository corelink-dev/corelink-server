#!/usr/bin/env python3
"""Check, and render, the server repository-ID guard of every workflow.

The org move (HuGR-dev -> corelink-dev, migration PLAN section 4.1) gives every
workflow guard one of two forms:

* routine lane:     github.repository_id == vars.CORELINK_SERVER_REPO_ID
* privileged lane:  github.repository_id == '<server repository ID>'

A workflow is *privileged* when any job names an ``environment`` or a
``permissions`` block grants ``id-token: write`` (or ``write-all``). An unset
variable expands to ``''``, so a routine guard is false and the job is skipped:
it fails closed. The privileged literal is rendered by ``--write`` from
``config/github-identity.json`` (``current.repos.server.id``); the value 0 means
"not read back yet" and is refused, and the committed placeholder ``'0'`` can
never match a real repository, so a privileged lane cannot run before the ID is
rendered.

Findings (each names ``path:line``):

* a name guard ``github.repository == '<owner>/<repo>'`` (name guards are
  dropped by the plan), or ``github.event.repository.<field> == '<literal>'``;
* a shell comparison of ``$GITHUB_REPOSITORY`` / ``$GITHUB_REPOSITORY_ID``;
* a retired numeric repository ID (1232040291, 1380335483);
* a ``github.repository_id`` comparison whose other side is neither canonical
  form, or a reversed comparison other than the fork check
  ``github.event.pull_request.head.repo.id == github.repository_id``;
* the routine form in a privileged workflow, or a literal in a routine one;
* a ledger entry (``PENDING``) whose file is missing or no longer carries a
  legacy guard -- the ledger is shrink-only and a stale row fails;
* with ``--check`` (the default) only: a missing/invalid config, a server ID of
  0, or a privileged literal that differs from the config.

What this does NOT prove: that no guard exists in a spelling outside the closed
set above. It matches raw lines (comments included, so it can only
over-report) and does not interpret expressions.

Modes: ``--check`` (default), ``--structure-only`` (usable before the ID is
read back), ``--write`` (render privileged literals, then ``--check``).
Exit status: 0 clean, 1 findings, 2 instrument error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Mapping, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = Path(".github/workflows")
CONFIG = Path("config/github-identity.json")
ROUTINE_FORM = "vars.CORELINK_SERVER_REPO_ID"
FORK_CHECK_LHS = "github.event.pull_request.head.repo.id"

# Workflows that still carry a legacy guard because another work package owns
# them. Shrink-only: a row whose file no longer has a legacy finding fails.
PENDING: dict[str, str] = {
    ".github/workflows/campaign-ci.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/cf-deploy-prod.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/container-build-push-prod.yml": "I3: sha256-pinned by backlog_verify.py, verify_i2176, verify_i2574",
    ".github/workflows/issue-1652-b072-evidence.yml": "I3: sha256-pinned by backlog_verify.py and verify_i2176",
    ".github/workflows/issue-1700-container-staging-deploy.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/issue-2568-sla-credit-real.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/issue-2575-staging-grpc-probe.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/load-test-nightly.yml": "I3: sha256-pinned by backlog_verify.py",
    ".github/workflows/real-ignored-harnesses.yml": "I3: sha256-pinned by verify_i2176_grpc_deny_gate.py",
    ".github/workflows/staging-quarantine-apply.yml": "I3: sha256-pinned by backlog_verify.py, verify_i2176, verify_i2574",
    ".github/workflows/issue-2176-grpc-deny-gate.yml": "I3: guard text bound by verify_i2176 BOOTSTRAP_WORKFLOW_SOURCE (critic K1.5)",
    ".github/workflows/issue-2574-staging-grpc-diagnostic.yml": "I3: verify_i2574 POLICY file and deny-gate trigger path",
    ".github/workflows/staging-provider-preflight.yml": "I3: guard asserted by sha256-pinned verify_staging_provider_preflight.py",
    ".github/workflows/issue-1658-b102-cargo-put.yml": "I6: guard asserted by verify_i1658_b102_contract.py, blob-bound by the CodeQL dispositions manifest",
    ".github/workflows/b216-receiver-deploy-nonprod.yml": "receiver-identity PR: receiver path boundary of verify_i2574 (critic K1.4)",
}

LEGACY_IDS = ("1232040291", "1380335483")
NAME_GUARD = re.compile(r"github\.repository\s*(?:==|!=)\s*'")
EVENT_REPOSITORY_GUARD = re.compile(r"github\.event\.repository\.\w+\s*(?:==|!=)\s*'")
SHELL_GUARD = re.compile(r"\$\{?GITHUB_REPOSITORY(?:_ID)?\}?\"?\s*(?:=|==|!=|-eq|-ne)\s")
FORWARD = re.compile(r"github\.repository_id\s*(==|!=)\s*(\S+)")
REVERSED = re.compile(r"(\S+)\s*(==|!=)\s*github\.repository_id\b")
LITERAL = re.compile(r"^'(\d+)'\)?$")
RENDER = re.compile(r"(github\.repository_id == ')(\d+)(')")


class Finding(NamedTuple):
    path: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


class Report(NamedTuple):
    findings: list[Finding]
    workflows: int
    routine: dict[str, int]
    privileged: dict[str, list[tuple[int, str]]]


def _workflow_texts(root: Path, overrides: Mapping[str, str] | None) -> dict[str, str]:
    directory = root / WORKFLOWS
    if not directory.is_dir():
        return {}
    texts = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
        if path.is_file()
    }
    for path, text in (overrides or {}).items():
        texts[path] = text
    return texts


def _privileged(text: str) -> bool:
    import yaml  # PyYAML; a missing module is an instrument error, not a pass.

    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("workflow is not a mapping")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError("workflow has no jobs mapping")

    def grants_oidc(permissions: object) -> bool:
        if permissions == "write-all":
            return True
        return isinstance(permissions, dict) and permissions.get("id-token") == "write"

    if grants_oidc(data.get("permissions")):
        return True
    for job in jobs.values():
        if not isinstance(job, dict):
            raise ValueError("job is not a mapping")
        if "environment" in job or grants_oidc(job.get("permissions")):
            return True
    return False


def _legacy(path: str, text: str) -> list[Finding]:
    found: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        if NAME_GUARD.search(line):
            found.append(Finding(path, number, "repository name guard (use the repository-ID guard)"))
        if EVENT_REPOSITORY_GUARD.search(line):
            found.append(Finding(path, number, "event repository literal guard (use the repository-ID guard)"))
        if SHELL_GUARD.search(line):
            found.append(Finding(path, number, "shell repository comparison (test the guard expression instead)"))
        for legacy in LEGACY_IDS:
            if legacy in line:
                found.append(Finding(path, number, f"retired repository ID {legacy}"))
    return found


def _read_server_id(root: Path) -> tuple[int | None, str | None]:
    path = root / CONFIG
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"{CONFIG} is missing (it lands with the identity source of truth, I1)"
    except (OSError, ValueError) as exc:
        return None, f"{CONFIG} is unreadable: {exc.__class__.__name__}"
    try:
        value = data["current"]["repos"]["server"]["id"]
    except (KeyError, TypeError):
        return None, f"{CONFIG} has no current.repos.server.id"
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None, f"{CONFIG} current.repos.server.id is not a non-negative integer"
    if value == 0:
        return None, f"{CONFIG} current.repos.server.id is 0: the server repository ID has not been read back"
    return value, None


def check(
    root: Path = ROOT,
    *,
    structure_only: bool = False,
    pending: Mapping[str, str] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> Report:
    pending = PENDING if pending is None else pending
    findings: list[Finding] = []
    texts = _workflow_texts(root, overrides)
    routine: dict[str, int] = {}
    privileged: dict[str, list[tuple[int, str]]] = {}
    if not texts:
        findings.append(Finding(WORKFLOWS.as_posix(), 0, "no workflow files found: the population is empty"))
        return Report(findings, 0, routine, privileged)

    for path, reason in sorted(pending.items()):
        if not reason.strip():
            findings.append(Finding(path, 0, "ledger entry has no reason"))
        if path not in texts:
            findings.append(Finding(path, 0, "ledger entry names a workflow that does not exist"))
        elif not _legacy(path, texts[path]):
            findings.append(Finding(path, 0, "stale ledger entry: the workflow has no legacy guard left; remove the row"))

    for path, text in texts.items():
        if path in pending:
            continue
        findings.extend(_legacy(path, text))
        try:
            is_privileged = _privileged(text)
        except ImportError:
            raise
        except Exception as exc:  # noqa: BLE001 - every parse failure is a named finding
            findings.append(Finding(path, 0, f"cannot classify workflow: {exc.__class__.__name__}: {exc}"))
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for match in REVERSED.finditer(line):
                if match.group(1) != FORK_CHECK_LHS or match.group(2) != "==":
                    findings.append(Finding(path, number, "reversed repository-ID comparison is not a canonical guard"))
            for match in FORWARD.finditer(line):
                operator, rhs = match.groups()
                if rhs.endswith("}}"):
                    rhs = rhs[:-2]
                literal = LITERAL.match(rhs)
                if operator != "==":
                    findings.append(Finding(path, number, "negated repository-ID comparison is not a canonical guard"))
                elif rhs.rstrip(")") == ROUTINE_FORM:
                    if is_privileged:
                        findings.append(Finding(path, number, "privileged workflow uses the routine vars guard; it needs the rendered literal"))
                    else:
                        routine[path] = routine.get(path, 0) + 1
                elif literal:
                    if is_privileged:
                        privileged.setdefault(path, []).append((number, literal.group(1)))
                    else:
                        findings.append(Finding(path, number, f"routine workflow pins a literal repository ID; use {ROUTINE_FORM}"))
                elif rhs == FORK_CHECK_LHS:
                    continue
                else:
                    findings.append(Finding(path, number, f"repository-ID comparison against {rhs!r} is not a canonical guard"))

    if not routine and not privileged:
        findings.append(Finding(WORKFLOWS.as_posix(), 0, "no canonical repository-ID guard found: the extraction found nothing to check"))

    if not structure_only:
        server_id, problem = _read_server_id(root)
        if problem:
            findings.append(Finding(CONFIG.as_posix(), 0, problem))
        else:
            for path, literals in sorted(privileged.items()):
                for number, value in literals:
                    if value != str(server_id):
                        findings.append(Finding(path, number, f"privileged literal {value} differs from {CONFIG} ({server_id}); run --write"))
    return Report(findings, len(texts), routine, privileged)


def write(root: Path = ROOT, *, pending: Mapping[str, str] | None = None) -> tuple[int, list[str]]:
    """Render the configured server ID into every privileged literal guard."""
    server_id, problem = _read_server_id(root)
    if problem:
        return 0, [problem]
    report = check(root, structure_only=True, pending=pending)
    changed = 0
    for path in sorted(report.privileged):
        target = root / path
        text = target.read_text(encoding="utf-8")
        rendered = RENDER.sub(lambda m: f"{m.group(1)}{server_id}{m.group(3)}", text)
        if rendered != text:
            target.write_text(rendered, encoding="utf-8")
            changed += 1
    return changed, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="structure and value (default)")
    mode.add_argument("--structure-only", action="store_true", help="skip the config value check")
    mode.add_argument("--write", action="store_true", help="render privileged literals from the config, then check")
    args = parser.parse_args(argv)
    try:
        if args.write:
            changed, problems = write()
            if problems:
                for problem in problems:
                    print(f"REFUSED: {problem}", file=sys.stderr)
                return 1
            print(f"rendered the server repository ID into {changed} privileged workflow(s)")
        report = check(structure_only=args.structure_only)
    except ImportError as exc:
        print(f"INSTRUMENT ERROR: {exc}; PyYAML is required to classify workflows", file=sys.stderr)
        return 2
    for finding in report.findings:
        print(finding, file=sys.stderr)
    if report.findings:
        print(f"FAIL: {len(report.findings)} finding(s)", file=sys.stderr)
        return 1
    literal_count = sum(len(rows) for rows in report.privileged.values())
    print(
        f"OK: {report.workflows} workflows; routine guards {sum(report.routine.values())} in "
        f"{len(report.routine)} workflows; privileged literals {literal_count} in "
        f"{len(report.privileged)} workflows; {len(PENDING)} ledger rows pending other work packages"
        + ("; value check skipped (--structure-only)" if args.structure_only else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
