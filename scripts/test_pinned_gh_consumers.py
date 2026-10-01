#!/usr/bin/env python3
"""Credentialless hosted smoke of real gh guard steps and release auth scopes."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from install_pinned_gh import install

ROOT = Path(__file__).resolve().parent.parent
GUARD = 'python3 scripts/verify_pinned_gh.py --binary "${RUNNER_TEMP}/corelink-pinned-gh/gh"'
CONSUMERS = (
    ("release-cli.yml", "release", "release"),
    ("release-cli.yml", "final-manifest", "final-manifest"),
    ("release-cli.yml", "publish-release", "publish-release"),
    ("release-cli.yml", "verify-draft-release", "verify-draft-release"),
    ("sign-linux.yml", "sign", "Linux signer"),
    ("release-slsa3.yml", "attest-final-inventory", "SLSA consumer"),
)
WORKFLOWS = ("release-cli.yml", "sign-linux.yml", "release-slsa3.yml")
TARGET_READ_TOKEN = "${{ secrets.CORELINK_CLI_RELEASE_TOKEN }}"
TARGET_STEP_COUNTS = {"release-cli.yml": 8, "sign-linux.yml": 4, "release-slsa3.yml": 3}
ATTESTATION_STEP_COUNTS = {"release-cli.yml": 2, "sign-linux.yml": 0, "release-slsa3.yml": 1}
OLD_DATE = "2025-09-08"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_workflows() -> dict[str, dict[str, Any]]:
    return {
        name: yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
        for name in WORKFLOWS
    }


def guard_step(workflow: dict[str, Any], workflow_name: str, job_name: str) -> dict[str, Any]:
    job = workflow.get("jobs", {}).get(job_name)
    require(isinstance(job, dict), f"{workflow_name}:{job_name} job is missing")
    matches = [step for step in job.get("steps", []) if step.get("name") == "Verify pinned GitHub CLI"]
    require(len(matches) == 1, f"{workflow_name}:{job_name} must have exactly one pinned CLI guard")
    step = matches[0]
    require(step.get("shell") == "bash", f"{workflow_name}:{job_name} guard must run under Bash")
    require("if" not in step, f"{workflow_name}:{job_name} guard must be unconditional")
    require(step.get("continue-on-error") is not True,
            f"{workflow_name}:{job_name} guard failure must stop the consumer")
    run = step.get("run")
    require(isinstance(run, str) and run.count(GUARD) == 1,
            f"{workflow_name}:{job_name} must execute the shared absolute-binary guard")
    require(OLD_DATE not in run, f"{workflow_name}:{job_name} has the obsolete hardcoded date")
    return step


def assert_release_auth(workflows: dict[str, dict[str, Any]]) -> None:
    target_counts = {name: 0 for name in WORKFLOWS}
    attestation_counts = {name: 0 for name in WORKFLOWS}
    for workflow_name, workflow in workflows.items():
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                run = step.get("run", "")
                if not isinstance(run, str):
                    continue
                if (
                    "gh api " in run
                    or "gh release " in run
                    or "scripts/cli_release_api.py" in run
                ):
                    target_counts[workflow_name] += 1
                    token = step.get("env", {}).get("GH_TOKEN")
                    require(token == TARGET_READ_TOKEN,
                            f"{workflow_name}:{job_name}:{step.get('name')} must bind the destination release token")
                if "gh attestation verify " in run:
                    attestation_counts[workflow_name] += 1
                    for required in (
                        "--bundle",
                        "--signer-workflow",
                        "--source-ref",
                        "--source-digest",
                        "--cert-oidc-issuer",
                    ):
                        require(required in run,
                                f"{workflow_name}:{job_name}:{step.get('name')} lacks {required}")
                    require("--repo \"${GITHUB_REPOSITORY}\"" in run or "--repo \"${REPO}\"" in run,
                            f"{workflow_name}:{job_name}:{step.get('name')} must verify the source repository identity")
                    require(step.get("env", {}).get("GH_TOKEN") == TARGET_READ_TOKEN,
                            f"{workflow_name}:{job_name}:{step.get('name')} must have the required read credential for its target inventory step")
    require(target_counts == TARGET_STEP_COUNTS,
            f"release command census changed: expected {TARGET_STEP_COUNTS}, got {target_counts}")
    require(attestation_counts == ATTESTATION_STEP_COUNTS,
            f"attestation command census changed: expected {ATTESTATION_STEP_COUNTS}, got {attestation_counts}")


def execute_run(run: str, runner_temp: Path, path: str) -> subprocess.CompletedProcess[str]:
    home = runner_temp / "runner-home"
    config = runner_temp / "runner-config"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        "PATH": path,
        "HOME": str(home),
        "GH_CONFIG_DIR": str(config),
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_WORKSPACE": str(ROOT),
    }
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", run],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def assert_bundle_suffix_behavior(binary: Path, runner_temp: Path) -> None:
    """Prove the actual pinned CLI rejects `.bundle` and accepts `.json` parsing."""
    fixture = runner_temp / "bundle-extension-fixture"
    fixture.mkdir(mode=0o700)
    artifact = fixture / "subject.bin"
    artifact.write_bytes(b"fixed offline bundle suffix fixture")
    unsupported = fixture / "attestation.bundle"
    supported = fixture / "attestation.json"
    malformed = b"{}\n"
    unsupported.write_bytes(malformed)
    supported.write_bytes(malformed)
    environment = {
        "PATH": str(binary.parent),
        "HOME": str(fixture / "home"),
        "GH_CONFIG_DIR": str(fixture / "config"),
        "LC_ALL": "C",
        "GH_TOKEN": "",
        "GH_ENTERPRISE_TOKEN": "",
        "GITHUB_ENTERPRISE_TOKEN": "",
    }
    Path(environment["HOME"]).mkdir(mode=0o700)
    Path(environment["GH_CONFIG_DIR"]).mkdir(mode=0o700)
    common = [
        str(binary), "attestation", "verify", str(artifact),
        "--repo", "HuGR-Labs/corelink-cli",
        "--signer-workflow", "HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml",
        "--source-ref", "refs/tags/cli-v0.1.7",
        "--source-digest", "d36cb1639ecd406e304d612da4143e9b28fba6a7",
        "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
    ]
    rejected = subprocess.run(
        [*common, "--bundle", str(unsupported)], capture_output=True, text=True,
        env=environment, check=False, timeout=20,
    )
    require(rejected.returncode != 0 and "bundle file extension not supported" in rejected.stderr,
            "pinned gh must reject the public `.bundle` suffix with its exact extension error")
    parsed = subprocess.run(
        [*common, "--bundle", str(supported)], capture_output=True, text=True,
        env=environment, check=False, timeout=20,
    )
    require(parsed.returncode != 0 and "bundle file extension not supported" not in parsed.stderr,
            "pinned gh must accept `.json` and proceed to parse the bundle without network credentials")


def main() -> int:
    workflows = read_workflows()
    consumers = []
    for workflow_name, job_name, label in CONSUMERS:
        step = guard_step(workflows[workflow_name], workflow_name, job_name)
        consumers.append((label, step["run"]))
    assert_release_auth(workflows)

    # Source controls prove the exact stale-date, reachable-step, and auth omissions fail closed.
    release_workflow = copy.deepcopy(workflows["release-cli.yml"])
    release_guard = guard_step(release_workflow, "release-cli.yml", "release")
    release_guard["run"] = release_guard["run"].replace(
        GUARD, f"gh --version | grep -Fx 'gh version 2.79.0 ({OLD_DATE})'", 1
    )
    try:
        guard_step(release_workflow, "release-cli.yml", "release")
    except AssertionError:
        pass
    else:
        raise AssertionError("obsolete 2025-09-08 workflow guard mutation must be rejected")

    unreachable = copy.deepcopy(workflows["release-cli.yml"])
    unreachable_guard = guard_step(unreachable, "release-cli.yml", "release")
    unreachable_guard["if"] = "false"
    try:
        guard_step(unreachable, "release-cli.yml", "release")
    except AssertionError:
        pass
    else:
        raise AssertionError("conditional pinned CLI guard mutation must be rejected")

    missing_target_auth = copy.deepcopy(workflows["release-slsa3.yml"])
    auth_step = next(
        step for step in missing_target_auth["jobs"]["attest-final-inventory"]["steps"]
        if step.get("name") == "Verify official identity, issuer, and every exact subject"
    )
    auth_step.get("env", {}).pop("GH_TOKEN", None)
    try:
        assert_release_auth({**workflows, "release-slsa3.yml": missing_target_auth})
    except AssertionError:
        pass
    else:
        raise AssertionError("missing destination read credential mutation must be rejected")

    with tempfile.TemporaryDirectory(prefix="corelink-pinned-gh-consumers-") as temporary:
        root = Path(temporary)
        runner_temp = root / "runner-temp"
        binary_dir = runner_temp / "corelink-pinned-gh"
        binary_dir.mkdir(mode=0o700, parents=True)
        binary = binary_dir / "gh"
        installed = install(binary)
        require(installed == binary, "installer returned a different executable path")
        assert_bundle_suffix_behavior(binary, runner_temp)
        python_dir = str(Path(sys.executable).resolve().parent)
        pinned_path = os.pathsep.join((str(binary_dir), python_dir, os.defpath))

        for label, run in consumers:
            result = execute_run(run, runner_temp, pinned_path)
            if result.returncode != 0:
                raise AssertionError(f"{label} actual Bash guard failed: {result.stderr.strip()}")
            require("verified pinned gh path:" in result.stdout,
                    f"{label} actual Bash guard did not report the verified executable path")
            print(f"{label}: {result.stdout.splitlines()[-1]}")
            mutant = execute_run(f"{run}\nexit 23", runner_temp, pinned_path)
            require(mutant.returncode == 23, f"{label} smoke accepted an appended guard failure")

        release_run = consumers[0][1]
        stale_date_run = release_run.replace(
            GUARD, f"gh --version | grep -Fx 'gh version 2.79.0 ({OLD_DATE})'", 1
        )
        stale_date_result = execute_run(stale_date_run, runner_temp, pinned_path)
        require(stale_date_result.returncode != 0,
                "actual pinned binary must reject the stale 2025-09-08 expected-date guard")

        unpinned_dir = root / "unpinned"
        unpinned_dir.mkdir(mode=0o700)
        unpinned = unpinned_dir / "gh"
        unpinned.write_text("#!/bin/sh\nprintf '%s\\n' 'gh version 2.79.0 (2025-09-09)'\n", encoding="utf-8")
        unpinned.chmod(0o700)
        unpinned_result = execute_run(consumers[0][1], runner_temp,
                                      os.pathsep.join((str(unpinned_dir), str(binary_dir), python_dir, os.defpath)))
        require(unpinned_result.returncode != 0 and "PATH does not resolve" in unpinned_result.stderr,
                "actual Bash guard must reject an unpinned PATH executable")

        wrong_temp = root / "wrong-runner-temp"
        wrong_bin_dir = wrong_temp / "corelink-pinned-gh"
        wrong_bin_dir.mkdir(mode=0o700, parents=True)
        wrong_binary = wrong_bin_dir / "gh"
        wrong_binary.write_text("#!/bin/sh\nprintf '%s\\n' 'gh version 2.80.0 (2025-09-09)'\n", encoding="utf-8")
        wrong_binary.chmod(0o700)
        wrong_result = execute_run(consumers[0][1], wrong_temp,
                                   os.pathsep.join((str(wrong_bin_dir), python_dir, os.defpath)))
        require(wrong_result.returncode != 0 and "digest mismatch" in wrong_result.stderr,
                "actual Bash guard must reject a wrong-version executable by digest")

    print("checksum-pinned Linux gh, actual bundle suffix behavior, six Bash guards, auth census, negatives: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
