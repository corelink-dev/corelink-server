#!/usr/bin/env python3
"""Fail-closed guard for the credentialless #1648 verifier artifact mode."""

from __future__ import annotations

from pathlib import Path

import yaml


WORKFLOW = Path(".github/workflows/audit-chain-daily-verify.yml")


def verify(source: str) -> None:
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    dispatch = workflow["on"]["workflow_dispatch"]["inputs"]
    mode = dispatch["mode"]
    if mode.get("type") != "choice" or mode.get("options") != ["full", "build_only"] or mode.get("default") != "full":
        raise AssertionError("mode must be the closed full/build_only choice and default to full")
    if dispatch["expected_sha"].get("required") != "false":
        raise AssertionError("expected_sha is optional only because normal dispatch does not need it")

    jobs = workflow["jobs"]
    smoke = jobs["smoke-verify"]
    if "macos-15" not in smoke["runs-on"] or "ubuntu-24.04" not in smoke["runs-on"]:
        raise AssertionError("only build_only may select the standard macOS arm64 runner")
    steps = smoke["steps"]
    by_name = {step.get("name"): step for step in steps}
    validate = by_name["Validate closed build-only dispatch and native runner"]
    if (
        '[[ "$GITHUB_REF" == "refs/heads/main" ]]' not in validate["run"]
        or '"$EXPECTED_SHA" == "$GITHUB_SHA"' not in validate["run"]
        or "^[0-9a-f]{40}$" not in validate["run"]
    ):
        raise AssertionError("build_only must be bound to the exact main commit")
    native = by_name["Assert native macOS arm64 Rust target"]["run"]
    if "uname -m" not in native or "arm64" not in native or "aarch64-apple-darwin" not in native:
        raise AssertionError("build_only must prove native Apple Silicon execution")
    for name in ("Create build-only provenance", "Upload native arm64 verifier artifact"):
        if "inputs.mode == 'build_only'" not in by_name[name].get("if", ""):
            raise AssertionError(f"{name} must only run for build_only")
    provenance = by_name["Create build-only provenance"]["run"]
    for claim in ("source_blob", "crate_source_tree_sha256", "cargo_lock_sha256", "binary_sha256", "runner_arch", "rust_host"):
        if claim not in provenance:
            raise AssertionError(f"provenance missing {claim}")
    if "secrets." in provenance or "CF_API_TOKEN" in provenance or "PAGERDUTY" in provenance:
        raise AssertionError("artifact provenance must contain no production credentials")
    if "github.event_name != 'workflow_dispatch' || inputs.mode != 'build_only'" != jobs["seven-day-verify"].get("if"):
        raise AssertionError("production verifier job must be skipped for build_only")
    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError("workflow token permissions must stay contents:read only")


def main() -> int:
    verify((Path(__file__).resolve().parents[1] / WORKFLOW).read_text())
    print("#1648 build-only workflow guard: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
