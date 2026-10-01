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
    if smoke.get("runs-on") != "ubuntu-24.04":
        raise AssertionError("normal smoke job must remain statically pinned to Ubuntu")
    if smoke.get("if") != "github.event_name != 'workflow_dispatch' || inputs.mode != 'build_only'":
        raise AssertionError("normal smoke job must skip build_only")

    build = jobs["build-only-verifier"]
    if build.get("runs-on") != "macos-15":
        raise AssertionError("build_only must use the standard statically declared macOS arm64 runner")
    if build.get("if") != "github.event_name == 'workflow_dispatch' && inputs.mode == 'build_only'":
        raise AssertionError("native artifact job must run only for explicit build_only dispatch")
    if build.get("permissions") != {"contents": "read"}:
        raise AssertionError("build_only permissions must remain contents:read only")
    if "secrets." in str(build) or "CF_API_TOKEN" in str(build) or "PAGERDUTY" in str(build):
        raise AssertionError("build_only job must not reference production secrets or paging")
    build_steps = {step.get("name"): step for step in build["steps"]}
    checkout = build_steps["Checkout repo"]
    if checkout.get("with", {}).get("persist-credentials") != "false":
        raise AssertionError("build_only checkout must not persist its read token")
    validate = build_steps["Validate closed build-only dispatch"]
    if (
        '[[ "$GITHUB_REF" == "refs/heads/main" ]]' not in validate["run"]
        or '"$EXPECTED_SHA" == "$GITHUB_SHA"' not in validate["run"]
        or "^[0-9a-f]{40}$" not in validate["run"]
    ):
        raise AssertionError("build_only must be bound to the exact main commit")
    native = build_steps["Assert native macOS arm64 Rust target"]["run"]
    if "uname -m" not in native or "arm64" not in native or "aarch64-apple-darwin" not in native:
        raise AssertionError("build_only must prove native Apple Silicon execution")
    for name in ("Create build-only provenance", "Upload native arm64 verifier artifact"):
        if name not in build_steps:
            raise AssertionError(f"build_only job missing {name}")
    provenance = build_steps["Create build-only provenance"]["run"]
    for claim in ("source_blob", "crate_source_tree_sha256", "cargo_lock_sha256", "binary_sha256", "runner_arch", "rust_host"):
        if claim not in provenance:
            raise AssertionError(f"provenance missing {claim}")
    if "github.event_name != 'workflow_dispatch' || inputs.mode != 'build_only'" != jobs["seven-day-verify"].get("if"):
        raise AssertionError("production verifier job must be skipped for build_only")
    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError("workflow token permissions must stay contents:read only")

    walk = next(step for step in jobs["seven-day-verify"]["steps"] if step.get("id") == "walk")
    if walk.get("env", {}).get("DATES") != "${{ steps.window.outputs.dates }}":
        raise AssertionError("window dates must be bound through the step environment")
    if "${{" in walk.get("run", "") or "steps.window.outputs.dates" in walk.get("run", ""):
        raise AssertionError("the long production shell body must not contain GitHub template expressions")


def main() -> int:
    verify((Path(__file__).resolve().parents[1] / WORKFLOW).read_text())
    print("#1648 build-only workflow guard: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
