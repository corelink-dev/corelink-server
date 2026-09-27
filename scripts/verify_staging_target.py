#!/usr/bin/env python3
"""Fail-closed contract check for the unprovisioned #1700 staging target."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ORIGIN = "https://staging.corelink.humangr.com"
CONTRACT = Path("infra/staging/topology.json")
WORKFLOWS = (Path(".github/workflows/load-test-nightly.yml"), Path(".github/workflows/endurance-2h-nightly.yml"))
SECRETS = {
    "K6_STAGING_BYOK_CMK_ID",
    "K6_STAGING_MFA_STUB",
    "K6_STAGING_PAT",
    "K6_STAGING_STRIPE_WHSEC",
    "K6_STAGING_TEARDOWN_TOKEN",
    "K6_TARGET_IDENTITY_RECEIPT",
    "K6_TARGET_HOST",
}
RESOURCES = {"corelink-config-staging", "corelink-cas-staging", "corelink-ac-iad-staging", "corelink-chunk-iad-staging", "corelink-manifest-iad-staging", "corelink-metadata-staging", "corelink-clerk-jwks-staging", "corelink-negative-cache-staging", "corelink-dsr-erasure-staging", "corelink-dsr-erasure-dlq-staging"}


def assess(root: Path) -> list[str]:
    data = json.loads((root / CONTRACT).read_text(encoding="utf-8"))
    gaps: list[str] = []
    if data.get("schema_version") != 1 or data.get("issue") != 1700:
        gaps.append("schema-or-issue")
    if data.get("deployment_state") != "unprovisioned":
        gaps.append("deployment-must-remain-unprovisioned")
    if data.get("canonical_origin") != ORIGIN:
        gaps.append("canonical-origin")
    owner = data.get("ownership", {})
    if owner.get("owner") != "SRE Lead" or set(owner.get("approvers", [])) != {"SRE Lead", "Security Lead"}:
        gaps.append("ownership")
    budget = data.get("budget", {})
    if budget.get("enforce_before_apply") is not True or budget.get("workflow_timeout_minutes") != 145 or budget.get("max_load_run", 0) <= 0 or budget.get("max_endurance_run", 0) <= 0 or budget.get("monthly_cap", 0) <= 0:
        gaps.append("budget")
    life = data.get("lifecycle", {})
    teardown = life.get("teardown", {})
    if not (0 < life.get("lease_ttl_hours", 0) <= 24 and 0 < life.get("idle_teardown_after_hours", 0) <= 2 and life.get("r2_object_ttl_hours") == 24 and teardown.get("manual_only") is True and teardown.get("automatic") is False and teardown.get("fail_closed") is True):
        gaps.append("lifecycle-or-teardown")
    inputs = data.get("validated_inputs", {})
    if inputs.get("runner_label") != "corelink" or inputs.get("target_host") != ORIGIN or set(inputs.get("load_scenarios", [])) != {"signup", "webhook", "dsr", "cas", "byok"} or set(inputs.get("endurance_durations", [])) != {"30s", "2h"} or set(inputs.get("required_secret_names", [])) != SECRETS:
        gaps.append("validated-inputs")
    outputs = data.get("outputs", {})
    if outputs.get("target_host") != ORIGIN or outputs.get("github_environment") != "staging" or set(outputs.get("resource_names", [])) != RESOURCES:
        gaps.append("outputs")
    cf = data.get("cloudflare", {})
    if cf.get("zone_name") != "humangr.com" or cf.get("route") != "staging.corelink.humangr.com" or cf.get("root_worker") != "corelink-staging" or cf.get("signup_worker") != "corelink-signup-staging" or cf.get("synthetic_receiver_worker") != "corelink-synthetic-pager-staging":
        gaps.append("cloudflare-boundary")
    settings = cf.get("root_worker_settings", {})
    if settings.get("workers_dev") is not False or settings.get("crons") != [] or settings.get("observability", {}).get("enabled") is not True:
        gaps.append("worker-isolation")
    if settings.get("compatibility_flags") != ["nodejs_compat", "enable_request_signal", "request_signal_passthrough"]:
        gaps.append("root-request-signal-compatibility")
    if cf.get("container", {}).get("max_instances") != 5 or cf.get("container", {}).get("instance_type") != "basic":
        gaps.append("container-budget")
    serialized = json.dumps(data, sort_keys=True)
    if re.search(r'(?i)(secret|token|password|credential)[^,}]*:', serialized) and re.search(r'(?i)(secret|token|password|credential)[^,}]*:\s*"(?!K6_|https?://)', serialized):
        gaps.append("possible-secret-value")
    for resource in data.get("outputs", {}).get("resource_names", []):
        if not isinstance(resource, str) or not resource.endswith("-staging"):
            gaps.append("non-staging-resource-name")
            break
    for path in WORKFLOWS:
        text = (root / path).read_text(encoding="utf-8")
        if "CANONICAL_TARGET='https://staging.corelink.humangr.com'" not in text or 'TARGET_HOST="${K6_TARGET_HOST%/}"' not in text or '[[ "$TARGET_HOST" != "$CANONICAL_TARGET" ]]' not in text:
            gaps.append(f"workflow-host:{path.name}")
    endurance = (root / WORKFLOWS[1]).read_text(encoding="utf-8")
    dispatch = re.search(r"(?ms)^  workflow_dispatch:\s*\n(?P<body>.*?)(?=^\S|\Z)", endurance)
    inputs = (
        re.search(r"(?ms)^    inputs:\s*\n(?P<body>.*?)(?=^  \S|\Z)", dispatch.group("body"))
        if dispatch
        else None
    )
    duration_input = (
        re.search(r"(?ms)^      duration:\s*\n(?P<body>.*?)(?=^      \S|\Z)", inputs.group("body"))
        if inputs
        else None
    )
    duration_block = duration_input.group("body") if duration_input else ""
    option_block = re.search(
        r"(?ms)^        options:\s*\n(?P<body>(?:^          -[^\n]*\n)+)", duration_block
    )
    options = (
        set(
            re.findall(
                r"(?m)^          -\s*['\"]?([^'\"#\n]+?)['\"]?\s*$",
                option_block.group("body"),
            )
        )
        if option_block
        else set()
    )
    input_type = re.search(r"(?m)^        type:\s*([^\s#]+)\s*$", duration_block)
    required = re.search(r"(?m)^        required:\s*true\s*$", duration_block)
    default = re.search(r"(?m)^        default:\s*['\"]?([^'\"#\n]+?)['\"]?\s*$", duration_block)
    syntax_step = re.search(
        r"(?ms)^      - name: validate script syntax\n(?P<body>.*?)(?=^      - |\Z)", endurance
    )
    has_bounded_syntax_duration = bool(
        syntax_step and re.search(r"(?m)^\s*-e DURATION=30s\s*\\?$", syntax_step.group("body"))
    )
    preflight_step = re.search(
        r"(?ms)^      - name: pre-flight target host check\n(?P<body>.*?)(?=^      - |\Z)",
        endurance,
    )
    has_runtime_budget_guard = bool(
        preflight_step and "test \"${DURATION}\" = '2h' || {" in preflight_step.group("body")
    )
    has_dispatch_duration_binding = bool(
        preflight_step
        and re.search(
            r"(?m)^          DURATION:\s*\$\{\{\s*github\.event\.inputs\.duration\s*\|\|\s*['\"]2h['\"]\s*\}\}\s*$",
            preflight_step.group("body"),
        )
    )
    if (
        not duration_input
        or not input_type
        or input_type.group(1) != "choice"
        or not required
        or not default
        or default.group(1) != "2h"
        or options != {"2h"}
        or not has_bounded_syntax_duration
        or not has_runtime_budget_guard
        or not has_dispatch_duration_binding
    ):
        gaps.append("workflow-duration-budget")
    if re.search(r"(?m)^\s*\[env\.staging\]\s*$", (root / "wrangler.toml").read_text(encoding="utf-8")):
        gaps.append("partial-wrangler-staging-environment")
    return sorted(set(gaps))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    gaps = assess(args.root.resolve())
    print(f"staging target contract: {'OPEN' if gaps else 'READY TO PROVISION'} ({len(gaps)} gap(s))")
    for gap in gaps:
        print(f"- {gap}")
    return 1 if gaps else 0


if __name__ == "__main__":
    raise SystemExit(main())
