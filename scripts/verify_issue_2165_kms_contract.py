#!/usr/bin/env python3
"""Credentialless static guard for the Issue #2165 AWS KMS workflow contract.

This checks only the workflow source and CLI inputs. It never loads credentials,
contacts AWS, or treats a workflow inspection as proof that the workflow ran.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PROTECTED_ENVIRONMENT = "b083-kms-lifecycle"
PHASES = frozenset({"inventory", "pregrant-deny", "postgrant-readonly", "lifecycle", "cleanup"})
REQUIRED_BINDINGS = (
    "B083_AWS_ACCOUNT_ID",
    "B083_AWS_REGION",
    "B083_AWS_PREFLIGHT_ROLE_ARN",
    "B083_AWS_CONTROLLER_ROLE_ARN",
    "B083_AWS_CUSTODIAN_ROLE_ARN",
    "B083_AWS_RUNTIME_ROLE_ARN",
    "B083_AWS_OPERATOR_TASK_DEFINITION_ARN",
    "B083_AWS_OPERATOR_ROLE_ARN",
    "B083_AWS_APP_EXECUTION_ROLE_ARN",
    "B083_AWS_OPERATOR_EXECUTION_ROLE_ARN",
    "B083_AWS_OPERATOR_IMAGE_URI",
    "B083_AWS_CLUSTER_ARN",
    "B083_AWS_TASK_DEFINITION_ARN",
    "B083_IMAGE_URI",
    "B083_D1_DATABASE_ID",
    "B083_D1_REGION",
    "B083_R2_S3_ENDPOINT",
    "B083_CF_ACCOUNT_ID",
    "B083_AUDIT_SINK_REF",
    "B083_CUSTODIAN_REF",
    "B083_RUNTIME_CONFIG_SECRET_ARN",
    "B083_TARGET_MANIFEST_SECRET_ARN",
    "B083_KMS_KEY_ARN",
)
MUTATING_AWS_ACTION = re.compile(
    r"\baws\s+(?:[\w-]+\s+)*(?:create|put|update|delete|remove|attach|detach|modify|"
    r"associate|disassociate|enable|disable|schedule|cancel|revoke|grant|import|"
    r"tag|untag|register|deregister|start|stop|run|execute|invoke|rotate|restore|"
    r"set|write|apply|deploy|upload|copy|sync|push|publish)[\w-]*\b",
    re.IGNORECASE,
)
RUNTIME_KMS_COMMAND = re.compile(r"\baws\s+kms\s+(?:encrypt|decrypt)\b", re.IGNORECASE)
STOP_RUNTIME_COMMAND = re.compile(r"\baws\s+ecs\s+stop-task\b", re.IGNORECASE)
RUNTIME_TASK_COMMAND = re.compile(r"\baws\s+ecs\s+run-task\b", re.IGNORECASE)
RUNTIME_OPERATOR_COMMAND = re.compile(r"\bpython(?:3)?\s+scripts/issue_2165_kms_runtime\.py\b")
SIMULATION_ACTIONS = frozenset({"kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"})
FORBIDDEN_SIMULATION_ACTIONS = frozenset({
    "kms:GenerateDataKey", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant", "kms:ScheduleKeyDeletion"
})
WRITE_PERMISSION = re.compile(r"^\s*[\w-]+\s*:\s*write\s*$", re.MULTILINE | re.IGNORECASE)
SECRET_LIKE = re.compile(r"\$\{\{\s*secrets\.B083_KMS_KEY_ARN\s*\}\}")


class ContractError(ValueError):
    """The proposed workflow or invocation violates the frozen contract."""


def validate_runtime_source(runtime_text: str) -> None:
    """Require the runner to bind and independently read two distinct tasks."""
    required_markers = (
        'aws["task_definition_arn"] == operator["task_definition_arn"]',
        'aws["runtime_role_arn"] == operator["operator_role_arn"]',
        'len(set(op_roles + [aws["controller_role_arn"], aws["runtime_role_arn"], aws["execution_role_arn"], aws["custodian_role_arn"]])) != 6',
        'desc.get("taskDefinitionArn") != aws["task_definition_arn"]',
        'operator_desc.get("taskDefinitionArn") != operator["task_definition_arn"]',
        'desc.get("taskRoleArn") != aws["runtime_role_arn"]',
        'operator_desc.get("taskRoleArn") != operator["operator_role_arn"]',
        'desc.get("executionRoleArn") != aws["execution_role_arn"]',
        'operator_desc.get("executionRoleArn") != operator["operator_execution_role_arn"]',
        'app.get("image") != aws["image_uri"]',
        'sidecar.get("image") != operator["image_uri"]',
        '"ecs", "describe-task-definition", "--task-definition", aws["task_definition_arn"]',
        '"ecs", "describe-task-definition", "--task-definition", operator["task_definition_arn"]',
        '"B083_AWS_CONTROLLER_ROLE_ARN": aws["controller_role_arn"]',
        '"B083_AWS_CUSTODIAN_ROLE_ARN": aws["custodian_role_arn"]',
        '"B083_AWS_APP_EXECUTION_ROLE_ARN": aws["execution_role_arn"]',
        '"B083_AWS_OPERATOR_EXECUTION_ROLE_ARN": operator["operator_execution_role_arn"]',
        '"B083_D1_REGION": d1["region"]',
        '"B083_CF_ACCOUNT_ID": cf_account',
        'stream.write(f"app_task_arn={app_task}\\noperator_task_arn={operator_task}\\nruntime_run_id={run_id}\\n")',
        '"B083_ISSUE2165_APP_TASK_ARN"',
        '"B083_ISSUE2165_OPERATOR_TASK_ARN"',
        '"B083_ISSUE2165_RUN_ID"',
    )
    missing = [marker for marker in required_markers if marker not in runtime_text]
    if missing:
        raise ContractError("runtime source must verify exact separate app/operator task roles, images, and definitions")
    live_read = runtime_text.find("verify_live_target(m, runner)")
    task_start = runtime_text.find("_start_task(m, m[\"aws\"][\"task_definition_arn\"]")
    if live_read < 0 or task_start < 0 or live_read > task_start:
        raise ContractError("runtime source must read back both exact task definitions before starting either task")
    handoff_start = runtime_text.find("def _write_handoff_outputs(")
    handoff_end = runtime_text.find("\ndef ", handoff_start + 1)
    handoff_function = runtime_text[handoff_start:handoff_end if handoff_end >= 0 else None]
    if "::add-mask::" in handoff_function:
        raise ContractError("task ARNs and run UUID must remain unmasked so GitHub can carry job outputs")


def validate_custodian_source(source: str) -> None:
    """Require exact runtime grant construction, caller identity, and cleanup."""
    schedule_gate = source.find('days, cancel_by = _schedule_approval(m)')
    schedule_call = source.find('_aws(\n            "kms", "schedule-key-deletion"')
    if schedule_gate < 0 or schedule_call < 0 or schedule_gate > schedule_call:
        raise ContractError("ScheduleKeyDeletion must follow the exact protected rollback-proof gate")
    markers = (
        'OPERATIONS = ("Encrypt", "Decrypt", "DescribeKey")',
        'identity.get("Account") != m["aws"]["account_id"]',
        'm["aws"]["custodian_role_arn"]',
        'key.get("Arn") != arn',
        'key.get("KeyUsage") != "ENCRYPT_DECRYPT"',
        'key.get("KeySpec") != "SYMMETRIC_DEFAULT"',
        'current = [g for g in all_grants if g.get("GranteePrincipal") == m["aws"]["runtime_role_arn"]]',
        '"--key-id", m["aws"]["cmk_arn"], "--grantee-principal", m["aws"]["runtime_role_arn"], "--operations", *OPERATIONS',
        'set(row.get("Operations", [])) == set(OPERATIONS)',
        'row.get("KeyId") == m["aws"]["cmk_arn"]',
        'row.get("GranteePrincipal") == m["aws"]["runtime_role_arn"]',
        '"--grant-id", grant_id',
        'if key.get("KeyState") == "PendingDeletion"',
        'def _cancel_and_enable(',
        'def _rollback_proof_approval(',
        'proof.get("cmk_arn") != m["aws"]["cmk_arn"]',
        'proof.get("approved_github_sha") != github_sha',
        'proof.get("run_namespace") != run_namespace',
        'expires_at < cancel_by',
        'after_cancel.get("KeyState") != "Disabled"',
        '_aws("kms", "enable-key"',
        'restored.get("KeyState") == "Enabled"',
        'pending.get("KeyState") != "PendingDeletion"',
        'stage == "cleanup"',
    )
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise ContractError("custodian helper must enforce exact custodian identity, CMK, runtime role, 3-operation grant, and safe cleanup")
    if re.search(r'"kms",\s*"(?:create-key|put-key-policy|delete-key|tag-resource|untag-resource)"', source):
        raise ContractError("custodian helper contains a forbidden key creation, policy edit, deletion, or tagging operation")
    kms_calls = set(re.findall(r'"kms",\s*"([a-z-]+)"', source))
    permitted = {
        "describe-key", "list-grants", "create-grant", "revoke-grant", "cancel-key-deletion",
        "get-key-rotation-status", "list-key-rotations", "rotate-key-on-demand", "enable-key", "schedule-key-deletion",
    }
    if not kms_calls or not kms_calls.issubset(permitted):
        raise ContractError("custodian helper must use only the enumerated exact CMK read and lifecycle calls")


def validate_cycles_source(source: str) -> None:
    if "for index in range(1, 11):" not in source:
        raise ContractError("cycle helper must execute exactly ten bounded lifecycle cycles")
    if "validate_cycle_manifest(manifest, env)" not in source or "existing GITHUB_OUTPUT is required before lifecycle mutation" not in source:
        raise ContractError("cycle helper must validate its protected manifest and output handoff before mutation")
    if "B083_ISSUE2165_GRANT_ID" not in source or '"grant_ids": all_grant_ids' not in source:
        raise ContractError("cycle helper must use the exact protected grant and emit cycle grant handoff evidence")


def _step_blocks(text: str) -> list[str]:
    starts = list(re.finditer(r"(?m)^ {6}- ", text))
    jobs = list(re.finditer(r"(?m)^  [\w-]+:\s*$", text))
    blocks: list[str] = []
    for index, match in enumerate(starts):
        next_step = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        next_job = next((job.start() for job in jobs if job.start() > match.start()), len(text))
        blocks.append(text[match.start(): min(next_step, next_job)])
    return blocks


def _phase_gates(step: str) -> set[str]:
    return set(re.findall(r"inputs\.phase\s*==\s*['\"]([^'\"]+)['\"]", step))


def _job_block(text: str, job_id: str) -> str | None:
    match = re.search(rf"(?ms)^  {re.escape(job_id)}:\s*\n(.*?)(?=^  [\w-]+:\s*\n|\Z)", text)
    return match.group(1) if match else None


def _require_readiness_before_oidc(block: str, *, cycle_job: bool = False) -> None:
    steps = _step_blocks(block)
    ready = next((i for i, step in enumerate(steps) if "Enforce lifecycle readiness after protected environment approval" in step), -1)
    oidc = next((i for i, step in enumerate(steps) if "aws-actions/configure-aws-credentials" in step), -1)
    if ready < 0 or oidc < 0 or ready >= oidc:
        raise ContractError("protected lifecycle readiness must be checked before assuming the provider role")
    required = ["B083_LIFECYCLE_READY", "B083_LIFECYCLE_APPROVED_SHA", "GITHUB_SHA", "B083_CONFIRMATION"]
    if cycle_job:
        required.extend(("test -f scripts/issue_2165_kms_cycles.py", "test -f scripts/issue_2165_kms_latency.py", "B083_ISSUE2165_GRANT_ID"))
    if not all(marker in steps[ready] for marker in required):
        raise ContractError("lifecycle readiness must verify approval, exact run confirmation, and required helpers before provider access")


def validate_role_separation(text: str) -> None:
    """Keep ECS control and CMK lifecycle permissions in separate OIDC jobs."""
    controller = _job_block(text, "runtime-controller")
    custodian = _job_block(text, "kms-custodian")
    observer = _job_block(text, "runtime-observe")
    cycles = _job_block(text, "kms-cycles")
    cleanup = _job_block(text, "runtime-cleanup")
    custodian_cleanup = _job_block(text, "kms-cleanup")
    cleanup_readback = _job_block(text, "cleanup-readback")
    if controller is None or custodian is None or observer is None or cycles is None or cleanup is None or custodian_cleanup is None or cleanup_readback is None:
        raise ContractError("workflow must split controller, custodian, observer, lifecycle cycles, task cleanup, custodian cleanup, and cleanup telemetry into separate OIDC jobs")
    for block, role in ((controller, "B083_AWS_CONTROLLER_ROLE_ARN"), (observer, "B083_AWS_CONTROLLER_ROLE_ARN"), (cycles, "B083_AWS_CUSTODIAN_ROLE_ARN"), (cleanup, "B083_AWS_CONTROLLER_ROLE_ARN"), (custodian_cleanup, "B083_AWS_CUSTODIAN_ROLE_ARN")):
        roles = re.findall(r"role-to-assume:\s*([^\n#]+)", block)
        if len(roles) != 1 or not re.fullmatch(rf"\s*\$\{{\{{\s*vars\.{role}\s*\}}\}}\s*", roles[0]):
            raise ContractError(f"{role} must be assumed only by its dedicated OIDC job")
    custodian_roles = re.findall(r"role-to-assume:\s*([^\n#]+)", custodian)
    expected_custodian_roles = ("B083_AWS_CUSTODIAN_ROLE_ARN", "B083_AWS_PREFLIGHT_ROLE_ARN")
    if len(custodian_roles) != 2 or any(
        not re.fullmatch(rf"\s*\$\{{\{{\s*vars\.{name}\s*\}}\}}\s*", value)
        for value, name in zip(custodian_roles, expected_custodian_roles)
    ):
        raise ContractError("kms-custodian must hand off from custodian mutation credentials to preflight read-only credentials")
    for left, right in (("B083_AWS_CONTROLLER_ROLE_ARN", "B083_AWS_CUSTODIAN_ROLE_ARN"), ("B083_AWS_CONTROLLER_ROLE_ARN", "B083_AWS_PREFLIGHT_ROLE_ARN"), ("B083_AWS_CUSTODIAN_ROLE_ARN", "B083_AWS_PREFLIGHT_ROLE_ARN")):
        if not re.search(rf"test\s+['\"]?\${left}['\"]?\s+!=\s+['\"]?\${right}['\"]?", text) and not re.search(
            rf"test\s+['\"]?\${right}['\"]?\s+!=\s+['\"]?\${left}['\"]?", text
        ):
            raise ContractError(f"protected roles {left} and {right} must be checked as distinct")
    if role_to_assume := re.findall(r"role-to-assume:\s*([^\n#]+)", controller):
        if any("CUSTODIAN" in value for value in role_to_assume):
            raise ContractError("controller job must not assume the custodian role")
    if role_to_assume := re.findall(r"role-to-assume:\s*([^\n#]+)", custodian):
        if any("CONTROLLER" in value for value in role_to_assume):
            raise ContractError("custodian job must not assume the controller role")
    for block, label in ((custodian, "kms-custodian"), (cycles, "kms-cycles")):
        if not re.search(r"(?m)^    if:[^\n]*github\.event_name\s*==\s*'workflow_dispatch'[^\n]*github\.ref\s*==\s*'refs/heads/main'[^\n]*inputs\.phase\s*==\s*'lifecycle'", block):
            raise ContractError(f"{label} must be manual main-branch lifecycle only")
        _require_readiness_before_oidc(block, cycle_job=(label == "kms-cycles"))
    if not re.search(r"(?m)^    needs:\s*runtime-controller\s*$", custodian):
        raise ContractError("custodian job must depend on the runtime-controller handoff")
    if not re.search(r"(?ms)^    needs:\s*\[[^\]]*runtime-controller[^\]]*kms-custodian[^\]]*\]", observer):
        raise ContractError("runtime-observe job must depend on both controller outputs and custodian lifecycle completion")
    if not re.search(r"(?ms)^    needs:\s*\[[^\]]*runtime-controller[^\]]*kms-custodian[^\]]*runtime-observe[^\]]*\]", cycles):
        raise ContractError("kms-cycles must follow controller, grant, and runtime observation")
    if not re.search(r"(?ms)^    needs:\s*\[[^\]]*runtime-controller[^\]]*kms-custodian[^\]]*runtime-observe[^\]]*\]", cleanup):
        raise ContractError("runtime-cleanup must follow controller, custodian, and observer even after failure")
    if not re.search(r"(?m)^    if:\s*always\(\)\s*&&[^\n]*inputs\.phase\s*==\s*'lifecycle'", cleanup):
        raise ContractError("runtime-cleanup must run after failures to stop exact handed-off tasks")
    if not re.search(r"(?ms)^    needs:\s*\[[^\]]*runtime-controller[^\]]*kms-custodian[^\]]*runtime-observe[^\]]*runtime-cleanup[^\]]*\]", custodian_cleanup):
        raise ContractError("kms-cleanup must follow lifecycle jobs even after failure")
    if not re.search(r"(?m)^    if:\s*always\(\)\s*&&[^\n]*inputs\.phase\s*==\s*'lifecycle'[^\n]*inputs\.phase\s*==\s*'cleanup'", custodian_cleanup):
        raise ContractError("kms-cleanup must run after failure only for lifecycle or cleanup phases")
    if (not re.search(r"(?m)^    needs:\s*\[kms-cleanup\]", cleanup_readback)
            or not re.search(r"(?m)^    if:\s*always\(\)[^\n]*needs\.kms-cleanup\.outputs\.cancel_expected\s*==\s*'true'", cleanup_readback)
            or not re.search(r"role-to-assume:\s*\$\{\{\s*vars\.B083_AWS_PREFLIGHT_ROLE_ARN\s*\}\}", cleanup_readback)
            or "aws cloudtrail lookup-events" not in cleanup_readback
            or "verify_issue_2165_kms_cleanup.py" not in cleanup_readback):
        raise ContractError("cleanup-readback must run after expected key recovery under preflight OIDC and validate bounded CloudTrail evidence")
    if "aws cloudtrail lookup-events" in custodian_cleanup:
        raise ContractError("CloudTrail cleanup readback must use the read-only preflight role, not custodian credentials")
    if not all(marker in custodian_cleanup for marker in ("cancel_expected=true", "custodian-cleanup-rollback-receipt.json", "rollback_receipt_json")):
        raise ContractError("kms-cleanup must preserve the same-run exact-key rollback receipt for read-only telemetry")
    if re.search(r"(?i)\baws\s+kms\s+(?:create-grant|revoke-grant|rotate-key|schedule-key-deletion|cancel-key-deletion)\b", controller + observer + cleanup):
        raise ContractError("controller job must not perform CMK lifecycle mutations")
    if re.search(r"(?i)\baws\s+ecs\s+run-task\b", custodian + custodian_cleanup):
        raise ContractError("custodian job must not run ECS tasks")
    if re.search(r"(?i)\baws\s+ecs\s+run-task\b", cycles):
        raise ContractError("kms-cycles must not run ECS tasks")
    output_names = {"app_task_arn", "operator_task_arn", "runtime_run_id", "failure_retry_pregrant_json"}
    output_section = re.search(r"(?ms)^    outputs:\s*\n(.*?)(?=^    \w[\w-]*:|^  [\w-]+:\s*$|\Z)", controller)
    parsed_output_names = re.findall(r"(?m)^      (\w+):", output_section.group(1)) if output_section else []
    if not output_section or len(parsed_output_names) != len(output_names) or set(parsed_output_names) != output_names:
        raise ContractError("controller job outputs must contain only app_task_arn, operator_task_arn, runtime_run_id, failure_retry_pregrant_json")
    pregrant_output = re.search(r"(?m)^      failure_retry_pregrant_json:\s*(.*?)\s*$", output_section.group(1))
    if not pregrant_output or pregrant_output.group(1) != "${{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}":
        raise ContractError("failure_retry_pregrant_json must come only from the exact pregrant-probe step output")
    controller_steps = _step_blocks(controller)
    pregrant_probe = next((step for step in controller_steps if re.search(r"(?m)^\s*id:\s*pregrant-probe\s*$", step)), "")
    if (not pregrant_probe or "inputs.phase == 'lifecycle'" not in pregrant_probe
            or "B083_CAPTURE_FAILURE_RETRY: '1'" not in pregrant_probe
            or not re.search(r"issue_2165_kms_runtime\.py.*--phase pregrant-deny.*--stage run", pregrant_probe)):
        raise ContractError("failure_retry_pregrant_json must be produced only by the gated pregrant runtime probe")
    readiness_step = next((i for i, step in enumerate(controller_steps) if "Enforce lifecycle readiness after protected environment approval" in step), -1)
    oidc_step = next((i for i, step in enumerate(controller_steps) if "aws-actions/configure-aws-credentials" in step), -1)
    target_step = next((i for i, step in enumerate(controller_steps) if "Validate bounded target and immutable images" in step), -1)
    if (readiness_step < 0 or target_step < 0 or oidc_step < 0 or not readiness_step < target_step < oidc_step
            or not all(marker in controller_steps[readiness_step] for marker in ("B083_LIFECYCLE_READY", "B083_LIFECYCLE_APPROVED_SHA", "GITHUB_SHA"))
            or not all(marker in controller_steps[target_step] for marker in ("REQUESTED_TARGET_ALIAS", "B083_TARGET_ALIAS", "B083_CONFIRMATION"))):
        raise ContractError("controller readiness and target confirmation must pass before provider role assumption")
    for env_name, output in (("B083_ISSUE2165_APP_TASK_ARN", "app_task_arn"), ("B083_ISSUE2165_OPERATOR_TASK_ARN", "operator_task_arn"), ("B083_ISSUE2165_RUN_ID", "runtime_run_id")):
        if not re.search(rf"(?m)^\s*{re.escape(env_name)}:\s*\$\{{\{{\s*needs\.runtime-controller\.outputs\.{output}\s*\}}\}}", text):
            raise ContractError(f"workflow handoff must bind {env_name} from the controller job output")
    custodian_gates = set().union(*(_phase_gates(block) for block in _step_blocks(custodian)))
    cleanup_gates = set().union(*(_phase_gates(block) for block in _step_blocks(custodian_cleanup)))
    if "lifecycle" not in custodian_gates or "lifecycle" not in cleanup_gates:
        raise ContractError("custodian grant and cleanup mutations must be gated to the approved lifecycle phase")
    if re.search(r"(?i)\baws\s+kms\s+(?:create-key|put-key-policy|tag-resource|untag-resource)\b", custodian):
        raise ContractError("custodian may not create keys, edit policies, or tag keys")
    if not re.search(r"issue_2165_kms_runtime\.py.*--phase lifecycle.*--stage start", controller):
        raise ContractError("runtime-controller must start the lifecycle app/operator tasks before handoff")
    if re.search(r"issue_2165_kms_runtime\.py.*--stage cleanup", controller):
        raise ContractError("controller task cleanup must wait until the runtime-cleanup job")
    if not re.search(r"issue_2165_kms_runtime\.py.*--phase lifecycle.*--stage observe", observer):
        raise ContractError("runtime-observe must observe the lifecycle tasks only after custodian work")
    if not re.search(r"issue_2165_kms_runtime\.py.*--phase lifecycle.*--stage cleanup", cleanup):
        raise ContractError("runtime-cleanup must stop the exact handed-off lifecycle tasks")
    for block, job_id in ((observer, "runtime-observe"), (cleanup, "runtime-cleanup")):
        for env_name, output in (("B083_ISSUE2165_APP_TASK_ARN", "app_task_arn"), ("B083_ISSUE2165_OPERATOR_TASK_ARN", "operator_task_arn"), ("B083_ISSUE2165_RUN_ID", "runtime_run_id")):
            if not re.search(rf"(?m)^\s*{re.escape(env_name)}:\s*\$\{{\{{\s*needs\.runtime-controller\.outputs\.{output}\s*\}}\}}", block):
                raise ContractError(f"{job_id} must consume {env_name} from the protected controller handoff")
    handoff_guard = all(marker in cleanup for marker in (
        "needs.runtime-controller.outputs.app_task_arn != ''",
        "needs.runtime-controller.outputs.operator_task_arn != ''",
        "needs.runtime-controller.outputs.runtime_run_id == github.run_id",
        "--phase lifecycle --stage cleanup",
    ))
    if not handoff_guard:
        raise ContractError("runtime cleanup must stop only the authenticated same-run lifecycle task handoff")
    if not re.search(r"(?is)Reject standalone cleanup without authenticated same-run handoff.{0,600}exit 2", cleanup):
        raise ContractError("standalone task cleanup must fail closed when same-run task outputs are absent")
    if not re.search(r"(?is)Reject standalone key cleanup without authenticated same-run state.{0,600}exit 2", custodian_cleanup):
        raise ContractError("standalone CMK cleanup must fail closed when same-run task outputs are absent")
    if not re.search(r"issue_2165_kms_custodian\.py.*--stage cleanup", custodian_cleanup):
        raise ContractError("kms-cleanup must invoke the bounded custodian cleanup stage")
    custodian_manifest = re.search(r"(?is)aws secretsmanager get-secret-value.{0,300}chmod\s+600", custodian)
    if not custodian_manifest or not re.search(r"issue_2165_kms_custodian\.py.*--stage grant", custodian):
        raise ContractError("kms-custodian must fetch the protected manifest mode 0600 and invoke the exact grant helper")
    if not all(marker in custodian for marker in ("B083_LIFECYCLE_READY", "B083_LIFECYCLE_APPROVED_SHA", "GITHUB_SHA", "B083_CONFIRMATION", "needs.runtime-controller.outputs.app_task_arn", "needs.runtime-controller.outputs.operator_task_arn")):
        raise ContractError("grant helper must be gated by exact lifecycle readiness, SHA, confirmation, and started task outputs")
    preflight_assume = custodian.find("role-to-assume:", custodian.find("role-to-assume:") + 1)
    grant_mutation = custodian.find("--stage grant")
    receipt_readback = custodian.find("Collect authenticated custodian lifecycle receipts")
    if (grant_mutation < 0 or preflight_assume < grant_mutation or receipt_readback < preflight_assume
            or "B083_AWS_PREFLIGHT_ROLE_ARN" not in custodian[preflight_assume:receipt_readback]
            or "custodian-readback-caller.json" not in custodian[receipt_readback:]
            or "CloudTrail LookupEvents must run under this run's exact preflight role session" not in custodian[receipt_readback:]
            or re.search(r"(?i)\baws\s+kms\s+", custodian[preflight_assume:])):
        raise ContractError("custodian job must finish KMS mutations before authenticated preflight-only CloudTrail readback")
    if "issue_2165_kms_custodian.py" in controller or re.search(r"\baws\s+kms\s+(?:create-grant|revoke-grant)\b", custodian):
        raise ContractError("custodian mutations must go through the bounded helper under the custodian OIDC role")
    if not re.search(r"issue_2165_kms_custodian\.py.*--stage cleanup", custodian_cleanup):
        raise ContractError("kms-cleanup must invoke the bounded custodian cleanup stage")
    cycles_commands = _shell_commands(cycles)
    if not all(marker in cycles for marker in ("test -f scripts/issue_2165_kms_cycles.py", "test -f scripts/issue_2165_kms_latency.py")):
        raise ContractError("kms-cycles must require both the cycle runner and latency collector files before provider access")
    if not any("issue_2165_kms_cycles.py" in c and "--manifest" in c for c in cycles_commands) or not any(
        "issue_2165_kms_latency.py" in c and "--manifest" in c and "--input" in c and "--output" in c for c in cycles_commands
    ):
        raise ContractError("kms-cycles must run exact-manifest ten-cycle and latency collection helpers")
    validate_custodian_source(Path(__file__).with_name("issue_2165_kms_custodian.py").read_text(encoding="utf-8"))
    validate_cycles_source(Path(__file__).with_name("issue_2165_kms_cycles.py").read_text(encoding="utf-8"))
    runtime_text = Path(__file__).with_name("issue_2165_kms_runtime.py").read_text(encoding="utf-8")
    if re.search(r"(?i)sts\s+assume-role|assume_role\s*\(", runtime_text):
        raise ContractError("runtime source must not internally assume a custodian role")


def _shell_commands(text: str) -> list[str]:
    commands: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if current:
            current += " " + stripped.removesuffix("\\").strip()
        else:
            current = stripped.removesuffix("\\").strip()
        if line.rstrip().endswith("\\"):
            continue
        if current:
            commands.append(current)
        current = ""
    if current:
        commands.append(current)
    return commands


def validate_contract(workflow_text: str, *, environment: str, target_alias: str, phase: str) -> None:
    if environment != PROTECTED_ENVIRONMENT:
        raise ContractError(f"environment must be exactly {PROTECTED_ENVIRONMENT}")
    if phase not in PHASES:
        raise ContractError(f"phase must be one of {', '.join(sorted(PHASES))}")
    if not isinstance(target_alias, str) or not target_alias.strip():
        raise ContractError("target_alias must be a non-empty protected alias value")
    text = workflow_text
    if not text.strip():
        raise ContractError("workflow input is empty")

    # Require an explicit, job-level protected GitHub environment and the
    # protected alias variable to be the source of the target selection.
    if not re.search(r"(?m)^\s*environment\s*:\s*[\"']?b083-kms-lifecycle[\"']?\s*(?:#.*)?$", text):
        raise ContractError("workflow must bind the protected b083-kms-lifecycle environment")
    if "B083_TARGET_ALIAS" not in text:
        raise ContractError("workflow must bind and check protected B083_TARGET_ALIAS")
    if target_alias.casefold() in {"", "none", "null"}:
        raise ContractError("target_alias must identify the requested protected target")
    if "prod6a" in target_alias.casefold():
        raise ContractError("production target aliases are forbidden")
    if not re.search(r"(?m)^\s*REQUESTED_TARGET_ALIAS\s*:\s*\$\{\{\s*inputs\.target_alias\s*\}\}\s*$", text):
        raise ContractError("workflow must bind the dispatch target_alias input")
    if not re.search(r"test\s+['\"]?\$REQUESTED_TARGET_ALIAS['\"]?\s*=\s*['\"]?\$B083_TARGET_ALIAS['\"]?", text):
        raise ContractError("dispatch target_alias must equal protected B083_TARGET_ALIAS")
    if not re.search(r"test\s+['\"]?\$B083_TARGET_ALIAS['\"]?\s+!=\s+['\"]?prod6a['\"]?", text, re.IGNORECASE):
        raise ContractError("workflow must reject the production target alias")
    # Do not accept a checked-in literal as an AWS account/resource selector.
    if re.search(r"(?im)^[ \t]*(?:aws_account_id|account_id|target_alias)[ \t]*:[ \t]*(?!\$\{\{)(?:\d{12}|[^$\s][^\n]*)$", text):
        raise ContractError("account and target selectors must come from protected inputs")

    # All contract values must be present, with the KMS key coming from a
    # secret binding. The other names are protected environment variables.
    bound_names = set(re.findall(r"(?m)^\s*(B083_[A-Z0-9_]+)\s*:", text))
    missing = [name for name in REQUIRED_BINDINGS if name not in bound_names]
    if missing:
        raise ContractError("missing protected bindings: " + ", ".join(missing))
    unbound = [
        name for name in REQUIRED_BINDINGS if name != "B083_KMS_KEY_ARN"
        and not re.search(rf"(?m)^\s*{re.escape(name)}\s*:\s*\$\{{\{{\s*vars\.{re.escape(name)}\s*\}}\}}\s*$", text)
    ]
    if unbound:
        raise ContractError("bindings must use their protected environment variables: " + ", ".join(unbound))
    if not SECRET_LIKE.search(text):
        raise ContractError("B083_KMS_KEY_ARN must be consumed from the protected secret")
    for image_name in ("B083_IMAGE_URI", "B083_AWS_OPERATOR_IMAGE_URI"):
        if image_name not in text or not re.search(
            rf"(?s){re.escape(image_name)}.{{0,1500}}@sha256:\[a-fA-F0-9\]\{{64\}}", text
        ):
            raise ContractError(f"workflow must validate {image_name} as an immutable sha256 digest")
    if "${{ vars.B083_TARGET_ALIAS }}" not in text and "vars.B083_TARGET_ALIAS" not in text:
        raise ContractError("target alias must be sourced from the protected B083_TARGET_ALIAS variable")

    static_job = re.search(r"(?ms)^  static-contract:\s*\n(.*?)(?=^  [\w-]+:\s*\n|\Z)", text)
    if not static_job or not re.search(r"(?m)^\s*if:\s*github\.event_name\s*==\s*['\"]pull_request['\"]\s*$", static_job.group(1)):
        raise ContractError("static contract job must be gated to pull requests")
    if re.search(r"(?i)\baws\s+|configure-aws-credentials", static_job.group(1)):
        raise ContractError("pull-request static job must not invoke AWS")
    job_blocks = re.split(r"(?m)(?=^  [\w-]+:\s*$)", text)
    provider_jobs = [
        block for block in job_blocks
        if re.search(r"(?m)^\s*environment:\s*[\"']?b083-kms-lifecycle[\"']?\s*$", block)
        and re.search(r"github\.event_name\s*==\s*['\"]workflow_dispatch['\"]", block)
        and re.search(r"github\.ref\s*==\s*['\"]refs/heads/main['\"]", block)
    ]
    if not provider_jobs:
        raise ContractError("protected provider phases must be manual-dispatch-only on main")
    validate_role_separation(text)
    provider_text = provider_jobs[0]
    provider_commands = provider_text.replace("\\\n", " ")
    if "aws secretsmanager get-secret-value" not in provider_commands or '--secret-id "$B083_TARGET_MANIFEST_SECRET_ARN"' not in provider_commands:
        raise ContractError("workflow must fetch the protected runtime manifest by its protected secret ARN")
    if "--query SecretString" not in provider_commands or "RUNNER_TEMP" not in provider_text or not re.search(
        r"(?i)chmod\s+600", provider_text
    ) or "--manifest" not in provider_commands:
        raise ContractError("protected runtime manifest must be stored mode 0600 under RUNNER_TEMP and passed to the runner")
    if re.search(r"(?i)\bset\s+-[^\n]*x|\btee\b", provider_text):
        raise ContractError("workflow must not trace or tee protected runtime manifest contents")

    permissions = re.search(r"(?ms)^permissions\s*:\s*\n((?:[ \t]+[^\n]*\n|\s*\n)+)", text)
    if not permissions:
        raise ContractError("workflow must declare narrow top-level OIDC permissions")
    permission_lines = [line.strip() for line in permissions.group(1).splitlines() if line.strip()]
    allowed = {"contents: read", "id-token: write"}
    if set(permission_lines) - allowed or "id-token: write" not in permission_lines or any(
        line.startswith("contents:") and line != "contents: read" for line in permission_lines
    ):
        raise ContractError("permissions may only be contents: read and id-token: write")
    if any(match.group(0).strip().lower() != "id-token: write" for match in WRITE_PERMISSION.finditer(text)):
        raise ContractError("workflow grants a write-capable permission")

    options = re.search(r"(?s)options\s*:\s*(\[[^\]]*\]|(?:\n[ \t]+-[^\n]*)+)", text)
    if not options or not all(phase_name in options.group(1) for phase_name in PHASES) or not all(
        re.search(rf"inputs\.phase\s*==\s*['\"]{re.escape(phase_name)}['\"]", text) for phase_name in PHASES
    ):
        raise ContractError("workflow must gate inventory, pregrant-deny, postgrant-readonly, lifecycle, and cleanup phases")

    # Prove that the runtime role has no identity-policy KMS access before or
    # after a grant. The synthetic key ARN is for IAM simulation only.
    normalized = text.replace("\\\n", " ")
    if "aws iam simulate-principal-policy" not in normalized or "--policy-source-arn \"$B083_AWS_RUNTIME_ROLE_ARN\"" not in normalized:
        raise ContractError("runtime role identity-policy simulations are required")
    sentinel = "arn:aws:kms:${B083_AWS_REGION}:${B083_AWS_ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000000"
    if "POLICY_ONLY_SENTINEL_ARN" not in text or sentinel not in normalized or not re.search(
        r"(?is)(?:synthetic|policy.only).{0,100}(?:never call KMS|no KMS call)|(?:never call KMS|no KMS call).{0,100}(?:synthetic|policy.only)",
        text,
    ):
        raise ContractError("synthetic sentinel must be labeled IAM policy-only and never sent to KMS")
    shell_commands = _shell_commands(text)
    if any("aws kms" in command and "POLICY_ONLY_SENTINEL_ARN" in command for command in shell_commands):
        raise ContractError("synthetic sentinel must never be used in a KMS API call")
    phase_text: dict[str, str] = {}
    for phase_name in ("pregrant-deny", "postgrant-readonly"):
        phase_text[phase_name] = "\n".join(
            block for block in _step_blocks(text)
            if phase_name in _phase_gates(block) and "aws iam simulate-principal-policy" in block
        )
        simulated = phase_text[phase_name]
        if not simulated:
            raise ContractError(f"runtime role policy simulation is missing from {phase_name}")
        if '--policy-source-arn "$B083_AWS_RUNTIME_ROLE_ARN"' not in simulated:
            raise ContractError(f"{phase_name} simulation must target the runtime role identity policy")
        if '--resource-arns "$B083_KMS_KEY_ARN" "$POLICY_ONLY_SENTINEL_ARN"' not in simulated:
            raise ContractError(f"{phase_name} simulation must cover primary and policy-only sentinel resources")
        for action in SIMULATION_ACTIONS | FORBIDDEN_SIMULATION_ACTIONS:
            if action not in simulated:
                raise ContractError(f"{phase_name} simulation is missing {action}")
        if "EvalDecision" not in simulated or "implicitDeny" not in simulated:
            raise ContractError(f"{phase_name} simulations must assert implicitDeny decisions")
    postgrant_steps = "\n".join(
        block for block in _step_blocks(text) if "postgrant-readonly" in _phase_gates(block)
    )
    if 'set(g[0]["Operations"]) == {"Encrypt", "Decrypt", "DescribeKey"}' not in postgrant_steps:
        raise ContractError("postgrant readback must assert exactly one runtime grant with Encrypt, Decrypt, DescribeKey")
    if not re.search(r"GranteePrincipal.{0,180}B083_AWS_RUNTIME_ROLE_ARN|B083_AWS_RUNTIME_ROLE_ARN.{0,180}GranteePrincipal", postgrant_steps, re.DOTALL):
        raise ContractError("postgrant readback must bind the exact runtime role principal")

    # Mutations and runtime calls belong only to their separately selected
    # phases. Read-only identity and postgrant policy checks stay fail-closed.
    run_task_gates: set[str] = set()
    stop_task_gates: set[str] = set()
    for block in _step_blocks(text):
        gates = _phase_gates(block)
        mutating = bool(MUTATING_AWS_ACTION.search(block))
        run_task = bool(RUNTIME_TASK_COMMAND.search(block))
        stop_task = bool(STOP_RUNTIME_COMMAND.search(block))
        kms_data_plane = bool(RUNTIME_KMS_COMMAND.search(block))
        runtime_operator = bool(RUNTIME_OPERATOR_COMMAND.search(block))
        if runtime_operator:
            if len(gates) != 1 or not gates.issubset({"pregrant-deny", "lifecycle", "cleanup"}):
                raise ContractError("runtime operator must be invoked in one explicit pregrant-deny, lifecycle, or cleanup phase")
            phase_arg = re.search(r"--phase\s+(?:['\"]?(pregrant-deny|lifecycle|cleanup)['\"]?|['\"]?\$PHASE['\"]?)", block)
            stage_cleanup = "--stage cleanup" in block and gates in ({"cleanup"}, {"lifecycle"}) and phase_arg and phase_arg.group(1) == "lifecycle"
            pregrant_capture = (
                gates == {"lifecycle"} and phase_arg and phase_arg.group(1) == "pregrant-deny"
                and re.search(r"(?m)^\s*id:\s*pregrant-probe\s*$", block)
                and "B083_CAPTURE_FAILURE_RETRY: '1'" in block and "--stage run" in block
            )
            if not phase_arg or (phase_arg.group(1) and phase_arg.group(1) not in gates and not stage_cleanup and not pregrant_capture):
                raise ContractError("runtime operator phase argument must match its workflow phase gate")
            if "pregrant-deny" in gates:
                run_task_gates.add("pregrant-deny")
            if "lifecycle" in gates:
                run_task_gates.add("lifecycle")
            if "cleanup" in gates or stage_cleanup:
                stop_task_gates.add("cleanup")
        if stop_task and gates != {"cleanup"}:
            raise ContractError("runtime stop is allowed only in the cleanup phase")
        if stop_task:
            stop_task_gates.update(gates)
        if run_task and not gates.issubset({"pregrant-deny", "lifecycle"}) or run_task and not gates:
            raise ContractError("ECS run-task must be gated only by pregrant-deny or lifecycle")
        if run_task:
            run_task_gates.update(gates)
        if kms_data_plane and (not gates or not gates.issubset({"pregrant-deny", "lifecycle"})):
            raise ContractError("KMS data-plane probes must be gated only by pregrant-deny or lifecycle")
        if mutating and not run_task and not stop_task and (not gates or not gates.issubset({"cleanup", "lifecycle"})):
            raise ContractError("workflow mutation must be gated only by lifecycle or cleanup")
    if not {"pregrant-deny", "lifecycle"}.issubset(run_task_gates):
        raise ContractError("runtime operator must be explicitly invoked in pregrant-deny and lifecycle phases")
    if "cleanup" not in stop_task_gates:
        raise ContractError("cleanup phase must invoke the runtime cleanup operator or stop the isolated runtime")
    simulation_steps = [block for block in _step_blocks(text) if "aws iam simulate-principal-policy" in block]
    if not any({"pregrant-deny", "postgrant-readonly"}.issubset(_phase_gates(block)) for block in simulation_steps):
        # A shared gate may be expressed as two distinct YAML steps. Require
        # both phases to have at least one simulation step in that case.
        gated = set().union(*(_phase_gates(block) for block in simulation_steps)) if simulation_steps else set()
        if not {"pregrant-deny", "postgrant-readonly"}.issubset(gated):
            raise ContractError("policy simulations must run in pregrant-deny and postgrant-readonly")
    if re.search(r"(?i)kms:\s*\*|\bkms:\*|\b\*\s*:\s*\*", text):
        raise ContractError("broad KMS or wildcard IAM action is forbidden")
    # Controller-role reads may inspect exact CMK metadata and grants in both
    # phases. No KMS data-plane call is part of this read-only candidate.


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--env", required=True)
    parser.add_argument("--target-alias", required=True)
    parser.add_argument("--phase", required=True, choices=sorted(PHASES))
    args = parser.parse_args(argv)
    try:
        if not args.workflow.is_file() or args.workflow.is_symlink():
            raise ContractError(f"workflow must be a regular file: {args.workflow}")
        validate_contract(
            args.workflow.read_text(encoding="utf-8"),
            environment=args.env,
            target_alias=args.target_alias,
            phase=args.phase,
        )
        runtime_source = Path(__file__).resolve().with_name("issue_2165_kms_runtime.py")
        if not runtime_source.is_file() or runtime_source.is_symlink():
            raise ContractError("runtime operator source must be a regular file")
        validate_runtime_source(runtime_source.read_text(encoding="utf-8"))
    except (ContractError, OSError, UnicodeDecodeError) as exc:
        print(f"Issue #2165 KMS contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print("Issue #2165 KMS contract: PASS (static workflow inspection only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
