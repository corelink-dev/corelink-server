"""Adversarial tests for the credentialless Issue #2165 workflow checker."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_issue_2165_kms_contract import ContractError, validate_contract, validate_runtime_source, validate_custodian_source, validate_cycles_source  # noqa: E402


def _workflow() -> str:
    bindings = "\n".join(f"      {name}: ${{{{ vars.{name} }}}}" for name in (
        "B083_AWS_ACCOUNT_ID", "B083_AWS_REGION", "B083_AWS_PREFLIGHT_ROLE_ARN",
        "B083_AWS_CONTROLLER_ROLE_ARN", "B083_AWS_CUSTODIAN_ROLE_ARN",
        "B083_AWS_RUNTIME_ROLE_ARN", "B083_AWS_OPERATOR_TASK_DEFINITION_ARN", "B083_AWS_OPERATOR_ROLE_ARN",
        "B083_AWS_APP_EXECUTION_ROLE_ARN", "B083_AWS_OPERATOR_EXECUTION_ROLE_ARN", "B083_AWS_OPERATOR_IMAGE_URI",
        "B083_AWS_CLUSTER_ARN", "B083_AWS_TASK_DEFINITION_ARN",
        "B083_IMAGE_URI", "B083_D1_DATABASE_ID", "B083_D1_REGION", "B083_R2_S3_ENDPOINT",
        "B083_CF_ACCOUNT_ID", "B083_AUDIT_SINK_REF",
        "B083_CUSTODIAN_REF", "B083_RUNTIME_CONFIG_SECRET_ARN", "B083_TARGET_MANIFEST_SECRET_ARN",
    ))
    return f"""name: Issue 2165 KMS read-only contract
on:
  workflow_dispatch:
    inputs:
      target_alias:
        type: string
      phase:
        type: choice
        options: [inventory, pregrant-deny, postgrant-readonly, lifecycle, cleanup]
permissions:
  contents: read
  id-token: write
jobs:
  static-contract:
    if: github.event_name == 'pull_request'
    steps:
      - run: python3 scripts/verify_issue_2165_kms_contract.py
  runtime-controller:
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'
    environment: b083-kms-lifecycle
    env:
      REQUESTED_TARGET_ALIAS: ${{{{ inputs.target_alias }}}}
{bindings}
      B083_KMS_KEY_ARN: ${{{{ secrets.B083_KMS_KEY_ARN }}}}
      B083_TARGET_ALIAS: ${{{{ vars.B083_TARGET_ALIAS }}}}
    outputs:
      app_task_arn: ${{{{ steps.lifecycle-start.outputs.app_task_arn }}}}
      operator_task_arn: ${{{{ steps.lifecycle-start.outputs.operator_task_arn }}}}
      runtime_run_id: ${{{{ steps.lifecycle-start.outputs.runtime_run_id }}}}
      failure_retry_pregrant_json: ${{{{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}}}
    steps:
      - name: Enforce lifecycle readiness after protected environment approval
        run: |
          test "$B083_LIFECYCLE_READY" = yes
          test "$B083_LIFECYCLE_APPROVED_SHA" = "$GITHUB_SHA"
      - name: Validate bounded target and immutable images
        run: |
          test "$REQUESTED_TARGET_ALIAS" = "$B083_TARGET_ALIAS"
          test "$B083_CONFIRMATION" = "issue-2165-$B083_TARGET_ALIAS"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CONTROLLER_ROLE_ARN }}}}
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        run: |
          mkdir -p "$RUNNER_TEMP"
          aws secretsmanager get-secret-value --secret-id "$B083_TARGET_MANIFEST_SECRET_ARN" --query SecretString --output text > "$RUNNER_TEMP/manifest.json"
          chmod 600 "$RUNNER_TEMP/manifest.json"
      - run: 'test "$REQUESTED_TARGET_ALIAS" = "$B083_TARGET_ALIAS" && test "$B083_TARGET_ALIAS" != prod6a'
      - if: ${{{{ inputs.phase == 'inventory' }}}}
        run: aws sts get-caller-identity
      - if: ${{{{ inputs.phase == 'pregrant-deny' }}}}
        run: |
          aws iam simulate-principal-policy --policy-source-arn "$B083_AWS_RUNTIME_ROLE_ARN" --action-names kms:Encrypt kms:Decrypt kms:DescribeKey --resource-arns "$B083_KMS_KEY_ARN" "$POLICY_ONLY_SENTINEL_ARN"
          aws iam simulate-principal-policy --policy-source-arn "$B083_AWS_RUNTIME_ROLE_ARN" --action-names kms:GenerateDataKey kms:ReEncryptFrom kms:ReEncryptTo kms:CreateGrant kms:ScheduleKeyDeletion --resource-arns "$B083_KMS_KEY_ARN"
          python3 -c 'assert all(x["EvalDecision"] == "implicitDeny" for x in results)'
      - if: ${{{{ inputs.phase == 'postgrant-readonly' }}}}
        run: aws kms describe-key --key-id "$B083_KMS_KEY_ARN"
      - if: ${{{{ inputs.phase == 'postgrant-readonly' }}}}
        run: |
          aws iam simulate-principal-policy --policy-source-arn "$B083_AWS_RUNTIME_ROLE_ARN" --action-names kms:Encrypt kms:Decrypt kms:DescribeKey --resource-arns "$B083_KMS_KEY_ARN" "$POLICY_ONLY_SENTINEL_ARN"
          aws iam simulate-principal-policy --policy-source-arn "$B083_AWS_RUNTIME_ROLE_ARN" --action-names kms:GenerateDataKey kms:ReEncryptFrom kms:ReEncryptTo kms:CreateGrant kms:ScheduleKeyDeletion --resource-arns "$B083_KMS_KEY_ARN"
          python3 -c 'assert all(x["EvalDecision"] == "implicitDeny" for x in results)'
          python3 -c 'role=os.environ["B083_AWS_RUNTIME_ROLE_ARN"]; g=[x for x in grants if x["GranteePrincipal"] == role]; assert len(g) == 1 and set(g[0]["Operations"]) == {{"Encrypt", "Decrypt", "DescribeKey"}}'
      - if: ${{{{ inputs.phase == 'pregrant-deny' }}}}
        run: python3 scripts/issue_2165_kms_runtime.py --phase pregrant-deny --stage run
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        id: pregrant-probe
        env:
          B083_CAPTURE_FAILURE_RETRY: '1'
        run: python3 scripts/issue_2165_kms_runtime.py --phase pregrant-deny --stage run
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        run: test -n "$B083_TARGET_ALIAS"
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        id: lifecycle-start
        run: python3 scripts/issue_2165_kms_runtime.py --manifest "$RUNNER_TEMP/manifest.json" --phase lifecycle --stage start
      - run: '[[ "$B083_IMAGE_URI" =~ @sha256:[a-fA-F0-9]{{64}}$ ]]'
      - run: '[[ "$B083_AWS_OPERATOR_IMAGE_URI" =~ @sha256:[a-fA-F0-9]{{64}}$ ]]'
      # Synthetic policy-only target: never call KMS.
      - run: 'POLICY_ONLY_SENTINEL_ARN="arn:aws:kms:${{B083_AWS_REGION}}:${{B083_AWS_ACCOUNT_ID}}:key/00000000-0000-0000-0000-000000000000"'
      - run: 'test "$B083_AWS_CONTROLLER_ROLE_ARN" != "$B083_AWS_CUSTODIAN_ROLE_ARN" && test "$B083_AWS_CONTROLLER_ROLE_ARN" != "$B083_AWS_PREFLIGHT_ROLE_ARN" && test "$B083_AWS_CUSTODIAN_ROLE_ARN" != "$B083_AWS_PREFLIGHT_ROLE_ARN"'
  kms-custodian:
    needs: runtime-controller
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.phase == 'lifecycle'
    environment: b083-kms-lifecycle
    steps:
      - name: Enforce lifecycle readiness after protected environment approval
        run: |
          test "$B083_LIFECYCLE_READY" = yes
          test "$B083_LIFECYCLE_APPROVED_SHA" = "$GITHUB_SHA"
          test "$B083_CONFIRMATION" = "issue-2165-$B083_TARGET_ALIAS"
          test -n "${{{{ needs.runtime-controller.outputs.app_task_arn }}}}"
          test -n "${{{{ needs.runtime-controller.outputs.operator_task_arn }}}}"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CUSTODIAN_ROLE_ARN }}}}
      - name: Fetch protected target manifest
        run: |
          aws secretsmanager get-secret-value --secret-id "$B083_TARGET_MANIFEST_SECRET_ARN" --query SecretString --output text > "$RUNNER_TEMP/manifest.json"
          chmod 600 "$RUNNER_TEMP/manifest.json"
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        id: create-grant
        run: python3 scripts/issue_2165_kms_custodian.py --manifest "$RUNNER_TEMP/manifest.json" --stage grant --evidence-dir "$RUNNER_TEMP/evidence"
      - name: Capture exact custodian caller before the read-only role handoff
        run: aws sts get-caller-identity --output json > "$RUNNER_TEMP/custodian-caller.json"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_PREFLIGHT_ROLE_ARN }}}}
      - name: Collect authenticated custodian lifecycle receipts
        env:
          CALLER_PATH: ${{{{ runner.temp }}}}/custodian-caller.json
          PREFLIGHT_CALLER_PATH: ${{{{ runner.temp }}}}/custodian-readback-caller.json
        run: |
          aws sts get-caller-identity --output json > "$PREFLIGHT_CALLER_PATH"
          echo "CloudTrail LookupEvents must run under this run's exact preflight role session"
          aws cloudtrail lookup-events --max-results 50
          python3 scripts/issue_2165_kms_custodian_receipts.py --manifest "$RUNNER_TEMP/manifest.json" --receipt-dir "$RUNNER_TEMP/evidence" --cloudtrail "$RUNNER_TEMP/cloudtrail.json" --caller-identity "$CALLER_PATH" --output "$RUNNER_TEMP/receipts.json"
  runtime-observe:
    needs: [runtime-controller, kms-custodian]
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'
    environment: b083-kms-lifecycle
    env:
      B083_ISSUE2165_APP_TASK_ARN: ${{{{ needs.runtime-controller.outputs.app_task_arn }}}}
      B083_ISSUE2165_OPERATOR_TASK_ARN: ${{{{ needs.runtime-controller.outputs.operator_task_arn }}}}
      B083_ISSUE2165_RUN_ID: ${{{{ needs.runtime-controller.outputs.runtime_run_id }}}}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CONTROLLER_ROLE_ARN }}}}
      - if: ${{{{ inputs.phase == 'lifecycle' }}}}
        run: python3 scripts/issue_2165_kms_runtime.py --phase lifecycle --stage observe
  kms-cycles:
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.phase == 'lifecycle'
    needs: [runtime-controller, kms-custodian, runtime-observe]
    environment: b083-kms-lifecycle
    steps:
      - name: Enforce lifecycle readiness after protected environment approval
        run: |
          test "$B083_LIFECYCLE_READY" = yes
          test "$B083_LIFECYCLE_APPROVED_SHA" = "$GITHUB_SHA"
          test "$B083_CONFIRMATION" = "issue-2165-$B083_TARGET_ALIAS"
          test -n "$B083_ISSUE2165_GRANT_ID"
          test -f scripts/issue_2165_kms_cycles.py
          test -f scripts/issue_2165_kms_latency.py
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CUSTODIAN_ROLE_ARN }}}}
      - name: Run ten exact key cycles
        run: python3 scripts/issue_2165_kms_cycles.py --manifest "$RUNNER_TEMP/manifest.json" --evidence-dir "$RUNNER_TEMP/evidence"
      - name: Collect and verify latency
        run: python3 scripts/issue_2165_kms_latency.py --manifest "$RUNNER_TEMP/manifest.json" --input "$RUNNER_TEMP/evidence/cloudtrail-latency-input.json" --output "$RUNNER_TEMP/evidence/lifecycle-samples.json"
  runtime-cleanup:
    needs: [runtime-controller, kms-custodian, runtime-observe]
    if: always() && github.event_name == 'workflow_dispatch' && inputs.phase == 'lifecycle'
    environment: b083-kms-lifecycle
    env:
      B083_ISSUE2165_APP_TASK_ARN: ${{{{ needs.runtime-controller.outputs.app_task_arn }}}}
      B083_ISSUE2165_OPERATOR_TASK_ARN: ${{{{ needs.runtime-controller.outputs.operator_task_arn }}}}
      B083_ISSUE2165_RUN_ID: ${{{{ needs.runtime-controller.outputs.runtime_run_id }}}}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CONTROLLER_ROLE_ARN }}}}
      - if: always() && inputs.phase == 'lifecycle' && needs.runtime-controller.outputs.app_task_arn != '' && needs.runtime-controller.outputs.operator_task_arn != '' && needs.runtime-controller.outputs.runtime_run_id == github.run_id
        run: python3 scripts/issue_2165_kms_runtime.py --phase lifecycle --stage cleanup
      - name: Reject standalone cleanup without authenticated same-run handoff
        if: always() && inputs.phase == 'cleanup' && needs.runtime-controller.outputs.app_task_arn == ''
        run: echo 'No authenticated handoff'; exit 2
  kms-cleanup:
    needs: [runtime-controller, kms-custodian, runtime-observe, runtime-cleanup]
    if: always() && (inputs.phase == 'lifecycle' || inputs.phase == 'cleanup')
    environment: b083-kms-lifecycle
    outputs:
      cancel_expected: ${{{{ steps.cleanup.outputs.cancel_expected }}}}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_CUSTODIAN_ROLE_ARN }}}}
      - if: ${{{{ inputs.phase == 'cleanup' || inputs.phase == 'lifecycle' }}}}
        run: |
          echo 'cancel_expected=true' >> "$GITHUB_OUTPUT"
          python3 scripts/issue_2165_kms_custodian.py --manifest "$RUNNER_TEMP/manifest.json" --stage cleanup --evidence-dir "$RUNNER_TEMP/evidence"
          custodian-cleanup-rollback-receipt.json
          rollback_receipt_json
      - name: Reject standalone key cleanup without authenticated same-run state
        if: always() && inputs.phase == 'cleanup' && needs.runtime-controller.outputs.app_task_arn == ''
        run: echo 'No authenticated state'; exit 2
  cleanup-readback:
    needs: [kms-cleanup]
    if: always() && needs.kms-cleanup.outputs.cancel_expected == 'true'
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ vars.B083_AWS_PREFLIGHT_ROLE_ARN }}}}
      - run: aws cloudtrail lookup-events --max-results 50
      - run: python3 -B scripts/verify_issue_2165_kms_cleanup.py --manifest manifest --receipt receipt --cloudtrail events --caller-identity caller --output result
"""


def _accept(source: str | None = None, *, alias: str = "corelink-isolated") -> None:
    validate_contract(source if source is not None else _workflow(), environment="b083-kms-lifecycle", target_alias=alias, phase="postgrant-readonly")


def _runtime_source() -> str:
    return '''
if aws["task_definition_arn"] == operator["task_definition_arn"]: raise ContractError()
if aws["runtime_role_arn"] == operator["operator_role_arn"]: raise ContractError()
if len(set(op_roles + [aws["controller_role_arn"], aws["runtime_role_arn"], aws["execution_role_arn"], aws["custodian_role_arn"]])) != 6: raise ContractError()
desc.get("taskDefinitionArn") != aws["task_definition_arn"]
operator_desc.get("taskDefinitionArn") != operator["task_definition_arn"]
desc.get("taskRoleArn") != aws["runtime_role_arn"]
operator_desc.get("taskRoleArn") != operator["operator_role_arn"]
desc.get("executionRoleArn") != aws["execution_role_arn"]
operator_desc.get("executionRoleArn") != operator["operator_execution_role_arn"]
app.get("image") != aws["image_uri"]
sidecar.get("image") != operator["image_uri"]
_aws("ecs", "describe-task-definition", "--task-definition", aws["task_definition_arn"])
_aws("ecs", "describe-task-definition", "--task-definition", operator["task_definition_arn"])
"B083_AWS_CONTROLLER_ROLE_ARN": aws["controller_role_arn"]
"B083_AWS_CUSTODIAN_ROLE_ARN": aws["custodian_role_arn"]
"B083_AWS_APP_EXECUTION_ROLE_ARN": aws["execution_role_arn"]
"B083_AWS_OPERATOR_EXECUTION_ROLE_ARN": operator["operator_execution_role_arn"]
"B083_D1_REGION": d1["region"]
"B083_CF_ACCOUNT_ID": cf_account
"B083_ISSUE2165_APP_TASK_ARN"
"B083_ISSUE2165_OPERATOR_TASK_ARN"
"B083_ISSUE2165_RUN_ID"
def _write_handoff_outputs(app_task, operator_task, run_id):
    with open(output_path, "a") as stream:
        stream.write(f"app_task_arn={app_task}\\noperator_task_arn={operator_task}\\nruntime_run_id={run_id}\\n")
verify_live_target(m, runner)
app_task = _start_task(m, m["aws"]["task_definition_arn"], "app", run_id, runner)
'''


def _replace_nth(text: str, old: str, new: str, index: int) -> str:
    start = 0
    for _ in range(index):
        start = text.index(old, start) + len(old)
    return text[:start - len(old)] + new + text[start:]


class TestKmsContract(unittest.TestCase):
    def test_actual_lifecycle_runs_both_grant_boundary_checks_under_preflight(self) -> None:
        source = (ROOT / ".github" / "workflows" / "issue-2165-kms-real.yml").read_text(encoding="utf-8")
        pregrant = source.split("  pregrant-checks:\n", 1)[1].split("  runtime-controller:\n", 1)[0]
        self.assertIn("if: inputs.phase == 'pregrant-deny' || inputs.phase == 'lifecycle'", pregrant)
        self.assertIn("aws kms list-grants --key-id \"$B083_KMS_KEY_ARN\"", pregrant)
        self.assertIn("aws iam simulate-principal-policy --policy-source-arn \"$B083_AWS_RUNTIME_ROLE_ARN\"", pregrant)
        self.assertIn("aws iam simulate-principal-policy --policy-source-arn \"$B083_AWS_OPERATOR_ROLE_ARN\"", pregrant)
        postgrant = source.split("  postgrant-checks:\n", 1)[1].split("  runtime-observe:\n", 1)[0]
        self.assertIn("role-to-assume: ${{ vars.B083_AWS_PREFLIGHT_ROLE_ARN }}", postgrant)
        self.assertIn("aws kms describe-key --key-id \"$B083_KMS_KEY_ARN\"", postgrant)
        self.assertIn("aws kms list-grants --key-id \"$B083_KMS_KEY_ARN\"", postgrant)
        observe = source.split("  runtime-observe:\n", 1)[1].split("  kms-cycles:\n", 1)[0]
        self.assertIn("postgrant-checks", observe.split("    runs-on:", 1)[0])

    def test_valid_workflow_contract_passes(self) -> None:
        _accept()
        _accept(_workflow().replace("read-only-preflight:", "provider-phases:"))

    def test_runtime_source_binds_distinct_task_roles_and_readbacks(self) -> None:
        validate_runtime_source(_runtime_source())
        no_distinct_operator = _runtime_source().replace('aws["runtime_role_arn"] == operator["operator_role_arn"]', "")
        with self.assertRaisesRegex(ContractError, "separate app/operator task roles"):
            validate_runtime_source(no_distinct_operator)
        task_start_before_read = _runtime_source().replace("verify_live_target(m, runner)\n", "").replace(
            'app_task = _start_task(m, m["aws"]["task_definition_arn"], "app", run_id, runner)\n',
            'app_task = _start_task(m, m["aws"]["task_definition_arn"], "app", run_id, runner)\nverify_live_target(m, runner)\n',
        )
        with self.assertRaisesRegex(ContractError, "before starting either task"):
            validate_runtime_source(task_start_before_read)

    def test_actual_runtime_source_binds_protected_manifest_roles_and_cf_targets(self) -> None:
        runtime = (ROOT / "scripts" / "issue_2165_kms_runtime.py").read_text(encoding="utf-8")
        validate_runtime_source(runtime)
        without_cf_account = runtime.replace('"B083_CF_ACCOUNT_ID": cf_account,', "")
        with self.assertRaisesRegex(ContractError, "separate app/operator task roles"):
            validate_runtime_source(without_cf_account)
        with_mask = runtime.replace('stream.write(f"app_task_arn=', 'print("::add-mask::" + app_task)\n    stream.write(f"app_task_arn=')
        with self.assertRaisesRegex(ContractError, "remain unmasked"):
            validate_runtime_source(with_mask)

    def test_custodian_helper_exact_grant_and_ten_cycle_boundaries(self) -> None:
        custodian = (ROOT / "scripts" / "issue_2165_kms_custodian.py").read_text(encoding="utf-8")
        validate_custodian_source(custodian)
        unsafe_ops = custodian.replace('OPERATIONS = ("Encrypt", "Decrypt", "DescribeKey")', 'OPERATIONS = ("Encrypt", "Decrypt", "GenerateDataKey")')
        with self.assertRaisesRegex(ContractError, "exact custodian identity, CMK, runtime role"):
            validate_custodian_source(unsafe_ops)
        unsafe_cleanup = custodian.replace('after_cancel.get("KeyState") != "Disabled"', 'after_cancel.get("KeyState") != "Enabled"')
        with self.assertRaisesRegex(ContractError, "exact custodian identity, CMK, runtime role"):
            validate_custodian_source(unsafe_cleanup)
        unsafe_schedule = custodian.replace('days, cancel_by = _schedule_approval(m)', 'days, cancel_by = (7, datetime.now(timezone.utc))')
        with self.assertRaisesRegex(ContractError, "exact protected rollback-proof gate"):
            validate_custodian_source(unsafe_schedule)
        cycles = (ROOT / "scripts" / "issue_2165_kms_cycles.py").read_text(encoding="utf-8")
        validate_cycles_source(cycles)
        eleven_cycles = cycles.replace("range(1, 11)", "range(1, 12)")
        with self.assertRaisesRegex(ContractError, "exactly ten bounded"):
            validate_cycles_source(eleven_cycles)

    def test_workflow_tamper_is_rejected(self) -> None:
        cases = [
            (lambda text: text.replace("environment: b083-kms-lifecycle", "environment: production"), "protected b083-kms-lifecycle"),
            (lambda text: text.replace("vars.B083_TARGET_ALIAS", "vars.WRONG_ALIAS"), "protected B083_TARGET_ALIAS"),
            (lambda text: text.replace('test "$REQUESTED_TARGET_ALIAS" = "$B083_TARGET_ALIAS"', 'test "$REQUESTED_TARGET_ALIAS" = wrong'), "must equal protected"),
            (lambda text: text.replace("B083_AWS_REGION: ${{ vars.B083_AWS_REGION }}", "B083_AWS_REGION: us-east-1"), "protected environment variables"),
            (lambda text: text.replace("      B083_D1_REGION: ${{ vars.B083_D1_REGION }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_CF_ACCOUNT_ID: ${{ vars.B083_CF_ACCOUNT_ID }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_OPERATOR_TASK_DEFINITION_ARN: ${{ vars.B083_AWS_OPERATOR_TASK_DEFINITION_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_OPERATOR_ROLE_ARN: ${{ vars.B083_AWS_OPERATOR_ROLE_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_CONTROLLER_ROLE_ARN: ${{ vars.B083_AWS_CONTROLLER_ROLE_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_CUSTODIAN_ROLE_ARN: ${{ vars.B083_AWS_CUSTODIAN_ROLE_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_APP_EXECUTION_ROLE_ARN: ${{ vars.B083_AWS_APP_EXECUTION_ROLE_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_OPERATOR_EXECUTION_ROLE_ARN: ${{ vars.B083_AWS_OPERATOR_EXECUTION_ROLE_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_AWS_OPERATOR_IMAGE_URI: ${{ vars.B083_AWS_OPERATOR_IMAGE_URI }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("      B083_TARGET_MANIFEST_SECRET_ARN: ${{ vars.B083_TARGET_MANIFEST_SECRET_ARN }}\n", ""), "missing protected bindings"),
            (lambda text: text.replace("id-token: write", "id-token: none"), "permissions may only"),
            (lambda text: text.replace("contents: read", "contents: write"), "permissions may only"),
            (lambda text: text.replace("B083_KMS_KEY_ARN: ${{ secrets.B083_KMS_KEY_ARN }}", "B083_KMS_KEY_ARN: hard-coded"), "protected secret"),
            (lambda text: text.replace("@sha256:[a-fA-F0-9]{64}", "latest"), "immutable sha256 digest"),
            (lambda text: text.replace("options: [inventory, pregrant-deny, postgrant-readonly, lifecycle, cleanup]", "options: [inventory]"), "gate inventory, pregrant-deny, postgrant-readonly, lifecycle, and cleanup"),
            (lambda text: text.replace("aws sts get-caller-identity", "aws kms create-grant"), "controller job must not perform CMK lifecycle mutations"),
            (lambda text: text.replace("aws kms describe-key", "aws ecs run-task"), "ECS run-task must be gated only by pregrant-deny or lifecycle"),
            (lambda text: text.replace("aws kms describe-key", "aws kms decrypt"), "KMS data-plane probes must be gated"),
            (lambda text: text.replace("--action-names kms:GenerateDataKey", "--action-names kms:SomeOtherAction"), "kms:GenerateDataKey"),
            (lambda text: text.replace("implicitDeny", "allowed", 1), "implicitDeny"),
            (lambda text: text.replace("POLICY_ONLY_SENTINEL_ARN", "NOT_A_SENTINEL"), "sentinel"),
            (lambda text: text.replace('set(g[0]["Operations"]) == {"Encrypt", "Decrypt", "DescribeKey"}', 'set(g[0]["Operations"]) == {"Encrypt", "Decrypt"}'), "exactly one runtime grant"),
            (lambda text: text.replace("- if: ${{ inputs.phase == 'lifecycle' }}\n        id: lifecycle-start", "- if: ${{ inputs.phase == 'inventory' }}\n        id: lifecycle-start"), "runtime operator must be invoked"),
            (lambda text: text + "\n  Action: kms:*\n", "broad KMS"),
            (lambda text: text.replace("needs: [runtime-controller, kms-custodian]", "needs: [runtime-controller]", 1), "runtime-observe job must depend on both"),
            (lambda text: text.replace("    if: always() && github.event_name == 'workflow_dispatch' && inputs.phase == 'lifecycle'\n    environment: b083-kms-lifecycle\n    env:\n      B083_ISSUE2165_APP_TASK_ARN", "    if: github.event_name == 'workflow_dispatch'\n    environment: b083-kms-lifecycle\n    env:\n      B083_ISSUE2165_APP_TASK_ARN", 1), "runtime-cleanup must run after failures"),
            (lambda text: text.replace("role-to-assume: ${{ vars.B083_AWS_CUSTODIAN_ROLE_ARN }}", "role-to-assume: ${{ vars.B083_AWS_CONTROLLER_ROLE_ARN }}"), "B083_AWS_CUSTODIAN_ROLE_ARN must be assumed"),
            (lambda text: text.replace('test "$B083_AWS_CONTROLLER_ROLE_ARN" != "$B083_AWS_CUSTODIAN_ROLE_ARN"', 'test "$B083_AWS_CONTROLLER_ROLE_ARN" = "$B083_AWS_CUSTODIAN_ROLE_ARN"'), "protected roles B083_AWS_CONTROLLER_ROLE_ARN and B083_AWS_CUSTODIAN_ROLE_ARN"),
            (lambda text: text.replace("--stage grant", "--stage cleanup", 1), "invoke the exact grant helper"),
            (lambda text: text.replace("test -f scripts/issue_2165_kms_latency.py\n", ""), "protected lifecycle readiness must be checked before assuming"),
            (lambda text: text.replace("Reject standalone cleanup without authenticated same-run handoff", "Missing standalone cleanup guard"), "standalone task cleanup must fail closed"),
            (lambda text: text.replace("Reject standalone key cleanup without authenticated same-run state", "Missing standalone key cleanup guard"), "standalone CMK cleanup must fail closed"),
            (lambda text: text.replace("failure_retry_pregrant_json: ${{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}\n", ""), "controller job outputs must contain only"),
            (lambda text: text.replace("failure_retry_pregrant_json: ${{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}", "failure_retry_pregrant_json: ${{ steps.lifecycle-start.outputs.failure_retry_pregrant_json }}"), "failure_retry_pregrant_json must come only"),
            (lambda text: text.replace("runtime_run_id: ${{ steps.lifecycle-start.outputs.runtime_run_id }}\n", "runtime_run_id: ${{ steps.lifecycle-start.outputs.runtime_run_id }}\n      tenant_ids: ${{ steps.pregrant-probe.outputs.tenant_ids }}\n"), "controller job outputs must contain only"),
            (lambda text: text.replace("failure_retry_pregrant_json: ${{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}", "failure_retry_pregrant_json: ${{ secrets.B083_CF_API_TOKEN }}"), "failure_retry_pregrant_json must come only"),
            (lambda text: text.replace("failure_retry_pregrant_json: ${{ steps.pregrant-probe.outputs.failure_retry_pregrant_json }}", "failure_retry_pregrant_json: ${{ steps.pregrant-probe.outputs.raw_d1_rows }}"), "failure_retry_pregrant_json must come only"),
            (lambda text: text.replace("test \"$B083_LIFECYCLE_READY\" = yes\n", ""), "lifecycle readiness must verify approval|controller readiness and target confirmation must pass before provider"),
            (lambda text: text.replace("id: pregrant-probe\n", "id: other-step\n"), "failure_retry_pregrant_json must be produced only"),
        ]
        for change, message in cases:
            with self.subTest(expected=message), self.assertRaisesRegex(ContractError, message):
                _accept(change(_workflow()))

    def test_wrong_cli_environment_phase_and_production_alias_are_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "environment must be exactly"):
            validate_contract(_workflow(), environment="default", target_alias="corelink-isolated", phase="postgrant-readonly")
        with self.assertRaisesRegex(ContractError, "phase must be one of"):
            validate_contract(_workflow(), environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="all")
        with self.assertRaisesRegex(ContractError, "production target aliases"):
            _accept(alias="prod6a")
        hardcoded_target = _workflow().replace("      target_alias:\n        type: string", "      target_alias: prod6a\n        type: string")
        with self.assertRaisesRegex(ContractError, "account and target selectors"):
            _accept(hardcoded_target)

    def test_pregrant_and_postgrant_policy_controls_are_required(self) -> None:
        validate_contract(_workflow(), environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="pregrant-deny")
        missing_sentinel_deny = _workflow().replace("--resource-arns \"$B083_KMS_KEY_ARN\" \"$POLICY_ONLY_SENTINEL_ARN\"", "--resource-arns \"$B083_KMS_KEY_ARN\"", 1)
        with self.assertRaisesRegex(ContractError, "primary and policy-only sentinel"):
            validate_contract(missing_sentinel_deny, environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="pregrant-deny")
        postgrant_missing_forbidden = _replace_nth(_workflow(), "kms:GenerateDataKey", "kms:OtherAction", 2)
        with self.assertRaisesRegex(ContractError, "postgrant-readonly simulation is missing kms:GenerateDataKey"):
            validate_contract(postgrant_missing_forbidden, environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="postgrant-readonly")

    def test_mutation_is_allowed_only_under_runtime_or_cleanup_phase(self) -> None:
        validate_contract(_workflow(), environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="lifecycle")
        unguarded = _workflow().replace("- if: ${{ inputs.phase == 'lifecycle' }}\n        id: lifecycle-start", "- if: ${{ inputs.phase == 'postgrant-readonly' }}\n        id: lifecycle-start")
        with self.assertRaisesRegex(ContractError, "runtime operator must be invoked"):
            validate_contract(unguarded, environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="lifecycle")
        no_pregrant_runner = _workflow().replace(
            "      - if: ${{ inputs.phase == 'pregrant-deny' }}\n        run: python3 scripts/issue_2165_kms_runtime.py --phase pregrant-deny --stage run\n", ""
        )
        with self.assertRaisesRegex(ContractError, "runtime operator must be explicitly invoked"):
            validate_contract(no_pregrant_runner, environment="b083-kms-lifecycle", target_alias="corelink-isolated", phase="pregrant-deny")


if __name__ == "__main__":
    unittest.main()
