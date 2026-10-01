"""Offline negative tests for the bounded Issue #2165 runtime operator."""

from __future__ import annotations

import copy
import ast
import hashlib
import inspect
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from issue_2165_kms_runtime import ContractError, MAX_CONCURRENT_TASKS, SCHEMA, _assert_task_capacity, _audit_source_receipts, _cleanup_handoff, _exec_operator, _expected_operator_secret_refs, _failure_retry_d1_public, _failure_retry_d1_snapshot, _runtime_lifecycle_rows, _start_task, _validate_operator_result, _validate_security_group_rules, _write_runtime_lifecycle_rows_output, cleanup, run_phase, validate_manifest  # noqa: E402
import issue_2165_r2_audit_archive as audit_archive  # noqa: E402


def fixture() -> tuple[dict, dict[str, str]]:
    app_image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/corelink@sha256:" + "a" * 64
    operator_image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/issue-2165-operator@sha256:" + "b" * 64
    app_task = "arn:aws:ecs:us-east-1:123456789012:task-definition/corelink:7"
    operator_task = "arn:aws:ecs:us-east-1:123456789012:task-definition/issue-2165-operator:2"
    app_role = "arn:aws:iam::123456789012:role/kms-runtime"
    operator_role = "arn:aws:iam::123456789012:role/kms-operator"
    value = {
        "schema": SCHEMA,
        "environment": "b083-kms-lifecycle",
        "aws": {
            "account_id": "123456789012", "region": "us-east-1",
            "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/kms-test",
            "task_definition_arn": app_task, "image_uri": app_image,
            "controller_role_arn": "arn:aws:iam::123456789012:role/kms-controller",
            "runtime_role_arn": app_role,
            "execution_role_arn": "arn:aws:iam::123456789012:role/kms-execution",
            "custodian_role_arn": "arn:aws:iam::123456789012:role/kms-custodian",
            "cmk_arn": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
        },
        "operator": {
            "task_definition_arn": operator_task, "image_uri": operator_image,
            "container_name": "issue-2165-operator",
            "operator_role_arn": operator_role,
            "operator_execution_role_arn": "arn:aws:iam::123456789012:role/kms-operator-execution",
            "entrypoint": "/usr/local/bin/issue-2165-operator",
            "internal_auth_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:corelink-internal-auth",
            "staging_admission_key_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:staging-admission",
            "tcs_wrapped_secret_arn_a": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tcs-wrapped-a",
            "tcs_wrapped_secret_arn_b": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tcs-wrapped-b",
            "pat_a_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-pat-a",
            "pat_b_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-pat-b",
            "storage_quota_bytes": 1024,
            "target_deployment_sha": "c" * 40,
        },
        "network": {
            "vpc_id": "vpc-0123456789abcdef0", "routed_subnet_ids": ["subnet-0123456789abcdef0"],
            "app_security_group_id": "sg-0123456789abcdef0", "operator_security_group_id": "sg-abcdef01234567890",
            "app_port": 50051, "public_ingress": False, "assign_public_ip": True,
            "provisioning_receipt": {
                "ref": "restricted://i2165/network-created", "sha256": "d" * 64,
                "created_at": "2026-09-30T11:00:00Z",
                "app_security_group_id": "sg-0123456789abcdef0", "operator_security_group_id": "sg-abcdef01234567890",
            },
        },
        "cloudflare": {
            "account_alias": "cf5128", "account_id": "0123456789abcdef0123456789abcdef",
            "d1": {"binding": "B083_D1", "database_id": "d1-isolated", "region": "weur"},
            "r2": {"binding": "B083_R2", "region": "auto", "endpoint": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com", "bucket": "kms-evidence"},
            "r2_prefixes": [
                {"tenant_id": "kms-tenant-a", "region": "weur", "prefix": "weur/test-a/"},
                {"tenant_id": "kms-tenant-b", "region": "weur", "prefix": "weur/test-b/"},
            ],
        },
        "disposable_tenants": ["kms-tenant-a", "kms-tenant-b"],
        "audit_sink": {
            "kind": "d1-audit-outbox+r2-archive", "target_id": "kms-evidence", "durable": True,
            "d1_table": "audit_outbox",
            "d1_columns": ["id", "tenant_id", "digest", "request_id", "event_type", "payload_json", "enqueued_at", "emitted_at"],
            "r2_bucket": "kms-evidence", "r2_archive_key": "issue-2165/test-run/audit/receipts.ndjson",
        },
        "audit_outbox_refs": [{"request_id": "test-req-1", "event_type": "byok.activation"}],
        "run_namespace": "i2165-b083-20260930-fab9cc09",
        "expires_at": "2026-09-30T23:59:00Z", "estimated_cost_usd": 20,
        "approval": {"approved": True, "target": "isolated kms-test", "rollback": "stop task, revoke grant, restore key"},
    }
    env = {
        "B083_AWS_ACCOUNT_ID": "123456789012", "B083_AWS_REGION": "us-east-1",
        "B083_AWS_CLUSTER_ARN": value["aws"]["cluster_arn"], "B083_AWS_TASK_DEFINITION_ARN": app_task,
        "B083_AWS_CONTROLLER_ROLE_ARN": value["aws"]["controller_role_arn"],
        "B083_AWS_RUNTIME_ROLE_ARN": app_role, "B083_IMAGE_URI": app_image,
        "B083_AWS_APP_EXECUTION_ROLE_ARN": value["aws"]["execution_role_arn"],
        "B083_AWS_CUSTODIAN_ROLE_ARN": value["aws"]["custodian_role_arn"],
        "B083_KMS_KEY_ARN": value["aws"]["cmk_arn"],
        "B083_AWS_OPERATOR_TASK_DEFINITION_ARN": operator_task, "B083_AWS_OPERATOR_ROLE_ARN": operator_role,
        "B083_AWS_OPERATOR_EXECUTION_ROLE_ARN": value["operator"]["operator_execution_role_arn"],
        "B083_AWS_OPERATOR_IMAGE_URI": operator_image,
        "B083_D1_REGION": value["cloudflare"]["d1"]["region"],
        "B083_CF_ACCOUNT_ID": value["cloudflare"]["account_id"],
        "B083_RUN_NAMESPACE": value["run_namespace"],
        "B083_NETWORK_RECEIPT_SHA256": value["network"]["provisioning_receipt"]["sha256"],
        "B083_TARGET_MANIFEST_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:issue-2165-manifest-AbCdEf",
    }
    return value, env


class RuntimeContractTests(unittest.TestCase):
    def test_manifest_accepts_two_distinct_private_tasks(self) -> None:
        value, env = fixture()
        checked = validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)
        self.assertEqual(checked["schema"], SCHEMA)

    def test_rejects_production_region_image_and_cost_mutants(self) -> None:
        for mutate, message in (
            (lambda m: m["cloudflare"].update(account_alias="prod6a"), "production"),
            (lambda m: m["aws"].update(region="eu-west-1"), "region"),
            (lambda m: m["operator"].update(image_uri="latest"), "sha256"),
            (lambda m: m.update(estimated_cost_usd=20.01), "at most 20"),
            (lambda m: m.update(expires_at="2026-10-02T00:00:00Z"), "within 24 hours"),
        ):
            value, env = fixture()
            mutate(value)
            with self.subTest(message=message), self.assertRaisesRegex(ContractError, message):
                validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_rejects_role_and_task_definition_reuse(self) -> None:
        for mutate in (
            lambda m: m["operator"].update(operator_role_arn=m["aws"]["runtime_role_arn"]),
            lambda m: m["operator"].update(task_definition_arn=m["aws"]["task_definition_arn"]),
        ):
            value, env = fixture()
            mutate(value)
            with self.assertRaises(ContractError):
                validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_rejects_pat_ref_reuse_or_unsafe_quota(self) -> None:
        for mutate in (
            lambda m: m["operator"].update(pat_b_secret_arn=m["operator"]["pat_a_secret_arn"]),
            lambda m: m["operator"].update(pat_a_secret_arn="arn:aws:secretsmanager:eu-west-1:123456789012:secret:pat"),
            lambda m: m["operator"].update(storage_quota_bytes=127),
        ):
            value, env = fixture()
            mutate(value)
            with self.assertRaises(ContractError):
                validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_operator_secret_refs_use_manifest_json_key_and_protected_pat_secrets(self) -> None:
        value, env = fixture()
        refs = _expected_operator_secret_refs(value, env)
        self.assertEqual(refs["ISSUE_2165_TENANTS_JSON"], env["B083_TARGET_MANIFEST_SECRET_ARN"] + ":disposable_tenants::")
        self.assertEqual(refs["ISSUE_2165_PAT_A"], value["operator"]["pat_a_secret_arn"])
        self.assertEqual(refs["ISSUE_2165_PAT_B"], value["operator"]["pat_b_secret_arn"])
        self.assertEqual(refs["ISSUE_2165_TCS_WRAPPED_B64_A"], value["operator"]["tcs_wrapped_secret_arn_a"])
        self.assertEqual(refs["ISSUE_2165_TCS_WRAPPED_B64_B"], value["operator"]["tcs_wrapped_secret_arn_b"])
        self.assertNotEqual(refs["ISSUE_2165_TCS_WRAPPED_B64_A"], refs["ISSUE_2165_TCS_WRAPPED_B64_B"])
        env["B083_TARGET_MANIFEST_SECRET_ARN"] = "arn:aws:secretsmanager:us-west-2:123456789012:secret:wrong"
        with self.assertRaisesRegex(ContractError, "same-account us-east-1"):
            _expected_operator_secret_refs(value, env)

    def test_rejects_shared_or_legacy_wrapped_tcs_secret_binding(self) -> None:
        value, env = fixture()
        value["operator"]["tcs_wrapped_secret_arn_b"] = value["operator"]["tcs_wrapped_secret_arn_a"]
        with self.assertRaisesRegex(ContractError, "wrapped TCS"):
            validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)
        value, env = fixture()
        value["operator"]["tcs_wrapped_secret_arn"] = value["operator"].pop("tcs_wrapped_secret_arn_a")
        with self.assertRaisesRegex(ContractError, "must be str"):
            validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_rejects_protected_environment_binding_mismatch(self) -> None:
        value, env = fixture()
        env["B083_AWS_RUNTIME_ROLE_ARN"] = "arn:aws:iam::123456789012:role/other"
        with self.assertRaisesRegex(ContractError, "protected environment binding"):
            validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_rejects_public_or_wildcard_storage_and_bad_tenant_prefixes(self) -> None:
        for prefix in ("/weur/x/", "weur/../x/", "weur/*/"):
            value, env = fixture()
            value["cloudflare"]["r2_prefixes"][0]["prefix"] = prefix
            with self.assertRaises(ContractError):
                validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_rejects_duplicate_d1_receipt_ids(self) -> None:
        value, env = fixture()
        value["audit_outbox_refs"].append({"request_id": "test-req-1", "event_type": "other"})
        with self.assertRaisesRegex(ContractError, "request IDs"):
            validate_manifest(value, datetime(2026, 9, 30, 12, tzinfo=timezone.utc), env)

    def test_accepts_only_real_pregrant_http_denial_observations(self) -> None:
        row = {"schema": "corelink.issue-2165-sidecar.v1", "phase": "pregrant-deny", "route": "/v1/admin/byok/activate", "status": 501, "observed_at_utc": "2026-09-30T12:00:00Z"}
        _validate_operator_result([row, row.copy()], "pregrant-deny")
        row["status"] = 200
        with self.assertRaisesRegex(ContractError, "expected HTTP 501"):
            _validate_operator_result([row, row.copy()], "pregrant-deny")

    def test_only_source_backed_runtime_labels_are_exported(self) -> None:
        rows = []
        for slot in ("tenant_a", "tenant_b"):
            rows.append({"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "activate", "status": 202, "request_started_at_utc": "2026-09-30T11:59:59Z", "observed_at_utc": "2026-09-30T12:00:00Z", "request_body_sha256": "a" * 64})
            digest = ("a" if slot == "tenant_a" else "b") * 64
            rows.append({"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "cas-put", "status": 201, "observed_at_utc": "2026-09-30T12:00:01Z", "digest": digest})
            rows.append({"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": slot, "step": "cas-get", "status": 200, "observed_at_utc": "2026-09-30T12:00:02Z", "digest": digest})
        rows.append({"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": "tenant_b_to_a", "step": "cross-tenant-deny", "status": 403, "observed_at_utc": "2026-09-30T12:00:03Z", "digest": "a" * 64})
        _validate_operator_result(rows, "lifecycle")
        execution = {
            "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/kms-test/operator-task",
            "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/kms-test",
            "task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/issue-2165-operator:2",
            "image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/issue-2165-operator@sha256:" + "b" * 64,
            "image_digest": "sha256:" + "b" * 64,
            "execute_response_sha256": "c" * 64,
            "response_rows_sha256": "d" * 64,
        }
        receipts = _audit_source_receipts(rows, execution)
        lifecycle_rows = _runtime_lifecycle_rows(rows)
        self.assertEqual([row["slot"] for row in lifecycle_rows], ["tenant_a", "tenant_b"])
        self.assertEqual(set(lifecycle_rows[0]), {"slot", "step", "status", "request_started_at_utc", "observed_at_utc"})
        self.assertTrue(all(not any(tenant in json.dumps(row) for tenant in ("kms-tenant-a", "kms-tenant-b")) for row in lifecycle_rows))
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "output"
            with patch.dict("os.environ", {"GITHUB_OUTPUT": str(output)}):
                _write_runtime_lifecycle_rows_output(lifecycle_rows)
            self.assertEqual(json.loads(output.read_text().split("=", 1)[1]), lifecycle_rows)
        malformed = copy.deepcopy(rows)
        malformed[0].pop("request_started_at_utc")
        with self.assertRaises(ContractError):
            _runtime_lifecycle_rows(malformed)
        self.assertEqual([row["step"] for row in receipts], ["tenant_isolation"])
        self.assertEqual(receipts[0]["source"]["kind"], "runtime")
        self.assertNotIn("provider_access", [row["step"] for row in receipts])
        self.assertNotIn("customer_create_or_import", [row["step"] for row in receipts])
        self.assertNotIn("failure_retry", [row["step"] for row in receipts])
        self.assertNotIn("residency", [row["step"] for row in receipts])
        self.assertNotIn("wrap_unwrap", [row["step"] for row in receipts])
        self.assertTrue(all(not any(tenant in json.dumps(row) for tenant in ("tenant_a", "tenant_b")) for row in receipts))
        self.assertRegex(receipts[0]["source"]["event_ref"], r"^ecs-task:[0-9a-f]{16}/exec:[0-9a-f]{16}/obs:[0-9a-f]{16}$")
        for field in ("task_arn", "cluster_arn", "task_definition_arn", "image_uri", "image_digest", "execute_response_sha256", "response_rows_sha256"):
            execution.pop(field)
            with self.subTest(missing=field), self.assertRaisesRegex(ContractError, "complete ECS task/image/exec-response provenance"):
                _audit_source_receipts(rows, execution)
            execution[field] = {
                "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/kms-test/operator-task",
                "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/kms-test",
                "task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/issue-2165-operator:2",
                "image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/issue-2165-operator@sha256:" + "b" * 64,
                "image_digest": "sha256:" + "b" * 64,
                "execute_response_sha256": "c" * 64,
                "response_rows_sha256": "d" * 64,
            }[field]

    def test_runtime_event_ref_is_accepted_by_archive_source_validator(self) -> None:
        rows = []
        for step in sorted(audit_archive.SOURCE_STEPS):
            if step == "tenant_isolation":
                ref = {
                    "step": "tenant_isolation", "occurred_at_utc": "2026-09-30T12:00:03Z",
                    "source": {"kind": "runtime", "event_ref": "ecs-task:0123456789abcdef/exec:0123456789abcdef/obs:0123456789abcdef", "digest": "a" * 64},
                }
            else:
                ref = {"step": step, "occurred_at_utc": "2026-09-30T12:00:00Z", "source": {"kind": "runtime", "event_ref": f"source:{step}", "digest": "b" * 64}}
            rows.append(ref)
        validated = audit_archive.validate_source_receipts(rows)
        runtime_ref = next(item for item in validated if item["step"] == "tenant_isolation")["source"]["event_ref"]
        self.assertIn("/exec:", runtime_ref)
        self.assertNotRegex(runtime_ref, r":sha256:[a-f0-9]{64}$")

    def test_ecs_exec_rejects_wrong_task_readback_before_execution(self) -> None:
        value, _ = fixture()
        calls = []
        wrong_task = {"tasks": [{
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/kms-test/other",
            "clusterArn": value["aws"]["cluster_arn"],
            "taskDefinitionArn": value["operator"]["task_definition_arn"],
            "lastStatus": "RUNNING",
            "containers": [{"name": value["operator"]["container_name"], "lastStatus": "RUNNING", "imageDigest": "sha256:" + "b" * 64}],
        }]}
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout=json.dumps(wrong_task))
        with self.assertRaisesRegex(ContractError, "exact RUNNING operator task"):
            _exec_operator(value, "arn:aws:ecs:us-east-1:123456789012:task/kms-test/expected", "lifecycle", runner)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("execute-command", calls[0])

    def test_ecs_exec_source_is_bound_to_task_image_and_raw_response(self) -> None:
        value, _ = fixture()
        task_arn = "arn:aws:ecs:us-east-1:123456789012:task/kms-test/operator-task"
        describe = {"tasks": [{
            "taskArn": task_arn,
            "clusterArn": value["aws"]["cluster_arn"],
            "taskDefinitionArn": value["operator"]["task_definition_arn"],
            "lastStatus": "RUNNING",
            "containers": [{"name": value["operator"]["container_name"], "lastStatus": "RUNNING", "imageDigest": "sha256:" + "b" * 64}],
        }]}
        row = {"schema": "corelink.issue-2165-sidecar.v1", "phase": "lifecycle", "slot": "tenant_b_to_a", "step": "cross-tenant-deny", "status": 403, "observed_at_utc": "2026-09-30T12:00:03Z", "digest": "a" * 64}
        response = json.dumps(row)
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout=json.dumps(describe) if command[1:3] == ["ecs", "describe-tasks"] else response)
        provenance, raw = {}, []
        rows = _exec_operator(value, task_arn, "lifecycle", runner, provenance_out=provenance, raw_response_out=raw)
        self.assertEqual(rows, [row])
        self.assertEqual(raw, [response])
        self.assertEqual(provenance["task_arn"], task_arn)
        self.assertEqual(provenance["image_digest"], "sha256:" + "b" * 64)
        self.assertEqual(provenance["execute_response_sha256"], hashlib.sha256(response.encode()).hexdigest())

        describe["tasks"][0]["containers"][0]["imageDigest"] = "sha256:" + "e" * 64
        calls.clear()
        with self.assertRaisesRegex(ContractError, "exact RUNNING immutable image digest"):
            _exec_operator(value, task_arn, "lifecycle", runner)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("execute-command", calls[0])

    def test_operator_run_task_overrides_exclude_raw_tenants_and_credentials(self) -> None:
        value, _ = fixture()
        commands = []
        def runner(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["ecs", "list-tasks"]:
                result = {"taskArns": []}
            elif command[1:3] == ["ecs", "run-task"]:
                result = {"tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123456789012:task/kms-test/abcdef", "clusterArn": value["aws"]["cluster_arn"], "taskDefinitionArn": value["operator"]["task_definition_arn"]}], "failures": []}
            else:
                result = {"tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123456789012:task/kms-test/abcdef", "taskDefinitionArn": value["operator"]["task_definition_arn"], "lastStatus": "RUNNING"}]}
            return SimpleNamespace(stdout=json.dumps(result))
        with patch.dict("os.environ", {"GITHUB_RUN_ID": "1234567"}):
            _start_task(value, value["operator"]["task_definition_arn"], "operator", "1234567", runner, app_origin="http://10.0.0.2:50051")
        run_task = next(command for command in commands if command[1:3] == ["ecs", "run-task"])
        overrides = json.loads(run_task[run_task.index("--overrides") + 1])
        encoded = json.dumps(overrides)
        for tenant in value["disposable_tenants"]:
            self.assertNotIn(tenant, encoded)
        self.assertNotIn(value["operator"]["pat_a_secret_arn"], encoded)
        self.assertNotIn(value["operator"]["pat_b_secret_arn"], encoded)
        self.assertEqual({item["name"] for item in overrides["containerOverrides"][0]["environment"]}, {"ISSUE_2165_APP_ORIGIN", "ISSUE_2165_RUN_ID"})

    def test_task_capacity_allows_only_the_exact_two_task_pair(self) -> None:
        cluster = "arn:aws:ecs:us-east-1:123456789012:cluster/kms-test"
        app = "arn:aws:ecs:us-east-1:123456789012:task/kms-test/app"
        foreign = "arn:aws:ecs:us-east-1:123456789012:task/kms-test/foreign"
        def checker(running: list[str], pending: list[str], stopped: list[str] | None = None, actual_statuses: dict[str, str] | None = None):
            stopped = stopped or []
            actual_statuses = actual_statuses or {}
            def runner(command, **kwargs):
                if "list-tasks" in command:
                    status = command[command.index("--desired-status") + 1]
                    rows = {"RUNNING": running, "PENDING": pending, "STOPPED": stopped}[status]
                    return SimpleNamespace(stdout=json.dumps({"taskArns": rows}))
                task_arns = command[command.index("--tasks") + 1:command.index("--region")]
                rows = []
                defaults = {**{arn: "RUNNING" for arn in running}, **{arn: "PENDING" for arn in pending}, **{arn: "STOPPED" for arn in stopped}}
                for arn in task_arns:
                    rows.append({"taskArn": arn, "clusterArn": cluster, "lastStatus": actual_statuses.get(arn, defaults[arn])})
                return SimpleNamespace(stdout=json.dumps({"tasks": rows, "failures": []}))
            return runner
        self.assertEqual(MAX_CONCURRENT_TASKS, 2)
        _assert_task_capacity(cluster, (), checker([], []))
        _assert_task_capacity(cluster, (app,), checker([app], []))
        with self.assertRaisesRegex(ContractError, "exact app task is no longer active"):
            _assert_task_capacity(cluster, (app,), checker([], []))
        with self.assertRaisesRegex(ContractError, "unexpected active task"):
            _assert_task_capacity(cluster, (), checker([], [], [foreign], {foreign: "STOPPING"}))
        with self.assertRaisesRegex(ContractError, "not RUNNING"):
            _assert_task_capacity(cluster, (app,), checker([], [], [app], {app: "STOPPING"}))
        with self.assertRaisesRegex(ContractError, "recent stopped-task inventory is capped"):
            _assert_task_capacity(cluster, (), checker([], [], [f"arn:stopped:{index}" for index in range(100)]))
        with self.assertRaisesRegex(ContractError, "unexpected active task"):
            _assert_task_capacity(cluster, (app,), checker([app, foreign], []))
        with self.assertRaisesRegex(ContractError, "two-task concurrency limit"):
            _assert_task_capacity(cluster, (app, foreign), checker([app], [foreign]))

    def test_controller_helpers_never_call_kms(self) -> None:
        for helper in (run_phase, cleanup, _cleanup_handoff):
            tree = ast.parse(inspect.getsource(helper))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id == "_aws":
                    service = node.args[0]
                    self.assertFalse(isinstance(service, ast.Constant) and service.value == "kms", helper.__name__)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                    if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                        argv = node.args[0].elts
                        words = [item.value for item in argv if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                        self.assertFalse(len(words) > 1 and words[:2] == ["aws", "kms"], helper.__name__)

    def test_security_groups_reject_default_egress_and_reverse_ingress(self) -> None:
        network = {"app_security_group_id": "sg-app", "operator_security_group_id": "sg-operator"}
        app = {
            "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 50051, "ToPort": 50051, "UserIdGroupPairs": [{"GroupId": "sg-operator"}]}],
            "IpPermissionsEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }
        operator = {
            "IpPermissions": [],
            "IpPermissionsEgress": [
                {"IpProtocol": "tcp", "FromPort": 50051, "ToPort": 50051, "UserIdGroupPairs": [{"GroupId": "sg-app"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
        }
        _validate_security_group_rules(app, operator, network)
        with self.assertRaisesRegex(ContractError, "operator security group must have no inbound rules"):
            _validate_security_group_rules(app, {**operator, "IpPermissions": [{"IpProtocol": "tcp"}]}, network)
        with self.assertRaisesRegex(ContractError, "app security group must allow only operator"):
            _validate_security_group_rules({**app, "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 50051, "ToPort": 50051, "UserIdGroupPairs": [{"GroupId": "sg-wrong"}]}]}, operator, network)
        default_egress = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        with self.assertRaisesRegex(ContractError, "operator security group egress"):
            _validate_security_group_rules(app, {**operator, "IpPermissionsEgress": [*operator["IpPermissionsEgress"], default_egress]}, network)
        with self.assertRaisesRegex(ContractError, "app security group egress"):
            _validate_security_group_rules({**app, "IpPermissionsEgress": [default_egress]}, operator, network)

    def test_failure_retry_snapshot_is_fixed_select_with_zero_write_metadata(self) -> None:
        value, _ = fixture()
        rows = [
            {"tenant_id": tenant, "mode": "cas", "cmk_provider": None, "cmk_key_id": None, "state": "inactive", "updated_at_ms": 1000}
            for tenant in value["disposable_tenants"]
        ]
        payload = {"success": True, "result": [{"success": True, "meta": {"changed_db": False, "rows_written": 0, "changes": 0}, "results": rows}]}
        with patch("issue_2165_kms_runtime.cf_readback._api_json", return_value=payload) as api:
            snapshot = _failure_retry_d1_snapshot(value, "protected-test-token")
        self.assertEqual(snapshot["rows"], rows)
        self.assertEqual(snapshot["read_only_metadata"], {"changed_db": False, "rows_written": 0, "changes": 0})
        self.assertEqual(api.call_args.args[:3], ("POST", f"/accounts/{value['cloudflare']['account_id']}/d1/database/{value['cloudflare']['d1']['database_id']}/query", "protected-test-token"))
        self.assertIn("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms", api.call_args.args[3]["sql"])

        payload["result"][0]["meta"]["changed_db"] = True
        with patch("issue_2165_kms_runtime.cf_readback._api_json", return_value=payload):
            with self.assertRaisesRegex(ContractError, "zero-write SELECT"):
                _failure_retry_d1_snapshot(value, "protected-test-token")

    def test_failure_retry_cross_job_snapshot_redacts_tenant_ids_and_keeps_slots(self) -> None:
        value, _ = fixture()
        snapshot = {
            "account_alias": "cf5128", "account_id": "51284495e71acdb5a7677e7383ab026b",
            "method": "parameterized-select-post", "observed_at_utc": "2026-09-30T12:00:00Z",
            "endpoint": "https://api.cloudflare.com/client/v4/accounts/example/d1/database/example/query",
            "database_id": "d1-test", "region": "iad", "query_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "rows": [
                {"tenant_id": tenant, "mode": "cas", "cmk_provider": None, "cmk_key_id": None, "state": "inactive", "updated_at_ms": 1000}
                for tenant in value["disposable_tenants"]
            ],
            "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0},
        }
        output = _failure_retry_d1_public(snapshot, value)
        encoded = json.dumps(output)
        for tenant in value["disposable_tenants"]:
            self.assertNotIn(tenant, encoded)
        self.assertEqual([row["slot"] for row in output["slot_states"]], ["tenant_a", "tenant_b"])
        self.assertEqual(output["row_count"], 2)
        self.assertEqual(output["response_sha256"], snapshot["response_sha256"])


if __name__ == "__main__":
    unittest.main()
