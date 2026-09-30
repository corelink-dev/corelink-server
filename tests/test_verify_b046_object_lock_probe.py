import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_b046_object_lock_probe", ROOT / "scripts/verify_b046_object_lock_probe.py"
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)

LIVE_RECEIPT_SPEC = importlib.util.spec_from_file_location(
    "build_b046_object_lock_receipt", ROOT / "scripts/build_b046_object_lock_receipt.py"
)
assert LIVE_RECEIPT_SPEC and LIVE_RECEIPT_SPEC.loader
live_receipt = importlib.util.module_from_spec(LIVE_RECEIPT_SPEC)
sys.modules[LIVE_RECEIPT_SPEC.name] = live_receipt
LIVE_RECEIPT_SPEC.loader.exec_module(live_receipt)

TRAIL_RECONCILE_SPEC = importlib.util.spec_from_file_location(
    "reconcile_b046_object_lock_trail", ROOT / "scripts/reconcile_b046_object_lock_trail.py"
)
assert TRAIL_RECONCILE_SPEC and TRAIL_RECONCILE_SPEC.loader
trail_reconcile = importlib.util.module_from_spec(TRAIL_RECONCILE_SPEC)
sys.modules[TRAIL_RECONCILE_SPEC.name] = trail_reconcile
TRAIL_RECONCILE_SPEC.loader.exec_module(trail_reconcile)


def live_receipt_inputs() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": "HuGR-dev/corelink-server",
        "GITHUB_REPOSITORY_ID": "1232040291",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "999999999",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": "b" * 40,
        "B046_SOURCE_RUN_ID": "123456789",
        "B046_SOURCE_ATTEMPT": "2",
        "B046_SOURCE_SHA": "a" * 40,
        "B046_CHECKED_OUT_SHA": "b" * 40,
        "AWS_ACCOUNT_ID": "123456789012",
        "B046_ACTUAL_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "us-east-1",
        "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/corelink-b046-probe",
        "AWS_WRITER_ROLE_ARN": "arn:aws:iam::123456789012:role/corelink-b046-writer",
        "AWS_TRAIL_ARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/corelink-b046-live-proof",
        "AWS_LOG_BUCKET": "corelink-b046-audit-example",
        "AWS_LOG_PREFIX": "AWSLogs/123456789012/CloudTrail/",
        "B046_ACTUAL_REGION": "us-east-1",
        "AWS_BUCKET_PREFIX": "corelink-object-lock-probe-b046",
        "B046_BUCKET": "corelink-object-lock-probe-b046-123456789-2",
        "B046_KEY": "audit/probe-123456789/synthetic.txt",
        "B046_VERSION": "opaque-version-id",
        "B046_RETAIN_UNTIL": "2026-09-26T06:02:42+00:00",
        "B046_PROBE_WINDOW_START": "2026-09-25T06:00:00Z",
        "COST_CEILING_USD_MICROS": "5000000",
        "COST_OWNER": "aws-cost-owner",
        "CLEANUP_OWNER": "aws-cleanup-owner",
    }


def live_reconciliation() -> dict[str, object]:
    uri_hash = hashlib.sha256(b"s3://redacted/CloudTrail/example").hexdigest()
    return {
        "put_event_id": "put-event-123",
        "put_request_id": "put-request-123",
        "put_event_time": "2026-09-25T06:03:00Z",
        "delete_event_id": "delete-event-456",
        "delete_request_id": "delete-request-789",
        "delete_event_time": "2026-09-25T06:04:00Z",
        "validated_log_sha256": ["a" * 64],
        "put_validated_log_uri_sha256": uri_hash,
        "delete_validated_log_uri_sha256": uri_hash,
        "events_share_validated_log": True,
        "validated_log_uri_sha256": [uri_hash],
    }


DIGEST_VALIDATION_OK = """\
Validating log files for trail between 2026-09-25T06:00:00Z and 2026-09-25T06:20:00Z
Digest file s3://redacted/CloudTrail-Digest/example valid
Log file s3://redacted/CloudTrail/example valid
1/1 digest files valid
1/1 log files valid
"""


class B046ObjectLockProbeTests(unittest.TestCase):
    def test_trail_reconcile_requires_complete_validation_and_exact_log_uris(self) -> None:
        output = DIGEST_VALIDATION_OK.replace("1/1 log files valid", "2/2 log files valid") + "Log file s3://redacted/CloudTrail/example-2 valid\n"
        self.assertEqual(
            trail_reconcile.validated_log_uris(output),
            ["s3://redacted/CloudTrail/example", "s3://redacted/CloudTrail/example-2"],
        )
        for invalid in (
            "1/1 digest files valid\n1/1 log files valid\n",
            DIGEST_VALIDATION_OK + "1/1 digest files valid\n",
            DIGEST_VALIDATION_OK + "Log file s3://redacted/CloudTrail/bad INVALID\n",
            DIGEST_VALIDATION_OK + "Log file s3://redacted/CloudTrail/unreported valid\n",
            "0/1 digest files valid\n1/1 log files valid\nLog file s3://redacted/a valid\n",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.validated_log_uris(invalid)

    def test_trail_reconcile_binds_both_events_to_exact_principal_and_version(self) -> None:
        import gzip
        import tempfile

        writer_principal = "arn:aws:iam::123456789012:role/corelink-b046-writer-test"
        writer_session = "arn:aws:sts::123456789012:assumed-role/corelink-b046-writer-test/corelink-b046-writer-123-2"
        probe_principal = "arn:aws:iam::123456789012:role/corelink-b046-probe-test"
        probe_session = "arn:aws:sts::123456789012:assumed-role/corelink-b046-probe-test/corelink-object-lock-123-2"
        writer_identity = {"arn": writer_session, "sessionContext": {"sessionIssuer": {"arn": writer_principal}}}
        probe_identity = {"arn": probe_session, "sessionContext": {"sessionIssuer": {"arn": probe_principal}}}
        put = {
            "eventCategory": "Data", "eventSource": "s3.amazonaws.com", "eventName": "PutObject",
            "eventID": "put-event", "requestID": "put-request", "userIdentity": writer_identity,
            "eventTime": "2026-10-01T00:00:00Z",
            "requestParameters": {"bucketName": "probe", "key": "audit/key"},
            "responseElements": {"x-amz-version-id": "version-1"},
        }
        delete = {
            "eventCategory": "Data", "eventSource": "s3.amazonaws.com", "eventName": "DeleteObject",
            "eventID": "delete-event", "requestID": "delete-request", "userIdentity": probe_identity,
            "eventTime": "2026-10-01T00:01:00Z",
            "requestParameters": {"bucketName": "probe", "key": "audit/key", "versionId": "version-1"},
            "errorCode": "AccessDenied",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "001.json.gz"
            path.write_bytes(gzip.compress(json.dumps({"Records": [put, delete]}).encode()))
            result = trail_reconcile.reconcile_events(
                [path], bucket="probe", key="audit/key", version="version-1",
                put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                retention_expiry="2026-10-02T00:00:00Z",
            )
            self.assertEqual(result["put_event_id"], "put-event")
            self.assertEqual(result["delete_event_id"], "delete-event")
            self.assertEqual(result["put_validated_log_uri_sha256"], result["delete_validated_log_uri_sha256"])
            changed_delete = dict(delete, errorCode="InvalidRequest")
            path.write_bytes(gzip.compress(json.dumps({"Records": [put, changed_delete]}).encode()))
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            for changed_put, changed_delete, changes in (
                (dict(put, userIdentity={"arn": "other", "sessionContext": {"sessionIssuer": {"arn": writer_principal}}}), delete, {}),
                (dict(put, errorCode="AccessDenied"), delete, {}),
                (put, dict(delete, userIdentity=writer_identity), {}),
                (put, delete, {"bucket": "other-bucket"}),
                (put, delete, {"key": "other/key"}),
                (put, delete, {"expected_put_request_id": "wrong-request"}),
                (put, delete, {"expected_delete_request_id": "wrong-request"}),
            ):
                path.write_bytes(gzip.compress(json.dumps({"Records": [changed_put, changed_delete]}).encode()))
                kwargs = {
                    "bucket": changes.get("bucket", "probe"),
                    "key": changes.get("key", "audit/key"),
                    "version": "version-1",
                    "put_principal_arn": writer_principal, "put_principal_session_arn": writer_session,
                    "delete_principal_arn": probe_principal, "delete_principal_session_arn": probe_session,
                    "log_uris": ["s3://audit-bucket/prefix/log.gz"],
                    "log_bucket": "audit-bucket", "log_prefix": "prefix/",
                    "expected_put_request_id": changes.get("expected_put_request_id", "put-request"),
                    "expected_delete_request_id": changes.get("expected_delete_request_id", "delete-request"),
                    "retention_expiry": "2026-10-02T00:00:00Z",
                }
                with self.subTest(changes=changes), self.assertRaises(trail_reconcile.ReconcileError):
                    trail_reconcile.reconcile_events([path], **kwargs)
            path.write_bytes(gzip.compress(json.dumps({"Records": [put, delete, delete]}).encode()))
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://other-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            duplicate_id = dict(delete, eventID="put-event")
            path.write_bytes(gzip.compress(json.dumps({"Records": [put, duplicate_id]}).encode()))
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            path.write_bytes(b"not gzip")
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            old_limit = trail_reconcile.MAX_LOG_BYTES
            trail_reconcile.MAX_LOG_BYTES = 8
            path.write_bytes(gzip.compress(b"123456789"))
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )
            trail_reconcile.MAX_LOG_BYTES = old_limit
            changed_delete = dict(delete, requestParameters={**delete["requestParameters"], "versionId": "other"})
            path.write_bytes(gzip.compress(json.dumps({"Records": [put, changed_delete]}).encode()))
            with self.assertRaises(trail_reconcile.ReconcileError):
                trail_reconcile.reconcile_events(
                    [path], bucket="probe", key="audit/key", version="version-1",
                    put_principal_arn=writer_principal, put_principal_session_arn=writer_session,
                    delete_principal_arn=probe_principal, delete_principal_session_arn=probe_session,
                    log_uris=["s3://audit-bucket/prefix/log.gz"], log_bucket="audit-bucket", log_prefix="prefix/",
                    expected_put_request_id="put-request", expected_delete_request_id="delete-request",
                    retention_expiry="2026-10-02T00:00:00Z",
                )

    def test_protected_receipt_binds_redacted_target_and_owner_controls(self) -> None:
        inputs = live_receipt_inputs()
        receipt = live_receipt.build_receipt(
            inputs, digest_validation_output=DIGEST_VALIDATION_OK,
            reconciliation=live_reconciliation(),
        )
        unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        self.assertEqual(receipt["schema"], "corelink.b046.s3-object-lock-protected-proof.v2")
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["receipt_sha256"], digest)
        self.assertEqual(
            receipt["workflow_url"],
            "https://github.com/HuGR-dev/corelink-server/actions/runs/123456789",
        )
        self.assertEqual(
            receipt["target"]["account_id_sha256"],
            hashlib.sha256(inputs["AWS_ACCOUNT_ID"].encode()).hexdigest(),
        )
        self.assertEqual(
            receipt["target"]["bucket_name_sha256"],
            hashlib.sha256(inputs["B046_BUCKET"].encode()).hexdigest(),
        )
        self.assertEqual(
            receipt["target"]["object_key_sha256"],
            hashlib.sha256(inputs["B046_KEY"].encode()).hexdigest(),
        )
        self.assertEqual(
            receipt["target"]["object_version_sha256"],
            hashlib.sha256(inputs["B046_VERSION"].encode()).hexdigest(),
        )
        self.assertEqual(
            receipt["target"]["workload_writer_role_arn_sha256"],
            hashlib.sha256(inputs["AWS_WRITER_ROLE_ARN"].encode()).hexdigest(),
        )
        self.assertEqual(receipt["target"]["region"], "us-east-1")
        self.assertTrue(receipt["target"]["region_matches_configured_target"])
        self.assertTrue(receipt["bucket"]["versioning_enabled"])
        self.assertEqual(receipt["object"]["retain_until"], "2026-09-26T06:02:42Z")
        self.assertEqual(receipt["object"]["put_data_event_id"], "put-event-123")
        self.assertEqual(receipt["object"]["delete_request_id"], "delete-request-789")
        self.assertEqual(receipt["object"]["delete_event_time"], "2026-09-25T06:04:00Z")
        self.assertEqual(receipt["object"]["delete_denial_data_event_id"], "delete-event-456")
        self.assertEqual(receipt["source_probe"]["commit"], "a" * 40)
        self.assertEqual(receipt["reconciliation"]["commit"], "b" * 40)
        self.assertEqual(receipt["cloudtrail_digest_validation"], "passed")
        self.assertEqual(
            receipt["cloudtrail_digest_output_sha256"],
            hashlib.sha256(DIGEST_VALIDATION_OK.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(receipt["cost_ceiling_usd_micros"], 5_000_000)
        self.assertEqual(receipt["cost_owner"], "aws-cost-owner")
        self.assertEqual(receipt["cleanup_owner"], "aws-cleanup-owner")
        encoded = json.dumps(receipt)
        for private_identifier in (
            inputs["AWS_ACCOUNT_ID"],
            inputs["B046_BUCKET"],
            inputs["B046_KEY"],
            inputs["B046_VERSION"],
        ):
            self.assertNotIn(private_identifier, encoded)

    def test_protected_receipt_rejects_target_drift_and_unapproved_cost(self) -> None:
        for field, value in (
            ("B046_ACTUAL_ACCOUNT_ID", "999999999999"),
            ("B046_ACTUAL_REGION", "eu-west-1"),
            ("B046_CHECKED_OUT_SHA", "b" * 40),
            ("COST_CEILING_USD_MICROS", "5000001"),
            ("B046_BUCKET", "unapproved-bucket"),
        ):
            with self.subTest(field=field):
                inputs = live_receipt_inputs()
                inputs[field] = value
                with self.assertRaises(live_receipt.ReceiptError):
                    live_receipt.build_receipt(
                    inputs, digest_validation_output=DIGEST_VALIDATION_OK,
                    reconciliation=live_reconciliation(),
                    )

    def test_final_receipt_rejects_event_not_bound_to_a_validated_log_uri(self) -> None:
        reconciliation = live_reconciliation()
        reconciliation["put_validated_log_uri_sha256"] = "f" * 64
        with self.assertRaises(live_receipt.ReceiptError):
            live_receipt.build_receipt(
                live_receipt_inputs(), digest_validation_output=DIGEST_VALIDATION_OK,
                reconciliation=reconciliation,
            )

    def test_protected_receipt_rejects_missing_or_invalid_digest_validation(self) -> None:
        for output in (
            "",
            "1/2 digest files valid\n1/1 log files valid\n",
            "1/1 digest files valid\n0/0 log files valid\n",
            "1/1 digest files valid\n1/1 log files valid\nDigest file INVALID: signature verification failed\n",
            "1/1 digest files valid\n1/1 log files valid\n1/2 backfill digest files INVALID\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(live_receipt.ReceiptError):
                    live_receipt.build_receipt(
                        live_receipt_inputs(), digest_validation_output=output,
                        reconciliation=live_reconciliation(),
                    )

    def test_protected_workflow_reads_back_versioning_and_uses_receipt_builder(self) -> None:
        workflow = (ROOT / ".github/workflows/aws-s3-object-lock-live-proof.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("aws s3api get-bucket-versioning --bucket \"$bucket\"", workflow)
        self.assertIn("jq -e '.Status == \"Enabled\"'", workflow)
        self.assertIn("scripts/build_b046_object_lock_receipt.py", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn('--start-time "$(jq -r \'.probe_window_start\' "$source")"', workflow)
        self.assertIn('--region "$AWS_REGION"', workflow)
        self.assertIn("scripts/reconcile_b046_object_lock_trail.py", workflow)
        self.assertIn("--put-principal-session-arn", workflow)
        self.assertIn("--delete-principal-session-arn", workflow)
        self.assertIn("OBJECT_LOCK_PROBE_WORKLOAD_WRITER_ROLE_ARN", workflow)
        self.assertIn('--digest-validation-output "$RUNNER_TEMP/digest-validation.txt"', workflow)
        self.assertIn("B046_ACTUAL_ACCOUNT_ID=\"$actual_account\"", workflow)
        self.assertIn("B046_ACTUAL_REGION=\"$actual_region\"", workflow)
        self.assertIn("B046_CHECKED_OUT_SHA=\"$(git rev-parse HEAD)\"", workflow)
        self.assertIn("OBJECT_LOCK_PROBE_AUDIT_RECONCILE_ROLE_ARN", workflow)
        self.assertIn("Equals:((.Equals // []) | sort)", workflow)
        self.assertNotIn("LatestDigestDeliveryTime", workflow)
        self.assertNotIn("preflight-digest-validation.txt", workflow)
        self.assertIn("Assume audit-reader for probe preflight", workflow)
        self.assertIn("Assume probe role for scoped policy simulation", workflow)
        self.assertIn("s3:PutObject s3:PutObjectRetention s3:PutObjectLegalHold", workflow)
        self.assertIn("s3:object-lock-mode,ContextKeyValues=COMPLIANCE", workflow)
        self.assertIn("s3:object-lock-legal-hold,ContextKeyValues=ON", workflow)
        self.assertIn("simulate_denied()", workflow)
        self.assertIn("s3:DeleteObjectVersion s3:BypassGovernanceRetention s3:PutObjectLegalHold", workflow)
        self.assertIn("s3:object-lock-legal-hold,ContextKeyValues=OFF", workflow)
        self.assertIn('EvalDecision == "implicitDeny" or .EvalDecision == "explicitDeny"', workflow)
        self.assertIn(".ResourceSpecificResults | length == 1", workflow)
        self.assertIn(".EvalResourceName == $resource", workflow)
        permission_preflight = workflow.split(
            "      - name: Simulate exact probe and workload-writer permissions before bucket creation", 1
        )[1]
        create_bucket = permission_preflight.index("      - name: Create exact run-bound synthetic bucket")
        denied_simulation = permission_preflight.index("simulate_denied \"$WORKLOAD_WRITER_ROLE_ARN\"")
        self.assertLess(denied_simulation, create_bucket)
        self.assertEqual(workflow.count("unset-current-credentials: true"), 7)
        self.assertIn("inline-session-policy: ${{ steps.cleanup_source.outputs.cleanup_policy }}", workflow)
        self.assertIn("ReleaseOnlyAuthorizedHoldToOff", workflow)
        self.assertIn("Verify exact workload-writer role and put session", workflow)
        self.assertIn("Verify exact probe role and delete session", workflow)
        self.assertIn("Verify exact read-only audit role and source-run session", workflow)
        self.assertIn('--s3-bucket "$AWS_LOG_BUCKET" --s3-prefix "$AWS_LOG_PREFIX"', workflow)
        self.assertNotIn("AWS_EVENT_DATA_STORE_ID", workflow)
        self.assertNotIn("start-query", workflow)
        self.assertIn("actions/runs/$SOURCE_RUN_ID/attempts/$SOURCE_ATTEMPT", workflow)
        self.assertIn("workflow_id == $workflow", workflow)
        self.assertIn('"operation":"probe"', workflow)
        self.assertIn("CLEANUP_ROLE_ARN", workflow)

    def test_writer_negative_policy_simulation_rejects_any_broader_allow(self) -> None:
        workflow = (ROOT / ".github/workflows/aws-s3-object-lock-live-proof.yml").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"local denied_results_filter='(.*?)\n            '\n", workflow, re.DOTALL
        )
        self.assertIsNotNone(match, "writer deny simulation filter is missing")
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "jq is required by the hosted workflow and this contract test")
        jq_filter = match.group(1)
        resource = "arn:aws:s3:::corelink-object-lock-probe-b046-999999999-1/audit/probe-999999999/synthetic.txt"
        actions = (
            "s3:DeleteObjectVersion",
            "s3:BypassGovernanceRetention",
            "s3:PutObjectLegalHold",
        )

        def invoke(results: list[dict[str, object]], *, truncated: bool = False) -> bool:
            document = {"EvaluationResults": results, "IsTruncated": truncated}
            completed = subprocess.run(
                [jq, "-e", "--arg", "resource", resource, jq_filter],
                input=json.dumps(document),
                text=True,
                capture_output=True,
                check=False,
            )
            return completed.returncode == 0

        def make_results(
            decisions: tuple[str, ...], *, wrong_resource: bool = False
        ) -> list[dict[str, object]]:
            results = [
                {
                    "EvalActionName": action,
                    "EvalDecision": decision,
                    "ResourceSpecificResults": [
                        {
                            "EvalResourceName": (
                                "arn:aws:s3:::wrong/object" if wrong_resource else resource
                            ),
                            "EvalResourceDecision": decision,
                        }
                    ],
                }
                for action, decision in zip(actions, decisions, strict=True)
            ]
            return results

        expected_denials = make_results(("implicitDeny", "implicitDeny", "implicitDeny"))
        self.assertTrue(invoke(expected_denials))
        self.assertTrue(invoke(make_results(("explicitDeny", "implicitDeny", "explicitDeny"))))
        self.assertFalse(invoke(make_results(("allowed", "implicitDeny", "implicitDeny"))))
        self.assertFalse(invoke(make_results(("allowed", "allowed", "allowed"))))
        self.assertFalse(invoke(make_results(("unknown", "implicitDeny", "implicitDeny"))))
        self.assertFalse(
            invoke(
                make_results(("implicitDeny", "implicitDeny", "implicitDeny"), wrong_resource=True)
            )
        )
        self.assertFalse(invoke(expected_denials[:-1]))
        duplicate_action = [
            *expected_denials[:-1],
            {**expected_denials[0], "EvalDecision": "implicitDeny"},
        ]
        self.assertFalse(invoke(duplicate_action))
        self.assertFalse(invoke(expected_denials, truncated=True))

    def test_cleanup_expires_retention_before_releasing_exact_version_legal_hold(self) -> None:
        workflow = (ROOT / ".github/workflows/aws-s3-object-lock-live-proof.yml").read_text(
            encoding="utf-8"
        )
        cleanup = workflow.split("      - name: Clean up the exact expired synthetic probe", 1)[1]
        cleanup = cleanup.split("      - name: Publish redacted proof and cleanup obligation", 1)[0]

        retention_read = 'aws s3api get-object-retention --bucket "$bucket" --key "$expected_key" --version-id "$version"'
        expiry_check = 'test "$(date -u -d "$expiry" +%s)" -le "$(date -u +%s)"'
        hold_release = 'aws s3api put-object-legal-hold --bucket "$bucket" --key "$expected_key" --version-id "$version"'
        delete_version = 'aws s3api delete-object --bucket "$bucket" --key "$expected_key" --version-id "$version"'

        self.assertIn('[[ "$bucket" =~ ^${AWS_BUCKET_PREFIX}-[0-9]+-[1-9][0-9]*$ ]]', cleanup)
        self.assertIn('expected_key="audit/probe-${SOURCE_RUN_ID}/synthetic.txt"', cleanup)
        self.assertIn('length == 1', cleanup)
        self.assertLess(cleanup.index(retention_read), cleanup.index(expiry_check))
        self.assertLess(cleanup.index(expiry_check), cleanup.index(hold_release))
        self.assertLess(cleanup.index(hold_release), cleanup.index(delete_version))
        self.assertIn("--legal-hold '{\"Status\":\"OFF\"}'", cleanup)
        self.assertIn("jq -e '.LegalHold.Status == \"OFF\"'", cleanup)
        self.assertIn("CLEANUP_MODE: ${{ steps.cleanup_source.outputs.cleanup_mode }}", workflow)
        self.assertIn("bucket_created=True", workflow)
        self.assertIn("empty_bucket_recovery", workflow)
        self.assertIn('aws s3api list-object-versions --no-paginate --bucket "$bucket"', cleanup)
        self.assertIn('aws s3api list-objects-v2 --no-paginate --bucket "$bucket"', cleanup)
        self.assertIn('(.IsTruncated != true) and ((.Versions // []) | length == 0)', cleanup)
        self.assertIn('(.IsTruncated != true) and ((.Contents // []) | length == 0)', cleanup)

    def test_only_explicit_not_implemented_is_provider_block(self) -> None:
        self.assertEqual(verifier.classify_operation(1, "", "NotImplemented"), "NOT_SUPPORTED")
        self.assertEqual(verifier.classify_operation(1, "", "Not Implemented"), "NOT_SUPPORTED")
        self.assertEqual(verifier.classify_operation(1, "", "AccessDenied"), "INDETERMINATE")
        self.assertEqual(verifier.classify_operation(1, "", "object lock unsupported"), "INDETERMINATE")
        self.assertEqual(verifier.classify_operation(1, "", "NotImplementedError"), "INDETERMINATE")
        self.assertEqual(verifier.classify_operation(1, "", "timeout"), "INDETERMINATE")
        self.assertEqual(verifier.classify_operation(0, "NotImplemented", ""), "PASS")

    def test_both_operations_are_required(self) -> None:
        passed = lambda name: verifier.OperationResult(name, "PASS", 0, "")
        blocked = lambda name: verifier.OperationResult(name, "NOT_SUPPORTED", 1, "NotImplemented")
        unknown = lambda name: verifier.OperationResult(name, "INDETERMINATE", 1, "AccessDenied")
        skipped = lambda name: verifier.OperationResult(name, "SKIPPED", 125, "not attempted")
        self.assertEqual(verifier.evaluate_operations(passed("create"), passed("put")), "SUPPORTED")
        self.assertEqual(verifier.evaluate_operations(blocked("create"), passed("put")), "BLOCKED")
        self.assertEqual(verifier.evaluate_operations(passed("create"), unknown("put")), "INDETERMINATE")
        self.assertEqual(verifier.evaluate_operations(blocked("create"), skipped("put")), "BLOCKED")
        self.assertEqual(verifier.evaluate_operations(unknown("create"), skipped("put")), "INDETERMINATE")

    def test_aws_credentials_are_child_env_only_and_redacted(self) -> None:
        access_key, secret_key, session_token = "ak", "sk", "tok"
        child_env = verifier._aws_child_env(access_key, secret_key, session_token)
        self.assertEqual(child_env["AWS_ACCESS_KEY_ID"], access_key)
        self.assertEqual(child_env["AWS_SECRET_ACCESS_KEY"], secret_key)
        self.assertEqual(child_env["AWS_SESSION_TOKEN"], session_token)
        self.assertNotIn("R2_S3_ACCESS_KEY_ID", child_env)
        self.assertNotIn("R2_S3_SECRET_ACCESS_KEY", child_env)
        self.assertNotIn("R2_S3_SESSION_TOKEN", child_env)
        fake_cli = (
            "import os, sys; "
            "print('env-ok' if all(os.getenv(name) for name in "
            "('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')) "
            "else 'env-missing'); "
            "print('argv-clean' if len(sys.argv) == 1 else 'argv-extra'); "
            "print('|'.join(os.getenv(name, '') for name in "
            "('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')))"
        )
        command = (sys.executable, "-c", fake_cli)
        result = verifier._run(command, (access_key, secret_key, session_token), child_env)
        self.assertEqual(result.status, "PASS")
        self.assertIn("env-ok", result.detail)
        self.assertIn("argv-clean", result.detail)
        self.assertIn("<redacted>", result.detail)
        for secret in (access_key, secret_key, session_token):
            self.assertNotIn(secret, result.detail)

        # Mutation: putting any credential in argv is rejected before the fake
        # CLI can run, pinning the env-only contract at the process boundary.
        with self.assertRaises(verifier.ProbeError):
            verifier._run((*command, access_key), (access_key, secret_key, session_token), child_env)

    def test_contract_and_mutations_fail_closed(self) -> None:
        verifier.validate_repository_contract()
        paths = {path: Path(path).read_text(encoding="utf-8") for path in verifier._required_markers()}

        mutated = dict(paths)
        backlog = verifier.BACKLOG_PATH.as_posix()
        b046_start = mutated[backlog].index("id: B-046")
        prefix, suffix = mutated[backlog][:b046_start], mutated[backlog][b046_start:]
        mutated[backlog] = prefix + suffix.replace("status: parked", "status: done", 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        mutated[backlog] = prefix + suffix.replace(
            "verify: " + verifier.B046_VERIFY_COMMAND, "verify: true", 1
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        mutated[backlog] += "\n```backlog\nid: B-046\nstatus: parked\nverify: manual\n```\n"
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        migration = verifier.MIGRATION_PATH.as_posix()
        mutated[migration] = mutated[migration].replace("CHECK (mode IN ('governance'))", "CHECK (mode IN ('governance', 'compliance'))")
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        adapter = verifier.ADAPTER_PATH.as_posix()
        mutated[adapter] = mutated[adapter].replace("NOT storage immutability", "storage immutability", 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        okf = verifier.OKF_PATH.as_posix()
        mutated[okf] = mutated[okf].replace("INDETERMINATE", "PASS")
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

        mutated = dict(paths)
        workflow = verifier.WORKFLOW_PATH.as_posix()
        mutated[workflow] = mutated[workflow].replace("scripts/verify_b046_object_lock_probe.py", "scripts/missing.py")
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_repository_contract(mutated)

    def test_receipt_schema_and_capability_polarity_fail_closed(self) -> None:
        evidence_path = verifier.EVIDENCE_PATH
        raw = evidence_path.read_text(encoding="utf-8")
        verifier.validate_evidence_record(raw)

        malformed = raw.replace('"classification": "INDETERMINATE"', '"classification": "SUPPORTED"', 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace('"status": "SKIPPED"', '"status": "MALFORMED"', 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace('"detail": "provider rejected', '"detail": "AWS_ACCESS_KEY_ID provider rejected', 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"classification": "INDETERMINATE",',
            '"classification": "INDETERMINATE",\n  "classification": "INDETERMINATE",',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"attempted": false,\n    "resources_created": false,',
            '"attempted": true,\n    "resources_created": true,',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"operation": "CreateBucket with Object Lock enabled"',
            '"operation": "ListBuckets"',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"status": "INDETERMINATE"',
            '"status": "PASS"',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"captured_at": "2026-09-09T04:13:53Z"',
            '"captured_at": "2026-09-09 04:13:53"',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace('"schema_version": 1', '"schema_version": true', 1)
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)

        malformed = raw.replace(
            '"captured_at": "2026-09-09T04:13:53Z"',
            '"captured_at": "2026-9-9T4:13:53Z"',
            1,
        )
        with self.assertRaises(verifier.ProbeError):
            verifier.validate_evidence_record(malformed)


if __name__ == "__main__":
    unittest.main()
