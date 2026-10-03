"""Credentialless behavior and artifact contract for the B-103 staging lane."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from scripts import redact_b103_worker_tail as tail
from scripts import reproduce_b103_cargo_write as cargo
from scripts import validate_load_target_receipt as receipt


TENANT = "123e4567-e89b-42d3-a456-426614174000"
STALE_TENANT = "123e4567-e89b-42d3-a456-426614174001"
DEPLOYMENT_SHA = "a" * 40
TOKEN = "corelink_pat_fixture_DO_NOT_LEAK"
CF_TOKEN = "cfat_fixture_DO_NOT_LEAK"
ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
OPERATION_ID = "b103-12345678123456781234567812345678"


def sha256_tenant(tenant: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(tenant.encode("ascii")).hexdigest()


def valid_receipt() -> dict[str, object]:
    current = dt.datetime.now(dt.UTC).replace(microsecond=0)
    return {
        "schema": 1,
        "environment": "staging",
        "target": receipt.CANONICAL_TARGET,
        "tenant_id": TENANT,
        "deployment_sha": DEPLOYMENT_SHA,
        "issued_at": (current - dt.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (current + dt.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


class B103TenantBindingTests(unittest.TestCase):
    def run_receipt(self, configured_tenant: str, directory: Path) -> tuple[int, str]:
        receipt_file = directory / "receipt.json"
        output_file = directory / "github-output"
        raw = json.dumps(valid_receipt())
        args = [
            "validate_load_target_receipt.py",
            "--target",
            receipt.CANONICAL_TARGET,
            "--receipt-env",
            "TEST_RECEIPT",
            "--tenant-env",
            "B103_TENANT_ID",
            "--redact-tenant",
            "--output",
            str(receipt_file),
            "--github-output",
            str(output_file),
        ]
        stdout = io.StringIO()
        with mock.patch.object(os, "environ", {"TEST_RECEIPT": raw, "B103_TENANT_ID": configured_tenant}), \
             mock.patch("sys.argv", args), contextlib.redirect_stdout(stdout):
            result = receipt.main()
        return result, stdout.getvalue()

    def test_mismatch_fails_before_receipt_or_output_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            result, output = self.run_receipt(STALE_TENANT, directory)
            self.assertEqual(result, 1)
            self.assertFalse((directory / "receipt.json").exists())
            self.assertFalse((directory / "github-output").exists())
            self.assertNotIn(TENANT, output)
            self.assertNotIn(STALE_TENANT, output)

    def test_authorized_path_emits_only_hash_and_deployment_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            result, output = self.run_receipt(TENANT, directory)
            self.assertEqual(result, 0)
            artifact = (directory / "receipt.json").read_text(encoding="utf-8")
            self.assertNotIn(TENANT, artifact)
            self.assertIn(sha256_tenant(TENANT), artifact)
            self.assertIn(DEPLOYMENT_SHA, artifact)
            self.assertNotIn(TENANT, output)

    def test_reproducer_rejects_wrong_receipt_hash_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "wire.json"
            argv = ["reproduce_b103_cargo_write.py", "--output", str(output)]
            env = {
                "B103_TARGET_HOST": cargo.TARGET,
                "B103_TENANT_ID": TENANT,
                "B103_TENANT_SHA256": sha256_tenant(STALE_TENANT),
                "B103_DEPLOYMENT_SHA": DEPLOYMENT_SHA,
                "B103_PAT": TOKEN,
            }
            with mock.patch.object(os, "environ", env), mock.patch("sys.argv", argv), \
                 mock.patch.object(cargo, "urlopen") as urlopen:
                with self.assertRaisesRegex(SystemExit, "does not match"):
                    cargo.main()
            urlopen.assert_not_called()
            self.assertFalse(output.exists())

    def test_authorized_reproducer_keeps_bounded_arms_and_hash_only_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "wire.json"
            argv = ["reproduce_b103_cargo_write.py", "--output", str(output)]
            env = {
                "B103_TARGET_HOST": cargo.TARGET,
                "B103_TENANT_ID": TENANT,
                "B103_TENANT_SHA256": sha256_tenant(TENANT),
                "B103_DEPLOYMENT_SHA": DEPLOYMENT_SHA,
                "B103_PAT": TOKEN,
            }
            observed: list[str] = []
            operation_ids = [f"b103-{index:032x}" for index in range(1, 12)]
            next_operation = iter(operation_ids)

            def warm(base: str, tenant: str, token: str) -> dict[str, object]:
                observed.append(tenant)
                return {
                    "failed_requests": 0,
                    "responses": [{"operation_id": next(next_operation)} for _ in range(3)],
                }

            def arm(base: str, tenant: str, token: str, mode: str, concurrency: int) -> dict[str, object]:
                observed.append(tenant)
                return {
                    "failed_requests": 0,
                    "mode": mode,
                    "concurrency": concurrency,
                    "responses": [{"operation_id": next(next_operation)}],
                }

            with mock.patch.object(os, "environ", env), mock.patch("sys.argv", argv), \
                 mock.patch.object(cargo, "run_warm_sequence", side_effect=warm), \
                 mock.patch.object(cargo, "run_arm", side_effect=arm):
                self.assertEqual(cargo.main(), 0)
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(set(observed), {TENANT})
            self.assertNotIn("tenant_id", artifact)
            self.assertEqual(artifact["tenant_sha256"], sha256_tenant(TENANT))
            self.assertEqual(artifact["deployment_sha"], DEPLOYMENT_SHA)
            self.assertEqual(cargo.PUT_ONLY_CONCURRENCIES, (4, 16, 64, 220))
            self.assertEqual(cargo.WEBDAV_CONCURRENCIES, (4, 16, 64))
            required = tail.required_operation_ids(output)
            self.assertEqual(required, set(operation_ids[:10]))
            events = [
                json.dumps({
                    "outcome": "ok",
                    "eventTimestamp": "2026-09-24T00:00:00Z",
                    "event": {"request": {"method": "PUT", "headers": {"X-Corelink-Operation": operation}}},
                })
                for operation in required
            ]
            correlated = tail.redact_lines(events, required)
            self.assertEqual({json.loads(line)["operation_id"] for line in correlated}, required)


class B103ArtifactPrivacyTests(unittest.TestCase):
    def test_wire_response_hashes_or_parses_headers_without_serializing_values(self) -> None:
        class Response:
            status = 429
            headers = {
                "Retry-After": "120",
                "Server-Timing": "db;dur=53.2",
                "X-Request-ID": TENANT,
                "CF-Ray": ACCOUNT_ID,
            }

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps({"error": TENANT, "token": TOKEN, "nested": {"secret": CF_TOKEN}}).encode()

        with mock.patch.object(cargo, "urlopen", return_value=Response()), \
             mock.patch.object(cargo.uuid, "uuid4", return_value=uuid.UUID("12345678123456781234567812345678")):
            row = cargo.request(cargo.TARGET, TENANT, TOKEN, "PUT", "unique-object-key", b"payload")
        serialized = json.dumps(row, sort_keys=True)
        for sensitive in (TENANT, TOKEN, CF_TOKEN, ACCOUNT_ID, "Retry-After"):
            self.assertNotIn(sensitive, serialized)
        self.assertEqual(row["operation_id"], OPERATION_ID)
        self.assertEqual(row["retry_after_seconds"], 120)
        self.assertEqual(row["server_timing_durations_ms"], [53.2])
        self.assertIsNone(row["response_error_code"])

    def test_tail_projection_discards_secrets_and_requires_every_operation(self) -> None:
        second = "b103-ffffffffffffffffffffffffffffffff"
        required = {OPERATION_ID, second}
        raw = [
            json.dumps({
                "outcome": "ok",
                "eventTimestamp": 1780000000000,
                "event": {"request": {"method": "PUT", "url": f"https://staging/cargo/{TENANT}/x",
                                        "headers": {"X-Corelink-Operation": OPERATION_ID,
                                                    "Authorization": f"Bearer {TOKEN}", "CF-Trace": CF_TOKEN}}},
                "logs": [{"email": "person@example.invalid", "account_id": ACCOUNT_ID}],
            }),
            json.dumps({"outcome": "ok", "eventTimestamp": 1780000000001,
                        "event": {"request": {"method": "DELETE",
                                                "headers": {"X-Corelink-Operation": second}}}}),
        ]
        records = tail.redact_lines(raw, required)
        artifact = "\n".join(records)
        for sensitive in (TENANT, TOKEN, CF_TOKEN, ACCOUNT_ID, "person@example.invalid", "https://staging", "Authorization"):
            self.assertNotIn(sensitive, artifact)
        self.assertEqual({json.loads(line)["operation_id"] for line in records}, required)
        self.assertTrue(all(set(json.loads(line)) == {"operation_id", "method", "outcome", "event_timestamp"} for line in records))

    def test_incomplete_malformed_or_empty_tail_fails_without_output_file(self) -> None:
        for input_text in (
            "",
            "not-json\n",
            json.dumps({"eventTimestamp": "not-a-time", "event": {"request": {"method": "PUT", "headers": {"X-Corelink-Operation": OPERATION_ID}}}}),
            json.dumps({"event": {"request": {"method": "PUT", "headers": {"X-Corelink-Operation": OPERATION_ID}}}}),
        ):
            with self.subTest(input_text=input_text), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                wire = directory / "wire.json"
                output = directory / "tail.jsonl"
                wire.write_text(json.dumps({"operation_id": OPERATION_ID, "responses": [{"operation_id": "b103-ffffffffffffffffffffffffffffffff"}]}), encoding="utf-8")
                with mock.patch("sys.argv", ["redact_b103_worker_tail.py", "--wire-evidence", str(wire), "--output", str(output)]), \
                     mock.patch("sys.stdin", io.StringIO(input_text)):
                    with self.assertRaises(SystemExit):
                        tail.main()
                self.assertFalse(output.exists())

    def test_workflow_orders_receipt_before_tail_and_keeps_dispatch_guarded(self) -> None:
        workflow = Path(".github/workflows/b103-cargo-write-reproducer.yml").read_text(encoding="utf-8")
        self.assertLess(workflow.index("validate canonical staging receipt"), workflow.index("capture same-window root Worker tail"))
        self.assertIn("--tenant-env B103_TENANT_ID", workflow)
        self.assertIn("--redact-tenant", workflow)
        self.assertRegex(workflow, r"github\.repository_id == '[0-9]+'")
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.ref_protected", workflow)
        self.assertIn("B103_TAIL_WORKER: corelink-staging", workflow)
        self.assertIn("wrangler tail \"${B103_TAIL_WORKER}\" --format json", workflow)
        self.assertIn("Worker tail stopped before the observation window", workflow)
        self.assertIn("Worker tail stopped during the observation window", workflow)
        self.assertNotIn("--search", workflow)
        self.assertIn("tenant_id", workflow[workflow.index("payload=$(printf"):workflow.index("payload=$(printf") + 180])
        self.assertNotIn("  schedule:", workflow)


if __name__ == "__main__":
    unittest.main()
