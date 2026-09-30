"""Mocked D1/KMS lifecycle cycle tests; never contacts live providers."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import issue_2165_kms_cycles as cycle_module  # noqa: E402
from issue_2165_kms_cycles import CycleError, _transition_query, run_cycles, validate_cycle_manifest  # noqa: E402
from test_issue_2165_kms_runtime import fixture as runtime_fixture  # noqa: E402


TENANTS = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
CF_ACCOUNT = "51284495e71acdb5a7677e7383ab026b"


def cycle_fixture() -> tuple[dict, dict[str, str]]:
    manifest, env = runtime_fixture()
    manifest["aws"]["cmk_provider"] = "aws"
    manifest["disposable_tenants"] = list(TENANTS)
    manifest["cloudflare"]["account_id"] = CF_ACCOUNT
    manifest["cloudflare"]["d1"].update(region="iad", database_id="d1-isolated")
    manifest["cloudflare"]["r2"].update(endpoint=f"https://{CF_ACCOUNT}.r2.cloudflarestorage.com")
    manifest["cloudflare"]["r2_prefixes"] = [
        {"tenant_id": TENANTS[0], "region": "iad", "prefix": "iad/AAAAAAAAAAAAAAAA/"},
        {"tenant_id": TENANTS[1], "region": "iad", "prefix": "iad/BBBBBBBBBBBBBBBB/"},
    ]
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    manifest["lifecycle_window"] = {"started_at_ms": now_ms - 60_000, "ended_at_ms": now_ms + 20 * 60_000}
    manifest["network"]["provisioning_receipt"]["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    manifest["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    env.update({
        "B083_KMS_KEY_ARN": manifest["aws"]["cmk_arn"],
        "B083_CF_ACCOUNT_ID": CF_ACCOUNT,
        "B083_D1_DATABASE_ID": "d1-isolated",
        "B083_D1_REGION": "iad",
        "B083_R2_S3_ENDPOINT": manifest["cloudflare"]["r2"]["endpoint"],
        "B083_AUDIT_SINK_REF": manifest["audit_sink"]["target_id"],
        "B083_CF_API_TOKEN": "mock-protected-token",
        "B083_ISSUE2165_GRANT_ID": "grant-0",
        "GITHUB_RUN_ID": "1234567",
    })
    return manifest, env


def d1_payload(rows: list[dict], *, changed_db: bool = False, rows_written: int = 0, changes: int = 0) -> dict:
    return {"success": True, "result": [{"success": True, "meta": {"changed_db": changed_db, "rows_written": rows_written, "changes": changes}, "results": rows}]}


class CycleMocks:
    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.rows: dict[str, list[dict]] = {"degrade": [], "restore": []}
        self.epoch = 0
        self.mutation_calls: list[str] = []
        self.token = 0

    def stage(self, stage: str, manifest: dict, evidence_dir: Path) -> str | None:
        self.mutation_calls.append(stage)
        if stage in {"revoke", "restore"}:
            action = "degrade" if stage == "revoke" else "restore"
            for tenant_id in TENANTS:
                self.epoch += 1
                self.token += 1
                self.rows[action].append({"token": f"row-{self.token}", "tenant_id": tenant_id, "epoch": self.epoch, "action": action, "cmk_provider": "aws", "cmk_key_id": self.manifest["aws"]["cmk_arn"], "outcome": "completed", "completed_at_ms": int(datetime.now(timezone.utc).timestamp() * 1000)})
            receipt = {"schema": "corelink.issue-2165-kms-custodian-receipt-v1", "stage": stage, "run_id": "1234567", "receipt_sha256": "c" * 64, "actions": [{"operation": "revoke-grant" if stage == "revoke" else "restore-grant", "grant_id": os.environ.get("B083_ISSUE2165_GRANT_ID") if stage == "revoke" else f"grant-{self.epoch}", "readback": "absent" if stage == "revoke" else "exact"}]}
            evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            (evidence_dir / f"custodian-{stage}-receipt.json").write_text(json.dumps(receipt))
            if stage == "restore":
                return receipt["actions"][0]["grant_id"]
            return None
        elif stage == "cleanup":
            return None
        raise AssertionError(stage)

    def api(self, method, path, token, payload):
        self.assert_safe(method, path, token, payload)
        action = payload["params"][4]
        return d1_payload(copy.deepcopy(self.rows[action]))

    def assert_safe(self, method, path, token, payload):
        assert method == "POST" and path.endswith("/query") and token == "mock-protected-token"
        assert "SELECT " in payload["sql"] and "UPDATE " not in payload["sql"] and "DELETE " not in payload["sql"]


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.env = cycle_fixture()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env["RUNNER_TEMP"] = self.temp.name
        self.env["GITHUB_OUTPUT"] = str(Path(self.temp.name) / "github-output")
        Path(self.env["GITHUB_OUTPUT"]).touch()
        self.env["B083_TARGET_MANIFEST_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:protected-manifest"
        self.env["RUNNER_TEMP"] = self.temp.name
        self.env["B083_AWS_REGION"] = "us-east-1"
        self.env["B083_AWS_ACCOUNT_ID"] = self.manifest["aws"]["account_id"]
        self.env["B083_AWS_CUSTODIAN_ROLE_ARN"] = self.manifest["aws"]["custodian_role_arn"]

    def test_exact_ten_cycles_use_select_only_d1_and_write_private_bundle(self):
        mocks = CycleMocks(self.manifest)
        ticks = [0.0]
        def monotonic():
            return ticks[0]
        def sleeper(duration):
            ticks[0] += duration
        with patch.dict(os.environ, self.env):
            bundle = run_cycles(self.manifest, Path(self.temp.name) / "evidence", environ=os.environ, stage_runner=mocks.stage, api_json=mocks.api, monotonic=monotonic, sleeper=sleeper)
        self.assertEqual(len(bundle["cycles"]), 10)
        self.assertEqual(len(bundle["grant_ids"]), 11)
        self.assertEqual(mocks.mutation_calls.count("revoke"), 10)
        self.assertEqual(mocks.mutation_calls.count("restore"), 10)
        self.assertEqual(len(mocks.rows["degrade"]), 20)
        self.assertEqual(len(mocks.rows["restore"]), 20)
        for cycle in bundle["cycles"]:
            self.assertEqual(len(cycle["degrade_rows"]["rows"]), 2)
            self.assertEqual(len(cycle["restore_rows"]["rows"]), 2)
            for action in ("degrade_rows", "restore_rows"):
                source = cycle[action]["d1_source"]
                self.assertEqual(source["method"], "parameterized-select-post")
                self.assertEqual(source["account_alias"], "cf5128")
                self.assertEqual(source["d1_region"], "iad")
                self.assertEqual(source["read_only_metadata"], {"changed_db": False, "rows_written": 0, "changes": 0})
                self.assertRegex(source["query_sha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(source["response_sha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(source["selected_rows_sha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(source["selected_token_set_sha256"], r"^[a-f0-9]{64}$")
                self.assertNotIn("token_identity_sha256", source)
        path = Path(self.temp.name) / "evidence" / "lifecycle-cycle-bundle.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        saved = json.loads(path.read_text())
        self.assertEqual(saved["target"]["tenant_ids"], TENANTS)
        self.assertEqual(Path(self.env["GITHUB_OUTPUT"]).read_text().count("grant_ids_json="), 1)
        self.assertNotIn("audit://", json.dumps(saved))

    def test_two_tenants_may_share_epoch_but_not_repeat_it_per_tenant(self):
        target = validate_cycle_manifest(self.manifest, self.env)
        target["key_arn"] = self.manifest["aws"]["cmk_arn"]
        rows = [{"token": "tok-a", "tenant_id": TENANTS[0], "epoch": 1, "action": "degrade", "cmk_provider": "aws", "cmk_key_id": target["key_arn"], "outcome": "completed", "completed_at_ms": target["lifecycle_window"]["started_at_ms"] + 1}, {"token": "tok-b", "tenant_id": TENANTS[1], "epoch": 1, "action": "degrade", "cmk_provider": "aws", "cmk_key_id": target["key_arn"], "outcome": "completed", "completed_at_ms": target["lifecycle_window"]["started_at_ms"] + 2}]
        result = _transition_query(target, "degrade", lambda *args: d1_payload(rows), "token")
        self.assertEqual(len(result[0]), 2)
        with self.assertRaisesRegex(CycleError, "unique within each tenant"):
            _transition_query(target, "degrade", lambda *args: d1_payload([rows[0], {**rows[0], "token": "tok-a2"}]), "token")

    def test_nonzero_d1_write_metadata_fails_closed(self):
        target = validate_cycle_manifest(self.manifest, self.env)
        target["key_arn"] = self.manifest["aws"]["cmk_arn"]
        with self.assertRaisesRegex(CycleError, "read-only query metadata"):
            _transition_query(target, "degrade", lambda *args: d1_payload([], changed_db=True), "token")

    def test_d1_timeout_after_revoke_does_not_retry_mutation_and_writes_reconciliation(self):
        mocks = CycleMocks(self.manifest)
        ticks = [0.0]
        def monotonic():
            return ticks[0]
        def sleeper(duration):
            ticks[0] += duration
        def empty_api(method, path, token, payload):
            return d1_payload([])
        with patch.dict(os.environ, self.env):
            with self.assertRaisesRegex(CycleError, "timed out waiting"):
                run_cycles(self.manifest, Path(self.temp.name) / "evidence", environ=os.environ, stage_runner=mocks.stage, api_json=empty_api, monotonic=monotonic, sleeper=sleeper)
        self.assertEqual(mocks.mutation_calls.count("revoke"), 1)
        self.assertEqual(mocks.mutation_calls.count("restore"), 0)
        packet = Path(self.temp.name) / "evidence" / "lifecycle-cycle-reconciliation.json"
        self.assertTrue(packet.exists())

    def test_github_output_failure_runs_exact_cleanup_and_preserves_reconciliation(self):
        mocks = CycleMocks(self.manifest)
        ticks = [0.0]
        with patch.dict(os.environ, self.env), patch.object(cycle_module, "_write_outputs", side_effect=OSError("injected handoff write failure")):
            with self.assertRaisesRegex(OSError, "injected handoff"):
                run_cycles(self.manifest, Path(self.temp.name) / "evidence", environ=os.environ, stage_runner=mocks.stage, api_json=mocks.api, monotonic=lambda: ticks[0], sleeper=lambda duration: ticks.__setitem__(0, ticks[0] + duration))
        packet = Path(self.temp.name) / "evidence" / "lifecycle-cycle-reconciliation.json"
        self.assertTrue(packet.exists())
        value = json.loads(packet.read_text())
        self.assertEqual(value["cleanup_result"], "exact-known-grants-cleaned")
        self.assertIn("cleanup", mocks.mutation_calls)

    def test_rejects_bad_provider_key_and_out_of_window(self):
        bad = copy.deepcopy(self.manifest)
        bad["aws"]["cmk_provider"] = "other"
        with self.assertRaisesRegex(CycleError, "cmk_provider=aws"):
            validate_cycle_manifest(bad, self.env)
        bad = copy.deepcopy(self.manifest)
        bad["lifecycle_window"]["ended_at_ms"] = bad["lifecycle_window"]["started_at_ms"] + 61 * 60_000
        with self.assertRaisesRegex(CycleError, "60 minutes"):
            validate_cycle_manifest(bad, self.env)


if __name__ == "__main__":
    unittest.main()
